"""Asynchronous client for the MEGA.nz cloud storage API.

This module implements the subset of MEGA's API needed to use a MEGA account as
a Home Assistant backup location:

* login with account version 1 and 2 passwords, optional two-factor code and
  session resumption,
* folder creation/lookup,
* listing nodes,
* streaming, chunked upload and download (MEGA's client side encryption),
* permanent deletion.

MEGA encrypts all data client side. File contents use AES-128-CTR with a per
file key and are authenticated with MEGA's chunked CBC-MAC. Node names are
encrypted with the node key, and node keys are encrypted with the account
master key. This module only depends on ``aiohttp`` and ``cryptography``, both
of which are shipped with Home Assistant.

The code deliberately does not import Home Assistant so it can be tested on its
own and reused elsewhere.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

API_URL = "https://g.api.mega.co.nz/cs"

# MEGA stores files in chunks which start at 128 KiB and grow by 128 KiB per
# chunk until they reach 1 MiB. The chunk boundaries are part of the MAC
# calculation, so they must not be changed.
CHUNK_START = 128 * 1024
CHUNK_INCREMENT = 128 * 1024
CHUNK_MAX = 1024 * 1024

# Arbitrary limit for the JSON files this integration keeps next to backups.
MAX_METADATA_SIZE = 1024 * 1024

API_TIMEOUT = aiohttp.ClientTimeout(total=None, connect=30, sock_read=120)
TRANSFER_TIMEOUT = aiohttp.ClientTimeout(total=None, connect=30, sock_read=300)

MAX_API_RETRIES = 5
MAX_HASHCASH_RETRIES = 3

# The fixed AES key MEGA uses to derive the password key of v1 accounts.
_MEGA_AES_KEY = bytes.fromhex("93C467E37DB0C7A4D1BE3F810152CB56")

# Error codes returned by the API. See the MEGA SDK / mega.js.
_API_ERRORS: dict[int, str] = {
    -1: "An internal error occurred",
    -2: "Invalid arguments were passed to the API",
    -3: "The API is temporarily congested",
    -4: "Rate limit exceeded",
    -5: "The upload failed",
    -6: "Too many concurrent connections to the upload target",
    -7: "The upload chunk is out of range",
    -8: "The upload target expired",
    -9: "Object not found or invalid credentials",
    -10: "Circular linkage attempted",
    -11: "Access violation",
    -12: "The object already exists",
    -13: "The resource is incomplete",
    -14: "Decryption failed",
    -15: "The session is invalid or expired",
    -16: "The account is blocked",
    -17: "Storage quota exceeded",
    -18: "The resource is temporarily unavailable",
    -19: "Too many connections",
    -24: "The account is over its storage quota",
    -25: "The request was rolled back",
    -26: "Multi-factor authentication is required",
    -27: "This operation is only available to the account owner",
    -28: "The business account is past due",
    -29: "Payment required",
}


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded URL safe base64 (MEGA's encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Decode MEGA's unpadded URL safe base64."""
    # Old MEGA clients used a comma instead of a padding character.
    data = data.replace(",", "")
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def _b64_decode(data: str) -> bytes:
    """Decode standard or URL safe base64."""
    data = data.replace("-", "+").replace("_", "/").replace(",", "")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# AES helpers
# ---------------------------------------------------------------------------


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Encrypt data with AES in ECB mode (no padding)."""
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt data with AES in ECB mode (no padding)."""
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
    """Encrypt data with AES in CBC mode (no padding)."""
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes = bytes(16)) -> bytes:
    """Decrypt data with AES in CBC mode (no padding)."""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _xor(left: bytes, right: bytes) -> bytes:
    """XOR two equally sized byte strings."""
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _ctr_iv(nonce: bytes) -> bytes:
    """Return the 16 byte counter block for a MEGA file nonce."""
    return nonce + bytes(8)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def prepare_key(password: bytes) -> bytes:
    """Derive the AES key MEGA v1 accounts use for the password hash."""
    pkey = _MEGA_AES_KEY
    blocks = [
        password[offset : offset + 16].ljust(16, b"\0")
        for offset in range(0, len(password), 16)
    ]
    encryptors = [
        Cipher(algorithms.AES(block), modes.ECB()).encryptor() for block in blocks
    ]
    for _ in range(0x10000):
        for encryptor in encryptors:
            pkey = encryptor.update(pkey)
    return pkey


def string_hash(email: str, aes_key: bytes) -> bytes:
    """Calculate the v1 account login hash for an email address."""
    data = email.encode("utf-8")
    if len(data) % 4:
        data += b"\0" * (4 - len(data) % 4)

    digest = bytearray(16)
    for offset in range(0, len(data), 4):
        index = (offset // 4) % 4
        word = int.from_bytes(data[offset : offset + 4], "big")
        digest[index * 4 : index * 4 + 4] = (
            int.from_bytes(digest[index * 4 : index * 4 + 4], "big") ^ word
        ).to_bytes(4, "big")

    encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    for _ in range(0x4000):
        digest = bytearray(encryptor.update(bytes(digest)))
    return bytes(digest[0:4]) + bytes(digest[8:12])


def derive_v2_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive the password key and login hash for a v2 account."""
    derived = hashlib.pbkdf2_hmac("sha512", password, salt, 100000, 32)
    return derived[:16], derived[16:]


# ---------------------------------------------------------------------------
# Node key handling
# ---------------------------------------------------------------------------


def _node_cipher_key(node_key: bytes) -> bytes:
    """Return the AES key from a (possibly condensed) node key."""
    if len(node_key) >= 32:
        return _xor(node_key[:16], node_key[16:32])
    return node_key[:16]


def _decode_mpis(data: bytes, count: int = 4) -> list[int]:
    """Decode ``count`` MPI numbers from a MEGA buffer."""
    values: list[int] = []
    for _ in range(count):
        if len(data) < 2:
            raise ValueError("Truncated MPI")
        bits = int.from_bytes(data[:2], "big")
        length = (bits + 7) // 8 + 2
        if length > len(data):
            raise ValueError("Truncated MPI")
        values.append(int.from_bytes(data[2:length], "big"))
        data = data[length:]
    return values


def _decode_mpi(data: bytes) -> int:
    """Decode a single MPI number."""
    bits = int.from_bytes(data[:2], "big")
    length = (bits + 7) // 8
    return int.from_bytes(data[2 : 2 + length], "big")


def decrypt_attributes(data: bytes, node_key: bytes) -> dict[str, Any]:
    """Decrypt a node's attribute blob."""
    plain = aes_cbc_decrypt(_node_cipher_key(node_key), data)
    plain = plain.split(b"\0", 1)[0]
    if not plain.startswith(b"MEGA"):
        return {}
    try:
        attributes = json.loads(plain[4:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return attributes if isinstance(attributes, dict) else {}


def encrypt_attributes(attributes: dict[str, Any], key: bytes) -> bytes:
    """Encrypt a node's attribute blob."""
    plain = b"MEGA" + json.dumps(attributes, separators=(",", ":")).encode("utf-8")
    plain += b"\0" * (-len(plain) % 16)
    return aes_cbc_encrypt(key, plain)


# ---------------------------------------------------------------------------
# Chunking and integrity
# ---------------------------------------------------------------------------


def get_chunks(size: int) -> list[tuple[int, int]]:
    """Return ``(offset, length)`` pairs for a MEGA file of ``size`` bytes."""
    chunks: list[tuple[int, int]] = []
    offset = 0
    length = CHUNK_START
    while offset + length < size:
        chunks.append((offset, length))
        offset += length
        if length < CHUNK_MAX:
            length += CHUNK_INCREMENT
    if size > 0:
        chunks.append((offset, size - offset))
    return chunks


class _MegaMac:
    """Incremental implementation of MEGA's chunked CBC-MAC."""

    def __init__(self, key: bytes, nonce: bytes) -> None:
        self._key = key
        self._nonce = nonce[:8]
        self._state = self._nonce * 2
        self._buffer = bytearray()
        self._chunk_macs: list[bytes] = []
        self._position = 0
        self._next_boundary = CHUNK_START
        self._increment = CHUNK_START
        self._finished = False

    def update(self, data: bytes) -> None:
        """Process plaintext bytes."""
        if self._finished:
            raise RuntimeError("MAC already finalized")
        self._buffer.extend(data)
        complete = len(self._buffer) - (len(self._buffer) % 16)
        for offset in range(0, complete, 16):
            block = bytes(self._buffer[offset : offset + 16])
            self._state = aes_ecb_encrypt(self._key, _xor(self._state, block))
            self._position += 16
            if self._position >= self._next_boundary:
                self._chunk_macs.append(self._state)
                self._state = self._nonce * 2
                if self._increment < CHUNK_MAX:
                    self._increment += CHUNK_INCREMENT
                self._next_boundary += self._increment
        del self._buffer[:complete]

    def digest(self) -> bytes:
        """Return the 8 byte meta MAC."""
        if not self._finished:
            if self._buffer:
                block = bytes(self._buffer).ljust(16, b"\0")
                self._state = aes_ecb_encrypt(self._key, _xor(self._state, block))
                self._position += 16
                if self._position >= self._next_boundary:
                    self._chunk_macs.append(self._state)
                    self._state = self._nonce * 2
            self._chunk_macs.append(self._state)
            self._buffer.clear()
            self._finished = True

        state = bytes(16)
        for chunk_mac in self._chunk_macs:
            state = aes_ecb_encrypt(self._key, _xor(state, chunk_mac))
        return _xor(state[0:4], state[4:8]) + _xor(state[8:12], state[12:16])


class _BufferedStream:
    """Read exact byte counts from an async iterator."""

    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._stream = stream
        self._buffer = bytearray()
        self._eof = False

    async def read(self, size: int) -> bytes:
        """Read up to ``size`` bytes, returning less only at EOF."""
        while len(self._buffer) < size and not self._eof:
            try:
                chunk = await self._stream.__anext__()
            except StopAsyncIteration:
                self._eof = True
                break
            if chunk:
                self._buffer.extend(chunk)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    async def has_more(self) -> bool:
        """Return True if there is more data than requested."""
        return bool(await self.read(1))


# ---------------------------------------------------------------------------
# Hashcash (anti-bot challenge, only used when the API asks for it)
# ---------------------------------------------------------------------------


def solve_hashcash(challenge: str) -> str:
    """Solve a MEGA X-Hashcash challenge and return the response token."""
    parts = challenge.split(":")
    if len(parts) < 4 or parts[0] != "1":
        raise MegaError("Unsupported hashcash challenge")
    easiness = int(parts[1])
    token = parts[3]

    threshold = (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3)
    token_bytes = _b64_decode(token)
    buffer = bytearray(4 + 262144 * len(token_bytes))
    for index in range(4, len(buffer), len(token_bytes)):
        buffer[index : index + len(token_bytes)] = token_bytes

    counter = 0
    while True:
        buffer[0:4] = counter.to_bytes(4, "little")
        if int.from_bytes(hashlib.sha256(buffer).digest()[:4], "big") <= threshold:
            return f"1:{token}:{b64url_encode(bytes(buffer[0:4]))}"
        counter = (counter + 1) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MegaError(Exception):
    """Base error for the MEGA client."""


class MegaAuthError(MegaError):
    """Authentication failed."""


class MegaMfaRequired(MegaAuthError):
    """The account requires a two-factor authentication code."""


class MegaConnectionError(MegaError):
    """The MEGA API could not be reached."""


class MegaQuotaError(MegaError):
    """The account or the connection is out of quota."""


class MegaNotFound(MegaError):
    """The requested node does not exist."""


class MegaFolderError(MegaError):
    """The configured folder is not usable."""


class MegaSizeMismatch(MegaError):
    """The uploaded stream did not match the announced size."""


def _decode_upload_handle(body: bytes) -> str:
    """Decode the completion handle returned by the upload servers.

    MEGA implementations disagree on the wire format: the reference SDK and
    megajs read the raw 8 byte handle, while the older Python clients treat the
    body as text. Accept both so the integration works either way.
    """
    if len(body) == 8:
        return b64url_encode(body)
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        return b64url_encode(body)


class MegaNode:
    """A node (file or folder) in a MEGA account."""

    __slots__ = (
        "attributes",
        "handle",
        "key",
        "name",
        "parent",
        "size",
        "timestamp",
        "type",
    )

    def __init__(
        self,
        *,
        handle: str,
        parent: str | None,
        node_type: int,
        name: str,
        size: int,
        timestamp: int,
        key: bytes | None,
        attributes: dict[str, Any] | None,
    ) -> None:
        self.handle = handle
        self.parent = parent
        self.type = node_type
        self.name = name
        self.size = size
        self.timestamp = timestamp
        self.key = key
        self.attributes = attributes or {}

    @property
    def is_file(self) -> bool:
        """Return True for file nodes."""
        return self.type == 0

    @property
    def is_folder(self) -> bool:
        """Return True for folder nodes."""
        return self.type == 1

    def __repr__(self) -> str:
        """Return a readable representation."""
        return f"<MegaNode {self.name!r} type={self.type} size={self.size}>"


@dataclass(kw_only=True)
class MegaSession:
    """A MEGA session that can be resumed after a restart."""

    sid: str
    master_key: bytes
    user_id: str


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MegaClient:
    """A small asynchronous MEGA client."""

    def __init__(
        self,
        *,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        session_data: MegaSession | None = None,
    ) -> None:
        self._session = session
        self._email = email
        self._password = password

        self._sid: str | None = session_data.sid if session_data else None
        self._master_key: bytes | None = (
            session_data.master_key if session_data else None
        )
        self._user_id: str = session_data.user_id if session_data else ""

        self._login_lock = asyncio.Lock()
        self._sequence = int(time.time() * 1000) % 0xFFFFFFFF
        self._hashcash: str | None = None
        self._request_id = "".join(
            secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10)
        )

    # -- properties ---------------------------------------------------------

    @property
    def user_id(self) -> str:
        """Return the MEGA user handle."""
        return self._user_id

    @property
    def session(self) -> MegaSession:
        """Return the current session so it can be persisted."""
        if not self._sid or not self._master_key:
            raise MegaError("Not logged in")
        return MegaSession(
            sid=self._sid, master_key=self._master_key, user_id=self._user_id
        )

    @property
    def logged_in(self) -> bool:
        """Return True if a session is available."""
        return bool(self._sid and self._master_key)

    # -- API ----------------------------------------------------------------

    def _next_request_id(self) -> str:
        """Return a request counter for the API."""
        self._sequence = (self._sequence + 1) & 0xFFFFFFFF
        return str(self._sequence)

    async def _api_once(
        self, payload: dict[str, Any], request_id: str, hashcash: str | None = None
    ) -> tuple[Any, str | None]:
        """Perform a single API request.

        Returns the decoded response and a hashcash challenge if the server
        asked us to solve one. MEGA binds the challenge to the request id, so
        the retry after solving has to reuse the id of the original request.
        """
        params = {"id": request_id}
        if self._sid:
            params["sid"] = self._sid
        headers = {"Content-Type": "application/json"}
        token = hashcash or self._hashcash
        if token:
            headers["X-Hashcash"] = token

        try:
            async with self._session.post(
                API_URL,
                params=params,
                json=[payload],
                headers=headers,
                timeout=API_TIMEOUT,
            ) as response:
                # MEGA answers with HTTP 402 and an X-Hashcash header when it
                # wants proof of work; the body is empty in that case.
                challenge = response.headers.get("X-Hashcash")
                text = await response.text()
                if challenge:
                    return None, challenge
                if response.status == 509:
                    raise MegaQuotaError(
                        "MEGA download/upload quota exceeded, try again later"
                    )
                if response.status == 402:
                    raise MegaConnectionError(
                        "MEGA API is rate limiting this connection, try again later"
                    )
                if response.status != 200:
                    detail = f": {text[:200]}" if text else ""
                    raise MegaConnectionError(
                        f"MEGA API returned HTTP {response.status}{detail}"
                    )
        except (TimeoutError, aiohttp.ClientError) as err:
            raise MegaConnectionError(f"Error talking to MEGA: {err}") from err

        try:
            data = json.loads(text)
        except ValueError as err:
            raise MegaConnectionError("MEGA API returned invalid JSON") from err

        if isinstance(data, list):
            data = data[0] if data else None
        return data, None

    async def _api(self, payload: dict[str, Any], *, allow_relogin: bool = True) -> Any:
        """Perform an API request, retrying transient errors."""
        request_id = self._next_request_id()
        hashcash: str | None = None
        hashcash_attempts = 0
        attempt = 0
        while attempt < MAX_API_RETRIES:
            data, challenge = await self._api_once(payload, request_id, hashcash)
            if challenge is not None:
                hashcash_attempts += 1
                if hashcash_attempts > MAX_HASHCASH_RETRIES:
                    raise MegaConnectionError("Could not solve the MEGA challenge")
                _LOGGER.debug("Solving MEGA hashcash challenge")
                hashcash = await asyncio.to_thread(solve_hashcash, challenge)
                # The solved token is accepted for later requests as well, so
                # keep it and skip the proof of work until MEGA asks again.
                self._hashcash = hashcash
                continue

            if isinstance(data, int) and data < 0:
                if data == -3 or data == -18:
                    await asyncio.sleep(min(2**attempt, 30))
                    attempt += 1
                    continue
                if data == -4:
                    await asyncio.sleep(min(3 * (attempt + 1), 30))
                    attempt += 1
                    continue
                if data == -15 and allow_relogin:
                    _LOGGER.debug("MEGA session expired, logging in again")
                    await self.async_login()
                    attempt += 1
                    continue
                if data == -26:
                    raise MegaMfaRequired(_API_ERRORS[data])
                if data in (-9, -16):
                    raise MegaAuthError(_API_ERRORS.get(data, "Not authenticated"))
                if data in (-17, -24):
                    raise MegaQuotaError(_API_ERRORS.get(data, "Quota exceeded"))
                raise MegaError(_API_ERRORS.get(data, f"MEGA API error {data}"))

            if data is None:
                raise MegaConnectionError("MEGA API returned an empty response")
            return data

        raise MegaConnectionError("MEGA API is temporarily unavailable")

    # -- login --------------------------------------------------------------

    async def async_login(self, mfa_code: str | None = None) -> MegaSession:
        """Log in and return the session."""
        async with self._login_lock:
            self._sid = None
            self._master_key = None
            email = self._email.lower()
            password = self._password.encode("utf-8")

            prelogin = await self._api({"a": "us0", "user": email}, allow_relogin=False)
            version = prelogin.get("v", 1) if isinstance(prelogin, dict) else 1

            if version == 2:
                salt = _b64_decode(str(prelogin.get("s", "")))
                password_key, auth_key = derive_v2_key(password, salt)
                user_hash = b64url_encode(auth_key)
            else:
                password_key = prepare_key(password)
                user_hash = b64url_encode(string_hash(email, password_key))

            payload: dict[str, Any] = {
                "a": "us",
                "user": email,
                "uh": user_hash,
            }
            if mfa_code:
                payload["mfa"] = str(mfa_code).replace(" ", "")

            try:
                response = await self._api(payload, allow_relogin=False)
            except MegaMfaRequired:
                if mfa_code:
                    raise MegaAuthError(
                        "The two-factor authentication code was rejected"
                    ) from None
                raise

            if not isinstance(response, dict) or not {
                "k",
                "privk",
                "csid",
            }.issubset(response):
                raise MegaAuthError("MEGA returned an unexpected login response")

            try:
                master_key = aes_ecb_decrypt(password_key, _b64_decode(response["k"]))
                sid = self._derive_sid(response["csid"], response["privk"], master_key)
            except (ValueError, KeyError) as err:
                raise MegaAuthError("Could not decrypt the MEGA session") from err

            self._master_key = master_key
            self._sid = sid

            user = await self._api({"a": "ug"}, allow_relogin=False)
            if isinstance(user, dict) and user.get("u"):
                self._user_id = str(user["u"])
            elif not self._user_id:
                # Fall back to a stable identifier derived from the email.
                self._user_id = hashlib.sha256(email.encode()).hexdigest()[:16]

            _LOGGER.debug("Logged in to MEGA as %s", self._user_id)
            return self.session

    def _derive_sid(self, csid: str, privk: str, master_key: bytes) -> str:
        """Derive the API session id from the RSA encrypted session id."""
        encrypted_private_key = aes_ecb_decrypt(master_key, _b64_decode(privk))
        p, q, d, _u = _decode_mpis(encrypted_private_key)
        ciphertext = _decode_mpi(_b64_decode(csid))
        plaintext = pow(ciphertext, d, p * q)
        # MEGA encrypts a random block of the size of the modulus with the
        # session id in its most significant 43 bytes (the reference clients
        # take the first 43 bytes of the big endian plaintext). Small values,
        # as produced by the test emulator, are left padded to 43 bytes.
        length = max(43, (plaintext.bit_length() + 7) // 8)
        sid_bytes = plaintext.to_bytes(length, "big")[:43]
        return b64url_encode(sid_bytes)

    async def async_ensure_session(self) -> None:
        """Make sure a usable session is available."""
        if not self.logged_in:
            await self.async_login()
            return
        try:
            await self._api({"a": "uq", "strg": 1}, allow_relogin=False)
        except MegaMfaRequired as err:
            raise MegaAuthError("The saved MEGA session expired") from err
        except MegaError:
            # Any session/network problem is retried by a fresh login below.
            _LOGGER.debug("Saved MEGA session is not usable, logging in again")
            await self.async_login()

    # -- nodes --------------------------------------------------------------

    def _parse_node(self, raw: dict[str, Any]) -> MegaNode | None:
        """Decrypt and convert a raw API node."""
        node_type = raw.get("t")
        handle = raw.get("h")
        if not handle or not isinstance(node_type, int):
            return None

        if node_type in (2, 3, 4):
            names = {2: "Cloud Drive", 3: "Inbox", 4: "Rubbish Bin"}
            return MegaNode(
                handle=handle,
                parent=None,
                node_type=node_type,
                name=names[node_type],
                size=0,
                timestamp=int(raw.get("ts", 0)),
                key=None,
                attributes=None,
            )

        if node_type not in (0, 1) or not self._master_key:
            return None

        encrypted_keys = str(raw.get("k") or "")
        encoded_attributes = raw.get("a")
        if not encrypted_keys or not encoded_attributes:
            return None

        node_key_encoded: str | None = None
        for candidate in encrypted_keys.split("/"):
            owner, separator, key = candidate.partition(":")
            if separator and (owner == self._user_id or node_key_encoded is None):
                # Prefer the key encrypted with our master key, but keep the
                # last candidate as a fallback.
                if owner == self._user_id:
                    node_key_encoded = key
                    break
                node_key_encoded = key

        if node_key_encoded is None:
            return None

        try:
            node_key = aes_ecb_decrypt(
                self._master_key, b64url_decode(node_key_encoded)
            )
            attributes = decrypt_attributes(b64url_decode(encoded_attributes), node_key)
        except (ValueError, IndexError):
            return None

        name = attributes.get("n")
        if not isinstance(name, str):
            return None

        return MegaNode(
            handle=handle,
            parent=raw.get("p") or None,
            node_type=node_type,
            name=name,
            size=int(raw.get("s") or 0),
            timestamp=int(raw.get("ts") or 0),
            key=node_key,
            attributes=attributes,
        )

    async def async_list_nodes(self) -> dict[str, MegaNode]:
        """Return all nodes of the account, keyed by handle."""
        response = await self._api({"a": "f", "c": 1, "r": 1})
        if not isinstance(response, dict):
            raise MegaConnectionError("MEGA returned an invalid node list")
        nodes: dict[str, MegaNode] = {}
        for raw in response.get("f", []):
            if not isinstance(raw, dict):
                continue
            node = self._parse_node(raw)
            if node is not None:
                nodes[node.handle] = node
        return nodes

    @staticmethod
    def _root_handle(nodes: dict[str, MegaNode]) -> str:
        """Return the handle of the Cloud Drive root."""
        for node in nodes.values():
            if node.type == 2:
                return node.handle
        raise MegaFolderError("Could not find the MEGA Cloud Drive")

    async def async_resolve_folder(self, path: str) -> str:
        """Resolve a path below the Cloud Drive, creating it if necessary."""
        nodes = await self.async_list_nodes()
        parent = self._root_handle(nodes)
        parts = [part for part in path.replace("\\", "/").split("/") if part]

        for part in parts:
            existing = next(
                (
                    node
                    for node in nodes.values()
                    if node.parent == parent and node.name == part
                ),
                None,
            )
            if existing is not None:
                if not existing.is_folder:
                    raise MegaFolderError(f"{part!r} exists but is not a folder")
                parent = existing.handle
                continue

            created = await self._async_create_folder(parent, part)
            nodes = await self.async_list_nodes()
            created_node = nodes.get(created)
            if (
                created_node is None
                or created_node.parent != parent
                or created_node.name != part
            ):
                raise MegaFolderError(f"Could not create folder {part!r}")
            parent = created

        return parent

    async def _async_create_folder(self, parent: str, name: str) -> str:
        """Create a folder and return its handle."""
        node_key = secrets.token_bytes(16)
        encrypted_attributes = encrypt_attributes({"n": name}, node_key)
        encrypted_key = aes_ecb_encrypt(self._master_key or b"", node_key)
        response = await self._api(
            {
                "a": "p",
                "t": parent,
                "n": [
                    {
                        "h": "xxxxxxxx",
                        "t": 1,
                        "a": b64url_encode(encrypted_attributes),
                        "k": b64url_encode(encrypted_key),
                    }
                ],
                "i": self._request_id,
            }
        )
        try:
            return str(response["f"][0]["h"])
        except (KeyError, IndexError, TypeError) as err:
            raise MegaFolderError(f"Could not create folder {name!r}") from err

    async def async_list_folder(self, handle: str) -> list[MegaNode]:
        """Return the direct children of a folder."""
        nodes = await self.async_list_nodes()
        if handle not in nodes:
            raise MegaNotFound("Folder does not exist")
        return [node for node in nodes.values() if node.parent == handle]

    async def async_get_node(self, handle: str) -> MegaNode:
        """Return a node by handle."""
        nodes = await self.async_list_nodes()
        try:
            return nodes[handle]
        except KeyError as err:
            raise MegaNotFound(f"Node {handle} not found") from err

    # -- download -----------------------------------------------------------

    async def async_download_file(self, node: MegaNode) -> AsyncIterator[bytes]:
        """Yield the decrypted contents of a file node."""
        if not node.is_file or node.key is None:
            raise MegaError(f"{node.name!r} is not a file")

        response = await self._api({"a": "g", "g": 1, "n": node.handle})
        if not isinstance(response, dict) or not isinstance(response.get("g"), str):
            raise MegaConnectionError("MEGA did not return a download URL")

        url = response["g"]
        size = int(response.get("s", node.size))
        if size == 0:
            return

        key = node.key
        # File contents use the raw key/nonce, while attributes use the
        # condensed (folded) key handled by _node_cipher_key.
        aes_key = key[:16]
        nonce = key[16:24]
        expected_mac = key[24:32] if len(key) >= 32 else b""
        decryptor = Cipher(
            algorithms.AES(aes_key), modes.CTR(_ctr_iv(nonce))
        ).encryptor()
        mac = _MegaMac(aes_key, nonce)

        try:
            async with self._session.get(
                f"{url}/0-{size - 1}", timeout=TRANSFER_TIMEOUT
            ) as download:
                if download.status == 509:
                    raise MegaQuotaError(
                        "MEGA download quota exceeded, try again later"
                    )
                if download.status != 200:
                    raise MegaConnectionError(
                        f"MEGA download failed with HTTP {download.status}"
                    )
                async for chunk in download.content.iter_any():
                    plain = decryptor.update(chunk)
                    mac.update(plain)
                    yield plain
        except (TimeoutError, aiohttp.ClientError) as err:
            raise MegaConnectionError(f"Error downloading from MEGA: {err}") from err

        if expected_mac and mac.digest() != expected_mac:
            raise MegaError(f"Integrity check failed for {node.name!r}")

    async def async_read_file(self, node: MegaNode) -> bytes:
        """Read a small file node completely into memory."""
        if node.size > MAX_METADATA_SIZE:
            raise MegaError(f"{node.name!r} is too large to read")
        data = bytearray()
        async for chunk in self.async_download_file(node):
            data.extend(chunk)
        return bytes(data)

    # -- upload -------------------------------------------------------------

    async def _async_upload_chunk(self, url: str, data: bytes) -> bytes:
        """Upload one encrypted chunk and return the raw response body."""
        try:
            async with self._session.post(
                url,
                data=data,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(data)),
                },
                timeout=TRANSFER_TIMEOUT,
            ) as upload:
                body = await upload.read()
                if upload.status == 509:
                    raise MegaQuotaError("MEGA upload quota exceeded, try again later")
                if upload.status != 200:
                    raise MegaConnectionError(
                        f"MEGA upload failed with HTTP {upload.status}"
                    )
        except (TimeoutError, aiohttp.ClientError) as err:
            raise MegaConnectionError(f"Error uploading to MEGA: {err}") from err
        return body

    async def async_upload_file(
        self,
        *,
        parent: str,
        name: str,
        size: int,
        stream: AsyncIterator[bytes],
        on_progress: Callable[..., None] | None = None,
    ) -> MegaNode:
        """Upload a file and return the created node."""
        response = await self._api(
            {
                "a": "u",
                "ssl": 2,
                "s": size,
                "ms": 0,
                "r": 0,
                "e": 0,
                "v": 2,
            }
        )
        if not isinstance(response, dict) or not isinstance(response.get("p"), str):
            raise MegaConnectionError("MEGA did not return an upload URL")

        upload_url = response["p"]
        upload_key = secrets.token_bytes(24)
        aes_key = upload_key[:16]
        nonce = upload_key[16:24]

        encryptor = Cipher(
            algorithms.AES(aes_key), modes.CTR(_ctr_iv(nonce))
        ).encryptor()
        mac = _MegaMac(aes_key, nonce)
        reader = _BufferedStream(stream)

        upload_handle: str | None = None
        uploaded = 0

        # A zero byte file still needs one (empty) request to obtain its handle.
        chunks = get_chunks(size) or [(0, 0)]

        for offset, length in chunks:
            chunk = await reader.read(length)
            if len(chunk) != length:
                raise MegaSizeMismatch(
                    f"Backup stream ended after {uploaded + len(chunk)} bytes, expected {size}"
                )

            mac.update(chunk)
            ciphertext = encryptor.update(chunk)
            body = await self._async_upload_chunk(f"{upload_url}/{offset}", ciphertext)

            if body:
                try:
                    error_code = int(body)
                except ValueError:
                    error_code = 0
                if error_code < 0:
                    if error_code in (-17, -24):
                        raise MegaQuotaError(_API_ERRORS[error_code])
                    raise MegaError(
                        _API_ERRORS.get(error_code, f"MEGA upload error {error_code}")
                    )
                upload_handle = _decode_upload_handle(body)

            uploaded += length
            if on_progress is not None:
                on_progress(bytes_uploaded=uploaded)

        if await reader.has_more():
            raise MegaSizeMismatch("Backup stream contains more data than expected")
        if not upload_handle:
            raise MegaConnectionError("MEGA did not return the uploaded file handle")

        meta_mac = mac.digest()
        merged_key = upload_key + meta_mac
        # Attributes are encrypted with the condensed key (the first half of the
        # merged key XORed with the second half), while the node stores the
        # unmodified merged key.
        condensed_key = _xor(merged_key[:16], merged_key[16:32])

        encrypted_attributes = encrypt_attributes({"n": name}, condensed_key)
        stored_key = aes_ecb_encrypt(self._master_key or b"", merged_key)

        response = await self._api(
            {
                "a": "p",
                "t": parent,
                "n": [
                    {
                        "h": upload_handle,
                        "t": 0,
                        "a": b64url_encode(encrypted_attributes),
                        "k": b64url_encode(stored_key),
                    }
                ],
                "i": self._request_id,
            }
        )
        try:
            raw_node = response["f"][0]
        except (KeyError, IndexError, TypeError) as err:
            raise MegaError(f"Could not register uploaded file {name!r}") from err

        node = self._parse_node(raw_node)
        if node is None:
            raise MegaError(f"Could not read back uploaded file {name!r}")
        return node

    # -- delete -------------------------------------------------------------

    async def async_delete_node(self, handle: str) -> None:
        """Permanently delete a node."""
        result = await self._api({"a": "d", "n": handle, "i": self._request_id})
        if isinstance(result, int) and result < 0:
            raise MegaError(f"Could not delete node: {_API_ERRORS.get(result, result)}")

    async def async_get_storage_usage(self) -> tuple[int, int]:
        """Return ``(used, total)`` storage in bytes."""
        response = await self._api({"a": "uq", "strg": 1})
        if not isinstance(response, dict):
            raise MegaConnectionError("MEGA returned an invalid quota response")
        return int(response.get("cstrg", 0)), int(response.get("mstrg", 0))
