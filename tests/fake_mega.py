"""A small in-process MEGA API emulator used by the test suite.

It implements the parts of the MEGA API the integration uses, including the
client side encryption contract: logins with the ``uh`` password hash, RSA
protected sessions, node keys wrapped with the account master key, chunked file
uploads with a verified meta MAC, and range downloads. The emulator reuses the
crypto helpers of the client module so the tests stay readable, but it validates
every MAC and every key independently of the upload path.
"""

from __future__ import annotations

import contextlib
import hashlib
import secrets
import struct
import time
import zlib
from collections.abc import AsyncIterator
from typing import Any

from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from custom_components.mega_backup import client as mega

ROOT_HANDLE = "root0001"
INBOX_HANDLE = "inbox001"
RUBBISH_HANDLE = "trash001"
USER_HANDLE = "user0001"


def _mpi(value: int) -> bytes:
    """Encode an integer as a MEGA MPI."""
    bits = value.bit_length()
    return bits.to_bytes(2, "big") + value.to_bytes((bits + 7) // 8, "big")


def reference_fingerprint_crc(data: bytes) -> bytes:
    """Return the CRC half of MEGA's file fingerprint (the ``c`` attribute).

    This is a straightforward, full buffer implementation of MEGA's sparse file
    fingerprint, used by the emulator to check what the client uploaded.
    """
    size = len(data)
    if size <= mega.FINGERPRINT_CRC_SIZE:
        return data.ljust(mega.FINGERPRINT_CRC_SIZE, b"\0")
    if size <= mega.FINGERPRINT_FULL_COVERAGE:
        return b"".join(
            struct.pack(
                ">I",
                zlib.crc32(data[i * size // 4 : (i + 1) * size // 4]) & 0xFFFFFFFF,
            )
            for i in range(mega.FINGERPRINT_LANES)
        )

    span = size - mega.FINGERPRINT_BLOCK_SIZE
    denominator = mega.FINGERPRINT_LANES * mega.FINGERPRINT_BLOCKS_PER_LANE - 1
    lanes = []
    for lane in range(mega.FINGERPRINT_LANES):
        value = 0
        for block in range(mega.FINGERPRINT_BLOCKS_PER_LANE):
            index = lane * mega.FINGERPRINT_BLOCKS_PER_LANE + block
            offset = min(span * index // denominator, span)
            value = zlib.crc32(
                data[offset : offset + mega.FINGERPRINT_BLOCK_SIZE], value
            )
        lanes.append(struct.pack(">I", value & 0xFFFFFFFF))
    return b"".join(lanes)


class FakeMega:
    """Emulate the MEGA API for one account."""

    def __init__(
        self,
        *,
        email: str = "user@example.com",
        password: str = "correct horse battery staple",
        mfa_code: str | None = None,
        account_version: int = 1,
        text_completion_handle: bool = False,
        hashcash_bits: int | None = None,
        real_csid: bool = False,
    ) -> None:
        self.email = email.lower()
        self.password = password
        self.mfa_code = mfa_code
        self.account_version = account_version
        self.text_completion_handle = text_completion_handle
        self.hashcash_bits = hashcash_bits
        self.hashcash_token: str | None = None
        self.hashcash_token_request: str | None = None
        self.hashcash_challenges = 0
        self.hashcash_solved = False
        self.hashcash_solutions: list[str] = []
        self.hashcash_valid: set[str] = set()
        self.real_csid = real_csid

        self.master_key = secrets.token_bytes(16)
        self.user_handle = USER_HANDLE
        self.salt = secrets.token_bytes(16)

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        numbers = key.private_numbers()
        self._rsa = numbers
        privk = _mpi(numbers.p) + _mpi(numbers.q) + _mpi(numbers.d) + _mpi(numbers.iqmp)
        # MEGA encrypts the private key blob with AES-ECB, so pad it to a block.
        self._privk = privk.ljust((len(privk) + 15) // 16 * 16, b"\0")

        self.nodes: dict[str, dict[str, Any]] = {
            ROOT_HANDLE: {"h": ROOT_HANDLE, "t": 2, "ts": 0},
            INBOX_HANDLE: {"h": INBOX_HANDLE, "t": 3, "ts": 0},
            RUBBISH_HANDLE: {"h": RUBBISH_HANDLE, "t": 4, "ts": 0},
        }
        self.sessions: set[str] = set()
        self.uploads: dict[str, dict[str, Any]] = {}
        self.files: dict[str, bytes] = {}
        self.requests: list[dict[str, Any]] = []
        self.fail_next: list[int] = []
        self.app = web.Application()
        self.app.router.add_post("/cs", self._api)
        self.app.router.add_post("/upload/{handle}/{offset}", self._upload)
        self.app.router.add_get("/dl/{handle}/{start}-{end}", self._download)

        self._base = ""
        self._runner: web.AppRunner | None = None

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> str:
        """Start the server and return the API URL."""
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        self._base = f"http://127.0.0.1:{port}"
        return f"{self._base}/cs"

    async def stop(self) -> None:
        """Stop the server."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # -- helpers ------------------------------------------------------------

    @property
    def password_key(self) -> bytes:
        """Return the key used to protect login material."""
        if self.account_version == 2:
            derived = mega.derive_v2_key(self.password.encode("utf-8"), self.salt)
            return derived[0]
        return mega.prepare_key(self.password.encode("utf-8"))

    def _login_hash(self) -> str:
        """Return the expected ``uh`` value for the configured account."""
        if self.account_version == 2:
            derived = mega.derive_v2_key(self.password.encode("utf-8"), self.salt)
            return mega.b64url_encode(derived[1])
        password_key = mega.prepare_key(self.password.encode("utf-8"))
        return mega.b64url_encode(mega.string_hash(self.email, password_key))

    def _decrypt_node_key(self, node: dict[str, Any]) -> bytes:
        """Return the (merged) key of a node."""
        owner, _, encoded = str(node["k"]).partition(":")
        assert owner == self.user_handle
        return mega.aes_ecb_decrypt(self.master_key, mega.b64url_decode(encoded))

    def _node_payload(self, node: dict[str, Any]) -> dict[str, Any]:
        """Return a node as it is sent over the wire."""
        payload = {"h": node["h"], "t": node["t"], "ts": node["ts"]}
        if node["t"] == 0:
            payload["s"] = node["s"]
        if "p" in node:
            payload["p"] = node["p"]
        if "k" in node:
            payload["k"] = node["k"]
        if "a" in node:
            payload["a"] = node["a"]
        return payload

    def _children(self, handle: str) -> list[dict[str, Any]]:
        return [node for node in self.nodes.values() if node.get("p") == handle]

    def _find(self, parent: str, name: str) -> dict[str, Any] | None:
        """Find a node by name below a parent."""
        for node in self.nodes.values():
            if node.get("p") != parent:
                continue
            if "k" not in node:
                continue
            key = self._decrypt_node_key(node)
            attributes = mega.decrypt_attributes(mega.b64url_decode(node["a"]), key)
            if attributes.get("n") == name:
                return node
        return None

    def _accept_hashcash(self, token: str, request_id: str | None) -> bool:
        """Accept a solution for the current challenge or a solved one."""
        parts = token.split(":")
        if len(parts) == 3 and parts[1] in self.hashcash_valid:
            # A solved token stays valid for later requests, like on MEGA.
            return True
        if not self._verify_hashcash(token, request_id):
            return False
        assert self.hashcash_token is not None
        self.hashcash_valid.add(self.hashcash_token)
        return True

    def _verify_hashcash(self, token: str, request_id: str | None) -> bool:
        """Verify an ``X-Hashcash`` solution the way the MEGA servers do."""
        if self.hashcash_bits is None or self.hashcash_token is None:
            return False
        if request_id != self.hashcash_token_request:
            # MEGA binds the challenge to the request id it was issued for.
            return False
        parts = token.split(":")
        if len(parts) != 3 or parts[0] != "1" or parts[1] != self.hashcash_token:
            return False
        try:
            counter = mega.b64url_decode(parts[2])
            challenge_token = mega._b64_decode(self.hashcash_token)
        except ValueError:
            return False
        if len(counter) != 4:
            return False

        # The reference implementation hashes a buffer of a four byte counter
        # followed by the challenge token, repeated in 48 byte slots.
        easiness = self.hashcash_bits
        threshold = (((easiness & 63) << 1) + 1) << ((easiness >> 6) * 7 + 3)
        buffer = bytearray(4 + 262144 * 48)
        for index in range(262144):
            offset = 4 + index * 48
            buffer[offset : offset + len(challenge_token)] = challenge_token
        buffer[0:4] = counter
        return int.from_bytes(hashlib.sha256(buffer).digest()[:4], "big") <= threshold

    def _require_session(self, request: web.Request) -> str | None:
        """Return an error code if the request is not authenticated."""
        sid = request.query.get("sid")
        if not sid or sid not in self.sessions:
            return -15
        return None

    def _store_handle(self) -> str:
        """Return a fresh unused handle."""
        while True:
            handle = mega.b64url_encode(secrets.token_bytes(8))
            if handle not in self.nodes:
                return handle

    # -- API ----------------------------------------------------------------

    async def _api(self, request: web.Request) -> web.Response:
        if self.hashcash_bits is not None:
            token = request.headers.get("X-Hashcash")
            accepted = token is not None and self._accept_hashcash(
                token, request.query.get("id")
            )
            if not accepted:
                self.hashcash_challenges += 1
                self.hashcash_token = mega.b64url_encode(secrets.token_bytes(48))
                self.hashcash_token_request = request.query.get("id")
                challenge = (
                    f"1:{self.hashcash_bits}:{int(time.time())}:{self.hashcash_token}"
                )
                return web.Response(status=402, headers={"X-Hashcash": challenge})
            self.hashcash_solved = True
            self.hashcash_solutions.append(token)

        payload = (await request.json())[0]
        self.requests.append({**payload, "_query": dict(request.query)})

        if self.fail_next:
            return web.json_response([self.fail_next.pop(0)])

        command = payload.get("a")
        if command == "us0":
            if self.account_version == 2:
                return web.json_response([{"v": 2, "s": mega.b64url_encode(self.salt)}])
            return web.json_response([{"v": 1}])

        if command == "us":
            result = self._login(payload)
            return web.json_response([result])

        error = self._require_session(request)
        if error is not None:
            return web.json_response([error])

        handler = {
            "ug": self._user,
            "f": self._list,
            "p": self._create,
            "u": self._upload_url,
            "g": self._download_url,
            "d": self._delete,
            "uq": self._quota,
        }.get(str(command))
        if handler is None:
            return web.json_response([-2])
        return web.json_response([handler(payload)])

    def _login(self, payload: dict[str, Any]) -> dict[str, Any] | int:
        """Validate the login request and return the session material."""
        if str(payload.get("user", "")).lower() != self.email:
            return -9
        if payload.get("uh") != self._login_hash():
            return -9
        if self.mfa_code is not None:
            if not payload.get("mfa"):
                return -26
            if str(payload["mfa"]) != self.mfa_code:
                return -9

        sid_bytes = bytes([secrets.randbelow(254) + 1]) + secrets.token_bytes(42)

        numbers = self._rsa
        modulus = numbers.public_numbers.n
        block_size = (modulus.bit_length() + 7) // 8
        if self.real_csid:
            # Real MEGA encrypts a random block of the size of the modulus with
            # the session id in the most significant bytes.
            block = bytearray(secrets.token_bytes(block_size))
            block[0] = (block[0] & 0x7F) or 0x40
            plaintext = bytes(block)
            sid_bytes = plaintext[:43]
        else:
            plaintext = sid_bytes
        sid = mega.b64url_encode(sid_bytes)
        ciphertext = pow(
            int.from_bytes(plaintext, "big"), numbers.public_numbers.e, modulus
        )

        self.sessions.add(sid)
        return {
            "k": mega.b64url_encode(
                mega.aes_ecb_encrypt(self.password_key, self.master_key)
            ),
            "privk": mega.b64url_encode(
                mega.aes_ecb_encrypt(self.master_key, self._privk)
            ),
            "csid": mega.b64url_encode(_mpi(ciphertext)),
        }

    def _user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"u": self.user_handle, "name": "Test User"}

    def _list(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"f": [self._node_payload(node) for node in self.nodes.values()]}

    def _create(self, payload: dict[str, Any]) -> dict[str, Any]:
        parent = payload["t"]
        if parent not in self.nodes:
            return -9
        created = []
        for entry in payload["n"]:
            upload = self.uploads.get(str(entry["h"]))
            if entry["t"] == 0:
                if upload is None or not upload["complete"]:
                    return -9
                decrypted = self._decrypt_upload(upload, entry["k"])
                if decrypted is None:
                    return -14
                plain, merged_key = decrypted
                if not self._has_valid_fingerprint(entry, plain, merged_key):
                    return -14
            node: dict[str, Any] = {
                "h": self._store_handle() if entry["t"] == 1 else str(entry["h"]),
                "p": parent,
                "t": entry["t"],
                "ts": 1700000000,
                "a": entry["a"],
                "k": f"{self.user_handle}:{entry['k']}",
            }
            if entry["t"] == 0:
                node["s"] = upload["size"]
                self.files[node["h"]] = bytes(upload["data"])
            self.nodes[node["h"]] = node
            created.append(self._node_payload(node))
        return {"f": created}

    def _has_valid_fingerprint(
        self, entry: dict[str, Any], plain: bytes, merged_key: bytes
    ) -> bool:
        """Check that the node carries a correct ``c`` fingerprint attribute."""
        condensed_key = mega._xor(merged_key[:16], merged_key[16:32])
        attributes = mega.decrypt_attributes(
            mega.b64url_decode(str(entry["a"])), condensed_key
        )
        fingerprint = attributes.get("c")
        if not isinstance(fingerprint, str):
            return False

        raw = mega.b64url_decode(fingerprint)
        if len(raw) < mega.FINGERPRINT_CRC_SIZE + 2:
            return False
        if raw[mega.FINGERPRINT_CRC_SIZE] != len(raw) - mega.FINGERPRINT_CRC_SIZE - 1:
            return False
        return raw[: mega.FINGERPRINT_CRC_SIZE] == reference_fingerprint_crc(plain)

    def _decrypt_upload(
        self, upload: dict[str, Any], stored_key: str
    ) -> tuple[bytes, bytes] | None:
        """Verify the meta MAC of an upload and return its plaintext and key."""
        merged = mega.aes_ecb_decrypt(self.master_key, mega.b64url_decode(stored_key))
        key = merged[:16]
        nonce = merged[16:24]
        meta_mac = merged[24:32]

        mac = mega._MegaMac(key, nonce)
        decryptor = Cipher(
            algorithms.AES(key), modes.CTR(mega._ctr_iv(nonce))
        ).decryptor()
        plain = decryptor.update(bytes(upload["data"]))
        mac.update(plain)
        if mac.digest() != meta_mac:
            return None
        return plain, merged

    def _upload_url(self, payload: dict[str, Any]) -> dict[str, Any]:
        handle = mega.b64url_encode(secrets.token_bytes(8))
        self.uploads[handle] = {
            "size": int(payload["s"]),
            "data": bytearray(),
            "complete": False,
        }
        return {"p": f"{self._base}/upload/{handle}", "s": int(payload["s"])}

    def _download_url(self, payload: dict[str, Any]) -> dict[str, Any] | int:
        handle = str(payload.get("n", ""))
        node = self.nodes.get(handle)
        if node is None or node["t"] != 0:
            return -9
        return {"g": f"{self._base}/dl/{handle}", "s": node["s"]}

    def _delete(self, payload: dict[str, Any]) -> int:
        handles = payload["n"]
        if isinstance(handles, str):
            handles = [handles]
        for handle in handles:
            if handle not in self.nodes:
                return -9
            for child in list(self._children(handle)):
                self._delete({"n": child["h"]})
            del self.nodes[handle]
            self.files.pop(handle, None)
        return 0

    def _quota(self, payload: dict[str, Any]) -> dict[str, Any]:
        used = sum(node.get("s", 0) for node in self.nodes.values())
        return {"cstrg": used, "mstrg": 100 * 1024 * 1024, "usl": used}

    # -- transfers ----------------------------------------------------------

    async def _upload(self, request: web.Request) -> web.Response:
        upload = self.uploads.get(request.match_info["handle"])
        if upload is None:
            return web.Response(status=404)
        offset = int(request.match_info["offset"])
        data = await request.read()
        if offset != len(upload["data"]):
            return web.Response(status=500, text="-7")

        upload["data"].extend(data)
        if len(upload["data"]) > upload["size"]:
            return web.Response(status=500, text="-5")

        if len(upload["data"]) == upload["size"]:
            upload["complete"] = True
            handle = next(
                name for name, value in self.uploads.items() if value is upload
            )
            raw = mega._b64_decode(handle)[:8].ljust(8, b"\0")
            if self.text_completion_handle:
                return web.Response(body=handle.encode())
            return web.Response(body=raw)
        return web.Response(body=b"")

    async def _download(self, request: web.Request) -> web.StreamResponse:
        handle = request.match_info["handle"]
        data = self.files.get(handle)
        if data is None:
            return web.Response(status=404)
        start = int(request.match_info["start"])
        end = int(request.match_info["end"])
        return web.Response(body=data[start : end + 1])


@contextlib.asynccontextmanager
async def running_mega(**kwargs: Any) -> AsyncIterator[tuple[FakeMega, str]]:
    """Start a fake MEGA account and yield it together with its API URL."""
    fake = FakeMega(**kwargs)
    url = await fake.start()
    try:
        yield fake, url
    finally:
        await fake.stop()
