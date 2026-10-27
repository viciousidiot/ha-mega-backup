"""End to end tests for the MEGA client against an in-process fake API."""

from __future__ import annotations

from collections.abc import AsyncIterator

import aiohttp
import pytest
from fake_mega import ROOT_HANDLE, running_mega

from custom_components.mega_backup import client as mega


async def _collect(stream: AsyncIterator[bytes]) -> bytes:
    """Collect an async byte stream."""
    return b"".join([chunk async for chunk in stream])


async def _stream(data: bytes) -> AsyncIterator[bytes]:
    """Yield data as a single block."""
    if data:
        yield data


async def _login(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    email: str,
    password: str,
    *,
    session_data: mega.MegaSession | None = None,
) -> tuple[aiohttp.ClientSession, mega.MegaClient]:
    """Create a client for the fake server and log it in."""
    monkeypatch.setattr(mega, "API_URL", url)
    session = aiohttp.ClientSession()
    client = mega.MegaClient(
        session=session,
        email=email,
        password=password,
        session_data=session_data,
    )
    await client.async_login()
    return session, client


@pytest.mark.parametrize(
    ("account_version", "mfa_code"),
    [(1, None), (2, None), (1, "123456"), (2, "123456")],
)
async def test_login(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
    account_version: int,
    mfa_code: str | None,
) -> None:
    """Log in with v1/v2 accounts, with and without 2FA."""
    async with running_mega(account_version=account_version, mfa_code=mfa_code) as (
        fake,
        url,
    ):
        monkeypatch.setattr(mega, "API_URL", url)
        async with aiohttp.ClientSession() as session:
            client = mega.MegaClient(
                session=session, email=fake.email, password=fake.password
            )
            if mfa_code is not None:
                with pytest.raises(mega.MegaMfaRequired):
                    await client.async_login()

            session_data = await client.async_login(mfa_code)

            assert session_data.user_id == fake.user_handle
            assert client.user_id == fake.user_handle
            assert client.logged_in
            assert client.session.sid == session_data.sid


async def test_login_rejects_bad_credentials(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A wrong password or email is reported as an authentication error."""
    async with running_mega() as (fake, url):
        monkeypatch.setattr(mega, "API_URL", url)
        async with aiohttp.ClientSession() as session:
            client = mega.MegaClient(
                session=session, email=fake.email, password="wrong password"
            )
            with pytest.raises(mega.MegaAuthError):
                await client.async_login()

            client = mega.MegaClient(
                session=session, email="other@example.com", password=fake.password
            )
            with pytest.raises(mega.MegaAuthError):
                await client.async_login()


async def test_login_rejects_bad_mfa_code(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A wrong two-factor code is reported as an authentication error."""
    async with running_mega(mfa_code="123456") as (fake, url):
        monkeypatch.setattr(mega, "API_URL", url)
        async with aiohttp.ClientSession() as session:
            client = mega.MegaClient(
                session=session, email=fake.email, password=fake.password
            )
            with pytest.raises(mega.MegaAuthError):
                await client.async_login("000000")


async def test_hashcash_challenge(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A 402 response with an X-Hashcash header is solved and retried."""
    async with running_mega(hashcash_bits=192) as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        try:
            assert client.logged_in
            assert fake.hashcash_solved
            assert fake.hashcash_challenges == 1
            solutions = len(fake.hashcash_solutions)
            assert solutions >= 1
            nodes = await client.async_list_nodes()
            assert nodes
            # The solved token is reused, so no new proof of work is needed.
            assert fake.hashcash_challenges == 1
            assert len(fake.hashcash_solutions) > solutions
        finally:
            await session.close()


@pytest.mark.parametrize("account_version", [1, 2])
async def test_login_with_full_size_csid(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None, account_version: int
) -> None:
    """The session id is the prefix of a modulus sized RSA plaintext."""
    async with running_mega(account_version=account_version, real_csid=True) as (
        fake,
        url,
    ):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        try:
            sid = client.session.sid
            assert len(sid) == 58
            assert sid in fake.sessions
        finally:
            await session.close()


async def test_session_is_reused(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A persisted session can be used without logging in again."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        session_data = client.session
        assert await client.async_get_storage_usage() == (0, 100 * 1024 * 1024)
        await session.close()

        requests_before = len(fake.requests)
        async with aiohttp.ClientSession() as new_session:
            resumed = mega.MegaClient(
                session=new_session,
                email=fake.email,
                password=fake.password,
                session_data=session_data,
            )
            await resumed.async_ensure_session()
            assert resumed.logged_in
            assert resumed.user_id == fake.user_handle
            assert resumed.session.sid == session_data.sid

        new_requests = fake.requests[requests_before:]
        assert not [request for request in new_requests if request["a"] == "us0"]


async def test_invalid_saved_session_logs_in_again(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """An expired persisted session is replaced with a fresh login."""
    async with running_mega() as (fake, url):
        monkeypatch.setattr(mega, "API_URL", url)
        async with aiohttp.ClientSession() as session:
            client = mega.MegaClient(
                session=session,
                email=fake.email,
                password=fake.password,
                session_data=mega.MegaSession(
                    sid="expired", master_key=bytes(16), user_id=fake.user_handle
                ),
            )
            await client.async_ensure_session()

            assert client.session.sid != "expired"
            assert client.user_id == fake.user_handle
            assert any(request["a"] == "us" for request in fake.requests)


async def test_resolve_folder_creates_nested_folders(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A nested folder path is created once and then reused."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            handle = await client.async_resolve_folder("Backups/Home Assistant")
            assert handle != ROOT_HANDLE
            assert (
                await client.async_resolve_folder("/Backups/Home Assistant/") == handle
            )

            nodes = await client.async_list_nodes()
            assert nodes[handle].name == "Home Assistant"
            parent = nodes[handle].parent
            assert parent is not None
            assert nodes[parent].name == "Backups"
            assert nodes[parent].parent == ROOT_HANDLE

            assert await client.async_list_folder(handle) == []

            folders = [node for node in fake.nodes.values() if node["t"] == 1]
            assert len(folders) == 2


async def test_resolve_folder_rejects_a_file_in_the_path(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A path component that is a file is not silently replaced."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            await client.async_upload_file(
                parent=ROOT_HANDLE,
                name="Backups",
                size=1,
                stream=_stream(b"x"),
            )
            with pytest.raises(mega.MegaFolderError):
                await client.async_resolve_folder("Backups/Home Assistant")


@pytest.mark.parametrize("text_completion_handle", [False, True])
@pytest.mark.parametrize("size", [0, 1, 16, 200_000, 1_500_000])
async def test_upload_download_delete(
    monkeypatch: pytest.MonkeyPatch,
    socket_enabled: None,
    text_completion_handle: bool,
    size: int,
) -> None:
    """Uploads are encrypted and registered, downloads verify their MAC."""
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    async with running_mega(text_completion_handle=text_completion_handle) as (
        fake,
        url,
    ):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            progress: list[int] = []

            node = await client.async_upload_file(
                parent=ROOT_HANDLE,
                name="backup.tar",
                size=len(data),
                stream=_stream(data),
                on_progress=lambda *, bytes_uploaded: progress.append(bytes_uploaded),
            )

            assert node.name == "backup.tar"
            assert node.size == len(data)
            assert node.is_file
            assert node.parent == ROOT_HANDLE
            assert progress[-1] == len(data)

            downloaded = await _collect(client.async_download_file(node))
            assert downloaded == data

            if size <= mega.MAX_METADATA_SIZE:
                assert await client.async_read_file(node) == data

            assert fake.files[node.handle] != data or size == 0

            await client.async_delete_node(node.handle)
            assert node.handle not in fake.nodes
            assert node.handle not in fake.files
            with pytest.raises(mega.MegaNotFound):
                await client.async_get_node(node.handle)


async def test_upload_checks_the_stream_size(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A stream that does not match the announced size is rejected."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            with pytest.raises(mega.MegaSizeMismatch):
                await client.async_upload_file(
                    parent=ROOT_HANDLE,
                    name="short.tar",
                    size=10,
                    stream=_stream(b"x" * 4),
                )

            with pytest.raises(mega.MegaSizeMismatch):
                await client.async_upload_file(
                    parent=ROOT_HANDLE,
                    name="long.tar",
                    size=4,
                    stream=_stream(b"x" * 10),
                )

            assert [node for node in fake.nodes.values() if node["t"] == 0] == []


async def test_quota_errors(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Quota errors are translated into a dedicated exception."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            fake.fail_next = [-17]
            with pytest.raises(mega.MegaQuotaError):
                await client.async_get_storage_usage()

            fake.fail_next = [-24]
            with pytest.raises(mega.MegaQuotaError):
                await client.async_get_storage_usage()


async def test_expired_session_is_refreshed_transparently(
    monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """The client logs in again when the server reports an expired session."""
    async with running_mega() as (fake, url):
        session, client = await _login(monkeypatch, url, fake.email, fake.password)
        async with session:
            fake.fail_next = [-15]

            assert await client.async_get_storage_usage() == (0, 100 * 1024 * 1024)
            assert (
                len([request for request in fake.requests if request["a"] == "us"]) == 2
            )


async def test_chunk_boundaries() -> None:
    """Chunk sizes match MEGA's growing 128 KiB / 1 MiB schedule."""
    assert mega.get_chunks(0) == []
    assert mega.get_chunks(1) == [(0, 1)]
    assert mega.get_chunks(mega.CHUNK_START) == [(0, mega.CHUNK_START)]
    assert mega.get_chunks(mega.CHUNK_START + 1) == [
        (0, mega.CHUNK_START),
        (mega.CHUNK_START, 1),
    ]

    chunks = mega.get_chunks(8 * 1024 * 1024)
    assert sum(length for _, length in chunks) == 8 * 1024 * 1024
    assert chunks[0] == (0, 128 * 1024)
    assert chunks[1] == (128 * 1024, 256 * 1024)
    assert chunks[2] == (384 * 1024, 384 * 1024)
    assert chunks[3] == (768 * 1024, 512 * 1024)
    assert chunks[4] == (1280 * 1024, 640 * 1024)
    assert chunks[5] == (1920 * 1024, 768 * 1024)
    assert chunks[6] == (2688 * 1024, 896 * 1024)
    assert chunks[7] == (3584 * 1024, 1024 * 1024)


def test_prepare_key_and_v2_derivation() -> None:
    """Key derivation helpers are deterministic."""
    assert mega.prepare_key(b"") == bytes.fromhex("93c467e37db0c7a4d1be3f810152cb56")
    assert mega.prepare_key(b"password") == mega.prepare_key(b"password")
    assert mega.prepare_key(b"password") != mega.prepare_key(b"passwore")

    key, auth = mega.derive_v2_key(b"password", bytes(16))
    assert len(key) == 16
    assert len(auth) == 16
    assert (key, auth) == mega.derive_v2_key(b"password", bytes(16))


def test_decode_upload_handle() -> None:
    """Both completion handle formats used by MEGA are accepted."""
    raw = bytes(range(8))
    assert mega._decode_upload_handle(raw) == mega.b64url_encode(raw)
    assert mega._decode_upload_handle(b"abcdefghijk") == "abcdefghijk"


def test_b64url_helpers() -> None:
    """MEGA's unpadded URL safe base64 round trips."""
    for data in (b"", b"a", b"ab", b"abc", bytes(range(32))):
        assert mega.b64url_decode(mega.b64url_encode(data)) == data
    assert mega.b64url_encode(b"\xfb\xff") == "-_8"
