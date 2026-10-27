"""Tests for the Home Assistant backup agent backed by MEGA."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest
from fake_mega import running_mega
from homeassistant.components.backup import (
    AgentBackup,
    BackupAgentError,
    BackupNotFound,
    Folder,
    suggested_filename,
)
from homeassistant.components.backup.agent import BackupAgentUnreachableError
from homeassistant.core import HomeAssistant

from custom_components.mega_backup import client as mega_client
from custom_components.mega_backup.backup import MegaBackupAgent
from custom_components.mega_backup.const import CONF_EMAIL, CONF_FOLDER

FOLDER = "Home Assistant/Backups"


def _backup(
    *, backup_id: str = "backup-1", name: str = "Test backup", size: int = 1234
) -> AgentBackup:
    """Return a backup that can be stored on an agent."""
    return AgentBackup(
        addons=[],
        backup_id=backup_id,
        date="2026-10-26T12:00:00.000000+00:00",
        database_included=True,
        extra_metadata={"instance_id": "abc"},
        folders=[Folder.SHARE],
        homeassistant_included=True,
        homeassistant_version="2026.10.0",
        name=name,
        protected=False,
        size=size,
    )


async def _collect(stream: AsyncIterator[bytes]) -> bytes:
    """Collect an async byte stream."""
    return b"".join([chunk async for chunk in stream])


async def _stream(data: bytes) -> AsyncIterator[bytes]:
    """Yield data as a single block."""
    if data:
        yield data


def _open_stream(data: bytes) -> Any:
    """Return an ``open_stream`` callback as Home Assistant expects it."""

    async def open_stream() -> AsyncIterator[bytes]:
        return _stream(data)

    return open_stream


@contextlib.asynccontextmanager
async def _agent(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[Any, mega_client.MegaClient, MegaBackupAgent]]:
    """Start a fake MEGA account and a backup agent using it."""
    async with running_mega() as (fake, url):
        monkeypatch.setattr(mega_client, "API_URL", url)
        async with aiohttp.ClientSession() as session:
            client = mega_client.MegaClient(
                session=session, email=fake.email, password=fake.password
            )
            await client.async_login()
            entry = SimpleNamespace(
                data={CONF_EMAIL: fake.email, CONF_FOLDER: FOLDER},
                options={},
                unique_id=fake.user_handle,
            )
            yield fake, client, MegaBackupAgent(hass, entry, client)


async def test_upload_list_download_delete(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A backup is uploaded, listed, downloaded and deleted."""
    async with _agent(hass, monkeypatch) as (fake, client, agent):
        data = bytes(range(256)) * 1000
        backup = _backup(size=len(data))
        progress: list[int] = []

        await agent.async_upload_backup(
            open_stream=_open_stream(data),
            backup=backup,
            on_progress=lambda *, bytes_uploaded: progress.append(bytes_uploaded),
        )

        assert progress[-1] == len(data)
        assert agent.name == f"MEGA ({fake.email})"
        assert agent.unique_id == fake.user_handle

        backups = await agent.async_list_backups()
        assert backups == [backup]
        assert await agent.async_get_backup(backup.backup_id) == backup

        stream = await agent.async_download_backup(backup.backup_id)
        assert await _collect(stream) == data

        folder = await client.async_resolve_folder(FOLDER)
        children = {node.name: node for node in await client.async_list_folder(folder)}
        expected_name = suggested_filename(backup)
        assert set(children) == {
            expected_name,
            f"{expected_name}.metadata.json",
        }
        expected_mtime = int(datetime.fromisoformat(backup.date).timestamp())
        for node in children.values():
            raw = mega_client.b64url_decode(node.attributes["c"])
            assert raw[16] == len(raw) - 17
            assert int.from_bytes(raw[17:], "little") == expected_mtime

        await agent.async_delete_backup(backup.backup_id)

        assert await agent.async_list_backups() == []
        assert await client.async_list_folder(folder) == []
        with pytest.raises(BackupNotFound):
            await agent.async_get_backup(backup.backup_id)


async def test_upload_is_idempotent(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Uploading the same backup id twice does not create a second copy."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        data = b"backup data"
        backup = _backup(size=len(data))

        for _ in range(2):
            await agent.async_upload_backup(
                open_stream=_open_stream(data),
                backup=backup,
                on_progress=lambda **kwargs: None,
            )

        folder = await client.async_resolve_folder(FOLDER)
        assert len(await client.async_list_folder(folder)) == 2
        assert await agent.async_list_backups() == [backup]


async def test_orphaned_metadata_is_ignored(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Metadata without a matching archive does not show up as a backup."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        folder = await client.async_resolve_folder(FOLDER)
        await client.async_upload_file(
            parent=folder,
            name="orphan.tar.metadata.json",
            size=2,
            stream=_stream(b"{}"),
        )

        assert await agent.async_list_backups() == []


async def test_unreadable_metadata_is_ignored(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Broken metadata files are skipped instead of breaking every backup."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        folder = await client.async_resolve_folder(FOLDER)
        for name, data in (
            ("broken.tar", b"not a tar"),
            ("broken.tar.metadata.json", b"not json"),
            ("missing.tar.metadata.json", b"{}"),
        ):
            await client.async_upload_file(
                parent=folder, name=name, size=len(data), stream=_stream(data)
            )

        assert await agent.async_list_backups() == []


async def test_upload_failure_removes_the_partial_archive(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """A missing metadata upload does not leave an invisible archive behind."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        data = b"backup data"
        backup = _backup(size=len(data))

        original = client.async_upload_file
        calls = 0

        async def flaky_upload(**kwargs: Any) -> mega_client.MegaNode:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise mega_client.MegaConnectionError("metadata upload failed")
            return await original(**kwargs)

        monkeypatch.setattr(client, "async_upload_file", flaky_upload)

        with pytest.raises(BackupAgentUnreachableError):
            await agent.async_upload_backup(
                open_stream=_open_stream(data),
                backup=backup,
                on_progress=lambda **kwargs: None,
            )

        assert await agent.async_list_backups() == []
        folder = await client.async_resolve_folder(FOLDER)
        assert await client.async_list_folder(folder) == []


async def test_upload_checks_free_space(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """An upload is refused when the account has almost no space left."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        folder = await client.async_resolve_folder(FOLDER)
        assert folder

        total = 100 * 1024 * 1024
        monkeypatch.setattr(
            client,
            "async_get_storage_usage",
            AsyncMock(return_value=(total - 1, total)),
        )

        with pytest.raises(BackupAgentError):
            await agent.async_upload_backup(
                open_stream=_open_stream(b"x"),
                backup=_backup(size=1),
                on_progress=lambda **kwargs: None,
            )


async def test_errors_are_wrapped(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Client failures use the error types the backup manager expects."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        monkeypatch.setattr(
            client,
            "async_resolve_folder",
            AsyncMock(side_effect=mega_client.MegaConnectionError("offline")),
        )

        with pytest.raises(BackupAgentUnreachableError):
            await agent.async_list_backups()


async def test_missing_backups_raise_not_found(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """Unknown backup ids are reported as not found."""
    async with _agent(hass, monkeypatch) as (_fake, _client, agent):
        with pytest.raises(BackupNotFound):
            await agent.async_get_backup("unknown")

        with pytest.raises(BackupNotFound):
            await agent.async_download_backup("unknown")

        with pytest.raises(BackupNotFound):
            await agent.async_delete_backup("unknown")


async def test_old_folder_is_recreated(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch, socket_enabled: None
) -> None:
    """The backup folder is recreated when it disappears from the account."""
    async with _agent(hass, monkeypatch) as (_fake, client, agent):
        folder = await agent._async_folder()
        await client.async_delete_node(folder)

        assert await agent.async_list_backups() == []
        assert await client.async_list_nodes()
