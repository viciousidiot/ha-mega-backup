"""Backup agent that stores Home Assistant backups on a MEGA account."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import datetime
from typing import Any, override

from homeassistant.components.backup import (
    AgentBackup,
    BackupAgent,
    BackupAgentError,
    BackupNotFound,
    OnProgressCallback,
    suggested_filename,
)
from homeassistant.components.backup.agent import BackupAgentUnreachableError
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .client import (
    MegaClient,
    MegaConnectionError,
    MegaError,
    MegaNode,
    MegaNotFound,
)
from .const import (
    CONF_EMAIL,
    CONF_FOLDER,
    DATA_LISTENERS,
    DEFAULT_FOLDER,
    DOMAIN,
    METADATA_SUFFIX,
    MIN_FREE_SPACE,
)

_LOGGER = logging.getLogger(__name__)


def _fingerprint_mtime(backup: AgentBackup) -> int:
    """Return the backup date as a Unix timestamp for MEGA's fingerprint."""
    try:
        parsed = datetime.fromisoformat(backup.date)
    except (TypeError, ValueError):
        return int(time.time())
    return int(parsed.timestamp())


@callback
def async_notify_listeners(hass: HomeAssistant) -> None:
    """Tell the backup integration that the available agents changed."""
    for listener in hass.data.get(DOMAIN, {}).get(DATA_LISTENERS, ()):
        listener()


@callback
def async_register_listener(
    hass: HomeAssistant, listener: Callable[[], None]
) -> Callable[[], None]:
    """Register a listener that is called when agents are added or removed."""
    listeners: list[Callable[[], None]] = hass.data.setdefault(DOMAIN, {}).setdefault(
        DATA_LISTENERS, []
    )
    listeners.append(listener)

    @callback
    def unregister() -> None:
        if listener in listeners:
            listeners.remove(listener)

    return unregister


async def async_get_backup_agents(
    hass: HomeAssistant, **kwargs: Any
) -> list[BackupAgent]:
    """Return one backup agent per configured MEGA account."""
    agents: list[BackupAgent] = []
    for entry in hass.config_entries.async_loaded_entries(DOMAIN):
        client: MegaClient | None = getattr(entry, "runtime_data", None)
        if client is None:
            continue
        agents.append(MegaBackupAgent(hass, entry, client))
    return agents


@callback
def async_register_backup_agents_listener(
    hass: HomeAssistant,
    *,
    listener: Callable[[], None],
    **kwargs: Any,
) -> Callable[[], None]:
    """Register a listener to be called when agents are added or removed."""
    return async_register_listener(hass, listener)


class MegaBackupAgent(BackupAgent):
    """A backup agent storing backups in a MEGA cloud drive folder."""

    domain = DOMAIN

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: MegaClient
    ) -> None:
        """Initialize the agent."""
        super().__init__()
        self._hass = hass
        self._entry = entry
        self._client = client
        self._folder = str(
            entry.options.get(CONF_FOLDER, entry.data.get(CONF_FOLDER, DEFAULT_FOLDER))
        )
        self._folder_handle: str | None = None
        self._folder_lock = asyncio.Lock()
        self.name = f"MEGA ({entry.data.get(CONF_EMAIL, client.user_id)})"
        self.unique_id = str(entry.unique_id or client.user_id)

    # -- helpers ------------------------------------------------------------

    def _wrap_error(self, err: MegaError) -> BackupAgentError:
        """Translate a client error into a backup agent error."""
        if isinstance(err, MegaConnectionError):
            return BackupAgentUnreachableError(str(err))
        if isinstance(err, MegaNotFound):
            return BackupNotFound(str(err))
        return BackupAgentError(str(err))

    async def _async_folder(self, *, refresh: bool = False) -> str:
        """Return the handle of the folder backups are stored in."""
        async with self._folder_lock:
            if self._folder_handle is None or refresh:
                self._folder_handle = await self._client.async_resolve_folder(
                    self._folder
                )
            return self._folder_handle

    async def _async_children(self) -> list[MegaNode]:
        """Return the files in the backup folder."""
        handle = await self._async_folder()
        try:
            children = await self._client.async_list_folder(handle)
        except MegaNotFound:
            # The folder was removed behind our back, create it again.
            handle = await self._async_folder(refresh=True)
            children = await self._client.async_list_folder(handle)
        return [node for node in children if node.is_file]

    async def _async_index(self) -> dict[str, tuple[MegaNode, MegaNode, AgentBackup]]:
        """Return backups keyed by backup id with their tar and metadata nodes."""
        children = await self._async_children()
        by_name = {node.name: node for node in children}
        index: dict[str, tuple[MegaNode, MegaNode, AgentBackup]] = {}

        for node in children:
            if not node.name.endswith(METADATA_SUFFIX):
                continue
            tar_name = node.name[: -len(METADATA_SUFFIX)]
            tar_node = by_name.get(tar_name)
            if tar_node is None:
                _LOGGER.debug("Ignoring orphaned backup metadata %s", node.name)
                continue
            try:
                raw = await self._client.async_read_file(node)
                backup = AgentBackup.from_dict(json.loads(raw))
            except (MegaError, ValueError, KeyError, TypeError) as err:
                _LOGGER.warning(
                    "Ignoring unreadable backup metadata %s: %s", node.name, err
                )
                continue
            index[backup.backup_id] = (tar_node, node, backup)

        return index

    async def _async_get(
        self, backup_id: str
    ) -> tuple[MegaNode, MegaNode, AgentBackup]:
        """Return the nodes and metadata of a backup."""
        index = await self._async_index()
        try:
            return index[backup_id]
        except KeyError as err:
            raise BackupNotFound(f"Backup {backup_id} not found") from err

    # -- BackupAgent interface ---------------------------------------------

    @override
    async def async_list_backups(self, **kwargs: Any) -> list[AgentBackup]:
        """List the backups stored on MEGA."""
        try:
            index = await self._async_index()
        except MegaError as err:
            raise self._wrap_error(err) from err
        return [backup for _, _, backup in index.values()]

    @override
    async def async_get_backup(self, backup_id: str, **kwargs: Any) -> AgentBackup:
        """Return the metadata of a backup."""
        try:
            _, _, backup = await self._async_get(backup_id)
        except MegaError as err:
            raise self._wrap_error(err) from err
        return backup

    @override
    async def async_download_backup(
        self, backup_id: str, **kwargs: Any
    ) -> AsyncIterator[bytes]:
        """Download a backup archive."""
        try:
            tar_node, _, _ = await self._async_get(backup_id)
        except MegaError as err:
            raise self._wrap_error(err) from err
        return self._client.async_download_file(tar_node)

    @override
    async def async_delete_backup(self, backup_id: str, **kwargs: Any) -> None:
        """Delete a backup archive together with its metadata."""
        try:
            tar_node, meta_node, _ = await self._async_get(backup_id)
            await self._client.async_delete_node(tar_node.handle)
            await self._client.async_delete_node(meta_node.handle)
        except MegaError as err:
            raise self._wrap_error(err) from err

    @override
    async def async_upload_backup(
        self,
        *,
        open_stream: Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]]],
        backup: AgentBackup,
        on_progress: OnProgressCallback,
        **kwargs: Any,
    ) -> None:
        """Upload a backup archive and its metadata to MEGA."""
        try:
            index = await self._async_index()
        except MegaError as err:
            raise self._wrap_error(err) from err

        if backup.backup_id in index:
            _LOGGER.debug("Backup %s already exists on MEGA", backup.backup_id)
            return

        self._async_check_quota(await self._async_usage(), backup.size)

        folder = await self._async_folder()
        filename = suggested_filename(backup)
        mtime = _fingerprint_mtime(backup)

        tar_node: MegaNode | None = None
        try:
            stream = await open_stream()
            tar_node = await self._client.async_upload_file(
                parent=folder,
                name=filename,
                size=backup.size,
                stream=stream,
                on_progress=on_progress,
                mtime=mtime,
            )
            metadata = json.dumps(backup.as_dict()).encode("utf-8")
            await self._client.async_upload_file(
                parent=folder,
                name=f"{filename}{METADATA_SUFFIX}",
                size=len(metadata),
                stream=_single_block(metadata),
                mtime=mtime,
            )
        except MegaError as err:
            if tar_node is not None:
                # Do not leave a backup behind that Home Assistant cannot see.
                try:
                    await self._client.async_delete_node(tar_node.handle)
                except MegaError:
                    _LOGGER.debug("Could not remove incomplete backup", exc_info=True)
            raise self._wrap_error(err) from err

    async def _async_usage(self) -> tuple[int, int] | None:
        """Return the storage usage of the account, or None if unknown."""
        try:
            return await self._client.async_get_storage_usage()
        except MegaError:
            # Quota information is only used as a fast fail, ignore problems.
            return None

    @staticmethod
    def _async_check_quota(usage: tuple[int, int] | None, size: int) -> None:
        """Verify the account has room for another backup."""
        if usage is None:
            return
        used, total = usage
        if total and used + size + MIN_FREE_SPACE > total:
            raise BackupAgentError(
                "Not enough free space on the MEGA account for this backup"
            )


async def _single_block(data: bytes) -> AsyncIterator[bytes]:
    """Yield the given bytes as one async block."""
    yield data
