"""The MEGA backup integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .backup import async_notify_listeners
from .client import (
    MegaAuthError,
    MegaClient,
    MegaConnectionError,
    MegaError,
    MegaSession,
    b64url_decode,
    b64url_encode,
)
from .const import CONF_MASTER_KEY, CONF_SESSION_ID, CONF_USER_ID

_LOGGER = logging.getLogger(__name__)

type MegaBackupConfigEntry = ConfigEntry[MegaClient]


async def async_setup_entry(hass: HomeAssistant, entry: MegaBackupConfigEntry) -> bool:
    """Set up a MEGA backup account."""
    stored_session = _restore_session(entry)
    client = MegaClient(
        session=async_get_clientsession(hass),
        email=entry.data[CONF_EMAIL],
        password=entry.data[CONF_PASSWORD],
        session_data=stored_session,
    )

    try:
        await client.async_ensure_session()
    except MegaAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except MegaConnectionError as err:
        raise ConfigEntryNotReady(str(err)) from err
    except MegaError as err:
        raise ConfigEntryNotReady(str(err)) from err

    entry.runtime_data = client
    _store_session(hass, entry, client)
    async_notify_listeners(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: MegaBackupConfigEntry) -> bool:
    """Unload a MEGA backup account."""
    # The MEGA session is left alone on purpose: it stays valid and can be
    # reused after a restart or a reload.
    async_notify_listeners(hass)
    return True


def _restore_session(entry: ConfigEntry) -> MegaSession | None:
    """Return the persisted MEGA session, if there is one."""
    sid = entry.data.get(CONF_SESSION_ID)
    master_key = entry.data.get(CONF_MASTER_KEY)
    if not sid or not master_key:
        return None
    try:
        key = b64url_decode(str(master_key))
    except ValueError:
        _LOGGER.warning("Stored MEGA session is corrupt, logging in again")
        return None
    return MegaSession(
        sid=str(sid),
        master_key=key,
        user_id=str(entry.data.get(CONF_USER_ID, "")),
    )


def _store_session(
    hass: HomeAssistant, entry: MegaBackupConfigEntry, client: MegaClient
) -> None:
    """Persist the current MEGA session so restarts do not need a new login."""
    try:
        session = client.session
    except MegaError:
        return

    data = dict(entry.data)
    updates = {
        CONF_SESSION_ID: session.sid,
        CONF_MASTER_KEY: b64url_encode(session.master_key),
        CONF_USER_ID: session.user_id,
    }
    if all(data.get(key) == value for key, value in updates.items()):
        return
    data.update(updates)
    hass.config_entries.async_update_entry(entry, data=data)
