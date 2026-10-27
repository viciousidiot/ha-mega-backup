"""Tests for the config and options flows."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

import custom_components.mega_backup as integration
from custom_components.mega_backup import config_flow
from custom_components.mega_backup.client import (
    MegaAuthError,
    MegaConnectionError,
    MegaError,
    MegaFolderError,
    MegaMfaRequired,
    MegaSession,
    b64url_encode,
)
from custom_components.mega_backup.const import (
    CONF_EMAIL,
    CONF_FOLDER,
    CONF_MASTER_KEY,
    CONF_MFA_CODE,
    CONF_PASSWORD,
    CONF_SESSION_ID,
    CONF_USER_ID,
    DOMAIN,
)

EMAIL = "user@example.com"
PASSWORD = "correct horse battery staple"
FOLDER = "Home Assistant Backups"
USER_ID = "user0001"


class FakeMegaClient:
    """Stand-in for :class:`MegaClient` used by the flows."""

    def __init__(self, factory: ClientFactory) -> None:
        """Initialize the client."""
        self.factory = factory
        self.user_id = USER_ID
        self._session = MegaSession(
            sid="sid-123", master_key=bytes(range(16)), user_id=USER_ID
        )
        self.login_calls: list[str | None] = []
        self.folder_calls: list[str] = []

    async def async_login(self, mfa_code: str | None = None) -> MegaSession:
        """Pretend to log in."""
        self.login_calls.append(mfa_code)
        if self.factory.outcomes:
            raise self.factory.outcomes.pop(0)
        return self._session

    async def async_ensure_session(self) -> None:
        """Pretend to check a saved session."""
        if self.factory.outcomes:
            raise self.factory.outcomes.pop(0)

    async def async_resolve_folder(self, path: str) -> str:
        """Pretend to resolve a folder."""
        self.folder_calls.append(path)
        if self.factory.folder_error:
            raise MegaFolderError("could not use the folder")
        return "folder-handle"

    @property
    def session(self) -> MegaSession:
        """Return the fake session."""
        return self._session


class ClientFactory:
    """Create fake clients and control their behaviour."""

    def __init__(
        self, *, outcomes: tuple[Exception, ...] = (), folder_error: bool = False
    ) -> None:
        """Initialize the factory."""
        self.outcomes = list(outcomes)
        self.folder_error = folder_error
        self.clients: list[FakeMegaClient] = []

    def __call__(self, **kwargs: Any) -> FakeMegaClient:
        """Create a client."""
        client = FakeMegaClient(self)
        self.clients.append(client)
        return client


def _install(monkeypatch: pytest.MonkeyPatch, factory: Callable[..., Any]) -> None:
    """Replace the MEGA client used by the integration."""
    monkeypatch.setattr(config_flow, "MegaClient", factory)
    monkeypatch.setattr(integration, "MegaClient", factory)


async def _start_user_flow(hass: HomeAssistant) -> dict[str, Any]:
    """Start the user flow and return its first form."""
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )


async def test_user_flow(hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid account creates a fully populated config entry."""
    factory = ClientFactory()
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_EMAIL: "  User@Example.COM  ",
            CONF_PASSWORD: PASSWORD,
            CONF_FOLDER: "  My/Backups  ",
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"MEGA ({EMAIL})"
    assert result["data"] == {
        CONF_EMAIL: EMAIL,
        CONF_PASSWORD: PASSWORD,
        CONF_FOLDER: "My/Backups",
        CONF_SESSION_ID: "sid-123",
        CONF_MASTER_KEY: b64url_encode(bytes(range(16))),
        CONF_USER_ID: USER_ID,
    }
    assert factory.clients[0].folder_calls == ["My/Backups"]
    assert factory.clients[0].login_calls == [None]


async def test_user_flow_defaults_the_folder(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty folder falls back to the default folder."""
    factory = ClientFactory()
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: "   "},
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_FOLDER] == FOLDER


async def test_user_flow_invalid_auth(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wrong credentials are reported on the form."""
    factory = ClientFactory(outcomes=(MegaAuthError("bad credentials"),))
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: "wrong", CONF_FOLDER: FOLDER},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "invalid_auth"}


async def test_user_flow_cannot_connect(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Network problems are reported on the form."""
    factory = ClientFactory(outcomes=(MegaConnectionError("offline"),))
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: FOLDER},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_user_flow_unknown_error(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unexpected client errors are reported as unknown."""
    factory = ClientFactory(outcomes=(MegaError("boom"),))
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: FOLDER},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "unknown"}


async def test_user_flow_invalid_folder(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A folder that cannot be created is rejected."""
    factory = ClientFactory(folder_error=True)
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: "Bad/Folder"},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "invalid_folder"}
    assert factory.clients[0].folder_calls == ["Bad/Folder"]


async def test_user_flow_mfa(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An account with 2FA asks for a code and then logs in."""
    factory = ClientFactory(outcomes=(MegaMfaRequired("mfa required"),))
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: FOLDER},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "mfa"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MFA_CODE: "123456"}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_SESSION_ID] == "sid-123"
    assert factory.clients[0].login_calls == [None]
    assert factory.clients[1].login_calls == ["123456"]


async def test_user_flow_invalid_mfa(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rejected 2FA code keeps the user on the MFA step."""
    factory = ClientFactory(
        outcomes=(MegaMfaRequired("mfa required"), MegaAuthError("bad code"))
    )
    _install(monkeypatch, factory)

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_EMAIL: EMAIL, CONF_PASSWORD: PASSWORD, CONF_FOLDER: FOLDER},
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MFA_CODE: "000000"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "mfa"
    assert result["errors"] == {"base": "invalid_mfa"}


async def test_reauth_flow(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reauthentication replaces the stored password and session."""
    factory = ClientFactory()
    _install(monkeypatch, factory)
    monkeypatch.setattr(hass.config_entries, "async_schedule_reload", lambda _: None)

    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"MEGA ({EMAIL})",
        unique_id=USER_ID,
        data={
            CONF_EMAIL: EMAIL,
            CONF_PASSWORD: "old password",
            CONF_FOLDER: FOLDER,
            CONF_SESSION_ID: "old-sid",
            CONF_MASTER_KEY: "old-key",
            CONF_USER_ID: USER_ID,
        },
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: "new password"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new password"
    assert entry.data[CONF_SESSION_ID] == "sid-123"
    assert entry.data[CONF_MASTER_KEY] == b64url_encode(bytes(range(16)))


async def test_reauth_flow_invalid_auth(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wrong new password keeps the reauth form open."""
    factory = ClientFactory(outcomes=(MegaAuthError("bad credentials"),))
    _install(monkeypatch, factory)

    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"MEGA ({EMAIL})",
        unique_id=USER_ID,
        data={CONF_EMAIL: EMAIL, CONF_PASSWORD: "old", CONF_FOLDER: FOLDER},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_PASSWORD: "wrong"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"] == {"base": "invalid_auth"}


async def test_options_flow(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backup folder can be changed through the options flow."""
    factory = ClientFactory()
    _install(monkeypatch, factory)
    monkeypatch.setattr(hass.config_entries, "async_schedule_reload", lambda _: None)

    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"MEGA ({EMAIL})",
        unique_id=USER_ID,
        data={CONF_EMAIL: EMAIL, CONF_FOLDER: "Old/Folder"},
        options={},
    )
    entry.add_to_hass(hass)
    entry.runtime_data = factory()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_FOLDER: "  New/Folder  "}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_FOLDER] == "New/Folder"
    assert entry.runtime_data.folder_calls == ["New/Folder"]


async def test_options_flow_invalid_folder(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid folder is rejected by the options flow."""
    factory = ClientFactory(folder_error=True)
    _install(monkeypatch, factory)

    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"MEGA ({EMAIL})",
        unique_id=USER_ID,
        data={CONF_EMAIL: EMAIL, CONF_FOLDER: "Old/Folder"},
        options={},
    )
    entry.add_to_hass(hass)
    entry.runtime_data = factory()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {CONF_FOLDER: "Bad/Folder"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"
    assert result["errors"] == {"base": "invalid_folder"}
    assert CONF_FOLDER not in entry.options
