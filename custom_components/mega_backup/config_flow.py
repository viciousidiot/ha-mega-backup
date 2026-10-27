"""Config flow for the MEGA backup integration."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import (
    MegaAuthError,
    MegaClient,
    MegaConnectionError,
    MegaError,
    MegaMfaRequired,
    b64url_encode,
)
from .const import (
    CONF_FOLDER,
    CONF_MASTER_KEY,
    CONF_MFA_CODE,
    CONF_SESSION_ID,
    CONF_USER_ID,
    DEFAULT_FOLDER,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_FOLDER, default=DEFAULT_FOLDER): str,
    }
)


class MegaBackupConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for a MEGA backup account."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the flow."""
        self._email = ""
        self._password = ""
        self._folder = DEFAULT_FOLDER
        self._reauth_entry: ConfigEntry | None = None

    # -- helpers ------------------------------------------------------------

    async def _async_connect(self, mfa_code: str | None = None) -> MegaClient:
        """Create a client and log in with the collected credentials."""
        client = MegaClient(
            session=async_get_clientsession(self.hass),
            email=self._email,
            password=self._password,
        )
        await client.async_login(mfa_code)
        return client

    async def _async_finish(
        self, client: MegaClient, step_id: str, errors: dict[str, str]
    ) -> ConfigFlowResult:
        """Store the session, either in a new or in the reauthenticated entry."""
        try:
            await client.async_resolve_folder(self._folder)
        except MegaError:
            _LOGGER.debug("Could not use folder %s", self._folder, exc_info=True)
            errors["base"] = "invalid_folder"
            return self.async_show_form(
                step_id=step_id, data_schema=self._schema(step_id), errors=errors
            )

        session = client.session
        data = {
            CONF_EMAIL: self._email,
            CONF_PASSWORD: self._password,
            CONF_FOLDER: self._folder,
            CONF_SESSION_ID: session.sid,
            CONF_MASTER_KEY: b64url_encode(session.master_key),
            CONF_USER_ID: session.user_id,
        }

        if self._reauth_entry is not None:
            return self.async_update_reload_and_abort(self._reauth_entry, data=data)

        await self.async_set_unique_id(session.user_id, raise_on_progress=False)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=f"MEGA ({self._email})", data=data)

    def _schema(self, step_id: str) -> vol.Schema:
        """Return the schema belonging to a step."""
        if step_id == "mfa":
            return vol.Schema({vol.Required(CONF_MFA_CODE): str})
        if step_id == "reauth_confirm":
            return vol.Schema({vol.Required(CONF_PASSWORD): str})
        return STEP_USER_DATA_SCHEMA

    async def _async_handle_login(
        self, step_id: str, errors: dict[str, str]
    ) -> ConfigFlowResult:
        """Log in and advance the flow, handling 2FA and errors."""
        try:
            client = await self._async_connect()
        except MegaMfaRequired:
            return await self.async_step_mfa()
        except MegaAuthError:
            errors["base"] = "invalid_auth"
        except MegaConnectionError:
            errors["base"] = "cannot_connect"
        except MegaError:
            _LOGGER.exception("Unexpected error while logging in to MEGA")
            errors["base"] = "unknown"
        else:
            return await self._async_finish(client, step_id, errors)

        return self.async_show_form(
            step_id=step_id, data_schema=self._schema(step_id), errors=errors
        )

    # -- steps --------------------------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._email = user_input[CONF_EMAIL].strip().lower()
            self._password = user_input[CONF_PASSWORD]
            self._folder = user_input.get(CONF_FOLDER, DEFAULT_FOLDER).strip()
            if not self._folder:
                self._folder = DEFAULT_FOLDER
            return await self._async_handle_login("user", errors)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the two-factor authentication step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                client = await self._async_connect(user_input[CONF_MFA_CODE])
            except MegaMfaRequired:
                errors["base"] = "invalid_mfa"
            except MegaAuthError:
                # The password was already accepted in the previous step, so
                # the code itself must have been wrong.
                errors["base"] = "invalid_mfa"
            except MegaConnectionError:
                errors["base"] = "cannot_connect"
            except MegaError:
                _LOGGER.exception("Unexpected error while verifying the MEGA 2FA code")
                errors["base"] = "unknown"
            else:
                return await self._async_finish(client, "mfa", errors)

        return self.async_show_form(
            step_id="mfa",
            data_schema=self._schema("mfa"),
            errors=errors,
            description_placeholders={"email": self._email},
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start reauthentication after the credentials stopped working."""
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if entry is None:
            return self.async_abort(reason="reauth_failed")
        self._reauth_entry = entry
        self._email = entry.data[CONF_EMAIL]
        self._folder = entry.data.get(CONF_FOLDER, DEFAULT_FOLDER)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for a new password."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._password = user_input[CONF_PASSWORD]
            return await self._async_handle_login("reauth_confirm", errors)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self._schema("reauth_confirm"),
            errors=errors,
            description_placeholders={"email": self._email},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> MegaBackupOptionsFlow:
        """Return the options flow."""
        return MegaBackupOptionsFlow()


class MegaBackupOptionsFlow(OptionsFlowWithReload):
    """Allow changing the folder backups are stored in."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            folder = user_input.get(CONF_FOLDER, DEFAULT_FOLDER).strip()
            if not folder:
                folder = DEFAULT_FOLDER
            client: MegaClient = self.config_entry.runtime_data
            try:
                await client.async_resolve_folder(folder)
            except MegaError:
                errors["base"] = "invalid_folder"
            else:
                return self.async_create_entry(title="", data={CONF_FOLDER: folder})

        current = self.config_entry.options.get(
            CONF_FOLDER, self.config_entry.data.get(CONF_FOLDER, DEFAULT_FOLDER)
        )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Optional(CONF_FOLDER, default=current): str}),
            errors=errors,
        )
