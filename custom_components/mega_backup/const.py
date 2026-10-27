"""Constants for the MEGA backup integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "mega_backup"

CONF_EMAIL: Final = "email"
CONF_FOLDER: Final = "folder"
CONF_MFA_CODE: Final = "mfa_code"
CONF_PASSWORD: Final = "password"
CONF_MASTER_KEY: Final = "master_key"
CONF_SESSION_ID: Final = "session_id"
CONF_USER_ID: Final = "user_id"

DEFAULT_FOLDER: Final = "Home Assistant Backups"

# File that stores the metadata of a backup next to the backup archive itself.
METADATA_SUFFIX: Final = ".metadata.json"

# Smallest amount of free space we require before starting an upload (1 MiB).
MIN_FREE_SPACE: Final = 1024 * 1024

DATA_LISTENERS: Final = "listeners"
