"""Verify the MEGA backup integration against a real MEGA account.

The script logs in with real credentials, exercises the low level client and the
Home Assistant backup agent, compares downloaded bytes, and (by default) removes
everything it created.

Credentials are read from, in order:

1. ``--creds <path>`` pointing at a JSON file ``{"email": ..., "password": ...}``
2. the ``MEGA_EMAIL`` / ``MEGA_PASSWORD`` environment variables
3. ``%TEMP%/opencode/mega_creds.json`` on Windows, ``/tmp/opencode/mega_creds.json``
   elsewhere

A TOTP code can be supplied through ``--mfa`` or the ``MEGA_MFA`` environment
variable when the account has two factor authentication enabled.

Usage::

    python scripts/verify_live.py [--creds PATH] [--mfa CODE] [--keep]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from custom_components.mega_backup.backup import MegaBackupAgent
from custom_components.mega_backup.client import (
    MegaAuthError,
    MegaClient,
    MegaMfaRequired,
    MegaNode,
    MegaSession,
)

try:
    from homeassistant.components.backup import AgentBackup
except ImportError:  # pragma: no cover - only when Home Assistant is missing
    AgentBackup = None  # type: ignore[assignment,misc]

BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

CREDENTIALS: tuple[str, str, str | None] = ("", "", None)


class Checks:
    """Tiny assertion collector so one failure does not hide the rest."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def check(self, condition: bool, message: str) -> None:
        if condition:
            self.passed += 1
            print(f"  {GREEN}PASS{RESET} {message}")
        else:
            self.failed += 1
            self.failures.append(message)
            print(f"  {RED}FAIL{RESET} {message}")

    def equal(self, actual: object, expected: object, message: str) -> None:
        self.check(actual == expected, f"{message} (got {actual!r})")

    def summary(self) -> bool:
        print()
        if self.failed:
            print(f"{RED}{self.failed} check(s) failed{RESET}, {self.passed} passed")
            for failure in self.failures:
                print(f"  - {failure}")
            return False
        print(f"{GREEN}All {self.passed} checks passed{RESET}")
        return True


def load_credentials(path: str | None) -> tuple[str, str]:
    """Return the email and password to log in with."""
    if path:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return str(data["email"]), str(data["password"])

    email = os.environ.get("MEGA_EMAIL")
    password = os.environ.get("MEGA_PASSWORD")
    if email and password:
        return email, password

    default = Path(tempfile.gettempdir()) / "opencode" / "mega_creds.json"
    if default.is_file():
        data = json.loads(default.read_text(encoding="utf-8"))
        return str(data["email"]), str(data["password"])

    raise SystemExit(
        "No credentials found.\n"
        "Provide --creds <file>, set MEGA_EMAIL and MEGA_PASSWORD, or write\n"
        f'{default} with {{"email": "...", "password": "..."}}'
    )


async def stream(data: bytes, block: int = 64 * 1024) -> AsyncIterator[bytes]:
    """Yield ``data`` in blocks, like a Home Assistant backup stream."""
    for offset in range(0, len(data), block):
        yield data[offset : offset + block]


def opener(data: bytes) -> Callable[[], Coroutine[Any, Any, AsyncIterator[bytes]]]:
    """Return the ``open_stream`` callback Home Assistant expects."""

    async def open_stream() -> AsyncIterator[bytes]:
        return stream(data)

    return open_stream


def digest(data: bytes) -> str:
    """Return the sha256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


async def download(node: MegaNode, client: MegaClient) -> bytes:
    """Read a node completely through the streaming API."""
    buffer = bytearray()
    async for chunk in client.async_download_file(node):
        buffer.extend(chunk)
    return bytes(buffer)


def find_folder(nodes: dict[str, MegaNode], path: str) -> str | None:
    """Return the handle of ``path`` without creating anything."""
    parent = MegaClient._root_handle(nodes)
    for part in path.strip("/").split("/"):
        matches = [
            node
            for node in nodes.values()
            if node.parent == parent and node.is_folder and node.name == part
        ]
        if not matches:
            return None
        parent = matches[0].handle
    return parent


async def client_checks(
    session: aiohttp.ClientSession, checks: Checks, folder: str
) -> None:
    """Exercise the low level client: upload, list, download, delete."""
    print(f"\n{BOLD}Client checks{RESET}")
    email, password, mfa = CREDENTIALS

    client = MegaClient(session=session, email=email, password=password)
    login = await client.async_login(mfa)
    print(f"  logged in as user {login.user_id}")
    checks.check(bool(login.sid), "login returns a session id")
    checks.check(bool(login.master_key), "login returns the master key")

    used, total = await client.async_get_storage_usage()
    print(f"  storage: {used / 1024**2:.1f} MiB used of {total / 1024**2:.1f} MiB")

    nodes = await client.async_list_nodes()
    checks.check(len(nodes) > 0, f"root listing returned {len(nodes)} nodes")

    handle = await client.async_resolve_folder(folder)
    checks.check(handle != MegaClient._root_handle(nodes), "test folder was created")

    payload = secrets.token_bytes(3 * 1024 * 1024 + 12345)
    name = f"verify-{int(time.time())}.bin"
    node = await client.async_upload_file(
        parent=handle, name=name, size=len(payload), stream=stream(payload)
    )
    print(f"  uploaded {name} ({node.size} bytes) as {node.handle}")
    checks.equal(node.size, len(payload), "uploaded node reports the right size")
    checks.equal(node.name, name, "uploaded node reports the right name")

    children = {child.name: child for child in await client.async_list_folder(handle)}
    checks.check(name in children, "uploaded file is listed in the folder")

    if name in children:
        downloaded = await download(children[name], client)
        checks.equal(len(downloaded), len(payload), "download returns the full file")
        checks.equal(
            digest(downloaded),
            digest(payload),
            "download content matches (MAC verified)",
        )

    await client.async_delete_node(node.handle)
    remaining = {child.name for child in await client.async_list_folder(handle)}
    checks.check(name not in remaining, "delete removes the uploaded file")


async def _agent_client(session: aiohttp.ClientSession) -> MegaClient:
    """Return a client that resumed its session, like a Home Assistant restart."""
    email, password, mfa = CREDENTIALS
    client = MegaClient(session=session, email=email, password=password)
    login = await client.async_login(mfa)
    resumed = MegaClient(
        session=session,
        email=email,
        password=password,
        session_data=MegaSession(
            sid=login.sid, master_key=login.master_key, user_id=login.user_id
        ),
    )
    await resumed.async_ensure_session()
    return resumed


async def agent_checks(
    session: aiohttp.ClientSession, checks: Checks, folder: str
) -> None:
    """Exercise the Home Assistant backup agent against the real account."""
    if AgentBackup is None:
        print(
            f"\n{YELLOW}Home Assistant is not installed, skipping agent checks{RESET}"
        )
        return

    print(f"\n{BOLD}Backup agent checks{RESET}")
    email = CREDENTIALS[0]

    client = await _agent_client(session)
    checks.equal(client.user_id, client.session.user_id, "persisted session resumes")

    entry = SimpleNamespace(
        data={"email": email, "folder": folder},
        options={},
        unique_id=client.user_id,
    )
    agent = MegaBackupAgent(None, entry, client)  # type: ignore[arg-type]

    payload = secrets.token_bytes(2 * 1024 * 1024 + 777)
    backup = AgentBackup(
        addons=[],
        backup_id=f"verify_{int(time.time())}",
        date=datetime.now(UTC).isoformat(),
        database_included=True,
        extra_metadata={"verified_by": "scripts/verify_live.py"},
        folders=[],
        homeassistant_included=True,
        homeassistant_version="2026.10.0",
        name="Live verification",
        protected=False,
        size=len(payload),
    )
    progress: list[Any] = []

    await agent.async_upload_backup(
        open_stream=opener(payload),
        backup=backup,
        on_progress=lambda *args, **kwargs: progress.append(args),
    )
    print(f"  uploaded backup {backup.backup_id} plus metadata sidecar")
    checks.check(len(progress) > 0, "upload reports progress callbacks")

    backups = await agent.async_list_backups()
    checks.check(
        backup.backup_id in {item.backup_id for item in backups},
        "backup is listed by the agent",
    )

    fetched = await agent.async_get_backup(backup.backup_id)
    checks.equal(fetched.name, backup.name, "metadata round-trips through MEGA")
    checks.equal(fetched.size, backup.size, "metadata size survives the round-trip")
    checks.equal(
        fetched.extra_metadata, backup.extra_metadata, "extra metadata survives"
    )

    chunks = bytearray()
    async for chunk in await agent.async_download_backup(backup.backup_id):
        chunks.extend(chunk)
    checks.equal(len(chunks), len(payload), "agent download returns the full archive")
    checks.equal(
        digest(bytes(chunks)), digest(payload), "agent download content matches"
    )

    handle = await client.async_resolve_folder(folder)
    before = {node.name for node in await client.async_list_folder(handle)}
    await agent.async_upload_backup(
        open_stream=opener(b"should not be uploaded"),
        backup=backup,
        on_progress=lambda *args, **kwargs: None,
    )
    after = {node.name for node in await client.async_list_folder(handle)}
    checks.equal(after, before, "re-uploading the same backup id is a no-op")
    checks.equal(len(after), 2, "backup is stored as archive plus sidecar")

    await agent.async_delete_backup(backup.backup_id)
    remaining = {item.backup_id for item in await agent.async_list_backups()}
    checks.check(
        backup.backup_id not in remaining, "delete removes the archive and sidecar"
    )


async def cleanup(
    session: aiohttp.ClientSession, folders: list[str], checks: Checks
) -> None:
    """Remove the folders created by the verification run."""
    print(f"\n{BOLD}Cleanup{RESET}")
    email, password, mfa = CREDENTIALS
    client = MegaClient(session=session, email=email, password=password)
    await client.async_login(mfa)
    nodes = await client.async_list_nodes()
    root = MegaClient._root_handle(nodes)

    for folder in folders:
        handle = find_folder(nodes, folder)
        if handle is None:
            print(f"  {folder} was never created")
            continue
        if handle == root:
            continue
        try:
            await client.async_delete_node(handle)
            print(f"  removed {folder}")
        except Exception as err:  # noqa: BLE001 - cleanup must not raise
            checks.failed += 1
            checks.failures.append(f"cleanup of {folder}: {err}")
            print(f"  {RED}could not remove {folder}: {err}{RESET}")


async def async_main(args: argparse.Namespace) -> int:
    global CREDENTIALS

    email, password = load_credentials(args.creds)
    mfa = args.mfa or os.environ.get("MEGA_MFA")
    CREDENTIALS = (email, password, mfa)

    stamp = int(time.time())
    client_folder = f"HA-Backup-Verify-{stamp}"
    agent_folder = f"HA-Backup-Verify-Agent-{stamp}"
    checks = Checks()

    timeout = aiohttp.ClientTimeout(total=None, connect=30, sock_read=300)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            await client_checks(session, checks, client_folder)
            await agent_checks(session, checks, agent_folder)
        except MegaMfaRequired:
            print(
                f"{RED}This account uses two factor authentication.{RESET}\n"
                "Re-run with --mfa <code> or set MEGA_MFA."
            )
            return 2
        except MegaAuthError as err:
            print(f"{RED}Login failed: {err}{RESET}")
            return 2
        finally:
            if args.keep:
                print(f"\nKeeping {client_folder} and {agent_folder} for inspection")
            else:
                await cleanup(session, [client_folder, agent_folder], checks)

    return 0 if checks.summary() else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the MEGA backup integration against a real account"
    )
    parser.add_argument("--creds", help="JSON file with email and password")
    parser.add_argument("--mfa", help="current TOTP code")
    parser.add_argument(
        "--keep", action="store_true", help="keep the test folders on the account"
    )
    return asyncio.run(async_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
