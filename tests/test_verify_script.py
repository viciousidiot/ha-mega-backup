"""Smoke test for ``scripts/verify_live.py`` against the in-process fake server."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import aiohttp
import pytest
from fake_mega import running_mega

from custom_components.mega_backup import client as mega

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_live.py"


def _load_script() -> ModuleType:
    """Import the verification script as a module."""
    spec = importlib.util.spec_from_file_location("verify_live", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_verify_script_passes_against_fake_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run every live check against the fake server so the script stays correct."""
    script = _load_script()

    async with running_mega() as (fake, url):
        monkeypatch.setattr(mega, "API_URL", url)
        script.CREDENTIALS = (fake.email, fake.password, None)
        checks = script.Checks()

        async with aiohttp.ClientSession() as session:
            await script.client_checks(session, checks, "HA-Backup-Verify-Test")
            await script.agent_checks(session, checks, "HA-Backup-Verify-Agent-Test")
            await script.cleanup(
                session,
                ["HA-Backup-Verify-Test", "HA-Backup-Verify-Agent-Test"],
                checks,
            )

    assert checks.failures == []
    assert checks.failed == 0
    assert checks.passed > 10
