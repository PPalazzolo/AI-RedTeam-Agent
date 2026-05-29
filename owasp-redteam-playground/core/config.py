"""Persistent user config stored at ~/.owasp-redteam/config.json.

Lives outside the repo so it survives git operations and is never accidentally
committed. The file is created with mode 0600 to keep the API key private.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".owasp-redteam"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS: dict[str, Any] = {
    "api_key": "",
    "default_model": "gpt-4o",
    "default_temperature": 0.7,
    "default_system_prompt": "You are a helpful assistant.",
}


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(mode=0o700, exist_ok=True)


def load() -> dict[str, Any]:
    """Load the full config dict (with defaults merged for missing keys)."""
    if not CONFIG_FILE.exists():
        return dict(DEFAULTS)
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULTS)
    merged = dict(DEFAULTS)
    merged.update(data)
    return merged


def save(updates: dict[str, Any]) -> dict[str, Any]:
    """Merge `updates` into the existing config and persist to disk."""
    _ensure_dir()
    current = load()
    current.update(updates)
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
    return current


def is_configured() -> bool:
    """True if an API key has been saved."""
    return bool(load().get("api_key", "").strip())


def get_api_key() -> str:
    """Return the saved API key (empty string if not configured)."""
    return load().get("api_key", "").strip()


def public_view() -> dict[str, Any]:
    """Config view safe to return to the frontend — never includes the API key."""
    cfg = load()
    return {
        "configured": is_configured(),
        "default_model": cfg["default_model"],
        "default_temperature": cfg["default_temperature"],
        "default_system_prompt": cfg["default_system_prompt"],
        "config_path": str(CONFIG_FILE),
    }
