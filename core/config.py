"""Config loading for gravyard.

Looks for a TOML config file at the first of:
  1. ``$GRAVYARD_CONFIG``
  2. ``./gravyard.toml``
  3. ``~/.config/gravyard/config.toml``

Example ``gravyard.toml``::

    [crypto]
    default_wordlist = "/usr/share/wordlists/rockyou.txt"

Tools read settings via ``get_setting(section, key, default)`` so a config
file is never required.
"""

from __future__ import annotations

import os
from pathlib import Path

_cache: dict | None = None


def config_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("GRAVYARD_CONFIG")
    if env:
        paths.append(Path(env))
    paths.append(Path.cwd() / "gravyard.toml")
    paths.append(Path.home() / ".config" / "gravyard" / "config.toml")
    return paths


def load_config(path: str | Path | None = None, refresh: bool = False) -> dict:
    """Return the config dict (``{}`` when no config file exists)."""
    global _cache
    if path is None and _cache is not None and not refresh:
        return _cache
    data: dict = {}
    candidates = [Path(path)] if path else config_paths()
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover — Python < 3.11
        tomllib = None  # type: ignore[assignment]
    for candidate in candidates:
        if tomllib and candidate.is_file():
            try:
                with candidate.open("rb") as fh:
                    data.update(tomllib.load(fh))
            except OSError:
                continue
            break
    if path is None:
        _cache = data
    return data


def get_setting(section: str, key: str, default=None):
    """Read ``[section] key`` from the config, falling back to ``default``."""
    value = load_config().get(section, {})
    if isinstance(value, dict):
        return value.get(key, default)
    return default
