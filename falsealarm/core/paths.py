"""
Stable on-disk locations.

Everything FalseAlarm keeps between runs lives under one home directory so
``--diff``, ``--resume`` and ``list-scans`` work no matter which directory the
tool is started from:

    ~/.falsealarm/            (override with FALSEALARM_HOME)
        config.yaml           user defaults applied to every scan
        falsealarm.db         scan history (override with FALSEALARM_DB / --db)
        nuclei-templates/     `falsealarm templates update`
"""

from __future__ import annotations

import os
from pathlib import Path


def home_dir() -> Path:
    raw = os.environ.get("FALSEALARM_HOME")
    return Path(raw).expanduser() if raw else Path.home() / ".falsealarm"


def ensure_home() -> Path:
    path = home_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path() -> str:
    raw = os.environ.get("FALSEALARM_DB")
    if raw:
        return str(Path(raw).expanduser())
    return str(home_dir() / "falsealarm.db")


def user_config_path() -> Path:
    raw = os.environ.get("FALSEALARM_CONFIG")
    return Path(raw).expanduser() if raw else home_dir() / "config.yaml"


def nuclei_templates_dir() -> Path:
    return home_dir() / "nuclei-templates"
