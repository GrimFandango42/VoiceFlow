from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .config import Config
from .logging_setup import default_log_dir


def config_dir() -> Path:
    # Place alongside logs under LocalFlow
    base = default_log_dir().parent
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config(defaults: Config) -> Config:
    path = config_path()
    if not path.exists():
        return defaults
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return defaults
    # Apply known fields only
    for field in asdict(defaults).keys():
        if field in data:
            setattr(defaults, field, data[field])
    return defaults


def save_config(cfg: Config) -> None:
    path = config_path()
    try:
        path.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    except Exception:
        pass

