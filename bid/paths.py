"""
Where runtime state lives.

Stores, caches and journals go under one data directory: $BID_DATA_DIR when it
is set, else ./.bid in the working directory. Nothing is written inside the
installed package, so a read-only install (a container image, site-packages)
works, and one directory holds everything to back up or wipe.

The directory is read on every call, so setting BID_DATA_DIR after import (a
test, a CLI flag) takes effect.
"""
from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
FIXTURES = PACKAGE_DIR / "fixtures"


def data_dir() -> Path:
    """Root of all runtime state."""
    return Path(os.environ.get("BID_DATA_DIR") or ".bid").expanduser().resolve()


def store_dir(name: str = "store") -> Path:
    """Asset store and run outputs for one kind of run (pipeline, console, ...)."""
    return data_dir() / name


def cache_dir(name: str) -> Path:
    """Disposable cache (API responses, embeddings, model replies). Safe to delete."""
    return data_dir() / "cache" / name
