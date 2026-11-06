"""
Shared sensor helpers.

`FIXTURES` points at the bundled JSON so both sensors run with zero setup.
`load_fixture` is a tiny helper; nothing here talks to the network unless a real
credential is present (see meta_ad_library.py).
"""
from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
