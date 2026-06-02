"""MAC address to vendor name lookup using a bundled IEEE OUI-style table."""

from __future__ import annotations

import csv
import re
from functools import lru_cache
from pathlib import Path

OUI_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "oui.csv"


def lookup_vendor(mac: str) -> str | None:
    """Resolve the first 3 octets of `mac` to an organisation name.

    Accepts common MAC formats such as ``AA:BB:CC:DD:EE:FF``,
    ``AA-BB-CC-DD-EE-FF``, and ``aabb.ccdd.eeff``.
    """

    prefix = _normalise_prefix(mac)
    if not prefix:
        return None
    return _load_oui_table().get(prefix)


def _normalise_prefix(mac: str) -> str | None:
    hex_digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(hex_digits) < 6:
        return None
    return hex_digits[:6]


@lru_cache(maxsize=1)
def _load_oui_table() -> dict[str, str]:
    if not OUI_DATA_PATH.exists():
        return {}

    vendors: dict[str, str] = {}
    try:
        with OUI_DATA_PATH.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                prefix = _normalise_prefix(row.get("prefix", ""))
                vendor = (row.get("vendor") or "").strip()
                if prefix and vendor:
                    vendors[prefix] = vendor
    except OSError:
        return {}
    return vendors
