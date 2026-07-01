"""On-disk JSON cache for OSV responses (keyed by ecosystem/name/version)."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "depdrift" / "osv"
TTL_SECONDS = 7 * 24 * 3600  # 7 days

_SAFE = re.compile(r"[^A-Za-z0-9._@-]+")


def _key_path(ecosystem: str, name: str, version: str) -> Path:
    safe = _SAFE.sub("_", f"{name}@{version}")
    return CACHE_DIR / ecosystem / f"{safe}.json"


def read(ecosystem: str, name: str, version: str, ttl: int = TTL_SECONDS) -> dict | None:
    """Return the cached OSV response, or None on miss / expiry / corruption."""
    path = _key_path(ecosystem, name, version)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > ttl:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def write(ecosystem: str, name: str, version: str, data: dict) -> None:
    """Write an OSV response to the cache (best-effort; never raises)."""
    path = _key_path(ecosystem, name, version)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
