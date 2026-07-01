"""Abandonment detection: flag deps whose last release is older than a threshold.

The only strictly-online enricher — it hits PyPI / npm registry metadata. It is
opt-in (skipped in offline mode) and unit-tested against recorded fixtures by
injecting a ``fetcher`` callable, so no network is required for tests.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from typing import Callable

from ..models import Ecosystem

Fetcher = Callable[[str, Ecosystem], dict]


def _http_fetch(name: str, ecosystem: Ecosystem) -> dict:
    if ecosystem == Ecosystem.PYPI:
        url = f"https://pypi.org/pypi/{name}/json"
    else:
        url = f"https://registry.npmjs.org/{name}"
    with urllib.request.urlopen(url, timeout=10.0) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _parse_iso(value: str) -> datetime | None:
    v = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        try:
            dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def last_release_date(name: str, ecosystem: Ecosystem, metadata: dict) -> datetime | None:
    """Extract the most recent release timestamp from registry metadata."""
    times: list[datetime] = []
    if ecosystem == Ecosystem.PYPI:
        for files in (metadata.get("releases") or {}).values():
            for f in files or []:
                stamp = f.get("upload_time_iso_8601") or f.get("upload_time")
                if stamp:
                    dt = _parse_iso(stamp)
                    if dt:
                        times.append(dt)
    else:  # npm
        time_map = metadata.get("time") or {}
        for key, stamp in time_map.items():
            if key in ("created", "modified"):
                continue
            dt = _parse_iso(stamp)
            if dt:
                times.append(dt)
    return max(times, default=None)


def check(
    name: str,
    ecosystem: Ecosystem,
    threshold_years: float = 2.0,
    now: datetime | None = None,
    fetcher: Fetcher = _http_fetch,
) -> dict | None:
    """Return evidence dict if the package's last release is over the threshold.

    Returns ``{"last_release": iso, "age_years": float}`` when abandoned, else None.
    """
    now = now or datetime.now(timezone.utc)
    try:
        metadata = fetcher(name, ecosystem)
    except Exception:
        return None
    last = last_release_date(name, ecosystem, metadata)
    if last is None:
        return None
    age_years = (now - last).days / 365.25
    if age_years >= threshold_years:
        return {"last_release": last.date().isoformat(), "age_years": round(age_years, 1)}
    return None
