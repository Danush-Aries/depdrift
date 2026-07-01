"""OSV.dev client — offline (fixture), cached, or live modes.

Live mode POSTs to ``https://api.osv.dev/v1/query`` (free, keyless) using stdlib
``urllib`` so the package has no heavy HTTP dependency. Offline mode — the default
in tests and the demo — never touches the network: it reads recorded responses
from the bundled fixture directory, treating a missing file as "no known vulns".
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from ..models import Ecosystem, Severity, Vuln
from . import cache as _cache

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

DATA_DIR = Path(__file__).parent / "data" / "osv_fixtures"

_SEV_STRINGS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MODERATE,
    "MEDIUM": Severity.MODERATE,
    "LOW": Severity.LOW,
}


def _severity_from_vuln(vuln: dict) -> Severity:
    ds = vuln.get("database_specific") or {}
    label = ds.get("severity")
    if isinstance(label, str) and label.upper() in _SEV_STRINGS:
        return _SEV_STRINGS[label.upper()]
    # Fallback: some entries carry a numeric CVSS base score.
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        try:
            base = float(score)
        except (TypeError, ValueError):
            continue
        if base <= 0:
            return Severity.NONE
        if base < 4:
            return Severity.LOW
        if base < 7:
            return Severity.MODERATE
        if base < 9:
            return Severity.HIGH
        return Severity.CRITICAL
    return Severity.NONE


def _fixed_version_from_vuln(vuln: dict) -> str | None:
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                for event in rng.get("events") or []:
                    if "fixed" in event:
                        return event["fixed"]
    return None


def _first_reference(vuln: dict) -> str | None:
    refs = vuln.get("references") or []
    if refs and isinstance(refs[0], dict):
        return refs[0].get("url")
    return None


def parse_osv_response(data: dict) -> list[Vuln]:
    """Turn a raw OSV /v1/query response into a list of Vuln records."""
    out: list[Vuln] = []
    for vuln in data.get("vulns") or []:
        summary = vuln.get("summary") or (vuln.get("details") or "")[:200]
        out.append(
            Vuln(
                id=vuln.get("id", ""),
                aliases=tuple(vuln.get("aliases") or ()),
                summary=summary,
                severity=_severity_from_vuln(vuln),
                fixed_version=_fixed_version_from_vuln(vuln),
                reference_url=_first_reference(vuln),
            )
        )
    return out


class NetworkDisabledError(RuntimeError):
    """Raised if a live request is attempted while offline."""


class OSVClient:
    """Query OSV for a package@version. ``mode`` is live | cached | offline."""

    def __init__(
        self,
        mode: str = "offline",
        fixture_dir: Path | None = None,
        timeout: float = 10.0,
    ) -> None:
        if mode not in ("live", "cached", "offline"):
            raise ValueError(f"unknown OSV mode: {mode!r}")
        self.mode = mode
        self.fixture_dir = Path(fixture_dir) if fixture_dir else DATA_DIR
        self.timeout = timeout

    def query(self, name: str, ecosystem: Ecosystem, version: str) -> list[Vuln]:
        if self.mode == "offline":
            data = self._read_fixture(name, ecosystem, version)
            return parse_osv_response(data)
        if self.mode == "cached":
            cached = _cache.read(ecosystem.value, name, version)
            if cached is not None:
                return parse_osv_response(cached)
            data = self._live_query(name, ecosystem, version)
            _cache.write(ecosystem.value, name, version, data)
            return parse_osv_response(data)
        # live
        data = self._live_query(name, ecosystem, version)
        _cache.write(ecosystem.value, name, version, data)
        return parse_osv_response(data)

    # --- internals ----------------------------------------------------
    def _read_fixture(self, name: str, ecosystem: Ecosystem, version: str) -> dict:
        path = self.fixture_dir / ecosystem.value / f"{name}@{version}.json"
        if not path.exists():
            return {}  # no recorded response == no known vulns
        return json.loads(path.read_text(encoding="utf-8"))

    def _live_query(self, name: str, ecosystem: Ecosystem, version: str) -> dict:
        body = json.dumps(
            {"package": {"name": name, "ecosystem": ecosystem.value}, "version": version}
        ).encode()
        req = urllib.request.Request(
            OSV_QUERY_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
