"""Enrichment tests: OSV, typosquat, abandonment (13-20)."""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

from depdrift.enrich import abandonment, typosquat
from depdrift.enrich.osv import OSVClient
from depdrift.models import Ecosystem, Severity


def test_osv_offline_hits_fixture():
    vulns = OSVClient("offline").query("jinja2", Ecosystem.PYPI, "2.4.1")
    assert len(vulns) == 1
    v = vulns[0]
    assert v.id == "GHSA-462w-v97r-4m45"
    assert v.severity == Severity.HIGH
    assert "CVE-2019-10906" in v.aliases


def test_osv_offline_no_vuln_returns_empty():
    # no recorded fixture for this version == treated as no known vulns
    assert OSVClient("offline").query("jinja2", Ecosystem.PYPI, "3.1.0") == []


def test_osv_severity_and_fixed_version_parsing():
    v = OSVClient("offline").query("jinja2", Ecosystem.PYPI, "2.4.1")[0]
    assert v.fixed_version == "2.10.1"
    assert v.reference_url and v.reference_url.startswith("https://")


def test_osv_network_blocked_in_offline(monkeypatch):
    calls = {"n": 0}

    def _spy(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("offline mode must not touch the network")

    monkeypatch.setattr(urllib.request, "urlopen", _spy)
    vulns = OSVClient("offline").query("jinja2", Ecosystem.PYPI, "2.4.1")
    assert calls["n"] == 0
    assert len(vulns) == 1  # still resolved, from the fixture


def test_typosquat_distance_one_flagged():
    m1 = typosquat.check("requsts", Ecosystem.PYPI)
    assert m1 is not None and m1.nearest == "requests" and 1 <= m1.distance <= 2
    m2 = typosquat.check("reqests", Ecosystem.PYPI)
    assert m2 is not None and m2.nearest == "requests" and m2.distance <= 2


def test_typosquat_exact_popular_not_flagged():
    assert typosquat.check("requests", Ecosystem.PYPI) is None
    assert typosquat.check("lodash", Ecosystem.NPM) is None


def test_typosquat_confusable_underscore_hyphen():
    m = typosquat.check("cross_env", Ecosystem.NPM)
    assert m is not None
    assert m.nearest == "cross-env"
    assert m.distance == 0 and m.confusable is True


def test_abandonment_over_threshold(fx):
    metadata = json.loads(open(fx("pypi_meta_abandoned.json")).read())

    def fetcher(name, ecosystem):
        return metadata

    now = datetime(2026, 7, 2, tzinfo=timezone.utc)
    ev = abandonment.check(
        "leftpad-py", Ecosystem.PYPI, threshold_years=2.0, now=now, fetcher=fetcher
    )
    assert ev is not None
    assert ev["last_release"] == "2016-06-15"
    assert ev["age_years"] >= 2.0
