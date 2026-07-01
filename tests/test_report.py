"""Report + ranking tests (21-23)."""

from __future__ import annotations

import json

from depdrift.enrich import EnrichOptions, enrich
from depdrift.models import (
    BumpLevel,
    ChangeKind,
    DepDiff,
    Ecosystem,
    Report,
    Risk,
    RiskKind,
    Severity,
    Vuln,
)
from depdrift.report import render


def _sample_report() -> Report:
    diffs = [
        DepDiff("jinja2", Ecosystem.PYPI, ChangeKind.ADDED, None, "2.4.1"),
        DepDiff("click", Ecosystem.PYPI, ChangeKind.REMOVED, "7.1.2", None),
        DepDiff("flask", Ecosystem.PYPI, ChangeKind.UPGRADED, "2.0.0", "2.0.1", BumpLevel.PATCH),
    ]
    vuln = Vuln("GHSA-x", ("CVE-1",), "sandbox escape", Severity.HIGH, "2.10.1", "https://e")
    risks = [
        Risk(RiskKind.VULN, diffs[0], Severity.HIGH, "jinja2 2.4.1: GHSA-x", "sandbox escape", vuln)
    ]
    return Report("old.txt", "new.txt", "2026-07-02T00:00:00+00:00", diffs, risks)


def test_markdown_report_sections():
    md = render(_sample_report(), "markdown")
    assert "## Added" in md
    assert "## Removed" in md
    assert "## Upgraded" in md
    assert "## Risks" in md
    assert "HIGH" in md  # severity badge text
    assert "| Severity | Kind | Package | Detail |" in md


def test_json_report_schema_stable():
    d = _sample_report().to_dict()
    required = ("schema_version", "old_ref", "new_ref", "generated_at", "summary", "diffs", "risks")
    for key in required:
        assert key in d
    assert d["summary"]["max_severity"] == "high"
    # must be JSON-serializable and round-trip
    round_tripped = json.loads(json.dumps(d))
    assert round_tripped["diffs"][0]["name"] in {"jinja2", "click", "flask"}


def test_report_severity_ranking():
    diffs = [
        DepDiff("zzz-critical", Ecosystem.PYPI, ChangeKind.ADDED, None, "1.0.0"),
        DepDiff("zzz-low", Ecosystem.PYPI, ChangeKind.ADDED, None, "1.0.0"),
    ]

    class StubOSV:
        def query(self, name, ecosystem, version):
            if name == "zzz-critical":
                return [Vuln("C", (), "crit", Severity.CRITICAL, None, None)]
            if name == "zzz-low":
                return [Vuln("L", (), "low", Severity.LOW, None, None)]
            return []

    risks = enrich(
        diffs,
        EnrichOptions(offline=True, typosquat=False),
        osv_client=StubOSV(),
    )
    assert [r.severity for r in risks] == [Severity.CRITICAL, Severity.LOW]
