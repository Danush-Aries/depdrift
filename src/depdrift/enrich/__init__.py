"""Enrichment orchestrator: turn a diff into a ranked list of Risks.

Risk is only assessed on the *changed* set — added and upgraded deps — which is
the whole point of depdrift: a reviewer sees the NEW attack surface a bump
introduces, not a wall of pre-existing findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..models import (
    ChangeKind,
    DepDiff,
    Risk,
    RiskKind,
    Severity,
    severity_rank,
)
from . import abandonment as _abandon
from . import typosquat as _typo
from .osv import OSVClient

__all__ = ["EnrichOptions", "enrich"]


@dataclass(slots=True)
class EnrichOptions:
    offline: bool = True
    osv: bool = True
    typosquat: bool = True
    abandonment: bool = False  # online-only; opt-in
    abandoned_years: float = 2.0


def enrich(
    diffs: list[DepDiff],
    opts: EnrichOptions | None = None,
    osv_client: OSVClient | None = None,
    now: datetime | None = None,
) -> list[Risk]:
    opts = opts or EnrichOptions()
    client = osv_client or OSVClient("offline" if opts.offline else "cached")
    now = now or datetime.now(timezone.utc)

    risks: list[Risk] = []
    for diff in diffs:
        is_added = diff.kind == ChangeKind.ADDED
        is_changed = diff.kind in (
            ChangeKind.ADDED,
            ChangeKind.UPGRADED,
            ChangeKind.DOWNGRADED,
        )

        if opts.osv and is_changed and diff.new_version:
            for vuln in client.query(diff.name, diff.ecosystem, diff.new_version):
                fix = f" Fixed in {vuln.fixed_version}." if vuln.fixed_version else ""
                risks.append(
                    Risk(
                        kind=RiskKind.VULN,
                        dep=diff,
                        severity=vuln.severity,
                        title=f"{diff.name} {diff.new_version}: {vuln.id}",
                        detail=(vuln.summary or "severity unknown") + fix,
                        vuln=vuln,
                    )
                )

        if opts.typosquat and is_added:
            match = _typo.check(diff.name, diff.ecosystem)
            if match is not None:
                how = (
                    "confusable of" if match.confusable else f"edit-distance {match.distance} from"
                )
                risks.append(
                    Risk(
                        kind=RiskKind.TYPOSQUAT,
                        dep=diff,
                        severity=match.severity,
                        title=f"{diff.name}: possible typosquat of {match.nearest!r}",
                        detail=(
                            f"Newly-added {diff.ecosystem.value} package {diff.name!r} is a "
                            f"{how} the popular package {match.nearest!r}."
                        ),
                        evidence={"nearest": match.nearest, "distance": match.distance},
                    )
                )

        if opts.abandonment and not opts.offline and is_changed:
            ev = _abandon.check(
                diff.name, diff.ecosystem, threshold_years=opts.abandoned_years, now=now
            )
            if ev is not None:
                slightly_over = ev["age_years"] < opts.abandoned_years + 1
                sev = Severity.LOW if slightly_over else Severity.MODERATE
                last = ev["last_release"]
                risks.append(
                    Risk(
                        kind=RiskKind.ABANDONED,
                        dep=diff,
                        severity=sev,
                        title=f"{diff.name}: possibly abandoned (last release {last})",
                        detail=(
                            f"{diff.name!r} last published {ev['last_release']} "
                            f"(~{ev['age_years']}y ago), over the "
                            f"{opts.abandoned_years}y threshold."
                        ),
                        evidence=ev,
                    )
                )

    # Rank critical -> low; stable within a severity by name for determinism.
    risks.sort(key=lambda r: (-severity_rank(r.severity), r.dep.name, r.kind.value))
    return risks
