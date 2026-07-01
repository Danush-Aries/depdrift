"""Shared data contract for depdrift.

Every module — parsers, diffing, enrich, report, cli — codes against these types.
Kept dependency-free (stdlib only) so it is the stable center of the package.

Enums subclass ``str`` so they serialize straight to JSON, and ``Ecosystem``
values match the OSV ecosystem strings ("PyPI", "npm") exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import __version__


class Ecosystem(str, Enum):
    PYPI = "PyPI"  # value matches the OSV ecosystem string exactly
    NPM = "npm"


class ChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    UNCHANGED = "unchanged"  # computed but excluded from the report by default


class BumpLevel(str, Enum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    OTHER = "other"  # non-semver / pre-release / unparseable
    NONE = "none"


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class RiskKind(str, Enum):
    VULN = "vuln"
    TYPOSQUAT = "typosquat"
    ABANDONED = "abandoned"


# Low -> high ranking, shared so diffing/report/cli rank consistently.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MODERATE: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(sev: Severity) -> int:
    return SEVERITY_ORDER[sev]


def max_severity(severities: list[Severity]) -> Severity:
    return max(severities, key=severity_rank, default=Severity.NONE)


@dataclass(frozen=True, slots=True)
class Dependency:
    """A single resolved dependency from a lockfile."""

    name: str  # normalized (PyPI: PEP 503 lowercase/dash; npm: as-is incl scope)
    version: str  # exact resolved version string
    ecosystem: Ecosystem
    direct: bool = True  # best-effort: top-level vs transitive
    raw: str | None = None  # original line/key for traceability


@dataclass(frozen=True, slots=True)
class DepDiff:
    """One dependency's change between the old and new state."""

    name: str
    ecosystem: Ecosystem
    kind: ChangeKind
    old_version: str | None  # None for ADDED
    new_version: str | None  # None for REMOVED
    bump: BumpLevel = BumpLevel.NONE  # set for UPGRADED/DOWNGRADED

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem.value,
            "kind": self.kind.value,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "bump": self.bump.value,
        }


@dataclass(frozen=True, slots=True)
class Vuln:
    """A known vulnerability as reported by OSV."""

    id: str  # e.g. "GHSA-462w-v97r-4m45"
    aliases: tuple[str, ...]  # ("CVE-2019-10906", "PYSEC-2019-217")
    summary: str
    severity: Severity
    fixed_version: str | None  # first fixed version if OSV ranges give one
    reference_url: str | None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "aliases": list(self.aliases),
            "summary": self.summary,
            "severity": self.severity.value,
            "fixed_version": self.fixed_version,
            "reference_url": self.reference_url,
        }


@dataclass(frozen=True, slots=True)
class Risk:
    """A risk attached to a changed dependency."""

    kind: RiskKind
    dep: DepDiff  # the changed dep this risk attaches to
    severity: Severity
    title: str  # one-line human summary
    detail: str  # longer explanation
    vuln: Vuln | None = None  # populated when kind == VULN
    evidence: dict | None = None  # e.g. {"nearest": "requests", "distance": 1}

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "dep": self.dep.to_dict(),
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "vuln": self.vuln.to_dict() if self.vuln else None,
            "evidence": self.evidence,
        }


@dataclass(slots=True)  # not frozen: assembled incrementally
class Report:
    old_ref: str  # label of the old state (path or git ref)
    new_ref: str
    generated_at: str  # ISO-8601 UTC
    diffs: list[DepDiff] = field(default_factory=list)
    risks: list[Risk] = field(default_factory=list)

    @property
    def added(self) -> list[DepDiff]:
        return [d for d in self.diffs if d.kind == ChangeKind.ADDED]

    @property
    def removed(self) -> list[DepDiff]:
        return [d for d in self.diffs if d.kind == ChangeKind.REMOVED]

    @property
    def upgraded(self) -> list[DepDiff]:
        return [d for d in self.diffs if d.kind == ChangeKind.UPGRADED]

    @property
    def downgraded(self) -> list[DepDiff]:
        return [d for d in self.diffs if d.kind == ChangeKind.DOWNGRADED]

    @property
    def unchanged(self) -> list[DepDiff]:
        return [d for d in self.diffs if d.kind == ChangeKind.UNCHANGED]

    @property
    def max_severity(self) -> Severity:
        return max_severity([r.severity for r in self.risks])

    def to_dict(self) -> dict:
        """Canonical JSON shape."""
        return {
            "schema_version": "1.0",
            "tool_version": __version__,
            "old_ref": self.old_ref,
            "new_ref": self.new_ref,
            "generated_at": self.generated_at,
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "upgraded": len(self.upgraded),
                "downgraded": len(self.downgraded),
                "risks": len(self.risks),
                "max_severity": self.max_severity.value,
            },
            "diffs": [d.to_dict() for d in self.diffs],
            "risks": [r.to_dict() for r in self.risks],
        }
