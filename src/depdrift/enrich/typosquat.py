"""Typosquat detection: Levenshtein vs a bundled popular-name list.

Fully offline. For a newly-added dependency we look for a near-miss of a popular
package of the same ecosystem: normalized-confusables (hyphen/underscore swaps)
and small edit distances (1-2) — the classic vectors for a malicious add that a
CVE scanner cannot see because the package has no advisory.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ..models import Ecosystem, Severity

DATA_DIR = Path(__file__).parent / "data"
_TOP_TIER = 100  # first N names in each list are treated as "top-tier"


def levenshtein(a: str, b: str) -> int:
    """Classic DP edit distance (no external dependency)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _normalize(name: str) -> str:
    """Collapse confusable separators so cross_env == cross-env."""
    out = name.lower()
    for ch in ("_", ".", " "):
        out = out.replace(ch, "-")
    return out


@lru_cache(maxsize=None)
def _load(ecosystem: Ecosystem) -> tuple[str, ...]:
    fname = "popular_pypi.txt" if ecosystem == Ecosystem.PYPI else "popular_npm.txt"
    path = DATA_DIR / fname
    if not path.exists():
        return ()
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            names.append(s)
    return tuple(names)


class TyposquatMatch:
    """Result of a typosquat check: the nearest popular name + distance + tier."""

    __slots__ = ("nearest", "distance", "confusable", "top_tier")

    def __init__(self, nearest: str, distance: int, confusable: bool, top_tier: bool) -> None:
        self.nearest = nearest
        self.distance = distance
        self.confusable = confusable
        self.top_tier = top_tier

    @property
    def severity(self) -> Severity:
        if self.confusable or (self.distance == 1 and self.top_tier):
            return Severity.HIGH
        return Severity.MODERATE


def check(name: str, ecosystem: Ecosystem) -> TyposquatMatch | None:
    """Return a TyposquatMatch if *name* looks like a squat of a popular name.

    A name that is itself popular is never flagged. A normalized-confusable of a
    different popular name is flagged at distance 0; otherwise an edit distance of
    1-2 to the nearest popular name flags it.
    """
    popular = _load(ecosystem)
    if not popular:
        return None
    if name in popular:
        return None

    norm = _normalize(name)
    best: tuple[int, str, bool] | None = None  # (distance, popular, top_tier)
    for i, pop in enumerate(popular):
        top_tier = i < _TOP_TIER
        if pop != name and _normalize(pop) == norm:
            return TyposquatMatch(pop, 0, confusable=True, top_tier=top_tier)
        d = levenshtein(name, pop)
        if best is None or d < best[0]:
            best = (d, pop, top_tier)

    if best is not None and 1 <= best[0] <= 2:
        return TyposquatMatch(best[1], best[0], confusable=False, top_tier=best[2])
    return None
