"""Diff engine: two dependency sets -> a list of classified DepDiffs."""

from __future__ import annotations

from .models import ChangeKind, DepDiff, Dependency
from .semver import classify_bump, compare_versions


def compute_diff(old: list[Dependency], new: list[Dependency]) -> list[DepDiff]:
    """Compute the ADDED / REMOVED / UPGRADED / DOWNGRADED / UNCHANGED delta.

    Dependencies are indexed by ``(ecosystem, name)`` so the same name in two
    ecosystems never collides. Results are sorted by (ecosystem, name) for
    deterministic output.
    """
    old_idx = {(d.ecosystem, d.name): d for d in old}
    new_idx = {(d.ecosystem, d.name): d for d in new}

    diffs: list[DepDiff] = []
    for key in set(old_idx) | set(new_idx):
        ecosystem, name = key
        o = old_idx.get(key)
        n = new_idx.get(key)

        if o is not None and n is None:
            diffs.append(DepDiff(name, ecosystem, ChangeKind.REMOVED, o.version, None))
        elif o is None and n is not None:
            diffs.append(DepDiff(name, ecosystem, ChangeKind.ADDED, None, n.version))
        else:
            assert o is not None and n is not None
            cmp = compare_versions(o.version, n.version, ecosystem)
            if cmp == 0:
                diffs.append(DepDiff(name, ecosystem, ChangeKind.UNCHANGED, o.version, n.version))
            else:
                kind = ChangeKind.UPGRADED if cmp < 0 else ChangeKind.DOWNGRADED
                bump = classify_bump(o.version, n.version, ecosystem)
                diffs.append(DepDiff(name, ecosystem, kind, o.version, n.version, bump))

    diffs.sort(key=lambda d: (d.ecosystem.value, d.name))
    return diffs
