"""Diffing + semver tests (8-12)."""

from __future__ import annotations

from depdrift.diffing import compute_diff
from depdrift.models import BumpLevel, ChangeKind, Dependency, Ecosystem
from depdrift.semver import classify_bump


def _pypi(name: str, version: str) -> Dependency:
    return Dependency(name=name, version=version, ecosystem=Ecosystem.PYPI)


def test_diff_added_removed_unchanged():
    old = [_pypi("a", "1.0.0"), _pypi("b", "1.0.0")]
    new = [_pypi("b", "1.0.0"), _pypi("c", "1.0.0")]
    kinds = {d.name: d.kind for d in compute_diff(old, new)}
    assert kinds["c"] == ChangeKind.ADDED
    assert kinds["a"] == ChangeKind.REMOVED
    assert kinds["b"] == ChangeKind.UNCHANGED


def test_diff_semver_major_minor_patch():
    old = [_pypi("maj", "1.2.3"), _pypi("min", "1.2.3"), _pypi("pat", "1.2.3")]
    new = [_pypi("maj", "2.0.0"), _pypi("min", "1.3.0"), _pypi("pat", "1.2.4")]
    bumps = {d.name: d.bump for d in compute_diff(old, new)}
    assert bumps["maj"] == BumpLevel.MAJOR
    assert bumps["min"] == BumpLevel.MINOR
    assert bumps["pat"] == BumpLevel.PATCH


def test_diff_downgrade_detected():
    (d,) = compute_diff([_pypi("x", "2.0.0")], [_pypi("x", "1.9.0")])
    assert d.kind == ChangeKind.DOWNGRADED
    assert d.bump == BumpLevel.MAJOR  # magnitude of the change, direction is 'kind'


def test_classify_bump_prerelease_is_other():
    assert classify_bump("1.0.0", "1.0.1rc1", Ecosystem.PYPI) == BumpLevel.OTHER
    # and it must never crash on garbage input
    assert classify_bump("not-a-version", "also-bad", Ecosystem.NPM) == BumpLevel.OTHER
    (d,) = compute_diff([_pypi("p", "1.0.0")], [_pypi("p", "1.0.1rc1")])
    assert d.bump == BumpLevel.OTHER
    assert d.kind == ChangeKind.UPGRADED  # 1.0.0 < 1.0.1rc1 by release tuple


def test_diff_cross_ecosystem_keys_isolated():
    old = [Dependency("lodash", "1.0.0", Ecosystem.NPM)]
    new = [
        Dependency("lodash", "1.0.0", Ecosystem.NPM),
        Dependency("lodash", "1.0.0", Ecosystem.PYPI),
    ]
    diffs = compute_diff(old, new)
    by_key = {(d.ecosystem, d.name): d.kind for d in diffs}
    assert by_key[(Ecosystem.NPM, "lodash")] == ChangeKind.UNCHANGED
    assert by_key[(Ecosystem.PYPI, "lodash")] == ChangeKind.ADDED
