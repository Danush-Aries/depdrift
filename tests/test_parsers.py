"""Parser tests (1-7)."""

from __future__ import annotations

import pytest

from depdrift.models import Ecosystem
from depdrift.parsers import LockfileParseError, detect, parse
from depdrift.parsers.package_lock import PackageLockParser
from depdrift.parsers.requirements_txt import RequirementsTxtParser


def test_parse_requirements_basic(fx):
    deps = parse(fx("req_old.txt"))
    got = {d.name: d.version for d in deps}
    assert got == {"flask": "2.0.0", "requests": "2.25.0", "click": "7.1.2"}
    assert all(d.ecosystem == Ecosystem.PYPI for d in deps)


def test_parse_requirements_ignores_comments_and_options(fx):
    deps = parse(fx("req_messy.txt"))
    names = {d.name for d in deps}
    # -r / -e / --hash / blank lines / range-only django are all skipped
    assert "django" not in names
    assert names == {"flask", "python-dateutil", "requests", "uvicorn"}


def test_parse_requirements_normalizes_names(fx):
    deps = {d.name: d.version for d in parse(fx("req_messy.txt"))}
    assert "python-dateutil" in deps  # underscore normalized to dash
    assert "flask" in deps  # mixed-case Flask lowercased
    assert deps["uvicorn"] == "0.23.2"  # [standard] extra stripped


def test_parse_package_lock_v3(fx):
    deps = parse(fx("pkglock_old.json"))
    got = {d.name: d.version for d in deps}
    assert got["lodash"] == "4.17.20"
    assert "@types/node" in got  # scoped name preserved
    assert "ms" in got  # nested node_modules/ prefix stripped
    assert all(d.ecosystem == Ecosystem.NPM for d in deps)
    assert len(deps) == 4


def test_parse_package_lock_marks_direct_vs_transitive(fx):
    by_name = {d.name: d for d in parse(fx("pkglock_old.json"))}
    assert by_name["lodash"].direct is True
    assert by_name["express"].direct is True
    assert by_name["@types/node"].direct is False  # not in root dependencies
    assert by_name["ms"].direct is False  # transitive


def test_parser_registry_detects_ecosystem():
    assert isinstance(detect("requirements.txt"), RequirementsTxtParser)
    assert isinstance(detect("requirements-dev.txt"), RequirementsTxtParser)
    assert isinstance(detect("package-lock.json"), PackageLockParser)
    with pytest.raises(LockfileParseError):
        detect("Cargo.lock")


def test_parser_raises_on_malformed(fx):
    with pytest.raises(LockfileParseError):
        parse(fx("malformed.json"))
    with pytest.raises(LockfileParseError):
        parse(fx("does_not_exist.txt"))
