"""Parser registry: detect a lockfile's ecosystem and parse it to Dependencies."""

from __future__ import annotations

from pathlib import Path

from ..models import Dependency
from .base import LockfileParseError, Parser
from .package_lock import PackageLockParser
from .requirements_txt import RequirementsTxtParser

__all__ = [
    "PARSERS",
    "LockfileParseError",
    "Parser",
    "detect",
    "parse",
    "parse_source",
]

# Order matters only for ambiguous names; each parser's ``matches`` is specific.
PARSERS: list[Parser] = [
    RequirementsTxtParser(),
    PackageLockParser(),
]


def _sniff(text: str) -> Parser | None:
    """Content-based fallback when the filename is non-standard.

    A JSON object is treated as an npm lock; anything else as pip requirements —
    the two ecosystems depdrift supports today.
    """
    stripped = text.lstrip()
    if not stripped:
        return None
    if stripped[0] == "{":
        return PackageLockParser()
    return RequirementsTxtParser()


def detect(filename: str, text: str | None = None) -> Parser:
    """Return the parser for *filename* (or sniffed from *text*), else raise."""
    for parser in PARSERS:
        if parser.matches(filename):
            return parser
    if text is not None:
        sniffed = _sniff(text)
        if sniffed is not None:
            return sniffed
    raise LockfileParseError(
        f"no parser for {filename!r} (supported: requirements*.txt, package-lock.json)"
    )


def parse_source(text: str, filename: str) -> list[Dependency]:
    """Detect the ecosystem from *filename* (or content) and parse *text*."""
    return detect(filename, text).parse_text(text, filename)


def parse(path: str | Path) -> list[Dependency]:
    """Read *path*, detect its ecosystem, and parse it to Dependencies."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise LockfileParseError(f"lockfile not found: {path}") from e
    except OSError as e:
        raise LockfileParseError(f"cannot read {path}: {e}") from e
    return parse_source(text, p.name)
