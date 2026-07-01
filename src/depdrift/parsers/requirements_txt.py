"""Parser for pip ``requirements.txt`` files (exact ``==`` pins)."""

from __future__ import annotations

import re

from ..models import Dependency, Ecosystem
from .base import Parser

# name [extras] == version   (we only treat exact pins as resolved deps)
_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"\s*(?:\[[^\]]*\])?\s*"
    r"==\s*(?P<version>[^\s;#]+)$"
)


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapse to a single '-'."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


class RequirementsTxtParser(Parser):
    ecosystem = Ecosystem.PYPI

    def matches(self, filename: str) -> bool:
        base = filename.rsplit("/", 1)[-1].lower()
        return base.endswith(".txt") and "requirements" in base

    def parse_text(self, text: str, filename: str = "") -> list[Dependency]:
        deps: list[Dependency] = []
        for raw_line in text.splitlines():
            # strip trailing inline comment ("pkg==1  # note")
            line = raw_line.split(" #", 1)[0].rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # options / includes / editable installs / hash continuations
            if stripped.startswith("-"):
                continue
            # drop environment markers before matching the pin
            core = stripped.split(";", 1)[0].strip()
            m = _PIN_RE.match(core)
            if not m:
                continue
            deps.append(
                Dependency(
                    name=normalize_pypi(m.group("name")),
                    version=m.group("version"),
                    ecosystem=Ecosystem.PYPI,
                    direct=True,
                    raw=raw_line.strip(),
                )
            )
        return deps
