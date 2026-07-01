"""Parser ABC + the parse-error type shared by every ecosystem parser."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Dependency, Ecosystem


class LockfileParseError(ValueError):
    """Raised when a lockfile is malformed or cannot be parsed."""


class Parser(ABC):
    """A lockfile parser for one ecosystem."""

    ecosystem: Ecosystem

    @abstractmethod
    def matches(self, filename: str) -> bool:
        """Return True if this parser handles a file with the given name."""

    @abstractmethod
    def parse_text(self, text: str, filename: str = "") -> list[Dependency]:
        """Parse lockfile *text* into a list of Dependencies."""
