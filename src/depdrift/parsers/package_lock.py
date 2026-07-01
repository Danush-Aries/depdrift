"""Parser for npm ``package-lock.json`` (lockfileVersion 1, 2 and 3)."""

from __future__ import annotations

import json

from ..models import Dependency, Ecosystem
from .base import LockfileParseError, Parser

_NM = "node_modules/"


def _name_from_key(key: str) -> str:
    """Strip nested ``node_modules/`` prefixes to the installed package name.

    ``node_modules/a/node_modules/@scope/b`` -> ``@scope/b``.
    """
    idx = key.rfind(_NM)
    return key[idx + len(_NM) :] if idx >= 0 else key


class PackageLockParser(Parser):
    ecosystem = Ecosystem.NPM

    def matches(self, filename: str) -> bool:
        base = filename.rsplit("/", 1)[-1].lower()
        return base == "package-lock.json" or base == "npm-shrinkwrap.json"

    def parse_text(self, text: str, filename: str = "") -> list[Dependency]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise LockfileParseError(f"invalid package-lock JSON: {e}") from e
        if not isinstance(data, dict):
            raise LockfileParseError("package-lock root must be a JSON object")

        packages = data.get("packages")
        if isinstance(packages, dict):
            return self._parse_v2_v3(packages)
        deps_map = data.get("dependencies")
        if isinstance(deps_map, dict):
            return self._parse_v1(deps_map)
        # A valid-but-empty lock (no deps) yields nothing rather than erroring.
        return []

    def _parse_v2_v3(self, packages: dict) -> list[Dependency]:
        root = packages.get("", {}) or {}
        direct_names = (
            set(root.get("dependencies", {}))
            | set(root.get("devDependencies", {}))
            | set(root.get("optionalDependencies", {}))
        )
        # Dedupe by name, preferring the entry closest to the root (shortest key).
        chosen: dict[str, tuple[int, Dependency]] = {}
        for key, meta in packages.items():
            if key == "" or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            name = _name_from_key(key)
            if not name:
                continue
            depth = key.count(_NM)
            dep = Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.NPM,
                direct=name in direct_names,
                raw=key,
            )
            prev = chosen.get(name)
            if prev is None or depth < prev[0]:
                chosen[name] = (depth, dep)
        return [dep for _, dep in chosen.values()]

    def _parse_v1(self, deps_map: dict) -> list[Dependency]:
        chosen: dict[str, Dependency] = {}

        def walk(mapping: dict, direct: bool) -> None:
            for name, meta in mapping.items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if isinstance(version, str) and name not in chosen:
                    chosen[name] = Dependency(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NPM,
                        direct=direct,
                        raw=name,
                    )
                sub = meta.get("dependencies")
                if isinstance(sub, dict):
                    walk(sub, False)

        walk(deps_map, True)
        return list(chosen.values())
