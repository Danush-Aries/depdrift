"""Read a lockfile blob at a git ref, and parse ``A..B`` ranges."""

from __future__ import annotations

import subprocess


class GitError(RuntimeError):
    """Raised when a git command fails (bad ref, missing path, not a repo)."""


def parse_git_range(spec: str) -> tuple[str, str]:
    """Split ``REFA..REFB`` into ``(REFA, REFB)``."""
    if ".." not in spec:
        raise ValueError(f"expected 'REFA..REFB' range, got {spec!r}")
    a, b = spec.split("..", 1)
    a, b = a.strip(), b.strip()
    if not a or not b:
        raise ValueError(f"both refs required in range, got {spec!r}")
    return a, b


def read_lockfile_at_ref(repo: str, ref: str, path: str) -> str:
    """Return the text of ``path`` as it existed at ``ref`` via ``git show``."""
    try:
        result = subprocess.run(
            ["git", "-C", repo, "show", f"{ref}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:  # git not installed
        raise GitError("git executable not found") from e
    if result.returncode != 0:
        raise GitError(result.stderr.strip() or f"git show {ref}:{path} failed")
    return result.stdout
