"""Version parsing + bump classification for PyPI and npm.

Hand-rolled (no external ``packaging`` / ``semver`` dependency) so the package
stays stdlib-only. The rules are intentionally conservative: anything that does
not look like a clean numeric release (pre-releases, dev/rc/alpha, unparseable
strings) classifies as ``BumpLevel.OTHER`` and never raises.
"""

from __future__ import annotations

import re

from .models import BumpLevel, Ecosystem

# Leading range operators / decorations we strip before parsing a concrete version.
_RANGE_PREFIX = "^~=><! v"
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def _split_version(v: str) -> tuple[tuple[int, ...] | None, bool]:
    """Return (release_tuple, is_prerelease).

    ``release_tuple`` is ``None`` when the string has no leading numeric release.
    ``is_prerelease`` is True when anything trails the numeric release
    (rc1, -beta, .dev0, a1, post1, ...), which we treat as non-clean for bump
    classification purposes.
    """
    if v is None:
        return None, False
    s = v.strip().lstrip(_RANGE_PREFIX).strip()
    if not s:
        return None, False
    s = s.split("+", 1)[0]  # drop build metadata
    m = _RELEASE_RE.match(s)
    if not m:
        return None, False
    release = tuple(int(x) for x in m.group(1).split("."))
    rest = s[m.end() :]
    return release, bool(rest)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def compare_versions(a: str, b: str, ecosystem: Ecosystem | None = None) -> int:
    """Return -1 if a<b, 0 if equal, 1 if a>b.

    Numeric release tuples are compared element-wise. A clean release sorts
    *after* a pre-release of the same release (``1.0.0`` > ``1.0.0rc1``).
    Unparseable versions fall back to string comparison and never crash.
    """
    ra, pa = _split_version(a)
    rb, pb = _split_version(b)
    if ra is None or rb is None:
        if a == b:
            return 0
        return -1 if a < b else 1
    ra2, rb2 = _pad(ra, rb)
    if ra2 != rb2:
        return -1 if ra2 < rb2 else 1
    if pa and not pb:
        return -1
    if pb and not pa:
        return 1
    if a == b:
        return 0
    return -1 if a < b else 1


def classify_bump(old_v: str, new_v: str, ecosystem: Ecosystem | None = None) -> BumpLevel:
    """Classify the magnitude of a version change.

    Returns MAJOR/MINOR/PATCH for a clean numeric change, NONE when equal, and
    OTHER for pre-releases or anything unparseable. Direction (up vs down) is not
    encoded here — only magnitude.
    """
    ro, po = _split_version(old_v)
    rn, pn = _split_version(new_v)
    if ro is None or rn is None or po or pn:
        return BumpLevel.OTHER
    ro2, rn2 = _pad(ro, rn)
    if ro2 == rn2:
        return BumpLevel.NONE
    for i, (o, n) in enumerate(zip(ro2, rn2)):
        if o != n:
            if i == 0:
                return BumpLevel.MAJOR
            if i == 1:
                return BumpLevel.MINOR
            return BumpLevel.PATCH
    return BumpLevel.NONE
