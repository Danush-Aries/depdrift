#!/usr/bin/env python3
"""Dev helper: record a real OSV /v1/query response as a bundled fixture.

Not shipped in the wheel. Regenerates the offline fixtures the test suite and
demo run against, so the hermetic tests stay faithful to the live API.

    python scripts/record_osv.py PyPI jinja2 2.4.1

Writes to src/depdrift/enrich/data/osv_fixtures/{ecosystem}/{name}@{version}.json
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DATA_DIR = Path(__file__).resolve().parent.parent / "src/depdrift/enrich/data/osv_fixtures"


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: record_osv.py ECOSYSTEM NAME VERSION", file=sys.stderr)
        return 2
    ecosystem, name, version = sys.argv[1], sys.argv[2], sys.argv[3]
    body = json.dumps(
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    ).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        data = json.loads(resp.read().decode())

    out = DATA_DIR / ecosystem / f"{name}@{version}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"wrote {out} ({len(data.get('vulns', []))} vuln(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
