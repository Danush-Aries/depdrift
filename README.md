# depdrift

**A supply-chain *diff* for dependency lockfiles.** Point-in-time scanners answer
*"is my dependency set vulnerable right now?"*. The question a reviewer actually asks on a
lockfile-bumping PR is different:

> *"What **new** risk did **this** change introduce compared to the last known-good state?"*

`depdrift` answers that. Give it two lockfiles (or one repo at two git refs) and it reports
which dependencies were **added / removed / upgraded** — with semver classification — and then
flags security & trust risk **only on the changed set**: known vulnerabilities (OSV.dev),
typosquats, and abandonment. Cross-ecosystem (PyPI + npm), **keyless**, and fully
**offline-testable**.

---

## Why it's different

| Tool | What it does | Gap depdrift fills |
|------|--------------|--------------------|
| `pip-audit` | scans the current resolved env for CVEs | no diff; re-flags vulns you already accepted; PyPI-only |
| `npm audit` | scans the current lockfile | npm-only; noisy; no "delta vs previous release" |
| Dependabot / Renovate | opens per-package bump PRs | not a whole-lockfile delta; no typosquat/abandonment; SaaS-bound |
| OSV-Scanner | point-in-time scan against OSV | **no diff** — can't ask "what got worse between v1 and v2" |

`depdrift`'s angle:

1. **Release-delta framing** — risk is scored on the *newly-introduced* set, so a reviewer sees
   the new attack surface a bump adds, not a wall of pre-existing findings.
2. **Trust risks beyond CVEs** — typosquat (Levenshtein vs a bundled popular-name list) and
   abandonment detection catch a malicious/dead *new* dependency, which has no CVE to find.
3. **Cross-ecosystem, one report** — Python + Node, severity-ranked Markdown/JSON, CI exit codes.
4. **Offline-first & keyless** — OSV.dev is free and needs no key; the test suite and demo run
   against recorded fixtures with zero network.

`depdrift` does not replace pip-audit/OSV-Scanner for a full audit — it's the **code-review
companion** that turns a lockfile change into a risk delta.

---

## Install

```bash
pip install -e .
# or, with uv:
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e .
```

## Quickstart

```bash
# diff two lockfiles
depdrift diff requirements.old.txt requirements.new.txt

# npm
depdrift diff package-lock.old.json package-lock.new.json

# diff one lockfile across two git refs
depdrift diff --git HEAD~1..HEAD --path requirements.txt

# JSON output for CI / further processing
depdrift diff old.txt new.txt --format json -o drift.json
```

### Sample output

```
# depdrift report

- **old:** `requirements.old.txt`
- **new:** `requirements.new.txt`
- **max severity:** 🟠 HIGH

**1 added · 1 removed · 2 upgraded · 0 downgraded · 1 risk(s)**

## Added
- `jinja2` @ 2.4.1 (PyPI)

## Upgraded
- `flask` 2.0.0 → 2.0.1 (patch)
- `requests` 2.25.0 → 2.31.0 (minor)

## Risks
| Severity | Kind | Package | Detail |
|----------|------|---------|--------|
| 🟠 HIGH | vuln | `jinja2` | Jinja2 sandbox escape via string formatting Fixed in 2.10.1. |
```

## Offline vs live

`depdrift` is **offline by default** — OSV data comes from bundled fixtures and no network is
touched. Pass `--live` to hit OSV.dev directly (still keyless) and enable abandonment lookups
against the PyPI/npm registries. Results are cached under `~/.cache/depdrift/`.

```bash
depdrift diff old.txt new.txt --live          # live OSV + abandonment
depdrift diff old.txt new.txt --no-typosquat  # toggle individual enrichers
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | clean — no risk at/above `--fail-on` (default `low`) |
| `1` | risk found at/above the threshold |
| `2` | error — parse failure, bad git ref, invalid args |

```bash
depdrift diff old.txt new.txt --fail-on high   # only High/Critical fail the build
```

## Ecosystem support

| Ecosystem | Lockfile | Status |
|-----------|----------|--------|
| PyPI | `requirements.txt` (pinned `==`) | supported |
| npm | `package-lock.json` (v1/v2/v3) | supported |
| PyPI | `poetry.lock`, `uv.lock` | roadmap |
| npm | `pnpm-lock.yaml` | roadmap |

## Limitations

- Requirements parsing keys on exact `==` pins (the lockfile use-case); ranges are skipped.
- Version comparison never crashes — pre-releases / unparseable versions classify as `other`.
- Typosquat findings are **signals, not verdicts** (conservative edit-distance 1-2 window).
- Abandonment is the only strictly-online check and is opt-in via `--live`.

## Roadmap

`poetry.lock` / `uv.lock` / `pnpm-lock.yaml` parsers · OSV batch endpoint · SARIF output ·
GitHub Action wrapper.

## License

MIT © 2026 Dhanush Shankar
