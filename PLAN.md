# depdrift — Implementation Plan

> A supply-chain **DIFF** tool. Given two dependency states (two lockfiles, or the same
> repo at two git refs) it reports which dependencies were **ADDED / REMOVED / UPGRADED**,
> and for the newly-introduced set it flags **security & trust risks**
> (known vulns via OSV, typosquats, abandonment).

Status: greenfield. Target: Python 3.10–3.12, zero required API keys, tests run fully offline.

---

## 1. Context — the real unmet need

Point-in-time scanners answer *"is my current dependency set vulnerable right now?"*.
The question a **reviewer** actually asks on a PR that bumps a lockfile is different:

> *"What NEW risk did **this** change introduce compared to the last known-good state?"*

That is a **delta** question, and the existing tools answer it poorly:

| Tool | What it does | Gap depdrift fills |
|------|--------------|--------------------|
| `pip-audit` | scans the current resolved env for known CVEs | no diff; re-flags pre-existing vulns you already accepted; PyPI-only |
| `npm audit` | scans current `node_modules` / lockfile | npm-only; noisy; no "delta vs previous release" |
| Dependabot / Renovate | opens bump PRs, shows changelog | per-package, not a whole-lockfile delta; no typosquat/abandonment; SaaS/GitHub-bound |
| OSV-Scanner | point-in-time scan of a lockfile against OSV | **no diff** — you can't ask "what got worse between v1 and v2" |

**depdrift's angle (honest differentiation):**
1. **Release-delta framing.** It diffs two states and reports risk only on the *changed/added* set. A reviewer sees exactly the new attack surface a bump introduces, not a wall of pre-existing findings.
2. **Trust risks beyond CVEs.** Typosquatting detection (Levenshtein vs a bundled popular-package list) and abandonment detection (no release in > N years) — the classic vectors for a *newly added* dependency, which CVE scanners miss entirely because a malicious/dead package has no CVE.
3. **Cross-ecosystem, one report.** Python + Node in a single severity-ranked Markdown/JSON output with CI-friendly exit codes.
4. **Offline-first & keyless.** OSV.dev is free and needs no key; the test suite and demo run against recorded fixtures with zero network.

depdrift does **not** replace pip-audit/OSV-Scanner for a full point-in-time audit — it is the *code-review companion* that turns a lockfile change into a risk delta.

---

## 2. Architecture — module breakdown (built by 3–4 parallel subagents)

Package layout (`src/` layout, importable as `depdrift`):

```
depdrift/
├── pyproject.toml
├── README.md
├── LICENSE                     # MIT
├── .github/workflows/ci.yml
├── src/depdrift/
│   ├── __init__.py             # __version__ = "0.1.0"
│   ├── models.py               # [MODULE A] shared dataclasses (the data contract)
│   ├── parsers/
│   │   ├── __init__.py         # registry: EPARSERS, detect(path)->Parser, parse(path)->list[Dependency]
│   │   ├── base.py             # Parser ABC + LockfileParseError
│   │   ├── requirements_txt.py # [MODULE B] pip requirements.txt
│   │   ├── package_lock.py     # [MODULE B] npm package-lock.json (v2/v3)
│   │   ├── poetry_lock.py      # [MODULE B] (P3/stretch) poetry.lock (TOML)
│   │   ├── uv_lock.py          # [MODULE B] (P3/stretch) uv.lock (TOML)
│   │   └── pnpm_lock.py        # [MODULE B] (P3/stretch) pnpm-lock.yaml
│   ├── diffing.py              # [MODULE C] compute_diff(old, new) + semver classification
│   ├── semver.py               # [MODULE C] version parse + bump classification (py & npm)
│   ├── enrich/
│   │   ├── __init__.py         # enrich(diff, opts)->list[Risk]; orchestrates the three enrichers
│   │   ├── osv.py              # [MODULE D] OSV client (live + cached/offline)
│   │   ├── cache.py            # [MODULE D] on-disk JSON cache + fixture loader
│   │   ├── typosquat.py        # [MODULE D] Levenshtein vs bundled popular list
│   │   ├── abandonment.py      # [MODULE D] registry last-release lookup (online, optional)
│   │   └── data/
│   │       ├── popular_pypi.txt        # bundled top-N PyPI names
│   │       ├── popular_npm.txt         # bundled top-N npm names
│   │       └── osv_fixtures/           # recorded OSV responses for tests/demo
│   ├── report/
│   │   ├── __init__.py         # render(report, fmt)->str
│   │   ├── markdown.py         # [MODULE E] Markdown renderer
│   │   └── json_out.py         # [MODULE E] JSON renderer (stable schema)
│   ├── gitref.py               # [MODULE C] read a lockfile blob at a git ref
│   └── cli.py                  # [MODULE A/owner] argparse/click entrypoint, exit codes
└── tests/
    ├── fixtures/               # real lockfile pairs + recorded OSV JSON
    └── test_*.py
```

### Non-overlapping subagent assignment

The modules are drawn so builders never edit the same file. `models.py` is written **first**
and frozen as the contract; everyone imports from it.

- **Subagent 1 — Core & CLI (owner):** `models.py`, `cli.py`, `__init__.py`, `pyproject.toml`, CI, README, LICENSE. Defines the data contract, wires everyone together. Starts by publishing `models.py`, then builds CLI last against the finished modules.
- **Subagent 2 — Parsers:** everything under `parsers/`. Consumes `models.Dependency`. Owns the parser registry + per-ecosystem parsers + parse fixtures.
- **Subagent 3 — Diffing:** `diffing.py`, `semver.py`, `gitref.py`. Consumes `list[Dependency]`, produces `list[DepDiff]`. Pure/no-network → easiest to test.
- **Subagent 4 — Enrichment & Report:** `enrich/` and `report/`. Consumes `DepDiff`, produces `Risk`/`Report`, renders output. Owns OSV client, cache, typosquat, abandonment, and both renderers.

Dependency order for integration: A publishes contract → B, C, D build in parallel → A assembles CLI.

---

## 3. Shared data contract (`models.py`)

All dataclasses `@dataclass(frozen=True, slots=True)` unless noted. Enums are `str, Enum`
so they serialize cleanly to JSON.

```python
class Ecosystem(str, Enum):
    PYPI = "PyPI"        # value matches OSV ecosystem string exactly
    NPM  = "npm"

class ChangeKind(str, Enum):
    ADDED    = "added"
    REMOVED  = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    UNCHANGED = "unchanged"   # computed but excluded from report by default

class BumpLevel(str, Enum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    OTHER = "other"    # non-semver / pre-release / unparseable
    NONE  = "none"

class Severity(str, Enum):     # ordered low->critical for ranking
    NONE = "none"; LOW = "low"; MODERATE = "moderate"; HIGH = "high"; CRITICAL = "critical"

class RiskKind(str, Enum):
    VULN        = "vuln"
    TYPOSQUAT   = "typosquat"
    ABANDONED   = "abandoned"

@dataclass(frozen=True, slots=True)
class Dependency:
    name: str                  # normalized (PyPI: PEP 503 lowercase/dash; npm: as-is incl scope)
    version: str               # exact resolved version string
    ecosystem: Ecosystem
    direct: bool = True        # best-effort: top-level vs transitive
    raw: str | None = None     # original line/key for traceability

@dataclass(frozen=True, slots=True)
class DepDiff:
    name: str
    ecosystem: Ecosystem
    kind: ChangeKind
    old_version: str | None    # None for ADDED
    new_version: str | None    # None for REMOVED
    bump: BumpLevel = BumpLevel.NONE   # set for UPGRADED/DOWNGRADED

@dataclass(frozen=True, slots=True)
class Vuln:
    id: str                    # e.g. "GHSA-462w-v97r-4m45"
    aliases: tuple[str, ...]   # ("CVE-2019-10906", "PYSEC-2019-217")
    summary: str
    severity: Severity
    fixed_version: str | None  # first fixed version if OSV ranges give one
    reference_url: str | None

@dataclass(frozen=True, slots=True)
class Risk:
    kind: RiskKind
    dep: DepDiff               # the changed dep this risk attaches to
    severity: Severity
    title: str                 # one-line human summary
    detail: str                # longer explanation
    vuln: Vuln | None = None   # populated when kind == VULN
    evidence: dict | None = None  # e.g. {"nearest": "requests", "distance": 1} for typosquat

@dataclass(slots=True)         # not frozen: assembled incrementally
class Report:
    old_ref: str               # label of old state (path or git ref)
    new_ref: str
    generated_at: str          # ISO-8601 UTC
    diffs: list[DepDiff]
    risks: list[Risk]
    # derived helpers
    @property
    def added(self)   -> list[DepDiff]: ...
    @property
    def removed(self) -> list[DepDiff]: ...
    @property
    def upgraded(self)-> list[DepDiff]: ...
    @property
    def max_severity(self) -> Severity: ...   # drives exit code
    def to_dict(self) -> dict: ...            # canonical JSON shape
```

**Severity ordering helper** lives in `models.py` (`SEVERITY_ORDER: dict[Severity,int]`) so
diffing/report/cli all rank consistently.

---

## 4. OSV integration

### 4.1 Live request/response

Endpoint (single): `POST https://api.osv.dev/v1/query` — no key, no auth.

Request body:
```json
{ "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "2.4.1" }
```
`ecosystem` is `"PyPI"` or `"npm"` (exact strings — matches `Ecosystem` enum values).

Response (trimmed, confirmed live during planning):
```json
{ "vulns": [ {
  "id": "GHSA-462w-v97r-4m45",
  "summary": "Jinja2 sandbox escape via string formatting",
  "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
  "modified": "...", "published": "...",
  "database_specific": { "severity": "HIGH", "cwe_ids": ["CWE-693"] },
  "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..." } ],
  "affected": [ { "ranges": [ { "type": "ECOSYSTEM",
      "events": [ { "introduced": "0" }, { "fixed": "2.10.1" } ] } ] } ],
  "references": [ { "type": "ADVISORY", "url": "https://nvd.nist.gov/..." } ]
} ] }
```
Empty `{}` (or missing `vulns`) means no known vulnerabilities.

**Batch mode** (perf, P2+): `POST /v1/querybatch` accepts `{"queries":[...]}` and returns vuln
*IDs* only; depdrift then GETs `/v1/vulns/{id}` for details. v0.1.0 may ship with the simpler
per-package `/v1/query` (one request per changed dep) and add batch later.

### 4.2 Severity extraction

Priority: `database_specific.severity` (HIGH/MODERATE/LOW/CRITICAL string) → map to `Severity`.
Fallback: parse CVSS vector from `severity[].score`, bucket by base score
(0 none / <4 low / <7 moderate / <9 high / ≥9 critical). If neither present → `Severity.NONE`
but the vuln is still reported (`title` notes "severity unknown").

### 4.3 `fixed_version` extraction

From `affected[].ranges[].events[]`, take the first `fixed` value on an `ECOSYSTEM`/`SEMVER`
range whose `introduced` bound covers the dep's version. Best-effort; `None` if absent.

### 4.4 Offline / fixture strategy (CI never hits network)

`enrich/osv.py` exposes `OSVClient(mode: "live"|"cached"|"offline")`:

- **offline** (default in tests & `--offline`): NEVER makes a request. Looks up
  `enrich/data/osv_fixtures/{ecosystem}/{name}@{version}.json`; missing file ⇒ treated as
  "no known vulns" (empty result). Deterministic, hermetic.
- **cached**: check on-disk cache (`~/.cache/depdrift/osv/` via `cache.py`, keyed by
  `ecosystem/name/version` + 7-day TTL); on miss, do a live request and write-through.
- **live**: always request, still write cache.

Fixtures are **recorded real responses** (e.g. the `jinja2@2.4.1` payload above, trimmed to
the fields depdrift reads) committed under `tests/fixtures/osv/` and mirrored to the packaged
`enrich/data/osv_fixtures/` for the demo. A tiny dev script `scripts/record_osv.py`
(documented, not shipped in wheel) regenerates fixtures on demand. Network access in tests is
blocked by a `pytest` autouse fixture that monkeypatches the HTTP layer to raise, guaranteeing
no accidental live calls.

HTTP client: `httpx` (timeout 10s, one retry on 5xx/timeout). Standard-lib `urllib` acceptable
fallback to avoid a hard dep — decision recorded in README; plan assumes `httpx`.

---

## 5. Typosquat & abandonment

**Typosquat (`enrich/typosquat.py`, fully offline):**
- Bundled `popular_pypi.txt` / `popular_npm.txt` (top ~1000 names each, committed).
- For each **ADDED** dep, compute Levenshtein distance to every popular name of the same
  ecosystem. Flag when `1 <= distance <= 2` **and** the added name is NOT itself in the list
  (i.e. it's a near-miss of a popular package but not that package).
- Also flag zero-distance-after-normalization confusables (hyphen/underscore/homoglyph
  swaps, e.g. `python-requests` vs `requests`, `crossenv` vs `cross-env`).
- Severity: `HIGH` for distance 1 to a top-100 name, else `MODERATE`.
- `evidence = {"nearest": <popular>, "distance": <n>}`. Pure function → trivially unit-tested.
- Levenshtein: small hand-rolled DP (no external dep) in `typosquat.py`.

**Abandonment (`enrich/abandonment.py`, online, optional):**
- For each ADDED/UPGRADED dep, query registry metadata for last release date:
  - PyPI: `GET https://pypi.org/pypi/{name}/json` → `releases` → max upload_time.
  - npm: `GET https://registry.npmjs.org/{name}` → `time.modified` / latest version time.
- Flag when last release older than `--abandoned-years` (default 2y). Severity `MODERATE`
  (`LOW` if only slightly over threshold).
- Skipped in `--offline` mode; has its own tiny recorded fixtures for the two unit tests.

---

## 6. Diffing (`diffing.py` + `semver.py`)

`compute_diff(old: list[Dependency], new: list[Dependency]) -> list[DepDiff]`:
- Index both by `(ecosystem, name)`.
- Key only in new ⇒ `ADDED`; only in old ⇒ `REMOVED`; in both ⇒ compare versions:
  equal ⇒ `UNCHANGED`; new>old ⇒ `UPGRADED`; new<old ⇒ `DOWNGRADED`.
- `classify_bump(old_v, new_v, ecosystem) -> BumpLevel`:
  - PyPI: parse with `packaging.version.Version`; compare `release` tuple → major/minor/patch;
    pre/dev/post transitions or unparseable ⇒ `OTHER`.
  - npm: semver `x.y.z` compare (hand-rolled, handles `^`/`~` stripped, pre-release ⇒ `OTHER`).
- Ordering: results sorted by ecosystem then name for stable output.
- Comparison uses each ecosystem's ordering rules; unparseable versions never crash — they
  fall to `OTHER` and string-inequality decides upgraded/downgraded (documented behavior).

`gitref.py` — `read_lockfile_at_ref(repo, ref, path) -> str` via
`git show {ref}:{path}` (subprocess). Supports `A..B` range parsing in the CLI.

---

## 7. CLI surface (`cli.py`)

```
depdrift diff OLD NEW [options]
depdrift diff --git REFA..REFB [--path PATH] [options]
depdrift --version
```

Positional: `OLD`, `NEW` — lockfile paths (ecosystem auto-detected by filename/content).

Options:
| Flag | Default | Meaning |
|------|---------|---------|
| `--git REFA..REFB` | — | diff the lockfile at two git refs instead of two files |
| `--path PATH` | auto | lockfile path within repo (required with `--git` if ambiguous) |
| `--format {markdown,json}` | markdown | output format |
| `-o, --output FILE` | stdout | write report to file |
| `--offline` | on in CI/tests | never touch the network (OSV fixtures only, skip abandonment) |
| `--live` | — | force live OSV + abandonment queries |
| `--no-osv` / `--no-typosquat` / `--no-abandonment` | all on | toggle individual enrichers |
| `--abandoned-years N` | 2 | abandonment threshold |
| `--fail-on {none,low,moderate,high,critical}` | low | min severity that yields exit code 1 |
| `--include-unchanged` | off | show unchanged deps too |

**Exit codes:**
- `0` — clean (no risk at/above `--fail-on`).
- `1` — vulns/risks found at/above threshold.
- `2` — error (parse failure, bad git ref, invalid args, network error in `--live`).

Exit code derives from `Report.max_severity` vs `--fail-on`.

---

## 8. Quality gate — real tests (no stubs), lint, CI

Test fixtures are **real files** committed under `tests/fixtures/`:
`req_old.txt`/`req_new.txt`, `pkglock_old.json`/`pkglock_new.json`, and recorded OSV JSON.

Enumerated tests (≥15, all assert real behavior):

**Parsers**
1. `test_parse_requirements_basic` — parses `name==version`, count + exact versions.
2. `test_parse_requirements_ignores_comments_and_options` — skips `#`, `-r`, `--hash`, blank lines, env markers.
3. `test_parse_requirements_normalizes_names` — `Flask` / `python_dateutil` → PEP 503 normalized.
4. `test_parse_package_lock_v3` — parses `packages` map, strips leading `node_modules/`, gets scoped `@scope/x`.
5. `test_parse_package_lock_marks_direct_vs_transitive` — top-level deps flagged `direct=True`.
6. `test_parser_registry_detects_ecosystem` — `detect()` picks the right parser by filename.
7. `test_parser_raises_on_malformed` — corrupt JSON/line → `LockfileParseError`, exit-2 path.

**Diffing / semver**
8. `test_diff_added_removed_unchanged` — three-bucket correctness on a crafted pair.
9. `test_diff_semver_major_minor_patch` — `1.2.3→2.0.0` major, `→1.3.0` minor, `→1.2.4` patch.
10. `test_diff_downgrade_detected` — `2.0.0→1.9.0` ⇒ DOWNGRADED.
11. `test_classify_bump_prerelease_is_other` — `1.0.0→1.0.1rc1` ⇒ OTHER, no crash.
12. `test_diff_cross_ecosystem_keys_isolated` — same name in PyPI & npm don't collide.

**Enrichment**
13. `test_osv_offline_hits_fixture` — `jinja2@2.4.1` fixture ⇒ 1 Vuln, id + HIGH severity + CVE alias.
14. `test_osv_offline_no_vuln_returns_empty` — version with no fixture ⇒ no Risk.
15. `test_osv_severity_and_fixed_version_parsing` — extracts `fixed_version=2.10.1` from ranges.
16. `test_osv_network_blocked_in_offline` — asserts no HTTP call made (monkeypatched raiser).
17. `test_typosquat_distance_one_flagged` — `requsts`/`reqests` flagged nearest `requests` dist≤2.
18. `test_typosquat_exact_popular_not_flagged` — `requests` itself ⇒ no flag.
19. `test_typosquat_confusable_underscore_hyphen` — `cross_env` vs `cross-env` flagged.
20. `test_abandonment_over_threshold` — recorded metadata older than 2y ⇒ ABANDONED risk.

**Report / CLI**
21. `test_markdown_report_sections` — output contains Added/Removed/Upgraded + a Risks table + severity badge.
22. `test_json_report_schema_stable` — `to_dict()` round-trips, has required keys, JSON-serializable.
23. `test_report_severity_ranking` — risks sorted critical→low.
24. `test_cli_exit_code_1_on_vuln` — end-to-end on fixture pair ⇒ exit 1.
25. `test_cli_exit_code_0_when_clean` — clean pair ⇒ exit 0.
26. `test_cli_exit_code_2_on_bad_input` — missing file ⇒ exit 2.
27. `test_cli_git_ref_mode` — `--git` reads lockfile via `git show` from a tmp repo built in the test.

**Tooling**
- **ruff** (lint + format check) clean; config in `pyproject.toml`.
- **mypy** (optional, `strict` on `models.py`/`diffing.py`).
- **pytest** with `--cov`, autouse network-block fixture, target ≥85% line coverage.
- **GitHub Actions** `.github/workflows/ci.yml`: matrix py3.10/3.11/3.12 on ubuntu; steps =
  install → `ruff check` → `ruff format --check` → `pytest` (offline). No secrets, no network.
- **README.md** outline: what/why (diff framing), install, `depdrift diff` quickstart,
  sample Markdown output, git-ref mode, offline vs live, exit codes, ecosystem support matrix,
  limitations, roadmap.
- **LICENSE**: MIT.
- **Release v0.1.0**: tag `v0.1.0`, GitHub release notes, build sdist+wheel (`python -m build`).

---

## 9. Offline / free-tier guarantees

- OSV.dev — free, public, **no API key**. Live mode uses it directly.
- CI + local test suite run with `--offline`; all OSV/registry data comes from committed
  fixtures. A pytest autouse fixture hard-blocks outbound HTTP so a regression can never
  silently depend on the network.
- Typosquat + Levenshtein are 100% local (bundled name lists, no external lib).
- Abandonment is the only strictly-online feature; it is opt-in (`--live`) and its unit tests
  use recorded fixtures.
- Zero paid services anywhere in the stack.

---

## 10. Phased roadmap

- **P0 — Scaffold.** `pyproject.toml`, src layout, `models.py` (frozen contract), `__init__`
  with version, ruff config, empty CI, LICENSE, README skeleton. Gate: `pip install -e .`
  imports cleanly, `ruff check` passes.
- **P1 — Parsers + diff.** `requirements_txt.py`, `package_lock.py`, parser registry,
  `diffing.py`, `semver.py`. Tests 1–12. Gate: `depdrift diff old new` prints a Markdown diff
  (no enrichment yet), exit 0.
- **P2 — OSV enrich (offline fixtures).** `enrich/osv.py`, `cache.py`, `enrich/__init__`,
  report renderers, recorded fixtures, network-block fixture. Tests 13–16, 21–26. Gate:
  vuln in fixture ⇒ exit 1, offline, deterministic.
- **P3 — Trust risks + git mode.** `typosquat.py` (+ bundled lists), `abandonment.py`,
  `gitref.py`, `--git` CLI. Tests 17–20, 27. Gate: typosquat + git-ref demo work offline.
- **Ship.** Fill README, finalize CI matrix, tag **v0.1.0**, publish release + wheel.
  Stretch (post-0.1): poetry.lock / uv.lock / pnpm-lock parsers, OSV batch endpoint, SARIF
  output, GitHub Action wrapper.

---

## 11. Risks & differentiation (honest)

**Product risk — "isn't this just OSV-Scanner?"** No: OSV-Scanner is point-in-time. depdrift's
value is the *delta* + trust signals (typosquat/abandonment) scoped to newly-introduced deps.
If a reviewer only wants a full audit, they should still use OSV-Scanner/pip-audit; depdrift is
the PR-time companion.

**Technical risks & mitigations:**
- *Lockfile format drift* (npm v1/v2/v3, poetry versions) → parser ABC + registry isolates each
  format; ship the two most stable first, mark others experimental.
- *Version-comparison edge cases* (epochs, pre-releases, npm ranges) → never crash; fall to
  `BumpLevel.OTHER`; documented and unit-tested.
- *OSV flakiness/rate limits* → offline-first design; live mode is opt-in with retry+cache.
- *Typosquat false positives* → conservative distance window (1–2) + exclude exact popular
  names + severity tiering; the report labels these as *signals*, not verdicts.
- *Name normalization mismatches across old/new* → single normalization pass in each parser so
  diff keys are consistent (PEP 503 for PyPI, scope-preserving for npm).

**Differentiation summary:** the diff framing + trust risks (typosquat/abandonment) on the
*newly-introduced* set, cross-ecosystem, keyless and offline-testable — that combination is not
served by pip-audit, npm audit, Dependabot, or OSV-Scanner individually.
