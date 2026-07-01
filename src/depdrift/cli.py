"""depdrift CLI.

    depdrift diff OLD NEW [options]          # diff two lockfiles
    depdrift diff --git REFA..REFB --path P  # diff one lockfile across git refs
    depdrift --version

Exit codes: 0 clean · 1 risk at/above --fail-on · 2 error.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .diffing import compute_diff
from .enrich import EnrichOptions, enrich
from .gitref import GitError, parse_git_range, read_lockfile_at_ref
from .models import Report, Severity, severity_rank
from .parsers import LockfileParseError, parse, parse_source
from .report import render

app = typer.Typer(add_completion=False, help="Supply-chain DIFF for dependency lockfiles.")


class DepdriftError(Exception):
    """Any operational failure that should map to exit code 2."""


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="print version and exit"),
) -> None:
    if version:
        typer.echo(f"depdrift {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


def _exit_code(report: Report, fail_on: Severity) -> int:
    if not report.risks:
        return 0
    if fail_on == Severity.NONE:
        return 1
    if severity_rank(report.max_severity) >= severity_rank(fail_on):
        return 1
    return 0


def build_report(
    *,
    old: Optional[str],
    new: Optional[str],
    git: Optional[str],
    path: Optional[str],
    repo: str,
    offline: bool,
    do_osv: bool,
    do_typosquat: bool,
    do_abandonment: bool,
    abandoned_years: float,
) -> Report:
    """Load both states, diff, enrich, and assemble a Report. Raises DepdriftError."""
    if git:
        if not path:
            raise DepdriftError("--git requires --path to locate the lockfile in the repo")
        try:
            ref_a, ref_b = parse_git_range(git)
        except ValueError as e:
            raise DepdriftError(str(e)) from e
        try:
            old_text = read_lockfile_at_ref(repo, ref_a, path)
            new_text = read_lockfile_at_ref(repo, ref_b, path)
        except GitError as e:
            raise DepdriftError(f"git: {e}") from e
        try:
            old_deps = parse_source(old_text, path)
            new_deps = parse_source(new_text, path)
        except LockfileParseError as e:
            raise DepdriftError(str(e)) from e
        old_ref, new_ref = f"{ref_a}:{path}", f"{ref_b}:{path}"
    else:
        if not old or not new:
            raise DepdriftError("OLD and NEW lockfile paths are required (or use --git)")
        try:
            old_deps = parse(old)
            new_deps = parse(new)
        except LockfileParseError as e:
            raise DepdriftError(str(e)) from e
        old_ref, new_ref = old, new

    diffs = compute_diff(old_deps, new_deps)
    opts = EnrichOptions(
        offline=offline,
        osv=do_osv,
        typosquat=do_typosquat,
        abandonment=do_abandonment,
        abandoned_years=abandoned_years,
    )
    risks = enrich(diffs, opts)
    return Report(
        old_ref=old_ref,
        new_ref=new_ref,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        diffs=diffs,
        risks=risks,
    )


@app.command()
def diff(
    old: Optional[str] = typer.Argument(None, help="old lockfile path"),
    new: Optional[str] = typer.Argument(None, help="new lockfile path"),
    git: Optional[str] = typer.Option(None, "--git", help="diff a lockfile across REFA..REFB"),
    path: Optional[str] = typer.Option(None, "--path", help="lockfile path in the repo (--git)"),
    repo: str = typer.Option(".", "--repo", help="git repo directory for --git mode"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown|json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="write report to FILE"),
    live: bool = typer.Option(False, "--live", help="allow live OSV + abandonment network queries"),
    offline: bool = typer.Option(False, "--offline", help="never touch the network (default)"),
    no_osv: bool = typer.Option(False, "--no-osv", help="skip OSV vulnerability lookups"),
    no_typosquat: bool = typer.Option(False, "--no-typosquat", help="skip typosquat detection"),
    no_abandonment: bool = typer.Option(False, "--no-abandonment", help="skip abandonment check"),
    abandoned_years: float = typer.Option(2.0, "--abandoned-years", help="abandonment threshold"),
    fail_on: str = typer.Option("low", "--fail-on", help="min severity for exit code 1"),
    include_unchanged: bool = typer.Option(False, "--include-unchanged", help="show unchanged"),
) -> None:
    """Diff two dependency states and report the risk delta on the changed set."""
    is_offline = not live  # offline is the default; --live opts into the network
    if offline:
        is_offline = True

    try:
        threshold = Severity(fail_on.lower())
    except ValueError:
        typer.secho(f"error: invalid --fail-on {fail_on!r}", fg="red", err=True)
        raise typer.Exit(2) from None

    try:
        report = build_report(
            old=old,
            new=new,
            git=git,
            path=path,
            repo=repo,
            offline=is_offline,
            do_osv=not no_osv,
            do_typosquat=not no_typosquat,
            do_abandonment=(not no_abandonment) and (not is_offline),
            abandoned_years=abandoned_years,
        )
    except DepdriftError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from None

    if not include_unchanged:
        report.diffs = [d for d in report.diffs if d.kind.value != "unchanged"]

    rendered = render(report, fmt)
    if output:
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"wrote {fmt} report to {output}")
    else:
        typer.echo(rendered)

    raise typer.Exit(_exit_code(report, threshold))


if __name__ == "__main__":
    app()
