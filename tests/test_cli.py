"""End-to-end CLI tests, incl. git-ref mode (24-27)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from typer.testing import CliRunner

from depdrift.cli import app

runner = CliRunner()


def test_cli_exit_code_1_on_vuln(fx):
    # req_new adds jinja2==2.4.1, which has a recorded OSV HIGH vuln
    result = runner.invoke(app, ["diff", fx("req_old.txt"), fx("req_new.txt")])
    assert result.exit_code == 1
    assert "jinja2" in result.stdout
    assert "Added" in result.stdout


def test_cli_exit_code_0_when_clean(fx):
    # req_clean is a patch-only bump of the old set: no adds, no vulns
    result = runner.invoke(app, ["diff", fx("req_old.txt"), fx("req_clean.txt")])
    assert result.exit_code == 0
    assert "No risks found" in result.stdout


def test_cli_exit_code_2_on_bad_input(fx):
    result = runner.invoke(app, ["diff", fx("does_not_exist.txt"), fx("req_new.txt")])
    assert result.exit_code == 2
    result2 = runner.invoke(app, ["diff", fx("req_old.txt")])  # missing NEW
    assert result2.exit_code == 2


def test_cli_json_format(fx):
    import json

    result = runner.invoke(app, ["diff", fx("req_old.txt"), fx("req_new.txt"), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"]["max_severity"] == "high"


def test_cli_git_ref_mode(tmp_path: Path, fx):
    repo = tmp_path
    env_run = lambda *args: subprocess.run(  # noqa: E731
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    env_run("init", "-q")
    env_run("config", "user.email", "t@example.com")
    env_run("config", "user.name", "t")

    lock = repo / "requirements.txt"
    lock.write_text(Path(fx("req_old.txt")).read_text())
    env_run("add", "requirements.txt")
    env_run("commit", "-q", "-m", "old")

    lock.write_text(Path(fx("req_new.txt")).read_text())
    env_run("add", "requirements.txt")
    env_run("commit", "-q", "-m", "new")

    result = runner.invoke(
        app,
        ["diff", "--git", "HEAD~1..HEAD", "--path", "requirements.txt", "--repo", str(repo)],
    )
    assert result.exit_code == 1
    assert "jinja2" in result.stdout
