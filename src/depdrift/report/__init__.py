"""Report rendering dispatch: markdown | json."""

from __future__ import annotations

import json

from ..models import Report
from .json_out import render_json
from .markdown import render_markdown

__all__ = ["render", "render_markdown", "render_json"]


def render(report: Report, fmt: str = "markdown") -> str:
    fmt = fmt.lower()
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "json":
        return json.dumps(render_json(report), indent=2)
    raise ValueError(f"unknown report format: {fmt!r} (use markdown|json)")
