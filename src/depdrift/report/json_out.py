"""JSON renderer — a thin wrapper over Report.to_dict for a stable schema."""

from __future__ import annotations

from ..models import Report


def render_json(report: Report) -> dict:
    return report.to_dict()
