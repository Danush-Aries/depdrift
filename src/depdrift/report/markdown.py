"""Markdown renderer for a depdrift Report."""

from __future__ import annotations

from ..models import BumpLevel, Report, Severity

_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MODERATE: "🟡 MODERATE",
    Severity.LOW: "🔵 LOW",
    Severity.NONE: "⚪ NONE",
}


def _bump_note(bump: BumpLevel) -> str:
    return f" ({bump.value})" if bump not in (BumpLevel.NONE, BumpLevel.OTHER) else ""


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append("# depdrift report")
    lines.append("")
    lines.append(f"- **old:** `{report.old_ref}`")
    lines.append(f"- **new:** `{report.new_ref}`")
    lines.append(f"- **generated:** {report.generated_at}")
    lines.append(f"- **max severity:** {_BADGE[report.max_severity]}")
    lines.append("")
    lines.append(
        f"**{len(report.added)} added · {len(report.removed)} removed · "
        f"{len(report.upgraded)} upgraded · {len(report.downgraded)} downgraded · "
        f"{len(report.risks)} risk(s)**"
    )
    lines.append("")

    if report.added:
        lines.append("## Added")
        for d in report.added:
            lines.append(f"- `{d.name}` @ {d.new_version} ({d.ecosystem.value})")
        lines.append("")

    if report.removed:
        lines.append("## Removed")
        for d in report.removed:
            lines.append(f"- `{d.name}` @ {d.old_version} ({d.ecosystem.value})")
        lines.append("")

    if report.upgraded:
        lines.append("## Upgraded")
        for d in report.upgraded:
            lines.append(f"- `{d.name}` {d.old_version} → {d.new_version}{_bump_note(d.bump)}")
        lines.append("")

    if report.downgraded:
        lines.append("## Downgraded")
        for d in report.downgraded:
            lines.append(f"- `{d.name}` {d.old_version} → {d.new_version}{_bump_note(d.bump)}")
        lines.append("")

    if report.unchanged:
        lines.append("## Unchanged")
        for d in report.unchanged:
            lines.append(f"- `{d.name}` @ {d.new_version} ({d.ecosystem.value})")
        lines.append("")

    lines.append("## Risks")
    if not report.risks:
        lines.append("")
        lines.append("_No risks found on the changed dependency set._")
    else:
        lines.append("")
        lines.append("| Severity | Kind | Package | Detail |")
        lines.append("|----------|------|---------|--------|")
        for r in report.risks:
            detail = r.detail.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {_BADGE[r.severity]} | {r.kind.value} | `{r.dep.name}` | {detail} |")
    lines.append("")
    return "\n".join(lines)
