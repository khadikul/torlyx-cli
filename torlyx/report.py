"""Terminal report renderer, JSON/Markdown exporters, and score calculation.

Language-agnostic: renders any :class:`~torlyx.models.ScanResult`
regardless of which parser backend produced the findings.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.padding import Padding
from rich.text import Text

import torlyx
from torlyx.models import Finding, ScanResult, Severity

DOCS_URL = "https://github.com/khadikul/torlyx-cli"

#: Score deductions per finding severity.
_PENALTY = {Severity.CRITICAL: 20, Severity.WARNING: 5, Severity.INFO: 1}

_BADGE = {
    Severity.CRITICAL: ("🔴", "CRITICAL", "bold red"),
    Severity.WARNING: ("🟡", "WARNING ", "bold yellow"),
    Severity.INFO: ("🔵", "INFO    ", "bold blue"),
}

#: (minimum score, grade) — first match wins.
_GRADES = ((90, "A"), (75, "B"), (60, "C"), (30, "D"))

_BAR_WIDTH = 20

#: Continuation lines of wrapped text stay aligned under the first line.
_INDENT = (0, 2, 0, 5)  # (top, right, bottom, left)


def calculate_score(findings: list[Finding]) -> int:
    """Security score: start at 100, deduct per finding, floor at 0."""
    score = 100
    for finding in findings:
        score -= _PENALTY[finding.severity]
    return max(0, score)


def grade(score: int) -> str:
    """Letter grade for a score: A ≥90, B ≥75, C ≥60, D ≥30, else F."""
    for minimum, letter in _GRADES:
        if score >= minimum:
            return letter
    return "F"


def _score_style(score: int) -> str:
    if score >= 90:
        return "bold green"
    if score >= 70:
        return "bold yellow"
    return "bold red"


def _score_header(result: ScanResult, score: int) -> Text:
    style = _score_style(score)
    filled = round(score * _BAR_WIDTH / 100)
    line = Text("  Security Score: ")
    line.append(f"{score}/100", style=style)
    line.append("  ")
    line.append("█" * filled, style=style)
    line.append("░" * (_BAR_WIDTH - filled), style="dim")
    line.append("  Grade: ")
    line.append(grade(score), style=style)
    return line


def _counts_line(result: ScanResult) -> str:
    parts: list[str] = []
    if result.criticals:
        parts.append(f"🔴 [red]{result.criticals} critical[/red]")
    if result.warnings:
        parts.append(f"🟡 [yellow]{result.warnings} warning[/yellow]")
    if result.infos:
        parts.append(f"🔵 [blue]{result.infos} info[/blue]")
    return "  " + " · ".join(parts)


def render(result: ScanResult, console: Console | None = None) -> None:
    """Render the human-readable scan report to the terminal."""
    console = console or Console()
    score = calculate_score(result.findings)

    console.print()
    console.print("  [bold]⚡ TORLYX SECURITY SCAN[/bold]")
    console.print(
        f"  [dim]Scanned {result.files_scanned} files "
        f"in {result.duration_seconds:.1f}s[/dim]"
    )
    console.print()
    console.print(_score_header(result, score))
    if result.findings:
        console.print(_counts_line(result))
    else:
        console.print("  🎉 [bold green]No issues found[/bold green]")
    console.print()

    for finding in result.sorted_findings():
        emoji, label, style = _BADGE[finding.severity]
        header = Text("  ")
        header.append(f"{emoji} {label}", style=style)
        header.append(f"  {finding.rule_id}", style="bold")
        header.append(" · ", style="dim")
        header.append(finding.title, style="bold")
        console.print(header)

        location = Text(finding.file + ":" + str(finding.line), style="cyan")
        if finding.context:
            location.append(f" → {finding.context}", style="magenta")
        console.print(Padding(location, _INDENT))

        message = Text("→ ", style="italic")
        message.append(finding.message, style="italic")
        console.print(Padding(message, _INDENT))

        if finding.fix:
            fix = Text("Fix: ", style="green")
            fix.append(finding.fix)
            console.print(Padding(fix, _INDENT))
        console.print()

    _render_footer(result, console)


def _render_footer(result: ScanResult, console: Console) -> None:
    for note in result.notes:
        console.print(f"  [dim]ℹ {note}[/dim]")
    if result.notes:
        console.print()

    console.print("  " + "─" * 45, style="dim")
    unit = "check" if result.rules_passed == 1 else "checks"
    console.print(f"  [green]{result.rules_passed} {unit} passed[/green]")
    if result.findings:
        console.print(
            "  Fix the [red]reds[/red] first, then run torlyx again "
            "to watch your score climb."
        )
    else:
        console.print("  [bold]Ship it. 🚀[/bold]")
    console.print(
        '  [dim]Tip: add "torlyx scan . --fail-on critical" to CI to stay clean.[/dim]'
    )
    console.print(f"  [dim]Docs: {DOCS_URL}[/dim]")
    console.print()


def to_json(result: ScanResult) -> str:
    """Machine-readable JSON document (findings + score + metadata)."""
    score = calculate_score(result.findings)
    payload = {
        "tool": "torlyx",
        "version": torlyx.__version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "duration_seconds": round(result.duration_seconds, 3),
        "score": score,
        "grade": grade(score),
        "counts": {
            "critical": result.criticals,
            "warning": result.warnings,
            "info": result.infos,
            "checks_passed": result.rules_passed,
        },
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "notes": result.notes,
    }
    return json.dumps(payload, indent=2)


def to_markdown(result: ScanResult) -> str:
    """AI-ready Markdown report: paste into an assistant, ask it to fix each finding."""
    score = calculate_score(result.findings)
    lines = [
        "# ⚡ Torlyx Security Report",
        "",
        f"**Security Score: {score}/100 (Grade {grade(score)})** — "
        f"{result.criticals} critical · {result.warnings} warning · "
        f"{result.infos} info · {result.files_scanned} files scanned",
        "",
        "> 🤖 **Paste this report into your AI assistant (Cursor, Claude Code, "
        "Copilot …) and ask it to fix each finding.** Every finding lists the "
        "exact file and line, why it is dangerous, and the fix to apply. "
        "Fix the criticals first.",
        "",
    ]

    if not result.findings:
        lines += ["No issues found — nothing to fix. 🎉", ""]
    else:
        lines += ["## Findings", ""]
        for number, finding in enumerate(result.sorted_findings(), start=1):
            location = f"`{finding.file}:{finding.line}`"
            if finding.context:
                location += f" ({finding.context})"
            lines += [
                f"### {number}. [{finding.severity.value.upper()}] "
                f"{finding.rule_id} · {finding.title}",
                "",
                f"- **Where:** {location}",
                f"- **Why it matters:** {finding.message}",
            ]
            if finding.fix:
                if "\n" in finding.fix:
                    lines += ["- **Fix:**", "", "  ```", *(
                        "  " + fix_line for fix_line in finding.fix.splitlines()
                    ), "  ```"]
                else:
                    lines.append(f"- **Fix:** `{finding.fix}`")
            lines.append("")

    if result.notes:
        lines += ["## Notes", "", *(f"- {note}" for note in result.notes), ""]

    lines += [
        "---",
        "",
        f"_Generated by [Torlyx]({DOCS_URL}) v{torlyx.__version__} — "
        "`torlyx scan . --export md`_",
        "",
    ]
    return "\n".join(lines)
