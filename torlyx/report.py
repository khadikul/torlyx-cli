"""Terminal report renderer, JSON exporter, and score calculation.

Language-agnostic: renders any :class:`~torlyx.models.ScanResult`
regardless of which parser backend produced the findings.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.text import Text

import torlyx
from torlyx.models import Finding, ScanResult, Severity

DOCS_URL = "https://github.com/khadikul/torlyx"

#: Score deductions per finding severity.
_PENALTY = {Severity.CRITICAL: 20, Severity.WARNING: 5, Severity.INFO: 1}

_BADGE = {
    Severity.CRITICAL: ("🔴", "CRITICAL", "bold red"),
    Severity.WARNING: ("🟡", "WARNING ", "bold yellow"),
    Severity.INFO: ("🔵", "INFO    ", "bold blue"),
}


def calculate_score(findings: list[Finding]) -> int:
    """Security score: start at 100, deduct per finding, floor at 0."""
    score = 100
    for finding in findings:
        score -= _PENALTY[finding.severity]
    return max(0, score)


def _score_style(score: int) -> str:
    if score >= 90:
        return "bold green"
    if score >= 70:
        return "bold yellow"
    return "bold red"


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

    if not result.findings:
        console.print(
            "  🎉 [bold green]No issues found — Security Score: 100/100[/bold green]"
        )
        console.print()
        _render_footer(result, console, score, show_score=False)
        return

    for finding in result.sorted_findings():
        emoji, label, style = _BADGE[finding.severity]
        header = Text("  ")
        header.append(f"{emoji} {label}", style=style)
        header.append(f"  {finding.rule_id}", style="bold")
        header.append(" · ", style="dim")
        header.append(finding.title, style="bold")
        console.print(header)

        location = Text(f"     {finding.file}:{finding.line}", style="cyan")
        if finding.context:
            location.append(f" → {finding.context}", style="magenta")
        console.print(location)

        console.print(f"     [italic]→ {finding.message}[/italic]")
        if finding.fix:
            console.print(f"     [green]Fix:[/green] {finding.fix}")
        console.print()

    _render_footer(result, console, score)


def _render_footer(
    result: ScanResult, console: Console, score: int, show_score: bool = True
) -> None:
    for note in result.notes:
        console.print(f"  [dim]ℹ {note}[/dim]")
    if result.notes:
        console.print()

    console.print("  " + "─" * 45, style="dim")
    if show_score:
        console.print(
            f"  Security Score: "
            f"[{_score_style(score)}]{score}/100[/{_score_style(score)}]"
        )

    parts: list[str] = []
    if result.criticals:
        parts.append(f"[red]{result.criticals} critical[/red]")
    if result.warnings:
        parts.append(f"[yellow]{result.warnings} warning[/yellow]")
    if result.infos:
        parts.append(f"[blue]{result.infos} info[/blue]")
    unit = "check" if result.rules_passed == 1 else "checks"
    parts.append(f"[green]{result.rules_passed} {unit} passed[/green]")
    console.print("  " + " · ".join(parts))
    console.print(f"  [dim]Docs: {DOCS_URL}[/dim]")
    console.print()


def to_json(result: ScanResult) -> str:
    """Machine-readable JSON document (findings + score + metadata)."""
    payload = {
        "tool": "torlyx",
        "version": torlyx.__version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "duration_seconds": round(result.duration_seconds, 3),
        "score": calculate_score(result.findings),
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
