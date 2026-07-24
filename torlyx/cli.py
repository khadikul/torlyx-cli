"""Torlyx command-line interface.

Commands:
    torlyx scan PATH   — scan a project (the main event)
    torlyx version     — print the version
    torlyx rules       — list every rule with a one-line description
"""

from __future__ import annotations

import enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

import torlyx
from torlyx import checks, report, scanner
from torlyx.models import Severity

app = typer.Typer(
    name="torlyx",
    help="Scan your vibe-coded app before you ship it.",
    add_completion=False,
    no_args_is_help=True,
)

_console = Console()
_err_console = Console(stderr=True)


class FailOn(str, enum.Enum):
    """Threshold for CI-friendly non-zero exit codes."""

    critical = "critical"
    warning = "warning"
    any = "any"


class ExportFormat(str, enum.Enum):
    """File formats for --export."""

    md = "md"


def _threshold_met(result, fail_on: FailOn) -> bool:
    if fail_on is FailOn.critical:
        return result.criticals > 0
    if fail_on is FailOn.warning:
        return result.criticals > 0 or result.warnings > 0
    return len(result.findings) > 0


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        exists=True,
        help="Project directory to scan (defaults to the current directory).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON to stdout."
    ),
    fail_on: FailOn | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if findings at/above this level exist (for CI).",
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="Glob pattern to exclude (repeatable)."
    ),
    no_audit: bool = typer.Option(
        False,
        "--no-audit",
        help="Skip the dependency CVE audit — the only check that uses the network.",
    ),
    export: ExportFormat | None = typer.Option(
        None,
        "--export",
        help="Also write torlyx-report.md — an AI-ready report you can paste "
        "into Cursor/Claude/Copilot to fix each finding.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show skipped files and extra notes."
    ),
) -> None:
    """Scan a project for security issues. Zero config, runs locally."""
    try:
        result = scanner.scan(
            path, excludes=list(exclude), verbose=verbose, audit=not no_audit
        )
    except Exception as exc:  # scan error → exit 2, never a traceback
        _err_console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2)

    if json_output:
        typer.echo(report.to_json(result))
    else:
        report.render(result, _console)

    if export is ExportFormat.md:
        out = Path.cwd() / "torlyx-report.md"
        out.write_text(report.to_markdown(result), encoding="utf-8", newline="\n")
        _err_console.print(
            f"[green]Report written to[/green] {out} — paste it into your AI "
            "assistant to fix each finding."
        )

    if fail_on is not None and _threshold_met(result, fail_on):
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the Torlyx version."""
    typer.echo(f"torlyx {torlyx.__version__}")


@app.command()
def rules() -> None:
    """List all rule IDs with one-line descriptions."""
    table = Table(title=f"Torlyx rules ({len(checks.all_rules())})", show_lines=False)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    table.add_column("Description")
    style = {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
    }
    for rule in checks.all_rules():
        table.add_row(
            rule.id,
            f"[{style[rule.severity]}]{rule.severity.value}[/{style[rule.severity]}]",
            rule.title,
            rule.description,
        )
    _console.print(table)


if __name__ == "__main__":
    app()
