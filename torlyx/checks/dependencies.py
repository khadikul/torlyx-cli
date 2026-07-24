"""Dependency audit (TLX-D001): known CVEs via pip-audit.

The only rule that may touch the network. Wraps ``pip-audit`` in a
subprocess; if pip-audit is missing, offline, or anything else goes wrong,
a friendly note is added to the scan and the rule is skipped — never a crash.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from torlyx.models import Finding, Rule, Severity

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

RULES: list[Rule] = [
    Rule(
        "TLX-D001",
        "Vulnerable dependency",
        Severity.WARNING,
        "A dependency has a known CVE (severity mapped from CVSS: ≥7 critical, ≥4 warning, else info).",
    ),
]

_AUDIT_TIMEOUT_SECONDS = 120


def _audit_command() -> list[str] | None:
    """Locate pip-audit: the console script, else the installed module."""
    exe = shutil.which("pip-audit")
    if exe:
        return [exe]
    if importlib.util.find_spec("pip_audit") is not None:
        return [sys.executable, "-m", "pip_audit"]
    return None


def _run_pip_audit(requirements: Path) -> dict[str, Any] | list[Any] | None:
    """Run pip-audit against a requirements file and return parsed JSON.

    Returns None when pip-audit is unavailable or fails; raises nothing.
    """
    command = _audit_command()
    if command is None:
        return None
    try:
        proc = subprocess.run(
            [*command, "-r", str(requirements), "-f", "json", "--progress-spinner", "off"],
            capture_output=True,
            text=True,
            timeout=_AUDIT_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    # pip-audit exits 1 when vulnerabilities are found — still valid JSON.
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _severity_from_cvss(record: dict[str, Any]) -> Severity:
    """Map a CVSS score to a Severity; unknown scores default to WARNING."""
    score: float | None = None
    raw = record.get("severity") or record.get("cvss")
    if isinstance(raw, (int, float)):
        score = float(raw)
    elif isinstance(raw, str):
        match = re.search(r"\d+(\.\d+)?", raw)
        if match:
            score = float(match.group(0))
    if score is None:
        return Severity.WARNING
    if score >= 7:
        return Severity.CRITICAL
    if score >= 4:
        return Severity.WARNING
    return Severity.INFO


def _requirement_line(requirements_text: str, package: str) -> int:
    """Find the 1-based line where *package* is pinned (1 if not found)."""
    pattern = re.compile(rf"(?i)^\s*{re.escape(package)}\s*(\[|==|>=|<=|~=|!=|$|\s)")
    for lineno, line in enumerate(requirements_text.splitlines(), start=1):
        if pattern.match(line):
            return lineno
    return 1


def run(context: "ScanContext") -> list[Finding]:
    """TLX-D001: map every known CVE in requirements.txt to a Finding."""
    requirements = next(
        (p for p in context.files_named("requirements.txt") if p.parent == context.root),
        None,
    )
    if requirements is None:
        return []

    if _audit_command() is None:
        context.notes.append(
            "pip-audit is not installed — dependency audit skipped "
            "(pip install 'torlyx[audit]' to enable it)"
        )
        return []

    data = _run_pip_audit(requirements)
    if data is None:
        context.notes.append(
            "Dependency audit skipped (pip-audit failed — offline, or the "
            "requirements file could not be resolved)"
        )
        return []

    entries = data.get("dependencies", []) if isinstance(data, dict) else data
    requirements_text = context.read_text(requirements) or ""
    rel = context.rel(requirements)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "?")
        version = entry.get("version", "?")
        for vuln in entry.get("vulns", []) or []:
            vuln_id = vuln.get("id", "unknown")
            if (name, vuln_id) in seen:  # pip-audit can emit duplicates
                continue
            seen.add((name, vuln_id))
            fixes = [f for f in vuln.get("fix_versions", []) or [] if f]
            fix = (
                f"Upgrade: pip install -U \"{name}>={fixes[0]}\" (then update requirements.txt)"
                if fixes
                else f"No fixed release yet — check {vuln_id} for mitigations or switch packages."
            )
            findings.append(
                Finding(
                    rule_id="TLX-D001",
                    title=f"Vulnerable dependency: {name}",
                    severity=_severity_from_cvss(vuln),
                    file=rel,
                    line=_requirement_line(requirements_text, str(name)),
                    message=f"{name} {version} has a known vulnerability "
                    f"({vuln_id}) — attackers scan for apps running unpatched versions.",
                    fix=fix,
                    context=f"{name}=={version}",
                )
            )
    return findings
