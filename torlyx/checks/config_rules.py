"""Config / infrastructure rules (TLX-I001 … TLX-I003)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from torlyx.models import Finding, Rule, Severity

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

RULES: list[Rule] = [
    Rule(
        "TLX-I001",
        "Container runs as root",
        Severity.WARNING,
        "The Dockerfile never drops privileges with a USER instruction.",
    ),
    Rule(
        "TLX-I002",
        "Server binds all interfaces without auth",
        Severity.INFO,
        "The app listens on 0.0.0.0 while no auth dependency exists anywhere.",
    ),
    Rule(
        "TLX-I003",
        "Source maps committed to git",
        Severity.WARNING,
        "*.js.map files in build output directories are tracked by git.",
    ),
]

_USER_LINE = re.compile(r"(?im)^\s*USER\s+(\S+)")
_BUILD_DIRS = frozenset({"dist", "build", "out", ".next", "public", "static", "assets"})


def run(context: "ScanContext") -> list[Finding]:
    """Run all config/infra rules against the project."""
    findings: list[Finding] = []
    findings.extend(_check_dockerfiles(context))
    findings.extend(_check_bind_all_interfaces(context))
    findings.extend(_check_source_maps(context))
    return findings


def _check_dockerfiles(context: "ScanContext") -> list[Finding]:
    """I001: Dockerfile with no USER instruction (or USER root)."""
    findings: list[Finding] = []
    for dockerfile in context.files_named("Dockerfile"):
        text = context.read_text(dockerfile)
        if text is None:
            continue
        users = _USER_LINE.findall(text)
        if users and users[-1].lower() != "root":
            continue
        findings.append(
            Finding(
                rule_id="TLX-I001",
                title="Container runs as root",
                severity=Severity.WARNING,
                file=context.rel(dockerfile),
                line=1,
                message="If anyone breaks into the app, they own the whole "
                "container — root can read every file and install anything.",
                fix="RUN useradd --create-home appuser\nUSER appuser  # after installing dependencies",
            )
        )
    return findings


def _project_has_auth(context: "ScanContext") -> bool:
    """True when any Depends/Security usage exists in the project."""
    for path in context.python_files():
        tree = context.get_python_ast(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else (
                    func.id if isinstance(func, ast.Name) else ""
                )
                if name in {"Depends", "Security"}:
                    return True
    return False


def _check_bind_all_interfaces(context: "ScanContext") -> list[Finding]:
    """I002: host 0.0.0.0 while the project has no auth rules at all."""
    binds: list[tuple[str, int]] = []
    for path in context.python_files():
        tree = context.get_python_ast(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "host"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value == "0.0.0.0"
                ):
                    binds.append((context.rel(path), node.lineno))
    if not binds or _project_has_auth(context):
        return []
    return [
        Finding(
            rule_id="TLX-I002",
            title="Server binds all interfaces without auth",
            severity=Severity.INFO,
            file=file,
            line=line,
            message="The server accepts connections from any machine that can "
            "reach it, and no route requires a login.",
            fix='Bind to 127.0.0.1 during development, or add auth before exposing it: uvicorn.run(app, host="127.0.0.1")',
        )
        for file, line in binds
    ]


def _check_source_maps(context: "ScanContext") -> list[Finding]:
    """I003: tracked *.js.map files inside build output directories."""
    findings: list[Finding] = []
    for tracked in sorted(context.git_tracked):
        if not tracked.endswith(".js.map"):
            continue
        segments = tracked.lower().split("/")[:-1]
        if not any(seg in _BUILD_DIRS for seg in segments):
            continue
        findings.append(
            Finding(
                rule_id="TLX-I003",
                title="Source maps committed to git",
                severity=Severity.WARNING,
                file=tracked,
                line=1,
                message="Source maps reconstruct your original frontend code — "
                "including comments and internal logic — for anyone who downloads them.",
                fix="Remove *.js.map from the repo and add it to .gitignore; keep maps only for local debugging.",
            )
        )
    return findings
