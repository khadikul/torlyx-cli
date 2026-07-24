"""Scan orchestrator: discovery → parse → run checks → collect findings.

The orchestrator knows nothing about individual rules. Checks register
themselves in :mod:`torlyx.checks`; each receives a :class:`ScanContext`
and returns a list of :class:`~torlyx.models.Finding`.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from pathlib import Path

from torlyx import discovery
from torlyx.models import Finding, ScanResult


@dataclass
class ScanContext:
    """Everything a check needs to inspect the project.

    The context is parser-backend-agnostic at its core: ``files``,
    ``git_tracked`` and ``read_text`` work for any language. Language
    layers sit on top — today that is the Python ``ast`` layer
    (:meth:`python_files` / :meth:`get_python_ast`); a future tree-sitter
    layer for JS/TS/PHP can be added alongside without touching existing
    checks.
    """

    root: Path
    files: list[Path]
    git_tracked: set[str] = field(default_factory=set)
    verbose: bool = False
    notes: list[str] = field(default_factory=list)
    _text_cache: dict[Path, str | None] = field(default_factory=dict, repr=False)
    _ast_cache: dict[Path, ast.Module | None] = field(default_factory=dict, repr=False)

    def rel(self, path: Path) -> str:
        """Path relative to the scan root, forward slashes."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def read_text(self, path: Path) -> str | None:
        """Read a file once and cache it. Returns None for unreadable/binary files."""
        if path not in self._text_cache:
            try:
                raw = path.read_bytes()
            except OSError:
                self._text_cache[path] = None
            else:
                if b"\x00" in raw[:8192]:  # binary
                    self._text_cache[path] = None
                else:
                    self._text_cache[path] = raw.decode("utf-8", errors="replace")
        return self._text_cache[path]

    # -- Python AST layer -------------------------------------------------

    def python_files(self) -> list[Path]:
        """All discovered ``.py`` files."""
        return [p for p in self.files if p.suffix == ".py"]

    def get_python_ast(self, path: Path) -> ast.Module | None:
        """Parse a Python file exactly once (cached across all checks).

        Returns None when the file has syntax errors — the file is skipped
        and noted in verbose mode, never a crash.
        """
        if path not in self._ast_cache:
            text = self.read_text(path)
            if text is None:
                self._ast_cache[path] = None
            else:
                try:
                    self._ast_cache[path] = ast.parse(text, filename=str(path))
                except (SyntaxError, ValueError):
                    if self.verbose:
                        self.notes.append(f"Skipped {self.rel(path)} (syntax error)")
                    self._ast_cache[path] = None
        return self._ast_cache[path]

    # -- Convenience helpers used by several checks ------------------------

    def files_named(self, *names: str) -> list[Path]:
        """Discovered files whose basename matches any of *names* (case-insensitive)."""
        lowered = {n.lower() for n in names}
        return [p for p in self.files if p.name.lower() in lowered]

    def has_production_signals(self) -> bool:
        """True when the project looks deployable (Dockerfile/Procfile present)."""
        return bool(self.files_named("Dockerfile", "Procfile"))


def build_context(
    root: Path,
    excludes: list[str] | None = None,
    verbose: bool = False,
) -> ScanContext:
    """Discover files and git state for *root* and assemble a ScanContext."""
    files = discovery.discover_files(root, excludes)
    tracked = discovery.git_tracked_files(root)
    return ScanContext(root=root, files=files, git_tracked=tracked, verbose=verbose)


def scan(
    path: str | Path,
    excludes: list[str] | None = None,
    verbose: bool = False,
) -> ScanResult:
    """Run every registered check against *path* and return a ScanResult."""
    from torlyx import checks  # imported late so the registry is fully populated

    root = Path(path).resolve()
    started = time.perf_counter()
    context = build_context(root, excludes=excludes, verbose=verbose)

    findings: list[Finding] = []
    for check in checks.all_checks():
        findings.extend(check(context))

    return ScanResult(
        root=str(root),
        findings=sorted(findings, key=Finding.sort_key),
        files_scanned=len(context.files),
        duration_seconds=time.perf_counter() - started,
        rules_total=len(checks.all_rules()),
        notes=list(context.notes),
    )
