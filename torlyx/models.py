"""Core data models for Torlyx.

Everything in this module is language-agnostic: a Finding is just a rule ID,
a file location, a severity, a plain-English message, and an optional fix.
Nothing here may assume the scanned project is Python — future backends
(tree-sitter for JS/TS/PHP) reuse these models untouched.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """How dangerous a finding is. Ordered: CRITICAL > WARNING > INFO."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Sort weight — lower sorts first (most severe first)."""
        return {"critical": 0, "warning": 1, "info": 2}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.weight < other.weight


@dataclass(frozen=True)
class Rule:
    """Static metadata for a single rule (used by `torlyx rules` and scoring)."""

    id: str
    title: str
    severity: Severity
    description: str


@dataclass(frozen=True)
class Finding:
    """A single security issue discovered in the scanned project."""

    rule_id: str
    title: str
    severity: Severity
    file: str
    """Path relative to the scan root, using forward slashes."""
    line: int
    message: str
    """One-line plain-English explanation of why this is dangerous."""
    fix: str | None = None
    """Concrete fix suggestion, code where possible."""
    context: str | None = None
    """Optional extra location detail, e.g. ``DELETE /users/{id}``."""

    def sort_key(self) -> tuple[int, str, int]:
        return (self.severity.weight, self.file, self.line)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "fix": self.fix,
            "context": self.context,
        }


@dataclass
class ScanResult:
    """The complete outcome of one scan."""

    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    rules_total: int = 0
    notes: list[str] = field(default_factory=list)
    """Non-finding messages, e.g. 'pip-audit not installed, skipped'."""

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def criticals(self) -> int:
        return self.count(Severity.CRITICAL)

    @property
    def warnings(self) -> int:
        return self.count(Severity.WARNING)

    @property
    def infos(self) -> int:
        return self.count(Severity.INFO)

    @property
    def rules_failed(self) -> int:
        """Number of distinct rules that produced at least one finding."""
        return len({f.rule_id for f in self.findings})

    @property
    def rules_passed(self) -> int:
        return max(0, self.rules_total - self.rules_failed)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.sort_key)
