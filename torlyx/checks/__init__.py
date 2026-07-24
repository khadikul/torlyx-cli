"""Check registry.

Every module in this package that defines a ``run(context) -> list[Finding]``
function (and a ``RULES: list[Rule]`` table) is picked up automatically —
adding a new check requires zero changes to the orchestrator or this file.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING, Callable, Protocol

from torlyx.models import Finding, Rule

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

CheckFn = Callable[["ScanContext"], list[Finding]]


class CheckModule(Protocol):
    """Structural interface every check module implements."""

    RULES: list[Rule]

    def run(self, context: "ScanContext") -> list[Finding]: ...


_checks: list[CheckFn] | None = None
_rules: list[Rule] | None = None


def _load() -> None:
    global _checks, _rules
    checks: list[CheckFn] = []
    rules: list[Rule] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{info.name}")
        run = getattr(module, "run", None)
        if callable(run):
            checks.append(run)
            rules.extend(getattr(module, "RULES", []))
    _checks, _rules = checks, rules


def all_checks() -> list[CheckFn]:
    """Every registered ``run`` function, in deterministic module order."""
    if _checks is None:
        _load()
    assert _checks is not None
    return _checks


def all_rules() -> list[Rule]:
    """Static metadata for every registered rule (drives ``torlyx rules``)."""
    if _rules is None:
        _load()
    assert _rules is not None
    return _rules
