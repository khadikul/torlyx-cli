"""Tests for score calculation, the rich renderer, and the JSON exporter."""

from __future__ import annotations

import json

from rich.console import Console

from torlyx import report
from torlyx.models import Finding, ScanResult, Severity


def _finding(rule_id: str, severity: Severity, file: str = "app.py", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="A test finding",
        severity=severity,
        file=file,
        line=line,
        message="Something risky.",
        fix="Do the safe thing instead.",
    )


def test_score_starts_at_100_and_floors_at_0():
    assert report.calculate_score([]) == 100
    assert report.calculate_score([_finding("X", Severity.CRITICAL)]) == 80
    assert report.calculate_score([_finding("X", Severity.WARNING)]) == 95
    assert report.calculate_score([_finding("X", Severity.INFO)]) == 99
    many = [_finding(f"R{i}", Severity.CRITICAL) for i in range(10)]
    assert report.calculate_score(many) == 0


def test_findings_sorted_by_severity_then_file_then_line():
    result = ScanResult(
        root=".",
        findings=[
            _finding("I1", Severity.INFO, "a.py", 1),
            _finding("C1", Severity.CRITICAL, "z.py", 9),
            _finding("C2", Severity.CRITICAL, "a.py", 5),
            _finding("W1", Severity.WARNING, "m.py", 2),
        ],
    )
    ordered = [(f.rule_id) for f in result.sorted_findings()]
    assert ordered == ["C2", "C1", "W1", "I1"]


def test_render_report_contains_the_essentials():
    console = Console(record=True, width=100, force_terminal=False)
    result = ScanResult(
        root=".",
        findings=[_finding("TLX-S003", Severity.CRITICAL, "app/config.py", 12)],
        files_scanned=47,
        duration_seconds=6.2,
        rules_total=30,
    )
    report.render(result, console)
    text = console.export_text()
    assert "TORLYX SECURITY SCAN" in text
    assert "Scanned 47 files in 6.2s" in text
    assert "TLX-S003" in text
    assert "app/config.py:12" in text
    assert "Fix:" in text
    assert "Security Score: 80/100" in text
    assert "29 checks passed" in text


def test_clean_scan_celebrates():
    console = Console(record=True, width=100, force_terminal=False)
    result = ScanResult(root=".", files_scanned=3, rules_total=30)
    report.render(result, console)
    text = console.export_text()
    assert "🎉" in text
    assert "100/100" in text
    assert text.count("100/100") == 1  # no duplicate score line
    assert "30 checks passed" in text


def test_json_export_shape():
    result = ScanResult(
        root="/proj",
        findings=[_finding("TLX-S003", Severity.CRITICAL, "app/config.py", 12)],
        files_scanned=5,
        duration_seconds=1.234,
        rules_total=30,
        notes=["pip-audit not installed — dependency audit skipped"],
    )
    payload = json.loads(report.to_json(result))
    assert payload["tool"] == "torlyx"
    assert payload["score"] == 80
    assert payload["files_scanned"] == 5
    assert payload["counts"] == {
        "critical": 1,
        "warning": 0,
        "info": 0,
        "checks_passed": 29,
    }
    assert payload["findings"][0]["rule_id"] == "TLX-S003"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["file"] == "app/config.py"
    assert payload["notes"]
