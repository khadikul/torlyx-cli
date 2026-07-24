"""Tests for the dependency audit (TLX-D001) — pip-audit is always mocked."""

from __future__ import annotations

from torlyx.checks import dependencies
from torlyx.models import Severity

CANNED_AUDIT = {
    "dependencies": [
        {"name": "fastapi", "version": "0.68.0", "vulns": []},
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "description": "Credentials leak via redirect.",
                    "severity": "9.8",
                }
            ],
        },
        {
            "name": "uvicorn",
            "version": "0.15.0",
            "vulns": [
                {"id": "GHSA-xxxx", "fix_versions": [], "description": "…"}
            ],
        },
        {  # pip-audit sometimes reports the same package/vuln twice
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "fix_versions": ["2.20.0"],
                    "description": "Credentials leak via redirect.",
                    "severity": "9.8",
                }
            ],
        },
    ]
}

REQUIREMENTS = "fastapi==0.68.0\nuvicorn==0.15.0\nrequests==2.19.1\n"


def test_cves_map_to_findings(make_ctx, monkeypatch):
    # _audit_command is mocked too, so the test passes without pip-audit installed
    monkeypatch.setattr(dependencies, "_audit_command", lambda: ["pip-audit"])
    monkeypatch.setattr(dependencies, "_run_pip_audit", lambda _: CANNED_AUDIT)
    ctx = make_ctx({"requirements.txt": REQUIREMENTS})
    findings = dependencies.run(ctx)
    assert len(findings) == 2
    requests_finding = next(f for f in findings if "requests" in f.title)
    assert requests_finding.rule_id == "TLX-D001"
    assert requests_finding.severity is Severity.CRITICAL  # CVSS 9.8
    assert requests_finding.line == 3  # requests pinned on line 3
    assert "PYSEC-2018-28" in requests_finding.message
    assert "2.20.0" in requests_finding.fix

    uvicorn_finding = next(f for f in findings if "uvicorn" in f.title)
    assert uvicorn_finding.severity is Severity.WARNING  # no CVSS → default
    assert "No fixed release yet" in uvicorn_finding.fix


def test_missing_pip_audit_adds_note_and_skips(make_ctx, monkeypatch):
    monkeypatch.setattr(dependencies, "_audit_command", lambda: None)
    ctx = make_ctx({"requirements.txt": REQUIREMENTS})
    assert dependencies.run(ctx) == []
    assert any("pip-audit is not installed" in note for note in ctx.notes)


def test_audit_failure_adds_note_and_skips(make_ctx, monkeypatch):
    monkeypatch.setattr(dependencies, "_audit_command", lambda: ["pip-audit"])
    monkeypatch.setattr(dependencies, "_run_pip_audit", lambda _: None)
    ctx = make_ctx({"requirements.txt": REQUIREMENTS})
    assert dependencies.run(ctx) == []
    assert any("audit skipped" in note for note in ctx.notes)


def test_no_audit_skips_without_touching_pip_audit(make_ctx, monkeypatch):
    def _boom(*_args):
        raise AssertionError("pip-audit must not be invoked with --no-audit")

    monkeypatch.setattr(dependencies, "_audit_command", _boom)
    monkeypatch.setattr(dependencies, "_run_pip_audit", _boom)
    ctx = make_ctx({"requirements.txt": REQUIREMENTS})
    ctx.audit = False
    assert dependencies.run(ctx) == []
    assert any("--no-audit" in note for note in ctx.notes)


def test_no_requirements_file_is_silently_skipped(make_ctx):
    ctx = make_ctx({"main.py": "print(1)\n"})
    assert dependencies.run(ctx) == []
    assert ctx.notes == []


def test_severity_mapping():
    assert dependencies._severity_from_cvss({"severity": "9.8"}) is Severity.CRITICAL
    assert dependencies._severity_from_cvss({"severity": "5.0"}) is Severity.WARNING
    assert dependencies._severity_from_cvss({"severity": "2.1"}) is Severity.INFO
    assert dependencies._severity_from_cvss({}) is Severity.WARNING
    assert dependencies._severity_from_cvss({"cvss": 7}) is Severity.CRITICAL


def test_severity_labels_are_mapped():
    assert dependencies._severity_from_cvss({"severity": "CRITICAL"}) is Severity.CRITICAL
    assert dependencies._severity_from_cvss({"severity": "High"}) is Severity.CRITICAL
    assert dependencies._severity_from_cvss({"severity": "moderate"}) is Severity.WARNING
    assert dependencies._severity_from_cvss({"severity": "low"}) is Severity.INFO


def test_cvss_vector_strings_are_not_scraped_for_digits():
    # A 9.8-critical vuln whose severity field is a vector string must NOT
    # become INFO because "3.1" (the CVSS *version*) was read as the score.
    vector = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert dependencies._severity_from_cvss(vector) is Severity.WARNING


def test_requirement_line_lookup():
    text = "# deps\nfastapi==0.68.0\nrequests==2.19.1\n"
    assert dependencies._requirement_line(text, "requests") == 3
    assert dependencies._requirement_line(text, "fastapi") == 2
    assert dependencies._requirement_line(text, "missing") == 1
