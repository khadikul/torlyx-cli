"""CLI tests: commands, flags, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import torlyx
from torlyx.checks import dependencies
from torlyx.cli import app

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VULN_APP = FIXTURES / "vulnerable_app"
CLEAN_APP = FIXTURES / "clean_app"

runner = CliRunner()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No git, no network, no pip-audit requirement in CLI tests."""
    monkeypatch.setattr("torlyx.discovery.git_tracked_files", lambda root: set())
    monkeypatch.setattr(dependencies, "_audit_command", lambda: ["pip-audit"])
    monkeypatch.setattr(dependencies, "_run_pip_audit", lambda _: {"dependencies": []})


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert f"torlyx {torlyx.__version__}" in result.output


def test_python_m_torlyx_works():
    """`python -m torlyx` is the fallback when Scripts isn't on PATH."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "torlyx", "version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert f"torlyx {torlyx.__version__}" in proc.stdout


def test_rules_command_lists_all_30():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    for rule_id in ("TLX-S001", "TLX-F008", "TLX-C007", "TLX-I003", "TLX-D001"):
        assert rule_id in result.output


def test_scan_defaults_to_exit_0_even_with_findings():
    result = runner.invoke(app, ["scan", str(VULN_APP)])
    assert result.exit_code == 0
    assert "TORLYX SECURITY SCAN" in result.output


def test_fail_on_critical_sets_exit_1():
    result = runner.invoke(app, ["scan", str(VULN_APP), "--fail-on", "critical"])
    assert result.exit_code == 1


def test_fail_on_clean_app_stays_exit_0():
    result = runner.invoke(app, ["scan", str(CLEAN_APP), "--fail-on", "any"])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_fail_on_warning_triggers_on_warnings_only(tmp_path):
    (tmp_path / "m.py").write_text(
        "import pickle\ndef f(b):\n    return pickle.loads(b)\n", encoding="utf-8"
    )
    assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "warning"]).exit_code == 1
    assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "any"]).exit_code == 1


def test_json_output_is_machine_readable():
    result = runner.invoke(app, ["scan", str(VULN_APP), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["tool"] == "torlyx"
    assert 0 <= payload["score"] <= 100
    assert payload["counts"]["critical"] > 0
    assert all(
        {"rule_id", "severity", "file", "line", "message"} <= set(f)
        for f in payload["findings"]
    )


def test_exclude_flag_is_repeatable():
    everything = runner.invoke(app, ["scan", str(VULN_APP), "--json"])
    excluded = runner.invoke(
        app,
        ["scan", str(VULN_APP), "--json", "--exclude", "app/config.py", "--exclude", "app/utils.py"],
    )
    all_files = {f["file"] for f in json.loads(everything.output)["findings"]}
    kept_files = {f["file"] for f in json.loads(excluded.output)["findings"]}
    assert "app/config.py" in all_files
    assert "app/config.py" not in kept_files
    assert "app/utils.py" not in kept_files


def test_no_audit_flag_skips_dependency_audit(monkeypatch):
    def _boom(*_args):
        raise AssertionError("pip-audit must not run with --no-audit")

    monkeypatch.setattr(dependencies, "_audit_command", _boom)
    monkeypatch.setattr(dependencies, "_run_pip_audit", _boom)
    result = runner.invoke(app, ["scan", str(VULN_APP), "--no-audit"])
    assert result.exit_code == 0
    assert "TORLYX SECURITY SCAN" in result.output


def test_export_md_writes_ai_ready_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(VULN_APP), "--no-audit", "--export", "md"])
    assert result.exit_code == 0
    report_file = tmp_path / "torlyx-report.md"
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert "Paste this report into your AI assistant" in content
    assert "TLX-S003" in content


def test_export_rejects_unknown_formats(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(VULN_APP), "--export", "pdf"])
    assert result.exit_code == 2
    assert not (tmp_path / "torlyx-report.md").exists()


def test_scan_of_missing_path_exits_2():
    result = runner.invoke(app, ["scan", "definitely/not/a/real/path"])
    assert result.exit_code == 2
