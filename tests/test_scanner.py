"""End-to-end scanner tests: all 30 rules on the vulnerable app, zero on clean."""

from __future__ import annotations

from pathlib import Path

import pytest

from torlyx import checks, scanner
from torlyx.checks import dependencies

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VULN_APP = FIXTURES / "vulnerable_app"
CLEAN_APP = FIXTURES / "clean_app"

#: Git state the vulnerable app would have in the wild (it has no .git of its own).
VULN_GIT_TRACKED = {
    ".env",
    "Dockerfile",
    "requirements.txt",
    "certs/server.pem",
    "dist/bundle.js.map",
    "app/main.py",
    "app/config.py",
}

CANNED_AUDIT = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [
                {"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"], "severity": "9.8"}
            ],
        }
    ]
}

ALL_RULE_IDS = {
    *(f"TLX-S{i:03d}" for i in range(1, 13)),
    *(f"TLX-F{i:03d}" for i in range(1, 9)),
    *(f"TLX-C{i:03d}" for i in range(1, 8)),
    *(f"TLX-I{i:03d}" for i in range(1, 4)),
    "TLX-D001",
}


@pytest.fixture(autouse=True)
def offline_scan(monkeypatch):
    """Keep integration scans deterministic: fake git state, canned pip-audit."""
    monkeypatch.setattr(
        "torlyx.discovery.git_tracked_files", lambda root: set(VULN_GIT_TRACKED)
    )
    monkeypatch.setattr(dependencies, "_audit_command", lambda: ["pip-audit"])
    monkeypatch.setattr(dependencies, "_run_pip_audit", lambda _: CANNED_AUDIT)


def test_registry_exposes_every_rule():
    # 12 secrets + 8 fastapi + 7 code + 3 config + 1 dependency = 31
    rule_ids = [rule.id for rule in checks.all_rules()]
    assert len(rule_ids) == len(ALL_RULE_IDS) == 31
    assert set(rule_ids) == ALL_RULE_IDS


def test_every_rule_fires_on_the_vulnerable_app():
    result = scanner.scan(VULN_APP)
    fired = {f.rule_id for f in result.findings}
    assert fired == ALL_RULE_IDS, f"missing: {ALL_RULE_IDS - fired}"
    assert result.files_scanned > 0
    assert result.rules_total == 31


def test_clean_app_scan_is_spotless(monkeypatch):
    monkeypatch.setattr("torlyx.discovery.git_tracked_files", lambda root: set())
    monkeypatch.setattr(dependencies, "_run_pip_audit", lambda _: {"dependencies": []})
    result = scanner.scan(CLEAN_APP)
    assert result.findings == []


def test_exclude_patterns_drop_files():
    full = scanner.scan(VULN_APP)
    trimmed = scanner.scan(VULN_APP, excludes=["app/config.py"])
    trimmed_files = {f.file for f in trimmed.findings}
    assert "app/config.py" not in trimmed_files
    assert len(trimmed.findings) < len(full.findings)


def test_exclude_patterns_also_filter_git_tracked_findings():
    """S011/S012/I003 read `git ls-files`; --exclude must silence them too."""
    full = scanner.scan(VULN_APP)
    assert {"TLX-I003", "TLX-S011"} <= {f.rule_id for f in full.findings}

    trimmed = scanner.scan(VULN_APP, excludes=["dist", ".env", "certs"])
    fired = {f.rule_id for f in trimmed.findings}
    assert "TLX-I003" not in fired  # dist/bundle.js.map (tracked-only)
    assert "TLX-S011" not in fired  # .env (tracked-only)
    assert not any(f.file.startswith("certs/") for f in trimmed.findings)


def test_syntax_errors_never_crash_the_scan(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "fine.py").write_text("x = eval(input())\n", encoding="utf-8")
    result = scanner.scan(tmp_path, verbose=True)
    assert any(f.rule_id == "TLX-C002" for f in result.findings)
    assert any("broken.py" in note for note in result.notes)
