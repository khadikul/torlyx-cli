"""Tests for the config/infra rules (TLX-I001 … TLX-I003)."""

from __future__ import annotations

from torlyx.checks import config_rules


def rules_fired(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_every_config_rule_fires_on_vulnerable_app(vuln_ctx):
    findings = config_rules.run(vuln_ctx)
    assert rules_fired(findings) == {"TLX-I001", "TLX-I002", "TLX-I003"}
    where = {(f.rule_id, f.file) for f in findings}
    assert ("TLX-I001", "Dockerfile") in where
    assert ("TLX-I002", "app/main.py") in where
    assert ("TLX-I003", "dist/bundle.js.map") in where


def test_clean_app_has_no_config_findings(clean_ctx):
    assert config_rules.run(clean_ctx) == []


def test_dockerfile_with_user_root_is_flagged(make_ctx):
    ctx = make_ctx({"Dockerfile": "FROM python:3.12\nUSER root\nCMD ['app']\n"})
    assert rules_fired(config_rules.run(ctx)) == {"TLX-I001"}


def test_dockerfile_with_non_root_user_is_clean(make_ctx):
    ctx = make_ctx(
        {"Dockerfile": "FROM python:3.12\nRUN useradd app\nUSER app\nCMD ['app']\n"}
    )
    assert config_rules.run(ctx) == []


def test_bind_all_interfaces_with_auth_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {
            "main.py": (
                "import uvicorn\n"
                "from fastapi import Depends, FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/x')\n"
                "def x(user=Depends(lambda: 1)):\n"
                "    return user\n"
                "uvicorn.run(app, host='0.0.0.0')\n"
            )
        }
    )
    assert config_rules.run(ctx) == []


def test_bind_localhost_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {"main.py": "import uvicorn\nuvicorn.run(None, host='127.0.0.1')\n"}
    )
    assert config_rules.run(ctx) == []


def test_source_map_outside_build_dir_is_not_flagged(make_ctx):
    ctx = make_ctx({}, git_tracked={"src/widget.js.map"})
    assert config_rules.run(ctx) == []


def test_source_map_in_build_dir_is_flagged(make_ctx):
    ctx = make_ctx({}, git_tracked={"build/static/js/main.js.map"})
    assert rules_fired(config_rules.run(ctx)) == {"TLX-I003"}
