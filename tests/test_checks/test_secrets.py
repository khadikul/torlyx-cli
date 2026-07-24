"""Tests for the secrets rules (TLX-S001 … TLX-S012)."""

from __future__ import annotations

from pathlib import Path

from torlyx.checks import secrets
from torlyx.models import Severity

VULN_APP = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_app"

#: rule id -> (expected file, marker substring on the expected line)
EXPECTED = {
    "TLX-S001": ("app/config.py", "PAYMENT_SIGNING_TOKEN"),
    "TLX-S002": ("app/config.py", "AWS_ACCESS_KEY_ID"),
    "TLX-S003": ("app/config.py", "STRIPE_KEY"),
    "TLX-S004": ("app/config.py", "OPENAI_API_KEY"),
    "TLX-S005": ("app/config.py", "ANTHROPIC_API_KEY"),
    "TLX-S006": ("app/config.py", "GITHUB_TOKEN"),
    "TLX-S007": ("app/config.py", "GOOGLE_API_KEY"),
    "TLX-S008": ("app/config.py", "SUPABASE_SERVICE_ROLE_KEY"),
    "TLX-S009": ("app/db.py", "DATABASE_URL"),
    "TLX-S010": ("app/config.py", "SECRET_KEY ="),
    "TLX-S011": (".env", None),
    "TLX-S012": ("certs/server.pem", "BEGIN RSA PRIVATE KEY"),
}


def test_every_secrets_rule_fires_on_vulnerable_app(vuln_ctx, line_of):
    findings = secrets.run(vuln_ctx)
    fired = {f.rule_id for f in findings}
    assert fired == set(EXPECTED), f"missing: {set(EXPECTED) - fired}, extra: {fired - set(EXPECTED)}"

    for rule_id, (file, marker) in EXPECTED.items():
        rule_findings = [f for f in findings if f.rule_id == rule_id]
        assert any(f.file == file for f in rule_findings), f"{rule_id} not in {file}"
        if marker is not None:
            expected_line = line_of(VULN_APP / file, marker)
            assert any(
                f.line == expected_line for f in rule_findings if f.file == file
            ), f"{rule_id} expected at {file}:{expected_line}"


def test_all_secrets_findings_are_critical(vuln_ctx):
    for finding in secrets.run(vuln_ctx):
        assert finding.severity is Severity.CRITICAL
        assert finding.message
        assert finding.fix


def test_specific_rules_suppress_generic_entropy_rule(vuln_ctx):
    """The Stripe key line must fire S003 only, never also S001."""
    findings = secrets.run(vuln_ctx)
    stripe = [f for f in findings if f.rule_id == "TLX-S003"]
    assert stripe
    s001_locations = {(f.file, f.line) for f in findings if f.rule_id == "TLX-S001"}
    assert not any((f.file, f.line) in s001_locations for f in stripe)


def test_clean_app_has_no_secret_findings(clean_ctx):
    assert secrets.run(clean_ctx) == []


def test_placeholders_are_ignored(make_ctx):
    ctx = make_ctx(
        {
            "config.py": 'API_KEY = "your-api-key-here-please-change"\n'
            'TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
            'SECRET_KEY = "changeme-in-production-please"\n'
        }
    )
    assert secrets.run(ctx) == []


def test_getenv_lines_are_ignored(make_ctx):
    ctx = make_ctx(
        {"config.py": 'import os\nSECRET_KEY = os.getenv("SECRET_KEY", "u9Tr4eWq2zXc8vBn6mAs1dFg")\n'}
    )
    assert secrets.run(ctx) == []


def test_ignore_pragma_suppresses_line(make_ctx):
    ctx = make_ctx(
        {"config.py": 'STRIPE_KEY = "sk_live_9rXt2pQv8mZw4nLb"  # torlyx:ignore\n'}
    )
    assert secrets.run(ctx) == []


def test_test_directories_are_skipped(make_ctx):
    ctx = make_ctx(
        {"tests/test_billing.py": 'STRIPE_KEY = "sk_live_9rXt2pQv8mZw4nLb"\n'}
    )
    assert secrets.run(ctx) == []


def test_env_file_content_is_not_flagged_when_untracked(make_ctx):
    ctx = make_ctx({".env": "STRIPE_KEY=sk_live_9rXt2pQv8mZw4nLb\n"})
    assert secrets.run(ctx) == []


def test_tracked_env_file_fires_s011_once(make_ctx):
    ctx = make_ctx(
        {".env": "STRIPE_KEY=sk_live_9rXt2pQv8mZw4nLb\n"},
        git_tracked={".env"},
    )
    findings = secrets.run(ctx)
    assert [f.rule_id for f in findings] == ["TLX-S011"]


def test_env_example_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {".env.example": "STRIPE_KEY=sk_live_put_yours_here\n"},
        git_tracked={".env.example"},
    )
    assert secrets.run(ctx) == []


def test_tracked_key_file_fires_s012_without_content(make_ctx):
    ctx = make_ctx({}, git_tracked={"deploy/server.key"})
    findings = secrets.run(ctx)
    assert [f.rule_id for f in findings] == ["TLX-S012"]


def test_tracked_pem_with_key_content_fires_s012_once(make_ctx):
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"
    ctx = make_ctx({"certs/server.pem": pem}, git_tracked={"certs/server.pem"})
    findings = secrets.run(ctx)
    assert [f.rule_id for f in findings] == ["TLX-S012"]


def test_public_key_names_are_not_secrets(make_ctx):
    ctx = make_ctx(
        {"config.py": 'STRIPE_PUBLIC_KEY = "Vq3xZ8pL1nRw6tYb2mKd9fJh4sGc7aQe"\n'}
    )
    assert secrets.run(ctx) == []


def test_low_entropy_values_are_not_flagged(make_ctx):
    ctx = make_ctx({"config.py": 'API_KEY = "not-really-random-at-all-ok"\n'})
    assert secrets.run(ctx) == []


def test_entropy_function():
    assert secrets.shannon_entropy("aaaa") == 0.0
    assert secrets.shannon_entropy("Vq3xZ8pL1nRw6tYb2mKd9fJh4sGc7aQe") > 4.0
