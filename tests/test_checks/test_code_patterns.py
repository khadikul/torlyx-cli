"""Tests for the code pattern rules (TLX-C001 … TLX-C007)."""

from __future__ import annotations

from torlyx.checks import code_patterns


def rules_fired(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_every_code_pattern_rule_fires_on_vulnerable_app(vuln_ctx):
    findings = code_patterns.run(vuln_ctx)
    fired = rules_fired(findings)
    assert fired == {
        "TLX-C001",
        "TLX-C002",
        "TLX-C003",
        "TLX-C004",
        "TLX-C005",
        "TLX-C006",
        "TLX-C007",
    }
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["TLX-C001"].file == "app/db.py"
    assert by_rule["TLX-C002"].file == "app/utils.py"
    assert by_rule["TLX-C003"].file == "app/utils.py"
    assert by_rule["TLX-C004"].file == "app/utils.py"
    assert by_rule["TLX-C005"].file == "app/routes/auth.py"
    assert by_rule["TLX-C006"].file == "app/routes/auth.py"
    assert by_rule["TLX-C007"].file == "app/utils.py"


def test_sql_concat_variant_and_fstring_variant_both_fire(vuln_ctx):
    findings = [f for f in code_patterns.run(vuln_ctx) if f.rule_id == "TLX-C001"]
    assert len(findings) == 2  # f-string execute + concatenated query variable


def test_clean_app_has_no_code_pattern_findings(clean_ctx):
    assert code_patterns.run(clean_ctx) == []


def test_parameterized_sql_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {
            "db.py": (
                "def f(cursor, email):\n"
                '    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))\n'
                '    cursor.execute("DELETE FROM logs")\n'
            )
        }
    )
    assert code_patterns.run(ctx) == []


def test_fstring_without_interpolation_is_not_flagged(make_ctx):
    ctx = make_ctx({"db.py": 'def f(c):\n    c.execute(f"SELECT 1")\n'})
    assert code_patterns.run(ctx) == []


def test_eval_of_literal_is_not_flagged(make_ctx):
    ctx = make_ctx({"m.py": 'x = eval("2 + 2")\n'})
    assert code_patterns.run(ctx) == []


def test_eval_of_variable_is_flagged(make_ctx):
    ctx = make_ctx({"m.py": "def f(expr):\n    return eval(expr)\n"})
    assert rules_fired(code_patterns.run(ctx)) == {"TLX-C002"}


def test_subprocess_list_args_not_flagged(make_ctx):
    ctx = make_ctx(
        {
            "m.py": (
                "import subprocess\n"
                "def f(host):\n"
                '    subprocess.run(["ping", host])\n'
                '    subprocess.run("dir", shell=True)\n'  # literal + shell → not flagged
            )
        }
    )
    assert code_patterns.run(ctx) == []


def test_subprocess_shell_with_variable_command_is_flagged(make_ctx):
    ctx = make_ctx(
        {
            "m.py": (
                "import subprocess\n"
                "def f(host):\n"
                '    cmd = "ping " + host\n'
                "    subprocess.run(cmd, shell=True)\n"
            )
        }
    )
    assert rules_fired(code_patterns.run(ctx)) == {"TLX-C004"}


def test_md5_for_file_checksum_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {
            "m.py": (
                "import hashlib\n"
                "def file_checksum(data: bytes) -> str:\n"
                "    return hashlib.md5(data).hexdigest()\n"
            )
        }
    )
    assert code_patterns.run(ctx) == []


def test_md5_with_password_context_is_flagged(make_ctx):
    ctx = make_ctx(
        {
            "m.py": (
                "import hashlib\n"
                "def store(password: str) -> str:\n"
                "    return hashlib.md5(password.encode()).hexdigest()\n"
            )
        }
    )
    assert rules_fired(code_patterns.run(ctx)) == {"TLX-C005"}


def test_random_for_jitter_is_not_flagged(make_ctx):
    ctx = make_ctx(
        {"m.py": "import random\ndef backoff(n):\n    delay = random.uniform(0, n)\n    return delay\n"}
    )
    assert code_patterns.run(ctx) == []


def test_random_token_is_flagged_but_secrets_module_is_not(make_ctx):
    ctx = make_ctx(
        {
            "m.py": (
                "import random, secrets\n"
                "def make_tokens():\n"
                "    reset_token = random.getrandbits(64)\n"
                "    good_token = secrets.token_urlsafe(32)\n"
                "    return reset_token, good_token\n"
            )
        }
    )
    findings = code_patterns.run(ctx)
    assert rules_fired(findings) == {"TLX-C006"}
    assert len(findings) == 1


def test_verify_false_without_http_lib_is_not_flagged(make_ctx):
    ctx = make_ctx({"m.py": "def f(client):\n    client.check(verify=False)\n"})
    assert code_patterns.run(ctx) == []


def test_httpx_verify_false_is_flagged(make_ctx):
    ctx = make_ctx(
        {"m.py": 'import httpx\ndef f(url):\n    return httpx.get(url, verify=False)\n'}
    )
    assert rules_fired(code_patterns.run(ctx)) == {"TLX-C007"}
