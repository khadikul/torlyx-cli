"""Secrets rules (TLX-S001 … TLX-S012).

Finds hardcoded credentials: provider API keys, database passwords,
JWT signing secrets, committed .env files and private key material.

False-positive policy:
- ``.env*`` file *contents* are never flagged — that is the right place
  for secrets. Committing the file to git is the problem (TLX-S011).
- test/fixture/example directories are skipped entirely.
- Obvious placeholders (``your-api-key-here``, ``changeme``, ``xxx``,
  ``os.getenv(...)`` lines) are ignored.
- A line matched by a specific rule (S002…S010) is not also flagged by
  the generic entropy rule (S001).
- Append ``# torlyx:ignore`` to a line to suppress it explicitly.
"""

from __future__ import annotations

import ast
import base64
import binascii
import math
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from torlyx.models import Finding, Rule, Severity

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

RULES: list[Rule] = [
    Rule(
        "TLX-S001",
        "Hardcoded secret (high entropy)",
        Severity.CRITICAL,
        "A random-looking value is assigned to a secret-named variable in source code.",
    ),
    Rule(
        "TLX-S002",
        "AWS access key exposed",
        Severity.CRITICAL,
        "An AWS access key ID or secret access key is hardcoded in the code.",
    ),
    Rule(
        "TLX-S003",
        "Stripe live key exposed",
        Severity.CRITICAL,
        "A live Stripe secret key (sk_live_…) is hardcoded in the code.",
    ),
    Rule(
        "TLX-S004",
        "OpenAI API key exposed",
        Severity.CRITICAL,
        "An OpenAI API key (sk-… / sk-proj-…) is hardcoded in the code.",
    ),
    Rule(
        "TLX-S005",
        "Anthropic API key exposed",
        Severity.CRITICAL,
        "An Anthropic API key (sk-ant-…) is hardcoded in the code.",
    ),
    Rule(
        "TLX-S006",
        "GitHub token exposed",
        Severity.CRITICAL,
        "A GitHub personal access token (ghp_/gho_/github_pat_) is hardcoded.",
    ),
    Rule(
        "TLX-S007",
        "Google API key exposed",
        Severity.CRITICAL,
        "A Google API key (AIza…) is hardcoded in the code.",
    ),
    Rule(
        "TLX-S008",
        "Supabase service role key exposed",
        Severity.CRITICAL,
        "A Supabase service_role key (bypasses row-level security) is in source.",
    ),
    Rule(
        "TLX-S009",
        "Database password in connection URL",
        Severity.CRITICAL,
        "A database URL with an embedded password is hardcoded in the code.",
    ),
    Rule(
        "TLX-S010",
        "JWT signing secret hardcoded",
        Severity.CRITICAL,
        "SECRET_KEY / JWT_SECRET is assigned a literal string in source code.",
    ),
    Rule(
        "TLX-S011",
        ".env file committed to git",
        Severity.CRITICAL,
        "A .env file is tracked by git, exposing every secret inside it.",
    ),
    Rule(
        "TLX-S012",
        "Private key material in repo",
        Severity.CRITICAL,
        "A private key block or .pem/.key file is present in the repository.",
    ),
]

#: Directory names (path segments) skipped for all secrets rules.
_SKIP_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "fixture",
        "fixtures",
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "mock",
        "mocks",
    }
)

_PLACEHOLDER_HINTS = (
    "example",
    "sample",
    "changeme",
    "change-me",
    "change_me",
    "change me",
    "placeholder",
    "your-",
    "your_",
    "your ",
    "dummy",
    "fake",
    "xxx",
    "insert",
    "replace",
    "redacted",
    "<",
    ">",
    "${",
    "%(",
    "{{",
)

_IGNORE_PRAGMA = "torlyx:ignore"

#: Lines that read secrets the right way — never flagged.
_SAFE_LINE_HINTS = ("os.getenv", "os.environ", "getenv(", "config(", "secrets.token")


def _is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    if any(part in _SKIP_SEGMENTS for part in parts):
        return True
    name = parts[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return True
    return len(set(value)) <= 4  # "aaaa…", "xxxx…", "1234123412…"


def _line_suppressed(line: str) -> bool:
    lowered = line.lower()
    if _IGNORE_PRAGMA in lowered.replace(" ", ""):
        return True
    return any(hint in lowered for hint in _SAFE_LINE_HINTS)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character (Shannon)."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


# --- specific provider patterns (S002…S009) --------------------------------

_AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET = re.compile(
    r"(?i)\baws[a-z0-9_]*(?:secret|key)[a-z0-9_]*\s*[:=]\s*[\"'][A-Za-z0-9/+=]{40}[\"']"
)
_STRIPE = re.compile(r"\bsk_live_[0-9a-zA-Z]{10,}\b")
_OPENAI = re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b")
_ANTHROPIC = re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")
_GITHUB = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")
_GOOGLE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
_JWT_SHAPE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}\b")
_DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)"
    r"://[^\s:@/\"']+:([^\s@/\"']+)@"
)

_PATTERN_RULES: list[tuple[str, str, re.Pattern[str], str, str]] = [
    (
        "TLX-S002",
        "AWS access key exposed",
        _AWS_ACCESS,
        "Anyone with this key can use your AWS account — spin up servers, read "
        "your data, and run up your bill.",
        'AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")  # move to .env, then rotate the key in AWS IAM',
    ),
    (
        "TLX-S003",
        "Stripe live key exposed",
        _STRIPE,
        "Anyone who sees this code can charge cards on your Stripe account.",
        'STRIPE_KEY = os.getenv("STRIPE_KEY")  # move value to .env, then roll the key in the Stripe dashboard',
    ),
    (
        "TLX-S004",
        "OpenAI API key exposed",
        _OPENAI,
        "Anyone with this key can make OpenAI API calls billed to your account.",
        'OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # move to .env, then revoke this key at platform.openai.com',
    ),
    (
        "TLX-S005",
        "Anthropic API key exposed",
        _ANTHROPIC,
        "Anyone with this key can make Anthropic API calls billed to your account.",
        'ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")  # move to .env, then revoke at console.anthropic.com',
    ),
    (
        "TLX-S006",
        "GitHub token exposed",
        _GITHUB,
        "This token grants access to your GitHub account — private repos and "
        "possibly pushing code as you.",
        'GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # move to .env, then revoke at github.com/settings/tokens',
    ),
    (
        "TLX-S007",
        "Google API key exposed",
        _GOOGLE,
        "Anyone with this key can call Google APIs on your bill.",
        'GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")  # move to .env, then regenerate in Google Cloud Console',
    ),
    (
        "TLX-S009",
        "Database password in connection URL",
        _DB_URL,
        "Your database username and password are visible to anyone who reads "
        "this code.",
        'DATABASE_URL = os.getenv("DATABASE_URL")  # move the full URL to .env and change the DB password',
    ),
]

_JWT_SECRET_NAMES = frozenset(
    {
        "secret_key",
        "jwt_secret",
        "jwt_secret_key",
        "session_secret",
        "auth_secret",
        "signing_key",
    }
)

#: Variable-name segments that mark a value as secret-looking (S001).
_SECRET_SEGMENTS = frozenset(
    {"key", "secret", "token", "password", "passwd", "pwd", "apikey", "credentials"}
)
#: …unless one of these segments is also present (public keys aren't secret).
_NONSECRET_SEGMENTS = frozenset({"public", "pub", "pattern", "regex", "name", "id", "url", "path", "file"})

_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_]{0,60})\s*[:=]\s*[\"']([^\"']{20,})[\"']"
)

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----")

_ENV_OK_SUFFIXES = (".example", ".sample", ".template", ".dist", ".test")


def _name_segments(name: str) -> set[str]:
    # split snake_case and camelCase into lowercase segments
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {seg for seg in spaced.lower().split("_") if seg}


def _looks_secret_name(name: str) -> bool:
    segments = _name_segments(name)
    if segments & _NONSECRET_SEGMENTS:
        return False
    return bool(segments & _SECRET_SEGMENTS)


def _is_env_file(path: Path) -> bool:
    return path.name.lower().startswith(".env")


def _jwt_role_is_service(token: str) -> bool:
    """Decode a JWT payload and check for Supabase's service_role claim."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64).decode("utf-8", "replace")
    except (IndexError, ValueError, binascii.Error):
        return False
    return "service_role" in payload


def run(context: "ScanContext") -> list[Finding]:
    """Run all secrets rules against the project."""
    findings: list[Finding] = []
    flagged_lines: set[tuple[str, int]] = set()
    key_content_files: set[str] = set()

    for path in context.files:
        rel = context.rel(path)
        if _is_test_path(rel):
            continue

        text = context.read_text(path)
        if text is None:
            continue

        # S012 fires on content in any file, including .env files.
        key_findings = _check_private_key_content(rel, text, flagged_lines)
        if key_findings:
            key_content_files.add(rel)
            findings.extend(key_findings)

        # Everything else skips .env content — see module docstring.
        if _is_env_file(path):
            continue

        findings.extend(_check_specific_patterns(rel, text, flagged_lines))
        if path.suffix == ".py":
            findings.extend(_check_jwt_secret_ast(context, path, rel, flagged_lines))
        findings.extend(_check_entropy(rel, text, flagged_lines))

    findings.extend(_check_git_state(context, key_content_files))
    return findings


def _check_git_state(
    context: "ScanContext", already_flagged_files: set[str]
) -> list[Finding]:
    """S011 (.env tracked) and the tracked-file half of S012 (.pem/.key)."""
    findings: list[Finding] = []
    for tracked in sorted(context.git_tracked):
        name = tracked.rsplit("/", 1)[-1].lower()
        if _is_test_path(tracked) or tracked in already_flagged_files:
            continue
        if name.startswith(".env") and not name.endswith(_ENV_OK_SUFFIXES):
            findings.append(
                Finding(
                    rule_id="TLX-S011",
                    title=".env file committed to git",
                    severity=Severity.CRITICAL,
                    file=tracked,
                    line=1,
                    message="Every secret in this file is visible to anyone with "
                    "repo access — and stays in git history even after deletion.",
                    fix='git rm --cached "' + tracked + '" && echo "' + name + '" >> .gitignore  # then rotate every secret inside',
                )
            )
        elif name.endswith((".pem", ".key")):
            findings.append(
                Finding(
                    rule_id="TLX-S012",
                    title="Private key material in repo",
                    severity=Severity.CRITICAL,
                    file=tracked,
                    line=1,
                    message="A private key in the repo lets anyone impersonate "
                    "your server or decrypt its traffic.",
                    fix='git rm --cached "' + tracked + '" and generate a new key — the old one is compromised.',
                )
            )
    return findings


def _check_private_key_content(
    rel: str, text: str, flagged: set[tuple[str, int]]
) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _PRIVATE_KEY.search(line):
            flagged.add((rel, lineno))
            findings.append(
                Finding(
                    rule_id="TLX-S012",
                    title="Private key material in repo",
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=lineno,
                    message="A private key in your code lets anyone impersonate "
                    "your server or decrypt its traffic.",
                    fix="Remove the key from the repo, load it from a secrets "
                    "manager or environment, and generate a new key pair.",
                )
            )
            break  # one finding per file is enough
    return findings


def _check_specific_patterns(
    rel: str, text: str, flagged: set[tuple[str, int]]
) -> list[Finding]:
    """S002…S009: known provider key shapes."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _line_suppressed(line):
            continue
        for rule_id, title, pattern, message, fix in _PATTERN_RULES:
            match = pattern.search(line)
            if not match or _is_placeholder(match.group(0)):
                continue
            flagged.add((rel, lineno))
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=lineno,
                    message=message,
                    fix=fix,
                )
            )

        # AWS secret access key (name-anchored, 40-char base64ish value)
        if _AWS_SECRET.search(line):
            if (rel, lineno) not in flagged:
                flagged.add((rel, lineno))
                findings.append(
                    Finding(
                        rule_id="TLX-S002",
                        title="AWS secret access key exposed",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=lineno,
                        message="Anyone with this key can use your AWS account — "
                        "spin up servers, read your data, and run up your bill.",
                        fix='AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")  # move to .env, rotate in IAM',
                    )
                )

        # S008: Supabase service_role JWT
        jwt_match = _JWT_SHAPE.search(line)
        if jwt_match and _jwt_role_is_service(jwt_match.group(0)):
            flagged.add((rel, lineno))
            findings.append(
                Finding(
                    rule_id="TLX-S008",
                    title="Supabase service role key exposed",
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=lineno,
                    message="The service role key bypasses all row-level security — "
                    "full read/write access to your entire database.",
                    fix='SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")  # server-side .env only, never ship to a browser',
                )
            )
    return findings


def _check_jwt_secret_ast(
    context: "ScanContext", path: Path, rel: str, flagged: set[tuple[str, int]]
) -> list[Finding]:
    """S010: SECRET_KEY / JWT_SECRET assigned a literal string (AST-based)."""
    tree = context.get_python_ast(path)
    if tree is None:
        return []
    findings: list[Finding] = []
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None or not isinstance(value, ast.Constant):
            continue
        if not isinstance(value.value, str) or len(value.value) < 8:
            continue
        if _is_placeholder(value.value):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id.lower() in _JWT_SECRET_NAMES:
                flagged.add((rel, node.lineno))
                findings.append(
                    Finding(
                        rule_id="TLX-S010",
                        title="JWT signing secret hardcoded",
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=node.lineno,
                        message="Anyone with this value can forge login tokens and "
                        "impersonate any user, including admins.",
                        fix=f'{target.id} = os.getenv("{target.id.upper()}")  # move the value to .env and rotate it',
                    )
                )
    return findings


def _check_entropy(
    rel: str, text: str, flagged: set[tuple[str, int]]
) -> list[Finding]:
    """S001: generic high-entropy value assigned to a secret-looking name."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if (rel, lineno) in flagged or _line_suppressed(line):
            continue
        for match in _ASSIGNMENT.finditer(line):
            name, value = match.group(1), match.group(2)
            if not _looks_secret_name(name):
                continue
            if _is_placeholder(value):
                continue
            if len(value) < 20 or shannon_entropy(value) <= 4.0:
                continue
            findings.append(
                Finding(
                    rule_id="TLX-S001",
                    title="Hardcoded secret (high entropy)",
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=lineno,
                    message="This looks like a real secret. Anyone who reads your "
                    "code — or your git history — can use it.",
                    fix=f'{name} = os.getenv("{name.upper()}")  # move the value to .env and rotate it',
                )
            )
            break  # one S001 per line
    return findings
