<div align="center">

# Torlyx CLI

**Scan your vibe-coded app before you ship it.**

Torlyx CLI is a zero-configuration security scanner for AI-generated web
applications. It detects hardcoded secrets, unprotected endpoints, SQL
injection, permissive CORS, and vulnerable dependencies — in seconds,
entirely on your machine.

[![PyPI](https://img.shields.io/pypi/v/torlyx)](https://pypi.org/project/torlyx/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/torlyx/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

<!-- TODO: animated demo -->
![Torlyx CLI demo](docs/demo.gif)

</div>

## Installation

```bash
pip install torlyx
```

To enable the dependency vulnerability audit, install with the `audit` extra:

```bash
pip install 'torlyx[audit]'
```

## Usage

```bash
cd my-app
torlyx scan .
```

No configuration file, no account, no API key. Analysis runs locally — the
only optional network call is the dependency audit. Every finding includes a
plain-English explanation of the risk and a concrete fix:

```
  ⚡ TORLYX SECURITY SCAN
  Scanned 47 files in 1.2s

  🔴 CRITICAL  TLX-S003 · Stripe live key exposed
     app/config.py:12
     → Anyone who sees this code can charge cards on your Stripe account.
     Fix: STRIPE_KEY = os.getenv("STRIPE_KEY")

  🔴 CRITICAL  TLX-F001 · Unprotected DELETE endpoint
     app/routes/users.py:34 → DELETE /users/{id}
     → Anyone on the internet can call this endpoint and change your data.
     Fix: def delete_user(id: int, user=Depends(get_current_user)):

  ─────────────────────────────────────────────
  Security Score: 38/100
  2 critical · 1 warning · 28 checks passed
```

## Commands

| Command | Description |
|---|---|
| `torlyx scan [PATH]` | Scan a project. `PATH` defaults to the current directory. |
| `torlyx rules` | List every rule with its severity and description. |
| `torlyx version` | Print the installed version. |

### Scan options

| Option | Description |
|---|---|
| `--json` | Emit machine-readable JSON (findings, score, metadata) to stdout. |
| `--fail-on <critical\|warning\|any>` | Exit with code 1 when findings at or above the threshold exist. Intended for CI. |
| `--exclude <pattern>` | Exclude files matching a glob pattern. Repeatable. |
| `--no-audit` | Skip the dependency CVE audit — the only check that uses the network. |
| `--export md` | Also write `torlyx-report.md` — an AI-ready report: paste it into Cursor, Claude Code, or Copilot and ask it to fix each finding. |
| `--verbose` | Report files skipped due to syntax errors. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; below the `--fail-on` threshold (or no threshold set). |
| `1` | Findings at or above the `--fail-on` threshold. |
| `2` | The scan itself failed. |

## Design principles

- **Zero configuration.** A single command with sensible defaults.
- **Fast.** Pure-Python AST analysis; a typical project scans in seconds.
- **Framework-aware.** Understands FastAPI auth in all its forms — router-level
  dependencies, `Annotated[..., Depends(...)]`, and `include_router`
  dependencies — so it reports real gaps rather than false positives.
- **Readable.** Findings are written for developers, not security auditors.
  No jargon; every finding ships with a fix.
- **Private.** Code never leaves the machine.

## Rules

Torlyx CLI v0.1 ships 31 rules across five categories.

### Secrets

| ID | Detects | Severity |
|---|---|---|
| TLX-S001 | High-entropy value assigned to a secret-named variable | Critical |
| TLX-S002 | AWS access key or secret key | Critical |
| TLX-S003 | Stripe live key | Critical |
| TLX-S004 | OpenAI API key | Critical |
| TLX-S005 | Anthropic API key | Critical |
| TLX-S006 | GitHub token | Critical |
| TLX-S007 | Google API key | Critical |
| TLX-S008 | Supabase service role key | Critical |
| TLX-S009 | Database password embedded in a connection URL | Critical |
| TLX-S010 | Hardcoded JWT or session signing secret | Critical |
| TLX-S011 | `.env` file tracked by git | Critical |
| TLX-S012 | Private key material in the repository | Critical |

### FastAPI

| ID | Detects | Severity |
|---|---|---|
| TLX-F001 | State-changing route (POST/PUT/PATCH/DELETE) without an auth dependency | Critical |
| TLX-F002 | Admin route without an auth dependency | Critical |
| TLX-F003 | CORS wildcard origin combined with credentials | Critical |
| TLX-F004 | CORS wildcard origin | Warning |
| TLX-F005 | Debug mode enabled | Warning |
| TLX-F006 | API documentation enabled in a deployable project | Info |
| TLX-F007 | Response model exposing password, secret, or token fields | Warning |
| TLX-F008 | Login routes without rate limiting | Warning |

### Code patterns

| ID | Detects | Severity |
|---|---|---|
| TLX-C001 | SQL built with f-strings or concatenation passed to `execute()` / `text()` | Critical |
| TLX-C002 | `eval()` or `exec()` on non-literal input | Critical |
| TLX-C003 | `pickle` deserialization of untrusted data | Warning |
| TLX-C004 | `subprocess` with `shell=True` and a dynamic command | Critical |
| TLX-C005 | MD5 or SHA1 in a password context | Warning |
| TLX-C006 | `random` module used for tokens instead of `secrets` | Warning |
| TLX-C007 | TLS verification disabled (`verify=False`) | Warning |

### Configuration and infrastructure

| ID | Detects | Severity |
|---|---|---|
| TLX-I001 | Dockerfile running as root | Warning |
| TLX-I002 | Server bound to `0.0.0.0` with no authentication anywhere | Info |
| TLX-I003 | Source maps committed in build output | Warning |

### Dependencies

| ID | Detects | Severity |
|---|---|---|
| TLX-D001 | Known CVEs, via [pip-audit](https://github.com/pypa/pip-audit) | Mapped from CVSS |

### False-positive policy

False positives are treated as bugs. Test and fixture directories are skipped
by the secrets rules, common placeholder values are recognized, and login,
signup, and webhook routes are exempt from the authentication rule. Any
individual line can be suppressed with a trailing comment:

```python
STRIPE_TEST_KEY = "sk_test_example"  # torlyx:ignore
```

## Continuous integration

Add a workflow such as `.github/workflows/security.yml`:

```yaml
name: security
on: [push, pull_request]
jobs:
  torlyx:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install 'torlyx[audit]'
      - run: torlyx scan . --fail-on critical
```

## Roadmap

**v0.2: Next.js/React support (`npx torlyx`), plus `--ai-fix` export and YAML
custom rules · v0.3: Laravel + Inertia support (`composer require
torlyx/laravel` → `php artisan torlyx:scan`)**

The core — findings, scoring, and reporting — is language-agnostic. New
stacks plug in as parser backends via tree-sitter, distributed through npm
and Composer wrappers around a compiled binary.

## Contributing

```bash
git clone https://github.com/khadikul/torlyx-cli
cd torlyx-cli
pip install -e ".[dev]"
pytest
```

Every check module implements `run(context) -> list[Finding]` and is
registered automatically; adding a rule never requires changes to the
orchestrator. Validate changes against the two fixture applications:
`tests/fixtures/vulnerable_app` must trigger every rule, and
`tests/fixtures/clean_app` must produce zero findings.

## License

Released under the [MIT License](LICENSE).

---

*Torlyx CLI is the open source scanner from the [Torlyx](https://torlyx.com) security platform.*
