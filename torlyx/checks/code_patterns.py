"""Dangerous code pattern rules (TLX-C001 … TLX-C007). AST-based.

One visitor pass per file. Function scopes track simple local assignments
so one-hop indirection is caught (``query = f"..."; cursor.execute(query)``)
while literal/parameterized calls stay unflagged.
"""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from torlyx.models import Finding, Rule, Severity

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

RULES: list[Rule] = [
    Rule(
        "TLX-C001",
        "SQL injection risk",
        Severity.CRITICAL,
        "SQL is built with an f-string or concatenation and passed to execute()/text().",
    ),
    Rule(
        "TLX-C002",
        "eval/exec on dynamic input",
        Severity.CRITICAL,
        "eval() or exec() is called on something other than a literal.",
    ),
    Rule(
        "TLX-C003",
        "Unsafe pickle deserialization",
        Severity.WARNING,
        "pickle.load()/loads() runs arbitrary code if the data is attacker-controlled.",
    ),
    Rule(
        "TLX-C004",
        "Shell command injection risk",
        Severity.CRITICAL,
        "A subprocess call uses shell=True with a non-literal command string.",
    ),
    Rule(
        "TLX-C005",
        "Weak hash for passwords",
        Severity.WARNING,
        "MD5/SHA1 is used in a password or auth context.",
    ),
    Rule(
        "TLX-C006",
        "Predictable random for secrets",
        Severity.WARNING,
        "The random module (not secrets) is used to generate tokens or secrets.",
    ),
    Rule(
        "TLX-C007",
        "TLS verification disabled",
        Severity.WARNING,
        "An HTTP call passes verify=False, disabling certificate checks.",
    ),
]

_EXECUTE_METHODS = frozenset({"execute", "executemany"})
_SUBPROCESS_FNS = frozenset({"run", "call", "check_call", "check_output", "Popen"})
_RANDOM_FNS = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "sample",
        "getrandbits",
        "randbytes",
        "uniform",
    }
)
_HTTP_VERBS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "stream"}
)

_AUTH_CONTEXT = re.compile(r"(?i)(password|passwd|pwd|auth|login|credential)")
_SECRET_NAME = re.compile(r"(?i)(token|secret|otp|nonce|session|api_key|apikey|password)")


def _dotted(node: ast.expr) -> str:
    """Best-effort dotted name for a call target, e.g. ``subprocess.run``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_dynamic_string(
    node: ast.expr | None, scopes: list[dict[str, ast.expr]], depth: int = 0
) -> bool:
    """True when *node* builds a string from non-literal parts."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        has_str = any(
            isinstance(n, ast.Constant) and isinstance(n.value, str)
            for n in ast.walk(node)
        )
        has_dynamic = any(
            not isinstance(n, (ast.Constant, ast.BinOp, ast.Add, ast.Mod))
            for n in ast.walk(node)
            if isinstance(n, ast.expr)
        )
        return has_str and has_dynamic
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
    ):
        return bool(node.args or node.keywords)
    if isinstance(node, ast.Name) and depth < 2:
        return _is_dynamic_string(_resolve(node.id, scopes), scopes, depth + 1)
    return False


def _resolve(name: str, scopes: list[dict[str, ast.expr]]) -> ast.expr | None:
    for scope in reversed(scopes):
        if name in scope:
            return scope[name]
    return None


def _is_literal(node: ast.expr | None, scopes: list[dict[str, ast.expr]]) -> bool:
    """True when the value is a literal constant (directly or via one hop)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return isinstance(_resolve(node.id, scopes), ast.Constant)
    return False


class _PatternVisitor(ast.NodeVisitor):
    """Single pass over one file, collecting C001…C007 findings."""

    def __init__(self, rel: str, imports: set[str], from_imports: dict[str, set[str]]):
        self.rel = rel
        self.imports = imports
        self.from_imports = from_imports
        self.findings: list[Finding] = []
        self._flagged: set[tuple[str, int]] = set()
        self._scopes: list[dict[str, ast.expr]] = [{}]
        self._context_names: list[set[str]] = [set()]
        self._assign_targets: list[str] = []

    # -- scope bookkeeping -------------------------------------------------

    def _collect_assigns(self, node: ast.AST) -> dict[str, ast.expr]:
        assigns: dict[str, ast.expr] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        assigns[target.id] = child.value
        return assigns

    def visit_Module(self, node: ast.Module) -> None:
        self._scopes[0] = self._collect_assigns(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = [a.arg for a in node.args.args + node.args.kwonlyargs]
        assigns = self._collect_assigns(node)
        self._scopes.append(assigns)
        self._context_names.append({node.name, *args, *assigns})
        if _SECRET_NAME.search(node.name):
            self._flag_random_calls(node, reason=f"function {node.name}()")
        self.generic_visit(node)
        self._context_names.pop()
        self._scopes.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if any(_SECRET_NAME.search(n) for n in names):
            self._flag_random_calls(node.value, reason=f"assigned to {names[0]}")
        self._assign_targets.extend(names)
        self.generic_visit(node)
        del self._assign_targets[len(self._assign_targets) - len(names):]

    # -- the rules ----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sql(node)
        self._check_eval(node)
        self._check_pickle(node)
        self._check_subprocess(node)
        self._check_weak_hash(node)
        self._check_verify_false(node)
        self.generic_visit(node)

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        node: ast.AST,
        message: str,
        fix: str,
        context: str | None = None,
    ) -> None:
        key = (rule_id, node.lineno)
        if key in self._flagged:
            return
        self._flagged.add(key)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=self.rel,
                line=node.lineno,
                message=message,
                fix=fix,
                context=context,
            )
        )

    def _check_sql(self, node: ast.Call) -> None:
        func = node.func
        is_execute = isinstance(func, ast.Attribute) and func.attr in _EXECUTE_METHODS
        is_text = (isinstance(func, ast.Name) and func.id == "text") or (
            isinstance(func, ast.Attribute) and func.attr == "text"
        )
        if not (is_execute or is_text) or not node.args:
            return
        if _is_dynamic_string(node.args[0], self._scopes):
            self._add(
                "TLX-C001",
                "SQL injection risk",
                Severity.CRITICAL,
                node,
                "This query includes raw input — an attacker can type SQL into "
                "that field and read or delete your entire database.",
                'Use parameters: cursor.execute("SELECT * FROM users WHERE email = ?", (email,))',
            )

    def _check_eval(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name) or node.func.id not in {"eval", "exec"}:
            return
        if not node.args or _is_literal(node.args[0], self._scopes):
            return
        self._add(
            "TLX-C002",
            f"{node.func.id}() on dynamic input",
            Severity.CRITICAL,
            node,
            f"{node.func.id}() runs whatever text it is given — user input "
            "becomes code running on your server.",
            "For data, use ast.literal_eval(); for math, use a parsing library — "
            f"never {node.func.id}() user input.",
        )

    def _check_pickle(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        from_pickle = self.from_imports.get("pickle", set())
        is_pickle = dotted in {"pickle.load", "pickle.loads"} or (
            isinstance(node.func, ast.Name) and node.func.id in from_pickle & {"load", "loads"}
        )
        if not is_pickle:
            return
        self._add(
            "TLX-C003",
            "Unsafe pickle deserialization",
            Severity.WARNING,
            node,
            "Unpickling data an attacker can influence lets them run arbitrary "
            "code on your server.",
            "Use JSON for untrusted data: json.loads(blob)",
        )

    def _check_subprocess(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        from_subprocess = self.from_imports.get("subprocess", set())
        is_subprocess = (
            dotted.startswith("subprocess.") and dotted.split(".")[-1] in _SUBPROCESS_FNS
        ) or (
            isinstance(node.func, ast.Name)
            and node.func.id in from_subprocess & _SUBPROCESS_FNS
        )
        if not is_subprocess:
            return
        shell_true = any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_true or not node.args:
            return
        if _is_literal(node.args[0], self._scopes):
            return
        self._add(
            "TLX-C004",
            "Shell command injection risk",
            Severity.CRITICAL,
            node,
            "Anyone who controls part of this string can run any command on "
            "your server.",
            'Pass a list instead: subprocess.run(["ping", "-n", "1", host])  # no shell=True',
        )

    def _check_weak_hash(self, node: ast.Call) -> None:
        dotted = _dotted(node.func)
        from_hashlib = self.from_imports.get("hashlib", set())
        algo: str | None = None
        if dotted in {"hashlib.md5", "hashlib.sha1"}:
            algo = dotted.split(".")[-1]
        elif isinstance(node.func, ast.Name) and node.func.id in from_hashlib & {"md5", "sha1"}:
            algo = node.func.id
        elif dotted == "hashlib.new" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and str(first.value).lower() in {"md5", "sha1"}:
                algo = str(first.value).lower()
        if algo is None:
            return
        nearby = " ".join((*self._context_names[-1], *self._assign_targets))
        if not _AUTH_CONTEXT.search(nearby):
            return
        self._add(
            "TLX-C005",
            f"{algo.upper()} used for passwords",
            Severity.WARNING,
            node,
            f"{algo.upper()} can be cracked in seconds on a laptop — a leaked "
            "database means every password is exposed.",
            "Use a real password hasher: from passlib.hash import bcrypt; bcrypt.hash(password)",
        )

    def _flag_random_calls(self, node: ast.AST, reason: str) -> None:
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == "random"
                and child.func.attr in _RANDOM_FNS
            ):
                self._add(
                    "TLX-C006",
                    "Predictable random for secrets",
                    Severity.WARNING,
                    child,
                    "Python's random module is predictable — an attacker can "
                    "reconstruct these tokens and hijack sessions.",
                    "Use the secrets module: secrets.token_urlsafe(32)",
                    context=reason,
                )

    def _check_verify_false(self, node: ast.Call) -> None:
        verify_false = any(
            kw.arg == "verify"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.keywords
        )
        if not verify_false:
            return
        dotted = _dotted(node.func)
        root = dotted.split(".")[0] if dotted else ""
        method = dotted.split(".")[-1] if dotted else ""
        http_libs = {"requests", "httpx"}
        if root not in http_libs and not (
            method in _HTTP_VERBS and (self.imports & http_libs)
        ):
            return
        self._add(
            "TLX-C007",
            "TLS verification disabled",
            Severity.WARNING,
            node,
            "verify=False lets anyone on the network read and tamper with this "
            "traffic — including the credentials it carries.",
            "Remove verify=False and fix the certificate instead of ignoring it.",
        )


def _file_imports(tree: ast.Module) -> tuple[set[str], dict[str, set[str]]]:
    """Top-level imported module names and ``from x import y`` names."""
    imports: set[str] = set()
    from_imports: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            imports.add(root)
            from_imports.setdefault(root, set()).update(a.name for a in node.names)
    return imports, from_imports


def run(context: "ScanContext") -> list[Finding]:
    """Run all code pattern rules against every Python file."""
    findings: list[Finding] = []
    for path in context.python_files():
        tree = context.get_python_ast(path)
        if tree is None:
            continue
        imports, from_imports = _file_imports(tree)
        visitor = _PatternVisitor(context.rel(path), imports, from_imports)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings
