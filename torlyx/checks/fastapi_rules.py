"""FastAPI framework rules (TLX-F001 … TLX-F008). AST-based, project-wide.

The analysis pass collects apps, routers, routes, CORS middleware calls and
pydantic models across all files; rules are evaluated on the collected graph.

Auth is recognized in every form FastAPI supports, to keep false positives
down: ``Depends(...)``/``Security(...)`` parameter defaults,
``Annotated[..., Depends(...)]`` annotations, route-decorator
``dependencies=[...]``, router-level ``APIRouter(dependencies=[...])``,
app-level ``FastAPI(dependencies=[...])`` and
``include_router(..., dependencies=[...])``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from torlyx.models import Finding, Rule, Severity

if TYPE_CHECKING:
    from torlyx.scanner import ScanContext

RULES: list[Rule] = [
    Rule(
        "TLX-F001",
        "Unprotected state-changing endpoint",
        Severity.CRITICAL,
        "A POST/PUT/PATCH/DELETE route has no auth dependency at any level.",
    ),
    Rule(
        "TLX-F002",
        "Unprotected admin endpoint",
        Severity.CRITICAL,
        "A route with 'admin' in its path has no auth dependency.",
    ),
    Rule(
        "TLX-F003",
        "CORS wildcard with credentials",
        Severity.CRITICAL,
        "CORS allows every origin AND credentials — any site can act as logged-in users.",
    ),
    Rule(
        "TLX-F004",
        "CORS allows all origins",
        Severity.WARNING,
        "CORS middleware is configured with allow_origins=[\"*\"].",
    ),
    Rule(
        "TLX-F005",
        "Debug mode enabled",
        Severity.WARNING,
        "debug=True exposes stack traces and internals to visitors.",
    ),
    Rule(
        "TLX-F006",
        "API docs enabled in production",
        Severity.INFO,
        "Interactive docs are exposed while the project shows production signals.",
    ),
    Rule(
        "TLX-F007",
        "Response model leaks sensitive fields",
        Severity.WARNING,
        "A route returns a model containing password/secret/token fields.",
    ),
    Rule(
        "TLX-F008",
        "No rate limiting on auth routes",
        Severity.WARNING,
        "Login routes exist but no rate-limiting library is used anywhere.",
    ),
]

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_STATE_CHANGING = frozenset({"post", "put", "patch", "delete"})

#: Paths that are unauthenticated by design — exempt from TLX-F001.
_AUTH_EXEMPT_PATH = re.compile(
    r"(?i)(login|logout|signin|sign-in|signup|sign-up|register|token|refresh"
    r"|forgot|reset|verify|confirm|webhook|callback|oauth|health|ping|contact|subscribe)"
)

_LOGIN_PATH = re.compile(r"(?i)(login|signin|sign-in|token|/auth)")

_RATE_LIMIT_LIBS = frozenset(
    {"slowapi", "limits", "fastapi_limiter", "starlette_limiter", "ratelimit", "throttled"}
)

#: Hand-rolled limiters count too: Depends(rate_limit(...)), @limiter.limit(...)
_RATE_LIMIT_NAME = re.compile(r"(?i)(rate_?limit|throttl|limiter)")

_SENSITIVE_FIELDS = frozenset(
    {"password", "hashed_password", "password_hash", "secret", "secret_key", "token"}
)


@dataclass
class _App:
    var: str
    file: str
    line: int
    debug: bool = False
    docs_disabled: bool = False
    has_dependencies: bool = False


@dataclass
class _Router:
    var: str
    file: str
    has_dependencies: bool = False
    has_rate_limit: bool = False


@dataclass
class _Route:
    file: str
    line: int
    method: str
    path: str
    owner: str
    func_name: str
    has_auth: bool
    has_rate_limit: bool = False
    response_refs: list[str] = field(default_factory=list)


@dataclass
class _CorsCall:
    file: str
    line: int
    wildcard_origin: bool
    with_credentials: bool


@dataclass
class _Analysis:
    apps: list[_App] = field(default_factory=list)
    routers: list[_Router] = field(default_factory=list)
    routes: list[_Route] = field(default_factory=list)
    cors_calls: list[_CorsCall] = field(default_factory=list)
    debug_lines: list[tuple[str, int]] = field(default_factory=list)
    model_fields: dict[str, set[str]] = field(default_factory=dict)
    model_bases: dict[str, list[str]] = field(default_factory=dict)
    model_lines: dict[str, tuple[str, int]] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)
    #: names mentioned in include_router(..., dependencies=[...]) first args,
    #: e.g. {"users", "router"} for include_router(users.router, dependencies=[...])
    include_with_deps: set[str] = field(default_factory=set)


def _call_name(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_none(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _non_empty(node: ast.expr | None) -> bool:
    """Whether a dependencies=… value plausibly holds at least one entry."""
    if node is None:
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return len(node.elts) > 0
    return True  # a Name/Call we can't inspect — assume it provides auth


def _is_depends(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node.func).split(".")[-1] in {"Depends", "Security"}
    )


def _annotation_has_depends(annotation: ast.expr | None) -> bool:
    """Detect Annotated[X, Depends(...)] style dependencies."""
    if annotation is None:
        return False
    return any(_is_depends(n) for n in ast.walk(annotation) if isinstance(n, ast.expr))


def _mentions_rate_limit(*nodes: ast.AST | None) -> bool:
    """True when any node references a limiter by name (call, attr, or bare)."""
    for node in nodes:
        if node is None:
            continue
        for child in ast.walk(node):
            name = ""
            if isinstance(child, ast.Call):
                name = _call_name(child.func)
            elif isinstance(child, ast.Attribute):
                name = child.attr
            elif isinstance(child, ast.Name):
                name = child.id
            if name and _RATE_LIMIT_NAME.search(name):
                return True
    return False


def _signature_has_auth(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    defaults = list(fn.args.defaults) + [d for d in fn.args.kw_defaults if d is not None]
    if any(_is_depends(d) for d in defaults):
        return True
    all_args = fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs
    return any(_annotation_has_depends(a.annotation) for a in all_args)


def _names_in(node: ast.expr | None) -> list[str]:
    """Class names referenced by a response_model value / return annotation."""
    if node is None:
        return []
    skip = {"list", "List", "Optional", "Union", "Sequence", "dict", "Dict", "None"}
    return [
        n.id for n in ast.walk(node) if isinstance(n, ast.Name) and n.id not in skip
    ]


def _wildcard_origins(node: ast.expr | None, module_assigns: dict[str, ast.expr]) -> bool:
    if isinstance(node, ast.Name):
        node = module_assigns.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(
            isinstance(e, ast.Constant) and e.value == "*" for e in node.elts
        )
    return isinstance(node, ast.Constant) and node.value == "*"


def _analyze_file(tree: ast.Module, rel: str, analysis: _Analysis) -> None:
    module_assigns: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    module_assigns[target.id] = node.value

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                analysis.imports.update(a.name.split(".")[0] for a in node.names)
            elif node.module:
                analysis.imports.add(node.module.split(".")[0])

        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            ctor = _call_name(node.value.func).split(".")[-1]
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if ctor == "FastAPI":
                    analysis.apps.append(
                        _App(
                            var=target.id,
                            file=rel,
                            line=node.lineno,
                            debug=_is_true(_kwarg(node.value, "debug")),
                            docs_disabled=_is_none(_kwarg(node.value, "docs_url"))
                            or _is_none(_kwarg(node.value, "openapi_url")),
                            has_dependencies=_non_empty(_kwarg(node.value, "dependencies")),
                        )
                    )
                elif ctor == "APIRouter":
                    analysis.routers.append(
                        _Router(
                            var=target.id,
                            file=rel,
                            has_dependencies=_non_empty(_kwarg(node.value, "dependencies")),
                            has_rate_limit=_mentions_rate_limit(
                                _kwarg(node.value, "dependencies")
                            ),
                        )
                    )

        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            attr = name.split(".")[-1]
            if attr == "add_middleware" and node.args:
                middleware = _call_name(node.args[0]).split(".")[-1]
                if middleware == "CORSMiddleware":
                    analysis.cors_calls.append(
                        _CorsCall(
                            file=rel,
                            line=node.lineno,
                            wildcard_origin=_wildcard_origins(
                                _kwarg(node, "allow_origins"), module_assigns
                            ),
                            with_credentials=_is_true(_kwarg(node, "allow_credentials")),
                        )
                    )
            elif attr == "include_router" and node.args:
                if _non_empty(_kwarg(node, "dependencies")):
                    analysis.include_with_deps.update(_names_in(node.args[0]))
            elif name == "uvicorn.run" and _is_true(_kwarg(node, "debug")):
                analysis.debug_lines.append((rel, node.lineno))

        elif isinstance(node, ast.ClassDef):
            _collect_model(node, rel, analysis)

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_routes(node, rel, analysis)


def _collect_model(node: ast.ClassDef, rel: str, analysis: _Analysis) -> None:
    bases = [_call_name(b).split(".")[-1] for b in node.bases if isinstance(b, (ast.Name, ast.Attribute))]
    fields: set[str] = set()
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            fields.add(stmt.target.id)
        elif isinstance(stmt, ast.Assign):
            fields.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
    analysis.model_bases[node.name] = bases
    analysis.model_fields[node.name] = fields
    analysis.model_lines[node.name] = (rel, node.lineno)


def _collect_routes(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, rel: str, analysis: _Analysis
) -> None:
    defaults = [d for d in (*fn.args.defaults, *fn.args.kw_defaults) if d is not None]
    has_rate_limit = _mentions_rate_limit(*fn.decorator_list, *defaults)
    for decorator in fn.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(
            decorator.func, ast.Attribute
        ):
            continue
        method = decorator.func.attr
        if method not in _HTTP_METHODS:
            continue
        owner = _call_name(decorator.func.value)
        path = ""
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            path = str(decorator.args[0].value)
        else:
            path_kw = _kwarg(decorator, "path")
            if isinstance(path_kw, ast.Constant):
                path = str(path_kw.value)
        has_auth = _signature_has_auth(fn) or _non_empty(_kwarg(decorator, "dependencies"))
        response_refs = _names_in(_kwarg(decorator, "response_model")) + _names_in(fn.returns)
        analysis.routes.append(
            _Route(
                file=rel,
                line=fn.lineno,
                method=method,
                path=path,
                owner=owner,
                func_name=fn.name,
                has_auth=has_auth,
                has_rate_limit=has_rate_limit,
                response_refs=response_refs,
            )
        )


def _route_is_protected(route: _Route, analysis: _Analysis) -> bool:
    if route.has_auth:
        return True
    owner_last = route.owner.split(".")[-1]
    local = [r for r in analysis.routers if r.var == owner_last and r.file == route.file]
    if local:
        if any(r.has_dependencies for r in local):
            return True
    else:
        # owner defined elsewhere: trust any same-named router with deps
        if any(r.var == owner_last and r.has_dependencies for r in analysis.routers):
            return True
    apps = [a for a in analysis.apps if a.var == owner_last and a.file == route.file]
    if any(a.has_dependencies for a in apps):
        return True
    # app.include_router(users.router, dependencies=[...]) — match by module
    # basename or owner var name mentioned in the include call.
    module = route.file.rsplit("/", 1)[-1].removesuffix(".py")
    if analysis.include_with_deps & {module, owner_last}:
        return True
    return False


def _pydantic_models(analysis: _Analysis) -> set[str]:
    """Fixpoint of classes that (transitively) inherit from BaseModel."""
    models = {
        name
        for name, bases in analysis.model_bases.items()
        if "BaseModel" in bases or "BaseSettings" in bases
    }
    changed = True
    while changed:
        changed = False
        for name, bases in analysis.model_bases.items():
            if name not in models and any(b in models for b in bases):
                models.add(name)
                changed = True
    return models


def _effective_fields(name: str, analysis: _Analysis, seen: set[str] | None = None) -> set[str]:
    seen = seen or set()
    if name in seen or name not in analysis.model_fields:
        return set()
    seen.add(name)
    fields = set(analysis.model_fields[name])
    for base in analysis.model_bases.get(name, []):
        fields |= _effective_fields(base, analysis, seen)
    return fields


def run(context: "ScanContext") -> list[Finding]:
    """Run all FastAPI rules against the project."""
    analysis = _Analysis()
    for path in context.python_files():
        tree = context.get_python_ast(path)
        if tree is not None:
            _analyze_file(tree, context.rel(path), analysis)

    if not analysis.apps and not analysis.routes:
        return []  # not a FastAPI project — every F rule stays quiet

    findings: list[Finding] = []
    findings.extend(_check_unprotected_routes(analysis))
    findings.extend(_check_cors(analysis))
    findings.extend(_check_debug(analysis))
    findings.extend(_check_docs(analysis, context))
    findings.extend(_check_response_models(analysis))
    findings.extend(_check_rate_limiting(analysis))
    return findings


def _check_unprotected_routes(analysis: _Analysis) -> list[Finding]:
    findings: list[Finding] = []
    for route in analysis.routes:
        if _route_is_protected(route, analysis):
            continue
        label = f"{route.method.upper()} {route.path}"
        if "admin" in route.path.lower():
            findings.append(
                Finding(
                    rule_id="TLX-F002",
                    title="Unprotected admin endpoint",
                    severity=Severity.CRITICAL,
                    file=route.file,
                    line=route.line,
                    message="This admin endpoint is open to the whole internet — "
                    "no login required.",
                    fix=f"def {route.func_name}(..., user=Depends(get_current_admin)):",
                    context=label,
                )
            )
        elif route.method in _STATE_CHANGING and not _AUTH_EXEMPT_PATH.search(route.path):
            findings.append(
                Finding(
                    rule_id="TLX-F001",
                    title=f"Unprotected {route.method.upper()} endpoint",
                    severity=Severity.CRITICAL,
                    file=route.file,
                    line=route.line,
                    message="Anyone on the internet can call this endpoint and "
                    "change your data. No login required.",
                    fix=f"def {route.func_name}(..., user=Depends(get_current_user)):",
                    context=label,
                )
            )
    return findings


def _check_cors(analysis: _Analysis) -> list[Finding]:
    findings: list[Finding] = []
    for cors in analysis.cors_calls:
        if not cors.wildcard_origin:
            continue
        if cors.with_credentials:
            findings.append(
                Finding(
                    rule_id="TLX-F003",
                    title="CORS wildcard with credentials",
                    severity=Severity.CRITICAL,
                    file=cors.file,
                    line=cors.line,
                    message="Any website can make logged-in requests to your API "
                    "from a visitor's browser — with their cookies attached.",
                    fix='allow_origins=["https://yourapp.com"]  # list your real frontends, never "*" with credentials',
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="TLX-F004",
                    title="CORS allows all origins",
                    severity=Severity.WARNING,
                    file=cors.file,
                    line=cors.line,
                    message="Any website can call your API from a visitor's browser.",
                    fix='allow_origins=["https://yourapp.com"]  # list the sites that actually need access',
                )
            )
    return findings


def _check_debug(analysis: _Analysis) -> list[Finding]:
    findings: list[Finding] = []
    locations = [(a.file, a.line) for a in analysis.apps if a.debug]
    locations += analysis.debug_lines
    for file, line in locations:
        findings.append(
            Finding(
                rule_id="TLX-F005",
                title="Debug mode enabled",
                severity=Severity.WARNING,
                file=file,
                line=line,
                message="When something breaks, visitors see full stack traces, "
                "paths and internals of your app.",
                fix="Remove debug=True before deploying.",
            )
        )
    return findings


def _check_docs(analysis: _Analysis, context: "ScanContext") -> list[Finding]:
    if not context.has_production_signals():
        return []
    findings: list[Finding] = []
    for app in analysis.apps:
        if not app.docs_disabled:
            findings.append(
                Finding(
                    rule_id="TLX-F006",
                    title="API docs enabled in production",
                    severity=Severity.INFO,
                    file=app.file,
                    line=app.line,
                    message="Your interactive API docs (/docs) are public — a "
                    "ready-made map of every endpoint for an attacker.",
                    fix="app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # in production",
                )
            )
    return findings


def _check_response_models(analysis: _Analysis) -> list[Finding]:
    models = _pydantic_models(analysis)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for route in analysis.routes:
        for ref in route.response_refs:
            if ref not in models:
                continue
            leaked = sorted(_effective_fields(ref, analysis) & _SENSITIVE_FIELDS)
            if not leaked or (route.file, route.line) in seen:
                continue
            seen.add((route.file, route.line))
            findings.append(
                Finding(
                    rule_id="TLX-F007",
                    title="Response model leaks sensitive fields",
                    severity=Severity.WARNING,
                    file=route.file,
                    line=route.line,
                    message=f"This endpoint's response includes '{', '.join(leaked)}' "
                    "— that data leaves your server even if no UI ever shows it.",
                    fix=f"Make a public variant of {ref} without {leaked[0]} and use it as response_model.",
                    context=f"{route.method.upper()} {route.path} → {ref}",
                )
            )
    return findings


def _route_rate_limited(route: _Route, analysis: _Analysis) -> bool:
    """Rate-limited at route level or via its router's dependencies."""
    if route.has_rate_limit:
        return True
    owner_last = route.owner.split(".")[-1]
    local = [r for r in analysis.routers if r.var == owner_last and r.file == route.file]
    routers = local or [r for r in analysis.routers if r.var == owner_last]
    return any(r.has_rate_limit for r in routers)


def _check_rate_limiting(analysis: _Analysis) -> list[Finding]:
    if analysis.imports & _RATE_LIMIT_LIBS:
        return []
    login_routes = [
        r
        for r in analysis.routes
        if (_LOGIN_PATH.search(r.path) or "login" in r.func_name.lower())
        and not _route_rate_limited(r, analysis)
    ]
    if not login_routes:
        return []
    route = min(login_routes, key=lambda r: (r.file, r.line))
    return [
        Finding(
            rule_id="TLX-F008",
            title="No rate limiting on auth routes",
            severity=Severity.WARNING,
            file=route.file,
            line=route.line,
            message="Without rate limiting, a bot can try thousands of passwords "
            "per minute against this login.",
            fix='pip install slowapi, then: @limiter.limit("5/minute") on auth routes',
            context=f"{route.method.upper()} {route.path}",
        )
    ]
