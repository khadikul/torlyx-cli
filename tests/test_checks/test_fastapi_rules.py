"""Tests for the FastAPI rules (TLX-F001 … TLX-F008)."""

from __future__ import annotations

import sys

import pytest

from torlyx.checks import fastapi_rules


def rules_fired(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_every_fastapi_rule_fires_on_vulnerable_app(vuln_ctx):
    findings = fastapi_rules.run(vuln_ctx)
    assert rules_fired(findings) == {
        "TLX-F001",
        "TLX-F002",
        "TLX-F003",
        "TLX-F004",
        "TLX-F005",
        "TLX-F006",
        "TLX-F007",
        "TLX-F008",
    }
    where = {(f.rule_id, f.file) for f in findings}
    assert ("TLX-F001", "app/routes/users.py") in where
    assert ("TLX-F002", "app/routes/admin.py") in where
    assert ("TLX-F003", "app/main.py") in where
    assert ("TLX-F004", "app/internal_api.py") in where
    assert ("TLX-F005", "app/main.py") in where
    assert ("TLX-F007", "app/routes/users.py") in where
    assert ("TLX-F008", "app/routes/auth.py") in where


def test_route_context_shows_method_and_path(vuln_ctx):
    findings = fastapi_rules.run(vuln_ctx)
    f001 = next(f for f in findings if f.rule_id == "TLX-F001")
    assert f001.context == "DELETE /users/{user_id}"


def test_clean_app_has_no_fastapi_findings(clean_ctx):
    assert fastapi_rules.run(clean_ctx) == []


def test_depends_parameter_protects_route(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n"
                "@router.delete('/items/{i}')\n"
                "def remove(i: int, user=Depends(lambda: 1)):\n"
                "    return i\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_annotated_depends_protects_route(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from typing import Annotated\n"
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n"
                "@router.post('/items')\n"
                "def create(user: Annotated[dict, Depends(lambda: 1)]):\n"
                "    return user\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_router_level_dependencies_protect_routes(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter(dependencies=[Depends(lambda: 1)])\n"
                "@router.delete('/items/{i}')\n"
                "def remove(i: int):\n"
                "    return i\n"
                "@router.get('/admin/panel')\n"
                "def panel():\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_decorator_dependencies_protect_route(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n"
                "@router.post('/items', dependencies=[Depends(lambda: 1)])\n"
                "def create():\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_include_router_dependencies_protect_other_file_routes(make_ctx):
    ctx = make_ctx(
        {
            "routes/users.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n"
                "@router.delete('/users/{i}')\n"
                "def remove(i: int):\n"
                "    return i\n"
            ),
            "main.py": (
                "from fastapi import FastAPI, Depends\n"
                "from routes import users\n"
                "app = FastAPI(docs_url=None)\n"
                "app.include_router(users.router, dependencies=[Depends(lambda: 1)])\n"
            ),
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_annotated_alias_from_another_file_protects_route(make_ctx):
    """The official FastAPI template pattern: CurrentUser = Annotated[User, Depends(...)]."""
    ctx = make_ctx(
        {
            "deps.py": (
                "from typing import Annotated\n"
                "from fastapi import Depends\n"
                "def get_current_user():\n"
                "    return {}\n"
                "CurrentUser = Annotated[dict, Depends(get_current_user)]\n"
            ),
            "api.py": (
                "from fastapi import APIRouter\n"
                "from deps import CurrentUser\n"
                "router = APIRouter()\n"
                "@router.delete('/items/{i}')\n"
                "def remove(i: int, user: CurrentUser):\n"
                "    return i\n"
                "@router.get('/admin/panel')\n"
                "def panel(user: CurrentUser):\n"
                "    return {}\n"
            ),
        }
    )
    assert fastapi_rules.run(ctx) == []


@pytest.mark.skipif(
    sys.version_info < (3, 12),
    reason="PEP 695 `type X = ...` fixtures only parse on Python 3.12+",
)
def test_pep695_type_alias_protects_route(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from typing import Annotated\n"
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n"
                "type CurrentUser = Annotated[dict, Depends(lambda: 1)]\n"
                "@router.post('/items')\n"
                "def create(user: CurrentUser):\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_bare_depends_alias_as_default_protects_route(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n"
                "require_user = Depends(lambda: 1)\n"
                "@router.delete('/items/{i}')\n"
                "def remove(i: int, user=require_user):\n"
                "    return i\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_password_recovery_routes_are_exempt_from_f001(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n"
                "@router.post('/password-recovery/{email}')\n"
                "def recover_password(email: str):\n"
                "    return {}\n"
            )
        }
    )
    assert not any(f.rule_id == "TLX-F001" for f in fastapi_rules.run(ctx))


def test_login_routes_are_exempt_from_f001(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n"
                "@router.post('/login')\n"
                "def login(email: str, password: str):\n"
                "    return {}\n"
                "@router.post('/webhooks/stripe')\n"
                "def stripe_hook():\n"
                "    return {}\n"
            )
        }
    )
    assert rules_fired(fastapi_rules.run(ctx)) == {"TLX-F008"}  # only rate limiting


def test_explicit_cors_origins_not_flagged(make_ctx):
    ctx = make_ctx(
        {
            "main.py": (
                "from fastapi import FastAPI\n"
                "from fastapi.middleware.cors import CORSMiddleware\n"
                "app = FastAPI(docs_url=None)\n"
                "app.add_middleware(CORSMiddleware, allow_origins=['https://a.com'], allow_credentials=True)\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_wildcard_via_module_variable_is_caught(make_ctx):
    ctx = make_ctx(
        {
            "main.py": (
                "from fastapi import FastAPI\n"
                "from fastapi.middleware.cors import CORSMiddleware\n"
                "origins = ['*']\n"
                "app = FastAPI(docs_url=None)\n"
                "app.add_middleware(CORSMiddleware, allow_origins=origins)\n"
            )
        }
    )
    assert rules_fired(fastapi_rules.run(ctx)) == {"TLX-F004"}


def test_docs_rule_needs_production_signals(make_ctx):
    files = {
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    }
    ctx = make_ctx(files)
    assert fastapi_rules.run(ctx) == []  # no Dockerfile/Procfile → no F006

    ctx = make_ctx({"Dockerfile": "FROM python:3.12\nUSER app\n"})
    # same tmp_path now also has main.py from the first call
    findings = fastapi_rules.run(ctx)
    assert rules_fired(findings) == {"TLX-F006"}


def test_custom_rate_limit_dependency_silences_f008(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter, Depends\n"
                "from app.security import rate_limit\n"
                "router = APIRouter()\n"
                "@router.post('/login', dependencies=[Depends(rate_limit(30, 60))])\n"
                "def login(email: str, password: str):\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_limiter_decorator_silences_f008(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n"
                "@router.post('/login')\n"
                "@limiter.limit('5/minute')\n"
                "def login(email: str, password: str):\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_rate_limit_import_silences_f008(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter\n"
                "from slowapi import Limiter\n"
                "router = APIRouter()\n"
                "@router.post('/login')\n"
                "def login():\n"
                "    return {}\n"
            )
        }
    )
    assert fastapi_rules.run(ctx) == []


def test_non_fastapi_project_is_silent(make_ctx):
    ctx = make_ctx({"script.py": "print('hello')\n", "Dockerfile": "FROM python\n"})
    assert fastapi_rules.run(ctx) == []


def test_inherited_sensitive_field_is_detected(make_ctx):
    ctx = make_ctx(
        {
            "api.py": (
                "from fastapi import APIRouter\n"
                "from pydantic import BaseModel\n"
                "router = APIRouter()\n"
                "class UserBase(BaseModel):\n"
                "    email: str\n"
                "    hashed_password: str\n"
                "class UserOut(UserBase):\n"
                "    id: int\n"
                "@router.get('/me', response_model=UserOut)\n"
                "def me():\n"
                "    return {}\n"
            )
        }
    )
    findings = fastapi_rules.run(ctx)
    assert rules_fired(findings) == {"TLX-F007"}
    assert "hashed_password" in findings[0].message
