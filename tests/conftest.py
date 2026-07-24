"""Shared fixtures: ScanContexts for the fixture apps and a tmp-project factory."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

from torlyx import discovery
from torlyx.scanner import ScanContext

FIXTURES = Path(__file__).parent / "fixtures"
VULN_APP = FIXTURES / "vulnerable_app"
CLEAN_APP = FIXTURES / "clean_app"

#: Git state the vulnerable app *would* have (the fixture lives inside the
#: torlyx repo, so it has no .git of its own — tests inject it).
VULN_GIT_TRACKED: set[str] = {
    ".env",
    "Dockerfile",
    "requirements.txt",
    "certs/server.pem",
    "dist/bundle.js.map",
    "app/main.py",
    "app/config.py",
    "app/db.py",
    "app/utils.py",
    "app/internal_api.py",
    "app/routes/users.py",
    "app/routes/admin.py",
    "app/routes/auth.py",
}

CLEAN_GIT_TRACKED: set[str] = {
    "Dockerfile",
    "requirements.txt",
    "app/main.py",
    "app/config.py",
    "app/deps.py",
}


def _context_for(root: Path, git_tracked: set[str]) -> ScanContext:
    return ScanContext(
        root=root,
        files=discovery.discover_files(root),
        git_tracked=git_tracked,
    )


@pytest.fixture(scope="session")
def vuln_ctx() -> ScanContext:
    """ScanContext over the intentionally vulnerable fixture app."""
    return _context_for(VULN_APP, VULN_GIT_TRACKED)


@pytest.fixture(scope="session")
def clean_ctx() -> ScanContext:
    """ScanContext over the well-behaved fixture app."""
    return _context_for(CLEAN_APP, CLEAN_GIT_TRACKED)


@pytest.fixture()
def make_ctx(tmp_path: Path) -> Callable[..., ScanContext]:
    """Factory: write a dict of {relative path: content} and get a ScanContext."""

    def _make(
        files: dict[str, str], git_tracked: set[str] | None = None
    ) -> ScanContext:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return ScanContext(
            root=tmp_path,
            files=discovery.discover_files(tmp_path),
            git_tracked=git_tracked or set(),
        )

    return _make


@pytest.fixture(scope="session")
def line_of() -> Callable[[Path, str], int]:
    """Return the 1-based line number of the first line containing *needle*."""

    def _line_of(path: Path, needle: str) -> int:
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if needle in line:
                return lineno
        raise AssertionError(f"{needle!r} not found in {path}")

    return _line_of
