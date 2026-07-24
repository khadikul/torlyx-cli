"""File discovery: walk the project tree and detect git-tracked files.

Keeps the scan fast by skipping dependency/build/VCS directories and
binary or oversized files.
"""

from __future__ import annotations

import subprocess
from fnmatch import fnmatch
from pathlib import Path

#: Directory names never worth descending into.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env.d",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        "site-packages",
        ".idea",
        ".vscode",
        ".next",
        ".turbo",
        ".cache",
    }
)

#: File extensions Torlyx reads (plus the named files below).
TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".env",
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".txt",
        ".sh",
        ".pem",
        ".key",
        ".crt",
        ".sql",
        ".properties",
    }
)

#: Extensionless / specially-named files always worth reading.
SPECIAL_NAMES: frozenset[str] = frozenset(
    {"dockerfile", "procfile", "makefile", ".gitignore", ".dockerignore"}
)

#: Skip anything bigger than this — real source files are small.
MAX_FILE_BYTES = 1_000_000


def _wanted(path: Path) -> bool:
    """Return True if this file should be read by the scanner."""
    name = path.name.lower()
    if name in SPECIAL_NAMES or name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def is_excluded(rel_posix: str, patterns: list[str]) -> bool:
    """Match a relative posix path against user-supplied glob excludes."""
    parts = rel_posix.split("/")
    for pat in patterns:
        pat = pat.replace("\\", "/").rstrip("/")
        if (
            fnmatch(rel_posix, pat)
            or fnmatch(rel_posix, pat + "/*")
            or any(fnmatch(part, pat) for part in parts)
        ):
            return True
    return False


def discover_files(root: Path, excludes: list[str] | None = None) -> list[Path]:
    """Walk *root* and return every scannable file, sorted for determinism.

    Skips VCS/dependency/cache directories, binary-looking files, and
    anything matching an ``--exclude`` glob.
    """
    excludes = excludes or []
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            rel = entry.relative_to(root).as_posix()
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.name.endswith(".egg-info"):
                    continue
                if excludes and is_excluded(rel, excludes):
                    continue
                stack.append(entry)
            elif entry.is_file():
                if not _wanted(entry):
                    continue
                if excludes and is_excluded(rel, excludes):
                    continue
                try:
                    if entry.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                found.append(entry)
    return sorted(found)


def git_tracked_files(root: Path) -> set[str]:
    """Return the set of git-tracked paths (posix, relative to *root*).

    Returns an empty set when *root* is not inside a git repository or
    git is not installed — rules that depend on git state simply skip.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if proc.returncode != 0:
        return set()
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}
