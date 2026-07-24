"""Fallback entry point: ``python -m torlyx`` works even when the
Scripts directory holding ``torlyx.exe`` is not on PATH."""

from torlyx.cli import app

if __name__ == "__main__":
    app()
