"""Shared input resolution.

Text tools accept ``--text``, ``--file`` or piped stdin, in that priority.
``--text -`` reads stdin explicitly.
"""

from __future__ import annotations

import sys
from pathlib import Path

from core.output import fail


def resolve_text(args, *, required: bool = True) -> str | None:
    """Return the message from --text / --file / stdin as str (utf-8)."""
    text = getattr(args, "text", None)
    file = getattr(args, "file", None)
    if text is not None and file is not None:
        fail("choose either --text or --file, not both")
    if text is not None:
        return sys.stdin.read() if text == "-" else text
    if file is not None:
        try:
            return Path(file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            fail(f"cannot read {file}: {exc}")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    if required:
        fail("no input given: use --text, --file, or pipe data on stdin")
    return None
