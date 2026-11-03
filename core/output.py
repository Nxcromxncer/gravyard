"""Shared output formatting for gravyard tools.

Output policy (applies to every tool, so the toolkit feels like one program):

- stdout carries *results only*: tables, records, or plain transform output
  that can be piped into another command
- diagnostics ([+]/[-]/[!] status lines, logs) go to stderr
- ``--json`` switches stdout to machine-readable JSON
- colour is used only on a tty and is disabled by the ``NO_COLOR`` env var
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, NoReturn, Sequence

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
}


def _color_enabled(stream=sys.stderr) -> bool:
    return "NO_COLOR" not in os.environ and stream.isatty()


def style(text: Any, *codes: str) -> str:
    """Wrap text in ANSI codes when the destination supports colour."""
    text = str(text)
    if not codes or not _color_enabled():
        return text
    prefix = "".join(_ANSI[c] for c in codes if c in _ANSI)
    return f"{prefix}{text}{_ANSI['reset']}"


def note(text: str) -> None:
    """Dim informational line (stderr)."""
    print(style(text, "dim"), file=sys.stderr)


def success(text: str) -> None:
    print(style(f"[+] {text}", "green"), file=sys.stderr)


def warn(text: str) -> None:
    print(style(f"[!] {text}", "yellow"), file=sys.stderr)


def failure(text: str) -> None:
    print(style(f"[-] {text}", "red"), file=sys.stderr)


def fail(message: str, code: int = 2) -> NoReturn:
    """Print an error and exit — the standard way gravyard tools abort."""
    failure(message)
    raise SystemExit(code)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    return str(value)


def render_record(record: dict, fmt: str = "table") -> str:
    """Render a single flat dict as aligned ``key: value`` lines or JSON."""
    if fmt == "json":
        return json.dumps(record, indent=2, default=str)
    width = max((len(str(k)) for k in record), default=0)
    return "\n".join(f"{str(k).ljust(width)}  {_cell(v)}" for k, v in record.items())


def render_rows(
    rows: Sequence[dict], columns: Sequence[str] | None = None, fmt: str = "table"
) -> str:
    """Render a list of dicts as an aligned table or a JSON array.

    Column order defaults to first-appearance across the rows; missing
    values render as empty cells.
    """
    if fmt == "json":
        return json.dumps(list(rows), indent=2, default=str)
    rows = list(rows)
    if not rows:
        return "(no results)"
    if columns is None:
        columns = []
        seen: set = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
    columns = list(columns)
    body = [[_cell(row.get(col)) for col in columns] for row in rows]
    widths = [max(len(col), *(len(r[i]) for r in body)) for i, col in enumerate(columns)]
    header = "  ".join(col.ljust(widths[i]) for i, col in enumerate(columns))
    divider = "  ".join("-" * widths[i] for i in range(len(columns)))
    lines = [header, divider]
    lines += ["  ".join(r[i].ljust(widths[i]) for i in range(len(columns))) for r in body]
    return "\n".join(lines)
