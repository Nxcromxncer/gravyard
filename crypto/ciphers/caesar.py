#!/usr/bin/env python3
"""Caesar cipher — encode, decode, and brute-force with English scoring.

Every letter is rotated by a fixed shift; case and non-letters are kept.
Breakable by eye (25 possibilities) or exactly by frequency analysis.

Examples:
    gravyard crypto caesar encode --shift 3 --text "Hello, World!"
    gravyard crypto caesar decode --shift 3 --text "Khoor, Zruog!"
    gravyard crypto caesar brute --text "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"

Note: on very short texts (<20 letters) the chi-squared ranking is noisy —
scan the previews; on sentence-length text the top hit is the answer.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.input import resolve_text
from core.output import fail, render_rows, success
from crypto.ciphers.frequency import english_score, letters_only


def shift_text(text: str, k: int) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", nargs="?", choices=("encode", "decode", "brute"), default="encode")
    parser.add_argument("--shift", type=int, default=3, help="rotation amount (default 3)")
    parser.add_argument("--text", help="text to process ('-' reads stdin)")
    parser.add_argument("--file", type=Path, help="read text from a file")


def run(args: argparse.Namespace) -> int:
    message = resolve_text(args)
    if not letters_only(message) and args.action != "encode":
        fail("no a-z letters in the input — nothing to do")

    if args.action == "encode":
        result = shift_text(message, args.shift)
    elif args.action == "decode":
        result = shift_text(message, -args.shift)
    else:
        rows = []
        for k in range(1, 26):
            candidate = shift_text(message, -k)
            rows.append(
                {"shift": k, "score": round(english_score(candidate), 2), "preview": candidate[:64]}
            )
        rows.sort(key=lambda r: r["score"], reverse=True)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(render_rows(rows, columns=["shift", "score", "preview"]))
            success(f"most likely shift: {rows[0]['shift']} -> {rows[0]['preview'][:48]!r}")
        return 0

    if args.json:
        print(json.dumps({"action": args.action, "shift": args.shift, "output": result}, indent=2))
    else:
        print(result)
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "caesar",
        parents=[common_flags()],
        help="Caesar cipher: encode, decode, brute-force with scoring",
        description="Caesar cipher — encode, decode, and brute-force with English scoring.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caesar",
        description="Caesar cipher — encode, decode, and brute-force with English scoring.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
