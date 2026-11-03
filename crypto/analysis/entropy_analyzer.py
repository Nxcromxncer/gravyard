#!/usr/bin/env python3
"""Entropy analyzer: how random is this byte stream?

Computes Shannon entropy per byte (0-8 bits/byte), byte-value diversity,
printable ratio and a chi-squared uniformity test, then offers a heuristic
verdict. High entropy means "indistinguishable from random" — it is what
encrypted and compressed data look like, but it is NOT proof of encryption.

Useful for triage: is this "image.jpg" actually an encrypted blob? Is this
key file really random? Is this firmware section compressed?

Examples:
    gravyard crypto entropy --file backup.bin
    head -c 1M /dev/urandom | gravyard crypto entropy
    gravyard crypto entropy --file image.png --sample 65536
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, render_record

MAX_READ = 64 * 1024 * 1024


def shannon_entropy(counts: dict[int, int], total: int) -> float:
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def analyze(data: bytes) -> dict:
    total = len(data)
    counts = Counter(data)
    entropy = shannon_entropy(counts, total)
    printable = sum(1 for b in data if 32 <= b <= 126) / total * 100 if total else 0.0
    # chi-squared against a uniform distribution (255 degrees of freedom);
    # uniform random data scores ≈ 255, structured data is far away
    expected = total / 256
    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256)) if expected else float("inf")
    top = counts.most_common(3)

    if total < 256:
        verdict = "too small to judge (< 256 bytes)"
    else:
        # expected entropy of a truly uniform sample of this size: a finite
        # sample of n bytes tops out at 8 - 255/(2n·ln2) bits/byte
        expected_max = 8.0 - 255.0 / (2.0 * total * math.log(2))
        if entropy >= expected_max - 0.02:
            verdict = "indistinguishable from random — encrypted, compressed, or genuine noise"
        elif entropy >= 7.5:
            verdict = "very high entropy — likely compressed or packed"
        elif entropy >= 6.0:
            verdict = "mixed — binary with structure (headers, code, images)"
        else:
            verdict = "low entropy — plain text, padding, or a sparse format"

    return {
        "bytes": total,
        "entropy_bits_per_byte": round(entropy, 4),
        "max_possible": 8.0,
        "distinct_byte_values": len(counts),
        "printable_ascii_pct": round(printable, 1),
        "chi_square_vs_uniform": round(chi2, 1) if math.isfinite(chi2) else None,
        "chi_square_df": 255,
        "top_bytes": [{"hex": f"0x{b:02x}", "count": c, "pct": round(c / total * 100, 2)} for b, c in top],
        "verdict": verdict,
    }


def _read(args) -> bytes:
    if args.text is not None:
        return args.text.encode("utf-8")
    if args.file:
        if not args.file.is_file():
            fail(f"no such file: {args.file}")
        data = args.file.read_bytes()
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        fail("no input: use --file, --text, or pipe data on stdin")
    if args.sample and len(data) > args.sample:
        data = data[: args.sample]
    if len(data) > MAX_READ:
        data = data[:MAX_READ]
    return data


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file", type=Path, help="file to analyze")
    parser.add_argument("--text", help="short text/string to analyze")
    parser.add_argument("--sample", type=int, default=0, help="analyze only the first N bytes")


def run(args: argparse.Namespace) -> int:
    data = _read(args)
    if not data:
        fail("no bytes to analyze")
    record = analyze(data)
    if args.file:
        record["file"] = str(args.file)
    print(json.dumps(record, indent=2) if args.json else render_record(record))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "entropy",
        parents=[common_flags()],
        help="Shannon entropy / randomness analysis of byte streams",
        description="Entropy and uniformity analysis of files or byte streams (triage: random vs structured).",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="entropy",
        description="Entropy and uniformity analysis of files or byte streams (triage: random vs structured).",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
