#!/usr/bin/env python3
"""Benchmark hashing and AEAD encryption throughput on this machine.

Answers "how fast is SHA-256 vs BLAKE2 vs AES-GCM *here*", which is the
input to real engineering decisions (KDF cost tuning, checksum strategy,
cipher choice). Numbers are throughput on one core with an in-memory
buffer — not disk I/O.

MD5 and SHA-1 are included as reference points: they are cryptographically
broken and their only remaining job is being fast.

Examples:
    gravyard crypto cryptobench
    gravyard crypto cryptobench --mb 64 --iters 5 --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, note, render_rows, warn

HASH_ALGOS = (
    ("md5", "broken — comparison only"),
    ("sha1", "broken — comparison only"),
    ("sha256", "workhorse"),
    ("sha512", "fast on 64-bit"),
    ("sha3_256", "SHA-3 standard"),
    ("blake2s", "fast, 256-bit"),
    ("blake2b", "fastest general hash here"),
)
AEAD_CIPHERS = ("aes256gcm", "chacha20poly1305")
MB = 1024 * 1024


def _bench_hash(name: str, buffer: bytes, iters: int) -> dict:
    t0 = time.monotonic()
    h = hashlib.new(name)
    for _ in range(iters):
        h.update(buffer)
    h.digest()
    dt = time.monotonic() - t0
    return _row(name, buffer, iters, dt)


def _bench_aead(name: str, buffer: bytes, iters: int) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aead = AESGCM(key) if name == "aes256gcm" else ChaCha20Poly1305(key)
    t0 = time.monotonic()
    for _ in range(iters):
        aead.encrypt(nonce, buffer, b"gravyard-bench")
    dt = time.monotonic() - t0
    return _row(name, buffer, iters, dt, note="authenticated encryption")


def _row(name: str, buffer: bytes, iters: int, dt: float, note: str = "") -> dict:
    mbs = len(buffer) * iters / MB / max(dt, 1e-9)
    return {"algorithm": name, "mb_per_s": round(mbs, 1), "seconds": round(dt, 3), "note": note}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mb", type=int, default=16, help="buffer size in MiB (default 16)")
    parser.add_argument("--iters", type=int, default=3, help="iterations per algorithm (default 3)")
    parser.add_argument("--skip-aead", action="store_true", help="skip the AEAD benchmarks")


def run(args: argparse.Namespace) -> int:
    if args.mb < 1 or args.iters < 1:
        fail("--mb and --iters must be >= 1")
    buffer = secrets.token_bytes(args.mb * MB)

    rows = [_bench_hash(name, buffer, args.iters) for name, _ in HASH_ALGOS]
    notes = dict(HASH_ALGOS)
    for row in rows:
        row["note"] = notes[row["algorithm"]]

    if not args.skip_aead:
        try:
            aead_buffer = secrets.token_bytes(min(args.mb, 8) * MB)
            for name in AEAD_CIPHERS:
                rows.append(_bench_aead(name, aead_buffer, args.iters))
        except ModuleNotFoundError:
            warn("cryptography not installed — skipping AEAD benchmarks")

    rows.sort(key=lambda r: r["mb_per_s"], reverse=True)
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(render_rows(rows, columns=["algorithm", "mb_per_s", "seconds", "note"]))
        note(f"single core, in-memory {args.mb} MiB buffer x {args.iters} — "
             "throughput only; disk and parallelism not included")
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "cryptobench",
        parents=[common_flags()],
        help="benchmark hash/AEAD throughput on this machine",
        description="Measure hashing and authenticated-encryption throughput (single core, in memory).",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptobench",
        description="Measure hashing and authenticated-encryption throughput (single core, in memory).",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
