#!/usr/bin/env python3
"""Diffie-Hellman playground — key exchange, and breaking it.

Two lessons in one tool:

1. `demo` walks the full exchange between Alice and Bob over a small safe
   prime, showing every number that crosses the wire and the shared secret
   both sides derive without ever transmitting it.
2. `attack` recovers the private key from a public key with baby-step
   giant-step — O(sqrt(p)) — to show *why* toy parameters are useless and
   real deployments use >= 2048-bit primes.

PLAYGROUND ONLY: small parameters exist so you can watch the math happen.

Examples:
    gravyard crypto dh demo --bits 32 --seed 7
    gravyard crypto dh pub --p 23 --g 5 --priv 6
    gravyard crypto dh secret --p 23 --priv 15 --peer-pub 8
    gravyard crypto dh attack --p 2147483647 --g 2 --pub 123456789
"""
from __future__ import annotations

import argparse
import json
import math
import random
import secrets
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, note, render_record, success

DEMO_MAX_BITS = 256          # safe-prime generation in pure python gets slow past this
ATTACK_MAX_BITS = 40         # BSGS needs ~2^(bits/2) memory
DEMO_DEFAULT_BITS = 32       # small on purpose — attackable


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _safe_prime(bits: int, rng: random.Random) -> int:
    """p = 2q+1 with q prime — then any g in [3, p-2] has large order."""
    while True:
        q = _gen_prime(bits - 1, rng)
        p = 2 * q + 1
        if _is_probable_prime(p):
            return p


def _validate_pg(p: int, g: int) -> None:
    if p < 5 or not _is_probable_prime(p):
        fail("--p must be a prime >= 5")
    if not 2 <= g <= p - 2:
        fail(f"--g must be in [2, p-1] = [2, {p - 1}]")


def _discrete_log(g: int, y: int, p: int) -> int | None:
    """Baby-step giant-step: find x with g^x = y (mod p), 0 <= x < p-1."""
    m = math.isqrt(p - 1) + 1
    table: dict[int, int] = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    g_inv_m = pow(pow(g, m, p), -1, p)
    gamma = y % p
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * g_inv_m % p
    return None


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=("demo", "pub", "secret", "attack"))
    parser.add_argument("--bits", type=int, default=DEMO_DEFAULT_BITS,
                        help=f"demo: safe-prime size (default {DEMO_DEFAULT_BITS}, max {DEMO_MAX_BITS})")
    parser.add_argument("--seed", type=int, help="demo: seed the rng for a reproducible run")
    parser.add_argument("--p", type=int, help="prime modulus")
    parser.add_argument("--g", type=int, default=2, help="generator (default 2)")
    parser.add_argument("--priv", type=int, help="your private exponent x")
    parser.add_argument("--peer-pub", type=int, help="the peer's public key Y = g^y mod p")
    parser.add_argument("--pub", type=int, help="public key to attack (attack)")


def run(args: argparse.Namespace) -> int:
    fmt = "json" if args.json else "table"

    if args.action == "demo":
        if not 16 <= args.bits <= DEMO_MAX_BITS:
            fail(f"--bits must be 16-{DEMO_MAX_BITS} for the demo (safe-prime generation)")
        rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
        p = _safe_prime(args.bits, rng)
        g = rng.randrange(3, p - 2)
        a = rng.randrange(2, p - 2)
        b = rng.randrange(2, p - 2)
        big_a, big_b = pow(g, a, p), pow(g, b, p)
        shared_a, shared_b = pow(big_b, a, p), pow(big_a, b, p)
        record = {
            "p": str(p), "g": str(g),
            "alice_private": str(a), "alice_public": str(big_a),
            "bob_private": str(b), "bob_public": str(big_b),
            "shared_secret": str(shared_a),
            "both_sides_agree": shared_a == shared_b,
            "attacker_sees": f"p, g, {big_a}, {big_b} — not a or b, not the secret",
        }
        print(render_record(record, fmt))
        if args.bits <= ATTACK_MAX_BITS:
            note(f"p is only {args.bits} bits — try: dh attack --p {p} --g {g} --pub {big_a}")
        return 0

    if args.action == "pub":
        if args.p is None:
            fail("pub needs --p (and --g; --priv omitted = random)")
        _validate_pg(args.p, args.g)
        x = args.priv if args.priv is not None else 2 + secrets.randbelow(args.p - 4)
        if not 2 <= x <= args.p - 2:
            fail(f"--priv must be in [2, p-2]")
        print(render_record({
            "public_key": str(pow(args.g, x, args.p)), "private_key": str(x),
            "p": str(args.p), "g": str(args.g),
        }, fmt))
        return 0

    if args.action == "secret":
        if args.p is None or args.priv is None or args.peer_pub is None:
            fail("secret needs --p, --priv and --peer-pub")
        _validate_pg(args.p, args.g)
        print(render_record({"shared_secret": str(pow(args.peer_pub, args.priv, args.p)),
                             "p": str(args.p)}, fmt))
        return 0

    # attack
    if args.p is None or args.pub is None:
        fail("attack needs --p, --g and --pub")
    _validate_pg(args.p, args.g)
    if args.p.bit_length() > ATTACK_MAX_BITS:
        fail(
            f"--p has {args.p.bit_length()} bits; the demo attack caps at {ATTACK_MAX_BITS} "
            f"(BSGS needs ~2^(bits/2) memory). Real deployments use >= 2048-bit primes — "
            "that gap is the entire security argument."
        )
    started = time.monotonic()
    x = _discrete_log(args.g, args.pub, args.p)
    elapsed = time.monotonic() - started
    if x is None:
        fail(f"no x in [0, p-2) with g^x = {args.pub} (mod p) — is --pub a power of g?")
    steps = math.isqrt(args.p - 1) + 1
    elapsed = round(time.monotonic() - started, 2)
    success(f"recovered private key x = {x} in {elapsed:.2f}s ({steps:,} BSGS steps)")
    check = pow(args.g, x, args.p) == args.pub % args.p
    print(render_record({
        "private_key": str(x), "public_key_target": str(args.pub),
        "verification": "g^x mod p matches" if check else "MISMATCH",
        "bsgs_steps": f"{steps:,}", "elapsed_s": elapsed,
        "lesson": "security scales with ~sqrt(p): 40 bits falls in seconds, "
                  "2048 bits would take ~10^292 steps",
    }, fmt))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "dh",
        parents=[common_flags()],
        help="Diffie-Hellman playground: exchange demo + discrete-log attack",
        description="Diffie-Hellman playground — watch the exchange, then break toy parameters.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dh",
        description="Diffie-Hellman playground — watch the exchange, then break toy parameters.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
