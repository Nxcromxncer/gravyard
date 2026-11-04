#!/usr/bin/env python3
"""RSA playground — small-key keygen, textbook encrypt/decrypt, factoring.

This is the math lesson, not a production library. Keys are generated in
pure Python at playground sizes (16-1024 bits) so every component (p, q,
n, e, d) is visible, and `factor` shows how quickly small moduli fall to
Pollard's rho. Textbook RSA (no padding) is deterministic and malleable —
the `encrypt`/`decrypt` actions exist to demonstrate exactly that.

PLAYGROUND ONLY: never use these keys or raw modpow for real security.
Real applications need OAEP/PSS padding and >= 2048-bit keys (see the
`keypair` tool).

Examples:
    gravyard crypto rsa keygen --bits 128
    gravyard crypto rsa encrypt --n 3233 --e 17 --text "hi"
    gravyard crypto rsa decrypt --n 3233 --d 2753 --cipher 855 --as-text
    gravyard crypto rsa factor --n 3233
"""
from __future__ import annotations

import argparse
import json
import math
import secrets
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, render_record, warn

MIN_BITS, MAX_BITS = 16, 1024
_SLOW_BITS = 512
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin — probabilities fine for a playground."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
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


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def rsa_keygen(bits: int) -> dict:
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return {"p": p, "q": q, "n": n, "e": e, "d": pow(e, -1, phi), "phi": phi}


def _pollard_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    while True:
        x = secrets.randbelow(n - 3) + 2 if n > 4 else 2
        y, c = x, (secrets.randbelow(n - 2) + 1 if n > 3 else 1)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factor(n: int) -> tuple[int, int]:
    """Split a product of two primes (trial division, then Pollard's rho)."""
    for p in _SMALL_PRIMES:
        if n % p == 0 and _is_probable_prime(n // p):
            return p, n // p
    d = _pollard_rho(n)
    return d, n // d


def _message_int(args, n: int) -> int:
    if args.number is not None:
        if not 0 <= args.number < n:
            fail(f"--number must satisfy 0 <= m < n ({n})")
        return args.number
    if args.text is not None:
        m = int.from_bytes(args.text.encode("utf-8"), "big")
        if m >= n:
            fail(f"text encodes to an integer >= n — use a bigger --bits or shorter text")
        return m
    fail("provide --number INT or --text STR")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=("keygen", "encrypt", "decrypt", "factor"))
    parser.add_argument("--bits", type=int, default=128, help=f"keygen modulus size ({MIN_BITS}-{MAX_BITS}, default 128)")
    parser.add_argument("--n", type=int, help="modulus (encrypt/decrypt/factor)")
    parser.add_argument("--e", type=int, default=65537, help="public exponent (encrypt)")
    parser.add_argument("--d", type=int, help="private exponent (decrypt)")
    parser.add_argument("--number", type=int, help="plaintext as an integer (0 <= m < n)")
    parser.add_argument("--text", help="plaintext as text (utf-8, must fit under n)")
    parser.add_argument("--cipher", type=int, help="ciphertext integer (decrypt)")
    parser.add_argument("--as-text", action="store_true", help="decrypt: also decode the result as utf-8 text")


def run(args: argparse.Namespace) -> int:
    fmt = "json" if args.json else "table"

    if args.action == "keygen":
        if not MIN_BITS <= args.bits <= MAX_BITS:
            fail(f"--bits must be {MIN_BITS}-{MAX_BITS} (playground sizes; real RSA is >= 2048)")
        if args.bits >= _SLOW_BITS:
            warn(f"generating a {args.bits}-bit playground key in pure Python may take a while")
        keys = rsa_keygen(args.bits)
        record = {"bits": args.bits, **{k: str(v) for k, v in keys.items()},
                  "warning": "PLAYGROUND ONLY — textbook RSA, no padding; never use for real security"}
        print(render_record(record, fmt))
        return 0

    if args.action == "encrypt":
        if args.n is None:
            fail("encrypt needs --n and (by default) --e")
        m = _message_int(args, args.n)
        c = pow(m, args.e, args.n)
        record = {"ciphertext": str(c), "n": str(args.n), "e": str(args.e),
                  "warning": "textbook RSA: deterministic and malleable — never use without padding (OAEP)"}
        print(render_record(record, fmt))
        return 0

    if args.action == "decrypt":
        if args.n is None or args.d is None or args.cipher is None:
            fail("decrypt needs --n, --d and --cipher")
        m = pow(args.cipher, args.d, args.n)
        record = {"plaintext_int": str(m), "n": str(args.n)}
        if args.as_text:
            raw = m.to_bytes(max(1, (m.bit_length() + 7) // 8), "big")
            record["plaintext_text"] = raw.decode("utf-8", errors="replace")
        print(render_record(record, fmt))
        return 0

    # factor
    if args.n is None or args.n < 4:
        fail("factor needs --n >= 4 (a product of two primes)")
    p, q = factor(args.n)
    if p * q != args.n:
        fail(f"failed to split {args.n} — is it a semiprime?")
    print(render_record({
        "n": str(args.n), "p": str(p), "q": str(q),
        "lesson": "small moduli fall to Pollard's rho in milliseconds; "
                  "2048-bit n would take longer than the age of the universe",
    }, fmt))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "rsa",
        parents=[common_flags()],
        help="RSA playground: small keys, textbook encrypt/decrypt, factoring",
        description="RSA playground — the math with nothing hidden (playground only, no padding).",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rsa",
        description="RSA playground — the math with nothing hidden (playground only, no padding).",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
