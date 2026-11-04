#!/usr/bin/env python3
"""Decode and inspect JWTs — structure, claims, and red flags.

Inspection only: nothing is verified here (that needs the key — see
`gravyard crypto ed25519` or your app). The tool surfaces what matters when
you are reviewing a token: algorithm, expiry claims, and the classic
weaknesses (alg=none, symmetric vs asymmetric, missing expiry).

Examples:
    gravyard crypto jwt-inspect <token>
    gravyard crypto jwt-inspect <token> --json
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, render_record, warn

SYMMETRIC_ALGS = {"HS256", "HS384", "HS512"}
ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
KNOWN_ALGS = SYMMETRIC_ALGS | ASYMMETRIC_ALGS | {"none"}
CLAIM_ALIASES = {"exp": "expires", "iat": "issued-at", "nbf": "not-before"}


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_token(token: str) -> tuple[dict, dict, bytes, list[str]]:
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        fail("not a JWT: expected three dot-separated base64url segments")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        fail(f"malformed JWT (header/payload not valid base64url JSON): {exc}")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        fail("malformed JWT: header/payload must be JSON objects")
    signature = b64url_decode(parts[2]) if len(parts) == 3 else b""
    return header, payload, signature, parts


def humanize_seconds(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def analyze(header: dict, payload: dict, signature: bytes) -> dict:
    alg = header.get("alg", "<missing>")
    now = int(time.time())
    flags: list[str] = []
    summary: dict = {"alg": alg, "typ": header.get("typ"), "kid": header.get("kid")}

    if alg == "none":
        flags.append("CRITICAL: alg=none — token is unsigned; any app that accepts it trusts anyone")
    elif alg not in KNOWN_ALGS:
        flags.append(f"unknown alg {alg!r}")
    elif alg in SYMMETRIC_ALGS:
        flags.append("symmetric (HMAC) — same secret signs and verifies; vulnerable to "
                     "key-confusion if the app also accepts RSA keys (see jwt-test)")
    if not signature:
        flags.append("no signature present")

    for claim, label in CLAIM_ALIASES.items():
        value = payload.get(claim)
        if value is None:
            continue
        summary[label] = {"unix": value, "utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))}
    if "exp" in payload:
        remaining = payload["exp"] - now
        summary["expires_in"] = humanize_seconds(remaining) if remaining > 0 else "expired"
        if remaining <= 0:
            flags.append(f"token EXPIRED {humanize_seconds(-remaining)} ago")
    else:
        flags.append("no exp claim — token never expires")
    if payload.get("nbf", 0) > now:
        flags.append("not-before in the future — token not valid yet")
    if payload.get("iat", 0) > now + 60:
        flags.append("issued-at is in the future — clock skew or forgery")

    summary["flags"] = flags
    return summary


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("token", help="JWT (header.payload.signature)")


def run(args: argparse.Namespace) -> int:
    header, payload, signature, parts = parse_token(args.token)
    result = analyze(header, payload, signature)
    result["header"] = header
    result["claims"] = payload
    result["signature_hex"] = signature.hex()
    result["signature_bits"] = len(signature) * 8
    result["segments"] = len(parts)
    print(json.dumps(result, indent=2, default=str) if args.json else render_record(result))
    for flag in result["flags"]:
        if flag.startswith("CRITICAL") or "EXPIRED" in flag:
            warn(flag)
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "jwt-inspect",
        parents=[common_flags()],
        help="decode/inspect a JWT: header, claims, expiry, red flags",
        description="Decode and inspect JWTs — structure, claims, and classic weaknesses.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwt-inspect",
        description="Decode and inspect JWTs — structure, claims, and classic weaknesses.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
