#!/usr/bin/env python3
"""Generate real key pairs as PEM files: RSA, Ed25519, X25519.

This is the production counterpart to the `rsa` playground — proper key
sizes, standard PEM (PKCS8 private / SubjectPublicKeyInfo public), private
files written with mode 600.

Private PEMs are UNENCRYPTED on disk. Keep them out of repos and backups,
or encrypt the storage yourself. (Passphrase-encrypted PKCS8 is a possible
future flag.)

Requires the `cryptography` package (pip install "gravyard[crypto]").

Examples:
    gravyard crypto keypair --algo ed25519 --out-prefix signing
    gravyard crypto keypair --algo rsa4096 --out-prefix tls-sim
    gravyard crypto keypair --algo x25519 --out-prefix kx --show-pub
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, render_record, warn

ALGOS = {
    "rsa2048": ("RSA 2048-bit", 2048),
    "rsa3072": ("RSA 3072-bit", 3072),
    "rsa4096": ("RSA 4096-bit", 4096),
    "ed25519": ("Ed25519 signing", None),
    "x25519": ("X25519 key exchange", None),
}


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ModuleNotFoundError:
        fail("this tool needs the 'cryptography' package: pip install 'gravyard[crypto]'")


def _generate(algo: str):
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519

    if algo.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=ALGOS[algo][1])
    if algo == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return x25519.X25519PrivateKey.generate()


def _public_info(pub) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    if isinstance(pub, _rsa.RSAPublicKey):
        return {"key_size": pub.key_size, "public_exponent": pub.public_numbers().e}
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"public_key_hex": raw.hex()}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--algo", choices=tuple(ALGOS), default="ed25519",
                        help=f"key type (default: ed25519; {', '.join(f'{k}={v[0]}' for k, v in ALGOS.items())})")
    parser.add_argument("--out-prefix", required=True, type=Path,
                        help="write PREFIX.priv.pem + PREFIX.pub.pem")
    parser.add_argument("--force", action="store_true", help="overwrite existing key files")
    parser.add_argument("--show-pub", action="store_true", help="print the raw/derived public key info")


def run(args: argparse.Namespace) -> int:
    _require_cryptography()
    fmt = "json" if args.json else "table"
    for suffix in (".priv.pem", ".pub.pem"):
        if Path(str(args.out_prefix) + suffix).exists() and not args.force:
            fail(f"{args.out_prefix}{suffix} exists (use --force)")

    if args.algo in ("rsa3072", "rsa4096"):
        warn(f"generating an {args.algo[3:]}-bit RSA key — this can take a few seconds")

    from cryptography.hazmat.primitives import serialization

    private = _generate(args.algo)
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = private.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = Path(str(args.out_prefix) + ".priv.pem")
    pub_path = Path(str(args.out_prefix) + ".pub.pem")
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(pub_pem)

    record = {
        "algorithm": args.algo,
        "description": ALGOS[args.algo][0],
        "private_file": str(priv_path) + " (mode 600)",
        "public_file": str(pub_path),
        "warning": "unencrypted private key on disk — keep it out of repos and backups",
    }
    if args.show_pub:
        record.update(_public_info(pub))
    print(render_record(record, fmt))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "keypair",
        parents=[common_flags()],
        help="generate real key pairs as PEM files (RSA / Ed25519 / X25519)",
        description="Generate production key pairs (PEM, PKCS8) with proper sizes and file modes.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="keypair",
        description="Generate production key pairs (PEM, PKCS8) with proper sizes and file modes.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
