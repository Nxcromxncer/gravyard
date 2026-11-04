#!/usr/bin/env python3
"""Modern signatures (Ed25519) and X25519 key exchange — the real thing.

Unlike the rsa/dh playgrounds, this tool uses the production `cryptography`
library: Ed25519 for signing (deterministic, fast, misuse-resistant) and
X25519 for Diffie-Hellman (what TLS 1.3 actually negotiates).

Requires the `cryptography` package (pip install "gravyard[crypto]").

Examples:
    gravyard crypto ed25519 keygen --out-prefix mykey
    gravyard crypto ed25519 sign --key mykey.priv.pem --text "release v1.2"
    gravyard crypto ed25519 verify --pub mykey.pub.pem \\
        --sig <hex> --text "release v1.2"
    gravyard crypto ed25519 x25519
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, failure, render_record, success, warn
from crypto.hashing.hash_generator import resolve_source

SIG_LEN = 64


def _require_cryptography() -> None:
    try:
        import cryptography  # noqa: F401
    except ModuleNotFoundError:
        fail("this tool needs the 'cryptography' package: pip install 'gravyard[crypto]'")


def _load_private(path: Path):
    from cryptography.hazmat.primitives import serialization

    try:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError):
        fail(f"{path} is not a readable private key PEM")


def _load_public(path: Path):
    from cryptography.hazmat.primitives import serialization

    try:
        return serialization.load_pem_public_key(path.read_bytes())
    except (ValueError, TypeError):
        fail(f"{path} is not a readable public key PEM")


def _pub_hex(pub) -> str:
    from cryptography.hazmat.primitives import serialization

    return pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=("keygen", "sign", "verify", "x25519"))
    parser.add_argument("--out-prefix", type=Path, help="keygen: write PREFIX.priv.pem + PREFIX.pub.pem")
    parser.add_argument("--force", action="store_true", help="keygen: overwrite existing key files")
    parser.add_argument("--key", type=Path, help="sign: private key PEM")
    parser.add_argument("--pub", type=Path, help="verify: public key PEM")
    parser.add_argument("--sig", help="verify: signature as hex")
    parser.add_argument("--text", help="message to sign/verify ('-' reads stdin)")
    parser.add_argument("--file", type=Path, help="message file (signed byte for byte)")
    parser.add_argument("--show-private", action="store_true",
                        help="keygen without --out-prefix: print the raw private key hex")


def run(args: argparse.Namespace) -> int:
    _require_cryptography()
    fmt = "json" if args.json else "table"

    if args.action == "keygen":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        pub_hex = _pub_hex(private.public_key())
        record: dict = {"algorithm": "ed25519", "public_key_hex": pub_hex}
        if args.out_prefix:
            for suffix in (".priv.pem", ".pub.pem"):
                if Path(str(args.out_prefix) + suffix).exists() and not args.force:
                    fail(f"{args.out_prefix}{suffix} exists (use --force)")
            priv_pem = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            priv_path = Path(str(args.out_prefix) + ".priv.pem")
            priv_path.write_bytes(priv_pem)
            os.chmod(priv_path, 0o600)
            Path(str(args.out_prefix) + ".pub.pem").write_bytes(pub_pem)
            record["private_file"] = str(priv_path) + " (mode 600, unencrypted PEM — store safely)"
            record["public_file"] = str(args.out_prefix) + ".pub.pem"
        elif args.show_private:
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

            record["private_key_hex"] = private.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ).hex()
            warn("raw private key printed to stdout — it now lives in your scrollback")
        else:
            record["note"] = "pass --out-prefix to save PEM files, or --show-private to print raw keys"
        print(render_record(record, fmt))
        return 0

    if args.action == "sign":
        if not args.key:
            fail("sign needs --key PRIV.pem")
        _, data, label = resolve_source(args)
        signature = _load_private(args.key).sign(data)
        print(render_record({
            "input": label, "bytes": len(data), "signature_hex": signature.hex(),
            "algorithm": "ed25519", "public_key_hex": _pub_hex(_load_private(args.key).public_key()),
        }, fmt))
        return 0

    if args.action == "verify":
        if not args.pub or not args.sig:
            fail("verify needs --pub PUB.pem and --sig HEX")
        try:
            signature = bytes.fromhex(args.sig)
        except ValueError:
            fail(f"--sig is not valid hex: {args.sig[:40]!r}...")
        if len(signature) != SIG_LEN:
            fail(f"ed25519 signatures are {SIG_LEN} bytes ({SIG_LEN * 2} hex chars), got {len(signature)}")
        _, data, label = resolve_source(args)
        from cryptography.exceptions import InvalidSignature

        try:
            _load_public(args.pub).verify(signature, data)
        except InvalidSignature:
            failure(f"signature INVALID for this message/key ({label}, {len(data)} bytes)")
            print(render_record({"valid": False, "input": label, "bytes": len(data)}, fmt))
            return 1
        success(f"signature valid ({label}, {len(data)} bytes)")
        print(render_record({"valid": True, "input": label, "bytes": len(data)}, fmt))
        return 0

    # x25519 demo
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    alice, bob = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    a_pub = alice.public_key().public_bytes_raw()
    b_pub = bob.public_key().public_bytes_raw()
    shared_a = alice.exchange(X25519PublicKey.from_public_bytes(b_pub))
    shared_b = bob.exchange(X25519PublicKey.from_public_bytes(a_pub))
    print(render_record({
        "alice_public_hex": a_pub.hex(), "bob_public_hex": b_pub.hex(),
        "shared_secret_hex": shared_a.hex(), "both_sides_agree": shared_a == shared_b,
        "note": "X25519 is what TLS 1.3 negotiates; the raw shared secret is fed through HKDF before use",
    }, fmt))
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "ed25519",
        parents=[common_flags()],
        help="Ed25519 sign/verify + X25519 key exchange (production library)",
        description="Ed25519 signatures and X25519 key exchange via the cryptography library.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ed25519",
        description="Ed25519 signatures and X25519 key exchange via the cryptography library.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
