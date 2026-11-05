#!/usr/bin/env python3
"""Merkle trees: build, generate inclusion proofs, verify them.

Leaves are SHA-256 digests of the input lines (or raw bytes passed as hex).
Pairs concatenate left+right and hash again; an odd node at any level is
duplicated with itself (Bitcoin convention). An inclusion proof is the
sibling chain from a leaf to the root — you can prove a leaf is in the tree
knowing only the root, which is how blockchains commit to transactions and
CT logs commit to certificates.

Examples:
    gravyard crypto merkle build --text "tx1
    tx2
    tx3"
    gravyard crypto merkle proof --file txs.txt --index 2 --out proof.json
    gravyard crypto merkle verify --proof proof.json --leaf "tx3"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.input import resolve_text
from core.output import fail, render_record, render_rows, success

MAGIC = "gravyard-merkle-proof"


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def _leaf_from_line(line: str) -> bytes:
    return hashlib.sha256(line.encode("utf-8")).digest()


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        fail("no leaves given")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2:
            current.append(current[-1])  # Bitcoin-style odd-node duplication
        levels.append([_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)])
    return levels


def _collect_leaves(args) -> list[bytes]:
    if args.leaves_hex:
        out = []
        for item in args.leaves_hex.split(","):
            try:
                out.append(bytes.fromhex(item.strip()))
            except ValueError:
                fail(f"--leaves-hex item is not valid hex: {item.strip()[:20]!r}")
        return out
    text = resolve_text(args)
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        fail("no non-empty lines to use as leaves")
    return [_leaf_from_line(line) for line in lines]


def _proof_steps(levels: list[list[bytes]], index: int) -> list[dict]:
    steps, idx = [], index
    for level in levels[:-1]:
        sibling_idx = idx ^ 1
        if sibling_idx < len(level):
            sibling, position = level[sibling_idx], ("right" if idx % 2 == 0 else "left")
        else:
            sibling, position = level[idx], "right"  # duplicated odd node
        steps.append({"position": position, "sibling": sibling.hex()})
        idx //= 2
    return steps


def _verify_proof(leaf: bytes, index: int, steps: list[dict], root: str, leaf_count: int) -> bool:
    if not 0 <= index < leaf_count:
        return False
    h = leaf
    for step in steps:
        try:
            sibling = bytes.fromhex(step["sibling"])
        except (ValueError, KeyError):
            return False
        if step.get("position") == "right":
            h = _hash_pair(h, sibling)
        elif step.get("position") == "left":
            h = _hash_pair(sibling, h)
        else:
            return False
    return h.hex() == root


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=("build", "proof", "verify"))
    parser.add_argument("--text", help="leaves as text, one leaf per line ('-' reads stdin)")
    parser.add_argument("--file", type=Path, help="leaves from a file, one per line")
    parser.add_argument("--leaves-hex", help="raw leaf bytes as comma-separated hex (used as-is)")
    parser.add_argument("--index", type=int, help="proof: leaf position to prove (0-based)")
    parser.add_argument("--out", type=Path, help="proof: write the proof JSON to a file")
    parser.add_argument("--proof", type=Path, help="verify: proof JSON file (from the proof action)")
    parser.add_argument("--leaf", help="verify: the original leaf line (hashed like build does)")
    parser.add_argument("--leaf-hex", help="verify: raw leaf bytes as hex (alternative to --leaf)")
    parser.add_argument("--root", help="verify: expected root (defaults to the proof's stated root)")
    parser.add_argument("--show-levels", action="store_true", help="build: print every tree level")


def run(args: argparse.Namespace) -> int:
    fmt = "json" if args.json else "table"

    if args.action == "build":
        leaves = _collect_leaves(args)
        levels = build_tree(leaves)
        if args.show_levels and not args.json:
            rows = [{"level": i, "nodes": len(level), "hashes": " ".join(h.hex()[:8] for h in level)}
                    for i, level in enumerate(levels)]
            print(render_rows(rows))
            print()
        print(render_record({
            "leaves": len(leaves), "depth": len(levels) - 1,
            "root": levels[-1][0].hex(),
        }, fmt))
        return 0

    if args.action == "proof":
        if args.index is None:
            fail("proof needs --index N")
        leaves = _collect_leaves(args)
        if not 0 <= args.index < len(leaves):
            fail(f"--index must be in [0, {len(leaves) - 1}]")
        levels = build_tree(leaves)
        steps = _proof_steps(levels, args.index)
        proof = {
            "magic": MAGIC,
            "leaf_count": len(leaves),
            "index": args.index,
            "leaf_hash": leaves[args.index].hex(),
            "steps": steps,
            "root": levels[-1][0].hex(),
        }
        if args.out:
            args.out.write_text(json.dumps(proof, indent=2), encoding="utf-8")
        record = {k: v for k, v in proof.items() if k != "magic"}
        record["written_to"] = str(args.out) if args.out else None
        print(json.dumps(record, indent=2) if args.json else render_record(record))
        return 0

    # verify
    if not args.proof or not args.proof.is_file():
        fail("verify needs --proof FILE (from the proof action)")
    proof = json.loads(args.proof.read_text(encoding="utf-8"))
    if proof.get("magic") != MAGIC:
        fail(f"{args.proof} is not a gravyard merkle proof")
    if args.leaf:
        leaf = _leaf_from_line(args.leaf)
    elif args.leaf_hex:
        try:
            leaf = bytes.fromhex(args.leaf_hex)
        except ValueError:
            fail("--leaf-hex is not valid hex")
    else:
        fail("verify needs --leaf TEXT or --leaf-hex HEX")
    root = args.root or proof["root"]
    valid = _verify_proof(leaf, proof["index"], proof["steps"], root, proof["leaf_count"])
    if valid:
        success(f"inclusion PROVEN: leaf {proof['index']} is in the tree with root {root[:16]}...")
        print(render_record({"valid": True, "index": proof["index"], "root": root}, fmt))
        return 0
    print(render_record({"valid": False, "index": proof["index"], "root": root}, fmt))
    fail(f"inclusion FAILED: leaf {proof['index']} does not hash up to root {root[:16]}...", code=1)
    return 1  # unreachable — fail() exits


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "merkle",
        parents=[common_flags()],
        help="Merkle trees: build, inclusion proofs, verification",
        description="Merkle tree build/proof/verify (SHA-256, Bitcoin-style odd-node duplication).",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="merkle",
        description="Merkle tree build/proof/verify (SHA-256, Bitcoin-style odd-node duplication).",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
