#!/usr/bin/env python3
"""Toy blockchain explorer: mine, inspect, tamper, verify.

Builds a real (if toy) proof-of-work chain: each block's hash is the
SHA-256 of its canonical JSON (index, timestamp, data, prev_hash, nonce)
and must start with `difficulty` zeros. `tamper` rewrites one block's data
without fixing the hashes, and `verify` then shows exactly where the chain
breaks — hash chaining + proof-of-work is what makes rewriting history
expensive, and this tool lets you watch that fail.

Educational toy: no transactions, no peers, no real consensus.

Examples:
    gravyard crypto chain mine --blocks 5 --difficulty 4 --out chain.json
    gravyard crypto chain show --file chain.json
    gravyard crypto chain verify --file chain.json
    gravyard crypto chain tamper --file chain.json --block 2 --data "rewrote history"
    gravyard crypto chain verify --file chain.tampered.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.cli import common_flags, standalone
from core.output import fail, failure, note, render_record, render_rows, success, warn

GENESIS_PREV = "0" * 64
CHAIN_VERSION = 1
HASHED_FIELDS = ("index", "timestamp", "data", "prev_hash", "nonce")
MAX_DIFFICULTY = 6


def block_hash(block: dict) -> str:
    payload = {field: block[field] for field in HASHED_FIELDS}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _mine(blocks: int, difficulty: int, data_prefix: str) -> list[dict]:
    target = "0" * difficulty
    chain, prev = [], GENESIS_PREV
    for index in range(blocks):
        started = time.monotonic()
        block = {
            "index": index,
            "timestamp": int(time.time()),
            "data": f"{data_prefix} #{index}",
            "prev_hash": prev,
            "nonce": 0,
        }
        digest = block_hash(block)
        while not digest.startswith(target):
            block["nonce"] += 1
            digest = block_hash(block)
        block["hash"] = digest
        block["mine_seconds"] = round(time.monotonic() - started, 3)
        chain.append(block)
        prev = digest
    return chain


def _load_document(path: Path) -> tuple[int, list[dict]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        fail(f"cannot read chain {path}: {exc}")
    if not isinstance(document, dict) or document.get("magic") != "gravyard-chain":
        fail(f"{path} is not a gravyard chain file")
    return int(document.get("difficulty", 4)), document["blocks"]


def _check_chain(chain: list[dict], difficulty: int) -> list[dict]:
    rows, prev_hash = [], GENESIS_PREV
    for block in chain:
        problems = []
        if block.get("prev_hash") != prev_hash:
            problems.append("prev_hash does not match the previous block")
        if "hash" not in block or block_hash(block) != block["hash"]:
            problems.append("stored hash does not match the block contents")
        elif not block["hash"].startswith("0" * difficulty):
            problems.append("proof-of-work target not met")
        rows.append({"block": block.get("index"), "status": "broken" if problems else "ok",
                     "detail": "; ".join(problems)})
        prev_hash = block.get("hash", prev_hash)
    return rows


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=("mine", "show", "verify", "tamper"))
    parser.add_argument("--blocks", type=int, default=5, help="mine: chain length (default 5)")
    parser.add_argument("--difficulty", type=int, default=4, help="mine: leading zero hex digits (default 4)")
    parser.add_argument("--data-prefix", default="payload", help="mine: block data prefix")
    parser.add_argument("--out", type=Path, help="mine/tamper: output path")
    parser.add_argument("--file", type=Path, help="show/verify/tamper: chain file")
    parser.add_argument("--block", type=int, help="tamper: block index to rewrite")
    parser.add_argument("--data", help="tamper: replacement data")
    parser.add_argument("--force", action="store_true", help="tamper: overwrite the original file")


def run(args: argparse.Namespace) -> int:
    fmt = "json" if args.json else "table"

    if args.action == "mine":
        if args.blocks < 1:
            fail("--blocks must be >= 1")
        if not 1 <= args.difficulty <= MAX_DIFFICULTY:
            fail(f"--difficulty must be 1-{MAX_DIFFICULTY} (each digit multiplies the work by 16)")
        if args.difficulty >= 6:
            warn(f"difficulty {args.difficulty} in pure Python can take a while per block")
        chain = _mine(args.blocks, args.difficulty, args.data_prefix)
        out = args.out or Path("chain.json")
        out.write_text(json.dumps({
            "magic": "gravyard-chain", "version": CHAIN_VERSION,
            "difficulty": args.difficulty, "blocks": chain,
        }, indent=2), encoding="utf-8")
        success(f"mined {len(chain)} blocks (difficulty {args.difficulty}) -> {out}")
        rows = [{"index": b["index"], "data": b["data"], "nonce": b["nonce"],
                 "hash": b["hash"][:16] + "...", "seconds": b["mine_seconds"]} for b in chain]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(render_rows(rows))
        return 0

    if not args.file or not args.file.is_file():
        fail(f"{args.action} needs --file CHAIN.json")
    difficulty, chain = _load_document(args.file)

    if args.action == "show":
        rows = [{"index": b.get("index"), "data": b.get("data"), "nonce": b.get("nonce"),
                 "prev_hash": str(b.get("prev_hash", ""))[:16] + "...",
                 "hash": str(b.get("hash", ""))[:16] + "..."} for b in chain]
        print(render_rows(rows) if not args.json else json.dumps(rows, indent=2))
        return 0

    if args.action == "tamper":
        if args.block is None or args.data is None:
            fail("tamper needs --block N and --data NEW")
        if not 0 <= args.block < len(chain):
            fail(f"--block must be in [0, {len(chain) - 1}]")
        chain[args.block]["data"] = args.data  # hash left stale — that's the lesson
        out = args.out or Path(str(args.file).replace(".json", "") + ".tampered.json")
        if out == args.file and not args.force:
            fail(f"refusing to overwrite {out} in place (use --force or choose another --out)")
        out.write_text(json.dumps({
            "magic": "gravyard-chain", "version": CHAIN_VERSION,
            "difficulty": difficulty, "blocks": chain,
        }, indent=2), encoding="utf-8")
        warn(f"block {args.block} data rewritten, hashes left stale -> {out}")
        note(f"run: chain verify --file {out} — the chain detects the rewrite")
        print(render_record({"block": args.block, "new_data": args.data,
                             "written_to": str(out)}, fmt))
        return 0

    # verify
    rows = _check_chain(chain, difficulty)
    broken = sum(1 for r in rows if r["status"] == "broken")
    if args.json:
        print(json.dumps({"blocks": len(chain), "broken": broken, "results": rows}, indent=2))
    else:
        print(render_rows(rows, columns=["block", "status", "detail"]))
    if broken:
        failure(f"chain INVALID: {broken}/{len(chain)} blocks fail")
        return 1
    success(f"chain VALID: all {len(chain)} blocks hash correctly, chain intact, PoW met")
    return 0


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "chain",
        parents=[common_flags()],
        help="toy blockchain: proof-of-work mining, tampering, verification",
        description="Toy blockchain explorer — hash chaining and proof-of-work you can break and verify.",
    )
    add_arguments(parser)
    parser.set_defaults(func=run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chain",
        description="Toy blockchain explorer — hash chaining and proof-of-work you can break and verify.",
        parents=[common_flags()],
    )
    add_arguments(parser)
    parser.set_defaults(func=run)
    return standalone(parser, argv)


if __name__ == "__main__":
    raise SystemExit(main())
