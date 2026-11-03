"""gravyard top-level command dispatcher.

Plugin-style registry, two levels deep:

    gravyard <category> <tool> [flags...]

- ``CATEGORY_REGISTRY`` maps a category name to its package, which must
  expose ``DESCRIPTION`` and ``register(subparsers)``.
- every tool module inside a category exposes ``add_arguments(parser)``,
  ``run(args)`` and ``register(subparsers)`` — adding a tool is adding a
  module, nothing else changes.

Tool modules stay import-safe with zero third-party dependencies: optional
dependencies (cryptography, Pillow, ...) are imported inside ``run()``, not
at module level, so a missing extra never breaks unrelated tools.

Each tool is also runnable standalone, e.g.::

    python crypto/hashing/hash_id.py <hash>

Authorized use only: run gravyard tools solely against systems, files and
networks you own or have written permission to test. See SCOPE.md.
"""

from __future__ import annotations

import argparse
import importlib

from core import __version__
from core.logging import setup_logging

CATEGORY_REGISTRY = {
    "crypto": "crypto",
    "webtest": "webtest",
    "crawler": "crawler",
    "reverse": "reverse",
    # future: "network": "network", ...
}

EPILOG = (
    "Authorized use only: run this tool solely against systems, files and "
    "networks you own or have written permission to test. See SCOPE.md."
)


def common_flags() -> argparse.ArgumentParser:
    """Parent parser with the flags every tool accepts."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--json", action="store_true", help="output JSON instead of tables")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="increase log verbosity (-v info, -vv debug)",
    )
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gravyard",
        description="Personal, modular cybersecurity toolkit (authorized use only).",
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"gravyard {__version__}")
    categories = parser.add_subparsers(dest="category", metavar="<category>", required=True)
    for name, module_path in CATEGORY_REGISTRY.items():
        module = importlib.import_module(module_path)
        cat_parser = categories.add_parser(
            name, help=module.DESCRIPTION, description=module.DESCRIPTION, epilog=EPILOG
        )
        tools = cat_parser.add_subparsers(dest="tool", metavar="<tool>", required=True)
        module.register(tools)
    return parser


def standalone(parser: argparse.ArgumentParser, argv: list[str] | None = None) -> int:
    """Parse and run for a tool invoked directly as a script."""
    args = parser.parse_args(argv)
    setup_logging(getattr(args, "verbose", 0))
    return args.func(args) or 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(getattr(args, "verbose", 0))
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
