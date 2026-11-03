"""Logging setup shared by all gravyard tools.

Logs always go to stderr — stdout is reserved for command output and JSON.
Default level is WARNING; ``-v`` shows INFO (progress, rates), ``-vv`` shows
DEBUG.
"""

from __future__ import annotations

import logging
import sys

_configured = False


def setup_logging(verbose: int = 0) -> None:
    global _configured
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    if _configured:
        logging.getLogger().setLevel(level)
        return
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    _configured = True


def get_logger(name: str = "gravyard") -> logging.Logger:
    return logging.getLogger(name)
