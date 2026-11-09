"""Structured logging for NetblockTool.

Produces the ``[INFO] message`` style used throughout the tool while still
being a normal :mod:`logging` setup, so callers embedding the package can
reconfigure handlers as they wish.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "netblocktool"

_LEVEL_TAGS = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARN",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "FATAL",
}


class TagFormatter(logging.Formatter):
    """Render records as ``[LEVEL] message``."""

    def format(self, record: logging.LogRecord) -> str:
        tag = _LEVEL_TAGS.get(record.levelno, record.levelname)
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        return f"[{tag}] {message}"


def configure(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure and return the package logger.

    Args:
        verbose: Emit DEBUG-level progress detail.
        quiet: Suppress everything below WARNING.
    """
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    # Replace handlers so repeated calls (tests, library use) do not duplicate.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    # Status output belongs on stderr so that stdout stays clean for piping.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(TagFormatter())
    handler.setLevel(level)
    logger.addHandler(handler)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child of the package logger."""
    if name:
        return logging.getLogger(f"{LOGGER_NAME}.{name}")
    return logging.getLogger(LOGGER_NAME)
