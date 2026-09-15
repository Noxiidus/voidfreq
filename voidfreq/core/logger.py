"""Centralized logging — file + console output for all modules."""

from __future__ import annotations

import logging
import os
import threading
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.expanduser("~/.voidfreq/logs")
LOG_FILE = os.path.join(LOG_DIR, "voidfreq.log")
MAX_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5

_console_handler: logging.StreamHandler | None = None
_lock = threading.Lock()


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(f"voidfreq.{name}")
    if logger.handlers:
        return logger

    with _lock:
        if logger.handlers:
            return logger

        logger.setLevel(level)

        fh = RotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)

        logger.propagate = False
        return logger


def set_console_level(level: int) -> None:
    """Attach or update a stderr handler on the root voidfreq logger."""
    global _console_handler
    root = logging.getLogger("voidfreq")
    root.setLevel(logging.DEBUG)

    if _console_handler is None:
        _console_handler = logging.StreamHandler()
        _console_handler.setFormatter(logging.Formatter(
            "[%(name)s] %(levelname)s: %(message)s",
        ))
        root.addHandler(_console_handler)

    _console_handler.setLevel(level)
