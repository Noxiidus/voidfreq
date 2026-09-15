"""Centralized logging — file + console output for all modules."""

from __future__ import annotations

import logging
import os

LOG_DIR = os.path.expanduser("~/.voidfreq/logs")


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(f"voidfreq.{name}")
    if logger.handlers:
        return logger

    logger.setLevel(level)

    fh = logging.FileHandler(
        os.path.join(LOG_DIR, "voidfreq.log"),
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
