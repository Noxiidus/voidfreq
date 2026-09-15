"""Tests for logger setup."""

import logging
import os
from unittest.mock import patch

from voidfreq.core.logger import get_logger, LOG_DIR


def test_get_logger_returns_logger():
    logger = get_logger("test_module")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "voidfreq.test_module"


def test_get_logger_level():
    logger = get_logger("test_level", level=logging.WARNING)
    assert logger.level == logging.WARNING


def test_get_logger_idempotent():
    logger1 = get_logger("test_idempotent")
    handler_count = len(logger1.handlers)
    logger2 = get_logger("test_idempotent")
    assert logger1 is logger2
    assert len(logger2.handlers) == handler_count


def test_get_logger_no_propagate():
    logger = get_logger("test_propagate")
    assert logger.propagate is False
