"""Tests for logger setup — rotation and console level."""

import logging
from logging.handlers import RotatingFileHandler

from voidfreq.core.logger import (
    BACKUP_COUNT,
    MAX_BYTES,
    get_logger,
    set_console_level,
)


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


def test_rotating_handler():
    logger = get_logger("test_rotate")
    file_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    assert len(file_handlers) == 1
    rh = file_handlers[0]
    assert rh.maxBytes == MAX_BYTES
    assert rh.backupCount == BACKUP_COUNT


def test_set_console_level_debug():
    set_console_level(logging.DEBUG)
    root = logging.getLogger("voidfreq")
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)
                       and not isinstance(h, RotatingFileHandler)]
    assert len(stream_handlers) >= 1
    assert stream_handlers[-1].level == logging.DEBUG


def test_set_console_level_warning():
    set_console_level(logging.WARNING)
    root = logging.getLogger("voidfreq")
    stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)
                       and not isinstance(h, RotatingFileHandler)]
    assert stream_handlers[-1].level == logging.WARNING


def test_max_bytes_value():
    assert MAX_BYTES == 10 * 1024 * 1024


def test_backup_count_value():
    assert BACKUP_COUNT == 5
