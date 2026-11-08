"""Structured logging configuration for DPI / IDS packet engine."""

from __future__ import annotations

import logging
import sys


def setup_logger(name: str = "dpi_ids_ips", level: int = logging.INFO, log_file: str | None = None) -> logging.Logger:
    """
    Configures and returns a structured logger.

    Args:
        name: Root logger name.
        level: Logging severity level.
        log_file: Optional file path to persist logs.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding duplicate handlers if already configured
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Note: Terminal console logs for raw packets are handled via Formatter
    # so standard logger outputs mainly operational status/warnings/errors
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

