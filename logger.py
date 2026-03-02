import logging
import os
from logging.handlers import RotatingFileHandler

_BASE = os.path.dirname(__file__)
AUTH_LOG  = os.path.join(_BASE, "logs", "auth.log")
ADMIN_LOG = os.path.join(_BASE, "logs", "admin.log")


def get_logger(name: str) -> logging.Logger:
    """Logger general (debug/info/warning) → consola + auth.log"""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = RotatingFileHandler(AUTH_LOG, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


def get_admin_logger() -> logging.Logger:
    """Logger de auditoría de acciones administrativas → admin.log"""
    name = "admin"
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False  # no contaminar el log general

    fmt = logging.Formatter(
        "%(asctime)s\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Consola (sólo INFO+)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Archivo rotativo
    fh = RotatingFileHandler(ADMIN_LOG, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger
