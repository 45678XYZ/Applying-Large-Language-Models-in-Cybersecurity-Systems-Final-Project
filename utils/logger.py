"""Project-wide logger factory."""

import logging

from config import settings


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger; level driven by `settings.log_level`."""
    raise NotImplementedError
