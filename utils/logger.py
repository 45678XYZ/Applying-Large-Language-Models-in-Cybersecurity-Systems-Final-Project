"""Project-wide logger factory."""

import logging

from config import settings


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger; level driven by `settings.log_level`."""
    logger = logging.getLogger(name)
    logger.setLevel(settings.log_level.upper())
    # Attach a handler only when logging is otherwise unconfigured, so this
    # composes with scripts that already call logging.basicConfig().
    if not logging.getLogger().handlers and not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s")
        )
        logger.addHandler(handler)
    return logger
