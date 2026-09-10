from __future__ import annotations

import structlog

from outcome.core.config import get_settings
from outcome.core.logging import configure_logging

logger = structlog.get_logger()


def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger.info("worker_started")
