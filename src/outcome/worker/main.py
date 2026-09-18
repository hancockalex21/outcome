from __future__ import annotations

import structlog

from outcome.core.config import get_settings, validate_startup_config
from outcome.core.logging import configure_logging

logger = structlog.get_logger()


def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    validate_startup_config(settings, process_role="worker")
    logger.info("worker_started")
