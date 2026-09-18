from __future__ import annotations

from mcp.server.transport_security import TransportSecuritySettings

from outcome.core.config import get_settings, validate_startup_config
from outcome.core.logging import configure_logging

from .main import build_application, build_session_factory
from .server import OutcomeMCPDependencies, create_mcp_server


def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    validate_startup_config(settings, process_role="mcp")
    server = create_mcp_server(
        OutcomeMCPDependencies(
            session_factory=build_session_factory(),
            application_factory=build_application,
        )
    )
    server.run(
        "streamable-http",
        host=settings.mcp_http_host,
        port=settings.mcp_http_port,
        streamable_http_path=settings.mcp_http_path,
        max_request_body_size=settings.mcp_request_max_bytes,
        session_idle_timeout=settings.mcp_session_idle_timeout_seconds,
        max_sessions=settings.mcp_max_sessions,
        transport_security=TransportSecuritySettings(
            allowed_hosts=list(settings.mcp_allowed_hosts),
            allowed_origins=[],
        ),
    )


__all__ = ["run"]
