"""Runtime configuration for BaitBox."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    ssh_host: str = os.getenv("BAITBOX_SSH_HOST", "0.0.0.0")
    ssh_port: int = int(os.getenv("BAITBOX_SSH_PORT", "2222"))
    dashboard_host: str = os.getenv("BAITBOX_DASHBOARD_HOST", "0.0.0.0")
    dashboard_port: int = int(os.getenv("BAITBOX_DASHBOARD_PORT", "8000"))
    database_path: str = os.getenv("BAITBOX_DB", "baitbox.db")
    max_events: int = int(os.getenv("BAITBOX_MAX_EVENTS", "100"))
    ssh_host_key: str = os.getenv("BAITBOX_SSH_HOST_KEY", "")
    ssh_backlog: int = int(os.getenv("BAITBOX_SSH_BACKLOG", "100"))
    ssh_channel_timeout: int = int(os.getenv("BAITBOX_SSH_CHANNEL_TIMEOUT", "20"))
    webhook_url: str = os.getenv("BAITBOX_WEBHOOK_URL", "")
    webhook_type: str = os.getenv("BAITBOX_WEBHOOK_TYPE", "discord")
    # Server-side GeoIP: set to "0" to disable (reduces external lookups)
    geoip_enabled: bool = os.getenv("BAITBOX_GEOIP_ENABLED", "1") not in ("0", "false", "no")
    # Telnet honeypot
    telnet_port: int = int(os.getenv("BAITBOX_TELNET_PORT", "2323"))
    telnet_enabled: bool = os.getenv("BAITBOX_TELNET_ENABLED", "1") not in ("0", "false", "no")
    # Banner customisation
    ssh_banner_hostname: str = os.getenv("BAITBOX_SSH_HOSTNAME", "web-prod-01")

    # Dashboard Authentication
    dashboard_username: str = os.getenv("BAITBOX_DASHBOARD_USER", "admin")
    # Database selection
    database_type: str = os.getenv("BAITBOX_DB_TYPE", "sqlite")
    database_url: str = os.getenv("BAITBOX_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/baitbox")
    dashboard_password: str = os.getenv("BAITBOX_DASHBOARD_PASSWORD", "admin")
    jwt_secret: str = os.getenv("BAITBOX_JWT_SECRET", "baitbox-super-secret-key-change-me")


settings = Settings()
