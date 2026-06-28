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


settings = Settings()
