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


settings = Settings()
