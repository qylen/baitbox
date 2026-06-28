"""BaitBox entry point — starts all honeypot servers concurrently."""

import asyncio
import threading

import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import settings
from .db import init_db
from .servers.http_server import app
from .servers.ssh_server import start_ssh_server

console = Console()


async def main() -> None:
    # Initialize Database
    await init_db()

    # ── Boot Banner ─────────────────────────────────────────────────────────
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(style="bright_white")
    table.add_row("🪤  SSH Honeypot", f"{settings.ssh_host}:{settings.ssh_port}")
    table.add_row("🌐  HTTP Decoys", f"http://localhost:{settings.dashboard_port}")
    table.add_row("📺  Dashboard", f"http://localhost:{settings.dashboard_port}")
    table.add_row("🗃️  Database", settings.database_path)
    if settings.telnet_enabled:
        table.add_row("📡  Telnet Honeypot", f"{settings.ssh_host}:{settings.telnet_port}")
    if settings.webhook_url:
        table.add_row("🔔  Webhooks", f"{settings.webhook_type.upper()} → {settings.webhook_url[:40]}...")
    if settings.geoip_enabled:
        table.add_row("🗺️  GeoIP", "Server-side (ip-api.com, cached 1h)")

    console.print(Panel(
        table,
        title="[bold green]🪤  BaitBox Honeypot v2.0[/bold green]",
        subtitle="[dim]Trap attackers. Capture intel. Stay safe.[/dim]",
        border_style="green",
        expand=False,
    ))

    # ── SSH Server (Paramiko is blocking — run in thread) ───────────────────
    ssh_thread = threading.Thread(
        target=start_ssh_server,
        kwargs={"host": settings.ssh_host, "port": settings.ssh_port},
        daemon=True,
    )
    ssh_thread.start()

    # ── Telnet Server (asyncio, optional) ───────────────────────────────────
    if settings.telnet_enabled:
        from .servers.telnet_server import start_telnet_server
        asyncio.ensure_future(start_telnet_server(settings.ssh_host, settings.telnet_port))

    # ── FastAPI (Dashboard + HTTP Honeypot) ─────────────────────────────────
    config = uvicorn.Config(
        app,
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
