import asyncio
import threading
import uvicorn
from rich.console import Console
from rich.panel import Panel
from .config import settings
from .db import init_db
from .servers.ssh_server import start_ssh_server
from .servers.http_server import app

console = Console()

async def main():
    # Initialize Database
    await init_db()
    
    # Print Fancy Boot Screen
    boot_text = "[bold green]🪤 BaitBox Honeypot[/bold green]\n" \
                f"[dim]SSH Honeypot: {settings.ssh_host}:{settings.ssh_port}[/dim]\n" \
                f"[dim]Dashboard + HTTP honeypot: http://localhost:{settings.dashboard_port}[/dim]\n" \
                f"[dim]SQLite DB: {settings.database_path}[/dim]"
    console.print(Panel(boot_text, border_style="green"))
    
    # Start SSH Server in a background thread (Paramiko is blocking)
    ssh_thread = threading.Thread(target=start_ssh_server, kwargs={"host": settings.ssh_host, "port": settings.ssh_port}, daemon=True)
    ssh_thread.start()
    
    # Start FastAPI Server (HTTP Honeypot + Dashboard) in asyncio loop
    config = uvicorn.Config(app, host=settings.dashboard_host, port=settings.dashboard_port, log_level="warning")
    server = uvicorn.Server(config)
    
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
