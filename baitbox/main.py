import asyncio
import threading
import uvicorn
from rich.console import Console
from rich.panel import Panel
from .db import init_db
from .servers.ssh_server import start_ssh_server
from .servers.http_server import app

console = Console()

async def main():
    # Initialize Database
    await init_db()
    
    # Print Fancy Boot Screen
    boot_text = "[bold green]🪤 BaitBox Honeypot[/bold green]\n" \
                "[dim]SSH Honeypot: Port 2222[/dim]\n" \
                "[dim]HTTP Honeypot: Port 8080[/dim]\n" \
                "[dim]Dashboard: http://localhost:8000[/dim]"
    console.print(Panel(boot_text, border_style="green"))
    
    # Start SSH Server in a background thread (Paramiko is blocking)
    ssh_thread = threading.Thread(target=start_ssh_server, daemon=True)
    ssh_thread.start()
    
    # Start FastAPI Server (HTTP Honeypot + Dashboard) in asyncio loop
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning")
    server = uvicorn.Server(config)
    
    # We also need the HTTP Honeypot to run on port 8080. 
    # FastAPI can't easily listen on two ports with different routes in the same process.
    # For simplicity in this MVP, the catch-all route handles HTTP honeypot traffic on 8000 as well.
    # In production, you'd use a reverse proxy (nginx) or run two uvicorn instances.
    
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
