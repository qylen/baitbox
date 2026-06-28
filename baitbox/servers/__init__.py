from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import asyncio
from ..db import log_event, get_recent_events
from ..pubsub import pubsub

app = FastAPI()

# Mount static files for the dashboard
static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# --- REAL DASHBOARD ROUTES ---

@app.get("/")
async def get_dashboard():
    with open(os.path.join(static_dir, "index.html"), "r") as f:
        return HTMLResponse(f.read())

@app.get("/api/events")
async def api_events():
    events = await get_recent_events(100)
    # Reverse to show oldest to newest
    return list(reversed(events))

@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    await websocket.accept()
    queue = await pubsub.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pubsub.unsubscribe(queue)

# --- FAKE HTTP HONEYPOT ROUTES ---
# These catch all other standard HTTP methods and paths

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def honeypot_catchall(request: Request, path: str):
    client_ip = request.client.host if request.client else "unknown"
    method = request.method
    headers = dict(request.headers)
    body = await request.body()
    
    payload = {
        "method": method,
        "path": f"/{path}",
        "headers": headers,
        "body": body.decode("utf-8", errors="ignore")
    }
    
    event = await log_event(src_ip=client_ip, protocol="HTTP", event_type="request", payload=payload)
    await pubsub.publish(event)
    
    # Return a fake admin login page to keep the bot interested
    fake_html = """
    <html><head><title>Admin Login</title></head>
    <body style="font-family: sans-serif; background: #f1f1f1; padding: 50px;">
        <div style="max-width: 300px; margin: auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h3>System Admin Panel</h3>
            <form method="POST" action="/login">
                <input type="text" name="user" placeholder="Username" style="width: 100%; margin-bottom: 10px; padding: 8px;"><br>
                <input type="password" name="pass" placeholder="Password" style="width: 100%; margin-bottom: 10px; padding: 8px;"><br>
                <button style="width: 100%; padding: 8px; background: #007bff; color: white; border: none;">Login</button>
            </form>
        </div>
    </body></html>
    """
    return HTMLResponse(content=fake_html, status_code=200)
