"""FastAPI dashboard and HTTP honeypot routes."""

from __future__ import annotations

import json
from urllib.parse import parse_qs
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..db import get_recent_events, get_stats, log_event
from ..pubsub import pubsub

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(
    title="BaitBox",
    description="A lightweight honeypot with a real-time dashboard.",
    version="0.2.0",
)

_DECOY_PATHS = {
    "/admin",
    "/administrator",
    "/login",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
}


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


async def _request_payload(request: Request) -> dict[str, Any]:
    body = await request.body()
    form_data: dict[str, Any] = {}
    if body:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                form_data = json.loads(body.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                form_data = {"raw_body": body.decode("utf-8", errors="replace")}
        elif "form" in content_type:
            parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
            form_data = {key: values[-1] if values else "" for key, values in parsed.items()}
        else:
            form_data = {"raw_body": body.decode("utf-8", errors="replace")[:2048]}

    return {
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query),
        "user_agent": request.headers.get("user-agent", ""),
        "headers": {
            "host": request.headers.get("host", ""),
            "referer": request.headers.get("referer", ""),
        },
        "body": form_data,
    }


async def _record_http_request(request: Request, event_type: str = "request") -> dict[str, Any]:
    event = await log_event(_client_ip(request), "HTTP", event_type, await _request_payload(request))
    await pubsub.publish(event)
    return event


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/api/events")
async def api_events(limit: int = 100) -> list[dict[str, Any]]:
    return await get_recent_events(limit=min(max(limit, 1), 500))


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    return await get_stats()


@app.get("/api/sessions")
async def api_sessions() -> list[dict[str, Any]]:
    from ..sessions import session_manager
    return session_manager.list_sessions()


@app.post("/api/sessions/{session_id}/kill")
async def api_kill_session(session_id: str) -> dict[str, Any]:
    from ..sessions import session_manager
    session = session_manager.get_session(session_id)
    if session:
        session.close()
        session_manager.unregister(session_id)
        return {"status": "ok", "message": f"Session {session_id} terminated."}
    return {"status": "error", "message": "Session not found."}


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = await pubsub.subscribe()
    try:
        while True:
            await websocket.send_json(await queue.get())
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(queue)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def honeypot(request: Request, path: str) -> Response:
    await _record_http_request(request, "credential_probe" if request.url.path in _DECOY_PATHS else "request")

    if request.method == "HEAD":
        return Response(status_code=200)

    if request.url.path in _DECOY_PATHS:
        return HTMLResponse(
            """
            <!doctype html><html><head><title>Admin Login</title></head>
            <body style="font-family: sans-serif; margin: 4rem;">
              <h1>Admin Login</h1>
              <form method="post">
                <input name="username" placeholder="Username" autofocus>
                <input name="password" placeholder="Password" type="password">
                <button type="submit">Log in</button>
              </form>
              <p style="color: #b91c1c;">Invalid credentials.</p>
            </body></html>
            """,
            status_code=401 if request.method == "POST" else 200,
        )

    return JSONResponse({"status": "ok"})
