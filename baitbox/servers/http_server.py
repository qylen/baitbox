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
from ..ratelimit import (
    block_ip,
    get_blocked_ips,
    get_connection_counts,
    is_blocked,
    record_connection,
    unblock_ip,
)

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI(
    title="BaitBox",
    description="A lightweight honeypot with a real-time dashboard.",
    version="2.0.0",
)

# Decoy paths that emulate common attack targets
_DECOY_PATHS = {
    "/admin",
    "/administrator",
    "/login",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/shell",
    "/cmd",
    "/cgi-bin/bash",
    "/.env",
    "/config",
    "/.git/config",
    "/api/v1/users",
    "/actuator",
    "/actuator/env",
    "/console",
    "/manager/html",
    "/jmx-console",
    "/invoke",
}

_FAKE_ENV = """APP_ENV=production
APP_KEY=base64:FakeBase64AppKeyBaitboxHoneypot==
DB_CONNECTION=mysql
DB_HOST=10.0.0.10
DB_DATABASE=production
DB_USERNAME=app_user
DB_PASSWORD=REDACTED_BY_BAITBOX
"""


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
    src_ip = _client_ip(request)
    record_connection(src_ip, "HTTP")
    event = await log_event(src_ip, "HTTP", event_type, await _request_payload(request))
    await pubsub.publish(event)
    return event


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/api/events")
async def api_events(limit: int = 100) -> list[dict[str, Any]]:
    events = await get_recent_events(limit=min(max(limit, 1), 500))
    # Enrich with cached GeoIP data server-side
    try:
        from ..geoip import get_cached
        for ev in events:
            geo = get_cached(ev.get("src_ip", ""))
            if geo:
                ev["geo"] = geo
    except Exception:
        pass
    return events


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    stats = await get_stats()
    # Append rate-limit data
    stats["top_connections"] = get_connection_counts()[:10]
    stats["blocked_ips"] = get_blocked_ips()
    return stats


@app.get("/api/sessions")
async def api_sessions() -> list[dict[str, Any]]:
    from ..sessions import session_manager
    sessions = session_manager.list_sessions()
    # Enrich with cached GeoIP
    try:
        from ..geoip import get_cached
        for s in sessions:
            geo = get_cached(s.get("src_ip", ""))
            if geo:
                s["geo"] = geo
    except Exception:
        pass
    return sessions


@app.post("/api/sessions/{session_id}/kill")
async def api_kill_session(session_id: str) -> dict[str, Any]:
    from ..sessions import session_manager
    session = session_manager.get_session(session_id)
    if session:
        session.close()
        session_manager.unregister(session_id)
        return {"status": "ok", "message": f"Session {session_id} terminated."}
    return {"status": "error", "message": "Session not found."}


@app.post("/api/block/{ip}")
async def api_block_ip(ip: str) -> dict[str, Any]:
    block_ip(ip)
    # Also terminate any active SSH sessions from this IP
    from ..sessions import session_manager
    sessions = session_manager.list_sessions()
    killed = 0
    for s in sessions:
        if s["src_ip"] == ip:
            sess = session_manager.get_session(s["session_id"])
            if sess:
                sess.close()
                session_manager.unregister(s["session_id"])
                killed += 1
    return {"status": "ok", "message": f"IP {ip} blocked.", "sessions_terminated": killed}


@app.post("/api/unblock/{ip}")
async def api_unblock_ip(ip: str) -> dict[str, Any]:
    unblock_ip(ip)
    return {"status": "ok", "message": f"IP {ip} unblocked."}


@app.get("/api/geoip/{ip}")
async def api_geoip(ip: str) -> dict[str, Any]:
    """Perform a server-side GeoIP lookup (rate-limited and cached)."""
    try:
        from ..geoip import lookup_ip
        return await lookup_ip(ip)
    except Exception as exc:
        return {"error": str(exc)}


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = await pubsub.subscribe()
    try:
        while True:
            event = await queue.get()
            # Enrich with cached geo
            try:
                from ..geoip import get_cached
                geo = get_cached(event.get("src_ip", ""))
                if geo:
                    event["geo"] = geo
            except Exception:
                pass
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(queue)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def honeypot(request: Request, path: str) -> Response:
    src_ip = _client_ip(request)
    if is_blocked(src_ip):
        return JSONResponse({"status": "blocked"}, status_code=403)

    # Log every probe
    is_probe = request.url.path in _DECOY_PATHS
    await _record_http_request(request, "credential_probe" if is_probe else "request")

    if request.method == "HEAD":
        return Response(status_code=200)

    # .env file decoy - return fake env to entice credential harvesting bots
    if request.url.path in ("/.env", "/env", "/.env.local"):
        return Response(_FAKE_ENV, media_type="text/plain", status_code=200)

    # .git/config decoy
    if "/.git" in request.url.path:
        return Response(
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example/production.git\n",
            media_type="text/plain", status_code=200,
        )

    if request.url.path in _DECOY_PATHS:
        is_post = request.method == "POST"
        return HTMLResponse(
            """
            <!doctype html><html lang="en"><head>
            <title>Admin Login</title>
            <meta charset="utf-8">
            <style>
              body{font-family:sans-serif;background:#1a1a2e;color:#eee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
              .card{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:2rem 2.5rem;width:320px}
              h1{color:#e94560;font-size:1.5rem;margin-bottom:1rem}
              input{width:100%;box-sizing:border-box;background:#0f3460;border:1px solid #1a4a8a;color:#eee;padding:.6rem;border-radius:4px;margin-bottom:.8rem}
              button{width:100%;background:#e94560;border:none;color:#fff;padding:.7rem;border-radius:4px;cursor:pointer;font-size:1rem}
              .err{color:#e94560;font-size:.8rem;margin-top:.5rem}
            </style>
            </head>
            <body>
              <div class="card">
                <h1>🔒 Admin Login</h1>
                <form method="post">
                  <input name="username" placeholder="Username" autofocus autocomplete="off">
                  <input name="password" placeholder="Password" type="password" autocomplete="off">
                  <button type="submit">Sign In</button>
                </form>
                """ + ('<p class="err">⚠ Invalid credentials. Try again.</p>' if is_post else "") + """
              </div>
            </body></html>
            """,
            status_code=401 if is_post else 200,
        )

    return JSONResponse({"status": "ok"})
