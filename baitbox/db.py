"""SQLite persistence helpers for honeypot events."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import aiosqlite

from .config import settings

DB_NAME = settings.database_path


async def init_db() -> None:
    async with aiosqlite.connect(DB_NAME) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
        await db.commit()


async def log_event(src_ip: str, protocol: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    timestamp = dt.datetime.now(dt.UTC).isoformat()
    payload_str = json.dumps(payload, sort_keys=True)

    async with aiosqlite.connect(DB_NAME) as db:
        cursor = await db.execute(
            "INSERT INTO events (timestamp, src_ip, protocol, event_type, payload) VALUES (?, ?, ?, ?, ?)",
            (timestamp, src_ip, protocol, event_type, payload_str),
        )
        await db.commit()
        event_id = cursor.lastrowid

    return {
        "id": event_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "protocol": protocol,
        "event_type": event_type,
        "payload": payload,
    }


def _decode_row(row: aiosqlite.Row) -> dict[str, Any]:
    event = dict(row)
    try:
        event["payload"] = json.loads(event.get("payload") or "{}")
    except json.JSONDecodeError:
        event["payload"] = {"raw": event.get("payload", "")}
    return event


async def get_recent_events(limit: int = 50) -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_NAME) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [_decode_row(row) for row in reversed(rows)]


async def get_stats() -> dict[str, Any]:
    async with aiosqlite.connect(DB_NAME) as db:
        db.row_factory = aiosqlite.Row
        total = (await (await db.execute("SELECT COUNT(*) AS count FROM events")).fetchone())["count"]
        by_protocol = await (await db.execute(
            "SELECT protocol, COUNT(*) AS count FROM events GROUP BY protocol ORDER BY count DESC"
        )).fetchall()
        top_ips = await (await db.execute(
            "SELECT src_ip, COUNT(*) AS count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT 10"
        )).fetchall()

    return {
        "total_events": total,
        "by_protocol": [dict(row) for row in by_protocol],
        "top_ips": [dict(row) for row in top_ips],
    }
