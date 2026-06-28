import aiosqlite
import datetime
import json

DB_NAME = "baitbox.db"

async def init_db():
    async with aiosqlite.connect(DB_NAME) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                protocol TEXT,
                event_type TEXT,
                payload TEXT
            )
        """)
        await db.commit()

async def log_event(src_ip: str, protocol: str, event_type: str, payload: dict):
    timestamp = datetime.datetime.now().isoformat()
    payload_str = json.dumps(payload)
    
    async with aiosqlite.connect(DB_NAME) as db:
        await db.execute(
            "INSERT INTO events (timestamp, src_ip, protocol, event_type, payload) VALUES (?, ?, ?, ?, ?)",
            (timestamp, src_ip, protocol, event_type, payload_str)
        )
        await db.commit()
    
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "protocol": protocol,
        "event_type": event_type,
        "payload": payload
    }

async def get_recent_events(limit: int = 50):
    async with aiosqlite.connect(DB_NAME) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
