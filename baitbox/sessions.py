"""State management for active SSH sessions in BaitBox."""

from __future__ import annotations
import time
from typing import Any, Dict, List
import paramiko

class SSHSession:
    def __init__(
        self,
        session_id: str,
        src_ip: str,
        src_port: int,
        username: str,
        channel: paramiko.Channel,
        transport: paramiko.Transport,
    ) -> None:
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username = username
        self.login_time = time.time()
        self.last_seen = time.time()
        self.channel = channel
        self.transport = transport
        self.cwd = "/root"
        self.commands: List[Dict[str, Any]] = []
        
        # Initialize a custom virtual filesystem for this session
        from .vfs import VirtualFilesystem
        self.vfs = VirtualFilesystem()

    def add_command(self, command: str) -> None:
        self.last_seen = time.time()
        self.commands.append({
            "command": command,
            "timestamp": time.time(),
        })

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.transport.close()
        except Exception:
            pass


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, SSHSession] = {}

    def register(self, session: SSHSession) -> None:
        self.sessions[session.session_id] = session

    def unregister(self, session_id: str) -> None:
        if session_id in self.sessions:
            del self.sessions[session_id]

    def get_session(self, session_id: str) -> SSHSession | None:
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        res = []
        for s in self.sessions.values():
            res.append({
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "src_port": s.src_port,
                "username": s.username,
                "login_time": s.login_time,
                "last_seen": s.last_seen,
                "cwd": s.cwd,
                "commands": s.commands[-10:]  # last 10 commands
            })
        return res


session_manager = SessionManager()
