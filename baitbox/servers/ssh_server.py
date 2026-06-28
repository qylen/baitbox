"""Paramiko-powered SSH honeypot server."""

from __future__ import annotations

import asyncio
import shlex
import socket
import threading
import time
from pathlib import Path
from typing import Any

import paramiko

from ..config import settings
from ..db import log_event
from ..pubsub import pubsub

PROMPT = b"root@web-prod-01:~# "
WELCOME = (
    b"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-94-generic x86_64)\r\n"
    b"\r\n"
    b" * Documentation:  https://help.ubuntu.com\r\n"
    b" * Management:     https://landscape.canonical.com\r\n"
    b"\r\n"
    b"Last login: Tue Jun 23 09:14:11 2026 from 203.0.113.24\r\n"
)


def _load_host_key() -> paramiko.PKey:
    """Load a stable host key when configured, otherwise create an ephemeral key."""
    if not settings.ssh_host_key:
        return paramiko.RSAKey.generate(2048)

    key_path = Path(settings.ssh_host_key).expanduser()
    if key_path.exists():
        return paramiko.RSAKey.from_private_key_file(str(key_path))

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key


HOST_KEY = _load_host_key()


class FakeShell(paramiko.ServerInterface):
    """Accepts authentication and records SSH channel requests."""

    def __init__(self, client_addr: tuple[str, int]) -> None:
        self.client_ip = client_addr[0]
        self.shell_requested = threading.Event()
        self.exec_command: str | None = None

    def get_allowed_auths(self, username: str) -> str:
        return "password,keyboard-interactive,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "password": password, "method": "password"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive(self, username: str, submethods: str) -> int:
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "method": "keyboard-interactive"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        _log_from_thread(
            self.client_ip,
            "auth_attempt",
            {"username": username, "method": "publickey", "key_type": key.get_name(), "fingerprint": key.fingerprint.hex()},
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.exec_command = command.decode("utf-8", errors="replace")
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_env_request(self, channel: paramiko.Channel, name: bytes, value: bytes) -> bool:
        return True


def _log_from_thread(src_ip: str, event_type: str, payload: dict[str, Any]) -> None:
    event = asyncio.run(log_event(src_ip, "SSH", event_type, payload))
    asyncio.run(pubsub.publish(event))


def command_response(command: str) -> tuple[bytes, bool]:
    """Return a fake shell response and whether the session should close."""
    try:
        parts = shlex.split(command, posix=True) if command else []
    except ValueError:
        parts = command.split()
    executable = parts[0] if parts else ""

    responses: dict[str, bytes] = {
        "pwd": b"/root\r\n",
        "whoami": b"root\r\n",
        "id": b"uid=0(root) gid=0(root) groups=0(root)\r\n",
        "hostname": b"web-prod-01\r\n",
        "uname": b"Linux web-prod-01 5.15.0-94-generic #104-Ubuntu SMP x86_64 GNU/Linux\r\n",
        "ls": b"backups.tar.gz  database.sql  deploy.sh  index.php  wp-config.php\r\n",
        "dir": b"backups.tar.gz  database.sql  deploy.sh  index.php  wp-config.php\r\n",
        "ps": b"  PID TTY          TIME CMD\r\n 1021 pts/0    00:00:00 bash\r\n 1177 pts/0    00:00:00 sshd\r\n",
        "env": b"SHELL=/bin/bash\r\nUSER=root\r\nHOME=/root\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n",
        "history": b"  1  cd /var/www/html\r\n  2  nano wp-config.php\r\n  3  systemctl restart nginx\r\n",
    }

    if executable in {"exit", "logout"}:
        return b"logout\r\n", True
    if executable in responses:
        return responses[executable], False
    if executable == "cat":
        target = " ".join(parts[1:]) if len(parts) > 1 else ""
        if target in {"/etc/passwd", "etc/passwd"}:
            return b"root:x:0:0:root:/root:/bin/bash\r\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n", False
        if target in {"wp-config.php", "/var/www/html/wp-config.php"}:
            return b"define('DB_NAME', 'wordpress');\r\ndefine('DB_USER', 'wp_user');\r\ndefine('DB_PASSWORD', 'REDACTED');\r\n", False
        return f"cat: {target}: Permission denied\r\n".encode(), False
    if executable in {"wget", "curl"}:
        return b"Resolving host... connected. Saving to: 'index.html'\r\n100%[===================>]  12.4K  --.-KB/s    in 0.01s\r\n", False
    if executable in {"sudo", "su"}:
        return b"root is already privileged on this host\r\n", False
    return f"bash: {command}: command not found\r\n".encode(), False


def _run_exec(channel: paramiko.Channel, addr: tuple[str, int], command: str) -> None:
    _log_from_thread(addr[0], "command", {"command": command, "mode": "exec"})
    response, _ = command_response(command.strip())
    channel.send(response)
    channel.send_exit_status(0)


def handle_ssh_client(client: socket.socket, addr: tuple[str, int]) -> None:
    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
    transport.add_server_key(HOST_KEY)
    server = FakeShell(addr)

    try:
        transport.start_server(server=server)
        channel = transport.accept(settings.ssh_channel_timeout)
        if channel is None:
            return

        wait_step = 0.05
        waited = 0.0
        while not server.shell_requested.is_set() and server.exec_command is None and waited < settings.ssh_channel_timeout:
            if not transport.is_active():
                return
            time.sleep(wait_step)
            waited += wait_step
        if not server.shell_requested.is_set() and server.exec_command is None:
            return

        if server.exec_command is not None:
            _run_exec(channel, addr, server.exec_command)
            return
        _run_shell(channel, addr)
    except (OSError, EOFError, paramiko.SSHException) as exc:
        _log_from_thread(addr[0], "connection_error", {"error": str(exc)})
    finally:
        transport.close()


def _run_shell(channel: paramiko.Channel, addr: tuple[str, int]) -> None:
    channel.send(WELCOME)
    channel.send(PROMPT)
    buffer = ""
    while True:
        char = channel.recv(1)
        if not char:
            break
        if char in {b"\r", b"\n"}:
            command = buffer.strip()
            channel.send(b"\r\n")
            if command:
                _log_from_thread(addr[0], "command", {"command": command, "mode": "shell"})
                response, should_close = command_response(command)
                channel.send(response)
                if should_close:
                    break
            buffer = ""
            channel.send(PROMPT)
        elif char == b"\x7f":
            if buffer:
                buffer = buffer[:-1]
                channel.send(b"\b \b")
        elif char == b"\x03":
            buffer = ""
            channel.send(b"^C\r\n")
            channel.send(PROMPT)
        else:
            decoded = char.decode("utf-8", errors="ignore")
            if decoded:
                buffer += decoded
                channel.send(char)


def start_ssh_server(host: str = "0.0.0.0", port: int = 2222) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(settings.ssh_backlog)
    print(f"[SSH Honeypot] Listening on {host}:{port}")

    try:
        while True:
            client, addr = sock.accept()
            thread = threading.Thread(target=handle_ssh_client, args=(client, addr), daemon=True)
            thread.start()
    finally:
        sock.close()
