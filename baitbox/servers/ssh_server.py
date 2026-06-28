"""Paramiko-powered SSH honeypot server."""

from __future__ import annotations

import asyncio
import shlex
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import paramiko

from ..config import settings
from ..db import log_event
from ..pubsub import pubsub
from ..sessions import SSHSession, session_manager

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
        self.username = "root"

    def get_allowed_auths(self, username: str) -> str:
        return "password,keyboard-interactive,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "password": password, "method": "password"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive(self, username: str, submethods: str) -> int:
        self.username = username
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "method": "keyboard-interactive"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.username = username
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


def make_prompt(cwd: str) -> bytes:
    p = cwd
    if p == "/root":
        p = "~"
    return f"root@web-prod-01:{p}# ".encode()


def execute_session_command(session: SSHSession, command: str) -> tuple[bytes, bool]:
    """Return a fake shell response and whether the session should close."""
    command = command.strip()
    session.add_command(command)
    try:
        parts = shlex.split(command, posix=True) if command else []
    except ValueError:
        parts = command.split()
    
    if not parts:
        return b"", False
    
    executable = parts[0]
    args = parts[1:]

    if executable in {"exit", "logout"}:
        return b"logout\r\n", True

    if executable == "pwd":
        return f"{session.cwd}\r\n".encode(), False

    if executable == "whoami":
        return b"root\r\n", False

    if executable == "id":
        return b"uid=0(root) gid=0(root) groups=0(root)\r\n", False

    if executable == "hostname":
        return b"web-prod-01\r\n", False

    if executable == "uname":
        return b"Linux web-prod-01 5.15.0-94-generic #104-Ubuntu SMP x86_64 GNU/Linux\r\n", False

    if executable in {"ls", "dir"}:
        target_dir = session.cwd
        paths = [a for a in args if not a.startswith("-")]
        options = "".join([a[1:] for a in args if a.startswith("-")])
        if paths:
            target_dir = session.vfs._normalize_path(session.cwd, paths[0])

        if not session.vfs.exists(target_dir):
            return f"ls: cannot access '{paths[0]}': No such file or directory\r\n".encode(), False

        if session.vfs.is_file(target_dir):
            return f"{paths[0]}\r\n".encode(), False

        items = session.vfs.list_dir(target_dir)
        if items is None:
            return f"ls: cannot open directory '{target_dir}': Permission denied\r\n".encode(), False

        if "l" in options:
            lines = []
            for item in items:
                item_path = target_dir if target_dir.endswith("/") else target_dir + "/"
                item_path += item
                is_dir = session.vfs.is_dir(item_path)
                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                size = 4096 if is_dir else len(session.vfs.read_file(item_path) or b"")
                lines.append(f"{perm} 1 root root {size:5d} Jun 28 13:42 {item}")
            return ("\r\n".join(lines) + "\r\n").encode(), False
        else:
            return ("  ".join(items) + "\r\n").encode(), False

    if executable == "cd":
        target = args[0] if args else "/root"
        target_dir = session.vfs._normalize_path(session.cwd, target)
        if session.vfs.is_dir(target_dir):
            session.cwd = target_dir
            return b"", False
        elif session.vfs.is_file(target_dir):
            return f"bash: cd: {target}: Not a directory\r\n".encode(), False
        else:
            return f"bash: cd: {target}: No such file or directory\r\n".encode(), False

    if executable == "cat":
        if not args:
            return b"", False
        target = args[0]
        target_path = session.vfs._normalize_path(session.cwd, target)
        if session.vfs.is_file(target_path):
            content = session.vfs.read_file(target_path)
            if content is not None:
                content_str = content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\n", "\r\n")
                return content_str.encode(), False
        elif session.vfs.is_dir(target_path):
            return f"cat: {target}: Is a directory\r\n".encode(), False
        return f"cat: {target}: No such file or directory\r\n".encode(), False

    if executable == "touch":
        if not args:
            return b"touch: missing file operand\r\n", False
        for target in args:
            if target.startswith("-"):
                continue
            target_path = session.vfs._normalize_path(session.cwd, target)
            session.vfs.write_file(target_path, b"")
        return b"", False

    if executable == "mkdir":
        if not args:
            return b"mkdir: missing operand\r\n", False
        for target in args:
            if target.startswith("-"):
                continue
            target_path = session.vfs._normalize_path(session.cwd, target)
            if not session.vfs.mkdir(target_path):
                return f"mkdir: cannot create directory '{target}': File exists or parent directory missing\r\n".encode(), False
        return b"", False

    if executable == "rm":
        if not args:
            return b"rm: missing operand\r\n", False
        recursive = False
        targets = []
        for target in args:
            if target in {"-r", "-rf", "-f"}:
                recursive = True
            else:
                targets.append(target)
        for target in targets:
            target_path = session.vfs._normalize_path(session.cwd, target)
            if session.vfs.is_file(target_path):
                session.vfs.rm(target_path)
            elif session.vfs.is_dir(target_path):
                if recursive:
                    prefix = target_path if target_path.endswith("/") else target_path + "/"
                    keys_to_del = [k for k in session.vfs.fs.keys() if k == target_path or k.startswith(prefix)]
                    for k in keys_to_del:
                        del session.vfs.fs[k]
                else:
                    return f"rm: cannot remove '{target}': Is a directory\r\n".encode(), False
            else:
                return f"rm: cannot remove '{target}': No such file or directory\r\n".encode(), False
        return b"", False

    if executable == "rmdir":
        if not args:
            return b"rmdir: missing operand\r\n", False
        for target in args:
            target_path = session.vfs._normalize_path(session.cwd, target)
            if not session.vfs.rmdir(target_path):
                return f"rmdir: failed to remove '{target}': Directory not empty or does not exist\r\n".encode(), False
        return b"", False

    if executable == "echo":
        raw_cmd = command[5:].strip() if len(command) > 4 else ""
        if ">>" in raw_cmd:
            content_part, file_part = raw_cmd.split(">>", 1)
            append = True
        elif ">" in raw_cmd:
            content_part, file_part = raw_cmd.split(">", 1)
            append = False
        else:
            content_part = raw_cmd
            file_part = ""
            append = False

        content_part = content_part.strip()
        if (content_part.startswith('"') and content_part.endswith('"')) or (content_part.startswith("'") and content_part.endswith("'")):
            content_part = content_part[1:-1]

        if file_part:
            file_name = file_part.strip()
            if (file_name.startswith('"') and file_name.endswith('"')) or (file_name.startswith("'") and file_name.endswith("'")):
                file_name = file_name[1:-1]
            target_path = session.vfs._normalize_path(session.cwd, file_name)
            existing = b""
            if append and session.vfs.is_file(target_path):
                existing = session.vfs.read_file(target_path) or b""
            new_content = existing + content_part.encode() + b"\n"
            if session.vfs.write_file(target_path, new_content):
                return b"", False
            else:
                return f"bash: {file_name}: No such file or directory or target is a directory\r\n".encode(), False
        else:
            return f"{content_part}\r\n".encode(), False

    if executable in {"wget", "curl"}:
        url = args[-1] if args else "index.html"
        filename = url.split("/")[-1] if "/" in url else "index.html"
        if not filename or filename.startswith("-"):
            filename = "index.html"
        target_path = session.vfs._normalize_path(session.cwd, filename)
        fake_payload = f"#!/bin/bash\n# Simulated payload downloaded from {url}\necho 'Error: system architecture not supported'\n".encode()
        session.vfs.write_file(target_path, fake_payload)
        if executable == "wget":
            return f"Connecting to {url}... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: {len(fake_payload)} [text/x-sh]\nSaving to: '{filename}'\n\n100%[===================>] {len(fake_payload)}  --.-KB/s    in 0s\r\n".replace("\n", "\r\n").encode(), False
        else:
            return fake_payload, False

    if executable == "ping":
        if not args:
            return b"ping: missing host operand\r\n", False
        host = args[0]
        ping_lines = [
            f"PING {host} ({host}) 56(84) bytes of data.",
            f"64 bytes from {host}: icmp_seq=1 ttl=64 time=0.032 ms",
            f"64 bytes from {host}: icmp_seq=2 ttl=64 time=0.045 ms",
            f"64 bytes from {host}: icmp_seq=3 ttl=64 time=0.029 ms",
            f"\n--- {host} ping statistics ---",
            "3 packets transmitted, 3 received, 0% packet loss, time 2004ms",
            "rtt min/avg/max/mdev = 0.029/0.035/0.045/0.007 ms"
        ]
        return "\r\n".join(ping_lines).replace("\n", "\r\n").encode() + b"\r\n", False

    if executable == "clear":
        return b"\x1b[2J\x1b[H", False

    if executable in {"sudo", "su"}:
        return b"root is already privileged on this host\r\n", False

    if executable == "env":
        return f"SHELL=/bin/bash\r\nUSER=root\r\nHOME=/root\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nPWD={session.cwd}\r\n".encode(), False

    if executable == "history":
        lines = []
        for i, cmd_info in enumerate(session.commands, 1):
            lines.append(f"  {i}  {cmd_info['command']}")
        return ("\r\n".join(lines) + "\r\n").encode(), False

    if executable == "ps":
        return b"  PID TTY          TIME CMD\r\n 1021 pts/0    00:00:00 bash\r\n 1177 pts/0    00:00:00 sshd\r\n", False

    run_file = ""
    if executable.startswith("./"):
        run_file = executable[2:]
    elif executable in {"sh", "bash"} and args:
        run_file = args[0]

    if run_file:
        file_path = session.vfs._normalize_path(session.cwd, run_file)
        if session.vfs.is_file(file_path):
            content = session.vfs.read_file(file_path) or b""
            if content.startswith(b"#!/"):
                lines = content.decode("utf-8", errors="replace").split("\n")
                output_lines = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    if line.startswith("echo "):
                        echo_str = line[5:].strip()
                        if (echo_str.startswith('"') and echo_str.endswith('"')) or (echo_str.startswith("'") and echo_str.endswith("'")):
                            echo_str = echo_str[1:-1]
                        output_lines.append(echo_str)
                if output_lines:
                    return ("\r\n".join(output_lines) + "\r\n").encode(), False
                return b"", False

    return f"bash: {executable}: command not found\r\n".encode(), False


def _run_exec(channel: paramiko.Channel, session: SSHSession, command: str) -> None:
    _log_from_thread(session.src_ip, "command", {"command": command, "mode": "exec", "session_id": session.session_id})
    response, _ = execute_session_command(session, command)
    channel.send(response)
    channel.send_exit_status(0)


def handle_ssh_client(client: socket.socket, addr: tuple[str, int]) -> None:
    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
    transport.add_server_key(HOST_KEY)
    server = FakeShell(addr)
    session_id = uuid.uuid4().hex

    try:
        transport.start_server(server=server)
        channel = transport.accept(settings.ssh_channel_timeout)
        if channel is None:
            return

        username = getattr(server, "username", "root")
        ssh_session = SSHSession(
            session_id=session_id,
            src_ip=addr[0],
            src_port=addr[1],
            username=username,
            channel=channel,
            transport=transport,
        )
        session_manager.register(ssh_session)

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
            _run_exec(channel, ssh_session, server.exec_command)
            return
        _run_shell(channel, ssh_session)
    except (OSError, EOFError, paramiko.SSHException) as exc:
        _log_from_thread(addr[0], "connection_error", {"error": str(exc)})
    finally:
        session_manager.unregister(session_id)
        transport.close()


def _run_shell(channel: paramiko.Channel, session: SSHSession) -> None:
    channel.send(WELCOME)
    channel.send(make_prompt(session.cwd))
    buffer = ""
    addr = (session.src_ip, session.src_port)
    while True:
        char = channel.recv(1)
        if not char:
            break
        if char in {b"\r", b"\n"}:
            command = buffer.strip()
            channel.send(b"\r\n")
            if command:
                _log_from_thread(addr[0], "command", {"command": command, "mode": "shell", "session_id": session.session_id})
                response, should_close = execute_session_command(session, command)
                channel.send(response)
                if should_close:
                    break
            buffer = ""
            channel.send(make_prompt(session.cwd))
        elif char == b"\x7f":
            if buffer:
                buffer = buffer[:-1]
                channel.send(b"\b \b")
        elif char == b"\x03":
            buffer = ""
            channel.send(b"^C\r\n")
            channel.send(make_prompt(session.cwd))
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
