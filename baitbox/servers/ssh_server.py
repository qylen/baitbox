import socket
import threading
import paramiko
import asyncio
from ..db import log_event
from ..pubsub import pubsub

# Generate a temporary RSA key for the SSH server on the fly
HOST_KEY = paramiko.RSAKey.generate(2048)

class FakeShell(paramiko.ServerInterface):
    def __init__(self, client_addr):
        self.client_ip = client_addr[0]
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        # Accept ANY password
        asyncio.run(log_event(self.client_ip, "SSH", "auth_attempt", {"username": username, "password": password}))
        asyncio.run(pubsub.publish({"src_ip": self.client_ip, "protocol": "SSH", "event_type": "auth_attempt", "payload": {"username": username, "password": password}}))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_ssh_client(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    
    server = FakeShell(addr)
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        return

    channel = transport.accept(20)
    if channel is None:
        return

    server.event.wait(10)
    if not server.event.is_set():
        transport.close()
        return

    # Fake shell interaction
    try:
        channel.send(b"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)\r\n\r\n")
        channel.send(b"root@web-prod-01:~# ")
        
        buffer = ""
        while True:
            char = channel.recv(1)
            if not char:
                break
            
            # Handle Enter key
            if char == b"\r" or char == b"\n":
                command = buffer.strip()
                channel.send(b"\r\n")
                
                if command:
                    asyncio.run(log_event(addr[0], "SSH", "command", {"command": command}))
                    asyncio.run(pubsub.publish({"src_ip": addr[0], "protocol": "SSH", "event_type": "command", "payload": {"command": command}}))

                    # Fake command responses
                    if command == "exit":
                        channel.send(b"logout\r\n")
                        break
                    elif command == "ls":
                        channel.send(b"backups.tar.gz  database.sql  index.php  wp-config.php\r\n")
                    elif command == "whoami":
                        channel.send(b"root\r\n")
                    elif command.startswith("cat "):
                        channel.send(b"cat: " + command[4:].encode() + b": Permission denied\r\n")
                    elif command.startswith("wget ") or command.startswith("curl "):
                        channel.send(b"Connecting... Connected. Downloading...\r\n")
                    else:
                        channel.send(b"bash: " + command.encode() + b": command not found\r\n")
                
                buffer = ""
                channel.send(b"root@web-prod-01:~# ")
            elif char == b"\x7f": # Backspace
                if len(buffer) > 0:
                    buffer = buffer[:-1]
                    channel.send(b"\b \b")
            else:
                buffer += char.decode("utf-8", errors="ignore")
                channel.send(char)

    except Exception:
        pass
    finally:
        transport.close()

def start_ssh_server(host="0.0.0.0", port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    
    print(f"[SSH Honeypot] Listening on {host}:{port}")
    
    while True:
        client, addr = sock.accept()
        thread = threading.Thread(target=handle_ssh_client, args=(client, addr))
        thread.daemon = True
        thread.start()
