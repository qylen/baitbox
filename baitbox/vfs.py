"""Stateful Virtual Filesystem (VFS) for the SSH honeypot shell."""

from __future__ import annotations
from typing import Any, Dict, List

class VirtualFilesystem:
    def __init__(self) -> None:
        # A dictionary mapping absolute paths of files to their content (bytes)
        # and directories to True.
        self.fs: Dict[str, Any] = {
            "/": True,
            "/root": True,
            "/root/backups.tar.gz": b"fake tarball data",
            "/root/database.sql": b"-- MySQL dump\n-- Fake Database Schema\nCREATE TABLE users (id int, username varchar(255), password varchar(255));\nINSERT INTO users VALUES (1, 'admin', 'super_secret_password_9921');\n",
            "/root/deploy.sh": b"#!/bin/bash\necho 'Deploying production application...'\nsleep 1\necho 'Compiling assets...'\nsleep 1\necho 'Database migration successful.'\nsleep 1\necho 'Deploy successful!'\n",
            "/root/secrets.txt": b"AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID_12345678\nAWS_SECRET_ACCESS_KEY=mock_aws_secret_access_key_987654321\nSTRIPE_API_KEY=stripe_test_key_placeholder_998877\n",
            "/var": True,
            "/var/www": True,
            "/var/www/html": True,
            "/var/www/html/index.php": b"<?php phpinfo(); ?>",
            "/var/www/html/wp-config.php": b"<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_user');\ndefine('DB_PASSWORD', 'super_secure_wp_pass_129381');\ndefine('DB_HOST', 'localhost');\n",
            "/etc": True,
            "/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\nbin:x:2:2:bin:/bin:/bin/sh\nsys:x:3:3:sys:/dev:/bin/sh\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/bin/sh\nman:x:6:12:man:/var/cache/man:/bin/sh\nlp:x:7:7:lp:/var/spool/lpd:/bin/sh\nmail:x:8:8:mail:/var/mail:/bin/sh\nnews:x:9:9:news:/var/spool/news:/bin/sh\nuucp:x:10:10:uucp:/var/spool/uucp:/bin/sh\nproxy:x:13:13:proxy:/bin:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/bin/sh\nlist:x:38:38:Mailing List Manager:/var/list:/bin/sh\nirc:x:39:39:ircd:/run/ircd:/bin/sh\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\nsystemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:104::/nonexistent:/usr/sbin/nologin\n",
            "/etc/hostname": b"web-prod-01\n",
            "/etc/resolv.conf": b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
            "/tmp": True,
        }

    def _normalize_path(self, cwd: str, path: str) -> str:
        if not path:
            return cwd
        if path.startswith("/"):
            parts = path.split("/")
        else:
            parts = (cwd.split("/") if cwd != "/" else []) + path.split("/")

        stack: List[str] = []
        for p in parts:
            if not p or p == ".":
                continue
            if p == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(p)
        return "/" + "/".join(stack)

    def exists(self, path: str) -> bool:
        return path in self.fs

    def is_dir(self, path: str) -> bool:
        return self.fs.get(path) is True

    def is_file(self, path: str) -> bool:
        return isinstance(self.fs.get(path), bytes)

    def list_dir(self, path: str) -> List[str] | None:
        if not self.is_dir(path):
            return None
        prefix = path if path.endswith("/") else path + "/"
        res = []
        for k in self.fs.keys():
            if k == path:
                continue
            if k.startswith(prefix):
                sub = k[len(prefix):]
                item = sub.split("/")[0]
                if item not in res:
                    res.append(item)
        return sorted(res)

    def read_file(self, path: str) -> bytes | None:
        if self.is_file(path):
            return self.fs[path]
        return None

    def stat(self, path: str) -> dict[str, Any] | None:
        """Return lightweight POSIX-like metadata for a virtual path."""
        if path not in self.fs:
            return None
        is_dir = self.is_dir(path)
        return {
            "path": path,
            "name": path.rstrip("/").split("/")[-1] or "/",
            "type": "directory" if is_dir else "file",
            "size": 4096 if is_dir else len(self.read_file(path) or b""),
            "mode": "drwxr-xr-x" if is_dir else "-rw-r--r--",
        }

    def copy(self, source: str, destination: str) -> bool:
        """Copy a file inside the virtual filesystem."""
        if not self.is_file(source) or self.is_dir(destination):
            return False
        content = self.read_file(source)
        if content is None:
            return False
        return self.write_file(destination, content)

    def move(self, source: str, destination: str) -> bool:
        """Move or rename a file or empty directory inside the virtual filesystem."""
        if source == "/" or source not in self.fs or destination in self.fs:
            return False
        parent = "/".join(destination.split("/")[:-1]) or "/"
        if not self.is_dir(parent):
            return False
        if self.is_file(source):
            self.fs[destination] = self.fs.pop(source)
            return True
        if self.is_dir(source):
            prefix = source if source.endswith("/") else source + "/"
            children = [k for k in self.fs if k != source and k.startswith(prefix)]
            if children:
                return False
            self.fs[destination] = self.fs.pop(source)
            return True
        return False

    def write_file(self, path: str, content: bytes) -> bool:
        parent = "/".join(path.split("/")[:-1])
        if not parent:
            parent = "/"
        if not self.is_dir(parent):
            return False
        if self.is_dir(path):
            return False
        self.fs[path] = content
        return True

    def mkdir(self, path: str) -> bool:
        parent = "/".join(path.split("/")[:-1])
        if not parent:
            parent = "/"
        if not self.is_dir(parent):
            return False
        if path in self.fs:
            return False
        self.fs[path] = True
        return True

    def rm(self, path: str) -> bool:
        if self.is_file(path):
            del self.fs[path]
            return True
        return False

    def rmdir(self, path: str) -> bool:
        if self.is_dir(path):
            prefix = path if path.endswith("/") else path + "/"
            for k in self.fs.keys():
                if k != path and k.startswith(prefix):
                    return False
            del self.fs[path]
            return True
        return False
