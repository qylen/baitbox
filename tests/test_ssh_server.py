from unittest.mock import MagicMock
from baitbox.servers.ssh_server import execute_session_command
from baitbox.sessions import SSHSession
from baitbox.vfs import VirtualFilesystem


def _setup_mock_session() -> MagicMock:
    session = MagicMock(spec=SSHSession)
    session.cwd = "/root"
    session.vfs = VirtualFilesystem()
    session.commands = []
    
    def add_command(cmd: str) -> None:
        session.commands.append({"command": cmd})
    session.add_command = add_command
    return session


def test_execute_session_command_common_linux_commands() -> None:
    session = _setup_mock_session()

    response, close = execute_session_command(session, "whoami")
    assert response == b"root\r\n"
    assert close is False

    response, close = execute_session_command(session, "cat /etc/passwd")
    assert b"root:x:0:0" in response
    assert close is False


def test_execute_session_command_exit_closes_session() -> None:
    session = _setup_mock_session()

    response, close = execute_session_command(session, "exit")
    assert response == b"logout\r\n"
    assert close is True


def test_stateful_cd_and_ls() -> None:
    session = _setup_mock_session()

    # cd /var/www/html
    response, close = execute_session_command(session, "cd /var/www/html")
    assert response == b""
    assert close is False
    assert session.cwd == "/var/www/html"

    # pwd
    response, close = execute_session_command(session, "pwd")
    assert response == b"/var/www/html\r\n"
    assert close is False

    # ls
    response, close = execute_session_command(session, "ls")
    assert b"index.php" in response
    assert b"wp-config.php" in response
    assert close is False


def test_execute_session_command_file_inspection_and_copy_move() -> None:
    session = _setup_mock_session()

    response, close = execute_session_command(session, "stat secrets.txt")
    assert b"File: secrets.txt" in response
    assert close is False

    response, close = execute_session_command(session, "cp secrets.txt /tmp/secrets.copy")
    assert response == b""
    assert session.vfs.exists("/tmp/secrets.copy")
    assert close is False

    response, close = execute_session_command(session, "mv /tmp/secrets.copy /tmp/secrets.moved")
    assert response == b""
    assert session.vfs.exists("/tmp/secrets.moved")
    assert close is False

    response, close = execute_session_command(session, "head -n 1 /tmp/secrets.moved")
    assert b"AWS_ACCESS_KEY_ID" in response
    assert close is False
