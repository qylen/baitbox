from baitbox.servers.ssh_server import command_response


def test_command_response_common_linux_commands():
    response, close = command_response("whoami")
    assert response == b"root\r\n"
    assert close is False

    response, close = command_response("cat /etc/passwd")
    assert b"root:x:0:0" in response
    assert close is False


def test_command_response_exit_closes_session():
    response, close = command_response("exit")
    assert response == b"logout\r\n"
    assert close is True
