from baitbox.vfs import VirtualFilesystem


def test_vfs_path_normalization() -> None:
    vfs = VirtualFilesystem()
    assert vfs._normalize_path("/root", "deploy.sh") == "/root/deploy.sh"
    assert vfs._normalize_path("/root", "../var/www") == "/var/www"
    assert vfs._normalize_path("/root", "/etc/passwd") == "/etc/passwd"
    assert vfs._normalize_path("/", "root/..") == "/"
    assert vfs._normalize_path("/var/www/html", "../../..") == "/"


def test_vfs_operations() -> None:
    vfs = VirtualFilesystem()
    
    # check initial files
    assert vfs.exists("/root/secrets.txt")
    assert vfs.is_file("/root/secrets.txt")
    assert not vfs.is_dir("/root/secrets.txt")
    
    # read file
    content = vfs.read_file("/root/secrets.txt")
    assert content is not None
    assert b"AWS_ACCESS_KEY_ID" in content
    
    # touch/write file
    assert vfs.write_file("/root/new_file.txt", b"hello world")
    assert vfs.exists("/root/new_file.txt")
    assert vfs.read_file("/root/new_file.txt") == b"hello world"
    
    # make directory
    assert vfs.mkdir("/root/subfolder")
    assert vfs.is_dir("/root/subfolder")
    
    # list directory
    items = vfs.list_dir("/root")
    assert items is not None
    assert "new_file.txt" in items
    assert "subfolder" in items
    
    # remove file
    assert vfs.rm("/root/new_file.txt")
    assert not vfs.exists("/root/new_file.txt")
    
    # remove directory
    assert vfs.rmdir("/root/subfolder")
    assert not vfs.exists("/root/subfolder")
