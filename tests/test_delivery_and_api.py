import base64
import subprocess
import sys
from pathlib import Path

from dispatch.client_app import _xor_bytes
from dispatch.db import DispatchDB

from tests.conftest import login_as


def test_script_interface_is_off_until_enabled(admin_client, isolated_env):
    login_as(admin_client)
    blocked = admin_client.get("/scripts")
    assert blocked.status_code == 403
    blocked_api = admin_client.get("/api/scripts/list")
    assert blocked_api.status_code == 403

    isolated_env["admin_app"].config["script_interface"] = True
    try:
        opened = admin_client.get("/scripts")
        assert opened.status_code == 200
    finally:
        isolated_env["admin_app"].config["script_interface"] = False

    help_text = subprocess.run(
        [sys.executable, "dispatch-server.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_text.returncode == 0
    assert "--enable-script-interface" in help_text.stdout
    assert "--disable-exec" not in help_text.stdout


def test_max_downloads_blocks_further_hits(client_app_client, isolated_env):
    path = isolated_env["upload_path"] + "/capped.txt"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("once")
    db = DispatchDB(isolated_env["db_path"])
    try:
        assert db.upload_file("capped.txt", path, "capped", "admin", 1, None, None, max_downloads=1)
    finally:
        db.close()

    assert client_app_client.get("/capped").status_code == 200
    assert client_app_client.get("/capped").status_code == 302
    db = DispatchDB(isolated_env["db_path"])
    try:
        rows = db.list_file_requests(limit=5)
        listed = db.list_files()
    finally:
        db.close()
    assert rows[0]["result"] == "denied"
    capped = next(item for item in listed if item["alias"] == "capped")
    assert capped["download_count"] == 1
    assert capped["max_downloads"] == 1


def test_covert_upload_and_download(client_app_client):
    login_as(client_app_client, role=4)
    opened = client_app_client.get("/api/v1/health?init=1&filename=note.txt")
    assert opened.status_code == 200
    assert opened.get_json()["status"] == "active"
    key = client_app_client.get_cookie("csrf").value.encode()
    raw = b"hello-covert<EOF>"
    encrypted = base64.b64encode(_xor_bytes(raw, key)).decode()
    done = client_app_client.get("/api/v1/health", query_string={"data": encrypted})
    body = done.get_json()
    assert done.status_code == 200
    assert body["status"] == "complete"
    alias = body["alias"]

    meta = client_app_client.get(f"/api/v1/health?fetch={alias}&init=1")
    assert meta.status_code == 200
    assert meta.get_json()["size"] == len(b"hello-covert")
    key = client_app_client.get_cookie("csrf").value.encode()
    chunk = client_app_client.get(f"/api/v1/health?fetch={alias}&off=0")
    payload = chunk.get_json()
    assert payload["eof"] is True
    restored = _xor_bytes(base64.b64decode(payload["data"]), key)
    assert restored == b"hello-covert"

    anonymous = client_app_client
    # private file without a download-capable identity is rejected
    client_app_client.delete_cookie("token")
    denied = anonymous.get(f"/api/v1/health?fetch={alias}&init=1")
    assert denied.status_code == 401


def test_cradles_include_new_methods(admin_client):
    login_as(admin_client)
    html = admin_client.get("/file/cradles").get_data(as_text=True)
    assert "certutil" in html
    assert "bitsadmin" in html
    assert "Invoke-WebRequest" in html
    assert 'id="ps1_b64"' in html
    assert 'class="language-bash" id="certutil"' in html
    assert 'class="language-bash" id="bitsadmin"' in html
    assert 'class="language-c#" id="iwr"' in html
    assert 'class="language-c#" id="ps1_b64"' in html
    assert "language-bat" not in html
    assert "language-powershell" not in html
    assert "function highlightCradles()" in html
    assert "highlightCradles();" in html
    css = Path("dispatch/static/css/dispatch-theme.css").read_text(encoding="utf-8")
    assert "pre code,\n.hljs" in css
    assert "background: var(--dispatch-code-bg);" in css
    assert 'id="covert_download"' in html
    assert "Bash Curl" in html


def test_admin_api_surface_does_not_crash(admin_client):
    login_as(admin_client)
    pages = [
        "/",
        "/file/upload",
        "/file/create",
        "/file/download",
        "/file/cradles",
        "/settings/admin",
        "/settings/client",
        "/settings/proxy",
        "/settings/log",
        "/settings/activity",
        "/settings/alerts",
        "/users",
        "/user/add",
        "/api/files/list",
        "/api/files/revision",
        "/api/files/minimal-list",
        "/api/files/param-key",
        "/api/files/reload",
        "/api/folders/list",
        "/api/logs/list",
        "/api/alerts",
        "/api/users/list",
        "/api/mfa/status",
    ]
    for path in pages:
        response = admin_client.get(path)
        assert response.status_code < 500, path

    created = admin_client.post(
        "/api/folder/create",
        json={"folder_name": "audit-box", "access": 2},
    )
    assert created.status_code == 200
    assert admin_client.post("/api/files/update-access", json={}).status_code < 500
    assert admin_client.post("/api/webhook/test").status_code < 500
    assert admin_client.get("/api/scripts/list").status_code == 403
    assert admin_client.post("/api/logs/clear").status_code == 200
