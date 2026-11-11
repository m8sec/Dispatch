import os

from dispatch.auth import createToken
from dispatch.db import DispatchDB

from tests.conftest import login_as


def _insert_file(db_path, upload_path, alias, access, filename="payload.txt"):
    full_path = os.path.join(upload_path, filename)
    with open(full_path, "w", encoding="utf-8") as handle:
        handle.write("payload")
    db = DispatchDB(db_path)
    try:
        db.upload_file(filename, full_path, alias, "admin", access, None, None)
    finally:
        db.close()
    return full_path


def _rows(db_path):
    db = DispatchDB(db_path)
    try:
        return db.list_file_requests(limit=50)
    finally:
        db.close()


def test_client_requests_are_logged(client_app_client, isolated_env):
    _insert_file(isolated_env["db_path"], isolated_env["upload_path"], "public-file", 1)
    _insert_file(isolated_env["db_path"], isolated_env["upload_path"], "private-file", 3, "secret.txt")

    missing = client_app_client.get(
        "/does-not-exist",
        headers={"User-Agent": "<img src=x onerror=alert(1)>"},
    )
    assert missing.status_code == 302

    served = client_app_client.get("/public-file")
    assert served.status_code == 200

    denied_auth = client_app_client.get("/private-file")
    assert denied_auth.status_code == 302

    token = createToken({
        "user": "downloader",
        "id": 2,
        "role": 1,
        "role_name": "Download Only",
    })
    client_app_client.set_cookie("token", token)
    authed = client_app_client.get("/private-file")
    assert authed.status_code == 200

    rows = list(reversed(_rows(isolated_env["db_path"])))
    assert [row["result"] for row in rows] == ["not_found", "served", "auth_failure", "served"]
    assert rows[0]["path"] == "does-not-exist"
    assert rows[0]["user_agent"] == "<img src=x onerror=alert(1)>"
    assert rows[0]["auth_method"] == "none"
    assert rows[1]["path"] == "public-file"
    assert rows[2]["result"] == "auth_failure"
    assert rows[3]["username"] == "downloader"
    assert rows[3]["auth_method"] == "session"


def test_ip_block_is_denied(client_app_client, isolated_env):
    app = isolated_env["client_app"]
    app.config["allow_ip"] = ["10.0.0.0/8"]
    try:
        response = client_app_client.get("/anything")
        assert response.status_code == 302
        rows = _rows(isolated_env["db_path"])
        assert rows[0]["result"] == "denied"
    finally:
        app.config["allow_ip"] = []


def test_activity_page_escapes_and_filters(admin_client, isolated_env):
    db = DispatchDB(isolated_env["db_path"])
    try:
        db.add_file_request("safe.txt", "served", "10.0.0.8", "curl/8.0", "alice", "api_key")
        db.add_file_request(
            "<script>alert(1)</script>",
            "auth_failure",
            "10.1.1.1",
            "<img src=x onerror=alert(1)>",
            None,
            "invalid_session",
        )
        db.add_file_request("safe.txt", "served", "10.0.0.8", "curl/8.0", "alice", "api_key")
    finally:
        db.close()

    login_as(admin_client, role=3, username="operator", user_id=5)
    page = admin_client.get("/settings/activity")
    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "Top Requesters" in html
    assert "Top Files" in html
    assert "10.0.0.8" in html
    assert "alice" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html

    filtered = admin_client.get("/settings/activity?result=auth_failure").get_data(as_text=True)
    assert "auth failure" in filtered
    assert "safe.txt" not in filtered
    assert "Auth Failures" in filtered


def test_activity_stream_tails_new_requests(admin_client, isolated_env):
    login_as(admin_client, role=3, username="operator", user_id=5)
    db = DispatchDB(isolated_env["db_path"])
    try:
        db.add_file_request("already.txt", "served", "10.0.0.1", "curl/8.0", "alice", "api_key")
        existing = db.list_file_requests(limit=1)[0]["id"]
        db.add_file_request(
            "<script>alert(1)</script>",
            "not_found",
            "10.9.9.9",
            "<img src=x onerror=alert(1)>",
            None,
            "none",
        )
    finally:
        db.close()

    response = admin_client.get(f"/api/file-requests/stream?since={existing}")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert "event: request" in body
    assert "event: summary" in body
    request_block = next(block for block in body.split("\n\n") if "event: request" in block)
    assert "already.txt" not in request_block
    assert "<script>alert(1)</script>" in request_block
    assert "<img src=x onerror=alert(1)>" in request_block

    snapshot = admin_client.get("/api/file-requests/stream")
    snap = snapshot.get_data(as_text=True)
    assert "event: snapshot" in snap
    assert "already.txt" in snap


def test_activity_stream_requires_operator(admin_client):
    login_as(admin_client, role=2, username="uploader", user_id=6)
    response = admin_client.get("/api/file-requests/stream")
    assert response.status_code == 302


def test_activity_requires_operator(admin_client):
    login_as(admin_client, role=2, username="uploader", user_id=6)
    response = admin_client.get("/settings/activity")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_file_request_table_is_added_to_existing_databases(tmp_path):
    db_path = tmp_path / "legacy.db"
    db = DispatchDB(str(db_path))
    try:
        db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);')
        db.exec("INSERT INTO users (username) VALUES ('kept');")
        assert db.add_file_request("legacy", "not_found", "127.0.0.1", "ua", None, "none")
        names = [row[0] for row in db.exec("SELECT name FROM sqlite_master WHERE type='table';")]
        assert "users" in names
        assert "file_requests" in names
        kept = db.exec("SELECT username FROM users;")
        assert kept[0][0] == "kept"
        rows = db.list_file_requests()
        assert rows[0]["path"] == "legacy"
    finally:
        db.close()


def test_file_request_retention(isolated_env, monkeypatch):
    monkeypatch.setattr(DispatchDB, "FILE_REQUEST_RETENTION", 2)
    db = DispatchDB(isolated_env["db_path"])
    try:
        for name in ("one", "two", "three"):
            assert db.add_file_request(name, "served", "127.0.0.1", "ua", None, "none")
        rows = db.list_file_requests(limit=10)
    finally:
        db.close()
    assert [row["path"] for row in rows] == ["three", "two"]
