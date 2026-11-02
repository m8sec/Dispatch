import os
from pathlib import Path

from dispatch import config
from dispatch.db import DispatchDB

from tests.conftest import login_as


def _seed_file(isolated_env, name="notes.txt", alias="notes-alias", access=3, encrypt=None):
    full_path = os.path.join(isolated_env["upload_path"], name)
    with open(full_path, "w", encoding="utf-8") as handle:
        handle.write("notes")
    db = DispatchDB(isolated_env["db_path"])
    try:
        assert db.upload_file(name, full_path, alias, "admin", access, encrypt, None)
        return db.list_files()[0]
    finally:
        db.close()


def test_api_key_list_is_minimal_and_listing_requires_a_session(admin_client, isolated_env):
    record = _seed_file(isolated_env, encrypt="secret-key")
    db = DispatchDB(isolated_env["db_path"])
    try:
        db.update_key_by_id(1, "dispatch-test-key")
    finally:
        db.close()

    admin_client.delete_cookie(config.COOKIE_NAME)
    headers = {config.API_HEADER: "dispatch-test-key"}
    listed = admin_client.get("/api/files/list", headers=headers)
    assert listed.status_code == 200
    payload = listed.get_json()
    assert payload[0]["id"] == record["id"]
    assert payload[0]["alias"] == "notes-alias"
    assert payload[0]["filename"] == "notes.txt"
    assert "file_path" not in payload[0]
    assert "uploaded_by" not in payload[0]
    assert "ip" not in payload[0]
    assert "encrypt" not in payload[0]
    assert "folder_id" not in payload[0]

    denied = admin_client.get("/api/files/listing", headers=headers)
    assert denied.status_code == 403

    login_as(admin_client)
    rich = admin_client.get("/api/files/listing")
    assert rich.status_code == 200
    body = rich.get_json()
    assert body[0]["file_path"] == record["file_path"]
    assert body[0]["encrypt"] == "secret-key"


def test_listing_can_change_access_and_download_limit(admin_client, isolated_env):
    record = _seed_file(isolated_env)
    login_as(admin_client)
    guid = record["id"]

    changed = admin_client.post("/api/files/update-access", json={"id": guid, "access": 1})
    assert changed.status_code == 200

    limited = admin_client.post("/api/files/download-limit", json={"id": guid, "max_downloads": 2})
    assert limited.status_code == 200
    cleared = admin_client.post("/api/files/download-limit", json={"id": guid, "max_downloads": 0})
    assert cleared.status_code == 200

    db = DispatchDB(isolated_env["db_path"])
    try:
        stored = db.get_file_by_id(guid)
    finally:
        db.close()
    assert stored["access"] == 1
    assert stored["max_downloads"] is None

    by_name = admin_client.get("/file/get/name/notes.txt")
    assert by_name.status_code == 200
    assert by_name.data == b"notes"
    by_alias = admin_client.get("/file/get/alias/notes-alias")
    assert by_alias.status_code == 200


def test_page_links_are_rounded():
    css = Path("dispatch/static/css/dispatch-theme.css").read_text(encoding="utf-8")
    assert "border-radius: 10px !important;" in css
