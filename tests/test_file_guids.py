import json
import os

from dispatch.db import DispatchDB, is_file_guid

from tests.conftest import login_as


def test_existing_rows_receive_guids_and_integers_are_rejected(tmp_path):
    db_path = tmp_path / "legacy.db"
    db = DispatchDB(str(db_path))
    try:
        db.exec(
            '''CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                file_path TEXT,
                alias TEXT,
                upload_date TEXT,
                uploaded_by TEXT,
                access INTEGER,
                encrypt TEXT,
                folder_id INTEGER
            );'''
        )
        db.exec(
            "INSERT INTO files (filename, file_path, alias, uploaded_by, access) VALUES (?, ?, ?, ?, ?);",
            ("kept.txt", str(tmp_path / "kept.txt"), "kept", "admin", 3),
        )
        assert db.ensure_file_guids()
        stored = db.exec("SELECT id, guid FROM files;")
        assert stored[0][0] == 1
        assert is_file_guid(stored[0][1])
        assert db.get_file_by_id("1") == {}
        assert db.get_file_by_id(1) == {}
        found = db.get_file_by_id(stored[0][1])
        assert found["id"] == stored[0][1]
        assert found["row_id"] == 1
        assert found["filename"] == "kept.txt"
    finally:
        db.close()


def test_api_uses_guid_and_revision_changes(admin_client, isolated_env):
    login_as(admin_client)
    full_path = os.path.join(isolated_env["upload_path"], "notes.txt")
    with open(full_path, "w", encoding="utf-8") as handle:
        handle.write("notes")

    db = DispatchDB(isolated_env["db_path"])
    try:
        before = db.file_listing_revision()
        assert db.upload_file("notes.txt", full_path, "notes-alias", "admin", 1, None, None)
        after = db.file_listing_revision()
        listed = db.list_files()
    finally:
        db.close()

    assert before != after
    assert len(listed) == 1
    guid = listed[0]["id"]
    assert is_file_guid(guid)
    assert "row_id" not in listed[0]

    payload = json.loads(admin_client.get("/api/files/list").get_data(as_text=True))
    assert payload[0]["id"] == guid
    assert all(is_file_guid(item["id"]) for item in payload)

    revision = json.loads(admin_client.get("/api/files/revision").get_data(as_text=True))
    assert revision["revision"] == after

    missing = admin_client.get("/file/get/1")
    assert missing.status_code == 404
    served = admin_client.get(f"/file/get/{guid}")
    assert served.status_code == 200
    assert served.data == b"notes"

    denied = admin_client.get("/file/delete?id=1", follow_redirects=False)
    assert denied.status_code == 302
    still_there = DispatchDB(isolated_env["db_path"])
    try:
        assert still_there.get_file_by_id(guid)["filename"] == "notes.txt"
    finally:
        still_there.close()

    removed = admin_client.get(f"/file/delete?id={guid}", follow_redirects=False)
    assert removed.headers["Location"].endswith("/?status=file_deleted") or "file_deleted" in removed.headers["Location"]
    gone = DispatchDB(isolated_env["db_path"])
    try:
        assert gone.get_file_by_id(guid) == {}
    finally:
        gone.close()
