import re

from dispatch.db import DispatchDB

from tests.conftest import login_as


def _folder_select(html):
    match = re.search(r'<select name="folder_id".*?</select>', html, re.S)
    assert match, "upload form is missing the folder select"
    return match.group(0)


def test_upload_defaults_to_current_and_nested_folder(admin_client, isolated_env):
    login_as(admin_client)
    db = DispatchDB(isolated_env["db_path"])
    try:
        parent_id = db.create_folder("ops", "admin")
        child_id = db.create_folder("nested", "admin", parent_id=parent_id)
    finally:
        db.close()

    root_html = admin_client.get("/file/upload").get_data(as_text=True)
    root_select = _folder_select(root_html)
    assert "selected" not in root_select
    assert "Root Directory" in root_select

    parent_html = admin_client.get(f"/file/upload?folder={parent_id}").get_data(as_text=True)
    parent_select = _folder_select(parent_html)
    assert f'value="{parent_id}" selected' in parent_select
    assert ">ops<" in parent_select

    child_html = admin_client.get(f"/file/upload?folder={child_id}").get_data(as_text=True)
    child_select = _folder_select(child_html)
    assert f'value="{child_id}" selected' in child_select
    assert ">ops/nested<" in child_select
    assert f'value="{parent_id}" selected' not in child_select


def test_unknown_folder_stays_at_root(admin_client):
    login_as(admin_client)
    html = admin_client.get("/file/upload?folder=99999").get_data(as_text=True)
    assert "selected" not in _folder_select(html)
