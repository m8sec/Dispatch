from io import BytesIO

from dispatch.admin_app import DispatchServer
from dispatch.db import DispatchDB

from tests.conftest import login_as


def test_login_error_is_escaped(admin_client):
    html = admin_client.post("/login", data={
        "username": "<script>alert(1)</script>",
        "password": "nope",
    }).get_data(as_text=True)
    assert "Login Failed" in html
    assert "<script>alert(1)</script>" not in html


def test_login_template_escapes_message():
    app = DispatchServer.app
    with app.test_request_context("/login"):
        html = app.jinja_env.get_template("login.html").render(
            login_error='<script>alert(1)</script>" onload="alert(2)'
        )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_upload_exception_is_json_encoded(admin_client, monkeypatch):
    login_as(admin_client)

    def explode(self, *args, **kwargs):
        raise Exception('</script><img src=x onerror=alert(1)>')

    monkeypatch.setattr(DispatchDB, "upload_file", explode)
    response = admin_client.post(
        "/file/upload",
        data={"file": (BytesIO(b"hello"), "notes.txt"), "access": "3"},
    )
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "showNotification(" in html
    assert "\\u003c/script\\u003e" in html
    assert "\\u003cimg src=x onerror=alert(1)\\u003e" in html
    assert "<img src=x onerror=alert(1)>" not in html


def test_static_notification_still_renders(admin_client):
    login_as(admin_client)
    html = admin_client.get("/?status=file_deleted").get_data(as_text=True)
    assert 'showNotification("File deleted successfully!", true)' in html
