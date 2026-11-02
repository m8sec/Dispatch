import pytest

from dispatch import config
from dispatch.admin_app import DispatchServer
from dispatch.auth import createToken
from dispatch.client_app import ClientServer
from dispatch.db import DispatchDB


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    db_path = tmp_path / "dispatch.db"
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()
    monkeypatch.setattr(config, "DB_NAME", str(db_path))
    monkeypatch.setattr(config, "FILE_PATH", str(upload_path))

    db = DispatchDB(str(db_path))
    db.setup_db()
    db.close()

    admin_app = DispatchServer.app
    client_app = ClientServer.app
    config_db = DispatchDB(str(db_path))
    try:
        config.refresh_app_configs(config_db, admin_app)
        config.refresh_app_configs(config_db, client_app)
    finally:
        config_db.close()

    admin_app.config["TESTING"] = True
    client_app.config["TESTING"] = True
    return {
        "db_path": str(db_path),
        "upload_path": str(upload_path),
        "admin_app": admin_app,
        "client_app": client_app,
    }


@pytest.fixture
def admin_client(isolated_env):
    return isolated_env["admin_app"].test_client()


@pytest.fixture
def client_app_client(isolated_env):
    return isolated_env["client_app"].test_client()


def login_as(client, role=4, username="admin", user_id=1):
    token = createToken({
        "user": username,
        "id": user_id,
        "role": role,
        "role_name": DispatchDB.user_roles.get(role, "Administrator"),
    })
    client.set_cookie(config.COOKIE_NAME, token)
    return token
