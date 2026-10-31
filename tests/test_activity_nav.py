from pathlib import Path

from tests.conftest import login_as


def test_dark_theme_covers_shared_surfaces():
    css = Path("dispatch/static/css/dispatch-theme.css").read_text(encoding="utf-8")
    for selector in (
        'html[data-theme="dark"] .table',
        'html[data-theme="dark"] table.dataTable tbody td',
        'html[data-theme="dark"] table.dataTable tbody tr:nth-of-type(odd) > .sorting_1',
        'html[data-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) > *',
        'html[data-theme="dark"] .form-control',
        'html[data-theme="dark"] .form-control:focus',
        'html[data-theme="dark"] .input-group-text',
        'html[data-theme="dark"] .dropdown-menu',
        'html[data-theme="dark"] .dropdown-menu-arrow::before',
        'html[data-theme="dark"] .hljs',
        'html[data-theme="dark"] .toc-box',
        'html[data-theme="dark"] #sidebar .nav-content a',
        'html[data-theme="dark"] .modal-content',
        'html[data-theme="dark"] .alert-success',
        'html[data-theme="dark"] .warning-box',
        "--bs-table-bg: var(--dispatch-surface)",
        "--dispatch-code-bg",
        "--dispatch-header-bg",
        "--dispatch-success-bg",
        "--dispatch-warning-bg",
    ):
        assert selector in css
    assert "--bs-table-bg: transparent" not in css
    login = Path("dispatch/templates/login.html").read_text(encoding="utf-8")
    master = Path("dispatch/templates/master.html").read_text(encoding="utf-8")
    assert "toggleDispatchTheme" in login
    assert "dispatch-theme.css?v=6" in login
    assert master.count("dispatch-theme.css?v=6") == 2
    assert "localStorage.setItem('dispatch-theme'" in master


def test_alerts_form_stacks_the_submit_button(admin_client):
    login_as(admin_client)
    html = admin_client.get("/settings/alerts").get_data(as_text=True)
    form = html.split('id="alertForm"', 1)[1].split("</form>", 1)[0]
    assert "d-flex flex-column gap-3" in html
    assert "col-md-3" not in form
    assert "col-md-6" not in form
    assert form.index("Alert Type") < form.index("Add Alert")
    assert "w-100" in form


def test_activity_nav_is_under_cradles_for_operators(admin_client):
    login_as(admin_client, role=3, username="operator", user_id=5)
    html = admin_client.get("/").get_data(as_text=True)
    assert html.index("Cradles") < html.index('href="/settings/activity"')
    assert html.index('href="/settings/activity"') < html.index("Administration")
    assert 'href="/settings/alerts"' not in html
    assert "Manage alerts" not in admin_client.get("/settings/activity").get_data(as_text=True)


def test_upload_role_cannot_open_activity(admin_client):
    login_as(admin_client, role=2, username="uploader", user_id=6)
    page = admin_client.get("/")
    assert 'href="/settings/activity"' not in page.get_data(as_text=True)
    denied = admin_client.get("/settings/activity")
    assert denied.status_code == 302
    stream = admin_client.get("/api/file-requests/stream")
    assert stream.status_code == 302


def test_operators_view_activity_but_cannot_edit_alerts(admin_client):
    login_as(admin_client, role=3, username="operator", user_id=5)
    assert admin_client.get("/settings/activity").status_code == 200
    assert admin_client.get("/api/file-requests/stream").status_code == 200
    assert admin_client.get("/settings/alerts").status_code == 302
    assert admin_client.get("/api/alerts").status_code == 302
    created = admin_client.post("/api/alerts", json={"alert_type": "failed_logins", "target_value": "3"})
    assert created.status_code == 302


def test_admins_can_open_alerts_from_activity(admin_client):
    login_as(admin_client, role=4)
    html = admin_client.get("/").get_data(as_text=True)
    assert html.index('href="/settings/activity"') < html.index('href="/settings/alerts"')
    activity = admin_client.get("/settings/activity").get_data(as_text=True)
    assert "Manage alerts" in activity
    assert admin_client.get("/settings/alerts").status_code == 200
