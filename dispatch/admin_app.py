#!/usr/bin/env python3
import os
import jwt
import shutil
import logging
import requests
import base64
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from json import dumps
from io import BytesIO
from urllib.parse import urlparse
from markupsafe import escape, Markup
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, redirect, render_template, Response, send_file, current_app, abort, url_for

from dispatch import auth
from dispatch import config
from dispatch.db import DispatchDB

try:
    import pyotp
    import qrcode
    MFA_AVAILABLE = True
except ImportError:
    MFA_AVAILABLE = False
log = logging.getLogger('dispatch-logger')
SCRIPT_EXECUTOR = ThreadPoolExecutor(max_workers=4)


def _execute_script_content(script_content, timeout=30):
    import subprocess
    import tempfile
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
            tmp.write(script_content)
            tmp_path = tmp.name

        result = subprocess.run(['python3', tmp_path],
                                capture_output=True,
                                text=True,
                                timeout=timeout)
        output = (result.stdout or '') + (result.stderr or '')
        return output, result.returncode
    except subprocess.TimeoutExpired:
        return 'Script execution timed out (30 seconds)', -1
    finally:
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _can_access_folder(user_role, folder_access):
    return user_role >= max(2, int(folder_access or 2))


def _can_access_admin_file(token, file_data, folder_access_map):
    if not file_data:
        return False

    folder_id = file_data.get('folder_id')
    if folder_id and not _can_access_folder(token.get('role', 0), folder_access_map.get(folder_id, 2)):
        return False

    file_access = file_data.get('access', 3)
    if file_access in [1, 2]:
        return True

    return token.get('role') in {1, 3, 4}


def _serve_admin_file(file_path, download_name, encrypt=False):
    if not os.path.isfile(file_path):
        return abort(404)

    if encrypt:
        with open(file_path, 'rb') as f:
            encrypted_b64 = config.dispatch_native_encrypt(f.read(), encrypt)
            buf = BytesIO(encrypted_b64)
            buf.seek(0)
            return send_file(
                buf,
                download_name=download_name,
                as_attachment=False if request.args.get('raw', type=bool) else True,
                mimetype='text/plain' if request.args.get('raw', type=bool) else None,
                conditional=False,
                max_age=0,
            )

    return send_file(
        file_path,
        download_name=download_name,
        as_attachment=False if request.args.get('raw', type=bool) else True,
        mimetype='text/plain' if request.args.get('raw', type=bool) else None,
        conditional=True,
        max_age=0,
    )


def _sanitize_folder_name(folder_name):
    return config.remove_special(secure_filename((folder_name or '').strip()))


def _safe_folder_name(parent_path, folder_name):
    safe_name = _sanitize_folder_name(folder_name)
    if not safe_name:
        return ''
    return config.file_collision_check(safe_name, base_dir=parent_path)


def _folder_parts(db, folder_id):
    parts = []
    seen = set()
    current_id = folder_id
    while current_id:
        if current_id in seen:
            break
        seen.add(current_id)
        folder = db.get_folder_by_id(current_id)
        if not folder:
            break
        parts.append(folder['folder_name'])
        current_id = folder.get('parent_id')
    return list(reversed(parts))


def _folder_disk_path(db, folder_id):
    parts = _folder_parts(db, folder_id)
    if not parts:
        return config.FILE_PATH
    return os.path.join(config.FILE_PATH, *parts)


def _folder_display_path(db, folder_id):
    parts = _folder_parts(db, folder_id)
    return '/'.join(parts) if parts else 'Root'


def _folder_options(db):
    folders = []
    for folder in db.list_folders():
        folder['path_label'] = _folder_display_path(db, folder['id'])
        folders.append(folder)
    folders.sort(key=lambda folder: folder['path_label'].lower())
    return folders


def _ensure_folder_exists(db, folder_id):
    if not folder_id:
        os.makedirs(config.FILE_PATH, exist_ok=True)
        return config.FILE_PATH

    folder = db.get_folder_by_id(folder_id)
    if not folder:
        raise ValueError('Invalid folder selected')

    folder_path = _folder_disk_path(db, folder_id)
    os.makedirs(folder_path, exist_ok=True)
    return folder_path


def _safe_file_path(base_dir, filename):
    safe_name = secure_filename(filename) or config.gen_filename()
    safe_name = config.remove_special(safe_name)
    name, ext = os.path.splitext(safe_name)
    candidate = safe_name
    counter = 0
    while os.path.exists(os.path.join(base_dir, candidate)):
        counter += 1
        candidate = f'{name}-{counter}{ext}'
    return candidate, os.path.join(base_dir, candidate)


def _update_file_paths_for_folder_tree(db, folder_id):
    prefix_parts = _folder_parts(db, folder_id)
    for file_data in db.list_files():
        file_folder_id = file_data.get('folder_id')
        if not file_folder_id:
            continue
        parts = _folder_parts(db, file_folder_id)
        if parts[:len(prefix_parts)] != prefix_parts:
            continue
        expected_path = os.path.join(config.FILE_PATH, *parts, file_data['filename'])
        if file_data['file_path'] != expected_path:
            db.update_file_storage_by_id(file_data['id'], expected_path, file_folder_id)


def _render_file_form(template_name, token, status_msg=''):
    db = DispatchDB(current_app.config['db_name'])
    try:
        return render_template(
            template_name,
            token=token,
            config=current_app.config,
            status_msg=status_msg,
            folders=_folder_options(db)
        )
    finally:
        db.close()


class DispatchServer(object):
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.secret_key = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE
    app.config['allow_ip'] = []
    app.config['allow_login'] = []
    app.config['redirect_url'] = ''

    @app.route('/', methods=['GET'])
    @auth.login_required
    def index(token, status_msg=''):
        if token.get('role', 0) < 2:
            return redirect(url_for('user_edit', id=token['id']))
        status = request.args.get('status')
        if status == 'file_deleted':
            status_msg = Markup('<script>showNotification("File deleted successfully!", true);</script>')
        elif status == 'file_delete_failed':
            status_msg = Markup('<script>showNotification("Failed to delete file.", false);</script>')
        return render_template('index.html', token=token, config=current_app.config, status_msg=status_msg)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            logging.debug(f'Rejected login attempt from {request.remote_addr} due to login restrictions.')
            return redirect(current_app.config['redirect_url'], 302)

        status = '<div></div>'
        if request.method == 'POST':
            db = DispatchDB(config.DB_NAME)

            # Check if this is an MFA verification step (using signed token instead of session)
            if 'mfa_token' in request.form and 'totp_code' in request.form:
                mfa_token = request.form.get('mfa_token', '')
                totp_code = request.form.get('totp_code', '').strip()
                username = None

                # Verify the MFA pending token
                try:
                    token_data = jwt.decode(mfa_token, config.SECRET_KEY, algorithms=['HS256'])
                    if token_data.get('mfa_pending'):
                        username = token_data.get('username')
                except Exception:
                    pass

                if not username:
                    db.close()
                    status = '<div style="color:red;">Session expired. Please login again.</div>'
                    return render_template('login.html', login_status=Markup(status))

                if MFA_AVAILABLE:
                    user_id = db.get_user_id_by_username(username)
                    totp_secret = db.get_user_totp_secret(user_id)

                    if totp_secret:
                        totp = pyotp.TOTP(totp_secret)
                        # Use valid_window=2 for better tolerance with time drift (allows ~90 seconds)
                        if totp.verify(totp_code, valid_window=2):
                            # MFA verified, complete login
                            user_data = auth.loadUser(db, username)
                            config.log("Web login successful (MFA verified)", user_data, request.remote_addr)

                            if user_data['role'] > 0:
                                jwt_token = auth.createToken(user_data)
                                resp = redirect('/', code=302)
                                resp.set_cookie(config.COOKIE_NAME, value=jwt_token, **config.auth_cookie_settings(request))
                                db.close()
                                return resp
                            else:
                                status = '<div style="color:red;">User disabled</div>'
                        else:
                            status = '<div style="color:red;">Invalid verification code</div>'
                    else:
                        status = '<div style="color:red;">MFA configuration error</div>'
                        db.close()
                        return render_template('login.html', login_status=Markup(status))
                else:
                    status = '<div style="color:red;">MFA not available</div>'
                    db.close()
                    return render_template('login.html', login_status=Markup(status))

                db.close()
                # Generate a new MFA token for retry
                mfa_token = jwt.encode({
                    'username': username,
                    'mfa_pending': True,
                    'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
                }, config.SECRET_KEY, algorithm='HS256')
                return render_template('login_mfa.html', login_status=Markup(status), username=username, mfa_token=mfa_token)

            # Standard username/password login
            if db.validate_login(request.form['username'].lower(), request.form['password']):
                username = request.form['username'].lower()

                # Check if MFA is enabled for this user
                if MFA_AVAILABLE and db.user_has_mfa_enabled(username):
                    # Create a short-lived signed token for MFA verification
                    mfa_token = jwt.encode({
                        'username': username,
                        'mfa_pending': True,
                        'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
                    }, config.SECRET_KEY, algorithm='HS256')
                    db.close()
                    return render_template('login_mfa.html', login_status=Markup('<div></div>'), username=username, mfa_token=mfa_token)

                user_data = auth.loadUser(db, username)
                config.log("Web login successful", user_data, request.remote_addr)

                # Check for user login alerts and reset failed login tracker
                try:
                    from dispatch.alerts import check_user_login_alert, reset_failed_logins
                    check_user_login_alert(config.DB_NAME, user_data['id'], user_data['user'], request.remote_addr)
                    reset_failed_logins(username)
                except Exception:
                    pass

                if user_data['role'] > 0:
                    # Check if MFA is required but not enabled for this user
                    mfa_required = db.get_mfa_required()
                    user_mfa_status = db.get_user_mfa_status(user_data['id'])

                    if MFA_AVAILABLE and mfa_required and not user_mfa_status['mfa_enabled']:
                        # User needs to set up MFA - create token and redirect to MFA setup
                        jwt_token = auth.createToken(user_data)
                        resp = redirect('/user/mfa/enroll', code=302)
                        resp.set_cookie(config.COOKIE_NAME, value=jwt_token, **config.auth_cookie_settings(request))
                        db.close()
                        return resp

                    jwt_token = auth.createToken(user_data)
                    resp = redirect('/', code=302)
                    resp.set_cookie(config.COOKIE_NAME, value=jwt_token, **config.auth_cookie_settings(request))
                    db.close()
                    return resp
                else:
                    status = '<div style="color:red;">User disabled</div>'
            else:
                # Check for failed login alerts
                try:
                    from dispatch.alerts import check_failed_login_alert
                    check_failed_login_alert(config.DB_NAME, request.form['username'].lower(), request.remote_addr)
                except Exception:
                    pass
                status = '<div style="color:red;">Login Failed</div>'
            db.close()
        return render_template('login.html', login_status=Markup(status))

    @app.route('/logout', methods=['GET'])
    def logout():
        return auth.signOut()

    #
    # Settings pages
    #
    @app.route('/settings', methods=['GET'])
    @auth.operator_required
    def settings_redirect(token):
        # Redirect old /settings to new admin page
        return redirect(url_for('admin_settings'))

    @app.route('/settings/admin', methods=['GET', 'POST'])
    @auth.operator_required
    def admin_settings(token):
        db = DispatchDB(current_app.config['db_name'])
        status_msg = Markup('')
        try:
            if request.method == 'POST':
                form_type = request.form.get('form_type')

                if form_type == 'admin_settings':
                    max_size = int(request.form['max_size'])
                    # Update only max_size in settings
                    settings = db.get_settings()
                    db.update_settings(
                        settings['redirect_url'],
                        settings['source_ip'],
                        settings['source_port'],
                        max_size,
                        settings.get('server_header', 'Apache'),
                        settings.get('client_port', 443)
                    )
                    config.log("Admin settings updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Admin settings saved.", true);</script>')

                elif form_type == 'login_restrictions':
                    db.update_allow_login(request.form['allow_login'])
                    config.log("Login restrictions updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Login restrictions saved.", true);</script>')

                elif form_type == 'webhook_settings':
                    webhook_url = request.form.get('webhook_url', '').strip()
                    db.update_webhook_url(webhook_url if webhook_url else None)
                    config.log("Webhook settings updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Webhook settings saved.", true);</script>')

                elif form_type == 'mfa_settings':
                    mfa_required = 'mfa_required' in request.form
                    db.set_mfa_required(mfa_required)
                    config.log(f"MFA requirement {'enabled' if mfa_required else 'disabled'}", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("MFA settings saved.", true);</script>')

                config.refresh_app_configs(db, current_app)

            return render_template('settings/admin.html', token=token, config=current_app.config, status_msg=status_msg)
        except Exception as e:
            logging.error(f"Error updating admin settings: {e}")
            status_msg = Markup('<script>showNotification("Failed to save settings.", false);</script>')
            return render_template('settings/admin.html', token=token, config=current_app.config, status_msg=status_msg)
        finally:
            db.close()

    @app.route('/settings/client', methods=['GET', 'POST'])
    @auth.operator_required
    def client_settings(token):
        db = DispatchDB(current_app.config['db_name'])
        status_msg = Markup('')
        try:
            if request.method == 'POST':
                form_type = request.form.get('form_type')

                if form_type == 'client_status':
                    client_enabled = 'client_enabled' in request.form
                    db.update_client_enabled(client_enabled)
                    config.log(f"Client interface {'enabled' if client_enabled else 'disabled'}", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Client interface status saved.", true);</script>')

                elif form_type == 'network_settings':
                    source_ip = request.form['source_ip']
                    client_port = int(request.form['client_port'])
                    redirect_url = request.form['redirect_url']
                    settings = db.get_settings()
                    db.update_settings(
                        redirect_url,
                        source_ip,
                        settings['source_port'],  # Keep existing admin port
                        settings['max_file_size'],
                        settings.get('server_header', 'Apache'),
                        client_port
                    )
                    config.log("Network settings updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Network settings saved.", true);</script>')

                elif form_type == 'response_headers':
                    header_names = request.form.getlist('header_name[]')
                    header_values = request.form.getlist('header_value[]')
                    headers = {name: value for name, value in zip(header_names, header_values) if name and value}
                    db.update_response_headers(headers)
                    config.log("Response headers updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Response headers saved.", true);</script>')

                elif form_type == 'access_control':
                    allow_ip = request.form['allow_ip']
                    allow_ua = request.form['allow_ua']
                    param_rotation = int(request.form['param_rotation'])

                    db.update_allow_address(allow_ip)
                    db.update_allow_agent(allow_ua)

                    if current_app.config['param_rotation'] == 0 and param_rotation == 1:
                        db.enable_param_key()
                        current_app.config['param_rotation'] = 1
                        update_param_key(db)
                    elif current_app.config['param_rotation'] == 1 and param_rotation == 0:
                        db.disable_param_key()

                    config.log("Access control updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Access control saved.", true);</script>')

                config.refresh_app_configs(db, current_app)

            response_headers = db.get_response_headers()
            return render_template('settings/client.html', token=token, config=current_app.config, response_headers=response_headers, status_msg=status_msg)
        except Exception as e:
            logging.error(f"Error updating client settings: {e}")
            status_msg = Markup('<script>showNotification("Failed to save settings.", false);</script>')
            response_headers = db.get_response_headers()
            return render_template('settings/client.html', token=token, config=current_app.config, response_headers=response_headers, status_msg=status_msg)
        finally:
            db.close()

    @app.route('/settings/proxy', methods=['GET', 'POST'])
    @auth.operator_required
    def c2_redirectors(token):
        db = DispatchDB(current_app.config['db_name'])
        status_msg = Markup('')
        try:
            if request.method == 'POST':
                form_type = request.form.get('form_type')

                if form_type == 'proxy_status':
                    proxy_enabled = 'proxy_enabled' in request.form
                    db.update_proxy_enabled(proxy_enabled)
                    config.log(f"Reverse proxy {'enabled' if proxy_enabled else 'disabled'}", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Reverse proxy status saved.", true);</script>')
                else:
                    # Convert form data to dictionary {path: redirect}
                    paths = request.form.getlist("path[]")  # Extract paths
                    redirects = request.form.getlist("redirect[]")  # Extract redirect URLs
                    route_dict = {path: redirect for path, redirect in zip(paths, redirects)}

                    # Update DB
                    db.update_proxy_routes(route_dict)
                    config.log(f"Reverse proxy routes updated", token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Proxy routes saved.", true);</script>')

                config.refresh_app_configs(db, current_app)

            routes = db.load_proxy_routes()
            return render_template('settings/proxy.html', token=token, routes=routes, config=current_app.config, status_msg=status_msg)
        except Exception as e:
            logging.error(f"Error updating proxy settings: {e}")
            status_msg = Markup('<script>showNotification("Failed to save proxy settings.", false);</script>')
            routes = db.load_proxy_routes()
            return render_template('settings/proxy.html', token=token, routes=routes, config=current_app.config, status_msg=status_msg)
        finally:
            db.close()

    @app.route('/settings/log', methods=['GET'])
    @auth.operator_required
    def dispatch_log(token):
        return render_template('settings/log_modern.html', token=token, config=current_app.config)

    @app.route('/api/logs/list', methods=['GET'])
    @auth.operator_required
    def api_list_logs(token):
        """Get log entries from database"""
        try:
            db = DispatchDB(current_app.config['db_name'])
            limit = int(request.args.get('limit', 100))

            # Get logs from database
            logs = db.list_logs(limit=limit)
            db.close()

            return Response(response=dumps(logs), status=200, mimetype='application/json')

        except Exception as e:
            logging.error(f"Error reading logs: {e}")
            return Response(response=dumps([]), status=200, mimetype='application/json')

    @app.route('/api/logs/clear', methods=['POST'])
    @auth.admin_required
    def api_clear_logs(token):
        """Clear all log entries from database - requires admin"""
        try:
            db = DispatchDB(current_app.config['db_name'])
            db.clear_logs()
            db.close()

            # Log the clear action (this will be the first entry after clearing)
            config.log("Logs cleared by administrator", token, request.remote_addr)

            return Response(
                response=dumps({'success': True, 'message': 'Logs cleared successfully'}),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            logging.error(f"Error clearing logs: {e}")
            return Response(
                response=dumps({'success': False, 'message': str(e)}),
                status=500,
                mimetype='application/json'
            )

    # ===== ALERTS CONFIGURATION ROUTES =====

    @app.route('/settings/alerts', methods=['GET'])
    @auth.operator_required
    def settings_alerts(token):
        """Alerts settings page"""
        return render_template('settings/alerts.html', token=token, config=current_app.config)

    @app.route('/api/alerts', methods=['GET'])
    @auth.operator_required
    def api_list_alerts(token):
        """List all configured alerts"""
        try:
            db = DispatchDB(current_app.config['db_name'])
            alerts = db.get_alerts()
            db.close()
            return Response(response=dumps(alerts), status=200, mimetype='application/json')
        except Exception as e:
            logging.error(f"Error listing alerts: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/alerts', methods=['POST'])
    @auth.operator_required
    def api_create_alert(token):
        """Create a new alert"""
        try:
            data = request.get_json()
            alert_type = data.get('alert_type')
            target_id = data.get('target_id')
            target_value = data.get('target_value')
            description = data.get('description', '')

            if not alert_type:
                return Response(response=dumps({'error': 'Alert type required'}), status=400, mimetype='application/json')

            # Auto-generate description if not provided
            if not description:
                db = DispatchDB(current_app.config['db_name'])
                if alert_type == 'user_login' and target_id:
                    user = db.get_user_by_id(target_id)
                    description = f"Alert when user '{user.get('username', 'Unknown')}' logs in"
                elif alert_type == 'file_download' and target_id:
                    file = db.get_file_by_id(target_id)
                    description = f"Alert when file '{file.get('filename', 'Unknown')}' is downloaded"
                elif alert_type == 'failed_logins' and target_value:
                    description = f"Alert after {target_value} failed login attempts"
                elif alert_type == 'ip_monitor' and target_value:
                    description = f"Monitor activity from IP/CIDR: {target_value}"
                db.close()

            db = DispatchDB(current_app.config['db_name'])
            alert_id = db.create_alert(alert_type, target_id, target_value, description)
            db.close()

            if alert_id:
                config.log(f"Created alert: {alert_type}", token, request.remote_addr)
                return Response(response=dumps({'id': alert_id, 'success': True}), status=200, mimetype='application/json')
            else:
                return Response(response=dumps({'error': 'Failed to create alert'}), status=500, mimetype='application/json')
        except Exception as e:
            logging.error(f"Error creating alert: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
    @auth.operator_required
    def api_update_alert(token, alert_id):
        """Update alert enabled status"""
        try:
            data = request.get_json()
            enabled = data.get('enabled', 1)

            db = DispatchDB(current_app.config['db_name'])
            db.update_alert(alert_id, enabled)
            db.close()

            return Response(response=dumps({'success': True}), status=200, mimetype='application/json')
        except Exception as e:
            logging.error(f"Error updating alert: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
    @auth.operator_required
    def api_delete_alert(token, alert_id):
        """Delete an alert"""
        try:
            db = DispatchDB(current_app.config['db_name'])
            db.delete_alert(alert_id)
            db.close()

            config.log(f"Deleted alert ID: {alert_id}", token, request.remote_addr)
            return Response(response=dumps({'success': True}), status=200, mimetype='application/json')
        except Exception as e:
            logging.error(f"Error deleting alert: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/webhook/test', methods=['POST'])
    @auth.operator_required
    def api_test_webhook(token):
        """Test webhook connection"""
        try:
            from dispatch.notifications import test_webhook
            success, message = test_webhook(current_app.config['db_name'])
            return Response(
                response=dumps({'success': success, 'message': message}),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            logging.error(f"Error testing webhook: {e}")
            return Response(
                response=dumps({'success': False, 'message': str(e)}),
                status=500,
                mimetype='application/json'
            )

    #
    # File Interactions
    #
    @app.route('/file/cradles', methods=['GET'])
    @auth.upload_only_required
    def documentation_download(token):
        return render_template('files/cradles.html', token=token, config=current_app.config)


    @app.route('/file/upload', methods=['GET', 'POST'])
    @auth.upload_only_required
    def upload_file(token, status_msg=''):
        if request.method == 'POST':
            files = request.files.getlist("file")
            if len(files) == 0 or files[0].filename == '':
                status_msg = Markup('<script>showNotification("No File Selected.", false);</script>')
                return _render_file_form('files/upload.html', token, status_msg)
            
            for f in files:
                db = DispatchDB(current_app.config['db_name'])
                try:
                    folder_id = request.form.get('folder_id', type=int)
                    if config.is_blocked_filename(f.filename):
                        status_msg = Markup('<script>showNotification("Uploading .gitignore is not allowed.", false);</script>')
                        return _render_file_form('files/upload.html', token, status_msg)
                    target_dir = _ensure_folder_exists(db, folder_id)
                    fname, full_path = _safe_file_path(target_dir, f.filename)
                    f.save(full_path)

                    # File access permissions
                    access_id = request.form.get('access', type=int)
                    access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

                    # Generate alias
                    alias = request.form.get('alias', '') if request.form.get('alias', False) else config.gen_alias(config.get_file_extension(fname))
                    alias = config.alias_collision_check(db, alias)

                    # File encryption
                    encrypt = request.form.get('encrypt', '')

                    if not db.upload_file(fname, full_path, alias, token['user'], access, encrypt, folder_id):
                        raise Exception("Database Error")

                except RequestEntityTooLarge:
                    status_msg = Markup('<script>showNotification("File Exceed Max Size.", false);</script>')
                    return _render_file_form('files/upload.html', token, status_msg)

                except Exception as e:
                    status_msg = Markup(f'<script>showNotification("File upload failed: {e}", false);</script>')
                    return _render_file_form('files/upload.html', token, status_msg)
                finally:
                    db.close()
            
            status_msg = Markup('<script>showNotification("File(s) uploaded successfully!");</script>')
            return redirect(url_for('index'))  
        return _render_file_form('files/upload.html', token, status_msg)
        

    @app.route('/file/create', methods=['GET', 'POST'])
    @auth.upload_only_required
    def create_file(token, status_msg=''):
        if request.method == 'POST':
            folder_id = request.form.get('folder_id', type=int)
            fname = request.form['filename'] if request.form['filename'] != '' else config.gen_filename()
            if config.is_blocked_filename(fname):
                status_msg = Markup('<script>showNotification("Creating .gitignore is not allowed.", false);</script>')
                return _render_file_form('files/create.html', token, status_msg)
            db = DispatchDB(current_app.config['db_name'])
            try:
                target_dir = _ensure_folder_exists(db, folder_id)
                fname, full_path = _safe_file_path(target_dir, fname)

                if request.form['file_content']:
                    with open(full_path, 'w') as f:
                        f.write(request.form['file_content'])
                else:
                    status_msg = Markup('<div style="color:red;margin-bottom:8px;">No content provided.</div>')
                    return _render_file_form('files/create.html', token, status_msg)

                access_id = request.form.get('access', type=int)
                access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

                alias = request.form.get('alias', '') if request.form.get('alias', False) else config.gen_alias(config.get_file_extension(fname))
                alias = config.alias_collision_check(db, alias)
                encrypt = request.form.get('encrypt', '')

                if db.upload_file(fname, full_path, alias, token['user'], access, encrypt, folder_id) is not False:
                    return redirect(url_for('index'))
                status_msg = Markup('<script>showNotification("File upload failed.", false);</script>')
            finally:
                db.close()
        return _render_file_form('files/create.html', token, status_msg)

    @app.route('/file/download', methods=['GET', 'POST'])
    @auth.upload_only_required
    def download_file(token, status_msg=''):
        if request.method == 'POST':
            folder_id = request.form.get('folder_id', type=int)
            if request.form['filename']:
                fname = request.form['filename']
            else:
                u = urlparse(request.form['url'])
                fname = os.path.basename(u.path)

            if config.is_blocked_filename(fname):
                status_msg = Markup('<script>showNotification("Creating .gitignore is not allowed.", false);</script>')
                return _render_file_form('files/download.html', token, status_msg)
            db = DispatchDB(current_app.config['db_name'])
            try:
                target_dir = _ensure_folder_exists(db, folder_id)
                fname, full_path = _safe_file_path(target_dir, fname)

                if not config.download_file(request.form['url'], full_path):
                    status_msg = Markup('<div style="color:red;margin-bottom:8px;">Failed to download file.</div>')
                    return _render_file_form('files/download.html', token, status_msg)

                access_id = request.form.get('access', type=int)
                access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

                alias = request.form.get('alias', '') if request.form.get('alias', False) else config.gen_alias(config.get_file_extension(fname))
                alias = config.alias_collision_check(db, alias)
                encrypt = request.form.get('encrypt', '')

                if db.upload_file(fname, full_path, alias, token['user'], access, encrypt, folder_id) is not False:
                    return redirect(url_for('index'))
                status_msg = Markup('<script>showNotification("File upload failed.", false);</script>')
            finally:
                db.close()
        return _render_file_form('files/download.html', token, status_msg)

    @app.route('/file/delete', methods=['GET'])
    @auth.operator_required
    def delete_file(token):
        if 'id' in request.args.keys():
            id = request.args.get('id', type=int)
            db = DispatchDB(current_app.config['db_name'])
            data = db.get_file_by_id(id)
            if data and os.path.exists(data['file_path']):
                db.del_file_by_id(id)
                os.remove(data['file_path'])
                config.log(f"Deleted file: {data['filename']}", token, request.remote_addr)
                db.close()
                return redirect(url_for('index', status='file_deleted'))
            db.close()
            return redirect(url_for('index', status='file_delete_failed'))
        return redirect(url_for('index'))

    @app.route('/file/edit', methods=['GET', 'POST'])
    @auth.upload_only_required
    def edit_file(token):
        if request.method == 'POST':
            db = DispatchDB(current_app.config['db_name'])
            data = db.get_file_by_id(request.form.get('id', type=int))
            og_file_path = data['file_path']
            folder_id = data.get('folder_id')
            folder_dir = _ensure_folder_exists(db, folder_id)

            if request.form['old_filename'] == request.form['filename']:
                fname = request.form['old_filename']
                full_path = og_file_path
            else:
                requested_name = request.form['filename'] if request.form['filename'] != '' else config.gen_filename()
                fname, full_path = _safe_file_path(folder_dir, requested_name)

            # Validate alias
            if request.form['old_alias'] == request.form['alias']:
                alias = request.form['old_alias']
            else:
                alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))

            # File access permissions
            access_id = request.form.get('access', 3, type=int)
            access = access_id if access_id in [1, 2, 3] else 3

            # File encryption
            encrypt = request.form.get('encrypt', '')

            if 'file_content' in request.form.keys():
                if full_path != og_file_path and os.path.exists(og_file_path):
                    os.remove(og_file_path)
                with open(full_path, 'w') as f:
                    f.write(request.form['file_content'])
            elif full_path != og_file_path:
                os.rename(og_file_path, full_path)

            db.update_file_by_id(request.form['id'], fname, full_path, alias, token['user'], access, encrypt, folder_id)
            db.close()
            return redirect(url_for('index'))

        if 'id' in request.args.keys():
            db = DispatchDB(current_app.config['db_name'])
            data = db.get_file_by_id(request.args.get('id', type=int))
            db.close()
            with open(data['file_path'], 'r') as f:
                try:
                    content = f.read()
                except:
                    content = False
                return render_template('files/edit.html', token=token, data=data, content=str(content))
        return redirect(url_for('index'))

    #
    # User Management
    #
    @app.route('/users', methods=['GET', 'POST'])
    @auth.admin_required
    def users(token):
        status = request.args.get('status')
        status_msg = Markup('')

        if request.method == 'POST':
            form_type = request.form.get('form_type')
            if form_type == 'mfa_settings':
                db = DispatchDB(current_app.config['db_name'])
                mfa_required = 'mfa_required' in request.form
                db.set_mfa_required(mfa_required)
                config.refresh_app_configs(db, current_app)
                db.close()
                config.log(f"MFA requirement {'enabled' if mfa_required else 'disabled'}", token, request.remote_addr)
                status_msg = Markup('<script>showNotification("MFA settings saved.", true);</script>')

        if status == 'user_added':
            status_msg = Markup('<script>showNotification("User added successfully.", true);</script>')
        elif status == 'user_deleted':
            status_msg = Markup('<script>showNotification("User deleted successfully.", true);</script>')
        elif status == 'user_delete_failed':
            status_msg = Markup('<script>showNotification("Failed to delete user.", false);</script>')
        elif status == 'last_admin':
            status_msg = Markup('<script>showNotification("Cannot delete the last administrator account.", false);</script>')
        return render_template('users/list.html', token=token, config=current_app.config, status_msg=status_msg)

    @app.route('/user/delete', methods=['GET'])
    @auth.admin_required
    def user_delete(token):
        if 'id' in request.args.keys():
            id = request.args.get('id', type=int)
            if id is not None and id != token['id']:
                db = DispatchDB(current_app.config['db_name'])
                user = db.get_user_by_id(id)

                # Check if we can delete this user (must keep at least one admin)
                if not db.can_disable_admin(id):
                    db.close()
                    return redirect(url_for('users', status='last_admin'))

                if user['role'] < token['role'] or token['role'] > 3:
                    db.del_user_by_id(id)
                    db.close()
                    config.log(f"Deleted user: {user['username']}", token, request.remote_addr)
                    return redirect(url_for('users', status='user_deleted'))
                db.close()
                return redirect(url_for('users', status='user_delete_failed'))
        return redirect(url_for('users', status='user_delete_failed'))

    @app.route('/user/add', methods=['GET', 'POST'])
    @auth.admin_required
    def user_add(token, status_msg=''):
        """
        Access: Private
        Role: 3
        Description: Add new user - operators will only be allowed to add user roles lower than themselves.
        """
        if request.method == 'POST':
            if config.validate_username(request.form['username']):
                if request.form['password'] == request.form['confirm_password'] and config.validate_password(request.form['password']):
                    # Validate Role
                    db = DispatchDB(current_app.config['db_name'])
                    role_id = request.form.get('user_role', type=int)
                    if role_id < token['role'] or token['role'] > 3:
                        # Create New User + Init API Key
                        role = role_id if role_id in [0, 1, 2, 3, 4] else 0
                        db.add_user(request.form.get('username'), request.form.get('password'), role)
                        db.close()
                        config.log(f'New user created: {escape(request.form.get("username"))}', token, request.remote_addr)
                        return redirect(url_for('users', status='user_added'))
                    else:
                        status_msg = Markup('<script>showNotification("Invalid Permissions.", false);</script>')
                else:
                    status_msg = Markup('<script>showNotification("Invalid Inputs.", false);</script>')
            else:
                status_msg = Markup('<script>showNotification("Invalid Username.", false);</script>')
        return render_template('users/add.html', token=token, config=current_app.config, user=False, status_msg=status_msg)

    @app.route('/user/edit', methods=['GET', 'POST'])
    @auth.login_required
    def user_edit(token, status_msg=''):
        """
        Access: Private
        Role: 1
        Description: Edit user - operators will only be allowed to edit user roles lower than themselves.
        """
        if request.method == 'POST':
            db = DispatchDB(current_app.config['db_name'])
            user_id = request.form.get('id', type=int)
            user = db.get_user_by_id(user_id)

            if user['id'] == token['id'] or (token['role'] > 2 and user['role'] < 3) or token['role'] > 3:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if password or confirm_password:
                    if password == confirm_password and config.validate_password(password):
                        db.update_user_password_by_id(user_id, password)
                        config.log(f'Changed password for {user["username"]}', token, request.remote_addr)
                        status_msg = Markup('<script>showNotification("User updated successfully.");</script>')
                    else:
                        status_msg = Markup('<script>showNotification("Invalid Inputs.", false);</script>')
                else:
                    status_msg = Markup('<script>showNotification("User updated successfully.");</script>')
            else:
                status_msg = Markup('<script>showNotification("Invalid Permissions.", false);</script>')
            db.close()
            return render_template('users/add.html', token=token, user=user, status_msg=status_msg)

        if 'id' in request.args.keys():
            db = DispatchDB(current_app.config['db_name'])
            user = db.get_user_by_id(request.args.get('id', type=int))
            if user['id'] == token['id'] or (token['role'] > 2 and user['role'] < 3) or token['role'] > 3:
                db.close()
                return render_template('users/add.html', token=token, user=user, status_msg=status_msg)
            db.close()
        return redirect(url_for('users'))

    @app.route('/api/users/list', methods=['GET'])
    @auth.admin_required
    def api_list_users(token):
        """
        Access: Private
        Role: 3
        Description: List users with permissions of current
        """
        db = DispatchDB(current_app.config['db_name'])
        data = db.list_users(token['id'], token['role'])
        db.close()
        return Response(response=dumps(data), status=200, mimetype='application/json')

    @app.route('/api/users/gen-key', methods=['POST'])
    @auth.login_required
    def user_refresh_api_key(token):
        """
        Access: Private
        Role: 1
        Description: Re-Generate API key
        """
        db = DispatchDB(current_app.config['db_name'])
        try:
            j = request.get_json(force=True)
            data = db.get_user_by_id(int(j['id']))
            if int(j['id']) == token['id'] or token['role'] > 2 and (data['role'] < 3 or token['role'] > 3):
                k = config.gen_api_key()
                db.update_key_by_id(int(j['id']), k)
                config.log(f'Generated API Key for {data["username"]}', token, request.remote_addr)
                return Response(response=dumps({'key': k}), status=200, mimetype='application/json')
        except:
            pass
        finally:
            db.close()
        return abort(403)

    @app.route('/api/user/get-key', methods=['POST'])
    @auth.login_required
    def api_get_user_api_key(token):
        """
        Access: Private
        Role: 1
        Description: Take in current user's JWT token and return api key
        """
        db = DispatchDB(current_app.config['db_name'])
        data = db.get_user_by_id(token['id'])
        db.close()
        if (data['id'] == token['id'] or token['role'] > 3) and (data['role'] < 3 or token['role'] > 3):
            return Response(response=dumps({'key': data['api_key']}), status=200, mimetype='application/json')
        return abort(403)

    @app.route('/api/users/update-role', methods=['POST'])
    @auth.operator_required
    def api_update_user_role(token):
        """
        Access: Private
        Role: 3
        Description: Update user role within permissions of current user
        """
        try:
            j = request.get_json(force=True)
            user_id = int(j['id'])
            new_role = int(j['role'])

            # Check valid inputs
            if user_id and new_role in [0, 1, 2, 3, 4]:
                # Users cannot change themselves
                if user_id != token['id']:
                    # Open database and retrieve target user info
                    db = DispatchDB(current_app.config['db_name'])
                    user = db.get_user_by_id(user_id)

                    # Check if this would remove the last admin
                    if not db.can_change_admin_role(user_id, new_role):
                        db.close()
                        return Response(response=dumps({'error': 'Cannot demote the last administrator'}), status=400, mimetype='application/json')

                    # Target user & role is < current OR admin user
                    if (user['role'] < token['role'] and new_role < token['role']) or token['role'] > 3:
                        db.update_role_by_id(user_id, new_role)
                        db.close()
                        config.log(f'{user["username"]} changed to {DispatchDB.user_roles[new_role]}', token, request.remote_addr)
                        return Response(response=dumps({'200': 'Success'}), status=200, mimetype='application/json')
                return abort(403)
        except Exception as e:
            logging.debug(f"Error updating user role: {e}")
        return abort(403)

    @app.route('/api/users/bulk-update-role', methods=['POST'])
    @auth.operator_required
    def api_bulk_update_user_role(token):
        try:
            j = request.get_json(force=True)
            role = int(j.get('role'))
            user_ids = [int(user_id) for user_id in j.get('ids', [])]
            if role not in [0, 1, 2, 3, 4] or not user_ids:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            updated = 0
            skipped_admin = False
            for user_id in user_ids:
                if user_id == token['id']:
                    continue
                user = db.get_user_by_id(user_id)
                if not user:
                    continue
                # Check if this would remove the last admin
                if not db.can_change_admin_role(user_id, role):
                    skipped_admin = True
                    continue
                if (user['role'] < token['role'] and role < token['role']) or token['role'] > 3:
                    db.update_role_by_id(user_id, role)
                    updated += 1
            db.close()

            if updated:
                config.log(f'Bulk updated {updated} user role(s) to {DispatchDB.user_roles[role]}', token, request.remote_addr)
            response_data = {'updated': updated}
            if skipped_admin:
                response_data['warning'] = 'Some users were skipped to preserve at least one administrator'
            return Response(response=dumps(response_data), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error bulk updating user roles: {e}")
        return abort(403)

    @app.route('/api/users/bulk-delete', methods=['POST'])
    @auth.admin_required
    def api_bulk_delete_users(token):
        try:
            j = request.get_json(force=True)
            user_ids = [int(user_id) for user_id in j.get('ids', [])]
            if not user_ids:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            deleted_users = []
            for user_id in user_ids:
                if user_id == token['id']:
                    continue
                user = db.get_user_by_id(user_id)
                if not user:
                    continue
                # Check if we can delete this user (admin check)
                if not db.can_disable_admin(user_id):
                    continue
                if user['role'] < token['role'] or token['role'] > 3:
                    db.del_user_by_id(user_id)
                    deleted_users.append(user['username'])
            db.close()

            if deleted_users:
                config.log(f"Deleted users: {', '.join(deleted_users)}", token, request.remote_addr)
            return Response(response=dumps({'deleted': len(deleted_users)}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error bulk deleting users: {e}")
        return abort(403)

    #
    # MFA / TOTP Management
    #
    @app.route('/user/mfa', methods=['GET'])
    @auth.login_required
    def user_mfa_setup(token):
        """MFA setup page for current user or specified user"""
        user_id = request.args.get('id', type=int) or token['id']
        db = DispatchDB(current_app.config['db_name'])
        user = db.get_user_by_id(user_id)

        # Permission check: users can only edit their own MFA, or admins can edit others
        if user_id != token['id'] and token['role'] < 4:
            db.close()
            return redirect(url_for('user_mfa_setup'))

        if not MFA_AVAILABLE:
            db.close()
            return render_template('users/mfa.html', token=token, user=user, mfa_available=False,
                                   mfa_status={'mfa_enabled': False, 'has_secret': False},
                                   status_msg=Markup('<script>showNotification("MFA not available. Install pyotp and qrcode packages.", false);</script>'))

        mfa_status = db.get_user_mfa_status(user_id)
        db.close()

        return render_template('users/mfa.html', token=token, user=user, mfa_status=mfa_status,
                               mfa_available=True, status_msg=Markup(''))

    @app.route('/api/mfa/setup', methods=['POST'])
    @auth.login_required
    def api_mfa_setup(token):
        """Generate new TOTP secret and QR code for MFA setup"""
        if not MFA_AVAILABLE:
            return Response(response=dumps({'error': 'MFA not available'}), status=400, mimetype='application/json')

        try:
            j = request.get_json(force=True)
            user_id = j.get('user_id', token['id'])

            # Permission check
            if user_id != token['id'] and token['role'] < 4:
                return abort(403)

            db = DispatchDB(current_app.config['db_name'])
            user = db.get_user_by_id(user_id)

            # Generate new TOTP secret
            secret = pyotp.random_base32()
            db.set_user_totp_secret(user_id, secret)

            # Generate provisioning URI for QR code
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user['username'],
                issuer_name='Dispatch'
            )

            # Generate QR code as base64 image
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")

            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            db.close()

            config.log(f"MFA setup initiated for {user['username']}", token, request.remote_addr)
            return Response(response=dumps({
                'secret': secret,
                'qr_code': f'data:image/png;base64,{qr_base64}'
            }), status=200, mimetype='application/json')

        except Exception as e:
            logging.error(f"Error setting up MFA: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/mfa/verify', methods=['POST'])
    @auth.login_required
    def api_mfa_verify(token):
        """Verify TOTP code and enable MFA"""
        if not MFA_AVAILABLE:
            return Response(response=dumps({'error': 'MFA not available'}), status=400, mimetype='application/json')

        try:
            j = request.get_json(force=True)
            user_id = j.get('user_id', token['id'])
            totp_code = j.get('code', '').strip()

            # Permission check
            if user_id != token['id'] and token['role'] < 4:
                return abort(403)

            if not totp_code:
                return Response(response=dumps({'error': 'Verification code required'}), status=400, mimetype='application/json')

            db = DispatchDB(current_app.config['db_name'])
            secret = db.get_user_totp_secret(user_id)

            if not secret:
                db.close()
                return Response(response=dumps({'error': 'MFA not set up. Generate QR code first.'}), status=400, mimetype='application/json')

            totp = pyotp.TOTP(secret)
            if totp.verify(totp_code, valid_window=1):
                db.enable_user_mfa(user_id)
                user = db.get_user_by_id(user_id)
                db.close()
                config.log(f"MFA enabled for {user['username']}", token, request.remote_addr)
                return Response(response=dumps({'success': True, 'message': 'MFA enabled successfully'}), status=200, mimetype='application/json')
            else:
                db.close()
                return Response(response=dumps({'error': 'Invalid verification code'}), status=400, mimetype='application/json')

        except Exception as e:
            logging.error(f"Error verifying MFA: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/mfa/disable', methods=['POST'])
    @auth.login_required
    def api_mfa_disable(token):
        """Disable MFA for a user"""
        if not MFA_AVAILABLE:
            return Response(response=dumps({'error': 'MFA not available'}), status=400, mimetype='application/json')

        try:
            j = request.get_json(force=True)
            user_id = j.get('user_id', token['id'])

            # Permission check
            if user_id != token['id'] and token['role'] < 4:
                return abort(403)

            db = DispatchDB(current_app.config['db_name'])
            user = db.get_user_by_id(user_id)
            db.disable_user_mfa(user_id)
            db.close()

            config.log(f"MFA disabled for {user['username']}", token, request.remote_addr)
            return Response(response=dumps({'success': True, 'message': 'MFA disabled'}), status=200, mimetype='application/json')

        except Exception as e:
            logging.error(f"Error disabling MFA: {e}")
            return Response(response=dumps({'error': str(e)}), status=500, mimetype='application/json')

    @app.route('/api/mfa/status', methods=['GET'])
    @auth.login_required
    def api_mfa_status(token):
        """Get MFA status for a user"""
        user_id = request.args.get('user_id', type=int) or token['id']

        # Permission check
        if user_id != token['id'] and token['role'] < 4:
            return abort(403)

        db = DispatchDB(current_app.config['db_name'])
        mfa_status = db.get_user_mfa_status(user_id)
        db.close()

        return Response(response=dumps({
            'mfa_enabled': mfa_status['mfa_enabled'],
            'mfa_available': MFA_AVAILABLE
        }), status=200, mimetype='application/json')

    @app.route('/user/mfa/enroll', methods=['GET'])
    @auth.login_required
    def user_mfa_enroll(token):
        """Mandatory MFA enrollment page when MFA is required"""
        if not MFA_AVAILABLE:
            # If MFA packages not available, allow access anyway
            return redirect('/')

        db = DispatchDB(current_app.config['db_name'])
        mfa_status = db.get_user_mfa_status(token['id'])
        mfa_required = db.get_mfa_required()
        user = db.get_user_by_id(token['id'])
        db.close()

        # If user already has MFA enabled or MFA not required, redirect to home
        if mfa_status['mfa_enabled'] or not mfa_required:
            return redirect('/')

        return render_template('users/mfa_enroll.html', token=token, user=user,
                               mfa_status=mfa_status, mfa_available=True)

    @app.route('/api/files/list', methods=['GET'])
    @auth.upload_only_required
    def api_list_files(token):
        db = DispatchDB(current_app.config['db_name'])
        all_files = db.list_files(include_size=True)
        all_folders = db.list_folders()
        user_role = token.get('role', 0)

        # Create folder access map (folder access = minimum role required)
        folder_access_map = {folder['id']: folder['access'] for folder in all_folders}

        # Filter files based on permissions
        filtered_files = []
        for file in all_files:
            # Check if file is in a folder
            folder_id = file.get('folder_id')

            if folder_id:
                # File is in a folder - check folder access (role-based)
                # Folder access levels: 2=Upload Only, 3=Operator, 4=Administrator
                folder_access = folder_access_map.get(folder_id, 2)

                # User must have role >= folder access level to see files in that folder
                if not _can_access_folder(user_role, folder_access):
                    continue

            # File access levels: 1=Public, 2=Public Once, 3=Private
            # Public (1) and Public Once (2) are accessible to all authenticated users
            # Private (3) requires Operator (3) or higher
            file_access = file.get('access', 3)
            if file_access == 3 and user_role < 3:
                continue

            filtered_files.append(file)

        db.close()
        return Response(response=dumps(filtered_files), status=200, mimetype='application/json')
    
    @app.route('/api/files/minimal-list', methods=['GET'])
    @auth.upload_only_required
    def api_minimal_list_files(token):
        # Minimal file listing for low priv users via api
        db = DispatchDB(current_app.config['db_name'])
        data = db.list_files()
        db.close()
        minimal = [{
                "filename": item["filename"],
                "alias": item["alias"],
                "size": item["file_size"],
        }for item in data]
        return Response(response=dumps(minimal), status=200, mimetype='application/json')

    @app.route('/api/files/update-access', methods=['POST'])
    @auth.operator_required
    def api_update_file_access(token):
        try:
            j = request.get_json(force=True)
            if int(j['id']) and int(j['access']) in [1, 2, 3]:
                db = DispatchDB(current_app.config['db_name'])
                db.update_access_by_id(int(j['id']), int(j['access']))
                db.close()
                return Response(response=dumps({'200': 'Success'}), status=200, mimetype='application/json')
        except:
            pass
        return abort(403)

    @app.route('/api/file/upload', methods=['POST'])
    @auth.upload_only_required
    def api_upload_file(token):
        f = request.files['file']
        if f.filename != '':
            if config.is_blocked_filename(f.filename):
                return abort(403)
            folder_id = request.form.get('folder_id', type=int)
            db = None
            try:
                db = DispatchDB(current_app.config['db_name'])
                target_dir = _ensure_folder_exists(db, folder_id)
                fname, full_path = _safe_file_path(target_dir, f.filename)
                f.save(full_path)

                # File access permissions
                access_id = request.form.get('access', type=int)
                access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

                # Encryption setting (0 = no encryption)
                encrypt = request.form.get('encrypt', '')

                # Generate alias
                alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))
                alias = config.alias_collision_check(db, alias)

                # On valid request, send alias URL using client port for file delivery
                param_key = "?" + current_app.config['param_key'] if current_app.config['param_rotation'] else ''
                client_port = current_app.config.get('client_port', 443)
                port_str = '' if client_port == 443 else f':{client_port}'
                alias_url = f'https://{current_app.config["source_ip"]}{port_str}/{alias}{param_key}'

                if db.upload_file(fname, full_path, alias, token['user'], access, encrypt, folder_id) is not False:
                    return Response(response=dumps({'url': alias_url}), status=200, mimetype='application/json')
            except Exception:
                pass
            finally:
                try:
                    db.close()
                except Exception:
                    pass
        return abort(403)

    @app.route('/api/files/param-key', methods=['GET'])
    @auth.login_required
    def api_get_param_key(token):
        db = DispatchDB(current_app.config['db_name'])
        settings = db.get_settings()
        db.close()
        param_key = settings.get('param_key', '') or ''
        param_rotation = int(settings.get('param_rotation', 0) or 0)
        current_app.config['param_key'] = param_key
        current_app.config['param_rotation'] = param_rotation
        key_value = f'?{param_key}' if param_rotation else ''
        return Response(response=dumps({'key': key_value}), status=200, mimetype='application/json')

    @app.route('/api/files/reload', methods=['GET'])
    @auth.operator_required
    def api_reload_files(token):
        """Rescan disk and reconcile with database"""
        db = DispatchDB(current_app.config['db_name'])
        upload_dir = config.FILE_PATH
        os.makedirs(upload_dir, exist_ok=True)

        db_files = db.list_files()
        db_folders = db.list_folders()
        db_file_paths = {os.path.normpath(f['file_path']): f for f in db_files}
        db_folders_by_path = {}
        for folder in db_folders:
            rel_path = os.path.join(*_folder_parts(db, folder['id'])) if folder['id'] else ''
            db_folders_by_path[rel_path] = folder

        disk_files = []
        disk_folder_paths = set()
        added = 0
        removed = 0
        added_folders = 0
        removed_folders = 0

        for root, dirs, files in os.walk(upload_dir):
            rel_dir = os.path.relpath(root, upload_dir)
            rel_dir = '' if rel_dir == '.' else rel_dir
            parent_id = None
            if rel_dir:
                parts = rel_dir.split(os.sep)
                current_parts = []
                for part in parts:
                    current_parts.append(part)
                    current_rel = os.path.join(*current_parts)
                    folder = db_folders_by_path.get(current_rel)
                    if not folder:
                        folder_id = db.create_folder(part, token['user'], parent_id, 2)
                        folder = db.get_folder_by_id(folder_id)
                        db_folders_by_path[current_rel] = folder
                        added_folders += 1
                    parent_id = folder['id']
                disk_folder_paths.add(rel_dir)

            folder_id = db_folders_by_path.get(rel_dir, {}).get('id') if rel_dir else None

            for filename in files:
                if config.is_blocked_filename(filename):
                    continue
                file_path = os.path.normpath(os.path.join(root, filename))
                disk_files.append(file_path)
                if file_path not in db_file_paths:
                    ext = config.get_file_extension(filename)
                    alias = config.alias_collision_check(db, config.gen_alias(ext))
                    db.upload_file(filename, file_path, alias, token['user'], 3, None, folder_id)
                    added += 1

        for file_path, file_info in db_file_paths.items():
            if not os.path.exists(file_path):
                db.del_file_by_id(file_info['id'])
                removed += 1

        for rel_path, folder in sorted(db_folders_by_path.items(), key=lambda item: item[0].count(os.sep), reverse=True):
            if rel_path and rel_path not in disk_folder_paths:
                db.del_folder_by_id(folder['id'])
                removed_folders += 1

        db.close()
        if added > 0 or removed > 0 or added_folders > 0 or removed_folders > 0:
            config.log(
                f"Disk rescan: added {added} files, removed {removed} files, added {added_folders} folders, removed {removed_folders} folders",
                token,
                request.remote_addr
            )
        return Response(
            response=dumps({
                'added': added,
                'removed': removed,
                'added_folders': added_folders,
                'removed_folders': removed_folders,
                'total': len(disk_files)
            }),
            status=200,
            mimetype='application/json'
        )

    #
    # Folder Management API
    #
    @app.route('/api/folders/list', methods=['GET'])
    @auth.upload_only_required
    def api_list_folders(token):
        """List folders accessible to current user based on role"""
        db = DispatchDB(current_app.config['db_name'])
        all_folders = db.list_folders()
        user_role = token.get('role', 0)

        # Filter folders based on user role
        # Folder access levels:
        # 1 = Download Only (role 1+)
        # 2 = Upload Only (role 2+)
        # 3 = Operator (role 3+)
        # 4 = Administrator (role 4+)
        filtered_folders = []
        for folder in all_folders:
            folder_access = folder.get('access', 2)

            # User must have role >= folder access level
            if _can_access_folder(user_role, folder_access):
                folder['path_label'] = _folder_display_path(db, folder['id'])
                filtered_folders.append(folder)

        db.close()
        return Response(response=dumps(filtered_folders), status=200, mimetype='application/json')

    @app.route('/api/folder/create', methods=['POST'])
    @auth.upload_only_required
    def api_create_folder(token):
        """Create a new folder"""
        try:
            j = request.get_json(force=True)
            folder_name = _sanitize_folder_name(j.get('folder_name', ''))
            parent_id = j.get('parent_id', None)
            access = j.get('access', 2)  # Default to Upload Only

            if not folder_name:
                return abort(400)

            # Validate access level (2-4)
            if access not in [2, 3, 4]:
                access = 2

            db = DispatchDB(current_app.config['db_name'])
            parent_path = _ensure_folder_exists(db, parent_id)
            folder_name = _safe_folder_name(parent_path, folder_name)
            if not folder_name:
                db.close()
                return abort(400)
            folder_path = os.path.join(parent_path, folder_name)
            os.makedirs(folder_path, exist_ok=False)
            folder_id = db.create_folder(folder_name, token['user'], parent_id, access)
            db.close()

            if folder_id:
                config.log(f"Created folder: {folder_name} with access level {access}", token, request.remote_addr)
                return Response(response=dumps({'id': folder_id, 'message': 'Folder created'}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error creating folder: {e}")
        return abort(403)

    @app.route('/api/folder/rename', methods=['POST'])
    @auth.operator_required
    def api_rename_folder(token):
        """Rename a folder"""
        try:
            j = request.get_json(force=True)
            folder_id = j.get('id')
            new_name = _sanitize_folder_name(j.get('folder_name', ''))

            if not folder_id or not new_name:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            folder = db.get_folder_by_id(int(folder_id))
            if not folder:
                db.close()
                return abort(404)
            old_path = _folder_disk_path(db, int(folder_id))
            parent_path = _folder_disk_path(db, folder.get('parent_id'))
            if old_path == os.path.join(parent_path, new_name):
                safe_name = new_name
            else:
                safe_name = _safe_folder_name(parent_path, new_name)
            if not safe_name:
                db.close()
                return abort(400)
            new_path = os.path.join(parent_path, safe_name)
            if old_path != new_path:
                os.rename(old_path, new_path)
            result = db.rename_folder(int(folder_id), safe_name)
            _update_file_paths_for_folder_tree(db, int(folder_id))
            db.close()

            if result is not False:
                config.log(f"Renamed folder ID {folder_id} to {safe_name}", token, request.remote_addr)
                return Response(response=dumps({'message': 'Folder renamed'}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error renaming folder: {e}")
        return abort(403)

    @app.route('/api/folder/delete', methods=['POST'])
    @auth.operator_required
    def api_delete_folder(token):
        """Delete a folder"""
        try:
            j = request.get_json(force=True)
            folder_id = j.get('id')

            if not folder_id:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            folder = db.get_folder_by_id(int(folder_id))
            if not folder:
                db.close()
                return abort(404)
            folder_path = _folder_disk_path(db, int(folder_id))
            all_folders = db.list_folders()
            subtree_ids = {int(folder_id)}
            changed = True
            while changed:
                changed = False
                for item in all_folders:
                    if item.get('parent_id') in subtree_ids and item['id'] not in subtree_ids:
                        subtree_ids.add(item['id'])
                        changed = True

            for file_info in db.list_files():
                if file_info.get('folder_id') in subtree_ids:
                    db.del_file_by_id(file_info['id'])

            for child_id in sorted(subtree_ids, key=lambda item: len(_folder_parts(db, item)), reverse=True):
                db.del_folder_by_id(child_id)
            db.close()
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)

            config.log(f"Deleted folder: {folder.get('folder_name', 'Unknown')}", token, request.remote_addr)
            return Response(response=dumps({'message': 'Folder deleted'}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error deleting folder: {e}")
        return abort(403)

    @app.route('/api/folder/move-file', methods=['POST'])
    @auth.operator_required
    def api_move_file_to_folder(token):
        """Move a file to a folder"""
        try:
            j = request.get_json(force=True)
            file_id = j.get('file_id')
            folder_id = j.get('folder_id')  # None for root

            if file_id is None:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            file_data = db.get_file_by_id(int(file_id))
            if not file_data:
                db.close()
                return abort(404)
            if file_data.get('folder_id') == folder_id:
                db.close()
                return Response(response=dumps({'message': 'File already in folder'}), status=200, mimetype='application/json')
            target_dir = _ensure_folder_exists(db, folder_id)
            fname, target_path = _safe_file_path(target_dir, file_data['filename'])
            shutil.move(file_data['file_path'], target_path)
            result = db.update_file_by_id(file_data['id'], fname, target_path, file_data['alias'], token['user'], file_data['access'], file_data['encrypt'], folder_id)
            db.close()

            if result is not False:
                config.log(f"Moved file ID {file_id} to folder {folder_id}", token, request.remote_addr)
                return Response(response=dumps({'message': 'File moved'}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error moving file: {e}")
        return abort(403)

    @app.route('/api/folder/update-access', methods=['POST'])
    @auth.operator_required
    def api_update_folder_access(token):
        """Update folder access permissions - Only Operators and Admins can edit"""
        try:
            j = request.get_json(force=True)
            folder_id = j.get('id')
            access = j.get('access')

            # Validate access level (2-4)
            if not folder_id or access not in [2, 3, 4]:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            result = db.update_folder_access(int(folder_id), int(access))
            db.close()

            if result is not False:
                access_names = {2: 'Upload Only', 3: 'Operator', 4: 'Administrator'}
                config.log(f"Updated folder ID {folder_id} access to {access_names.get(access, access)}", token, request.remote_addr)
                return Response(response=dumps({'message': 'Access updated'}), status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error updating folder access: {e}")
        return abort(403)

    @app.route('/file/get/<int:file_id>', methods=['GET'])
    @auth.login_required
    def admin_download_file_by_id(token, file_id):
        db = DispatchDB(current_app.config['db_name'])
        try:
            file_data = db.get_file_by_id(file_id)
            folder_access_map = {folder['id']: folder['access'] for folder in db.list_folders()}
            if not _can_access_admin_file(token, file_data, folder_access_map):
                return abort(403)

            config.log(f'Admin file access: {file_data["filename"]}', token, request.remote_addr)
            try:
                from dispatch.alerts import check_file_download_alert, check_ip_activity_alert
                check_file_download_alert(current_app.config['db_name'], file_data['id'], file_data['filename'], token.get('user'), request.remote_addr)
                check_ip_activity_alert(current_app.config['db_name'], request.remote_addr, 'download', f'Admin file: {file_data["filename"]}')
            except Exception:
                pass
            return _serve_admin_file(file_data['file_path'], file_data['filename'], encrypt=file_data['encrypt'])
        finally:
            db.close()

    @app.route('/file/get/alias/<path:alias>', methods=['GET'])
    @auth.login_required
    def admin_download_file_by_alias(token, alias):
        db = DispatchDB(current_app.config['db_name'])
        try:
            file_lookup = db.get_file_by_alias(alias)
            if not file_lookup:
                return abort(404)
            file_data = db.get_file_by_id(file_lookup['id'])
            folder_access_map = {folder['id']: folder['access'] for folder in db.list_folders()}
            if not _can_access_admin_file(token, file_data, folder_access_map):
                return abort(403)
            config.log(f'Admin file access: {file_data["filename"]}', token, request.remote_addr)
            try:
                from dispatch.alerts import check_file_download_alert, check_ip_activity_alert
                check_file_download_alert(current_app.config['db_name'], file_data['id'], file_data['filename'], token.get('user'), request.remote_addr)
                check_ip_activity_alert(current_app.config['db_name'], request.remote_addr, 'download', f'Admin file: {file_data["filename"]}')
            except Exception:
                pass
            return _serve_admin_file(file_data['file_path'], file_data['filename'], encrypt=file_data['encrypt'])
        finally:
            db.close()

    #
    # Script Runner Management
    #
    @app.route('/scripts', methods=['GET'])
    @auth.operator_required
    def scripts_page(token):
        if current_app.config.get('disable_exec'):
            return abort(403)
        has_webhook = False
        try:
            db = DispatchDB(current_app.config['db_name'])
            has_webhook = bool(db.get_webhook_url())
            db.close()
        except Exception:
            has_webhook = False
        return render_template('scripts/runner.html', token=token, config=current_app.config, has_webhook=has_webhook)

    @app.route('/api/scripts/list', methods=['GET'])
    @auth.operator_required
    def api_list_scripts(token):
        if current_app.config.get('disable_exec'):
            return abort(403)
        db = DispatchDB(current_app.config['db_name'])
        scripts = db.list_scripts()
        db.close()
        return Response(response=dumps(scripts), status=200, mimetype='application/json')

    @app.route('/api/script/create', methods=['POST'])
    @auth.operator_required
    def api_create_script(token):
        try:
            if current_app.config.get('disable_exec'):
                return abort(403)
            j = request.get_json(force=True)
            name = j.get('name', '').strip()
            description = j.get('description', '')
            script_content = j.get('script_content', '')
            schedule_type = j.get('schedule_type', 'manual')
            schedule_time = j.get('schedule_time')
            schedule_day_of_week = j.get('schedule_day_of_week')
            schedule_day_of_month = j.get('schedule_day_of_month')
            enabled = j.get('enabled', 1)
            # Notification settings
            notify_enabled = j.get('notify_enabled', 0)
            notify_on = j.get('notify_on', 'always')
            notify_skip_blank = 1 if j.get('notify_skip_blank', 1) else 0
            notify_plain = 1 if j.get('notify_plain', 0) else 0
            notify_plain_no_codeblock = 1 if j.get('notify_plain_no_codeblock', 0) else 0

            if not name or not script_content:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            script_id = db.create_script(name, description, script_content, schedule_type,
                                         schedule_time, schedule_day_of_week, schedule_day_of_month,
                                         token['user'], enabled, notify_enabled, None, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock)
            db.close()

            if script_id:
                config.log(f"Created script: {name}", token, request.remote_addr)
                return Response(response=dumps({'id': script_id, 'message': 'Script created'}),
                                status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error creating script: {e}")
        return abort(403)

    @app.route('/api/script/update', methods=['POST'])
    @auth.operator_required
    def api_update_script(token):
        try:
            if current_app.config.get('disable_exec'):
                return abort(403)
            j = request.get_json(force=True)
            script_id = j.get('id')
            name = j.get('name', '').strip()
            description = j.get('description', '')
            script_content = j.get('script_content', '')
            schedule_type = j.get('schedule_type', 'manual')
            schedule_time = j.get('schedule_time')
            schedule_day_of_week = j.get('schedule_day_of_week')
            schedule_day_of_month = j.get('schedule_day_of_month')
            enabled = j.get('enabled', 1)
            # Notification settings
            notify_enabled = j.get('notify_enabled', 0)
            notify_on = j.get('notify_on', 'always')
            notify_skip_blank = 1 if j.get('notify_skip_blank', 1) else 0
            notify_plain = 1 if j.get('notify_plain', 0) else 0
            notify_plain_no_codeblock = 1 if j.get('notify_plain_no_codeblock', 0) else 0

            if not script_id or not name or not script_content:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            result = db.update_script(script_id, name, description, script_content, schedule_type,
                                      schedule_time, schedule_day_of_week, schedule_day_of_month, enabled,
                                      notify_enabled, None, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock)
            db.close()

            if result is not False:
                config.log(f"Updated script: {name}", token, request.remote_addr)
                return Response(response=dumps({'message': 'Script updated'}),
                                status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error updating script: {e}")
        return abort(403)

    @app.route('/api/script/delete', methods=['POST'])
    @auth.operator_required
    def api_delete_script(token):
        try:
            if current_app.config.get('disable_exec'):
                return abort(403)
            j = request.get_json(force=True)
            script_id = j.get('id')

            if not script_id:
                return abort(400)

            db = DispatchDB(current_app.config['db_name'])
            script = db.get_script_by_id(script_id)
            result = db.delete_script(script_id)
            db.close()

            if result is not False:
                config.log(f"Deleted script: {script.get('name', 'Unknown')}", token, request.remote_addr)
                return Response(response=dumps({'message': 'Script deleted'}),
                                status=200, mimetype='application/json')
        except Exception as e:
            logging.debug(f"Error deleting script: {e}")
        return abort(403)

    @app.route('/api/script/execute', methods=['POST'])
    @auth.operator_required
    def api_execute_script(token):
        try:
            if current_app.config.get('disable_exec'):
                return abort(403)
            j = request.get_json(force=True)
            script_id = j.get('id')
            script_content = j.get('script_content', '')
            notify_enabled = 1 if j.get('notify_enabled') else 0
            notify_override = 1 if j.get('notify_override') else 0
            notify_on = j.get('notify_on', 'always')
            notify_skip_blank = 1 if j.get('notify_skip_blank', 1) else 0
            notify_plain = 1 if j.get('notify_plain', 0) else 0
            notify_plain_no_codeblock = 1 if j.get('notify_plain_no_codeblock', 0) else 0
            script_name_override = j.get('script_name')

            if not script_content:
                return Response(response=dumps({
                    'success': False,
                    'output': 'No script content provided',
                    'returncode': -1
                }), status=200, mimetype='application/json')

            future = SCRIPT_EXECUTOR.submit(_execute_script_content, script_content, 30)
            output, returncode = future.result()
            success = returncode == 0

            # Update database and send notifications if script_id provided
            script_name = script_name_override or "Ad-hoc Script"

            if script_id:
                db = DispatchDB(current_app.config['db_name'])
                script = db.get_script_by_id(script_id)
                if script:
                    script_name = script.get('name', script_name)
                    if notify_override == 0 and notify_enabled == 0:
                        notify_enabled = script.get('notify_enabled', 0) == 1
                        notify_on = script.get('notify_on', 'always')
                        notify_skip_blank = script.get('notify_skip_blank', 1)
                        notify_plain = script.get('notify_plain', 0)
                        notify_plain_no_codeblock = script.get('notify_plain_no_codeblock', 0)
                db.update_script_run(script_id, output)
                db.close()

            config.log(f"Executed script ID: {script_id}", token, request.remote_addr)

            # Send notification if enabled
            notify_error = None
            notify_sent = False
            notify_skipped = None
            if notify_enabled:
                try:
                    from dispatch.notifications import send_script_notification, should_notify
                    if notify_skip_blank and not output.strip():
                        notify_skipped = 'Blank output'
                    elif not should_notify(notify_on, success):
                        notify_skipped = 'Notification rule'
                    else:
                        sent = send_script_notification(
                            current_app.config['db_name'],
                            script_name,
                            success,
                            output,
                            notify_plain=bool(notify_plain),
                            notify_plain_no_codeblock=bool(notify_plain_no_codeblock)
                        )
                        notify_sent = bool(sent)
                        if not notify_sent:
                            notify_error = 'Failed to send notification to Discord. Check webhook URL in admin settings.'
                except Exception as notify_error:
                    logging.error(f"Error sending notification: {notify_error}")
                    notify_error = str(notify_error)

            return Response(response=dumps({
                'success': success,
                'output': output,
                'returncode': returncode,
                'notify_error': notify_error,
                'notify_sent': notify_sent,
                'notify_skipped': notify_skipped
            }), status=200, mimetype='application/json')

        except Exception as e:
            logging.error(f"Error executing script: {e}")
            import traceback
            error_output = f'Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}'
            # Send failure notification for errors
            if script_id:
                try:
                    db = DispatchDB(current_app.config['db_name'])
                    script = db.get_script_by_id(script_id)
                    db.close()
                    if script and script.get('notify_enabled') == 1:
                        from dispatch.notifications import send_script_notification, should_notify
                        if (not script.get('notify_skip_blank', 1) or error_output.strip()) and should_notify(script.get('notify_on', 'always'), False):
                            send_script_notification(
                                current_app.config['db_name'],
                                script.get('name', 'Unnamed Script'),
                                False,
                                error_output,
                                notify_plain=bool(script.get('notify_plain', 0)),
                                notify_plain_no_codeblock=bool(script.get('notify_plain_no_codeblock', 0))
                            )
                except:
                    pass
            return Response(response=dumps({
                'success': False,
                'output': error_output,
                'returncode': -1,
                'notify_error': None,
                'notify_sent': False,
                'notify_skipped': None
            }), status=200, mimetype='application/json')

    #
    # Login Protected Resources
    #
    @app.route('/js/dispatch.js', methods=['GET'])
    @auth.login_required
    def js_dispatch(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'js', 'dispatch.js'), download_name=fname, as_attachment=False)

    @app.route('/img/favicon/favicon.ico', methods=['GET'])
    @auth.login_required
    def img_favicon(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'favicon', 'favicon.ico'), download_name=fname, as_attachment=False)

    @app.route('/img/favicon/apple-touch-icon.png', methods=['GET'])
    @auth.login_required
    def img_favicon_apple(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'favicon', 'apple-touch-icon.png'), download_name=fname, as_attachment=False)


    #
    # Error Handling
    #
    @app.errorhandler(400)
    def bad_request(e):
        data = {'400': 'Bad Request'}
        return Response(response=dumps(data), status=400, mimetype='application/json')

    @app.errorhandler(401)
    def unauthorized(e):
        data = {'401': 'Unauthorized'}
        return Response(response=dumps(data), status=401, mimetype='application/json')

    @app.errorhandler(403)
    def forbidden(e):
        data = {'403': 'Forbidden'}
        return Response(response=dumps(data), status=403, mimetype='application/json')

    @app.errorhandler(404)
    def not_found(e):
        data = {'404': 'Page Not Found'}
        return Response(response=dumps(data), status=404, mimetype='application/json')

    @app.errorhandler(500)
    def server_error(e):
        data = {'500': 'Internal Server Error'}
        return Response(response=dumps(data), status=500, mimetype='application/json')

    #
    # Post Request Headers
    #
    @app.after_request
    def add_header(response):
        response.headers['X-Frame-Options'] = "deny"
        # Apply custom response headers from config
        custom_headers = current_app.config.get('response_headers', {})
        for header_name, header_value in custom_headers.items():
            response.headers[header_name] = header_value
        # Fallback to server_header if no custom headers set Server
        if 'Server' not in custom_headers:
            response.headers['Server'] = current_app.config.get('server_header', 'Apache')
        return response

def update_param_key(db):
    """Update param key value"""
    if current_app.config['param_rotation'] == 1:
        new_key = config.gen_param_key()
        db.update_param_key(new_key)
        current_app.config['param_key'] = new_key
