#!/usr/bin/env python3
import os
import logging
import requests
import json
import jwt
import base64
from io import BytesIO
from json import dumps
from flask import Flask, request, redirect, Response, send_file, current_app
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from dispatch import auth
from dispatch import config
from dispatch.db import DispatchDB


def _upload_meta_path(key):
    return os.path.join(config.FILE_PATH, f'.upload_{key}.meta')


def _write_upload_meta(meta_path, meta):
    with open(meta_path, 'w', encoding='utf-8') as f:
        f.write(dumps(meta))


def _read_upload_meta(meta_path):
    if not os.path.isfile(meta_path):
        return None
    try:
        with open(meta_path, encoding='utf-8') as f:
            return json.loads(f.read())
    except Exception:
        return None


def _delete_upload_meta(meta_path):
    try:
        os.remove(meta_path)
    except Exception:
        logging.debug('Failed to remove upload metadata %s', meta_path, exc_info=True)


def _generate_upload_key(num=12):
    return os.urandom(num).hex()


def _request_user_agent():
    try:
        return (request.user_agent.string or '')[:512]
    except Exception:
        logging.debug('Unable to read User-Agent', exc_info=True)
        return (request.headers.get('User-Agent') or '')[:512]


def _client_identity(db):
    """Identify a client for the activity log without refreshing cookies or storing secrets."""
    api_key = request.headers.get(config.API_HEADER)
    if api_key:
        data = db.validate_api_key(api_key)
        if data:
            return data.get('user'), 'api_key'
        return None, 'invalid_api_key'

    raw = request.cookies.get(config.COOKIE_NAME)
    if not raw:
        return None, 'none'
    try:
        data = jwt.decode(raw, config.SECRET_KEY, algorithms=['HS256'])
        return data.get('user'), 'session'
    except Exception:
        logging.debug('Unreadable client session cookie', exc_info=True)
        return None, 'invalid_session'


def _record_file_request(db, path, result, username=None, auth_method='none'):
    try:
        db.add_file_request(
            path=(path or '')[:1024],
            result=result,
            client_ip=request.remote_addr or '',
            user_agent=_request_user_agent(),
            username=username or None,
            auth_method=auth_method or 'none',
        )
    except Exception:
        logging.debug('Failed to record file request', exc_info=True)


def _audit_file_request(path, result):
    """Log a request that is rejected before the main database connection is open."""
    db = None
    try:
        db = DispatchDB(current_app.config['db_name'])
        username, auth_method = _client_identity(db)
        _record_file_request(db, path, result, username, auth_method)
    except Exception:
        logging.debug('Failed to open database for file request log', exc_info=True)
    finally:
        if db:
            db.close()


def _xor_bytes(data, key_bytes):
    key_len = len(key_bytes)
    if key_len == 0:
        return data
    return bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(data))


def _upload_token():
    """Upload role or higher. Does not refresh cookies."""
    raw = auth.validateKey(request) if request.headers.get(config.API_HEADER) else auth.validateToken(request)
    if isinstance(raw, dict) and raw.get('role', 0) >= 2:
        return raw
    return None


def _download_token():
    raw = auth.validateKey(request) if request.headers.get(config.API_HEADER) else auth.validateToken(request)
    if isinstance(raw, dict) and raw.get('role') in {1, 3, 4}:
        return raw
    return None


def _json(payload, status=200, **cookie):
    resp = Response(response=dumps(payload), status=status, mimetype='application/json')
    if cookie:
        resp.set_cookie(cookie['name'], cookie['value'], **config.auth_cookie_settings(request))
    return resp


COVERT_CHUNK = 256


def _covert_fetch():
    """Chunked XOR download on the same benign endpoint as covert upload."""
    alias = request.values.get('fetch', '')
    db = DispatchDB(current_app.config['db_name'])
    try:
        record = db.get_file_by_alias(alias)
        username, auth_method = _client_identity(db)
        if not record or not os.path.isfile(record['file_path']):
            _record_file_request(db, alias or 'fetch', 'not_found', username, auth_method)
            return _json({'error': 'not found'}, 404)
        if record['access'] >= 3:
            token = _download_token()
            if not token:
                _record_file_request(db, alias, 'auth_failure', username, auth_method)
                return _json({'error': 'auth required'}, 401)
            username = token.get('user')
            auth_method = 'api_key' if request.headers.get(config.API_HEADER) else 'session'
        size = os.path.getsize(record['file_path'])
        if request.values.get('init'):
            if not db.consume_download(record['id']):
                _record_file_request(db, alias, 'denied', username, auth_method)
                return _json({'error': 'download limit reached'}, 403)
            key = _generate_upload_key()
            _record_file_request(db, alias, 'served', username, auth_method)
            return _json(
                {'status': 'active', 'size': size, 'chunk': COVERT_CHUNK},
                name='csrf',
                value=key,
            )
        key = request.values.get('key') or request.cookies.get('csrf')
        if not key:
            return _json({'error': 'missing key'}, 400)
        try:
            offset = int(request.values.get('off', 0))
        except (TypeError, ValueError):
            return _json({'error': 'bad offset'}, 400)
        offset = max(offset, 0)
        with open(record['file_path'], 'rb') as handle:
            handle.seek(offset)
            raw = handle.read(COVERT_CHUNK)
        encrypted = base64.b64encode(_xor_bytes(raw, key.encode('utf-8'))).decode('ascii')
        next_off = offset + len(raw)
        return _json({
            'status': 'chunk',
            'data': encrypted,
            'off': offset,
            'next': next_off,
            'eof': next_off >= size,
        })
    finally:
        db.close()


def _covert_upload_body(token):
    cookie_name = 'csrf'  # Default cookie name for upload key
    # Upload files using GET or POST. Chunks are XOR'd and base64'd.
    init = request.values.get('init')
    key = request.values.get('key')
    data = request.values.get('data')

    if init:
        filename = request.values.get('filename') or f'upload_{config.get_timestamp()}.bin'
        filename = secure_filename(filename) or f'upload_{config.get_timestamp()}.bin'
        os.makedirs(config.FILE_PATH, exist_ok=True)

        safe_name = config.file_collision_check(filename)
        key = _generate_upload_key()
        part_name = f'.upload_{key}.part'
        part_path = os.path.join(config.FILE_PATH, part_name)
        meta_path = _upload_meta_path(key)

        with open(part_path, 'wb') as f:
            f.write(b'')


        meta = {
            'filename': safe_name,
            'part_name': part_name,
        }
        _write_upload_meta(meta_path, meta)
        resp = Response(
            response=dumps({'status': 'active'}),
            status=200,
            mimetype='application/json'
        )

        resp.set_cookie("csrf", key, **config.auth_cookie_settings(request))
        resp.set_cookie("_ga", _generate_upload_key(16), **config.auth_cookie_settings(request))
        resp.set_cookie("sid", _generate_upload_key(8), **config.auth_cookie_settings(request))
        return resp

    if not key:
        key = request.cookies.get(cookie_name)

    if not key or data is None:
        return Response(
            response=dumps({'error': 'missing key or data'}),
            status=400,
            mimetype='application/json'
        )

    meta_path = _upload_meta_path(key)
    meta = _read_upload_meta(meta_path)
    if not meta:
        return Response(
            response=dumps({'error': 'invalid key'}),
            status=404,
            mimetype='application/json'
        )

    try:
        encrypted_bytes = base64.b64decode(data, validate=True)
    except Exception:
        return Response(
            response=dumps({'error': 'invalid data encoding'}),
            status=400,
            mimetype='application/json'
        )

    part_path = os.path.join(config.FILE_PATH, meta['part_name'])
    decrypted_bytes = _xor_bytes(encrypted_bytes, key.encode('utf-8'))
    eof_index = decrypted_bytes.find(b'<EOF>')
    chunk = decrypted_bytes if eof_index == -1 else decrypted_bytes[:eof_index]

    with open(part_path, 'ab') as f:
        f.write(chunk)

    if eof_index != -1:
        final_name = config.file_collision_check(meta['filename'])
        final_path = os.path.join(config.FILE_PATH, final_name)
        os.replace(part_path, final_path)
        _delete_upload_meta(meta_path)
        alias = None
        db = DispatchDB(current_app.config['db_name'])
        try:
            alias = config.alias_collision_check(
                db, config.gen_alias(config.get_file_extension(final_name))
            )
            db.upload_file(final_name, final_path, alias, token.get('user') or 'covert', 3, None, None)
        finally:
            db.close()
        return Response(
            response=dumps({'status': 'complete', 'alias': alias, 'filename': final_name}),
            status=200,
            mimetype='application/json'
        )

    return Response(
        response=dumps({'status': 'partial', 'bytes': len(chunk)}),
        status=200,
        mimetype='application/json'
    )



class ClientServer:
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.secret_key = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE
    app.config['allow_ip'] = []
    app.config['allow_ua'] = []
    app.config['redirect_url'] = ''
    app.config['param_key'] = ''
    app.config['param_rotation'] = 0
    app.config['client_enabled'] = 1
    app.config['proxy_enabled'] = 0

    #
    # Client API Routes
    #
    @app.route('/', methods=['GET', 'POST', 'OPTIONS'])
    def client_root():
        return redirect(current_app.config['redirect_url'], 302)

    @app.route('/api/v1/health', methods=['GET', 'POST'])
    def rest_api_health():
        if request.values.get('fetch'):
            return _covert_fetch()
        token = _upload_token()
        if not token:
            return Response(
                response=dumps({'error': 'auth required'}),
                status=401,
                mimetype='application/json',
            )
        return _covert_upload_body(token)

    #
    # Primary Ruleset for Redirection
    #
    @app.route('/<path:path>', methods=['GET', 'POST', 'OPTIONS'])
    def catch_all(path):
        #
        # Validate client interface is enabled
        #
        if not current_app.config.get('client_enabled', 1):
            logging.debug(f'Rejected "{path}" - client interface is disabled')
            _audit_file_request(path, 'denied')
            return redirect(current_app.config['redirect_url'], 302)

        #
        # Safety checks
        #
        if is_blocked_by_ip(request.remote_addr):
            logging.debug(f'Rejected "{path}" due to blocked IP: {request.remote_addr}')
            # Check for IP monitor alert on blocked access
            try:
                from dispatch.alerts import check_ip_activity_alert
                check_ip_activity_alert(current_app.config['db_name'], request.remote_addr, 'blocked', 'IP allowlist violation')
            except Exception:
                logging.debug('IP activity alert failed', exc_info=True)
            _audit_file_request(path, 'denied')
            return redirect(current_app.config['redirect_url'], 302)

        if is_blocked_by_user_agent(request.user_agent.string):
            logging.debug(f'Rejected "{path}" due to blocked User-Agent: "{request.user_agent}"')
            _audit_file_request(path, 'denied')
            return redirect(current_app.config['redirect_url'], 302)

        db = None
        try:
            db = DispatchDB(current_app.config['db_name'])

            #
            # Serve reverse proxy (only if enabled)
            #
            if current_app.config.get('proxy_enabled', 0):
                redirect_path = db.lookup_proxy_route(request.path)
                if redirect_path:
                    return reverse_proxy(redirect_path)

            settings = db.get_settings()

            #
            # Param Key checked after proxy
            #
            if is_invalid_param_key(request.full_path, settings):
                logging.debug(f'Rejected "{path}" due to invalid param key.')
                username, auth_method = _client_identity(db)
                _record_file_request(db, path, 'denied', username, auth_method)
                return redirect(current_app.config['redirect_url'], 302)

            #
            # Serve Files
            #
            data = db.get_file_by_alias(path)
            username, auth_method = _client_identity(db)
            if not data:
                _record_file_request(db, path, 'not_found', username, auth_method)
                return redirect(current_app.config['redirect_url'], 302)

            # Public & Public Once files
            if data['access'] < 3:
                if not os.path.isfile(data['file_path']):
                    _record_file_request(db, path, 'not_found', username, auth_method)
                    return redirect(current_app.config['redirect_url'], 302)

                if not db.consume_download(data['id']):
                    _record_file_request(db, path, 'denied', username, auth_method)
                    return redirect(current_app.config['redirect_url'], 302)

                if data['access'] == 2:
                    # "Public Once" files revert to private
                    db.update_access_by_id(data['id'], 3)

                update_param_key(db, settings)
                config.log(f'Accessed File: {path}', False, request.remote_addr)

                # Check for file download and IP monitor alerts
                try:
                    from dispatch.alerts import check_file_download_alert, check_ip_activity_alert
                    check_file_download_alert(current_app.config['db_name'], data['row_id'], path, None, request.remote_addr)
                    check_ip_activity_alert(current_app.config['db_name'], request.remote_addr, 'download', f'File: {path}')
                except Exception:
                    logging.debug('File download alert failed', exc_info=True)

                _record_file_request(db, path, 'served', username, auth_method)
                return serve_file(data['file_path'], path, encrypt=data['encrypt'])

            # Check authentication (API Key or JWT Token)
            token = (
                auth.validateKey(request)
                if request.headers.get(config.API_HEADER)
                else auth.validateToken(request)
            )

            # Allow only users with role 1 (Download), 3, or 4 (Admin)
            if isinstance(token, dict) and token.get('role') in {1, 3, 4}:
                if not os.path.isfile(data['file_path']):
                    _record_file_request(db, path, 'not_found', token.get('user'), auth_method)
                    return redirect(current_app.config['redirect_url'], 302)

                if not db.consume_download(data['id']):
                    _record_file_request(db, path, 'denied', token.get('user'), auth_method)
                    return redirect(current_app.config['redirect_url'], 302)

                update_param_key(db, settings)
                config.log(f'Accessed File: {path}', token, request.remote_addr)

                # Check for file download and IP monitor alerts
                try:
                    from dispatch.alerts import check_file_download_alert, check_ip_activity_alert
                    served_user = token.get('user', None)
                    check_file_download_alert(current_app.config['db_name'], data['row_id'], path, served_user, request.remote_addr)
                    check_ip_activity_alert(current_app.config['db_name'], request.remote_addr, 'download', f'File: {path}')
                except Exception:
                    logging.debug('File download alert failed', exc_info=True)

                served_method = 'api_key' if request.headers.get(config.API_HEADER) else 'session'
                _record_file_request(db, path, 'served', token.get('user'), served_method)
                return serve_file(data['file_path'], path, encrypt=data['encrypt'])

            # Catch all bad traffic
            _record_file_request(db, path, 'auth_failure', username, auth_method)
            return redirect(current_app.config['redirect_url'], 302)
        finally:
            if db:
                db.close()

    #
    # Post Request Headers
    #
    @app.after_request
    def add_header(response):
        auth.apply_refreshed_token(response)
        response.headers['X-Frame-Options'] = "deny"
        # Apply custom response headers from config
        custom_headers = current_app.config.get('response_headers', {})
        for header_name, header_value in custom_headers.items():
            response.headers[header_name] = header_value
        # Fallback to server_header if no custom headers set Server
        if 'Server' not in custom_headers:
            response.headers['Server'] = current_app.config.get('server_header', 'Apache')
        return response

    @app.errorhandler(Exception)
    def client_all_errors(e):
        return redirect(current_app.config['redirect_url'], 302)


#
# Page Protection
#
def is_blocked_by_ip(ip):
    """Check if request source IP is allowed."""
    allowed_ips = current_app.config.get('allow_ip', [])
    return not config.allowlist_match(allowed_ips, ip, request.host)


def is_blocked_by_user_agent(user_agent):
    """Check if User-Agent is allowed."""
    allowed_ua = current_app.config.get('allow_ua', [])
    return allowed_ua and user_agent not in allowed_ua


def is_invalid_param_key(request_path, settings=None):
    """Check if parameter key rotation is enabled and valid."""
    param_rotation = current_app.config.get('param_rotation', 0)
    param_key = current_app.config.get('param_key', '')
    if settings:
        param_rotation = int(settings.get('param_rotation', param_rotation) or 0)
        param_key = settings.get('param_key', param_key) or ''
        current_app.config['param_rotation'] = param_rotation
        current_app.config['param_key'] = param_key
    return param_rotation == 1 and param_key not in request_path


def update_param_key(db, settings=None):
    """Update param key value"""
    param_rotation = current_app.config.get('param_rotation', 0)
    if settings:
        param_rotation = int(settings.get('param_rotation', param_rotation) or 0)
        current_app.config['param_rotation'] = param_rotation
    if param_rotation == 1:
        new_key = config.gen_param_key()
        db.update_param_key(new_key)
        current_app.config['param_key'] = new_key


#
# Dynamic page features
#

def serve_file(file_path, url_name, encrypt=False):
    if not os.path.isfile(file_path):
        return redirect(current_app.config['redirect_url'], 302)

    if encrypt:
        with open(file_path, "rb") as f:
            encrypted_b64 = config.dispatch_native_encrypt(f.read(), encrypt)
            buf = BytesIO(encrypted_b64)
            buf.seek(0)
            return send_file(
                buf,
                download_name=url_name,
                as_attachment=False if request.args.get('raw', type=bool) else True,
                mimetype='text/plain' if request.args.get('raw', type=bool) else None,
                conditional=False,
                max_age=0,
            )

    return send_file(
        file_path,
        download_name=url_name,
        as_attachment=False if request.args.get('raw', type=bool) else True,
        mimetype='text/plain' if request.args.get('raw', type=bool) else None,
        conditional=True,
        max_age=0,
    )


def reverse_proxy(redirect_url):
    """Forward headers and data, correctly handling HTTPS requests and common issues."""
    excluded_headers = {"host", "connection"}
    headers = {key: value for key, value in request.headers.items() if key.lower() not in excluded_headers}
    headers["X-Forwarded-For"] = request.remote_addr

    try:
        with requests.request(
                method=request.method,
                url=redirect_url,
                headers=headers,
                data=request.get_data(),  # Always send body data, even if empty
                cookies=request.cookies,  # Preserve cookies for session management
                allow_redirects=False,  # Handle redirects manually
                verify=False,  # noqa: S501 - operator-configured proxy targets may use private certificates
                stream=True,
                timeout=6,
                proxies={}
        ) as response:

            # Handle redirects manually
            if response.status_code in {301, 302, 303, 307, 308}:
                new_location = response.headers.get("Location")
                if new_location:
                    return redirect(new_location, response.status_code)

            # Remove problematic headers before forwarding response
            excluded_response_headers = {"content-encoding", "transfer-encoding", "connection"}
            response_headers = {k: v for k, v in response.headers.items() if k.lower() not in excluded_response_headers}
            return Response(response.content, response.status_code, response_headers)
    except requests.exceptions.RequestException as exc:
        logging.debug('Reverse proxy request failed: %s', exc)
        return Response('Proxy error', status=502, mimetype='text/plain')
