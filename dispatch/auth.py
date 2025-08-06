import jwt
import logging
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import redirect, request, current_app, Response

from dispatch import config
from dispatch.db import DispatchDB


#
# Authentication decorators
#
def login_required(func):
    # Login required with no special access
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict login access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)
        token = validateToken(request)
        if isinstance(token, Response):
            return token
        return func(token, *args, **kwargs) if token and token['role'] > 0 else signOut()
    return _decorator


def upload_only_required(func):
    # Login required with upload user or higher
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict login access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)
        token = validateToken(request)
        if isinstance(token, Response):
            return token
        return func(token, *args, **kwargs) if token and token['role'] > 1 else redirect("/", 302)
    return _decorator


def operator_required(func):
    # Operator login required
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict login access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)
        token = validateToken(request)
        if isinstance(token, Response):
            return token
        return func(token, *args, **kwargs) if token and token['role'] > 2 else redirect("/", 302)
    return _decorator


def admin_required(func):
    # Administrator login required
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict login access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)
        token = validateToken(request)
        if isinstance(token, Response):
            return token
        return func(token, *args, **kwargs) if token and token['role'] > 3 else redirect("/", 302)
    return _decorator


def api_download_only_required(func):
    # Authenticate via auth cookie or Dispatch API Header as upload user or higher
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)

        token = validateToken(request)
        if isinstance(token, Response):
            return token
        elif token and token['role'] > 0:
            return func(token, *args, **kwargs)

        api_key = validateKey(request)
        return func(api_key, *args, **kwargs) if api_key and api_key['role'] > 0 else redirect("/", 302)
    return _decorator


def api_upload_only_required(func):
    # Authenticate via auth cookie or Dispatch API Header as upload user or higher
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)

        token = validateToken(request)
        if isinstance(token, Response):
            return token
        elif token and token['role'] > 1:
            return func(token, *args, **kwargs)

        api_key = validateKey(request)
        return func(api_key, *args, **kwargs) if api_key and api_key['role'] > 1 else redirect("/", 302)
    return _decorator


def api_operator_required(func):
    # Authenticate via auth cookie or Dispatch API Header as admin
    @wraps(func)
    def _decorator(*args, **kwargs):
        # Restrict access by source IP
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            return redirect(current_app.config['redirect_url'], 302)

        token = validateToken(request)
        if isinstance(token, Response):
            return token
        elif token and token['role'] > 2:
            return func(token, *args, **kwargs)

        api_key = validateKey(request)
        return func(api_key, *args, **kwargs) if api_key and api_key['role'] > 2 else redirect("/", 302)
    return _decorator


#
# Token support / validation functions
#
def signOut():
    # Once token is found invalid, return to login and delete all prior cookies
    resp = redirect('/login', 302)
    resp.delete_cookie(config.COOKIE_NAME)
    return resp


def validateKey(request):
    data = False
    if request.headers.get(config.API_HEADER) is not None:
        db = DispatchDB(current_app.config['db_name'])
        data = db.validate_api_key(request.headers.get(config.API_HEADER))
        db.close()
        if data:
            config.log("API Login Successful", data, request.remote_addr)
    return data


def validateToken(request):
    # Validate JWT sent in Cookie against expiration date
    token = request.cookies.get(config.COOKIE_NAME)
    if token:
        try:
            return jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return refreshToken(token)
        except Exception as e:
            logging.debug(f'Token Error:: {e}')
    return False


def refreshToken(token, minute=20):
    # Refresh token if expired within N min
    data = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'], options={"verify_exp": False})
    now = datetime.now(timezone.utc)
    exp_time = datetime.fromtimestamp(data['exp'], tz=timezone.utc)

    if now < (exp_time + timedelta(minutes=minute)):
        logging.debug(f"Renewing token for {data['user']} user (exp: {exp_time})")
        new_token = createToken(data)
        resp = redirect(request.full_path, code=302)
        resp.set_cookie(config.COOKIE_NAME, value=new_token, path="/", httponly=True, secure=True)
        return resp
    return False


def createToken(data):
    # Take in JWT data and create token.
    data['exp'] = datetime.now(timezone.utc) + timedelta(minutes=config.TOKEN_TIMEOUT)
    return jwt.encode(data, config.SECRET_KEY)


def loadUser(db, username):
    user_data = db.create_token(username)
    return {
        'user': user_data['user'],
        'id': user_data['id'],
        'role': user_data['role'],
        'role_name': user_data['role_name']
    }


def loginCheck(username, password):
    db = DispatchDB(config.DB_NAME)
    try:
        if db.validate_login(username, password):
            return True
        return False
    finally:
        db.close()
