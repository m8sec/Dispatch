import jwt
import logging
from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import redirect, request, current_app, Response

from dispatch import config
from dispatch.db import DispatchDB


#
# Core authentication decorator support function
#
#   user_roles:
#     0: Disabled
#     1: Download Only / Login req.
#     2: Upload Only
#     3: Operator
#     4: Administrator
#
def _auth_required(min_role):
    """Core decorator support for authentication with role checking"""
    def decorator(func):
        @wraps(func)
        def _decorator(*args, **kwargs):
            # Restrict login & api access by source IP
            if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
                return redirect(current_app.config['redirect_url'], 302)
            
            # Try token authentication first
            token = validateToken(request)
            if isinstance(token, Response):
                return token
            elif token and token['role'] >= min_role:
                return func(token, *args, **kwargs)
            
            # Try API key authentication
            api_key = validateKey(request)
            if api_key and api_key['role'] >= min_role:
                return func(api_key, *args, **kwargs)
            
            # Authentication failed
            return signOut() if min_role == 1 else redirect("/", 302)
        return _decorator
    return decorator


#
# Authentication decorators (supports cookies + API)
#
def login_required(func):
    """Login required with no special access, download only"""
    return _auth_required(1)(func)


def upload_only_required(func):
    """Upload user or higher required"""
    return _auth_required(2)(func)


def operator_required(func):
    """Operator access required"""
    return _auth_required(3)(func)


def admin_required(func):
    """Administrator access required"""
    return _auth_required(4)(func)


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
            return refreshToken(token, request)
        except Exception as e:
            logging.debug(f'Token Error:: {e}')
    return False


def refreshToken(token, request, minute=20):
    # Refresh token if expired within N min
    data = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'], options={"verify_exp": False})
    now = datetime.now(timezone.utc)
    exp_time = datetime.fromtimestamp(data['exp'], tz=timezone.utc)

    # Only renew if within the minute window
    if now < (exp_time + timedelta(minutes=minute)):
        logging.debug(f"Renewing token for {data['user']} user (exp: {exp_time})")
        new_token = createToken(data)
        resp = redirect(request.full_path, code=302)
        resp.set_cookie(config.COOKIE_NAME, value=new_token, path="/", httponly=True, secure=True if request.is_secure else False)
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
