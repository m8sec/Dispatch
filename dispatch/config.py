# ----------- * --------- # ----------- * --------- # ----------- * --------- #
# DISPATCH SHARED UTILITIES
# ----------- * --------- # ----------- * --------- # ----------- * --------- #
import os
import re
import sys
import base64
import logging
import ipaddress
import socket
from os import path
from requests import get
from OpenSSL import crypto
from datetime import datetime
from random import choice, randint, shuffle
from string import ascii_letters, digits, punctuation, ascii_uppercase, ascii_lowercase
logger = logging.getLogger('dispatch-logger')


def generate_ssl_cert(cert_path, key_path, country="US", cn="Dispatch", org="Dispatch", ou="", valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a self-signed certificate
        cert = crypto.X509()
        cert.get_subject().C = country
        cert.get_subject().CN = cn
        cert.get_subject().O = org
        cert.get_subject().OU = ou

        cert.set_serial_number(int.from_bytes(os.urandom(16), "big"))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(int(valid) * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(key_path, 'wb') as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        with open(cert_path, 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        return True
    except:
        pass
    return False


def gen_filename():
    # Generates the internal filename if not provided during upload
    return get_timestamp() + ".lol"


def get_file_extension(file_name):
    _, extension = os.path.splitext(file_name)
    return extension


def gen_alias(extension=''):
    # Generates the external alias of filename if not provided during upload
    return gen_random_string(randint(6, 9)) + extension


def get_timestamp():
    return datetime.now().strftime('%m-%d-%y_%H%M%S')


def gen_random_string(length=6):
    return ''.join([choice(ascii_letters + digits) for x in range(length)])


def _load_secret_key():
    env_secret = os.getenv('DISPATCH_SECRET_KEY', '').strip()
    if env_secret:
        return env_secret

    secret_path = path.join(path.dirname(path.realpath(__file__)), 'data', 'mfa_secret.key')
    try:
        with open(secret_path, 'r', encoding='utf-8') as secret_file:
            persisted_secret = secret_file.read().strip()
            if persisted_secret:
                return persisted_secret
    except FileNotFoundError:
        pass
    except OSError:
        logger.warning('Unable to read persisted Dispatch secret key', exc_info=True)

    persisted_secret = (
        f'{gen_random_string(randint(4, 8))}-'
        f'{gen_random_string(randint(8, 10))}-'
        f'{gen_random_string(randint(4, 8))}'
    )
    try:
        os.makedirs(path.dirname(secret_path), exist_ok=True)
        with open(secret_path, 'w', encoding='utf-8') as secret_file:
            secret_file.write(persisted_secret)
    except OSError:
        logger.warning('Unable to persist Dispatch secret key; set DISPATCH_SECRET_KEY for stable auth', exc_info=True)
    return persisted_secret


def auth_cookie_settings(request, *, httponly=True, samesite='Lax', path='/'):
    return {
        'path': path,
        'httponly': httponly,
        'secure': request.is_secure,
        'samesite': samesite,
    }


def file_collision_check(filename, base_dir=None):
    count = 0
    filename = remove_special(filename)
    s_tmp = filename.split('.')
    fname = s_tmp[0]
    ext = s_tmp[-1] if len(s_tmp) > 1 else ''
    tmp = filename
    base_dir = base_dir or FILE_PATH

    while path.exists(path.join(base_dir, tmp)):
        count += 1
        tmp = f'{fname}-{count}'
        tmp += f'.{ext}' if ext else ''
    return tmp


def alias_collision_check(db, alias):
    count = 0
    alias = remove_special(alias)
    s_tmp = alias.split('.')
    fname = s_tmp[0]
    ext = s_tmp[-1] if len(s_tmp) > 1 else ''
    tmp = alias

    while db.alias_exists(tmp):
        count += 1
        tmp = f'{fname}-{count}'
        tmp += f'.{ext}' if ext else ''
    return tmp


def get_file_size(file_path):
    opt = ['gb', 'mb', 'kb', 'bytes']
    exponent = {'bytes': 0, 'kb': 1, 'mb': 2, 'gb': 3}
    try:
        file_size = path.getsize(file_path)

        for unit in opt:
            size = file_size / 1024 ** exponent[unit]
            if int(size) > 0 or unit == 'bytes':
                return f'{round(size, 1)} {unit}'
    except:
        return "n/a"


def download_file(source, output, timeout=5):
    try:
        f = open(output, 'wb+')
        f.write(get(source, verify=False, timeout=timeout).content)
        f.close()
        if path.exists(output):
            return True
    except:
        pass
    return False


def gen_param_key():
    # Rotate the param location
    k = gen_random_string(randint(1, 2))
    v = gen_random_string(randint(6, 9))
    return f'{k}={v}'


def gen_api_key():
    return '{}-{}-{}'.format(gen_random_string(randint(8, 10)),
                             gen_random_string(randint(12, 14)),
                             gen_random_string(randint(12, 14)))


def validate_password(password):
    if len(password) < 10:
        return False
    if not re.search(r"[!@#$%^&*(),.?\"':{}|<>]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


def validate_username(username):
    # Validate no special characters are in username values
    for u in username:
        if u in '!"#$%&\'()*+,./:;<=>?@[\\]^`{|}~':
            return False
    return True


def remove_special(value):
    # Remove special chars from filenames and aliases
    data = ''
    for x in value:
        if x not in '<>\'"\\$&{}|^`~!;':
            data += x
    return data


def allowlist_match(allow_list, client_ip, host=None):
    if not allow_list:
        return True
    if not client_ip:
        return False
    host = host or ''
    if ':' in host:
        host = host.split(':', 1)[0]
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for entry in allow_list:
        if not entry:
            continue
        item = entry.strip()
        if not item:
            continue
        if item == client_ip:
            return True
        if host and item == host:
            return True
        if '/' in item:
            try:
                if ip_obj in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                pass
            continue
        try:
            resolved = socket.getaddrinfo(item, None)
        except Exception:
            continue
        for res in resolved:
            addr = res[4][0]
            if addr == client_ip:
                return True
    return False


def is_blocked_filename(filename):
    return os.path.basename(filename).lower() == '.gitignore'


def generate_password(length=10):
    uppercase_letters = ascii_uppercase
    lowercase_letters = ascii_lowercase
    numbers = digits
    special_characters = punctuation
    password = choice(uppercase_letters) + choice(numbers) + choice(special_characters)+ choice(lowercase_letters)

    remaining_length = length - 4
    for _ in range(remaining_length):
        characters = uppercase_letters + lowercase_letters + numbers + special_characters
        password += choice(characters)

    password_list = list(password)
    shuffle(password_list)
    password = ''.join(password_list)
    return password


def refresh_app_configs(db, app):
    s = db.get_settings()
    ua = db.get_allow_agent()
    ip = db.get_allow_address()
    login = db.get_allow_login()
    response_headers = db.get_response_headers()
    app.config['allow_ip'] = ip
    app.config['allow_ua'] = ua
    app.config['db_name'] = DB_NAME
    app.config['version'] = VERSION
    app.config['allow_login'] = login
    app.config['source_ip'] = s['source_ip']
    app.config['param_key'] = s['param_key']
    app.config['source_port'] = s['source_port']
    app.config['client_port'] = s.get('client_port', 443)
    app.config['client_enabled'] = s.get('client_enabled', 1)
    app.config['proxy_enabled'] = s.get('proxy_enabled', 0)
    app.config['redirect_url'] = s['redirect_url']
    app.config['server_header'] = s.get('server_header', 'Apache')
    app.config['response_headers'] = response_headers
    app.config['MAX_CONTENT_LENGTH'] = s['max_file_size']
    app.config['param_rotation'] = int(s['param_rotation'])
    app.config['mfa_required'] = db.get_mfa_required()
    if 'disable_exec' not in app.config:
        app.config['disable_exec'] = False


def setup_debug_logger():
    debug_output_string = "DEBUG:: %(message)s".format()
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    root_logger.setLevel(logging.DEBUG)
    return root_logger


def setup_dispatch_logger(log_name='dispatch-logger', log_level=logging.INFO):
    """Setup logger - now primarily uses database, this is for console/debug output"""
    logger = logging.getLogger(log_name)
    logger.propagate = False
    logger.setLevel(log_level)
    return logger


def log(data, user=False, remote_ip=None, level='INFO'):
    """Log to database with auto-populated timestamp"""
    # Lazy import to avoid circular dependency
    from dispatch.db import DispatchDB

    user = user if user else {'id': 0, 'user': 'n/a', 'role_name': 'Public'}

    try:
        db = DispatchDB(DB_NAME)
        db.add_log(
            message=data,
            level=level,
            user=user.get('user', 'n/a'),
            user_id=user.get('id', 0),
            user_role=user.get('role_name', 'Public'),
            ip=remote_ip
        )
        db.close()
    except Exception as e:
        # Fallback to console if database fails
        logging.error(f"Failed to log to database: {e}")
        logging.info(f"{data} - USER: {user.get('user', 'n/a')} - SRC: {remote_ip}")


def dispatch_native_encrypt(data, password):
    data_bytes = data   # already in bytes format
    key_bytes = password.encode("utf-8")
    l = len(key_bytes)
    encrypted = bytes((data_bytes[i] ^ key_bytes[i % l]) for i in range(len(data_bytes)))
    return base64.b64encode(encrypted)  # Sent by server in byte format


# ----------- * --------- # ----------- * --------- # ----------- * --------- #
# DISPATCH CONFIGURATION SETUP
# ----------- * --------- # ----------- * --------- # ----------- * --------- #
VERSION = 'v0.2.4'

#
# Authentication
#
DEFAULT_USER = 'admin'                  # Default admin user
DEFAULT_PWD = generate_password(12)     # Default password for admin user
COOKIE_NAME = 'token'                   # Cookie name for auth token
TOKEN_TIMEOUT = 35  # (minutes)         # JWT token timeout
API_HEADER = 'X-Dispatch-Auth'          # Header name for API key authentication
MAX_FILE_SIZE = 16 * 1000 * 1000        # Maximum file upload size in bytes (16MB)

# Stable secret key for JWT signing. Use DISPATCH_SECRET_KEY in distributed deployments.
SECRET_KEY = _load_secret_key()

#
# File Storage
#
DB_NAME = path.join(path.dirname(path.realpath(__file__)), 'data', 'dispatch.db')
CERT_PATH = path.join(path.dirname(path.realpath(__file__)), 'data', 'certs', 'cert.crt')
KEY_PATH = path.join(path.dirname(path.realpath(__file__)), 'data', 'certs', 'key.pem')
FILE_PATH = path.join(path.dirname(path.realpath(__file__)), 'data', 'uploads')

#
# Password protect site resources
#
TMPL_PATH = path.join(path.dirname(path.realpath(__file__)), 'templates')


#
# Default SSL Config
#
COUNTRY = "US"
CN = "Dispatch"
ORG = "Dispatch Opations Server"
OU = "Security Testing"
VALID_DAYS = 365
