# ----------- * --------- # ----------- * --------- # ----------- * --------- #
# DISPATCH SHARED UTILITIES
# ----------- * --------- # ----------- * --------- # ----------- * --------- #
import os
import re
import sys
import logging
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

        cert.set_serial_number(1000)
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


def file_collision_check(filename):
    count = 0
    filename = remove_special(filename)
    s_tmp = filename.split('.')
    fname = s_tmp[0]
    ext = s_tmp[-1] if len(s_tmp) > 1 else ''
    tmp = filename

    while path.exists(path.join(FILE_PATH, tmp)):
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


def mb_to_bytes(megabytes):
    return megabytes * 1024 * 1024


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
    app.config['allow_ip'] = ip
    app.config['allow_ua'] = ua
    app.config['db_name'] = DB_NAME
    app.config['version'] = VERSION
    app.config['allow_login'] = login
    app.config['source_ip'] = s['source_ip']
    app.config['param_key'] = s['param_key']
    app.config['redirect_url'] = s['redirect_url']
    app.config['server_header'] = s['server_header']
    app.config['MAX_CONTENT_LENGTH'] = s['max_file_size']
    app.config['param_rotation'] = int(s['param_rotation'])


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
    formatter = logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S %Z")
    fh = logging.FileHandler(DISPATCH_LOG)
    fh.setFormatter(formatter)
    logger = logging.getLogger(log_name)
    logger.addHandler(fh)
    logger.propagate = False
    logger.setLevel(log_level)
    return logger


def log(data, user=False, remote_ip=None):
    user = user if user else {'id': 0, 'user': 'n/a', 'role_name': 'Public'}
    logger.info(f"{data} - USER: {user['user']} ({user['id']}) - PRIV: {user['role_name']} - SRC: {remote_ip}")


# ----------- * --------- # ----------- * --------- # ----------- * --------- #
# DISPATCH CONFIGURATION SETUP
# ----------- * --------- # ----------- * --------- # ----------- * --------- #
VERSION = 'v0.1.0'

#
# Authentication
#
INTERFACE = '0.0.0.0'                   # Bind Interface (default all)
PORT = 443                              # Bind Port (default 443)
DEFAULT_USER = 'admin'                  # Default admin user
DEFAULT_PWD = generate_password(12)     # Default password for admin user
COOKIE_NAME = 'token'                   # Cookie name for auth token
TOKEN_TIMEOUT = 60  # (minutes)         # JWT token timeout
API_HEADER = 'X-Dispatch-Auth'          # Header name for API key authentication
MAX_FILE_SIZE = 16 * 1000 * 1000        # Maximum file size in bytes (16MB)

# Rotating secret key to invalidate sessions on restart
SECRET_KEY = f'{gen_random_string(randint(4, 8))}-{gen_random_string(randint(8, 10))}-{gen_random_string(randint(4, 8))}'

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
# Log Path
#
DISPATCH_LOG = path.join(path.dirname(path.realpath(__file__)), 'data', 'logs', 'dispatch.log')