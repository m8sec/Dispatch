import os
import sys
import ssl
import shutil
import subprocess
import logging
from os import path

from dispatch import config


log = logging.getLogger('dispatch-logger')


def certbot_available():
    return shutil.which(config.CERTBOT_BIN) is not None


def install_certbot():
    """
    Attempt to install certbot using pip. Returns stdout on success.
    """
    cmd = [sys.executable, '-m', 'pip', 'install', 'certbot']
    log.info("Attempting to install certbot via pip")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        error_output = result.stderr if result.stderr else result.stdout
        log.error(f"Certbot install failed: {error_output}")
        raise RuntimeError(error_output)
    log.info("Certbot installation completed.")
    return result.stdout


def _get_acme_server(staging):
    return config.LE_STAGING_ACME_URL if staging else config.LE_PROD_ACME_URL


def _build_certbot_command(domain, email, staging):
    server = _get_acme_server(staging)
    cmd = [
        config.CERTBOT_BIN,
        'certonly',
        '--non-interactive',
        '--agree-tos',
        '--email', email,
        '--webroot',
        '-w', config.CHALLENGE_PATH,
        '-d', domain,
        '--config-dir', config.CERTBOT_CONFIG_PATH,
        '--work-dir', config.CERTBOT_WORK_PATH,
        '--logs-dir', config.CERTBOT_LOG_PATH,
        '--preferred-challenges', 'http',
        '--server', server
    ]
    if staging:
        cmd.append('--test-cert')
    return cmd


def _remove_lineage(domain):
    live_dir = path.join(config.CERTBOT_CONFIG_PATH, 'live', domain)
    archive_dir = path.join(config.CERTBOT_CONFIG_PATH, 'archive', domain)
    renewal_conf = path.join(config.CERTBOT_CONFIG_PATH, 'renewal', f'{domain}.conf')

    for target in [live_dir, archive_dir]:
        if path.exists(target):
            shutil.rmtree(target, ignore_errors=True)
    if path.exists(renewal_conf):
        os.remove(renewal_conf)


def _renewal_server_matches(domain, staging):
    renewal_conf = path.join(config.CERTBOT_CONFIG_PATH, 'renewal', f'{domain}.conf')
    desired = _get_acme_server(staging)
    if not path.exists(renewal_conf):
        return True
    try:
        with open(renewal_conf, 'r') as f:
            for line in f:
                if line.strip().startswith('server ='):
                    current = line.split('=', 1)[1].strip()
                    return current == desired
    except Exception as e:
        log.debug(f"Unable to read renewal config {renewal_conf}: {e}")
    return False


def read_cert_metadata(cert_path):
    """Return subject/issuer/dates for logging."""
    try:
        info = ssl._ssl._test_decode_cert(cert_path)
        return {
            'subject': info.get('subject'),
            'issuer': info.get('issuer'),
            'notBefore': info.get('notBefore'),
            'notAfter': info.get('notAfter')
        }
    except Exception as e:
        log.debug(f"Unable to decode certificate metadata for {cert_path}: {e}")
        return {}


def request_certificate(domain, email, staging=False):
    """
    Execute certbot to request/renew a certificate for the provided domain.
    Certificates are placed under dispatch/data/certs/.
    """
    if not domain or not email:
        raise ValueError("Domain and email must be provided for certificate enrollment.")

    if not certbot_available():
        raise FileNotFoundError(f"Certbot binary '{config.CERTBOT_BIN}' was not found in PATH.")

    os.makedirs(config.CHALLENGE_PATH, exist_ok=True)

    if not _renewal_server_matches(domain, staging):
        log.info(f"Detected ACME server change for {domain}. Removing existing Certbot lineage before requesting new certificate.")
        _remove_lineage(domain)

    cmd = _build_certbot_command(domain, email, staging)
    log.info(f"Running certbot for domain {domain} with staging={staging}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        error_output = result.stderr if result.stderr else result.stdout
        log.error(f"Certbot enrollment failed: {error_output}")
        raise RuntimeError(error_output)

    live_dir = path.join(config.CERTBOT_CONFIG_PATH, 'live', domain)
    fullchain_src = path.join(live_dir, 'fullchain.pem')
    privkey_src = path.join(live_dir, 'privkey.pem')

    if not path.exists(fullchain_src) or not path.exists(privkey_src):
        raise FileNotFoundError("Certbot did not produce the expected certificate files.")

    shutil.copy2(fullchain_src, config.CERT_PATH)
    shutil.copy2(privkey_src, config.KEY_PATH)

    meta = read_cert_metadata(config.CERT_PATH)
    log.info(f"Successfully updated certificate for {domain} (issuer={meta.get('issuer')}, notAfter={meta.get('notAfter')})")
    return result.stdout
