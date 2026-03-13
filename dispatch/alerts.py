"""
Dispatch Alert System
Checks configured alerts and sends Discord webhook notifications
"""

import logging
from dispatch.db import DispatchDB
from dispatch import config

logger = logging.getLogger('dispatch-logger')

# Track failed login attempts in memory (reset on restart)
_failed_login_tracker = {}  # {username: {'count': N, 'last_ip': 'x.x.x.x'}}


def check_user_login_alert(db_path, user_id, username, ip):
    """Check if user login should trigger an alert"""
    try:
        db = DispatchDB(db_path)
        alerts = db.get_alerts_by_type('user_login')
        db.close()

        for alert in alerts:
            if alert['target_id'] == user_id:
                from dispatch.notifications import send_webhook_message
                message = f"User '{username}' logged in from {ip}"
                send_webhook_message(db_path, message, 'user_login')
                logger.info(f"Alert triggered: user_login for {username}")
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking user login alert: {e}")
        return False


def check_file_download_alert(db_path, file_id, filename, username, ip):
    """Check if file download should trigger an alert"""
    try:
        db = DispatchDB(db_path)
        alerts = db.get_alerts_by_type('file_download')
        db.close()

        for alert in alerts:
            if alert['target_id'] == file_id:
                from dispatch.notifications import send_webhook_message
                user_str = f"by user '{username}' " if username else ""
                message = f"File '{filename}' downloaded {user_str}from {ip}"
                send_webhook_message(db_path, message, 'file_download')
                logger.info(f"Alert triggered: file_download for {filename}")
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking file download alert: {e}")
        return False


def check_failed_login_alert(db_path, username, ip):
    """Track failed login and check if threshold reached"""
    global _failed_login_tracker

    try:
        # Track this failed attempt
        if username not in _failed_login_tracker:
            _failed_login_tracker[username] = {'count': 0, 'last_ip': ip}

        _failed_login_tracker[username]['count'] += 1
        _failed_login_tracker[username]['last_ip'] = ip
        current_count = _failed_login_tracker[username]['count']

        # Check if any failed_logins alerts are configured
        db = DispatchDB(db_path)
        alerts = db.get_alerts_by_type('failed_logins')
        db.close()

        for alert in alerts:
            threshold = int(alert['target_value']) if alert['target_value'] else 5
            if current_count >= threshold:
                from dispatch.notifications import send_webhook_message
                message = f"{current_count} failed login attempts for user '{username}' from {ip}"
                send_webhook_message(db_path, message, 'failed_logins')
                logger.info(f"Alert triggered: failed_logins threshold reached for {username}")
                # Reset counter after alert
                _failed_login_tracker[username]['count'] = 0
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking failed login alert: {e}")
        return False


def reset_failed_logins(username):
    """Reset failed login counter on successful login"""
    global _failed_login_tracker
    if username in _failed_login_tracker:
        _failed_login_tracker[username] = {'count': 0, 'last_ip': ''}


def check_ip_activity_alert(db_path, ip, action, details=''):
    """Check if IP matches any monitored IP/CIDR"""
    try:
        db = DispatchDB(db_path)
        alerts = db.get_alerts_by_type('ip_monitor')
        db.close()

        for alert in alerts:
            target_ip = alert['target_value']
            if target_ip:
                # Use existing allowlist_match function for CIDR support
                if config.allowlist_match([target_ip], ip):
                    from dispatch.notifications import send_webhook_message
                    details_str = f" - {details}" if details else ""
                    message = f"Activity from monitored IP {ip}: {action}{details_str}"
                    send_webhook_message(db_path, message, 'ip_monitor')
                    logger.info(f"Alert triggered: ip_monitor for {ip}")
                    return True
        return False
    except Exception as e:
        logger.error(f"Error checking IP activity alert: {e}")
        return False
