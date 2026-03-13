"""
Dispatch Notification Helper
Sends notifications to Discord via webhook
"""

import logging
import requests
from datetime import datetime

logger = logging.getLogger('dispatch-logger')

# Alert type emojis
ALERT_EMOJIS = {
    'user_login': '\U0001F511',      # Key
    'file_download': '\U0001F4E5',   # Inbox tray
    'failed_logins': '\U0001F6A8',   # Rotating light
    'ip_monitor': '\U0001F310',      # Globe with meridians
    'script_success': '\u2705',      # Check mark
    'script_failure': '\u274C',      # Cross mark
    'info': '\u2139\uFE0F',          # Information
}


def send_webhook_message(db_path, message, alert_type='info'):
    """
    Send simple text message to Discord webhook with emoji prefix.

    Args:
        db_path: Path to the Dispatch database
        message: The message text to send
        alert_type: Type of alert for emoji selection

    Returns:
        True if message sent successfully, False otherwise
    """
    from dispatch.db import DispatchDB

    try:
        db = DispatchDB(db_path)
        webhook_url = db.get_webhook_url()
        db.close()

        if not webhook_url:
            logger.debug("No webhook URL configured, skipping notification")
            return False

        # Add emoji prefix
        emoji = ALERT_EMOJIS.get(alert_type, ALERT_EMOJIS['info'])
        content = f"{emoji} {message}"

        payload = {"content": content}

        response = requests.post(webhook_url, json=payload, timeout=10)

        if response.status_code in [200, 204]:
            logger.info(f"Webhook notification sent: {alert_type}")
            return True
        else:
            logger.error(f"Webhook error: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error sending webhook message: {e}")
        return False


def send_script_notification(db_path, script_name, success, output, notify_plain=False, notify_plain_no_codeblock=False):
    """
    Send script execution notification to configured webhook.

    Args:
        db_path: Path to the Dispatch database
        script_name: Name of the executed script
        success: Boolean indicating if script succeeded
        output: Script output text
        notify_plain: If True, send as plain message without embed
        notify_plain_no_codeblock: If True and notify_plain, don't wrap in codeblock

    Returns:
        True if notification sent successfully, False otherwise
    """
    from dispatch.db import DispatchDB

    try:
        db = DispatchDB(db_path)
        webhook_url = db.get_webhook_url()
        db.close()

        if not webhook_url:
            logger.debug("No webhook URL configured, skipping script notification")
            return False

        # Truncate output if too long
        max_output_length = 1800
        output_text = output if output else 'No output'
        if len(output_text) > max_output_length:
            output_text = output_text[:max_output_length] + "\n... (truncated)"

        # Select emoji based on success
        emoji = ALERT_EMOJIS['script_success'] if success else ALERT_EMOJIS['script_failure']
        status_text = "completed successfully" if success else "failed"

        if notify_plain:
            # Plain text message
            if notify_plain_no_codeblock:
                content = output_text
            else:
                content = f"```\n{output_text}\n```"
            payload = {"content": content}
        else:
            # Formatted message with script info
            content = f"{emoji} **Script '{script_name}'** {status_text}\n```\n{output_text}\n```"
            payload = {"content": content}

        response = requests.post(webhook_url, json=payload, timeout=10)

        if response.status_code in [200, 204]:
            logger.info(f"Script notification sent for: {script_name}")
            return True
        else:
            logger.error(f"Webhook error: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error sending script notification: {e}")
        return False


def should_notify(notify_on, success):
    """
    Determine if notification should be sent based on configuration.

    Args:
        notify_on: 'always', 'success', or 'failure'
        success: Boolean indicating if script succeeded

    Returns:
        Boolean indicating if notification should be sent
    """
    if notify_on == 'always':
        return True
    elif notify_on == 'success' and success:
        return True
    elif notify_on == 'failure' and not success:
        return True
    return False


def test_webhook(db_path):
    """
    Send a test message to verify webhook configuration.

    Args:
        db_path: Path to the Dispatch database

    Returns:
        Tuple of (success: bool, message: str)
    """
    from dispatch.db import DispatchDB

    try:
        db = DispatchDB(db_path)
        webhook_url = db.get_webhook_url()
        db.close()

        if not webhook_url:
            return False, "No webhook URL configured"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        content = f"\u2705 Dispatch webhook test successful at {timestamp}"
        payload = {"content": content}

        response = requests.post(webhook_url, json=payload, timeout=10)

        if response.status_code in [200, 204]:
            return True, "Webhook test successful"
        else:
            return False, f"Webhook error: {response.status_code}"

    except requests.exceptions.Timeout:
        return False, "Webhook request timed out"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"
