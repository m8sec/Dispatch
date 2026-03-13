"""Run scheduled scripts in a background thread."""

import threading
import subprocess
import tempfile
from datetime import datetime

from dispatch import config
from dispatch.db import DispatchDB


class ScriptScheduler:
    def __init__(self, db_path=None):
        self.db_path = db_path or config.DB_NAME
        self._thread = None
        self._stop_event = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name='DispatchScriptScheduler', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._run_due_scripts()
            except Exception as exc:
                config.log(f"Scheduler error: {exc}", user=False)
            # poll every 60 seconds
            self._stop_event.wait(60)

    def _run_due_scripts(self):
        now = datetime.now()
        db = DispatchDB(self.db_path)
        try:
            scripts = db.get_scheduled_scripts()
        finally:
            db.close()

        for script in scripts:
            if not self._is_due(script, now):
                continue
            self._execute_script(script)

    def _parse_last_run(self, last_run):
        if not last_run:
            return None
        try:
            return datetime.fromisoformat(last_run)
        except Exception:
            return None

    def _is_due(self, script, now):
        schedule_type = script.get('schedule_type')
        schedule_time = script.get('schedule_time') or '00:00'
        last_run = self._parse_last_run(script.get('last_run'))

        if schedule_type == 'hourly':
            try:
                minute = int(schedule_time.split(':')[1])
            except Exception:
                minute = 0
            if now.minute != minute:
                return False
            if not last_run:
                return True
            return last_run.strftime('%Y-%m-%d %H') != now.strftime('%Y-%m-%d %H')

        try:
            hour, minute = [int(x) for x in schedule_time.split(':')]
        except Exception:
            hour, minute = 0, 0

        if now.hour != hour or now.minute != minute:
            return False

        if schedule_type == 'daily':
            if not last_run:
                return True
            return last_run.date() != now.date()

        if schedule_type == 'weekly':
            # stored 0=Sunday..6=Saturday
            day_of_week = script.get('schedule_day_of_week')
            sunday_based = (now.weekday() + 1) % 7
            if day_of_week is None or int(day_of_week) != sunday_based:
                return False
            if not last_run:
                return True
            return last_run.date() != now.date()

        if schedule_type == 'monthly':
            day_of_month = script.get('schedule_day_of_month')
            if day_of_month is None or int(day_of_month) != now.day:
                return False
            if not last_run:
                return True
            return last_run.strftime('%Y-%m') != now.strftime('%Y-%m') or last_run.day != now.day

        return False

    def _execute_script(self, script):
        tmp_path = None
        output = ''
        success = False
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(script.get('script_content', ''))
                tmp_path = tmp.name

            result = subprocess.run(['python3', tmp_path], capture_output=True, text=True, timeout=30)
            output = (result.stdout or '') + (result.stderr or '')
            success = result.returncode == 0
        except subprocess.TimeoutExpired:
            output = 'Script execution timed out (30 seconds)'
            success = False
        except Exception as exc:
            output = f'Error executing scheduled script: {exc}'
            success = False
        finally:
            if tmp_path:
                try:
                    import os
                    os.remove(tmp_path)
                except Exception:
                    pass

        db = DispatchDB(self.db_path)
        try:
            db.update_script_run(script.get('id'), output)
        finally:
            db.close()

        config.log(f"Executed scheduled script: {script.get('name', 'Unnamed')}", user=False)

        if script.get('notify_enabled') == 1:
            try:
                from dispatch.notifications import send_script_notification, should_notify
                if (not script.get('notify_skip_blank', 1) or output.strip()) and should_notify(script.get('notify_on', 'always'), success):
                    send_script_notification(
                        self.db_path,
                        script.get('name', 'Unnamed'),
                        success,
                        output,
                        notify_plain=bool(script.get('notify_plain', 0)),
                        notify_plain_no_codeblock=bool(script.get('notify_plain_no_codeblock', 0))
                    )
            except Exception:
                pass


scheduler = ScriptScheduler()
