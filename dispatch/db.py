import hashlib
import logging
from dispatch import config
from sqlite3 import connect

#
# primary hashing function for DB passwords
#
def gen_password_hash(password):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))
    hash_result = sha256_hash.hexdigest()
    return hash_result


class SqliteDB:
    def __init__(self, db_file, timeout=3):
        self.db_file = db_file
        self.conn = connect(self.db_file, timeout=timeout, check_same_thread=False)

    def close(self):
        try:
            self.conn.close()
        except:
            pass

    def exec(self, query, args=()):
        try:
            cur = self.conn.cursor()
            cur.execute(query, args)
            data = cur.fetchall()
            self.conn.commit()
            return data
        except Exception as e:
            logging.debug(f"SQL Error:: {e}")
            return False
        finally:
            cur.close()

    def executemany(self, query, args_list):
        try:
            cur = self.conn.cursor()
            cur.executemany(query, args_list)
            self.conn.commit()
            return True
        except Exception as e:
            logging.debug(f"SQL Error:: {e}")
            return False
        finally:
            cur.close()


class DispatchDB(SqliteDB):
    user_roles = {
        0: 'Disabled',
        1: 'Download Only',
        2: 'Upload Only',
        3: 'Operator',
        4: 'Administrator'
    }

    file_access = {
        1: 'Public',
        2: 'Public Once',
        3: 'Private'
    }

    # Folder access levels map to user roles (who can access the folder)
    folder_access = {
        2: 'Upload Only',
        3: 'Operator',
        4: 'Administrator'
    }

    db_schema = [
        '''CREATE TABLE IF NOT EXISTS users (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "username" TEXT UNIQUE NOT NULL,
        "password" TEXT NOT NULL,
        "api_key" TEXT UNIQUE,
        "created" DATETIME DEFAULT (datetime('now','localtime')),
        "last_login" DATETIME DEFAULT (datetime('now','localtime')),
        "role" INTEGER DEFAULT 0,
        "totp_secret" TEXT DEFAULT NULL,
        "mfa_enabled" INTEGER DEFAULT 0);''',

        '''INSERT OR IGNORE INTO users 
        (id, username, password, role) 
        VALUES (1, "{}", "{}", 4);'''.format(config.DEFAULT_USER, gen_password_hash(config.DEFAULT_PWD)),

        '''CREATE TABLE IF NOT EXISTS folders (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "folder_name" TEXT NOT NULL,
        "parent_id" INTEGER DEFAULT NULL,
        "created_date" DATETIME DEFAULT (datetime('now','localtime')),
        "created_by" TEXT NOT NULL,
        "access" INTEGER DEFAULT 2,
        FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE);''',

        '''CREATE TABLE IF NOT EXISTS files (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "filename" TEXT UNIQUE NOT NULL,
        "file_path" TEXT UNIQUE NOT NULL,
        "access" INTEGER DEFAULT 3,
        "encrypt" TEXT DEFAULT NULL,
        "alias" TEXT UNIQUE NOT NULL,
        "upload_date" DATETIME DEFAULT (datetime('now','localtime')),
        "uploaded_by" TEXT NOT NULL,
        "folder_id" INTEGER DEFAULT NULL,
        FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL);''',

        '''CREATE TABLE IF NOT EXISTS settings (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "redirect_url" TEXT,
        "source_ip" TEXT,
        "source_port" INTEGER DEFAULT 8443,
        "client_port" INTEGER DEFAULT 443,
        "client_enabled" INTEGER DEFAULT 1,
        "proxy_enabled" INTEGER DEFAULT 0,
        "server_header" TEXT,
        "param_rotation" BOOLEAN DEFAULT 0,
        "param_key" TEXT DEFAULT 's=1234',
        "max_file_size" INTEGER DEFAULT {},
        "webhook_url" TEXT,
        "mfa_required" INTEGER DEFAULT 0);'''.format(config.MAX_FILE_SIZE),

        '''INSERT OR IGNORE INTO settings
        (redirect_url, source_ip, source_port, client_port, client_enabled, proxy_enabled, server_header)
        VALUES ("https://google.com", "127.0.0.1", 8443, 443, 1, 0, "Apache");''',

        '''CREATE TABLE IF NOT EXISTS ip_allow_login (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "ip" TEXT UNIQUE NOT NULL);''',

        '''CREATE TABLE IF NOT EXISTS ip_allow_list (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "ip" TEXT UNIQUE NOT NULL);''',

        '''CREATE TABLE IF NOT EXISTS ua_allow_list (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "agent" TEXT UNIQUE NOT NULL);''',

        '''CREATE TABLE IF NOT EXISTS proxy_routes (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "path" TEXT UNIQUE NOT NULL,
        "redirect_url" TEXT NOT NULL);''',

        '''CREATE TABLE IF NOT EXISTS response_headers (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "header_name" TEXT NOT NULL,
        "header_value" TEXT NOT NULL);''',

        '''INSERT OR IGNORE INTO response_headers (id, header_name, header_value) VALUES (1, 'Server', 'Apache');''',

        '''CREATE TABLE IF NOT EXISTS scripts (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "name" TEXT UNIQUE NOT NULL,
        "description" TEXT,
        "script_content" TEXT NOT NULL,
        "schedule_type" TEXT DEFAULT 'manual',
        "schedule_time" TEXT,
        "schedule_day_of_week" INTEGER,
        "schedule_day_of_month" INTEGER,
        "last_run" DATETIME,
        "last_output" TEXT,
        "created_by" TEXT NOT NULL,
        "created_date" DATETIME DEFAULT (datetime('now','localtime')),
        "enabled" INTEGER DEFAULT 1,
        "notify_enabled" INTEGER DEFAULT 0,
        "notify_channel_id" TEXT,
        "notify_on" TEXT DEFAULT 'always');''',

        '''CREATE TABLE IF NOT EXISTS dispatch_logs (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "timestamp" DATETIME DEFAULT (datetime('now','localtime')),
        "level" TEXT DEFAULT 'INFO',
        "message" TEXT NOT NULL,
        "user" TEXT,
        "user_id" INTEGER,
        "user_role" TEXT,
        "ip" TEXT);''',

        '''CREATE TABLE IF NOT EXISTS alerts (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "alert_type" TEXT NOT NULL,
        "target_id" INTEGER,
        "target_value" TEXT,
        "description" TEXT,
        "enabled" INTEGER DEFAULT 1,
        "created_date" DATETIME DEFAULT (datetime('now','localtime')));'''
    ]

    def __init__(self, db_file, timeout=3):
        SqliteDB.__init__(self, db_file, timeout)

    def normalize_folder_access(self, access):
        try:
            access = int(access)
        except (TypeError, ValueError):
            return 2
        return access if access in [2, 3, 4] else 2

    #
    # Application Support
    #
    def setup_db(self):
        for sql in self.db_schema:
            self.exec(sql)
        self.exec('UPDATE folders SET access=2 WHERE access IS NULL OR access < 2;')
        # Migration: Add MFA columns to existing databases
        self._migrate_mfa_columns()

    def _migrate_mfa_columns(self):
        """Add MFA columns to users table if they don't exist"""
        # Check users table columns
        user_columns = self.exec("PRAGMA table_info(users);")
        user_col_names = [col[1] for col in user_columns] if user_columns else []

        if 'totp_secret' not in user_col_names:
            self.exec('ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL;')
        if 'mfa_enabled' not in user_col_names:
            self.exec('ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;')

        # Check settings table columns
        settings_columns = self.exec("PRAGMA table_info(settings);")
        settings_col_names = [col[1] for col in settings_columns] if settings_columns else []

        if 'mfa_required' not in settings_col_names:
            self.exec('ALTER TABLE settings ADD COLUMN mfa_required INTEGER DEFAULT 0;')

    def validate_login(self, username, password):
        # Primary DB login functionality check if passwords match
        try:
            user_pass = self.exec('SELECT password FROM users WHERE username=?;', (username,))[0][0]
            if user_pass == gen_password_hash(password):
                self.exec('''UPDATE users SET last_login=datetime('now','localtime')''')
                return True
        except:
            return False
        return False

    def create_token(self, username):
        # Extract user info from database to create JWT
        data = {}
        for x in self.exec('SELECT id, role FROM users WHERE username=? LIMIT 1;', (username,)):
            data['user'] = username
            data['id'] = x[0]
            data['role'] = x[1]
            data['role_name'] = self.user_roles[int(x[1])]
        return data

    def validate_api_key(self, api_key):
        # Extract user info from database using API key
        try:
            data = {}
            for x in self.exec('SELECT id, username, role FROM users WHERE api_key=? LIMIT 1;', (api_key,)):
                data['id'] = x[0]
                data['user'] = x[1]
                data['role'] = x[2]
                data['role_name'] = self.user_roles[int(x[2])]
                return data
        except:
            return False
        return False

    #
    # User Table
    #
    def add_user(self, username, password, role):
        sql = '''INSERT OR IGNORE INTO users 
        (username, password, role, api_key)
        VALUES (?, ?, ?, ?);'''
        self.exec(sql, (username.lower(), gen_password_hash(password), role, config.gen_api_key()))

    def update_role_by_id(self, id, role):
        # Check if we can change this user's role (must keep at least one admin)
        if not self.can_change_admin_role(id, role):
            return False
        return self.exec('UPDATE users SET role=? WHERE id=?;', (role, id))

    def update_key_by_id(self, id, api_key):
        # Update user api key
        self.exec('UPDATE users SET api_key=? WHERE id=?;', (api_key, id))

    def update_user_password_by_id(self, id, password):
        self.exec('UPDATE users SET password=? WHERE id=?;', (gen_password_hash(password), id))

    def del_user_by_id(self, id):
        # Check if we can delete this user (must keep at least one admin)
        if not self.can_disable_admin(id):
            return False
        return self.exec('DELETE FROM users WHERE id=?;', (id,))

    def list_users(self, user_id, user_role):
        data = []
        mfa_required = self.get_mfa_required()
        if user_role > 3:
            query = self.exec('''SELECT id, username, created, last_login, role, mfa_enabled FROM users;''')
        else:
            # Only allow users to list accounts lower than them unless super admin
            sql = '''SELECT id, username, created, last_login, role, mfa_enabled FROM users WHERE role<? OR id=?;'''
            query = self.exec(sql, (user_role, user_id))
        for x in query:
            obj = {}
            obj['id'] = x[0]
            obj['username'] = x[1]
            obj['created'] = x[2]
            obj['last_login'] = x[3]
            obj['role'] = x[4]
            obj['role_name'] = self.user_roles[x[4]]
            obj['mfa_enabled'] = bool(x[5]) if len(x) > 5 else False
            # MFA status: 'enabled', 'pending' (required but not set up), 'disabled'
            if obj['mfa_enabled']:
                obj['mfa_status'] = 'enabled'
            elif mfa_required:
                obj['mfa_status'] = 'pending'
            else:
                obj['mfa_status'] = 'disabled'
            data.append(obj)
        return data

    def get_user_by_id(self, file_id):
        data = {}
        for x in self.exec('''SELECT username, created, last_login, role, api_key FROM users WHERE id=?;''', (file_id,)):
            data['id'] = file_id
            data['username'] = x[0]
            data['created'] = x[1]
            data['last_login'] = x[2]
            data['role'] = x[3]
            data['role_name'] = self.user_roles[x[3]]
            data['api_key'] = x[4] if x[4] is not None else ''
        return data

    def get_user_by_username(self, username):
        data = {}
        for x in self.exec('''SELECT id, username, created, last_login, role, api_key FROM users WHERE username=? LIMIT 1;''', (username.lower(),)):
            data['id'] = x[0]
            data['username'] = x[1]
            data['created'] = x[2]
            data['last_login'] = x[3]
            data['role'] = x[4]
            data['role_name'] = self.user_roles[x[4]]
            data['api_key'] = x[5] if x[5] is not None else ''
        return data if data else None

    #
    # MFA / TOTP Methods
    #
    def get_user_mfa_status(self, user_id):
        """Get MFA status for a user"""
        result = self.exec('SELECT mfa_enabled, totp_secret FROM users WHERE id=? LIMIT 1;', (user_id,))
        if result:
            return {'mfa_enabled': bool(result[0][0]), 'has_secret': result[0][1] is not None}
        return {'mfa_enabled': False, 'has_secret': False}

    def get_user_totp_secret(self, user_id):
        """Get TOTP secret for a user"""
        result = self.exec('SELECT totp_secret FROM users WHERE id=? LIMIT 1;', (user_id,))
        if result and result[0][0]:
            return result[0][0]
        return None

    def set_user_totp_secret(self, user_id, secret):
        """Set TOTP secret for a user"""
        return self.exec('UPDATE users SET totp_secret=? WHERE id=?;', (secret, user_id))

    def enable_user_mfa(self, user_id):
        """Enable MFA for a user"""
        return self.exec('UPDATE users SET mfa_enabled=1 WHERE id=?;', (user_id,))

    def disable_user_mfa(self, user_id):
        """Disable MFA and clear TOTP secret for a user"""
        return self.exec('UPDATE users SET mfa_enabled=0, totp_secret=NULL WHERE id=?;', (user_id,))

    def user_has_mfa_enabled(self, username):
        """Check if a user has MFA enabled (for login flow)"""
        result = self.exec('SELECT mfa_enabled FROM users WHERE username=? LIMIT 1;', (username.lower(),))
        if result:
            return bool(result[0][0])
        return False

    def get_user_id_by_username(self, username):
        """Get user ID by username"""
        result = self.exec('SELECT id FROM users WHERE username=? LIMIT 1;', (username.lower(),))
        if result:
            return result[0][0]
        return None

    #
    # MFA Settings
    #
    def get_mfa_required(self):
        """Check if MFA is required for all users"""
        try:
            result = self.exec('SELECT mfa_required FROM settings WHERE id=1;')
            if result and len(result) > 0 and len(result[0]) > 0:
                return bool(result[0][0])
        except Exception as e:
            logging.debug(f"Error getting mfa_required: {e}")
        return False

    def set_mfa_required(self, required):
        """Set whether MFA is required for all users"""
        return self.exec('UPDATE settings SET mfa_required=? WHERE id=1;', (1 if required else 0,))

    #
    # Admin Account Management
    #
    def count_administrators(self):
        """Count the number of users with Administrator role (role=4) who are not disabled"""
        result = self.exec('SELECT COUNT(*) FROM users WHERE role=4;')
        if result:
            return result[0][0]
        return 0

    def count_active_administrators(self):
        """Count the number of active (role=4) administrators - excludes disabled"""
        result = self.exec('SELECT COUNT(*) FROM users WHERE role=4;')
        if result:
            return result[0][0]
        return 0

    def can_disable_admin(self, user_id):
        """Check if an admin user can be disabled (there must be another admin)"""
        # Get the current user's role
        user = self.get_user_by_id(user_id)
        if not user or user['role'] != 4:
            return True  # Not an admin, can be modified
        # Check if there's at least one other active admin
        result = self.exec('SELECT COUNT(*) FROM users WHERE role=4 AND id!=?;', (user_id,))
        if result and result[0][0] > 0:
            return True
        return False

    def can_change_admin_role(self, user_id, new_role):
        """Check if an admin's role can be changed (there must remain at least one admin)"""
        if new_role == 4:
            return True  # Promoting to admin is always allowed
        user = self.get_user_by_id(user_id)
        if not user or user['role'] != 4:
            return True  # Not currently an admin, can be changed
        # Check if there's at least one other admin
        return self.can_disable_admin(user_id)

    #
    # File Table
    #
    def _coerce_encrypt_value(self, encrypt_value):
        if encrypt_value == 0:
            return '0'
        return encrypt_value

    def upload_file(self, filename, full_path, alias, user, access, encrypt, folder_id=None):
        if encrypt is None or encrypt == '':
            encrypt = None
        elif encrypt == 0:
            encrypt = '0'
        sql = '''INSERT OR IGNORE INTO files
                (filename, file_path, alias, uploaded_by, access, encrypt, folder_id)
                VALUES (?, ?, ?, ?, ?, ?, ?);'''
        if self.exec(sql, (filename, full_path, alias, user, access, encrypt, folder_id)) is not False:
            return True
        return False

    def list_files(self, include_size=False):
        data = []
        # Get settings once instead of subquery per row
        settings = self.get_settings()
        sql = '''SELECT id, filename, file_path, alias, upload_date, uploaded_by, access, encrypt, folder_id FROM files;'''
        for x in self.exec(sql):
            obj = {}
            obj['id'] = x[0]
            obj['filename'] = x[1]
            if obj['filename'].lower() == '.gitignore':
                continue
            obj['file_path'] = x[2]
            obj['alias'] = x[3]
            obj['upload_date'] = x[4]
            obj['uploaded_by'] = x[5]
            obj['access'] = x[6]
            obj['access_name'] = self.file_access[x[6]]
            obj['ip'] = settings.get('source_ip', '')
            obj['port'] = settings.get('source_port', 8443)
            obj['client_port'] = settings.get('client_port', 443)
            obj['encrypt'] = self._coerce_encrypt_value(x[7])
            obj['folder_id'] = x[8]
            # Only get file size if requested (slow disk I/O)
            obj['file_size'] = config.get_file_size(obj['file_path']) if include_size else ''
            data.append(obj)
        return data

    def update_access_by_id(self, file_id, access):
        if self.exec('UPDATE files SET access=? WHERE id=?;', (access, file_id)):
            return True
        return False

    def alias_exists(self, alias):
        # user for collision checks with alias names
        if int(self.exec('SELECT COUNT(id) FROM files WHERE alias=?;', (alias,))[0][0]) > 0:
            return True
        return False

    def get_file_by_alias(self, alias):
        data = {}
        for x in self.exec('SELECT id, file_path, access, encrypt FROM files WHERE alias=? LIMIT 1;', (alias,)):
            data['id'] = x[0]
            data['file_path'] = x[1]
            data['access'] = x[2]
            data['encrypt'] = self._coerce_encrypt_value(x[3])
            data['access_name'] = self.file_access[x[2]]
        return data

    def get_file_by_id(self, file_id):
        # used to pull file info for editing
        data = {}
        sql = '''SELECT filename, file_path, alias, upload_date, 
            uploaded_by, access, encrypt, folder_id
        FROM files 
        WHERE id=? LIMIT 1;'''
        for x in self.exec(sql, (file_id,)):
            data['id'] = file_id
            data['filename'] = x[0]
            data['file_path'] = x[1]
            data['alias'] = x[2]
            data['upload_date'] = x[3]
            data['uploaded_by'] = x[4]
            data['access'] = x[5]
            data['encrypt'] = self._coerce_encrypt_value(x[6])
            data['folder_id'] = x[7]
            data['access_name'] = self.file_access[x[5]]
        return data

    def update_file_by_id(self, file_id, filename, full_path, alias, user, access, encrypt, folder_id=None):
        if encrypt is None or encrypt == '':
            encrypt = None
        elif encrypt == 0:
            encrypt = '0'
        sql = '''UPDATE files
        SET filename=?, file_path=?, alias=?, encrypt=?,
        upload_date=datetime('now','localtime'), uploaded_by=?,
        access=?, folder_id=? WHERE id=?;'''
        self.exec(sql, (filename, full_path, alias, encrypt, user, access, folder_id, file_id))

    def del_file_by_id(self, file_id):
        return self.exec('DELETE FROM files WHERE id=?;', (file_id,))

    def move_file_to_folder(self, file_id, folder_id):
        # Move file to a folder (or root if folder_id is None)
        return self.exec('UPDATE files SET folder_id=? WHERE id=?;', (folder_id, file_id))

    def update_file_storage_by_id(self, file_id, full_path, folder_id):
        return self.exec('UPDATE files SET file_path=?, folder_id=? WHERE id=?;', (full_path, folder_id, file_id))

    #
    # Folder Table
    #
    def create_folder(self, folder_name, user, parent_id=None, access=2):
        access = self.normalize_folder_access(access)
        sql = '''INSERT INTO folders
                (folder_name, parent_id, created_by, access)
                VALUES (?, ?, ?, ?);'''
        result = self.exec(sql, (folder_name, parent_id, user, access))
        if result is not False:
            # Return the newly created folder ID
            folder_id = self.exec('SELECT last_insert_rowid();')[0][0]
            return folder_id
        return False

    def list_folders(self):
        data = []
        sql = '''SELECT id, folder_name, parent_id, created_date, created_by, access FROM folders;'''
        for x in self.exec(sql):
            obj = {}
            obj['id'] = x[0]
            obj['folder_name'] = x[1]
            obj['parent_id'] = x[2]
            obj['created_date'] = x[3]
            obj['created_by'] = x[4]
            obj['access'] = self.normalize_folder_access(x[5])
            obj['access_name'] = self.folder_access.get(obj['access'], 'Unknown')
            data.append(obj)
        return data

    def get_folder_by_id(self, folder_id):
        data = {}
        sql = '''SELECT folder_name, parent_id, created_date, created_by, access FROM folders WHERE id=? LIMIT 1;'''
        for x in self.exec(sql, (folder_id,)):
            data['id'] = folder_id
            data['folder_name'] = x[0]
            data['parent_id'] = x[1]
            data['created_date'] = x[2]
            data['created_by'] = x[3]
            data['access'] = self.normalize_folder_access(x[4])
            data['access_name'] = self.folder_access.get(data['access'], 'Unknown')
        return data

    def rename_folder(self, folder_id, new_name):
        return self.exec('UPDATE folders SET folder_name=? WHERE id=?;', (new_name, folder_id))

    def update_folder_access(self, folder_id, access):
        return self.exec('UPDATE folders SET access=? WHERE id=?;', (self.normalize_folder_access(access), folder_id))

    def del_folder_by_id(self, folder_id):
        # This will cascade delete subfolders and set files' folder_id to NULL
        return self.exec('DELETE FROM folders WHERE id=?;', (folder_id,))

    def get_files_in_folder(self, folder_id, include_size=False):
        # Get all files in a specific folder
        data = []
        settings = self.get_settings()
        sql = '''SELECT id, filename, file_path, alias, upload_date, uploaded_by, access, encrypt, folder_id
                 FROM files WHERE folder_id=?;'''
        for x in self.exec(sql, (folder_id,)):
            obj = {}
            obj['id'] = x[0]
            obj['filename'] = x[1]
            obj['file_path'] = x[2]
            obj['alias'] = x[3]
            obj['upload_date'] = x[4]
            obj['uploaded_by'] = x[5]
            obj['access'] = x[6]
            obj['access_name'] = self.file_access[x[6]]
            obj['ip'] = settings.get('source_ip', '')
            obj['port'] = settings.get('source_port', 8443)
            obj['client_port'] = settings.get('client_port', 443)
            obj['encrypt'] = self._coerce_encrypt_value(x[7])
            obj['folder_id'] = x[8]
            obj['file_size'] = config.get_file_size(obj['file_path']) if include_size else ''
            data.append(obj)
        return data

    def get_subfolders(self, parent_id):
        # Get all subfolders of a parent folder
        data = []
        sql = '''SELECT id, folder_name, parent_id, created_date, created_by, access FROM folders WHERE parent_id=?;'''
        for x in self.exec(sql, (parent_id,)):
            obj = {}
            obj['id'] = x[0]
            obj['folder_name'] = x[1]
            obj['parent_id'] = x[2]
            obj['created_date'] = x[3]
            obj['created_by'] = x[4]
            obj['access'] = self.normalize_folder_access(x[5])
            obj['access_name'] = self.folder_access.get(obj['access'], 'Unknown')
            data.append(obj)
        return data

    #
    # Scripts Management
    #
    def create_script(self, name, description, script_content, schedule_type, schedule_time, schedule_day_of_week, schedule_day_of_month, user, enabled=1, notify_enabled=0, notify_channel_id=None, notify_on='always', notify_skip_blank=1, notify_plain=0, notify_plain_no_codeblock=0):
        sql = '''INSERT INTO scripts
                (name, description, script_content, schedule_type, schedule_time, schedule_day_of_week, schedule_day_of_month, created_by, enabled, notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'''
        result = self.exec(sql, (name, description, script_content, schedule_type, schedule_time, schedule_day_of_week, schedule_day_of_month, user, enabled, notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock))
        if result is not False:
            script_id = self.exec('SELECT last_insert_rowid();')[0][0]
            return script_id
        return False

    def list_scripts(self):
        data = []
        sql = '''SELECT id, name, description, script_content, schedule_type, schedule_time,
                 schedule_day_of_week, schedule_day_of_month, last_run, last_output, created_by, created_date, enabled,
                 notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock FROM scripts;'''
        result = self.exec(sql)
        if not result:
            return data
        for x in result:
            obj = {}
            obj['id'] = x[0]
            obj['name'] = x[1]
            obj['description'] = x[2]
            obj['script_content'] = x[3]
            obj['schedule_type'] = x[4] or 'manual'
            obj['schedule_time'] = x[5]
            obj['schedule_day_of_week'] = x[6]
            obj['schedule_day_of_month'] = x[7]
            obj['last_run'] = x[8]
            obj['last_output'] = x[9]
            obj['created_by'] = x[10]
            obj['created_date'] = x[11]
            obj['enabled'] = x[12]
            obj['notify_enabled'] = x[13] if len(x) > 13 else 0
            obj['notify_channel_id'] = x[14] if len(x) > 14 else None
            obj['notify_on'] = x[15] if len(x) > 15 else 'always'
            obj['notify_skip_blank'] = x[16] if len(x) > 16 else 1
            obj['notify_plain'] = x[17] if len(x) > 17 else 0
            obj['notify_plain_no_codeblock'] = x[18] if len(x) > 18 else 0
            data.append(obj)
        return data

    def get_script_by_id(self, script_id):
        data = {}
        sql = '''SELECT name, description, script_content, schedule_type, schedule_time,
                 schedule_day_of_week, schedule_day_of_month, last_run, last_output, created_by, created_date, enabled,
                 notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock
                 FROM scripts WHERE id=? LIMIT 1;'''
        for x in self.exec(sql, (script_id,)):
            data['id'] = script_id
            data['name'] = x[0]
            data['description'] = x[1]
            data['script_content'] = x[2]
            data['schedule_type'] = x[3] or 'manual'
            data['schedule_time'] = x[4]
            data['schedule_day_of_week'] = x[5]
            data['schedule_day_of_month'] = x[6]
            data['last_run'] = x[7]
            data['last_output'] = x[8]
            data['created_by'] = x[9]
            data['created_date'] = x[10]
            data['enabled'] = x[11]
            data['notify_enabled'] = x[12] if len(x) > 12 else 0
            data['notify_channel_id'] = x[13] if len(x) > 13 else None
            data['notify_on'] = x[14] if len(x) > 14 else 'always'
            data['notify_skip_blank'] = x[15] if len(x) > 15 else 1
            data['notify_plain'] = x[16] if len(x) > 16 else 0
            data['notify_plain_no_codeblock'] = x[17] if len(x) > 17 else 0
        return data

    def update_script(self, script_id, name, description, script_content, schedule_type, schedule_time, schedule_day_of_week, schedule_day_of_month, enabled, notify_enabled=0, notify_channel_id=None, notify_on='always', notify_skip_blank=1, notify_plain=0, notify_plain_no_codeblock=0):
        sql = '''UPDATE scripts SET name=?, description=?, script_content=?, schedule_type=?,
                 schedule_time=?, schedule_day_of_week=?, schedule_day_of_month=?, enabled=?,
                 notify_enabled=?, notify_channel_id=?, notify_on=?, notify_skip_blank=?, notify_plain=?, notify_plain_no_codeblock=? WHERE id=?;'''
        return self.exec(sql, (name, description, script_content, schedule_type, schedule_time, schedule_day_of_week, schedule_day_of_month, enabled, notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock, script_id))

    def update_script_run(self, script_id, output):
        sql = '''UPDATE scripts SET last_run=datetime('now','localtime'), last_output=? WHERE id=?;'''
        return self.exec(sql, (output, script_id))

    def delete_script(self, script_id):
        return self.exec('DELETE FROM scripts WHERE id=?;', (script_id,))

    def get_scheduled_scripts(self):
        # Get all enabled scripts that have a schedule
        data = []
        sql = '''SELECT id, name, script_content, schedule_type, schedule_time, schedule_day_of_week,
                 schedule_day_of_month, last_run, notify_enabled, notify_channel_id, notify_on, notify_skip_blank, notify_plain, notify_plain_no_codeblock
                 FROM scripts WHERE enabled=1 AND schedule_type!='manual';'''
        result = self.exec(sql)
        if not result:
            return data
        for x in result:
            obj = {}
            obj['id'] = x[0]
            obj['name'] = x[1]
            obj['script_content'] = x[2]
            obj['schedule_type'] = x[3]
            obj['schedule_time'] = x[4]
            obj['schedule_day_of_week'] = x[5]
            obj['schedule_day_of_month'] = x[6]
            obj['last_run'] = x[7]
            obj['notify_enabled'] = x[8] if len(x) > 8 else 0
            obj['notify_channel_id'] = x[9] if len(x) > 9 else None
            obj['notify_on'] = x[10] if len(x) > 10 else 'always'
            obj['notify_skip_blank'] = x[11] if len(x) > 11 else 1
            obj['notify_plain'] = x[12] if len(x) > 12 else 0
            obj['notify_plain_no_codeblock'] = x[13] if len(x) > 13 else 0
            data.append(obj)
        return data

    #
    # Settings
    #
    def get_settings(self):
        data = {}
        sql = '''SELECT redirect_url, source_ip, source_port, param_rotation,
        param_key, max_file_size, server_header, client_port, client_enabled, proxy_enabled, webhook_url FROM settings WHERE id=1;'''

        for x in self.exec(sql):
            data['redirect_url'] = x[0]
            data['source_ip'] = x[1]
            data['source_port'] = x[2]
            data['param_rotation'] = x[3]
            data['param_key'] = x[4]
            data['max_file_size'] = x[5]
            data['server_header'] = x[6]
            data['client_port'] = x[7] if x[7] else 443
            data['client_enabled'] = x[8] if x[8] is not None else 1
            data['proxy_enabled'] = x[9] if x[9] is not None else 0
            data['webhook_url'] = x[10] if len(x) > 10 else None
        return data

    def update_settings(self, r_url, source_ip, source_port, max_size, server_header, client_port=443):
        sql = '''UPDATE settings SET
        redirect_url=?,
        source_ip=?,
        source_port=?,
        max_file_size=?,
        server_header=?,
        client_port=?
        WHERE id=1;
        '''
        self.exec(sql, (r_url, source_ip, source_port, max_size, server_header, client_port))

    def update_client_enabled(self, enabled):
        self.exec('UPDATE settings SET client_enabled=? WHERE id=1;', (1 if enabled else 0,))

    def update_proxy_enabled(self, enabled):
        self.exec('UPDATE settings SET proxy_enabled=? WHERE id=1;', (1 if enabled else 0,))

    def update_external_host(self, ip):
        # Update external IP/hostname for server
        self.exec('UPDATE settings SET source_ip=? WHERE id=1;', (ip,))

    #
    # Access Controls
    #
    def enable_param_key(self):
        self.exec('UPDATE settings SET param_rotation=1 WHERE id=1;')

    def disable_param_key(self):
        self.exec('UPDATE settings SET param_rotation=0 WHERE id=1;')

    def update_param_key(self, k):
        self.exec('UPDATE settings SET param_key=? WHERE id=1;', (k,))

    def get_allow_address(self):
        # Allow list of IPs allowed to access alias files
        data = []
        for x in self.exec('SELECT ip FROM ip_allow_list;'):
            data.append(x[0])
        return data

    def get_allow_agent(self):
        # Allow list of user-agents allowed to access alias files
        data = []
        for x in self.exec('SELECT agent FROM ua_allow_list;'):
            data.append(x[0])
        return data

    def get_allow_login(self):
        # Returns list of IP's allowed to access /login
        data = []
        for x in self.exec('SELECT ip FROM ip_allow_login;'):
            data.append(x[0])
        return data

    def load_proxy_routes(self):
        return {x[0]: x[1] for x in self.exec("SELECT path, redirect_url FROM proxy_routes")}

    def lookup_proxy_route(self, path):
        for x in self.exec("SELECT redirect_url FROM proxy_routes WHERE path=? LIMIT 1", (path,)):
            return x[0]
        return False

    def update_proxy_routes(self, routes={}):
        # Truncate DB and re-add
        self.exec('''DELETE FROM proxy_routes;''')
        for path, redirect_url in routes.items():
            self.exec("INSERT INTO proxy_routes (path, redirect_url) VALUES (?, ?)", (path, redirect_url))

    def get_response_headers(self):
        """Get all custom response headers as a dict"""
        try:
            result = self.exec("SELECT header_name, header_value FROM response_headers")
            if result:
                return {x[0]: x[1] for x in result}
        except:
            pass
        return {}

    def update_response_headers(self, headers={}):
        """Update response headers - truncate and re-add"""
        self.exec('''DELETE FROM response_headers;''')
        for name, value in headers.items():
            if name and value:  # Skip empty entries
                self.exec("INSERT INTO response_headers (header_name, header_value) VALUES (?, ?)", (name.strip(), value.strip()))

    def update_allow_address(self, form_input):
        # Truncate DB and re-add
        self.exec('''DELETE FROM ip_allow_list;''')
        if form_input:
            # Force localhost record to preserve app functionality
            self.executemany('INSERT OR IGNORE INTO ip_allow_list (ip) VALUES (?);',[("127.0.0.1",), ("localhost",)])
            # Add form inputs
            for x in form_input.split('\n'):
                self.exec('INSERT OR IGNORE INTO ip_allow_list (ip) VALUES (?);', (x.strip(),)) if x else False


    def update_allow_agent(self, form_input):
        # Truncate DB and re-add
        self.exec('''DELETE FROM ua_allow_list;''')
        if form_input:
            for x in form_input.split('\n'):
                self.exec('INSERT OR IGNORE INTO ua_allow_list (agent) VALUES (?);', (x.strip(),)) if x else False

    def update_allow_login(self, form_input):
        # Truncate DB and re-add
        self.exec('''DELETE FROM ip_allow_login;''')
        if form_input:
            # Force localhost record to prevent lockout
            self.executemany(
                'INSERT OR IGNORE INTO ip_allow_login (ip) VALUES (?);',[("127.0.0.1",), ("localhost",)])

            # Add form inputs
            for x in form_input.split('\n'):
                if x.strip():
                    self.exec('INSERT OR IGNORE INTO ip_allow_login (ip) VALUES (?);',(x.strip(),))

    # ===== DISPATCH LOGGING METHODS =====

    def add_log(self, message, level='INFO', user=None, user_id=None, user_role=None, ip=None):
        """Add a log entry to the database - timestamp auto-populates"""
        sql = '''INSERT INTO dispatch_logs (level, message, user, user_id, user_role, ip)
                 VALUES (?, ?, ?, ?, ?, ?);'''
        self.exec(sql, (level, message, user, user_id, user_role, ip))
        return True

    def list_logs(self, limit=100, level=None, user=None, search=None):
        """Get log entries with optional filtering"""
        data = []
        sql = '''SELECT id, timestamp, level, message, user, user_id, user_role, ip
                 FROM dispatch_logs ORDER BY timestamp DESC LIMIT ?;'''
        for x in self.exec(sql, (limit,)):
            obj = {
                'id': x[0],
                'timestamp': x[1] or '',
                'level': x[2] or 'INFO',
                'message': x[3] or '',
                'user': x[4] or '',
                'user_id': x[5],
                'user_role': x[6] or '',
                'ip': x[7] or ''
            }
            data.append(obj)
        return data

    def clear_logs(self):
        """Clear all log entries from the database"""
        self.exec('DELETE FROM dispatch_logs;')
        return True

    def get_log_stats(self):
        """Get log statistics"""
        stats = {
            'total': 0,
            'errors': 0,
            'warnings': 0,
            'info': 0
        }
        result = self.exec('SELECT COUNT(*) FROM dispatch_logs;')
        if result:
            stats['total'] = result[0][0]

        result = self.exec("SELECT COUNT(*) FROM dispatch_logs WHERE level IN ('ERROR', 'CRITICAL');")
        if result:
            stats['errors'] = result[0][0]

        result = self.exec("SELECT COUNT(*) FROM dispatch_logs WHERE level = 'WARNING';")
        if result:
            stats['warnings'] = result[0][0]

        result = self.exec("SELECT COUNT(*) FROM dispatch_logs WHERE level = 'INFO';")
        if result:
            stats['info'] = result[0][0]

        return stats

    # ===== WEBHOOK METHODS =====

    def get_webhook_url(self):
        """Get Discord webhook URL from settings"""
        result = self.exec('SELECT webhook_url FROM settings WHERE id=1;')
        if result and result[0][0]:
            return result[0][0]
        return None

    def update_webhook_url(self, url):
        """Update Discord webhook URL in settings"""
        self.exec('UPDATE settings SET webhook_url=? WHERE id=1;', (url if url else None,))
        return True

    # ===== ALERT METHODS =====

    def get_alerts(self):
        """List all configured alerts"""
        data = []
        sql = '''SELECT id, alert_type, target_id, target_value, description, enabled, created_date
                 FROM alerts ORDER BY created_date DESC;'''
        result = self.exec(sql)
        if not result:
            return data
        for x in result:
            obj = {
                'id': x[0],
                'alert_type': x[1],
                'target_id': x[2],
                'target_value': x[3],
                'description': x[4],
                'enabled': x[5],
                'created_date': x[6]
            }
            data.append(obj)
        return data

    def create_alert(self, alert_type, target_id=None, target_value=None, description=None):
        """Create a new alert"""
        sql = '''INSERT INTO alerts (alert_type, target_id, target_value, description)
                 VALUES (?, ?, ?, ?);'''
        result = self.exec(sql, (alert_type, target_id, target_value, description))
        if result is not False:
            alert_id = self.exec('SELECT last_insert_rowid();')[0][0]
            return alert_id
        return False

    def update_alert(self, alert_id, enabled):
        """Update alert enabled status"""
        return self.exec('UPDATE alerts SET enabled=? WHERE id=?;', (enabled, alert_id))

    def delete_alert(self, alert_id):
        """Delete an alert"""
        return self.exec('DELETE FROM alerts WHERE id=?;', (alert_id,))

    def get_alerts_by_type(self, alert_type):
        """Get all enabled alerts of a specific type"""
        data = []
        sql = '''SELECT id, alert_type, target_id, target_value, description, enabled, created_date
                 FROM alerts WHERE alert_type=? AND enabled=1;'''
        result = self.exec(sql, (alert_type,))
        if not result:
            return data
        for x in result:
            obj = {
                'id': x[0],
                'alert_type': x[1],
                'target_id': x[2],
                'target_value': x[3],
                'description': x[4],
                'enabled': x[5],
                'created_date': x[6]
            }
            data.append(obj)
        return data
