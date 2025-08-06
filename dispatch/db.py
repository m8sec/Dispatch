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

    db_schema = [
        '''CREATE TABLE IF NOT EXISTS users (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "username" TEXT UNIQUE NOT NULL,
        "password" TEXT NOT NULL,
        "api_key" TEXT UNIQUE,
        "created" DATETIME DEFAULT (datetime('now','localtime')), 
        "last_login" DATETIME DEFAULT (datetime('now','localtime')),  
        "role" INTEGER DEFAULT 0);''',

        '''INSERT OR IGNORE INTO users 
        (id, username, password, role) 
        VALUES (1, "{}", "{}", 4);'''.format(config.DEFAULT_USER, gen_password_hash(config.DEFAULT_PWD)),

        '''CREATE TABLE IF NOT EXISTS files (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "filename" TEXT UNIQUE NOT NULL,
        "file_path" TEXT UNIQUE NOT NULL,
        "access" INTEGER DEFAULT 3,
        "alias" TEXT UNIQUE NOT NULL,
        "upload_date" DATETIME DEFAULT (datetime('now','localtime')),  
        "uploaded_by" TEXT NOT NULL);''',

        '''CREATE TABLE IF NOT EXISTS settings (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "redirect_url" TEXT,
        "source_ip" TEXT,
        "server_header" TEXT,
        "param_rotation" BOOLEAN DEFAULT 0,
        "param_key" TEXT DEFAULT 's=1234',
        "max_file_size" INTEGER DEFAULT {});'''.format(config.MAX_FILE_SIZE),

        '''INSERT OR IGNORE INTO settings 
        (redirect_url, source_ip, server_header) 
        VALUES ("https://google.com", "127.0.0.1", "Apache");''',

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
        "redirect_url" TEXT NOT NULL);'''
    ]

    def __init__(self, db_file, timeout=3):
        SqliteDB.__init__(self, db_file, timeout)

    #
    # Application Support
    #
    def setup_db(self):
        for sql in self.db_schema:
            self.exec(sql)

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
        return self.exec('UPDATE users SET role=? WHERE id=?;', (role, id)) if id > 1 else False

    def update_key_by_id(self, id, api_key):
        # Update user api key
        self.exec('UPDATE users SET api_key=? WHERE id=?;', (api_key, id))

    def update_user_password_by_id(self, id, password):
        self.exec('UPDATE users SET password=? WHERE id=?;', (gen_password_hash(password), id))

    def del_user_by_id(self, id):
        # Cannot delete built-in admin
        return self.exec('DELETE FROM users WHERE id=?;', (id,)) if id > 1 else False

    def list_users(self, user_id, user_role):
        data = []
        if user_role > 3:
            query = self.exec('SELECT id, username, created, last_login, role FROM users;')
        else:
            # Only allow users to list accounts lower than them unless super admin
            sql = 'SELECT id, username, created, last_login, role FROM users WHERE role<? OR id=?;'
            query = self.exec(sql, (user_role, user_id))
        for x in query:
            obj = {}
            obj['id'] = x[0]
            obj['username'] = x[1]
            obj['created'] = x[2]
            obj['last_login'] = x[3]
            obj['role'] = x[4]
            obj['role_name'] = self.user_roles[x[4]]
            data.append(obj)
        return data

    def get_user_by_id(self, id):
        data = {}
        for x in self.exec('SELECT username, created, last_login, role, api_key FROM users WHERE id=?;', (id,)):
            data['id'] = id
            data['username'] = x[0]
            data['created'] = x[1]
            data['last_login'] = x[2]
            data['role'] = x[3]
            data['role_name'] = self.user_roles[x[3]]
            data['api_key'] = x[4] if x[4] is not None else ''
        return data

    #
    # File Table
    #
    def upload_file(self, filename, full_path, alias, user, access):
        sql = '''INSERT OR IGNORE INTO files 
                (filename, file_path, alias, uploaded_by, access) 
                VALUES (?, ?, ?, ?, ?)'''
        if self.exec(sql, (filename, full_path, alias, user, access)) is not False:
            return True
        return False

    def list_files(self):
        data = []
        sql = '''SELECT id, filename, file_path, alias, upload_date, uploaded_by, access,
                 (SELECT source_ip FROM settings) FROM files;'''
        for x in self.exec(sql):
            obj = {}
            obj['id'] = x[0]
            obj['filename'] = x[1]
            obj['file_path'] = x[2]
            obj['alias'] = x[3]
            obj['upload_date'] = x[4]
            obj['uploaded_by'] = x[5]
            obj['access'] = x[6]
            obj['access_name'] = self.file_access[x[6]]
            obj['ip'] = x[7]
            obj['file_size'] = config.get_file_size(obj['file_path'])
            data.append(obj)
        return data

    def update_access_by_id(self, id, access):
        if self.exec('UPDATE files SET access=? WHERE id=?;', (access, id)):
            return True
        return False

    def alias_exists(self, alias):
        # user for collision checks with alias names
        if int(self.exec('SELECT COUNT(id) FROM files WHERE alias=?;', (alias,))[0][0]) > 0:
            return True
        return False

    def get_file_by_alias(self, alias):
        data = {}
        for x in self.exec('SELECT id, file_path, access FROM files WHERE alias=? LIMIT 1;', (alias,)):
            data['id'] = x[0]
            data['file_path'] = x[1]
            data['access'] = x[2]
            data['access_name'] = self.file_access[x[2]]
        return data

    def get_file_by_path(self, file_path):
        # Check file exists for reload feature
        data = {}
        for x in self.exec('SELECT id FROM files WHERE file_path=? LIMIT 1;', (file_path,)):
            data['id'] = x[0]
        return data

    def get_file_by_id(self, id):
        # used to pull file info for editing
        data = {}
        sql = '''SELECT filename, file_path, alias, upload_date, 
            uploaded_by, access 
        FROM files 
        WHERE id=? LIMIT 1;'''
        for x in self.exec(sql, (id,)):
            data['id'] = id
            data['filename'] = x[0]
            data['file_path'] = x[1]
            data['alias'] = x[2]
            data['upload_date'] = x[3]
            data['uploaded_by'] = x[4]
            data['access'] = x[5]
            data['access_name'] = self.file_access[x[5]]
        return data

    def update_file_by_id(self, id, filename, full_path, alias, user, access):
        sql = '''UPDATE files 
        SET filename=?, file_path=?, alias=?, 
        upload_date=datetime('now','localtime'), uploaded_by=?,
        access=? WHERE id=?;'''
        self.exec(sql, (filename, full_path, alias, user, access, id))

    def del_file_by_id(self, id):
        return self.exec('DELETE FROM files WHERE id=?;', (id,))

    #
    # Settings
    #
    def get_settings(self):
        data = {}
        sql = '''SELECT redirect_url, source_ip, param_rotation, 
        param_key, max_file_size, server_header FROM settings WHERE id=1;'''

        for x in self.exec(sql):
            data['redirect_url'] = x[0]
            data['source_ip'] = x[1]
            data['param_rotation'] = x[2]
            data['param_key'] = x[3]
            data['max_file_size'] = x[4]
            data['server_header'] = x[5]
        return data

    def update_settings(self, r_url, source_ip, max_size, server_header):
        sql = '''UPDATE settings SET 
        redirect_url=?,
        source_ip=?,
        max_file_size=?,
        server_header=?
        WHERE id=1;
        '''
        self.exec(sql, (r_url, source_ip, max_size, server_header))

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



