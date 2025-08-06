#!/usr/bin/env python3
import os
import logging
import requests
from json import dumps
from urllib.parse import urlparse
from markupsafe import escape, Markup
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, request, redirect, render_template, Response, send_file, current_app, abort, url_for

from dispatch import auth
from dispatch import config
from dispatch.db import DispatchDB
log = logging.getLogger('dispatch-logger')


class DispatchServer(object):
    app = Flask(__name__)
    app.secret_key = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE
    app.config['allow_ip'] = []
    app.config['allow__ua'] = []
    app.config['allow_login'] = []
    app.config['redirect_url'] = ''

    @app.route('/', methods=['GET'])
    @auth.login_required
    def index(token, status_msg=''):
        db = DispatchDB(current_app.config['db_name'])
        upload_dir = os.listdir(config.FILE_PATH)
        file_list = db.list_files()

        # Write manually added files via console to DB
        file_names = [x['filename'] for x in file_list]
        for f in upload_dir:
            if f != '.gitignore' and f not in file_names:
                alias = config.gen_alias(config.get_file_extension(f))
                db.upload_file(f, os.path.join(config.FILE_PATH, f), alias, token['user'], 3)

        # Remove manually deleted files via console from DB
        for f in file_list:
            if f['filename'] not in upload_dir:
                db.del_file_by_id(f['id'])
        db.close()
        return render_template('index.html', token=token, config=current_app.config, status_msg=status_msg)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_app.config['allow_login'] and request.remote_addr not in current_app.config['allow_login']:
            logging.debug(f'Rejected login attempt from {request.remote_addr} due to login restrictions.')
            return redirect(current_app.config['redirect_url'], 302)

        status = '<div></div>'
        if request.method == 'POST':
            db = DispatchDB(config.DB_NAME)

            if db.validate_login(request.form['username'].lower(), request.form['password']):
                user_data = auth.loadUser(db, request.form['username'].lower())
                config.log("Web login successful", user_data, request.remote_addr)

                if user_data['role'] > 0:
                    jwt_token = auth.createToken(user_data)
                    resp = redirect('/', code=302)
                    resp.set_cookie(config.COOKIE_NAME, value=jwt_token, path="/", httponly=True, secure=True)
                    return resp
                else:
                    status = '<div style="color:red;">User disabled</div>'
            else:
                status = '<div style="color:red;">Login Failed</div>'
        return render_template('login.html', login_status=Markup(status))

    @app.route('/logout', methods=['GET'])
    def logout():
        return auth.signOut()

    #
    # Settings pages
    #
    @app.route('/settings', methods=['GET', 'POST'])
    @auth.operator_required
    def settings(token):
        if request.method == 'POST':
            db = DispatchDB(current_app.config['db_name'])
            if request.form['name'] == 'ui_settings':
                a = request.form['redirect_url']
                b = request.form['source_ip']
                c = request.form['max_size']
                d = request.form['server_header']
                db.update_settings(a, b, c, d)
                config.log(f"Settings changed", token, request.remote_addr)

            elif request.form['name'] == 'login_restrictions':
                db.update_allow_login(request.form['allow_login'])
                config.log(f"Login restrictions updated", token, request.remote_addr)

            config.refresh_app_configs(db, current_app)
            db.close()
        return render_template('settings/settings.html', token=token, config=current_app.config)

    @app.route('/settings/access', methods=['GET', 'POST'])
    @auth.operator_required
    def access_restrictions(token):
        if request.method == 'POST':
            db = DispatchDB(current_app.config['db_name'])
            allow_ip = request.form['allow_ip']
            allow_ua = request.form['allow_ua']
            param_rotation = int(request.form['param_rotation'])

            db.update_allow_address(allow_ip)
            db.update_allow_agent(allow_ua)

            if current_app.config['param_rotation'] == 0 and param_rotation == 1:
                db.enable_param_key()
                current_app.config['param_rotation'] = 1
                update_param_key(db)
            elif current_app.config['param_rotation'] == 1 and param_rotation == 0:
                db.disable_param_key()

            config.refresh_app_configs(db, current_app)
            config.log(f"Access restrictions updated", token, request.remote_addr)
            db.close()
        return render_template('settings/access.html', token=token, config=current_app.config)

    @app.route('/settings/proxy', methods=['GET', 'POST'])
    @auth.operator_required
    def c2_redirectors(token):
        db = DispatchDB(current_app.config['db_name'])
        try:
            if request.method == 'POST':
                # Convert form data to dictionary {path: redirect}
                paths = request.form.getlist("path[]")  # Extract paths
                redirects = request.form.getlist("redirect[]")  # Extract redirect URLs
                route_dict = {path: redirect for path, redirect in zip(paths, redirects)}

                # Update DB
                db.update_proxy_routes(route_dict)
                config.log(f"Reverse proxy routes updated", token, request.remote_addr)

            routes = db.load_proxy_routes()
            return render_template('settings/proxy.html', token=token, routes=routes, config=current_app.config)
        finally:
            db.close()

    @app.route('/settings/log', methods=['GET'])
    @auth.operator_required
    def dispatch_log(token):
        with open(config.DISPATCH_LOG, 'r') as f:
            return render_template('settings/log.html', token=token, content=escape(f.read()), config=current_app.config)

    #
    # File Interactions
    #
    @app.route('/file/cradles', methods=['GET'])
    @auth.login_required
    def documentation_download(token):
        return render_template('files/cradles.html', token=token, config=current_app.config)


    @app.route('/file/upload', methods=['GET', 'POST'])
    @auth.upload_only_required
    def upload_file(token, status_msg=''):
        if request.method == 'POST':
            f = request.files['file']
            if f.filename == '':
                status_msg = Markup('<script>showNotification("No File Selected.", false);</script>')
                return render_template('files/upload.html', token=token, status_msg=status_msg, config=current_app.config)

            fname = config.file_collision_check(secure_filename(f.filename))
            full_path = os.path.join(config.FILE_PATH, fname)
            try:
                f.save(full_path)
            except RequestEntityTooLarge:
                status_msg = Markup('<script>showNotification("File Exceed Max Size.", false);</script>')
                return render_template('files/upload.html', token=token, status_msg=status_msg, config=current_app.config)

            # File access permissions
            access_id = request.form.get('access', type=int)
            access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

            # Generate alias
            db = DispatchDB(current_app.config['db_name'])
            alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))
            alias = config.alias_collision_check(db, alias)

            if db.upload_file(fname, full_path, alias, token['user'], access) is not False:
                status_msg = Markup('<script>showNotification("File uploaded successfully!");</script>')
                return redirect(url_for('index'))
            else:
                status_msg = Markup('<script>showNotification("File upload failed.", false);</script>')
        return render_template('files/upload.html', token=token, status_msg=status_msg, config=current_app.config)

    @app.route('/file/create', methods=['GET', 'POST'])
    @auth.upload_only_required
    def create_file(token, status_msg=''):
        if request.method == 'POST':
            fname = request.form['filename'] if request.form['filename'] != '' else config.gen_filename()
            fname = config.file_collision_check(secure_filename(fname))

            full_path = os.path.join(config.FILE_PATH, fname)
            if request.form['file_content']:
                with open(full_path, 'w') as f:
                    f.write(request.form['file_content'])
            else:
                status_msg = Markup('<div style="color:red;margin-bottom:8px;">No content provided.</div>')
                return render_template('files/create.html', token=token, status_msg=status_msg, config=current_app.config)

            # File access permissions
            access_id = request.form.get('access', type=int)
            access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

            # Generate alias
            db = DispatchDB(current_app.config['db_name'])
            alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))
            alias = config.alias_collision_check(db, alias)

            if db.upload_file(fname, full_path, alias, token['user'], access) is not False:
                #status_msg = Markup('<script>showNotification("File uploaded successfully!", true);</script>')
                return redirect(url_for('index'))
            else:
                status_msg = Markup('<script>showNotification("File upload failed.", false);</script>')
        return render_template('files/create.html', token=token, status_msg=status_msg, config=current_app.config)

    @app.route('/file/download', methods=['GET', 'POST'])
    @auth.upload_only_required
    def download_file(token, status_msg=''):
        if request.method == 'POST':
            if request.form['filename']:
                fname = request.form['filename']
            else:
                u = urlparse(request.form['url'])
                fname = os.path.basename(u.path)

            fname = config.file_collision_check(secure_filename(fname))
            full_path = os.path.join(config.FILE_PATH, fname)

            if not config.download_file(request.form['url'], full_path):
                status_msg = Markup('<div style="color:red;margin-bottom:8px;">Failed to download file.</div>')
                return render_template('files/download.html', token=token, status_msg=status_msg, config=current_app.config)

            # File access permissions
            access_id = request.form.get('access', type=int)
            access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

            # Generate alias
            db = DispatchDB(current_app.config['db_name'])
            alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))
            alias = config.alias_collision_check(db, alias)

            if db.upload_file(fname, full_path, alias, token['user'], access) is not False:
                #status_msg = Markup('<script>showNotification("File uploaded successfully!", true);</script>')
                return redirect(url_for('index'))
            else:
                status_msg = Markup('<script>showNotification("File upload failed.", false);</script>')
        return render_template('files/download.html', token=token, status_msg=status_msg, config=current_app.config)

    @app.route('/file/delete', methods=['GET'])
    @auth.operator_required
    def delete_file(token):
        if 'id' in request.args.keys():
            id = request.args.get('id', type=int)
            db = DispatchDB(current_app.config['db_name'])
            data = db.get_file_by_id(id)
            if data and os.path.exists(data['file_path']):
                db.del_file_by_id(id)
                os.remove(data['file_path'])
                config.log(f"Deleted file: {data['filename']}", token, request.remote_addr)
            db.close()
        return redirect(url_for('index'))

    @app.route('/file/edit', methods=['GET', 'POST'])
    @auth.operator_required
    def edit_file(token):
        if request.method == 'POST':
            # Replace or Rename file - if content editing enabled.
            og_file_path = os.path.join(config.FILE_PATH, request.form['old_filename'])

            if request.form['old_filename'] == request.form['filename']:
                fname = request.form['old_filename']
            else:
                fname = request.form['filename'] if request.form['filename'] != '' else config.gen_filename()
                fname = config.file_collision_check(secure_filename(fname))
            full_path = os.path.join(config.FILE_PATH, fname)

            if 'file_content' in request.form.keys():
                try:
                    os.remove(og_file_path)
                    with open(full_path, 'w') as f:
                        f.write(request.form['file_content'])
                except:
                    pass
            else:
                os.rename(og_file_path, full_path)

            # Update Reference in DB
            db = DispatchDB(current_app.config['db_name'])

            # Validate alias
            if request.form['old_alias'] == request.form['alias']:
                alias = request.form['old_alias']
            else:
                alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))

            # Ensure no alias collisions
            alias = config.alias_collision_check(db, alias)

            # File access permissions
            access_id = request.form.get('access', type=int)
            access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

            # Update references in db
            db.update_file_by_id(request.form['id'], fname, full_path, alias, token['user'], access)
            db.close()
            return redirect(url_for('index'))

        if 'id' in request.args.keys():
            db = DispatchDB(current_app.config['db_name'])
            data = db.get_file_by_id(request.args.get('id', type=int))
            db.close()
            with open(data['file_path'], 'r') as f:
                try:
                    content = f.read()
                except:
                    content = False
                return render_template('files/edit.html', token=token, data=data, content=str(content))
        return redirect(url_for('index'))

    #
    # User Management
    #
    @app.route('/users', methods=['GET', 'POST'])
    @auth.admin_required
    def users(token):
        return render_template('users/list.html', token=token, config=current_app.config)

    @app.route('/user/delete', methods=['GET'])
    @auth.admin_required
    def user_delete(token):
        if 'id' in request.args.keys():
            id = request.args.get('id', type=int)
            if id is not None and id != token['id']:
                db = DispatchDB(current_app.config['db_name'])
                user = db.get_user_by_id(id)

                if user['role'] < token['role'] or token['role'] > 3:
                    db.del_user_by_id(id)
                    db.close()
                    config.log(f"Deleted user: {user['username']}", token, request.remote_addr)
        return redirect()

    @app.route('/user/add', methods=['GET', 'POST'])
    @auth.admin_required
    def user_add(token, status_msg=''):
        """
        Access: Private
        Role: 3
        Description: Add new user - operators will only be allowed to add user roles lower than themselves.
        """
        if request.method == 'POST':
            if config.validate_username(request.form['username']):
                if request.form['password'] == request.form['confirm_password'] and len(request.form['password']) >= 10:
                    # Validate Role
                    db = DispatchDB(current_app.config['db_name'])
                    role_id = request.form.get('user_role', type=int)
                    if role_id < token['role'] or token['role'] > 3:
                        # Create New User + Init API Key
                        role = role_id if role_id in [0, 1, 2, 3, 4] else 0
                        db.add_user(request.form.get('username'), request.form.get('password'), role)
                        db.close()
                        config.log(f'New user created: {escape(request.form.get("username"))}', token, request.remote_addr)
                        return redirect(url_for('users'))
                    else:
                        status_msg = Markup('<script>showNotification("Invalid Permissions.", false);</script>')
                else:
                    status_msg = Markup('<script>showNotification("Invalid Inputs.", false);</script>')
            else:
                status_msg = Markup('<script>showNotification("Invalid Username.", false);</script>')
        return render_template('users/add.html', token=token, config=current_app.config, user=False, status_msg=status_msg)

    @app.route('/user/edit', methods=['GET', 'POST'])
    @auth.login_required
    def user_edit(token, status_msg=''):
        """
        Access: Private
        Role: 1
        Description: Edit user - operators will only be allowed to edit user roles lower than themselves.
        """
        if request.method == 'POST':
            db = DispatchDB(current_app.config['db_name'])
            user_id = request.form.get('id', type=int)
            user = db.get_user_by_id(user_id)

            if user['id'] == token['id'] or (token['role'] > 2 and user['role'] < 3) or token['role'] > 3:
                password = request.form['password']
                confirm_password = request.form['confirm_password']
                if password == confirm_password and config.validate_password(password):
                    db.update_user_password_by_id(user_id, password)
                    config.log(f'Changed password for {user["username"]}', token, request.remote_addr)
                    status_msg = Markup('<script>showNotification("Password Updated Successfully.");</script>')
                else:
                    status_msg = Markup('<script>showNotification("Invalid Inputs.", false);</script>')
            else:
                status_msg = Markup('<script>showNotification("Invalid Permissions.", false);</script>')
            db.close()
            return render_template('users/add.html', token=token, user=user, status_msg=status_msg)

        if 'id' in request.args.keys():
            db = DispatchDB(current_app.config['db_name'])
            user = db.get_user_by_id(request.args.get('id', type=int))
            if user['id'] == token['id'] or (token['role'] > 2 and user['role'] < 3) or token['role'] > 3:
                db.close()
                return render_template('users/add.html', token=token, user=user, status_msg=status_msg)
            db.close()
        return redirect(url_for('users'))

    @app.route('/api/users/list', methods=['GET'])
    @auth.admin_required
    def api_list_users(token):
        """
        Access: Private
        Role: 3
        Description: List users with permissions of current
        """
        db = DispatchDB(current_app.config['db_name'])
        data = db.list_users(token['id'], token['role'])
        db.close()
        return Response(response=dumps(data), status=200, mimetype='application/json')

    @app.route('/api/users/gen-key', methods=['POST'])
    @auth.api_download_only_required
    def user_refresh_api_key(token):
        """
        Access: Private
        Role: 1
        Description: Re-Generate API key
        """
        db = DispatchDB(current_app.config['db_name'])
        try:
            j = request.get_json(force=True)
            data = db.get_user_by_id(int(j['id']))
            if int(j['id']) == token['id'] or token['role'] > 2 and (data['role'] < 3 or token['role'] > 3):
                k = config.gen_api_key()
                db.update_key_by_id(int(j['id']), k)
                config.log(f'Generated API Key for {data["username"]}', token, request.remote_addr)
                return Response(response=dumps({'key': k}), status=200, mimetype='application/json')
        except:
            pass
        finally:
            db.close()
        return abort(403)

    @app.route('/api/user/get-key', methods=['POST'])
    @auth.api_download_only_required
    def api_get_user_api_key(token):
        """
        Access: Private
        Role: 1
        Description: Take in current user's JWT token and return api key
        """
        db = DispatchDB(current_app.config['db_name'])
        data = db.get_user_by_id(token['id'])
        db.close()
        if (data['id'] == token['id'] or token['role'] > 3) and (data['role'] < 3 or token['role'] > 3):
            return Response(response=dumps({'key': data['api_key']}), status=200, mimetype='application/json')
        return abort(403)

    @app.route('/api/users/update-role', methods=['POST'])
    @auth.api_operator_required
    def api_update_user_role(token):
        """
        Access: Private
        Role: 3
        Description: Update user role within permissions of current user
        """
        try:
            j = request.get_json(force=True)
            # Check valid inputs
            if int(j['id']) and int(j['role']) in [0, 1, 2, 3, 4]:
                # Users cannot delete themselves
                if int(j['id']) != token['id']:
                    # Open database and retrieve target user info
                    db = DispatchDB(current_app.config['db_name'])
                    user = db.get_user_by_id(int(j['id']))
                # Target user & role is < current OR admin user
                if (user['role'] < token['role'] and int(j['role']) < token['role']) or token['role'] > 3:
                    db.update_role_by_id(int(j['id']), int(j['role']))
                    db.close()
                    config.log(f'{user["username"]} changed to {db.user_roles[int(j["role"])]}', token, request.remote_addr)
                    return Response(response=dumps({'200': 'Success'}), status=200, mimetype='application/json')
                return abort(403)
        except Exception as e:
            logging.debug(f"Error updating user role: {e}")
        return abort(403)

    @app.route('/api/files/list', methods=['GET'])
    @auth.api_operator_required
    def api_list_files(token):
        db = DispatchDB(current_app.config['db_name'])
        data = db.list_files()
        db.close()
        return Response(response=dumps(data), status=200, mimetype='application/json')

    @app.route('/api/files/update-access', methods=['POST'])
    @auth.api_operator_required
    def api_update_file_access(token):
        try:
            j = request.get_json(force=True)
            if int(j['id']) and int(j['access']) in [1, 2, 3]:
                db = DispatchDB(current_app.config['db_name'])
                db.update_access_by_id(int(j['id']), int(j['access']))
                db.close()
                return Response(response=dumps({'200': 'Success'}), status=200, mimetype='application/json')
        except:
            pass
        return abort(403)

    @app.route('/api/file/upload', methods=['POST'])
    @auth.api_upload_only_required
    def api_upload_file(token):
        f = request.files['file']
        if f.filename != '':
            fname = config.file_collision_check(secure_filename(f.filename))
            full_path = os.path.join(config.FILE_PATH, fname)
            try:
                f.save(full_path)

                # File access permissions
                access_id = request.form.get('access', type=int)
                access = access_id if access_id is not None and access_id in [1, 2, 3] else 3

                # Generate alias
                db = DispatchDB(current_app.config['db_name'])
                alias = request.form['alias'] if request.form['alias'] != '' else config.gen_alias(config.get_file_extension(fname))
                alias = config.alias_collision_check(db, alias)

                # On valid request, send alias URL
                param_key = "?" + current_app.config['param_key'] if current_app.config['param_rotation'] else ''
                alias_url = f'https://{current_app.config["source_ip"]}/{alias}{param_key}'

                if db.upload_file(fname, full_path, alias, token['user'], access) is not False:
                    return Response(response=dumps({'url': alias_url}), status=200, mimetype='application/json')
            except:
                pass
        return abort(403)

    @app.route('/api/files/param-key', methods=['GET'])
    @auth.api_download_only_required
    def api_get_param_key(token):
        k = current_app.config.get('param_key', '')
        return Response(response=dumps({'key': f'?{k}'}), status=200, mimetype='application/json')


    #
    # Primary Ruleset for Redirection
    #
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
    def catch_all(path):
        """Wildcard route to validate user and delivery payload/redirect"""
        #
        # Safety checks
        #
        if is_blocked_by_ip(request.remote_addr):
            logging.debug(f'Rejected "{path}" due to blocked IP: {request.remote_addr}')
            return redirect(current_app.config['redirect_url'], 302)

        if is_blocked_by_user_agent(request.user_agent.string):  # Ensure user-agent is a string
            logging.debug(f'Rejected "{path}" due to blocked User-Agent: "{request.user_agent}"')
            return redirect(current_app.config['redirect_url'], 302)

        try:
            db = DispatchDB(current_app.config['db_name'])

            #
            # Serve reverse proxy
            #
            redirect_path = db.lookup_proxy_route(request.path)
            if redirect_path:
                return reverse_proxy(redirect_path)
            
            #
            # Param Key checked after proxy
            #
            if is_invalid_param_key(request.full_path):
                logging.debug(f'Rejected "{path}" due to invalid param key.')
                return redirect(current_app.config['redirect_url'], 302)

            #
            # Serve Files
            #
            data = db.get_file_by_alias(path)
            if not data:
                db.close()
                return redirect(current_app.config['redirect_url'], 302)

            #  Public & Public Once files
            if data['access'] < 3:
                if data['access'] == 2:
                    # "Public Once" files revert to private
                    db.update_access_by_id(data['id'], 3)

                update_param_key(db)
                db.close()
                config.log(f'Accessed File: {path}', False, request.remote_addr)
                return serve_file(data['file_path'], path)

            # Check authentication (API Key or JWT Token)
            token = (
                auth.validateKey(request)
                if request.headers.get(config.API_HEADER)
                else auth.validateToken(request)
            )

            # Allow only users with role 1 (Download), 3, or 4 (Admin)
            if token and token.get('role') in {1, 3, 4}:
                update_param_key(db)
                db.close()
                config.log(f'Accessed File: {path}', token, request.remote_addr)
                return serve_file(data['file_path'], path)

            # Catch all bad traffic
            return redirect(current_app.config['redirect_url'], 302)
        finally:
            db.close()

    #
    # User Docs
    #
    @app.route('/docs/users', methods=['GET'])
    @auth.login_required
    def documentation_users(token):
        return render_template('docs/users.html', token=token, config=current_app.config)

    @app.route('/docs/files', methods=['GET'])
    @auth.login_required
    def documentation_files(token):
        return render_template('docs/files.html', token=token, config=current_app.config)

    @app.route('/docs/access', methods=['GET'])
    @auth.login_required
    def documentation_access(token):
        return render_template('docs/access.html', token=token, config=current_app.config)

    @app.route('/docs/upload', methods=['GET'])
    @auth.login_required
    def documentation_upload(token):
        return render_template('docs/upload.html', token=token, config=current_app.config)

    #
    # Login Protected Resources
    #
    @app.route('/js/dispatch.js', methods=['GET'])
    @auth.login_required
    def js_dispatch(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'js', 'dispatch.js'), download_name=fname, as_attachment=False)

    @app.route('/img/favicon/favicon.ico', methods=['GET'])
    @auth.login_required
    def img_favicon(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'favicon', 'favicon.ico'), download_name=fname, as_attachment=False)

    @app.route('/img/favicon/apple-touch-icon.png', methods=['GET'])
    @auth.login_required
    def img_favicon_apple(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'favicon', 'apple-touch-icon.png'), download_name=fname, as_attachment=False)

    @app.route('/img/param_key.png', methods=['GET'])
    @auth.login_required
    def img_param_key(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'param_key.png'), download_name=fname, as_attachment=False)

    @app.route('/img/upload_methods.png', methods=['GET'])
    @auth.login_required
    def img_upload_methods(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'upload_methods.png'), download_name=fname, as_attachment=False)


    @app.route('/img/user_roles.png', methods=['GET'])
    @auth.login_required
    def img_user_roles(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'user_roles.png'), download_name=fname, as_attachment=False)

    @app.route('/img/file_permissions.png', methods=['GET'])
    @auth.login_required
    def img_file_permissions(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'file_permissions.png'), download_name=fname, as_attachment=False)

    @app.route('/img/post_build_1.png', methods=['GET'])
    @auth.login_required
    def img_post_build_1(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'post_build_1.png'), download_name=fname, as_attachment=False)

    @app.route('/img/post_build_2.png', methods=['GET'])
    @auth.login_required
    def post_build_2(token):
        fname = os.path.basename(request.path)
        return send_file(os.path.join(config.TMPL_PATH, 'img', 'post_build_2.png'), download_name=fname, as_attachment=False)

    #
    # Error Handling
    #
    @app.errorhandler(400)
    def bad_request(e):
        data = {'400': 'Bad Request'}
        return Response(response=dumps(data), status=400, mimetype='application/json')

    @app.errorhandler(401)
    def unauthorized(e):
        data = {'401': 'Unauthorized'}
        return Response(response=dumps(data), status=401, mimetype='application/json')

    @app.errorhandler(403)
    def forbidden(e):
        data = {'403': 'Forbidden'}
        return Response(response=dumps(data), status=403, mimetype='application/json')

    @app.errorhandler(404)
    def not_found(e):
        data = {'404': 'Page Not Found'}
        return Response(response=dumps(data), status=404, mimetype='application/json')

    @app.errorhandler(500)
    def server_error(e):
        data = {'500': 'Internal Server Error'}
        return Response(response=dumps(data), status=500, mimetype='application/json')

    #
    # Post Request Headers
    #
    @app.after_request
    def add_header(response):
        response.headers['X-Frame-Options'] = "deny"
        response.headers['Server'] = current_app.config['server_header']
        return response

#
# Page Protection
#
def is_blocked_by_ip(ip):
    """Check if request source IP is allowed."""
    allowed_ips = current_app.config.get('allow_ip', [])
    return allowed_ips and ip not in allowed_ips

def is_blocked_by_user_agent(user_agent):
    """Check if User-Agent is allowed."""
    allowed_ua = current_app.config.get('allow_ua', [])
    return allowed_ua and user_agent not in allowed_ua

def is_invalid_param_key(request_path):
    """Check if parameter key rotation is enabled and valid."""
    param_rotation = current_app.config.get('param_rotation', 0)
    param_key = current_app.config.get('param_key', '')
    return param_rotation == 1 and param_key not in request_path

def update_param_key(db):
    """Update param key value"""
    if current_app.config['param_rotation'] == 1:
        new_key = config.gen_param_key()
        db.update_param_key(new_key)
        current_app.config['param_key'] = new_key

#
# Dynamic page features
#
def serve_file(file_path, url_name):
    # https://werkzeug.palletsprojects.com/en/2.3.x/serving/
    if os.path.exists(file_path):
        if request.args.get('raw', type=bool):
            return send_file(file_path, download_name=url_name, as_attachment=False, mimetype='text/plain')
        return send_file(file_path, download_name=url_name, as_attachment=True)
    return redirect(current_app.config['redirect_url'], 302)


def reverse_proxy(redirect_url):
    """Forward headers and data, correctly handling HTTPS requests and common issues."""
    excluded_headers = {"host", "connection"}
    headers = {key: value for key, value in request.headers.items() if key.lower() not in excluded_headers}
    headers["X-Forwarded-For"] = request.remote_addr

    try:
        with requests.request(
                method=request.method,
                url=redirect_url,
                headers=headers,
                data=request.get_data(),  # Always send body data, even if empty
                cookies=request.cookies,  # Preserve cookies for session management
                allow_redirects=False,  # Handle redirects manually
                verify=False,
                stream=True,
                timeout=6,
                proxies = {}
        ) as response:

            # Handle redirects manually
            if response.status_code in {301, 302, 303, 307, 308}:
                new_location = response.headers.get("Location")
                if new_location:
                    return redirect(new_location, response.status_code)

            # Remove problematic headers before forwarding response
            excluded_response_headers = {"content-encoding", "transfer-encoding", "connection"}
            response_headers = {k: v for k, v in response.headers.items() if k.lower() not in excluded_response_headers}
            return Response(response.content, response.status_code, response_headers)
    except requests.exceptions.RequestException as e:
        return f"Proxy Error: {str(e)}", 502


