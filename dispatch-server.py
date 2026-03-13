#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from gevent import monkey
monkey.patch_all()

import os
import ssl
import sys
import argparse
import socket
import gevent
from dispatch import config
from dispatch.db import DispatchDB
from dispatch.script_scheduler import scheduler
from gevent.pywsgi import WSGIServer
from gevent import spawn, get_hub
from dispatch.admin_app import DispatchServer as AdminDispatchServer
from dispatch.client_app import ClientServer


banner = rf'''
  ____  _                 _       _          ____
 |  _ \(_)___ _ __   __ _| |_ ___| |__      / ___|  ___ _ ____   _____ _ __
 | | | | / __| '_ \ / _` | __/ __| '_ \ ____\___ \ / _ \ '__\ \ / / _ \ '__|
 | |_| | \__ \ |_) | (_| | || (__| | | |_____|__) |  __/ |   \ V /  __/ |
 |____/|_|___/ .__/ \__,_|\__\___|_| |_|    |____/ \___|_|    \_/ \___|_|
             |_|
                            @m8sec | {config.VERSION}
'''


# Quiet logger for WSGIServer that ignores expected TLS handshake noise
class QuietWSGILogger:
    def write(self, msg):
        ignored_markers = (
            'SSLEOFError',
            'SSLError',
            'UNEXPECTED_EOF',
            'SSLV3_ALERT_BAD_CERTIFICATE',
            'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
            'sslv3 alert bad certificate',
            'sslv3 alert certificate unknown',
            'HTTP_REQUEST',
            'http request',
            'failed with SSLError',
        )
        if not any(marker in msg for marker in ignored_markers):
            sys.stderr.write(msg)


class QuietWSGIServer(WSGIServer):
    def wrap_socket_and_handle(self, client_socket, address):
        try:
            return super().wrap_socket_and_handle(client_socket, address)
        except ssl.SSLError as exc:
            # Silently ignore common SSL errors (bad certs, HTTP on HTTPS port, etc.)
            message = str(exc)
            ignored_markers = (
                'SSLV3_ALERT_BAD_CERTIFICATE',
                'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
                'sslv3 alert bad certificate',
                'sslv3 alert certificate unknown',
                'TLSV1_ALERT_UNKNOWN_CA',
                'tlsv1 alert unknown ca',
                'UNKNOWN_CA',
                'HTTP_REQUEST',
                'http request',
                'WRONG_VERSION_NUMBER',
                'wrong version number',
            )
            if any(marker in message for marker in ignored_markers):
                return
            raise

def main():
    parser = argparse.ArgumentParser(description="Run the Dispatch admin and client servers.")
    parser.add_argument('--debug', action='store_true', help='Run only the admin interface in Flask debug mode.')
    parser.add_argument('--http', action='store_true', help='Serve over HTTP instead of HTTPS.')
    parser.add_argument('--bind-host', type=str, default='0.0.0.0', help='Bind address for both listeners (default: 0.0.0.0).')
    parser.add_argument('--admin-port', type=int, default=8443, help='Port for the admin interface (default: 8443).')
    parser.add_argument('--client-port', type=int, default=443, help='Port for client file delivery (default: 443).')
    parser.add_argument('--external-host', type=str, default=None, help='External hostname or IP stored in settings for generated links.')
    parser.add_argument('--disable-exec', action='store_true', help='Disable script runner features (manual and scheduled execution).')
    args = parser.parse_args()
    cli_args = sys.argv[1:]

    def cli_option_provided(name):
        return any(arg == name or arg.startswith(f'{name}=') for arg in cli_args)

    if args.http:
        # Avoid binding to privileged/common HTTP ports unless the operator chose them explicitly.
        if not cli_option_provided('--admin-port') and args.admin_port == 8443:
            args.admin_port = 8080
        if not cli_option_provided('--client-port') and args.client_port == 443:
            args.client_port = 8000

    if args.admin_port == args.client_port and not args.debug:
        print(f'[!] ERROR: admin-port and client-port cannot both use {args.admin_port}.')
        print('[!] Choose distinct ports, for example: --admin-port 8080 --client-port 8000')
        sys.exit(1)


    print(banner)
    if not os.path.exists(config.DB_NAME):
        print(f'[*] No database file found. Starting setup...')
        print(f'[*] Generating SSL certificates...')
        config.generate_ssl_cert(config.CERT_PATH, config.KEY_PATH, 
                                 country=config.COUNTRY, cn=config.CN, 
                                 org=config.ORG, ou=config.OU, 
                                 valid=config.VALID_DAYS)

        print('[*] Creating new Dispatch database...')
        db = DispatchDB(config.DB_NAME)
        db.setup_db()
        db.close()
        print(f'[*] Login with default user: {config.DEFAULT_USER}')
        print(f'[*] Randomly generated password: {config.DEFAULT_PWD}\n')


    admin_server = AdminDispatchServer()
    admin_app = admin_server.app
    client_server = ClientServer()
    client_app = client_server.app
    db = DispatchDB(config.DB_NAME)

    # Update external host if provided
    if args.external_host:
        db.update_external_host(args.external_host)

    # Persist listener ports into settings database
    if args.admin_port or args.client_port:
        current_settings = db.get_settings()
        db.update_settings(
            current_settings['redirect_url'],
            current_settings['source_ip'],
            args.admin_port ,
            current_settings['max_file_size'],
            current_settings['server_header'],
            args.client_port
        )
        print(f'[+] Updated database with admin_port={args.admin_port }, client_port={args.client_port}')

    # Reload settings and display
    ext = db.get_settings()
    protocol = "http" if args.http else "https"

    config.refresh_app_configs(db, admin_app)
    config.refresh_app_configs(db, client_app)
    db.close()
    config.setup_dispatch_logger(log_name='dispatch-logger')
    admin_app.config['disable_exec'] = bool(args.disable_exec)
    client_app.config['disable_exec'] = bool(args.disable_exec)
    if admin_app.config['disable_exec']:
        scheduler.stop()
    else:
        scheduler.start()

    # Setup SSL context
    if args.http:
        print(f'[!] WARNING: Setting protocol to HTTP. This is NOT recommended for production environments!')
        print(f'[!] WARNING: navigator.clipboard requires HTTPS. Clipboard copy functions will NOT work via HTTP.')
        context = None
    else:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(config.CERT_PATH, config.KEY_PATH)

    def ensure_port_available(host, port, label):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            print(f'[!] ERROR: Could not bind {label} listener to {host}:{port}: {exc}')
            if exc.errno == 98:
                print(f'[!] Port {port} is already in use. Specify a different port with --{"admin" if label == "admin" else "client"}-port.')
            elif exc.errno == 13:
                print(f'[!] Permission denied on port {port}. Use a port above 1024 or run with the required privileges.')
            sys.exit(1)
        finally:
            probe.close()

    # Start servers
    ensure_port_available(args.bind_host, args.admin_port, 'admin')
    if not args.debug:
        ensure_port_available(args.bind_host, args.client_port, 'client')

    print(f'[+] Starting Admin console on: {protocol}://{args.bind_host}:{args.admin_port}/')
    print(f'[+] Starting Client delivery on: {protocol}://{ext["source_ip"]}:{args.client_port}/\n')

    if args.debug:
        config.setup_debug_logger()
        # In debug mode, only run admin server (can't run two Flask debug servers)
        print('[!] Debug mode: Only running admin server')
        admin_app.run(
            host=args.bind_host,
            port=args.admin_port,
            ssl_context=context,
            debug=True,
            threaded=True,
            use_debugger=False,
            use_reloader=True
        )
    else:
        # Suppress expected TLS handshake aborts from clients that reject the self-signed cert.
        hub = get_hub()
        hub.NOT_ERROR += (ssl.SSLEOFError, ssl.SSLError,)

        server_kwargs = {'ssl_context': context} if context else {}
        # Use quiet logger to suppress SSL errors in server output
        server_kwargs['log'] = QuietWSGILogger()
        server_kwargs['error_log'] = QuietWSGILogger()

        def create_server(port, flask_app):
            return QuietWSGIServer((args.bind_host , port), flask_app, **server_kwargs)

        # Create admin server (full app)
        admin_server = create_server(args.admin_port, admin_app)

        # Create client server (client app handles file delivery)
        client_server = create_server(args.client_port, client_app)

        # Run both servers concurrently
        def run_admin():
            admin_server.serve_forever()

        def run_client():
            client_server.serve_forever()

        # Spawn both servers
        admin_greenlet = spawn(run_admin)
        client_greenlet = spawn(run_client)
        last_client_port = args.client_port

        def monitor_ports():
            nonlocal client_server, client_greenlet, last_client_port
            while True:
                gevent.sleep(2)
                try:
                    db = DispatchDB(config.DB_NAME)
                    settings = db.get_settings()
                    db.close()
                except Exception:
                    continue

                new_client_port = settings.get('client_port', last_client_port)
                if new_client_port != last_client_port:
                    try:
                        client_server.stop()
                    except Exception:
                        pass
                    try:
                        client_greenlet.kill()
                    except Exception:
                        pass
                    last_client_port = new_client_port
                    client_server = create_server(last_client_port, client_app)
                    client_greenlet = spawn(client_server.serve_forever)

        monitor_greenlet = spawn(monitor_ports)

        try:
            # Wait for both (this will block until interrupted)
            admin_greenlet.join()
            client_greenlet.join()
            monitor_greenlet.join()
        except KeyboardInterrupt:
            print('\n[*] Shutting down servers...')
            admin_server.stop()
            client_server.stop()


if __name__ == "__main__":
    main()
