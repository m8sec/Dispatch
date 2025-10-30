#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from gevent import monkey
monkey.patch_all()

import os
import ssl
import sys
import logging
import argparse
from dispatch import config
from dispatch.db import DispatchDB
from gevent.pywsgi import WSGIServer
from dispatch.app import DispatchServer


banner = rf'''
  ____  _                 _       _          ____                           
 |  _ \(_)___ _ __   __ _| |_ ___| |__      / ___|  ___ _ ____   _____ _ __ 
 | | | | / __| '_ \ / _` | __/ __| '_ \ ____\___ \ / _ \ '__\ \ / / _ \ '__|
 | |_| | \__ \ |_) | (_| | || (__| | | |_____|__) |  __/ |   \ V /  __/ |   
 |____/|_|___/ .__/ \__,_|\__\___|_| |_|    |____/ \___|_|    \_/ \___|_|   
             |_|    
                            @m8sec | {config.VERSION}                                                       
'''


# Ignore SSLEOFError in gevent logs
class IgnoreSSLEOFError(logging.Filter):
    def filter(self, record):
        return "SSLEOFError" not in record.getMessage()
    
logging.getLogger("gevent").addFilter(IgnoreSSLEOFError())

def main():
    parser = argparse.ArgumentParser(description="Dispatch Server Options")
    parser.add_argument('--debug', action='store_true', help='Use Flask debug mode (default: False)')
    parser.add_argument('--http', action='store_true', help='Server over HTTP (default: False)')
    parser.add_argument('--bind-host', type=str, default=False, help='Override bind host config')
    parser.add_argument('--bind-port', type=str, default=False, help='Override bind port config')
    parser.add_argument('--external-host', type=str, default=False, help='Set external IP/Hostname of server ')
    parser.add_argument('--external-port', type=str, default=False, help='Set different external port from bind')
    args = parser.parse_args()


    print(banner)
    if not os.path.exists(config.DB_NAME):
        print(f'[*] No database file found. Starting setup...')
        print(f'[*] Generating SSL certificates...')
        config.generate_ssl_cert(config.CERT_PATH, config.KEY_PATH, country="US", cn="Dispatch", org="Dispatch", ou="Dispatch", valid=365)
    
        print('[*] Creating new Dispatch database...')
        db = DispatchDB(config.DB_NAME)
        db.setup_db()
        db.close()
        print(f'[*] Login with default user: {config.DEFAULT_USER}')
        print(f'[*] Randomly generated password: {config.DEFAULT_PWD}\n')


    ds = DispatchServer()
    app = ds.app

    db = DispatchDB(config.DB_NAME)

    # CMD Arg Overrrides
    config.INTERFACE = args.bind_host if args.bind_host else config.INTERFACE
    config.PORT = int(args.bind_port) if args.bind_port else config.PORT
    db.update_external_host(args.external_host) if args.external_host else False
    db.update_external_port(args.external_port if args.external_port else config.PORT)
    
    # Load External URL
    ext = db.get_settings()
    print(f'[+] External IP set to: {"http" if args.http else "https"}://{ext["source_ip"]}:{ext["source_port"]}/')

    config.refresh_app_configs(db, app)
    db.close()
    config.setup_dispatch_logger(log_name='dispatch-logger')

    # Setup SSL context
    if args.http:
        print(f'[!] WARNING: Setting protocol to HTTP. This is NOT recommended for production environments!')
        print(f'[!] WARNING: navigator.clipboard requires HTTPS. Clipboard copy functions will NOT work via HTTP.')
        context = None
    else:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(config.CERT_PATH, config.KEY_PATH)

    # Start server
    print(f'[+] Starting Dispatch locally on: {"http" if args.http else "https"}://{config.INTERFACE}:{config.PORT}/\n')
    if args.debug:
        config.setup_debug_logger()
        app.run(
            host=config.INTERFACE,
            port=config.PORT,
            ssl_context=context,
            debug=True,
            threaded=True,
            use_debugger=False,
            use_reloader=True
        )
    else:
        server_kwargs = {'ssl_context': context} if context else {}
        http_server = WSGIServer(
            (config.INTERFACE, config.PORT),
            app,
            **server_kwargs
        )
        http_server.serve_forever()


if __name__ == "__main__":
    main()