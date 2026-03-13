# Dispatch – Operational Security Server

<p align="center">
<img width="850" alt="dispatch" src="https://github.com/user-attachments/assets/665894a2-30e5-460a-900c-0767b38de604" />
</p>

## Overview
**Dispatch** is a general-purpose operational security server for **red team** and **offensive security testing**.  

It provides a single platform for controlled payload delivery, access governance, task automation, operator workflows, and event visibility.

## Core Capabilities
- **Dual-interface architecture**: separate admin control plane & client delivery listener.
- **Identity and access control**: role-based permissions, multi-factor authentication, API access, & more
- **Payload and artifact management**: file aliases, & public/private/one-time access modes.
- **Routing and delivery options**: reverse proxy routing & covert upload channel.
- **Operator utilities**: cradle generation using various languages, & built-in file encryption.
- **Alerting and notifications**: event-driven alerts using Discord webhooks.

## Install
```bash
git clone https://github.com/m8sec/Dispatch
cd Dispatch
pip3 install -r requirements.txt
```

## Run
```bash
# Start Dispatch Ssrver
python3 dispatch-server.py

# Modify Dispatch default host & port options
python3 dispatch-server.py --bind-host 0.0.0.0 --admin-port 8443 --client-port 443

# Serve Dispatch over HTTP
python3 dispatch-server.py --http

# Enable Debug logging
python3 dispatch-server.py --debug

# Disable Script Runner console
python3 dispatch-server.py --disable-exec
```

## Disclaimer
Dispatch is intended only for authorized security testing and sanctioned operations. Do not use it against systems without explicit permission.
