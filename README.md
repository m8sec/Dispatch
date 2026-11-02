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
- **Routing and delivery options**: reverse proxy routing, covert chunked upload, and covert chunked download.
- **Operator utilities**: cradle generation (curl, wget, Python, PowerShell, certutil, BITS, encoded PowerShell), & built-in file encryption.
- **Delivery governance**: per-file download caps, public/private/one-time access, and a live client-request feed.
- **Dual listeners**: the admin app and the client delivery app are separate Flask apps started on separate ports by `dispatch-server`.
- **Alerting and notifications**: event-driven alerts using Discord webhooks.

## Install
```bash
git clone https://github.com/m8sec/Dispatch
cd Dispatch
pip3 install -r requirements.txt
```

pipx / package install (console command `dispatch-server`):

```bash
pipx install .
dispatch-server --help
```

Docker:

```bash
docker compose up --build
```

The image listens on 8080 (admin) and 8000 (client) over HTTP. Persistent state is the `dispatch-data` volume.

## Run
```bash
# Start Dispatch. The script interface is OFF unless you opt in.
python3 dispatch-server.py

# HTTP is for labs only. Admin and client use different ports.
python3 dispatch-server.py --http --admin-port 8080 --client-port 8000

# Enable the script interface and its scheduler
python3 dispatch-server.py --enable-script-interface

# Enable Debug logging (admin listener only)
python3 dispatch-server.py --debug
```

`--disable-exec` was removed. The script interface is off by default; pass `--enable-script-interface` to turn it on.

## API keys

Send the user's key in the `X-Dispatch-Auth` header on the admin interface. The key uses that user's role.

- `GET /api/files/list` lists files the role can see. The payload is only `id`, `filename`, `alias`, `file_size`, `access`, `max_downloads`, and `download_count`. `GET /api/files/minimal-list` returns the same shape. `0` or a null `max_downloads` means unlimited.
- `POST /api/file/upload` uploads a file (Upload role or higher).
- `GET /file/get/alias/<alias>` downloads by alias.
- `GET /file/get/name/<filename>` downloads by filename.
- `GET /file/get/<id>` downloads by the file id.

The signed-in file page uses `GET /api/files/listing`, which requires a session cookie and is not available to an API key. That response includes the extra fields the admin UI needs, such as paths and uploader names.

## Disclaimer
Dispatch is intended only for authorized security testing and sanctioned operations. Do not use it against systems without explicit permission.
