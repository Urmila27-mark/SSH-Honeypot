"""
SSH Honeypot - Core Server
Listens on a fake SSH port, logs every login attempt.
Never grants access. Logs: IP, port, username, password, client version, timestamp.
"""

import socket
import threading
import paramiko
import json
import logging
import os
import sys
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────────────────────────
SSH_PORT      = 2222          # Change to 22 if running as root on a real server
HOST          = "0.0.0.0"
HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys", "server_key")
LOG_FILE      = os.path.join(os.path.dirname(__file__), "logs", "attempts.jsonl")
BANNER        = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"   # Fake banner to lure bots

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "server.log"))
    ]
)
log = logging.getLogger("honeypot")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def record_attempt(ip: str, port: int, username: str, password: str, client_version: str):
    """Append a login attempt to the JSONL log file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip":        ip,
        "port":      port,
        "username":  username,
        "password":  password,
        "client":    client_version,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Pretty-print to console
    log.info(f"ATTEMPT  {ip}:{port}  user={username!r}  pass={password!r}  client={client_version!r}")
    return entry


class HoneypotServer(paramiko.ServerInterface):
    """Paramiko server interface — always rejects auth, always logs."""

    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.event       = threading.Event()

    def check_channel_request(self, kind, chanid):
        # Accept channel requests (so attackers think they're getting in)
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        # Log but always deny
        record_attempt(
            ip=self.client_ip,
            port=self.client_port,
            username=username,
            password=password,
            client_version=getattr(self, "_client_version", "unknown"),
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_connection(client_sock: socket.socket, addr: tuple):
    """Handle a single incoming TCP connection as a fake SSH session."""
    ip, port = addr[0], addr[1]
    log.info(f"Connection from {ip}:{port}")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER          # Fake SSH banner
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(ip, port)

        # Capture client version after handshake
        try:
            transport.start_server(server=server)
            server._client_version = transport.remote_version or "unknown"
        except paramiko.SSHException as e:
            log.debug(f"SSH negotiation failed from {ip}: {e}")
            return

        # Wait briefly — the attacker will attempt auth via check_auth_password
        chan = transport.accept(timeout=20)
        if chan:
            chan.close()

    except Exception as e:
        log.debug(f"Error handling {ip}: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


def start_server():
    global HOST_KEY
    log.info(f"Loading host key from {HOST_KEY_PATH}")
    HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, SSH_PORT))
    server_sock.listen(100)
    log.info(f"🍯  SSH Honeypot listening on {HOST}:{SSH_PORT}")
    log.info(f"📄  Logging attempts to {LOG_FILE}")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            t = threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down honeypot.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    start_server()
