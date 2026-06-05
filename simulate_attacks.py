"""
simulate_attacks.py — Injects fake log entries to test the dashboard
Run this while the dashboard is open to see real-time updates.
"""

import json
import os
import random
import time
from datetime import datetime, timezone

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "attempts.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "postgres",
             "mysql", "ftpuser", "www-data", "git", "deploy", "ec2-user", "hadoop"]

PASSWORDS = ["123456", "password", "admin", "root", "toor", "qwerty", "letmein",
             "12345678", "pass123", "admin123", "raspberry", "changeme", "1234",
             "P@ssw0rd", "Welcome1", "sunshine", "iloveyou", "monkey", "dragon"]

CLIENTS   = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-OpenSSH_7.4",
             "SSH-2.0-Go", "SSH-2.0-PUTTY", "SSH-2.0-paramiko_2.11.0"]

IPS = [
    ("45.33.32.156",  "US"),
    ("195.54.160.210","RU"),
    ("103.214.109.42","CN"),
    ("185.220.101.6", "DE"),
    ("91.108.4.168",  "NL"),
    ("46.101.6.111",  "SG"),
    ("134.122.73.150","IN"),
    ("52.12.245.99",  "BR"),
]

print(f"Injecting simulated attacks into {LOG_FILE}")
print("Open the dashboard (http://localhost:5000) to watch live.")
print("Press Ctrl+C to stop.\n")

count = 0
try:
    while True:
        ip, country = random.choice(IPS)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip":        ip,
            "port":      random.randint(40000, 65000),
            "username":  random.choice(USERNAMES),
            "password":  random.choice(PASSWORDS),
            "client":    random.choice(CLIENTS),
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        count += 1
        print(f"[{count:4}] {ip} ({country}) → {entry['username']}:{entry['password']}")
        time.sleep(random.uniform(0.3, 1.5))
except KeyboardInterrupt:
    print(f"\nDone. Injected {count} simulated attempts.")
