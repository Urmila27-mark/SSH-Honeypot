# 🍯 SSH Honeypot

A Python SSH honeypot that logs brute-force login attempts with a real-time web dashboard.

## What it does

- Pretends to be a real OpenSSH server (fake banner: `SSH-2.0-OpenSSH_8.9p1`)
- **Never grants access** — always rejects auth after logging credentials
- Captures: IP, port, username, password, SSH client version, timestamp
- Real-time dashboard with GeoIP enrichment, stats, and charts

## Project structure

```
ssh-honeypot/
├── honeypot.py          ← Fake SSH server (runs on port 2222)
├── dashboard.py         ← Flask web dashboard (runs on port 5000)
├── analyze.py           ← CLI log analysis tool
├── simulate_attacks.py  ← Inject fake attempts (for testing)
├── requirements.txt
├── keys/
│   └── server_key       ← Auto-generated RSA host key
└── logs/
    ├── attempts.jsonl   ← All login attempts (one JSON per line)
    └── server.log       ← Server info/debug log
```

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate host key (first time only)

```bash
python3 -c "
from paramiko import RSAKey
import os
os.makedirs('keys', exist_ok=True)
RSAKey.generate(2048).write_private_key_file('keys/server_key')
print('Key generated')
"
```

### 3. Start the honeypot server

```bash
python3 honeypot.py
```

> This runs on **port 2222** by default (no root needed).
> To use port 22, change `SSH_PORT = 22` and run with `sudo`.

### 4. Start the dashboard (separate terminal)

```bash
python3 dashboard.py
```

Open `http://localhost:5000` in your browser.

### 5. Test it locally

```bash
# Try to SSH into your own honeypot
ssh -p 2222 root@localhost
# Enter any password — it will be logged and rejected
```

### 6. Test the dashboard with simulated traffic

```bash
python3 simulate_attacks.py
```

### 7. Analyze logs from the CLI

```bash
python3 analyze.py
python3 analyze.py --top 20
python3 analyze.py --export report.json
```

---

## Deploying on a real VPS

For actual attacker data, deploy on a public-facing server:

```bash
# On your VPS (Ubuntu/Debian)
sudo apt install python3-pip -y
pip3 install -r requirements.txt

# Run honeypot on port 22 (real SSH port — requires root)
# IMPORTANT: Move your real SSH to another port first!
sudo nano /etc/ssh/sshd_config   # Change Port 22 → Port 2200
sudo systemctl restart sshd
sudo python3 honeypot.py  # now edit SSH_PORT=22 in honeypot.py
```

Run both processes in the background:

```bash
nohup python3 honeypot.py  > /dev/null 2>&1 &
nohup python3 dashboard.py > /dev/null 2>&1 &
```

Within an hour you'll see real bot traffic. Within 24h you'll have thousands of attempts.

---

## What you'll learn

- **Most common credentials**: root/root, admin/admin, pi/raspberry
- **Automated scanners**: bots hit you within minutes of exposing port 22
- **Client fingerprinting**: different tools identify themselves differently
- **Geographic origins**: most automated attacks come from compromised hosts worldwide
- **Attack patterns**: some IPs try hundreds of passwords; others try one and move on

---

## Extending the project (ideas)

- [ ] Add **Shodan/VirusTotal API** lookups for attacker IPs
- [ ] **Block IPs** using `iptables` after N failed attempts
- [ ] Add **tarpit mode**: slow down attackers to waste their time
- [ ] Log **keystrokes** from attackers who get past auth (advanced)
- [ ] Forward alerts to **Telegram/Discord** bot
- [ ] Export to **Elasticsearch + Kibana** for advanced analysis
- [ ] Add **FTP or Telnet** honeypot service alongside SSH

---

## Safety & Ethics

- **Never** deploy on a machine with sensitive data
- Use a **dedicated VPS** or isolated VM
- This honeypot **never executes attacker commands** — it only logs credentials
- Always operate within your jurisdiction's laws regarding honeypots
