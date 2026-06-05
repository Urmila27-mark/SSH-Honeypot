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

## What you'll learn

- **Most common credentials**: root/root, admin/admin, pi/raspberry
- **Automated scanners**: bots hit you within minutes of exposing port 22
- **Client fingerprinting**: different tools identify themselves differently
- **Geographic origins**: most automated attacks come from compromised hosts worldwide
- **Attack patterns**: some IPs try hundreds of passwords; others try one and move on

---

## Extending the project (ideas)

 Add **Shodan/VirusTotal API** lookups for attacker IPs
**Block IPs** using `iptables` after N failed attempts
Add **tarpit mode**: slow down attackers to waste their time
Log **keystrokes** from attackers who get past auth (advanced)
Forward alerts to **Telegram/Discord** bot
Export to **Elasticsearch + Kibana** for advanced analysis
Add **FTP or Telnet** honeypot service alongside SSH

---

## Safety & Ethics

- **Never** deploy on a machine with sensitive data
- Use a **dedicated VPS** or isolated VM
- This honeypot **never executes attacker commands** — it only logs credentials
- Always operate within your jurisdiction's laws regarding honeypots
