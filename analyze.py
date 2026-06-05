"""
analyze.py — Quick CLI analysis of honeypot logs
Usage: python analyze.py [--top N] [--export report.json]
"""

import json
import os
import sys
import argparse
from collections import Counter, defaultdict
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "attempts.jsonl")


def load_attempts():
    if not os.path.exists(LOG_FILE):
        print(f"No log file found at {LOG_FILE}")
        print("Start the honeypot first and wait for some attempts.")
        sys.exit(0)
    attempts = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attempts.append(json.loads(line))
                except Exception:
                    pass
    return attempts


def analyze(attempts, top_n=10):
    total   = len(attempts)
    ips     = Counter(a["ip"]       for a in attempts)
    users   = Counter(a["username"] for a in attempts)
    passwds = Counter(a["password"] for a in attempts)
    clients = Counter(a.get("client","unknown") for a in attempts)

    # Common credential pairs
    pairs = Counter((a["username"], a["password"]) for a in attempts)

    # Time distribution
    hourly = defaultdict(int)
    for a in attempts:
        try:
            dt = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
            hourly[dt.strftime("%Y-%m-%d %H:00")] += 1
        except Exception:
            pass

    print(f"\n{'='*60}")
    print(f"  🍯  SSH HONEYPOT LOG ANALYSIS")
    print(f"{'='*60}")
    print(f"  Total attempts   : {total:,}")
    print(f"  Unique IPs       : {len(ips):,}")
    print(f"  Unique usernames : {len(users):,}")
    print(f"  Unique passwords : {len(passwds):,}")
    print(f"  Log file         : {LOG_FILE}")

    def section(title, data):
        print(f"\n  ── {title} ──")
        for i, (key, count) in enumerate(data, 1):
            bar = "█" * min(40, int(count / max(data[0][1], 1) * 40))
            print(f"  {i:2}. {str(key):<28}  {count:>6}  {bar}")

    section(f"Top {top_n} Usernames",  users.most_common(top_n))
    section(f"Top {top_n} Passwords",  passwds.most_common(top_n))
    section(f"Top {top_n} Source IPs", ips.most_common(top_n))
    section(f"Top {top_n} Credential Pairs",
            [(f"{u}:{p}", c) for (u,p),c in pairs.most_common(top_n)])
    section(f"Top {top_n} SSH Clients", clients.most_common(top_n))

    print(f"\n  ── Hourly Distribution (recent) ──")
    for hour, count in sorted(hourly.items())[-24:]:
        bar = "█" * min(40, int(count / max(hourly.values()) * 40))
        print(f"  {hour}  {count:>5}  {bar}")

    print(f"\n{'='*60}\n")
    return {
        "total": total,
        "unique_ips": len(ips),
        "top_usernames": users.most_common(top_n),
        "top_passwords": passwds.most_common(top_n),
        "top_ips": ips.most_common(top_n),
        "top_pairs": [(f"{u}:{p}", c) for (u,p),c in pairs.most_common(top_n)],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze SSH honeypot logs")
    parser.add_argument("--top",    type=int, default=10, help="Show top N entries (default 10)")
    parser.add_argument("--export", type=str, default=None, help="Export stats to JSON file")
    args = parser.parse_args()

    attempts = load_attempts()
    stats    = analyze(attempts, top_n=args.top)

    if args.export:
        with open(args.export, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"Stats exported to {args.export}")
