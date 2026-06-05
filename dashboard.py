"""
SSH Honeypot Dashboard
Flask + SocketIO web dashboard that tails the JSONL log in real-time
and enriches each attempt with GeoIP data.
"""

import json
import os
import threading
import time
import requests
from collections import Counter, defaultdict
from datetime import datetime
from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit

# ── Config ────────────────────────────────────────────────────────────────
LOG_FILE    = os.path.join(os.path.dirname(__file__), "logs", "attempts.jsonl")
GEOIP_CACHE = {}   # ip → country info

app = Flask(__name__)
app.config["SECRET_KEY"] = "honeypot-secret"
socketio = SocketIO(app, cors_allowed_origins="*")


# ── GeoIP ─────────────────────────────────────────────────────────────────
def get_geo(ip: str) -> dict:
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp", timeout=3)
        data = r.json() if r.ok else {}
    except Exception:
        data = {}
    GEOIP_CACHE[ip] = data
    return data


# ── Log reader ────────────────────────────────────────────────────────────
def read_all_attempts():
    attempts = []
    if not os.path.exists(LOG_FILE):
        return attempts
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    attempts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return attempts


def tail_log():
    """Background thread: watch the log file and emit new entries via SocketIO."""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()

    with open(LOG_FILE) as f:
        f.seek(0, 2)   # seek to end
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        entry["geo"] = get_geo(entry.get("ip", ""))
                        socketio.emit("new_attempt", entry)
                    except Exception:
                        pass
            else:
                time.sleep(0.5)


# ── Stats helpers ─────────────────────────────────────────────────────────
def compute_stats(attempts):
    total   = len(attempts)
    users   = Counter(a["username"] for a in attempts)
    passwds = Counter(a["password"]  for a in attempts)
    ips     = Counter(a["ip"]        for a in attempts)
    per_hour: dict = defaultdict(int)
    for a in attempts:
        try:
            hour = a["timestamp"][:13]   # "2024-01-15T14"
            per_hour[hour] += 1
        except Exception:
            pass

    return {
        "total":          total,
        "unique_ips":     len(ips),
        "top_usernames":  users.most_common(10),
        "top_passwords":  passwds.most_common(10),
        "top_ips":        ips.most_common(10),
        "per_hour":       sorted(per_hour.items())[-24:],   # last 24 hours
    }


# ── Routes ────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>🍯 SSH Honeypot Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0a0f1e; --surface: #111827; --border: #1f2d45;
    --accent: #00ff88; --danger: #ff4757; --warn: #ffa502;
    --text: #e2e8f0; --muted: #64748b;
    --font: 'JetBrains Mono', 'Fira Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; }

  header {
    padding: 16px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px;
    background: rgba(0,255,136,0.03);
  }
  header h1 { font-size: 18px; color: var(--accent); letter-spacing: 1px; }
  .status-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--accent); box-shadow: 0 0 8px var(--accent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  .grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; padding: 20px 24px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; text-align: center;
  }
  .stat-card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .stat-card .value { font-size: 32px; font-weight: bold; color: var(--accent); }

  .main { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 0 24px 20px; }
  .panel {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    overflow: hidden;
  }
  .panel-header {
    padding: 12px 16px; border-bottom: 1px solid var(--border);
    font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px;
    display: flex; justify-content: space-between; align-items: center;
  }
  .panel-body { padding: 12px; max-height: 300px; overflow-y: auto; }

  /* Feed */
  #live-feed { max-height: 340px; overflow-y: auto; }
  .feed-entry {
    padding: 8px 12px; border-bottom: 1px solid var(--border);
    animation: slideIn 0.3s ease;
  }
  @keyframes slideIn { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:none} }
  .feed-entry:last-child { border-bottom: none; }
  .feed-ip   { color: var(--warn); }
  .feed-user { color: #60a5fa; }
  .feed-pass { color: var(--danger); }
  .feed-time { color: var(--muted); font-size: 11px; }
  .feed-country { color: var(--accent); font-size: 11px; }

  /* Tables */
  .rank-table { width: 100%; border-collapse: collapse; }
  .rank-table tr:not(:last-child) td { border-bottom: 1px solid var(--border); }
  .rank-table td { padding: 7px 10px; }
  .rank-table .val { color: var(--accent); text-align: right; min-width: 40px; }
  .bar-wrap { background: var(--border); border-radius: 2px; height: 4px; margin-top: 3px; }
  .bar { background: var(--accent); height: 4px; border-radius: 2px; transition: width .5s; }

  /* Chart */
  .chart-wrap { padding: 16px; }
  canvas { max-height: 200px; }

  .full-width { grid-column: 1 / -1; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); }
</style>
</head>
<body>
<header>
  <div class="status-dot"></div>
  <h1>🍯 SSH HONEYPOT DASHBOARD</h1>
  <span style="margin-left:auto;color:var(--muted);font-size:11px" id="last-update">–</span>
</header>

<div class="grid">
  <div class="stat-card"><div class="label">Total Attempts</div><div class="value" id="s-total">0</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value" id="s-ips">0</div></div>
  <div class="stat-card"><div class="label">Top Username</div><div class="value" style="font-size:18px" id="s-topuser">–</div></div>
  <div class="stat-card"><div class="label">Top Password</div><div class="value" style="font-size:18px" id="s-toppass">–</div></div>
</div>

<div class="main">
  <!-- Live Feed -->
  <div class="panel">
    <div class="panel-header">
      ⚡ Live Feed
      <span style="color:var(--accent)" id="feed-count">0 attempts</span>
    </div>
    <div id="live-feed"></div>
  </div>

  <!-- Top Usernames -->
  <div class="panel">
    <div class="panel-header">👤 Top Usernames</div>
    <div class="panel-body">
      <table class="rank-table" id="tbl-users"></table>
    </div>
  </div>

  <!-- Top Passwords -->
  <div class="panel">
    <div class="panel-header">🔑 Top Passwords</div>
    <div class="panel-body">
      <table class="rank-table" id="tbl-passes"></table>
    </div>
  </div>

  <!-- Top IPs -->
  <div class="panel">
    <div class="panel-header">🌐 Top Attacker IPs</div>
    <div class="panel-body">
      <table class="rank-table" id="tbl-ips"></table>
    </div>
  </div>

  <!-- Timeline Chart -->
  <div class="panel full-width">
    <div class="panel-header">📈 Attempts Timeline (last 24h)</div>
    <div class="chart-wrap"><canvas id="timeline-chart"></canvas></div>
  </div>
</div>

<script>
const socket = io();
let feedCount = 0;
let chart = null;

// ── Init stats ─────────────────────────────────────────────────────────
fetch('/api/stats').then(r=>r.json()).then(applyStats);
fetch('/api/recent').then(r=>r.json()).then(entries=>{
  entries.slice(-50).forEach(e => addFeedEntry(e, false));
});

// ── Socket ─────────────────────────────────────────────────────────────
socket.on('new_attempt', entry => {
  addFeedEntry(entry, true);
  fetch('/api/stats').then(r=>r.json()).then(applyStats);
  document.getElementById('last-update').textContent = 'Last: ' + new Date().toLocaleTimeString();
});

// ── Helpers ────────────────────────────────────────────────────────────
function addFeedEntry(e, animate) {
  const feed = document.getElementById('live-feed');
  const geo  = e.geo || {};
  const flag = geo.countryCode ? `&#${127397 + geo.countryCode.charCodeAt(0)}&#${127397 + geo.countryCode.charCodeAt(1)};` : '🌐';
  const div  = document.createElement('div');
  div.className = 'feed-entry' + (animate ? '' : ' no-anim');
  div.innerHTML = `
    <span class="feed-time">${(e.timestamp||'').replace('T',' ').slice(0,19)}</span>
    &nbsp;<span class="feed-ip">${e.ip}</span>
    <span class="feed-country">&nbsp;${flag} ${geo.country||''}&nbsp;</span>
    <span class="feed-user">user:${e.username}</span>
    &nbsp;<span class="feed-pass">pass:${e.password}</span>
  `;
  feed.insertBefore(div, feed.firstChild);
  feedCount++;
  document.getElementById('feed-count').textContent = feedCount + ' attempts';
  // trim feed to 200 entries
  while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

function applyStats(s) {
  document.getElementById('s-total').textContent = s.total;
  document.getElementById('s-ips').textContent   = s.unique_ips;
  if (s.top_usernames.length) document.getElementById('s-topuser').textContent = s.top_usernames[0][0];
  if (s.top_passwords.length) document.getElementById('s-toppass').textContent = s.top_passwords[0][0];
  renderTable('tbl-users',  s.top_usernames);
  renderTable('tbl-passes', s.top_passwords);
  renderTable('tbl-ips',    s.top_ips);
  renderChart(s.per_hour);
}

function renderTable(id, items) {
  const max = items.length ? items[0][1] : 1;
  document.getElementById(id).innerHTML = items.map(([k,v]) => `
    <tr><td>
      <div style="color:var(--text)">${escHtml(k)}</div>
      <div class="bar-wrap"><div class="bar" style="width:${Math.round(v/max*100)}%"></div></div>
    </td><td class="val">${v}</td></tr>
  `).join('');
}

function renderChart(perHour) {
  const labels = perHour.map(([h]) => h.slice(11) + 'h');
  const data   = perHour.map(([,v]) => v);
  if (chart) { chart.data.labels=labels; chart.data.datasets[0].data=data; chart.update(); return; }
  const ctx = document.getElementById('timeline-chart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Attempts',
        data,
        backgroundColor: 'rgba(0,255,136,0.3)',
        borderColor: '#00ff88',
        borderWidth: 1,
        borderRadius: 3,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#64748b' }, grid: { color: '#1f2d45' } },
        y: { ticks: { color: '#64748b' }, grid: { color: '#1f2d45' } }
      }
    }
  });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def api_stats():
    attempts = read_all_attempts()
    return jsonify(compute_stats(attempts))


@app.route("/api/recent")
def api_recent():
    attempts = read_all_attempts()
    # Enrich last 100 with geo (cached)
    for a in attempts[-100:]:
        a["geo"] = get_geo(a.get("ip", ""))
    return jsonify(attempts[-100:])


# ── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    tail_thread = threading.Thread(target=tail_log, daemon=True)
    tail_thread.start()
    print("🌐  Dashboard running at http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
