"""Flask dashboard over the proxy's SQLite log.  Run: python dashboard.py  ->  http://127.0.0.1:5000"""
from flask import Flask, jsonify, render_template_string

from logger_db import DB_PATH, SCHEMA, connect

app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Gateway Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
 body{font-family:system-ui,sans-serif;margin:24px;max-width:1000px;color:#222}
 .cards{display:flex;gap:12px;margin-bottom:20px}
 .card{flex:1;padding:14px;border:1px solid #ddd;border-radius:8px}
 .card b{font-size:26px;display:block}
 table{border-collapse:collapse;width:100%;margin-bottom:24px}
 th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee;font-size:14px}
 .bar{background:#d9534f;height:10px;border-radius:4px}
 .bar.ok{background:#5cb85c}
 .block{color:#b52b27}.allow{color:#2d7a2d}
</style></head><body>
<h1>Secure Web Gateway Dashboard</h1>
<div class="cards">
 <div class="card"><b>{{ s.total }}</b>total requests</div>
 <div class="card"><b>{{ s.allowed }}</b>allowed</div>
 <div class="card"><b>{{ s.blocked }}</b>blocked</div>
 <div class="card"><b>{{ s.block_pct }}%</b>block rate</div>
</div>
<h2>Top blocked domains</h2>
<table><tr><th>Domain</th><th>Reason</th><th>Count</th><th></th></tr>
{% for r in s.top_blocked %}
<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td>
<td style="width:30%"><div class="bar" style="width:{{ (r[2]/s.top_blocked[0][2]*100)|int }}%"></div></td></tr>
{% else %}<tr><td colspan="4">No blocked requests yet.</td></tr>{% endfor %}
</table>
<h2>Requests per minute (last 30 min)</h2>
<table><tr><th>Minute</th><th>Allowed</th><th>Blocked</th></tr>
{% for r in s.per_minute %}<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td></tr>
{% else %}<tr><td colspan="3">No traffic yet.</td></tr>{% endfor %}
</table>
<h2>Recent requests</h2>
<table><tr><th>Time</th><th>Client</th><th>Method</th><th>Host</th><th>Action</th><th>Reason</th></tr>
{% for r in s.recent %}
<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td><td>{{ r[3] }}</td>
<td class="{{ r[4] }}">{{ r[4] }}</td><td>{{ r[5] }}</td></tr>{% endfor %}
</table></body></html>"""


def collect():
    conn = connect()
    conn.executescript(SCHEMA)
    q = lambda sql, *a: conn.execute(sql, a).fetchall()
    total = q("SELECT COUNT(*) FROM requests")[0][0]
    blocked = q("SELECT COUNT(*) FROM requests WHERE action='block'")[0][0]
    stats = {
        "total": total,
        "blocked": blocked,
        "allowed": q("SELECT COUNT(*) FROM requests WHERE action='allow'")[0][0],
        "block_pct": round(100 * blocked / total, 1) if total else 0,
        "top_blocked": q(
            "SELECT host, category, COUNT(*) c FROM requests WHERE action='block' "
            "GROUP BY host, category ORDER BY c DESC LIMIT 10"),
        "per_minute": q(
            "SELECT strftime('%Y-%m-%d %H:%M', ts, 'unixepoch', 'localtime') m, "
            "SUM(action='allow'), SUM(action='block') FROM requests "
            "WHERE ts > strftime('%s','now') - 1800 GROUP BY m ORDER BY m DESC"),
        "recent": q(
            "SELECT strftime('%H:%M:%S', ts, 'unixepoch', 'localtime'), client, method, host, action, reason "
            "FROM requests ORDER BY id DESC LIMIT 25"),
    }
    conn.close()
    return stats


@app.route("/")
def index():
    return render_template_string(PAGE, s=collect())


@app.route("/api/stats")
def api_stats():
    return jsonify(collect())


if __name__ == "__main__":
    print(f"Reading log from {DB_PATH}")
    app.run(host="127.0.0.1", port=5000)
