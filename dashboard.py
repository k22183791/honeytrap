from flask import Flask, jsonify, render_template_string
import json, os
from config import LOG_FILE, DASHBOARD_PORT, HONEYPOT_NAME

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Honeypot Dashboard</title>
  <meta http-equiv="refresh" content="10">
  <style>
    body  { font-family: monospace; background: #0a0a0f; color: #c9d1d9; padding: 20px; }
    h1    { color: #ff4444; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th    { background: #161b22; padding: 10px; text-align: left; color: #58a6ff; }
    td    { padding: 9px 10px; border-bottom: 1px solid #1c2128; }
    .HIGH   { color: #ff4444; font-weight: bold; }
    .MEDIUM { color: #ffaa00; font-weight: bold; }
    .LOW    { color: #33cc66; font-weight: bold; }
  </style>
</head>
<body>
  <h1>{{ name }} — {{ total }} hits logged</h1>
  <table>
    <tr>
      <th>Time</th>
      <th>IP</th>
      <th>Service</th>
      <th>Attack Type</th>
      <th>Threat</th>
      <th>Location</th>
      <th>Username</th>
      <th>Payload</th>
    </tr>
    {% for e in logs|reverse %}
    <tr>
      <td>{{ e.timestamp[11:19] }}</td>
      <td>{{ e.ip }}</td>
      <td>{{ e.service }}</td>
      <td>{{ e.attack }}</td>
      <td class="{{ e.threat }}">{{ e.threat }}</td>
      <td>{{ e.geo.city }}, {{ e.geo.country }}</td>
      <td>{{ e.username or "—" }}</td>
      <td>{{ e.payload[:60] or "—" }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>"""


def load_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        try:
            return json.load(f)
        except Exception:
            return []


@app.route("/")
def index():
    logs = load_logs()
    return render_template_string(HTML, logs=logs, total=len(logs), name=HONEYPOT_NAME)


@app.route("/api/logs")
def api():
    return jsonify(load_logs())


if __name__ == "__main__":
    print(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    app.run(debug=False, port=DASHBOARD_PORT)