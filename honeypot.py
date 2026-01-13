import socket
import threading
import json
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import requests
from config import *

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("HoneyTrap")

ip_hits = {}
_lock   = threading.Lock()


def geolocate(ip):
    if ip.startswith(("127.", "192.168.", "10.")):
        return {"country": "Local", "city": "localhost", "isp": "-"}
    try:
        d = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return {k: d.get(k, "?") for k in ("country", "city", "isp")}
    except Exception:
        return {"country": "?", "city": "?", "isp": "?"}


def analyse(p, port, hits):
    # exploit check before credential — order matters
    pl = p.lower()
    if any(s in pl for s in EXPLOIT_SIGS):
        return "Exploit Probe", "HIGH"
    if hits >= REPEAT_THRESHOLD and port in (21, 22):
        return "Brute Force", "HIGH"
    if port in (21, 22) and any(c in pl for c in KNOWN_CREDS):
        return "Credential Attempt", "MEDIUM"
    if hits >= 2:
        return "Repeat Scanner", "MEDIUM"
    return "Port Scan", "LOW"


def first_cred(p):
    pl = p.lower()
    return next((c for c in KNOWN_CREDS if c in pl), None)


def append_log(entry):
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try:
                rows = json.load(f)
            except json.JSONDecodeError:
                pass
    rows.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(rows, f, indent=2)


def handle(conn, addr, port, service):
    ip = addr[0]
    with _lock:
        ip_hits[ip] = ip_hits.get(ip, 0) + 1
        hits = ip_hits[ip]

    try:
        if port in BANNERS:
            conn.send(BANNERS[port])
        conn.settimeout(5)
        try:
            payload = conn.recv(1024).decode(errors="ignore").strip()
        except socket.timeout:
            payload = ""
    except Exception:
        return
    finally:
        conn.close()

    geo           = geolocate(ip)
    attack, level = analyse(payload, port, hits)
    cred          = first_cred(payload)

    append_log({
        "ts":      datetime.now().isoformat(),
        "ip":      ip,
        "port":    port,
        "service": service,
        "payload": payload[:200],
        "attack":  attack,
        "threat":  level,
        "hits":    hits,
        "cred":    cred,
        "geo":     geo,
        "sensor":  HONEYPOT_NAME,
    })

    lvl = logging.WARNING if level == "HIGH" else logging.INFO
    log.log(lvl, f"[{level}] {service} from {ip} ({geo['city']}) — {attack}"
                 + (f" cred={cred}" if cred else ""))


def listen(port, service):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    log.info(f"Fake {service} on :{port}")
    with ThreadPoolExecutor(max_workers=10) as pool:
        while True:
            conn, addr = s.accept()
            pool.submit(handle, conn, addr, port, service)


if __name__ == "__main__":
    log.info(f"{HONEYPOT_NAME} starting")
    threads = [
        threading.Thread(target=listen, args=(p, s), daemon=True)
        for p, s in SERVICES.items()
    ]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log.info("stopped")