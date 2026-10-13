"""End-to-end tests. Starts a local origin server and the proxy, then checks policy behaviour.
Run: python test_proxy.py
"""
import http.client
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy import Policy

PROXY_PORT, ORIGIN_PORT = 18888, 19000


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def via_proxy(url, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", PROXY_PORT, timeout=5)
    c.request(method, url)
    r = c.getresponse()
    return r.status, r.read()


def connect_status(target):
    s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=5)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    line = s.recv(200).split(b"\r\n")[0]
    s.close()
    return int(line.split()[1])


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        check.failed += 1


check.failed = 0


def main():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "test.db")
    srv = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = dict(os.environ, PROXY_PORT=str(PROXY_PORT), PROXY_DB=db)
    proc = subprocess.Popen([sys.executable, "proxy.py"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        status, body = via_proxy(f"http://127.0.0.1:{ORIGIN_PORT}/")
        check("allowed HTTP request is forwarded", status == 200 and body == b"hello from origin")
        check("malware category blocked", via_proxy("http://evil.example/")[0] == 403)
        check("subdomain of blocked domain blocked", via_proxy("http://a.b.doubleclick.net/x")[0] == 403)
        check("DGA-like domain blocked", via_proxy("http://xk3jf9s0qlz2mv.com/")[0] == 403)
        check("CONNECT to blocked domain -> 403", connect_status("evil.example:443") == 403)
        check("CONNECT to disallowed port -> 403", connect_status(f"127.0.0.1:{ORIGIN_PORT}") == 403)
        check("non-proxy (relative) request -> 400", via_proxy("/")[0] == 400)
        time.sleep(0.3)
        rows = sqlite3.connect(db).execute(
            "SELECT action, COUNT(*) FROM requests GROUP BY action").fetchall()
        counts = dict(rows)
        check("decisions logged to SQLite", counts.get("allow", 0) >= 1 and counts.get("block", 0) >= 4)
    finally:
        proc.terminate()
        srv.shutdown()

    p = Policy({"categories": {}, "groups": {}, "rate_limit": {"max_requests": 5, "window_seconds": 10}})
    results = [p.decide("example.com", "1.2.3.4")[0] for _ in range(8)]
    check("rate limiter blocks after 5 requests", results[:5] == ["allow"] * 5 and results[5:] == ["block"] * 3)
    check("legit long domain not flagged", not Policy.looks_generated("stackoverflow.com"))

    students = Policy({"categories": {"social": ["facebook.com"]},
                       "groups": {"students": {"block_categories": ["social"]}},
                       "client_groups": {"10.0.0.5": "students"}})
    check("group policy: students blocked from social", students.decide("www.facebook.com", "10.0.0.5")[0] == "block")
    check("group policy: default allowed", students.decide("www.facebook.com", "10.0.0.6")[0] == "allow")

    print(f"\n{check.failed} failure(s)")
    sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
    main()
