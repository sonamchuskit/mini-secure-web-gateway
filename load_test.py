"""Measure proxy overhead and throughput against a local origin server.
Start the proxy first (python proxy.py), then: python load_test.py
"""
import http.client
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROXY = ("127.0.0.1", 8888)
ORIGIN_PORT = 19001
TOTAL, WORKERS = 500, 20


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"x" * 1024
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def timed(use_proxy):
    t = time.perf_counter()
    if use_proxy:
        c = http.client.HTTPConnection(*PROXY, timeout=10)
        c.request("GET", f"http://127.0.0.1:{ORIGIN_PORT}/")
    else:
        c = http.client.HTTPConnection("127.0.0.1", ORIGIN_PORT, timeout=10)
        c.request("GET", "/")
    ok = c.getresponse().status == 200
    c.close()
    return (time.perf_counter() - t) * 1000, ok


def run(use_proxy):
    start = time.perf_counter()
    with ThreadPoolExecutor(WORKERS) as ex:
        res = list(ex.map(lambda _: timed(use_proxy), range(TOTAL)))
    elapsed = time.perf_counter() - start
    lat = sorted(r[0] for r in res)
    return {
        "ok": sum(r[1] for r in res),
        "rps": TOTAL / elapsed,
        "p50": statistics.median(lat),
        "p95": lat[int(0.95 * len(lat)) - 1],
    }


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    direct, proxied = run(False), run(True)
    print(f"{TOTAL} requests, {WORKERS} concurrent clients")
    for name, r in (("direct ", direct), ("proxied", proxied)):
        print(f"{name}: ok={r['ok']}/{TOTAL}  {r['rps']:.0f} req/s  p50={r['p50']:.1f} ms  p95={r['p95']:.1f} ms")
    print(f"added median latency: {proxied['p50'] - direct['p50']:.1f} ms")
    srv.shutdown()
