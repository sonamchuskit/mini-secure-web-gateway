# Mini Secure Web Gateway

An asyncio forward proxy in Python that inspects every request and enforces a
security policy before traffic leaves the network. It is a small-scale model of
how a cloud secure web gateway works: clients send traffic to the proxy, the
proxy decides allow or block, and every decision is logged and visible on a
dashboard.

## Features

- **HTTP forwarding** and **HTTPS tunnelling** (`CONNECT`) on one async event loop
- **Policy engine** (`policy.py`, rules in `rules.json`):
  - category blocklists (social, ads, malware) matched on the domain and all parent domains
  - per-group policies (e.g. `students` vs `default`), assigned by client IP
  - heuristic detection of auto-generated (DGA-like) domains using Shannon entropy
  - sliding-window rate limiting per client
  - `CONNECT` restricted to ports 443 and 8443 so the proxy cannot be used to tunnel to arbitrary services
- **Logging** of every decision to SQLite (`logger_db.py`)
- **Flask dashboard** (`dashboard.py`): totals, block rate, top blocked domains, traffic per minute, recent requests, JSON API at `/api/stats`
- **Tests**: end-to-end tests (`test_proxy.py`) and a load test (`load_test.py`)

## Architecture

```
 Browser / curl
      |
      v
 +-----------+   decide()   +---------------+
 |  proxy.py | -----------> |   policy.py   |  rules.json
 |  asyncio  | <----------- | allow / block |
 +-----------+              +---------------+
   |      |
   |      +--> log_request() --> SQLite (proxy_log.db) --> dashboard.py (Flask)
   v
 Origin server (HTTP, or HTTPS tunnel via CONNECT)
```

## Run it

```bash
pip install -r requirements.txt
python proxy.py            # gateway on 127.0.0.1:8888
python dashboard.py        # dashboard on http://127.0.0.1:5000  (second terminal)
```

Try it:

```bash
curl -x http://127.0.0.1:8888 http://example.com        # allowed
curl -x http://127.0.0.1:8888 http://evil.example       # 403 blocked (malware)
curl -x http://127.0.0.1:8888 http://doubleclick.net    # 403 blocked (ads)
curl -x http://127.0.0.1:8888 https://example.com       # HTTPS via CONNECT
```

To try group policies, edit `client_groups` in `rules.json`
(e.g. map `127.0.0.1` to `students`) and restart the proxy.

## Test it

```bash
python test_proxy.py       # 12 checks: forwarding, blocking, CONNECT, logging, rate limit, groups
python proxy.py &          # then, with the proxy running:
python load_test.py        # 500 requests, 20 concurrent clients, direct vs proxied
```

Sample load-test result (local machine, 1 KB responses, 20 concurrent clients):

| Path    | Success | p50    | p95     |
|---------|---------|--------|---------|
| Direct  | 500/500 | 3.6 ms | 8.1 ms  |
| Proxied | 500/500 | 7.3 ms | 14.3 ms |

The proxy adds about 3.7 ms of median latency in this setup. Your numbers will differ.

## Limitations (and what I would do next)

- HTTPS is filtered by domain only; TLS is not intercepted, so URL paths and content in encrypted traffic are not inspected.
- The DGA check is a heuristic and can produce false positives and false negatives.
- Client groups are assigned by IP, not by authenticated user.
- Plain HTTP uses one connection per request (no keep-alive or connection pooling).
- SQLite writes are synchronous; a production system would batch them or use a queue.
- Next steps: proxy authentication, keep-alive, a threat-intelligence feed for blocklists, and a Go or C++ rewrite of the hot path.
