"""Mini Secure Web Gateway: an asyncio forward proxy with policy enforcement.

Supports plain HTTP (absolute-URI requests) and HTTPS via CONNECT tunnelling
(domain-level filtering only; TLS is not intercepted).

Run:  python proxy.py
Use:  curl -x http://127.0.0.1:8888 http://example.com
"""
import asyncio
import logging
import os
from urllib.parse import urlsplit

from logger_db import init_db, log_request
from policy import Policy

LISTEN_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8888"))
RULES_FILE = os.environ.get("PROXY_RULES", "rules.json")

HEADER_TIMEOUT = 15      # seconds to receive request headers
CONNECT_TIMEOUT = 10     # seconds to reach the origin server
IDLE_TIMEOUT = 60        # seconds of silence before a tunnel is closed
ALLOWED_CONNECT_PORTS = {443, 8443}  # block tunnels to arbitrary ports (ssh, smtp, ...)

policy = Policy(RULES_FILE)
log = logging.getLogger("proxy")


async def respond(writer, code, reason, body=""):
    payload = body.encode()
    writer.write(
        f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload
    )
    try:
        await writer.drain()
    except ConnectionError:
        pass
    writer.close()


async def pipe(reader, writer, counter):
    """Copy bytes one way until EOF, timeout or error."""
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            counter[0] += len(data)
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass


async def relay(cr, cw, ur, uw):
    """Bidirectional copy; returns total bytes moved."""
    counter = [0]
    tasks = {
        asyncio.create_task(pipe(cr, uw, counter)),
        asyncio.create_task(pipe(ur, cw, counter)),
    }
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for w in (cw, uw):
        w.close()
    return counter[0]


async def handle(cr, cw):
    peer = cw.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, ConnectionError):
        cw.close()
        return

    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError:
        await respond(cw, 400, "Bad Request", "Malformed request line")
        return
    method = method.upper()
    headers = [h for h in lines[1:] if h]

    if method == "CONNECT":
        host, _, port_s = target.rpartition(":")
        host = host.strip("[]").lower()
        port = int(port_s) if port_s.isdigit() else 443
        path = None
    else:
        u = urlsplit(target)
        if not u.hostname:
            await respond(cw, 400, "Bad Request", "Proxy requests need an absolute URL")
            return
        host, port = u.hostname.lower(), u.port or 80
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")

    action, category, reason = policy.decide(host, client_ip)
    if action == "allow" and method == "CONNECT" and port not in ALLOWED_CONNECT_PORTS:
        action, category, reason = "block", "port", f"CONNECT to port {port} not allowed"

    if action == "block":
        log_request(client_ip, method, host, "block", category, reason, 0)
        log.info("BLOCK %s %s (%s)", method, host, reason)
        await respond(cw, 403, "Forbidden", f"Blocked by gateway policy: {host}\nReason: {reason}")
        return

    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        log_request(client_ip, method, host, "error", category, "upstream unreachable", 0)
        await respond(cw, 502, "Bad Gateway", f"Could not reach {host}:{port}")
        return

    if path is None:  # HTTPS tunnel
        cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await cw.drain()
    else:             # plain HTTP: rewrite to origin-form and close after one exchange
        drop = ("proxy-connection", "connection:", "proxy-authorization")
        fwd = [f"{method} {path} {version}"]
        fwd += [h for h in headers if not h.lower().startswith(drop)]
        fwd.append("Connection: close")
        uw.write(("\r\n".join(fwd) + "\r\n\r\n").encode("latin-1"))
        await uw.drain()

    nbytes = await relay(cr, cw, ur, uw)
    log_request(client_ip, method, host, "allow", category, reason, nbytes)
    log.info("ALLOW %s %s (%d bytes)", method, host, nbytes)


async def main():
    init_db()
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    log.info("Gateway listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
