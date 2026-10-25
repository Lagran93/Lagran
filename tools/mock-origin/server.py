#!/usr/bin/env python3
"""Tiny origin server used by the integration smoke test.

Responses:
  GET /              -> text/plain, no cache headers
  GET /cached        -> max-age=120, stale-while-revalidate=30
  GET /nostore       -> Cache-Control: no-store
  GET /private       -> Cache-Control: private
  GET /api/data      -> application/json
  GET /expires       -> Expires header only
  POST /echo         -> echoes method/body as JSON
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, headers):
        self.send_response(status)
        headers = dict(headers)
        headers.setdefault("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        body = b"hello from origin"
        headers = {"Content-Type": "text/plain"}
        if path == "/cached":
            headers["Cache-Control"] = "public, max-age=120, stale-while-revalidate=30"
        elif path == "/nostore":
            headers["Cache-Control"] = "no-store"
        elif path == "/private":
            headers["Cache-Control"] = "private, max-age=60"
        elif path == "/api/data":
            body = json.dumps({"ok": True, "ts": time.time()}).encode()
            headers["Content-Type"] = "application/json"
        elif path == "/expires":
            headers["Expires"] = "Wed, 21 Oct 2026 07:28:00 GMT"
        elif path == "/big":
            body = b"x" * (512 * 1024)
        self._send(200, body, headers)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length)
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "x_custom": self.headers.get("x-custom"),
                "cookie": self.headers.get("cookie"),
                "bytes": len(payload),
                "echo": payload.decode("utf-8", "replace"),
            }
        ).encode()
        self._send(200, body, {"Content-Type": "application/json"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
