from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from datetime import datetime, timedelta, timezone

HARDCODED_KEY = "KEY-DIVAN"          # input "Divan" → uppercased + prefixed → matches
EXPIRY_DAYS   = 9999


def _iso_z(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


class handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version   = "cloudflare"
    sys_version      = ""

    def version_string(self):
        return "cloudflare"

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self._json(405, {"valid": False, "status": "error",
                         "message": "Method not allowed.", "expires": None})

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"valid": False, "status": "error",
                                    "message": "Invalid JSON body.", "expires": None})

        raw_key    = str(body.get("key", "")).strip().upper()
        normalized = raw_key if raw_key.startswith("KEY-") else "KEY-" + raw_key

        if normalized != HARDCODED_KEY:
            return self._json(200, {
                "valid": False,
                "status": "error",
                "message": "Key invalid, expired, or revoked.",
                "expires": None,
            })

        expires = _iso_z(datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS))
        return self._json(200, {
            "valid": True,
            "status": "success",
            "message": "Key accepted.",
            "expires": expires,
        })

    def _json(self, status, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("content-security-policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-frame-options", "DENY")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"Local  →  http://localhost:{port}/api/v1/validate")
    print(f"LAN    →  http://0.0.0.0:{port}/api/v1/validate")
    print("Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        srv.shutdown()
