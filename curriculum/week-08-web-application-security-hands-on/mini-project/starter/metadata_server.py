"""
Mock cloud-metadata server for the C6 Week 8 SSRF exercise.

============================== AUTHORIZED USE ONLY =============================
This server binds to 127.0.0.1:8080 and serves fake credentials at the same
path shape AWS's Instance Metadata Service (IMDS) uses. The fake credentials
are obvious placeholders ("ASIA-NOT-A-REAL-KEY-LAB-ONLY", etc.) and cannot
be used against AWS or any other cloud.

The point is to make the SSRF exploit complete-able offline: the lab fetches
http://127.0.0.1:8080/latest/meta-data/iam/security-credentials/lab-role
and proxies the response. No real cloud metadata service is involved.

Do not change the bind address. Do not run this server on any host except
your own laptop, and do not expose port 8080 to any network you share with
others.
================================================================================
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST: str = "127.0.0.1"
PORT: int = 8080


# The fake credentials. All clearly labeled as lab-only placeholders.
FAKE_CREDENTIALS: dict[str, str] = {
    "Code": "Success",
    "LastUpdated": "2026-05-14T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIA-NOT-A-REAL-KEY-LAB-ONLY",
    "SecretAccessKey": "fake-secret-key-for-the-lab-only-do-not-cite",
    "Token": "lab-only-fake-token-do-not-cite",
    "Expiration": "2099-12-31T23:59:59Z",
}


HEALTH_PATH: str = "/health"
ROLE_LIST_PATH: str = "/latest/meta-data/iam/security-credentials/"
ROLE_CREDENTIALS_PATH_PREFIX: str = "/latest/meta-data/iam/security-credentials/"


class _Handler(BaseHTTPRequestHandler):
    """Mock IMDS handler. Logs every request to stderr for the lab terminal."""

    def log_message(self, format: str, *args: object) -> None:
        # Keep the log shape readable.
        sys.stderr.write(f"[metadata] {self.address_string()} - {format % args}\n")

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path == HEALTH_PATH:
            self._respond(200, "text/plain", b"ok\n")
            return
        if self.path == ROLE_LIST_PATH:
            # IMDS returns a newline-delimited list of role names here.
            self._respond(200, "text/plain", b"lab-role\n")
            return
        if self.path.startswith(ROLE_CREDENTIALS_PATH_PREFIX):
            body: bytes = json.dumps(FAKE_CREDENTIALS, indent=2).encode("utf-8")
            self._respond(200, "application/json", body)
            return
        # Anything else: 404 with a brief explanation.
        self._respond(404, "text/plain", b"not a mock-IMDS path\n")

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), _Handler)
    print(f"Mock metadata server listening on {HOST}:{PORT}")
    print("  GET /health")
    print("  GET /latest/meta-data/iam/security-credentials/")
    print("  GET /latest/meta-data/iam/security-credentials/<role>")
    print("AUTHORIZED USE ONLY: do not run this on any host except your laptop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down metadata server.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
