#!/usr/bin/env python3
"""DERP admission controller backed by recent Headscale endpoint source IPs."""

import argparse
import contextlib
import datetime as dt
import ipaddress
import json
import logging
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 64 * 1024
NODE_KEY = re.compile(r"^nodekey:[0-9a-f]{64}$")


def endpoint_ip(endpoint: str):
    try:
        if endpoint.startswith("["):
            host = endpoint[1 : endpoint.index("]")]
        else:
            host = endpoint.rsplit(":", 1)[0]
        return ipaddress.ip_address(host)
    except (ValueError, IndexError):
        return None


def parse_time(value: str | None):
    if not value:
        return None
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


class HeadscaleEndpointStore:
    def __init__(self, database: str, max_node_age: dt.timedelta):
        self.database = database
        self.max_node_age = max_node_age

    def contains_source(self, source: ipaddress._BaseAddress) -> bool:
        now = dt.datetime.now(dt.timezone.utc)
        uri = f"file:{self.database}?mode=ro"
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            rows = db.execute(
                """
                SELECT endpoints, last_seen, expiry
                FROM nodes
                WHERE deleted_at IS NULL
                """
            )
            for endpoints_raw, last_seen_raw, expiry_raw in rows:
                last_seen = parse_time(last_seen_raw)
                expiry = parse_time(expiry_raw)
                if last_seen is None or now - last_seen > self.max_node_age:
                    continue
                if expiry is not None and expiry <= now:
                    continue
                try:
                    endpoints = json.loads(endpoints_raw or "[]")
                except json.JSONDecodeError:
                    continue
                if any(endpoint_ip(value) == source for value in endpoints):
                    return True
        return False

    def ready(self):
        uri = f"file:{self.database}?mode=ro"
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            db.execute("SELECT 1 FROM nodes LIMIT 1").fetchone()


class VerifierHandler(BaseHTTPRequestHandler):
    store = None

    def log_message(self, fmt, *args):
        logging.info("%s %s", self.address_string(), fmt % args)

    def send_json(self, status: int, allow: bool):
        body = json.dumps({"Allow": allow}, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(204)
            self.end_headers()
            return
        if self.path == "/readyz":
            try:
                self.store.ready()
                self.send_response(204)
                self.end_headers()
            except Exception:
                logging.exception("Headscale database readiness failed")
                self.send_json(503, False)
            return
        self.send_json(404, False)

    def do_POST(self):
        if self.path != "/verify":
            self.send_json(404, False)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_json(400, False)
                return
            request = json.loads(self.rfile.read(length))
            if set(request) != {"NodePublic", "Source"}:
                self.send_json(400, False)
                return
            if not NODE_KEY.fullmatch(request["NodePublic"]):
                self.send_json(400, False)
                return
            source = ipaddress.ip_address(request["Source"])
            allow = self.store.contains_source(source)
            if not allow:
                logging.warning("rejected DERP source IP %s", source)
            self.send_json(200, allow)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_json(400, False)
        except Exception:
            logging.exception("Headscale endpoint lookup failed")
            self.send_json(503, False)


def duration(value: str):
    match = re.fullmatch(r"(\d+)([smhd])", value)
    if not match:
        raise argparse.ArgumentTypeError("duration must use s, m, h, or d")
    amount = int(match.group(1))
    return dt.timedelta(seconds=amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--max-node-age", type=duration, default=duration("2h"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    VerifierHandler.store = HeadscaleEndpointStore(args.database, args.max_node_age)
    server = ThreadingHTTPServer((args.listen, args.port), VerifierHandler)
    logging.info("serving Headscale source verifier on %s:%d", args.listen, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
