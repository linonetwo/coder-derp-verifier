import datetime as dt
import contextlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import ipaddress

from headscale_source_verifier import HeadscaleEndpointStore, endpoint_ip


class EndpointStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "headscale.db")
        with contextlib.closing(sqlite3.connect(self.db)) as db:
            db.execute(
                """CREATE TABLE nodes (
                    endpoints TEXT, last_seen TEXT, expiry TEXT, deleted_at TEXT
                )"""
            )
            db.commit()

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, endpoints, age=dt.timedelta(), expiry=None, deleted=False):
        now = dt.datetime.now(dt.timezone.utc)
        with contextlib.closing(sqlite3.connect(self.db)) as db:
            db.execute(
                "INSERT INTO nodes VALUES (?, ?, ?, ?)",
                (
                    json.dumps(endpoints),
                    (now - age).isoformat(),
                    expiry.isoformat() if expiry else None,
                    now.isoformat() if deleted else None,
                ),
            )
            db.commit()

    def test_allows_recent_endpoint_source(self):
        self.add(["198.51.100.7:41641", "[2001:db8::7]:41641"])
        store = HeadscaleEndpointStore(self.db, dt.timedelta(hours=2))
        self.assertTrue(store.contains_source(ipaddress.ip_address("198.51.100.7")))
        self.assertTrue(store.contains_source(ipaddress.ip_address("2001:db8::7")))

    def test_rejects_stale_expired_deleted_and_unknown(self):
        now = dt.datetime.now(dt.timezone.utc)
        self.add(["198.51.100.1:1"], age=dt.timedelta(hours=3))
        self.add(["198.51.100.2:1"], expiry=now - dt.timedelta(seconds=1))
        self.add(["198.51.100.3:1"], deleted=True)
        store = HeadscaleEndpointStore(self.db, dt.timedelta(hours=2))
        for address in ("198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"):
            self.assertFalse(store.contains_source(ipaddress.ip_address(address)))

    def test_endpoint_parser(self):
        self.assertEqual(str(endpoint_ip("192.0.2.1:123")), "192.0.2.1")
        self.assertEqual(str(endpoint_ip("[2001:db8::1]:123")), "2001:db8::1")
        self.assertIsNone(endpoint_ip("invalid"))


if __name__ == "__main__":
    unittest.main()
