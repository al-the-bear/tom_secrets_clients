# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""SecretValue: what a value message becomes, that no printable form shows
the secret, and that close() overwrites the buffer."""

import datetime
import unittest

import tsm

_MESSAGE = {
    "op": "value",
    "value": "demo-password",
    "entry": {
        "store": "demo",
        "uuid": "8f1c0f0e-0000-4000-8000-000000000001",
        "source": "github",
        "fetchedAt": "2026-11-19T10:00:00Z",
    },
    "bound": {"env": "prod"},
    "version": {"modified": "2026-11-18T09:30:00.250+01:00", "revision": "r7"},
}


class Values(unittest.TestCase):
    def test_from_message(self):
        v = tsm.SecretValue.from_message("db.main", _MESSAGE)
        self.assertEqual(v.text, "demo-password")
        self.assertEqual(v.encoding, "utf8")
        self.assertEqual(v.entry.source, "github")
        self.assertEqual(dict(v.bound), {"env": "prod"})
        self.assertEqual(v.version.revision, "r7")
        self.assertEqual(
            v.version.modified,
            datetime.datetime(2026, 11, 18, 8, 30, 0, 250000, datetime.timezone.utc),
        )
        self.assertIsNone(v.expires)

    def test_unknown_source_is_cache(self):
        m = dict(_MESSAGE, entry=dict(_MESSAGE["entry"], source="relay"))
        self.assertEqual(tsm.SecretValue.from_message("x", m).entry.source, "cache")

    def test_base64_refuses_text(self):
        m = dict(_MESSAGE, encoding="base64", value="AAEC/w==")
        v = tsm.SecretValue.from_message("x", m)
        self.assertEqual(bytes(v.data), b"\x00\x01\x02\xff")
        with self.assertRaises(ValueError):
            v.text

    def test_bad_message_is_internal(self):
        with self.assertRaises(tsm.SecretsError) as caught:
            tsm.SecretValue.from_message("x", dict(_MESSAGE, version=None))
        self.assertIs(caught.exception.kind, tsm.ErrorKind.INTERNAL)

    def test_never_printed(self):
        v = tsm.SecretValue.from_message("db.main", _MESSAGE)
        for printed in (str(v), repr(v), f"{v}", "%s" % v, "{}".format(v)):
            self.assertIn("***", printed)
            self.assertNotIn("demo-password", printed)

    def test_close_overwrites(self):
        v = tsm.SecretValue.from_message("db.main", _MESSAGE)
        buffer = v._data
        with v:
            pass
        self.assertTrue(v.closed)
        self.assertTrue(all(b == 0 for b in buffer))
        with self.assertRaises(ValueError):
            v.text


class Errors(unittest.TestCase):
    def test_unknown_kind_is_internal(self):
        self.assertIs(tsm.ErrorKind.from_wire("brand_new"), tsm.ErrorKind.INTERNAL)
        self.assertIs(tsm.ErrorKind.from_wire("not_running"), tsm.ErrorKind.INTERNAL)
        self.assertIs(tsm.ErrorKind.from_wire("denied"), tsm.ErrorKind.DENIED)


if __name__ == "__main__":
    unittest.main()
