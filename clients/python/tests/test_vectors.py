# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The library against every vector of protocol/vectors/ that a client
computes: references (parse, canonical form, malformed reasons,
formatting), discovery and port files, and the frames of the client
endpoint."""

import json
import os
import unittest

import tsm
from tsm import _frames
from tsm.discovery import Endpoints, NoRuntimeDirectory, discover, read_port_file

_VECTORS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "protocol", "vectors"
)


def vectors(name):
    with open(os.path.join(_VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def shape(r):
    t = r.target
    if isinstance(t, tsm.KeyTarget):
        target = {"kind": "key", "key": t.key}
    elif isinstance(t, tsm.UuidTarget):
        target = {"kind": "uuid", "store": t.store, "uuid": t.uuid}
    else:
        target = {"kind": "path", "store": t.store, "segments": list(t.segments)}
    return {
        "qualifiers": [{"dimension": q.dimension, "value": q.value} for q in r.qualifiers],
        "target": target,
        "field": r.field,
        "fieldGiven": r.field_given,
    }


def from_shape(m):
    t = m["target"]
    if t["kind"] == "key":
        target = tsm.KeyTarget(t["key"])
    elif t["kind"] == "uuid":
        target = tsm.UuidTarget(t["store"], t["uuid"])
    else:
        target = tsm.PathTarget(t["store"], tuple(t["segments"]))
    return tsm.SecretReference(
        target,
        tuple(tsm.SecretBinding(q["dimension"], q["value"]) for q in m["qualifiers"]),
        m.get("field") or tsm.DEFAULT_FIELD,
    )


class References(unittest.TestCase):
    v = vectors("references.json")

    def test_limit(self):
        from tsm.reference import MAX_REFERENCE_BYTES

        self.assertEqual(self.v["maxReferenceBytes"], MAX_REFERENCE_BYTES)

    def test_valid(self):
        for c in self.v["valid"]:
            with self.subTest(c["input"]):
                parsed = tsm.SecretReference.parse(c["input"])
                self.assertEqual(shape(parsed), c["parsed"])
                self.assertEqual(parsed.canonical, c["canonical"])
                self.assertEqual(
                    tsm.SecretReference.parse(parsed.canonical).canonical,
                    parsed.canonical,
                )

    def test_invalid(self):
        for c in self.v["invalid"]:
            with self.subTest(c["input"]):
                with self.assertRaises(tsm.SecretsError) as caught:
                    tsm.SecretReference.parse(c["input"])
                self.assertIs(caught.exception.kind, tsm.ErrorKind.MALFORMED)
                self.assertEqual(caught.exception.reason, c["reason"])

    def test_format(self):
        for c in self.v["format"]:
            with self.subTest(c["formatted"]):
                self.assertEqual(
                    tsm.SecretReference.format(from_shape(c["parsed"])), c["formatted"]
                )
                self.assertEqual(
                    shape(tsm.SecretReference.parse(c["formatted"])), c["reparsed"]
                )


class Discovery(unittest.TestCase):
    v = vectors("discovery.json")

    def test_cases(self):
        for c in self.v["cases"]:
            with self.subTest(os=c["os"], env=c["env"]):
                location = discover(c["os"], c["env"], lambda: c["uid"])
                expected = c["expect"]
                if isinstance(location, NoRuntimeDirectory):
                    self.assertEqual({"notRunning": location.reason}, expected)
                    continue
                self.assertIsInstance(location, Endpoints)
                client, admin = expected["client"], expected["admin"]
                self.assertEqual(location.directory, expected["directory"])
                self.assertEqual(location.client_socket, client.get("socket"))
                self.assertEqual(location.client_port_file, client.get("portFile"))
                self.assertEqual(location.client_token_file, client.get("tokenFile"))
                self.assertEqual(location.admin_socket, admin.get("socket"))
                self.assertEqual(location.admin_port_file, admin.get("portFile"))

    def test_port_files(self):
        for c in self.v["portFiles"]:
            with self.subTest(c["text"]):
                self.assertEqual(read_port_file(c["text"]), c["port"])


class Frames(unittest.TestCase):
    v = vectors("frames.json")

    def test_protocol(self):
        self.assertEqual(self.v["protocol"], tsm.PROTOCOL_VERSION)

    def test_json_frames(self):
        for c in self.v["frames"]:
            if c["type"] != _frames.FRAME_JSON:
                continue
            with self.subTest(c["name"]):
                read = _frames.FrameReader(_frames.MAX_ANSWER_PAYLOAD).add(
                    bytes.fromhex(c["hex"])
                )
                self.assertEqual(len(read), 1)
                self.assertEqual(_frames.decode_payload(read[0][1]), c["json"])
                self.assertEqual(
                    _frames.encode_frame(
                        _frames.FRAME_JSON, _frames.json_payload(c["json"])
                    ).hex(),
                    c["hex"],
                )

    def test_binary_frames(self):
        for c in self.v["frames"]:
            if c["type"] != _frames.FRAME_BINARY:
                continue
            with self.subTest(c["name"]):
                with self.assertRaises(_frames.FrameError):
                    _frames.FrameReader(_frames.MAX_ANSWER_PAYLOAD).add(
                        bytes.fromhex(c["hex"])
                    )
                negotiated = _frames.FrameReader(_frames.MAX_ANSWER_PAYLOAD)
                negotiated.binary_allowed = True
                read = negotiated.add(bytes.fromhex(c["hex"]))
                self.assertEqual(len(read), 1)
                payload = read[0][1]
                self.assertEqual(int.from_bytes(payload[:8], "big"), c["requestId"])
                self.assertEqual(payload[8:].hex(), c["chunkHex"])

    def test_split_reads(self):
        data = bytes.fromhex(self.v["frames"][0]["hex"])
        reader = _frames.FrameReader(_frames.MAX_REQUEST_PAYLOAD)
        self.assertEqual(reader.add(data[:3]), [])
        self.assertEqual(reader.add(data[3:20]), [])
        self.assertEqual(len(reader.add(data[20:] + data)), 2)

    def test_invalid(self):
        for c in self.v["invalid"]:
            with self.subTest(c["name"]):
                reader = _frames.FrameReader(
                    _frames.MAX_REQUEST_PAYLOAD
                    if c["direction"] == "to service"
                    else _frames.MAX_ANSWER_PAYLOAD
                )
                data = bytes.fromhex(c["hex"])
                if c["outcome"] == "close":
                    with self.assertRaises(_frames.FrameError):
                        reader.add(data)
                elif c["outcome"] == "read":
                    self.assertEqual(reader.add(data), [])
                elif c["name"] == "a first frame that is not hello":
                    # A frame the client reads whole; the service closes on it.
                    self.assertEqual(len(reader.add(data)), 1)
                else:
                    read = reader.add(data)
                    self.assertEqual(len(read), 1)
                    with self.assertRaises(_frames.FrameError):
                        _frames.decode_payload(read[0][1])


if __name__ == "__main__":
    unittest.main()
