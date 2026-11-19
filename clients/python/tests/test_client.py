# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The blocking and asyncio clients against a small service in the test:
hello and welcome, get, a service that is not there, and a fork, after
which the child opens a connection of its own. The full behaviour is the
conformance suite's (conformance/README.md)."""

import asyncio
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import warnings

import tsm
from tsm import _frames

_VALUE = {
    "op": "value",
    "value": "demo-secret",
    "entry": {
        "store": "demo",
        "uuid": "8f1c0f0e-0000-4000-8000-000000000002",
        "source": "file",
        "fetchedAt": "2026-11-19T10:00:00Z",
    },
    "bound": {},
    "version": {"modified": "2026-11-19T09:00:00Z", "revision": "r1"},
}


class FakeService:
    """Answers hello with welcome and every get with _VALUE; counts the
    connections and the processes that opened them."""

    def __init__(self, directory):
        self.path = os.path.join(directory, "client.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(8)
        self.hellos = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                peer, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(peer,), daemon=True).start()

    def _serve(self, peer):
        reader = _frames.FrameReader(_frames.MAX_REQUEST_PAYLOAD)
        with peer:
            while True:
                data = peer.recv(65536)
                if not data:
                    return
                for _, payload in reader.add(data):
                    m = _frames.decode_payload(payload)
                    if m["op"] == "hello":
                        self.hellos.append(m)
                        answer = {
                            "op": "welcome",
                            "protocol": 1,
                            "service": {"version": "0.0.0-test"},
                            "host": "testhost",
                            "platform": "macos",
                            "features": [],
                        }
                    elif m["op"] == "get":
                        answer = dict(_VALUE, id=m["id"], value=f"{_VALUE['value']}:{os.getpid()}")
                    else:
                        answer = {"op": "error", "id": m.get("id"), "kind": "malformed"}
                    peer.sendall(
                        _frames.encode_frame(_frames.FRAME_JSON, _frames.json_payload(answer))
                    )

    def close(self):
        self.listener.close()


@unittest.skipIf(sys.platform == "win32", "the Windows endpoint is TCP")
class Clients(unittest.TestCase):
    def setUp(self):
        # The system's temporary folder: a Unix socket's path is short.
        self.directory = tempfile.mkdtemp(prefix="tsm-test-")
        self.service = FakeService(self.directory)
        self.env = {"TSM_RUNTIME_DIR": self.directory}

    def tearDown(self):
        self.service.close()
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_blocking_get(self):
        with tsm.Client(client_name="unit-test", environment=self.env) as c:
            with c.get("db.main") as v:
                self.assertTrue(v.text.startswith("demo-secret:"))
            self.assertEqual(c.welcome.host, "testhost")
        hello = self.service.hellos[0]
        self.assertEqual(hello["client"]["name"], "unit-test")
        self.assertEqual(hello["client"]["language"], "python")
        self.assertEqual(hello["client"]["version"], tsm.__version__)
        self.assertEqual(hello["features"], ["binary", "getFile"])

    def test_asyncio_get(self):
        async def run():
            async with tsm.aio.Client(environment=self.env) as c:
                values = await asyncio.gather(*(c.get(f"k{i}") for i in range(5)))
                return [v.text for v in values]

        self.assertEqual(len(asyncio.run(run())), 5)
        self.assertEqual(len(self.service.hellos), 1)

    def test_get_file_needs_the_features(self):
        with tsm.Client(environment=self.env) as c:
            with self.assertRaises(tsm.SecretsError) as caught:
                c.get_file("db.main", field="key.pem")
        self.assertIs(caught.exception.kind, tsm.ErrorKind.UNSUPPORTED)

    def test_not_running(self):
        empty = tempfile.mkdtemp(prefix="tsm-test-")
        try:
            with tsm.Client(environment={"TSM_RUNTIME_DIR": empty}) as c:
                with self.assertRaises(tsm.SecretsError) as caught:
                    c.get("db.main")
            self.assertIs(caught.exception.kind, tsm.ErrorKind.NOT_RUNNING)
        finally:
            shutil.rmtree(empty)

    @unittest.skipUnless(hasattr(os, "fork"), "no fork")
    def test_fork_reconnects(self):
        c = tsm.Client(environment=self.env)
        try:
            c.get("db.main").close()
            read, write = os.pipe()
            with warnings.catch_warnings():
                # Python 3.12+ warns about forking a process with threads;
                # the client's own thread is what this test is about.
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()
            if pid == 0:  # the child
                os.close(read)
                ok = 0
                try:
                    with c.get("db.main") as v:
                        ok = 1 if v.text.startswith("demo-secret:") else 0
                finally:
                    os.write(write, bytes([ok]))
                    os._exit(0)
            os.close(write)
            self.assertEqual(os.read(read, 1), b"\x01")
            os.close(read)
            os.waitpid(pid, 0)
            # The parent's connection is untouched; the child had its own.
            c.get("db.main").close()
            self.assertEqual(len(self.service.hellos), 2)
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
