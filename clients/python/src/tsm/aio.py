# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The asyncio client (protocol.md section 5): the connection, ``hello``,
``get``, ``getMany`` and **[B]** ``getFile``.

    async with tsm.aio.Client() as c:
        v = await c.get("[env:prod]db.main", field="UserName")

The blocking :class:`tsm.Client` runs this client on a thread of its own.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import os
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from . import discovery
from ._frames import (
    FRAME_BINARY,
    FRAME_JSON,
    MAX_ANSWER_PAYLOAD,
    MAX_REQUEST_PAYLOAD,
    FrameError,
    FrameReader,
    Message,
    decode_payload,
    encode_frame,
    json_payload,
)
from ._version import __version__
from .errors import ErrorKind, SecretsError, not_running, protocol_error
from .reference import SecretReference
from .value import (
    Progress,
    ProgressCallback,
    SecretFile,
    SecretRequest,
    SecretResult,
    SecretValue,
)

#: The protocol version this library speaks.
PROTOCOL_VERSION = 1
#: The most references one ``get_many`` carries.
MAX_GET_MANY = 256
#: The optional features this library takes (section 8): binary frames and
#: ``getFile``.
CLIENT_FEATURES = ("binary", "getFile")


@dataclasses.dataclass(frozen=True)
class Welcome:
    """What the service said in ``welcome``: the protocol, its version, the
    optional features it offers (section 8), its host name (the current value
    of the ``host`` dimension) and platform."""

    protocol: int
    service_version: str
    features: frozenset
    host: str
    platform: str


def _script_name() -> str:
    script = sys.argv[0] if sys.argv else ""
    if not script or script == "-c":
        return "python"
    name = os.path.basename(script)
    if name == "__main__.py":
        name = os.path.basename(os.path.dirname(os.path.abspath(script)))
    return name[:-3] if name.lower().endswith(".py") else name


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _request_item(
    ref: str, field: Optional[str], dimensions: Optional[Mapping[str, str]]
) -> Message:
    parsed = SecretReference.parse(ref)
    if field is not None and parsed.field_given and field != parsed.field:
        raise SecretsError(
            ErrorKind.MALFORMED,
            "the field is named in the reference and as field",
            {"reason": "field_twice"},
        )
    item: Message = {"ref": ref}
    if dimensions:
        item["dimensions"] = dict(dimensions)
    if field is not None and not parsed.field_given:
        item["field"] = field
    return item


def _value_of(ref: str, answer: Message) -> SecretValue:
    if answer.get("op") != "value":
        raise protocol_error(f"get was answered {answer.get('op')}")
    return SecretValue.from_message(ref, answer)


def _welcome_of(m: Message) -> Welcome:
    protocol = m.get("protocol")
    if protocol != PROTOCOL_VERSION or isinstance(protocol, bool):
        raise SecretsError(
            ErrorKind.UNSUPPORTED,
            f"the service speaks protocol {protocol}",
            {"protocols": [protocol]},
        )
    service = m.get("service")
    features = m.get("features")
    host = m.get("host")
    platform = m.get("platform")
    return Welcome(
        protocol=PROTOCOL_VERSION,
        service_version=str(service.get("version"))
        if isinstance(service, dict)
        else "",
        features=frozenset(
            f for f in features if isinstance(f, str)
        )
        if isinstance(features, list)
        else frozenset(),
        host=host if isinstance(host, str) else "",
        platform=platform if isinstance(platform, str) else "",
    )


class _Pending:
    def __init__(self, on_progress: Optional[ProgressCallback]) -> None:
        self.on_progress = on_progress
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.file: Optional[Message] = None
        self.chunks: Optional[bytearray] = None


class _Connection:
    """One connection: frames in and out, the open requests by id."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.closed = False
        self.welcome: Optional[Welcome] = None
        self._writer = writer
        self._frames = FrameReader(MAX_ANSWER_PAYLOAD)
        self._pending: Dict[int, _Pending] = {}
        self._next_id = 1
        loop = asyncio.get_running_loop()
        self.welcomed: asyncio.Future = loop.create_future()
        self._task = loop.create_task(self._read(reader))

    def send_frame(self, message: Message) -> None:
        payload = json_payload(message)
        if len(payload) > MAX_REQUEST_PAYLOAD:
            raise SecretsError(
                ErrorKind.MALFORMED,
                f"the request is {len(payload)} bytes, over {MAX_REQUEST_PAYLOAD}",
                {"reason": "frame"},
            )
        self._writer.write(encode_frame(FRAME_JSON, payload))

    async def send(
        self, request: Message, on_progress: Optional[ProgressCallback]
    ) -> Message:
        if self.closed:
            raise _dropped()
        request_id = self._next_id
        self._next_id += 1
        self.send_frame({**request, "id": request_id})
        pending = _Pending(on_progress)
        self._pending[request_id] = pending
        return await pending.future

    async def _read(self, reader: asyncio.StreamReader) -> None:
        try:
            while not self.closed:
                data = await reader.read(65536)
                if not data:
                    self._fail(_dropped())
                    return
                for frame_type, payload in self._frames.add(data):
                    if frame_type == FRAME_BINARY:
                        self._on_chunk(payload)
                    else:
                        self._on_message(decode_payload(payload))
                    if self.closed:
                        return
        except FrameError as e:
            self._fail(protocol_error(str(e)))
        except SecretsError as e:
            self._fail(e)
        except (OSError, asyncio.IncompleteReadError):
            self._fail(_dropped())
        except asyncio.CancelledError:
            self._fail(_dropped())
            raise

    def _on_message(self, message: Message) -> None:
        op = message.get("op")
        request_id = message.get("id")
        if self.welcome is None:
            if op == "welcome":
                self.welcome = _welcome_of(message)
                self._frames.binary_allowed = "binary" in self.welcome.features
                if not self.welcomed.done():
                    self.welcomed.set_result(None)
            elif op == "error" and request_id is None:
                self._fail(SecretsError.from_error(message))
            else:
                self._fail(protocol_error(f"the first frame is {op}, not welcome"))
            return
        if op == "error" and request_id is None:
            self._fail(SecretsError.from_error(message))
            return
        pending = (
            self._pending.get(request_id)
            if isinstance(request_id, int) and not isinstance(request_id, bool)
            else None
        )
        if pending is None:
            return  # an answer nobody waits for; ignored
        if op == "progress":
            code = message.get("approvalCode")
            if pending.on_progress is not None:
                pending.on_progress(
                    Progress(
                        "unlock" if message.get("pending") == "unlock" else "approval",
                        code if isinstance(code, str) else None,
                    )
                )
        elif op == "file":
            pending.file = message
            pending.chunks = bytearray()
        elif op == "end":
            if pending.file is None or pending.chunks is None:
                raise protocol_error("end without file")
            self._complete(
                request_id,
                {**message, "_file": pending.file, "_bytes": pending.chunks},
            )
        elif op in ("value", "values", "error"):
            self._complete(request_id, message)
        # Any other answer is one this library does not know: section 8 says
        # ignore it.

    def _on_chunk(self, payload: bytes) -> None:
        if len(payload) < 8:
            raise protocol_error("a binary chunk without id")
        request_id = int.from_bytes(payload[:8], "big")
        pending = self._pending.get(request_id)
        if pending is None or pending.chunks is None:
            raise protocol_error("a chunk without file")
        pending.chunks += payload[8:]

    def _complete(self, request_id: Any, message: Message) -> None:
        pending = self._pending.pop(request_id, None)
        if pending is not None and not pending.future.done():
            pending.future.set_result(message)

    def _fail(self, error: SecretsError) -> None:
        if self.closed:
            return
        self.closed = True
        if not self.welcomed.done():
            self.welcomed.set_exception(error)
            # Read by the connecting call; never an unretrieved exception.
            self.welcomed.exception()
        for pending in self._pending.values():
            if pending.chunks is not None:
                pending.chunks[:] = bytes(len(pending.chunks))
            if not pending.future.done():
                pending.future.set_exception(error)
        self._pending.clear()
        try:
            self._writer.close()
        except (OSError, RuntimeError):
            pass

    def close(self) -> None:
        self._fail(not_running("the client closed the connection"))
        if not self._task.done():
            self._task.cancel()


def _dropped() -> SecretsError:
    return not_running("the connection to the service dropped")


class Client:
    """An asyncio client of the Tom Secrets Manager's secrets service.

    One connection, opened by the first call (or :meth:`open`); after
    ``not_running`` or a dropped connection the next call connects again.
    Calls may overlap. The library logs nothing: no value, token or payload.

    ``client_name`` is shown in approval prompts, never trusted (default the
    script's name); ``client_token`` is a token the program was given before
    (7.4), sent in every ``hello``; ``environment`` (default the process's;
    ``TSM_RUNTIME_DIR`` names the directory for containers and tests) and
    ``operating_system`` (``linux``, ``macos`` or ``windows``) say where the
    service is; ``connect_timeout`` (seconds) bounds connecting and the
    ``welcome``.
    """

    def __init__(
        self,
        *,
        client_name: Optional[str] = None,
        client_token: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
        operating_system: Optional[str] = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self.client_name = client_name or _script_name()
        self.client_token = client_token
        self.connect_timeout = connect_timeout
        self._environment: Mapping[str, str] = (
            environment if environment is not None else os.environ
        )
        self._operating_system = (
            operating_system or discovery.current_operating_system()
        )
        self._connection: Optional[_Connection] = None
        self._connecting: Optional[asyncio.Future] = None

    @classmethod
    async def connect(cls, **options: Any) -> "Client":
        """Creates a client and connects it, so a missing service shows at
        once (``not_running``)."""
        client = cls(**options)
        await client.open()
        return client

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *_: Any) -> None:
        self.close()

    @property
    def welcome(self) -> Optional[Welcome]:
        """The ``welcome`` of the current connection, or None."""
        c = self._connection
        return None if c is None or c.closed else c.welcome

    async def open(self) -> None:
        """Connects, unless a connection is open."""
        await self._ensure_connection()

    def close(self) -> None:
        """Closes the connection; a later call connects again."""
        connection, self._connection = self._connection, None
        if connection is not None:
            connection.close()

    async def get(
        self,
        ref: str,
        *,
        field: Optional[str] = None,
        dimensions: Optional[Mapping[str, str]] = None,
        wait: bool = True,
        timeout_ms: Optional[int] = None,
        on_progress: Optional[ProgressCallback] = None,
        want_client_token: bool = False,
        wait_on_rate_limit: bool = False,
    ) -> SecretValue:
        """Reads one secret.

        ``ref`` is parsed locally first; a malformed one fails as
        ``MALFORMED`` without a round trip. ``field`` names the field when
        the reference names none (the same field in both is sent once; two
        different ones are ``MALFORMED``, reason ``field_twice``). ``wait``
        waits for an unlock or an approval, up to ``timeout_ms`` (capped by
        the service), passing each progress notice to ``on_progress``.
        ``wait_on_rate_limit`` waits out a ``rate_limited`` answer;
        ``denied``, ``ambiguous`` and ``not_found`` are never retried.
        """
        request: Message = {"op": "get", **_request_item(ref, field, dimensions)}
        if not wait:
            request["wait"] = False
        if timeout_ms is not None:
            request["timeoutMs"] = timeout_ms
        if want_client_token:
            request["wantClientToken"] = True
        answer = await self._request(request, on_progress, wait_on_rate_limit)
        return _value_of(ref, answer)

    async def get_many(
        self,
        requests: Sequence[SecretRequest],
        *,
        wait: bool = True,
        timeout_ms: Optional[int] = None,
        on_progress: Optional[ProgressCallback] = None,
        wait_on_rate_limit: bool = False,
    ) -> List[SecretResult]:
        """Reads several secrets under one approval prompt (1 to 256); the
        results come in request order, each a value or an error. Every
        reference is parsed locally first."""
        if not 0 < len(requests) <= MAX_GET_MANY:
            raise ValueError(
                f"a get_many carries 1 to {MAX_GET_MANY} references, not "
                f"{len(requests)}"
            )
        items = [_request_item(r.ref, r.field, r.dimensions) for r in requests]
        request: Message = {"op": "getMany", "refs": items}
        if not wait:
            request["wait"] = False
        if timeout_ms is not None:
            request["timeoutMs"] = timeout_ms
        answer = await self._request(request, on_progress, wait_on_rate_limit)
        results = answer.get("results")
        if answer.get("op") != "values" or not isinstance(results, list):
            raise protocol_error(f"getMany was answered {answer.get('op')}")
        if len(results) != len(requests):
            raise protocol_error(f"getMany got {len(results)} results")
        out: List[SecretResult] = []
        for request_item, result in zip(requests, results):
            if not isinstance(result, dict):
                raise protocol_error("a getMany result is no object")
            if result.get("op") == "error":
                out.append(SecretResult(error=SecretsError.from_error(result)))
            else:
                out.append(SecretResult(value=_value_of(request_item.ref, result)))
        return out

    async def get_file(
        self,
        ref: str,
        *,
        field: Optional[str] = None,
        dimensions: Optional[Mapping[str, str]] = None,
        wait: bool = True,
        timeout_ms: Optional[int] = None,
        on_progress: Optional[ProgressCallback] = None,
    ) -> SecretFile:
        """**[B]** Reads an attachment or a typed key as bytes, over binary
        frames, checked against its size and SHA-256. Fails as
        ``UNSUPPORTED`` when the service does not offer the features
        ``binary`` and ``getFile``."""
        item = _request_item(ref, field, dimensions)
        connection = await self._ensure_connection()
        offered: Set[str] = set(connection.welcome.features if connection.welcome else ())
        missing = [f for f in CLIENT_FEATURES if f not in offered]
        if missing:
            raise SecretsError(
                ErrorKind.UNSUPPORTED,
                f"the service does not offer getFile (features {', '.join(missing)})",
                {"features": missing},
            )
        request: Message = {"op": "getFile", **item}
        if not wait:
            request["wait"] = False
        if timeout_ms is not None:
            request["timeoutMs"] = timeout_ms
        answer = await self._request(request, on_progress, False)
        if answer.get("op") != "end":
            raise protocol_error(f"getFile was answered {answer.get('op')}")
        file = answer["_file"]
        data: bytearray = answer["_bytes"]
        name = file.get("name")
        if (
            file.get("size") != len(data)
            or answer.get("sha256") != hashlib.sha256(data).hexdigest()
            or not isinstance(name, str)
        ):
            data[:] = bytes(len(data))
            raise protocol_error("the file does not match its size or sha256")
        return SecretFile(ref, name, data)

    async def _request(
        self,
        request: Message,
        on_progress: Optional[ProgressCallback],
        wait_on_rate_limit: bool,
    ) -> Message:
        while True:
            connection = await self._ensure_connection()
            answer = await connection.send(request, on_progress)
            if answer.get("op") != "error":
                return answer
            error = SecretsError.from_error(answer)
            if error.kind is ErrorKind.RATE_LIMITED and wait_on_rate_limit:
                ms = error.details.get("retryAfterMs")
                valid = isinstance(ms, int) and not isinstance(ms, bool) and ms > 0
                await asyncio.sleep((ms if valid else 1000) / 1000)
                continue
            raise error

    async def _ensure_connection(self) -> _Connection:
        connection = self._connection
        if connection is not None and not connection.closed:
            return connection
        if self._connecting is None:
            self._connecting = asyncio.ensure_future(self._connect())
            self._connecting.add_done_callback(self._connected)
        return await asyncio.shield(self._connecting)

    def _connected(self, future: asyncio.Future) -> None:
        self._connecting = None
        if not future.cancelled():
            future.exception()  # retrieved by the callers; never unhandled

    async def _connect(self) -> _Connection:
        location = discovery.discover(self._operating_system, self._environment)
        if not isinstance(location, discovery.Endpoints):
            raise not_running("no runtime directory can be named")
        token: Optional[str] = None
        try:
            if self._operating_system == "windows":
                text = _read_text(location.client_port_file or "")
                port = None if text is None else discovery.read_port_file(text)
                if port is None:
                    raise not_running("no readable client.port")
                raw = _read_text(location.client_token_file or "")
                if raw is None:
                    raise not_running("no client.token")
                token = discovery.strip_line_end(raw)
                opening = asyncio.open_connection("127.0.0.1", port)
            else:
                path = location.client_socket or ""
                if not os.path.exists(path):
                    raise not_running(f"no client.sock in {location.directory}")
                opening = asyncio.open_unix_connection(path)
            reader, writer = await asyncio.wait_for(opening, self.connect_timeout)
        except asyncio.TimeoutError:
            raise not_running("the connection timed out") from None
        except OSError:
            raise not_running("the connection was refused") from None
        connection = _Connection(reader, writer)
        hello: Message = {
            "op": "hello",
            "protocol": PROTOCOL_VERSION,
            "client": {
                "name": self.client_name,
                "version": __version__,
                "language": "python",
            },
            "features": list(CLIENT_FEATURES),
        }
        if token is not None:
            hello["token"] = token
        if self.client_token is not None:
            hello["clientToken"] = self.client_token
        try:
            connection.send_frame(hello)
            await asyncio.wait_for(
                asyncio.shield(connection.welcomed), self.connect_timeout
            )
        except asyncio.TimeoutError:
            connection.close()
            raise not_running(
                f"no welcome within {int(self.connect_timeout * 1000)} ms"
            ) from None
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        return connection
