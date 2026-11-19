# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The blocking client.

    with tsm.Client() as c:
        v = c.get("[env:prod]db.main", field="UserName")

It runs :class:`tsm.aio.Client` on an event loop of its own, on a daemon
thread, so calls from several threads overlap on the one connection. After
``os.fork`` the child starts a loop and a connection of its own instead of
sharing the parent's socket.
"""

from __future__ import annotations

import asyncio
import os
import threading
from typing import Any, Coroutine, List, Mapping, Optional, Sequence, TypeVar

from . import aio
from .value import (
    ProgressCallback,
    SecretFile,
    SecretRequest,
    SecretResult,
    SecretValue,
)

T = TypeVar("T")


class Client:
    """A blocking client of the Tom Secrets Manager's secrets service: the
    same options, calls and errors as :class:`tsm.aio.Client`, without
    ``await``. Thread-safe; a ``with`` block closes it."""

    def __init__(
        self,
        *,
        client_name: Optional[str] = None,
        client_token: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
        operating_system: Optional[str] = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self._options = dict(
            client_name=client_name,
            client_token=client_token,
            environment=environment,
            operating_system=operating_system,
            connect_timeout=connect_timeout,
        )
        self._lock = threading.Lock()
        self._pid = -1
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._client: Optional[aio.Client] = None

    @classmethod
    def connect(cls, **options: Any) -> "Client":
        """Creates a client and connects it, so a missing service shows at
        once (``not_running``)."""
        client = cls(**options)
        client.open()
        return client

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @property
    def client_name(self) -> str:
        """The name ``hello`` gives the program."""
        return self._ensure()[1].client_name

    @property
    def welcome(self) -> Optional[aio.Welcome]:
        """The ``welcome`` of the current connection, or None."""
        with self._lock:
            if self._client is None or self._pid != os.getpid():
                return None
            return self._client.welcome

    def open(self) -> None:
        """Connects, unless a connection is open."""
        self._run(lambda c: c.open())

    def close(self) -> None:
        """Closes the connection and stops the loop's thread; a later call
        starts them again."""
        with self._lock:
            loop, client = self._loop, self._client
            mine = self._pid == os.getpid()
            self._loop = None
            self._client = None
            self._pid = -1
        if loop is None or client is None or not mine:
            return

        async def shut() -> None:
            client.close()
            await asyncio.sleep(0)

        asyncio.run_coroutine_threadsafe(shut(), loop).result()
        loop.call_soon_threadsafe(loop.stop)

    def get(
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
        """Reads one secret; see :meth:`tsm.aio.Client.get`. ``on_progress``
        is called on the client's own thread."""
        return self._run(
            lambda c: c.get(
                ref,
                field=field,
                dimensions=dimensions,
                wait=wait,
                timeout_ms=timeout_ms,
                on_progress=on_progress,
                want_client_token=want_client_token,
                wait_on_rate_limit=wait_on_rate_limit,
            )
        )

    def get_many(
        self,
        requests: Sequence[SecretRequest],
        *,
        wait: bool = True,
        timeout_ms: Optional[int] = None,
        on_progress: Optional[ProgressCallback] = None,
        wait_on_rate_limit: bool = False,
    ) -> List[SecretResult]:
        """Reads several secrets under one approval prompt; see
        :meth:`tsm.aio.Client.get_many`."""
        return self._run(
            lambda c: c.get_many(
                requests,
                wait=wait,
                timeout_ms=timeout_ms,
                on_progress=on_progress,
                wait_on_rate_limit=wait_on_rate_limit,
            )
        )

    def get_file(
        self,
        ref: str,
        *,
        field: Optional[str] = None,
        dimensions: Optional[Mapping[str, str]] = None,
        wait: bool = True,
        timeout_ms: Optional[int] = None,
        on_progress: Optional[ProgressCallback] = None,
    ) -> SecretFile:
        """**[B]** Reads an attachment or a typed key as bytes; see
        :meth:`tsm.aio.Client.get_file`."""
        return self._run(
            lambda c: c.get_file(
                ref,
                field=field,
                dimensions=dimensions,
                wait=wait,
                timeout_ms=timeout_ms,
                on_progress=on_progress,
            )
        )

    def _ensure(self) -> "tuple[asyncio.AbstractEventLoop, aio.Client]":
        with self._lock:
            if self._loop is None or self._pid != os.getpid():
                # A new process (after fork) or the first call: a loop and a
                # client of its own; the parent's socket is never used.
                loop = asyncio.new_event_loop()
                ready = threading.Event()

                def serve() -> None:
                    asyncio.set_event_loop(loop)
                    loop.call_soon(ready.set)
                    loop.run_forever()
                    loop.close()

                threading.Thread(
                    target=serve, name="tsm-client", daemon=True
                ).start()
                ready.wait()
                self._loop = loop
                self._client = aio.Client(**self._options)
                self._pid = os.getpid()
            assert self._client is not None
            return self._loop, self._client

    def _run(self, call: "Any") -> Any:
        loop, client = self._ensure()
        coroutine: Coroutine[Any, Any, T] = call(client)
        return asyncio.run_coroutine_threadsafe(coroutine, loop).result()
