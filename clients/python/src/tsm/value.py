# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""What a ``get`` answers (protocol.md 5.2), what a ``getFile`` answers
(5.5), and the progress notices of a waiting request (5.4)."""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime
import re
from typing import Any, Callable, Dict, Mapping, Optional

from .errors import ErrorKind, SecretsError

_DATE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:([Zz])|([+-])(\d{2}):(\d{2}))"
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def parse_time(text: Any) -> datetime.datetime:
    """An RFC 3339 time (``2026-11-13T09:00:00Z``, fractions and offsets
    allowed) as an aware UTC ``datetime``; ``TypeError`` otherwise."""
    if not isinstance(text, str):
        raise TypeError("not a date")
    m = _DATE.fullmatch(text)
    if m is None:
        raise TypeError("not a date")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    fraction = (m.group(7) or "")[:6].ljust(6, "0")
    if m.group(8):
        zone = datetime.timezone.utc
    else:
        offset = datetime.timedelta(hours=int(m.group(10)), minutes=int(m.group(11)))
        zone = datetime.timezone(offset if m.group(9) == "+" else -offset)
    try:
        moment = datetime.datetime(
            year, month, day, hour, minute, second, int(fraction), tzinfo=zone
        )
    except ValueError:
        raise TypeError("not a date") from None
    return moment.astimezone(datetime.timezone.utc)


def _record(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("not an object")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("not a string")
    return value


def source_from_wire(name: Any) -> str:
    """The source a protocol ``source`` names; an unknown one is ``cache``
    (section 8: the most general one known, no claim to be fresh)."""
    return name if name in ("github", "file") else "cache"


@dataclasses.dataclass(frozen=True)
class SecretEntry:
    """The entry a value was read from: its store and KDBX UUID, where the
    service read it (``github``, ``file`` or ``cache``), and the last
    successful fetch of the store."""

    store: str
    uuid: str
    source: str
    fetched_at: datetime.datetime


@dataclasses.dataclass(frozen=True)
class SecretVersion:
    """The entry's last modification and the store file revision it was read
    from; a caller caching a value compares it to see a change."""

    modified: datetime.datetime
    revision: str


class SecretValue:
    """A secret. Its printable forms (``str``, ``repr``) never show it, and
    :meth:`close` (also the end of a ``with`` block) overwrites its buffer.
    A ``text`` the caller takes out is an immutable Python string the library
    cannot overwrite: the caller handles it."""

    def __init__(
        self,
        reference: str,
        data: bytearray,
        encoding: str,
        entry: SecretEntry,
        bound: Mapping[str, str],
        version: SecretVersion,
        expires: Optional[datetime.datetime],
        client_token: Optional[str],
    ) -> None:
        #: The reference the value was asked for, as given.
        self.reference = reference
        #: How the service sent it: ``utf8`` (text) or ``base64`` (bytes).
        self.encoding = encoding
        #: The entry it was read from.
        self.entry = entry
        #: The bindings the winning entry carries, ``{dimension: value}``.
        self.bound: Mapping[str, str] = dict(bound)
        #: The entry's version.
        self.version = version
        #: The entry's expiry, when it has one.
        self.expires = expires
        #: The client token the service granted, when one was asked for: the
        #: caller's to keep (7.4); the library never stores it.
        self.client_token = client_token
        self._data = data
        self._closed = False

    @classmethod
    def from_message(cls, reference: str, m: Mapping[str, Any]) -> "SecretValue":
        """The value of a ``value`` message (or a ``values`` result)."""
        try:
            encoding = "base64" if m.get("encoding") == "base64" else "utf8"
            raw = _text(m.get("value"))
            entry = _record(m.get("entry"))
            version = _record(m.get("version"))
            bound: Dict[str, str] = {}
            if isinstance(m.get("bound"), dict):
                for k, v in m["bound"].items():
                    bound[k] = _text(v)
            if encoding == "base64":
                if not _BASE64.fullmatch(raw):
                    raise TypeError("not base64")
                data = bytearray(
                    base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
                )
            else:
                data = bytearray(raw.encode("utf-8", "replace"))
            expires = m.get("expires")
            client_token = m.get("clientToken")
            return cls(
                reference,
                data,
                encoding,
                SecretEntry(
                    _text(entry.get("store")),
                    _text(entry.get("uuid")),
                    source_from_wire(entry.get("source")),
                    parse_time(entry.get("fetchedAt")),
                ),
                bound,
                SecretVersion(
                    parse_time(version.get("modified")),
                    _text(version.get("revision")),
                ),
                parse_time(expires) if isinstance(expires, str) else None,
                client_token if isinstance(client_token, str) else None,
            )
        except (TypeError, ValueError, binascii.Error):
            raise SecretsError(
                ErrorKind.INTERNAL,
                "the service sent a value message this library cannot read",
                {"code": "bad_value"},
            ) from None

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    @property
    def text(self) -> str:
        """The value as text. A binary value (``base64``) is refused with a
        ``ValueError`` rather than decoded into a corrupt string."""
        self._check()
        if self.encoding == "base64":
            raise ValueError(
                f"the value of {self.reference} is binary: read it with data, "
                "not text"
            )
        return bytes(self._data).decode("utf-8")

    @property
    def data(self) -> memoryview:
        """The value as bytes (text as its UTF-8): a view of the buffer that
        :meth:`close` overwrites; copy it (``bytes(v.data)``) to keep it."""
        self._check()
        return memoryview(self._data)

    def close(self) -> None:
        """Overwrites the buffer with zeros; the value cannot be read
        afterwards."""
        for i in range(len(self._data)):
            self._data[i] = 0
        self._closed = True

    def __enter__(self) -> "SecretValue":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _check(self) -> None:
        if self._closed:
            raise ValueError(f"the value of {self.reference} was closed")

    def __str__(self) -> str:
        return f"SecretValue({self.reference}: ***)"

    def __repr__(self) -> str:
        return self.__str__()

    def __format__(self, spec: str) -> str:
        return format(self.__str__(), spec)


class SecretFile:
    """**[B]** An attachment or a typed key read with ``get_file``: its name
    and bytes. Its printable forms never show the bytes, and :meth:`close`
    overwrites them."""

    def __init__(self, reference: str, name: str, data: bytearray) -> None:
        #: The reference the file was asked for, as given.
        self.reference = reference
        #: The field's name (an attachment's file name).
        self.name = name
        self._data = data
        self._closed = False

    @property
    def size(self) -> int:
        """The size in bytes."""
        return len(self._data)

    @property
    def data(self) -> memoryview:
        """The bytes: a view of the buffer that :meth:`close` overwrites."""
        if self._closed:
            raise ValueError(f"the file of {self.reference} was closed")
        return memoryview(self._data)

    def close(self) -> None:
        """Overwrites the bytes with zeros."""
        for i in range(len(self._data)):
            self._data[i] = 0
        self._closed = True

    def __enter__(self) -> "SecretFile":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def __str__(self) -> str:
        return f"SecretFile({self.reference}: {self.name}, {self.size} bytes)"

    def __repr__(self) -> str:
        return self.__str__()


@dataclasses.dataclass(frozen=True)
class Progress:
    """A progress notice: why a request waits, ``unlock`` (the service is
    locked and an admin was told) or ``approval`` (the request went to
    approval), with the one-time approval code on a host with no approver
    connected (7.5)."""

    pending: str
    approval_code: Optional[str] = None


#: Receives the progress notices of a waiting request.
ProgressCallback = Callable[[Progress], None]


@dataclasses.dataclass(frozen=True)
class SecretRequest:
    """One reference of a ``get_many``: the reference, the field when the
    reference names none, and values for dimensions beside it."""

    ref: str
    field: Optional[str] = None
    dimensions: Optional[Mapping[str, str]] = None


@dataclasses.dataclass(frozen=True)
class SecretResult:
    """One result of a ``get_many``, in request order: a value or an
    error."""

    value: Optional[SecretValue] = None
    error: Optional[SecretsError] = None
