# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The reference grammar (protocol.md section 4): parse and format."""

from __future__ import annotations

import dataclasses
import re
from typing import List, Sequence, Tuple, Union

from .errors import ErrorKind, SecretsError

#: The field a reference without ``#field`` names.
DEFAULT_FIELD = "Password"
#: The longest reference, in bytes of UTF-8 as sent.
MAX_REFERENCE_BYTES = 1024

_RESERVED = "/#[],:%"
_NAME = re.compile(r"[a-z][a-z0-9_-]*")
_STORE = re.compile(r"[a-z0-9][a-z0-9_-]*")
_UUID = re.compile(r"~[0-9A-Fa-f]{32}")
_HEX_PAIR = re.compile(r"[0-9a-fA-F]{2}")


def _is_control(rune: int) -> bool:
    return rune < 0x20 or rune == 0x7F


def _utf8(text: str) -> bytes:
    # A lone surrogate (possible in a Python string, never in valid UTF-8)
    # counts as the three bytes of U+FFFD, as other runtimes write it.
    return text.encode("utf-8", "replace")


def _malformed(reason: str, detail: str = "") -> SecretsError:
    message = f"the reference is malformed: {reason}"
    if detail:
        message += f" ({detail})"
    return SecretsError(ErrorKind.MALFORMED, message, {"reason": reason})


@dataclasses.dataclass(frozen=True)
class KeyTarget:
    """A key: the value of an entry's ``tsm.key`` field
    (``telegram.bot_token``)."""

    key: str
    kind: str = dataclasses.field(default="key", init=False)


@dataclasses.dataclass(frozen=True)
class PathTarget:
    """A path: a store, the group path below its root group and the entry
    title, each segment unescaped."""

    store: str
    segments: Tuple[str, ...]
    kind: str = dataclasses.field(default="path", init=False)


@dataclasses.dataclass(frozen=True)
class UuidTarget:
    """An entry of a store by its KDBX UUID (lower case)."""

    store: str
    uuid: str
    kind: str = dataclasses.field(default="uuid", init=False)


SecretTarget = Union[KeyTarget, PathTarget, UuidTarget]


@dataclasses.dataclass(frozen=True)
class SecretBinding:
    """One binding ``<dimension>:<value>`` of a reference's qualifiers."""

    dimension: str
    value: str


@dataclasses.dataclass(frozen=True)
class SecretReference:
    """A parsed reference. :meth:`parse` refuses a malformed one with a
    :class:`SecretsError` of kind ``MALFORMED`` whose ``reason`` is the rule
    of protocol.md 4.6 it broke; :meth:`format` gives the canonical form
    (4.5)."""

    target: SecretTarget
    qualifiers: Tuple[SecretBinding, ...] = ()
    field: str = DEFAULT_FIELD
    field_given: bool = False

    @property
    def canonical(self) -> str:
        """The canonical form."""
        return SecretReference.format(self)

    def __str__(self) -> str:
        return self.canonical

    @staticmethod
    def parse(reference: str) -> "SecretReference":
        """Parses ``reference`` (protocol.md 4.1-4.4, 4.6)."""
        if len(_utf8(reference)) > MAX_REFERENCE_BYTES:
            raise _malformed("too_long")
        if reference == "":
            raise _malformed("empty")
        rest = reference
        qualifiers: List[SecretBinding] = []
        if rest.startswith("["):
            end = rest.find("]")
            if end < 0:
                raise _malformed("unclosed_qualifiers")
            body = rest[1:end]
            rest = rest[end + 1 :]
            if body == "":
                raise _malformed("empty_segment", "[]")
            seen = set()
            for binding in body.split(","):
                parts = binding.split(":")
                if len(parts) != 2:
                    raise _malformed("bad_binding", binding)
                name, value = parts
                if not _NAME.fullmatch(name):
                    raise _malformed("bad_dimension", name)
                if name in seen:
                    raise _malformed("duplicate_dimension", name)
                seen.add(name)
                qualifiers.append(SecretBinding(name, _decode_segment(value)))
        if len(rest.split("#")) > 2:
            raise _malformed("reserved_character", "#")
        hash_at = rest.find("#")
        field_given = hash_at >= 0
        target_text = rest[:hash_at] if field_given else rest
        if target_text == "":
            raise _malformed("empty_target")
        field = (
            _decode_segment(rest[hash_at + 1 :]) if field_given else DEFAULT_FIELD
        )
        target: SecretTarget
        if "/" not in target_text:
            if not all(_NAME.fullmatch(p) for p in target_text.split(".")):
                raise _malformed("bad_key", target_text)
            target = KeyTarget(target_text)
        else:
            parts = target_text.split("/")
            store = parts[0]
            if not _STORE.fullmatch(store):
                raise _malformed("bad_store", store)
            raw = parts[1:]
            if len(raw) == 1 and raw[0].startswith("~"):
                if not _UUID.fullmatch(raw[0]):
                    raise _malformed("bad_uuid", raw[0])
                target = UuidTarget(store, raw[0][1:].lower())
            else:
                segments: List[str] = []
                for segment in raw:
                    if segment == "":
                        raise _malformed("empty_segment")
                    if segment[0] in "@~":
                        raise _malformed("reserved_prefix", segment[0])
                    segments.append(_decode_segment(segment))
                target = PathTarget(store, tuple(segments))
        return SecretReference(target, tuple(qualifiers), field, field_given)

    @staticmethod
    def format(reference: "SecretReference") -> str:
        """The canonical text of ``reference``: bindings sorted by dimension
        name (by UTF-8 bytes), every segment escaped in exactly what it must
        be, the uuid in lower case, the field omitted when it is
        ``Password``."""
        out = ""
        bindings = sorted(reference.qualifiers, key=lambda b: _utf8(b.dimension))
        if bindings:
            if len({b.dimension for b in bindings}) != len(bindings):
                raise ValueError("a dimension is bound once")
            out += (
                "["
                + ",".join(
                    f"{b.dimension}:{_encode_segment(b.value)}" for b in bindings
                )
                + "]"
            )
        target = reference.target
        if isinstance(target, KeyTarget):
            out += target.key
        elif isinstance(target, UuidTarget):
            out += f"{target.store}/~{target.uuid.lower()}"
        else:
            out += target.store + "/" + "/".join(
                _encode_segment(s, path=True) for s in target.segments
            )
        if reference.field != DEFAULT_FIELD:
            out += "#" + _encode_segment(reference.field)
        return out


def _decode_segment(raw: str) -> str:
    if raw == "":
        raise _malformed("empty_segment")
    data = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        rune = ord(ch)
        if ch == "%":
            pair = raw[i + 1 : i + 3]
            if not _HEX_PAIR.fullmatch(pair):
                raise _malformed("bad_escape", f"%{pair}")
            data.append(int(pair, 16))
            i += 3
            continue
        if ch in _RESERVED:
            raise _malformed("reserved_character", ch)
        if _is_control(rune):
            raise _malformed("control_character", f"U+{rune:04X}")
        data += _utf8(ch)
        i += 1
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError as e:
        raise _malformed("bad_utf8", str(e)) from None


def _encode_segment(text: str, path: bool = False) -> str:
    if text == "":
        raise ValueError("a segment is never empty")
    out = []
    for index, ch in enumerate(text):
        if (
            ch in _RESERVED
            or _is_control(ord(ch))
            or (path and index == 0 and ch in "@~")
        ):
            out.append("".join(f"%{b:02X}" for b in _utf8(ch)))
        else:
            out.append(ch)
    return "".join(out)


def parse(reference: str) -> SecretReference:
    """Parses ``reference``; see :meth:`SecretReference.parse`."""
    return SecretReference.parse(reference)


def format_reference(reference: SecretReference) -> str:
    """The canonical text; see :meth:`SecretReference.format`."""
    return SecretReference.format(reference)


def path_target(store: str, segments: Sequence[str]) -> PathTarget:
    """A :class:`PathTarget` of ``segments``."""
    return PathTarget(store, tuple(segments))
