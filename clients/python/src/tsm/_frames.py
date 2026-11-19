# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Frames and JSON payloads (protocol.md section 2)."""

from __future__ import annotations

import json
import math
import struct
from typing import Any, Dict, List, Tuple

#: Frame type of a JSON payload.
FRAME_JSON = 0
#: Frame type of a binary chunk ([B], 2.5).
FRAME_BINARY = 1
#: The largest payload of a frame sent to the service.
MAX_REQUEST_PAYLOAD = 64 * 1024
#: The largest payload of a frame sent by the service.
MAX_ANSWER_PAYLOAD = 1024 * 1024

Message = Dict[str, Any]


class FrameError(Exception):
    """A frame or payload that breaks section 2; the connection is closed."""


def json_payload(message: Message) -> bytes:
    """The compact UTF-8 JSON of ``message``, as the vectors write it."""
    return json.dumps(
        message, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def encode_frame(frame_type: int, payload: bytes) -> bytes:
    """A frame: the payload length (4 bytes big-endian), the type, the
    payload."""
    return struct.pack(">IB", len(payload), frame_type) + payload


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f'duplicate member "{name}"')
        out[name] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"bad value {name}")


def _number(text: str) -> Any:
    value = float(text)
    if math.isinf(value):
        raise ValueError("number out of range")
    return value


def parse_strict_json(text: str) -> Any:
    """Parses ``text`` strictly (2.3): one value, no duplicate member names,
    no ``NaN`` or ``Infinity``."""
    return json.loads(
        text,
        object_pairs_hook=_no_duplicates,
        parse_constant=_no_constant,
        parse_float=_number,
    )


def decode_payload(payload: bytes) -> Message:
    """The message of a JSON payload; a ``FrameError`` when it is malformed
    (2.2): empty, not UTF-8, starting with a byte order mark, not JSON, not
    an object, an object with a duplicate member name, or without a string
    ``op``."""
    if not payload:
        raise FrameError("empty payload")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise FrameError("payload is not UTF-8") from None
    if text.startswith("﻿"):
        raise FrameError("payload starts with a byte order mark")
    try:
        value = parse_strict_json(text)
    except (ValueError, RecursionError) as e:
        raise FrameError(f"payload is not JSON: {e}") from None
    if not isinstance(value, dict):
        raise FrameError("payload is not a JSON object")
    if not isinstance(value.get("op"), str):
        raise FrameError("payload has no op")
    return value


class FrameReader:
    """Splits a byte stream into frames, checking every length against
    ``max_payload`` before the payload is read and refusing a frame type that
    is neither JSON nor (with ``binary_allowed``) binary."""

    def __init__(self, max_payload: int) -> None:
        self.max_payload = max_payload
        self.binary_allowed = False
        self._pending = bytearray()

    def add(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Adds ``data`` and returns the frames now complete as
        ``(type, payload)``; raises ``FrameError``."""
        self._pending += data
        frames: List[Tuple[int, bytes]] = []
        offset = 0
        buffer = self._pending
        while len(buffer) - offset >= 5:
            length, frame_type = struct.unpack_from(">IB", buffer, offset)
            if length > self.max_payload:
                raise FrameError(
                    f"frame of {length} bytes over {self.max_payload}"
                )
            if frame_type != FRAME_JSON and not (
                frame_type == FRAME_BINARY and self.binary_allowed
            ):
                raise FrameError(f"frame type {frame_type}")
            if len(buffer) - offset - 5 < length:
                break
            frames.append(
                (frame_type, bytes(buffer[offset + 5 : offset + 5 + length]))
            )
            offset += 5 + length
        del self._pending[:offset]
        return frames
