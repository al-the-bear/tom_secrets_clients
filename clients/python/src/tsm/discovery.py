# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Finding the service (protocol.md section 3)."""

from __future__ import annotations

import dataclasses
import os
import re
import sys
from typing import Callable, Mapping, Optional, Union


@dataclasses.dataclass(frozen=True)
class Endpoints:
    """The runtime directory and its endpoint files: the Unix domain sockets
    on Linux and macOS, the port and token files on Windows."""

    directory: str
    client_socket: Optional[str] = None
    admin_socket: Optional[str] = None
    client_port_file: Optional[str] = None
    client_token_file: Optional[str] = None
    admin_port_file: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class NoRuntimeDirectory:
    """No runtime directory can be named (Windows without ``LOCALAPPDATA``
    and ``USERPROFILE``): the service is ``not_running``."""

    reason: str = "no_runtime_directory"


Location = Union[Endpoints, NoRuntimeDirectory]


def current_operating_system() -> str:
    """``linux``, ``macos`` or ``windows``, as the rules name this
    process's."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _strip(path: str, windows: bool) -> str:
    end = len(path)
    while end > 0 and (path[end - 1] == "/" or (windows and path[end - 1] == "\\")):
        end -= 1
    return path if end == 0 else path[:end]


def _uid() -> Optional[int]:
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else None


def discover(
    operating_system: str,
    environment: Mapping[str, str],
    uid: Callable[[], Optional[int]] = _uid,
) -> Location:
    """The location of the service (3.1) for ``operating_system`` (others
    than ``macos`` and ``windows`` are treated as ``linux``),
    ``environment`` and the numeric user id (needed only for the
    ``/tmp/tsm-<uid>`` fallback)."""
    windows = operating_system == "windows"
    override = environment.get("TSM_RUNTIME_DIR") or ""
    if override:
        directory = _strip(override, windows)
    elif windows:
        local = environment.get("LOCALAPPDATA") or ""
        profile = environment.get("USERPROFILE") or ""
        if local:
            base = _strip(local, True)
        elif profile:
            base = _strip(profile, True) + "\\AppData\\Local"
        else:
            return NoRuntimeDirectory()
        directory = base + "\\TomSecretsManager\\run"
    else:
        variable = "TMPDIR" if operating_system == "macos" else "XDG_RUNTIME_DIR"
        value = environment.get(variable) or ""
        directory = (
            _strip(value, False) + "/tsm"
            if value.startswith("/")
            else f"/tmp/tsm-{uid()}"
        )
    if windows:
        return Endpoints(
            directory=directory,
            client_port_file=directory + "\\client.port",
            client_token_file=directory + "\\client.token",
            admin_port_file=directory + "\\admin.port",
        )
    return Endpoints(
        directory=directory,
        client_socket=directory + "/client.sock",
        admin_socket=directory + "/admin.sock",
    )


def strip_line_end(text: str) -> str:
    """``text`` without one trailing LF or CR LF."""
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


_PORT = re.compile(r"[1-9][0-9]{0,4}")


def read_port_file(text: str) -> Optional[int]:
    """The port of a port file's ``text`` (decimal 1-65535, no sign or
    leading zero, at most one trailing LF or CR LF), or None when
    unreadable."""
    body = strip_line_end(text)
    if not _PORT.fullmatch(body):
        return None
    port = int(body)
    return port if port <= 65535 else None
