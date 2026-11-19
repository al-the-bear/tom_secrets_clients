# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The Python client of the Tom Secrets Manager's secrets service.

A program reads its secrets from the secrets service that runs for its user
on the same machine:

    import tsm

    with tsm.Client() as c:
        with c.get("[env:prod]db.main", field="UserName") as v:
            print(v.text)

``tsm.aio.Client`` is the same for asyncio. Every failure is a
:class:`SecretsError` with a ``kind`` (:class:`ErrorKind`). The library is
written from the protocol document (protocol.md) and uses only the standard
library.
"""

from . import aio
from ._version import __version__
from .aio import CLIENT_FEATURES, MAX_GET_MANY, PROTOCOL_VERSION, Welcome
from .client import Client
from .discovery import Endpoints, NoRuntimeDirectory, discover
from .errors import ErrorKind, SecretsError
from .reference import (
    DEFAULT_FIELD,
    KeyTarget,
    PathTarget,
    SecretBinding,
    SecretReference,
    UuidTarget,
)
from .value import (
    Progress,
    SecretEntry,
    SecretFile,
    SecretRequest,
    SecretResult,
    SecretValue,
    SecretVersion,
)

__all__ = [
    "CLIENT_FEATURES",
    "Client",
    "DEFAULT_FIELD",
    "Endpoints",
    "ErrorKind",
    "KeyTarget",
    "MAX_GET_MANY",
    "NoRuntimeDirectory",
    "PROTOCOL_VERSION",
    "PathTarget",
    "Progress",
    "SecretBinding",
    "SecretEntry",
    "SecretFile",
    "SecretReference",
    "SecretRequest",
    "SecretResult",
    "SecretValue",
    "SecretVersion",
    "SecretsError",
    "UuidTarget",
    "Welcome",
    "__version__",
    "aio",
    "discover",
]
