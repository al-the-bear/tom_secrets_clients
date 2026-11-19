# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The conformance runner of the Python client (tom-secrets-client).

Reads one case per line on standard input,
  {"case": name, "runtimeDir": dir, "action": {...}}
runs its action with the library's blocking client against the service in
runtimeDir, and writes one canonical result line per case on standard
output,
  {"case": name, "result": {...}}
(keys sorted, compact). conformance/README.md defines the actions and the
result shapes every runner writes. ``concurrent`` actions run on threads,
overlapping on the client's one connection.
"""

import base64
import datetime
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
        "clients", "python", "src",
    ),
)

import tsm  # noqa: E402

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _ms(moment):
    return (moment - _EPOCH) // datetime.timedelta(milliseconds=1)


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        result = run_case(request["runtimeDir"], request["action"])
        sys.stdout.write(canonical({"case": request["case"], "result": result}) + "\n")
        sys.stdout.flush()


def run_case(runtime_dir, action):
    options = action.get("client") or {}
    token = options.get("clientToken")
    client = tsm.Client(
        client_name="conformance-runner",
        client_token=token if isinstance(token, str) else None,
        environment={**os.environ, "TSM_RUNTIME_DIR": runtime_dir},
        connect_timeout=5.0,
    )
    try:
        return run(client, action)
    finally:
        client.close()


def run(client, action):
    do = action.get("do")
    if do == "parse":
        def body():
            r = tsm.SecretReference.parse(action["ref"])
            return {"parsed": shape(r), "canonical": r.canonical}
        return guard(body)
    if do == "format":
        return guard(lambda: {
            "formatted": tsm.SecretReference.format(from_shape(action["parsed"]))
        })
    if do == "connect":
        def body():
            client.open()
            w = client.welcome
            return {"welcome": {
                "host": w.host, "platform": w.platform,
                "features": sorted(w.features),
            }}
        return guard(body)
    if do == "get":
        progress = []

        def body():
            v = client.get(
                action["ref"],
                field=action.get("field"),
                dimensions=action.get("dimensions"),
                wait=action.get("wait", True) is not False,
                timeout_ms=action.get("timeoutMs"),
                want_client_token=action.get("wantClientToken") is True,
                wait_on_rate_limit=action.get("waitOnRateLimit") is True,
                on_progress=lambda p: progress.append(progress_shape(p)),
            )
            return {"value": value_shape(v)}
        result = guard(body)
        return {**result, "progress": progress} if progress else result
    if do == "getMany":
        progress = []

        def body():
            requests = [
                tsm.SecretRequest(r["ref"], r.get("field"), r.get("dimensions"))
                for r in action["refs"]
            ]
            results = client.get_many(
                requests,
                wait=action.get("wait", True) is not False,
                timeout_ms=action.get("timeoutMs"),
                on_progress=lambda p: progress.append(progress_shape(p)),
            )
            return {"results": [
                {"value": value_shape(r.value)} if r.value is not None
                else {"error": error_shape(r.error)}
                for r in results
            ]}
        result = guard(body)
        return {**result, "progress": progress} if progress else result
    if do == "getFile":
        def body():
            f = client.get_file(action["ref"], field=action.get("field"))
            with f:
                return {"file": {
                    "name": f.name, "size": f.size,
                    "base64": base64.b64encode(bytes(f.data)).decode("ascii"),
                }}
        return guard(body)
    if do == "concurrent":
        actions = action["actions"]
        with ThreadPoolExecutor(max_workers=max(1, len(actions))) as pool:
            return {"results": list(pool.map(lambda a: run(client, a), actions))}
    if do == "sequence":
        steps = []
        for step in action["actions"]:
            if step.get("do") == "pause":
                time.sleep(step["ms"] / 1000)
                continue
            steps.append(run(client, step))
        return {"steps": steps}
    return {"unsupportedAction": do}


def guard(body):
    try:
        return body()
    except tsm.SecretsError as e:
        return {"error": error_shape(e)}


def error_shape(e):
    out = {"kind": e.kind.value}
    if e.reason is not None:
        out["reason"] = e.reason
    return out


def progress_shape(p):
    out = {"pending": p.pending}
    if p.approval_code is not None:
        out["approvalCode"] = p.approval_code
    return out


def value_shape(v):
    text = None
    refused = False
    try:
        text = v.text
    except ValueError:
        refused = True
    printed = [str(v), repr(v), f"{v}", "%s" % v]
    out = {
        "encoding": v.encoding,
        "base64": base64.b64encode(bytes(v.data)).decode("ascii"),
        "entry": {
            "store": v.entry.store,
            "uuid": v.entry.uuid,
            "source": v.entry.source,
            "fetchedAtMs": _ms(v.entry.fetched_at),
        },
        "bound": dict(v.bound),
        "version": {
            "modifiedMs": _ms(v.version.modified),
            "revision": v.version.revision,
        },
        # Every printable form shows *** and never the value (README,
        # Results); a value that occurs in the reference cannot be told apart.
        "masked": all(
            "***" in p and (text is None or text in v.reference or text not in p)
            for p in printed
        ),
    }
    if text is not None:
        out["text"] = text
    if refused:
        out["textRefused"] = True
    if v.expires is not None:
        out["expiresMs"] = _ms(v.expires)
    if v.client_token is not None:
        out["clientToken"] = v.client_token
    v.close()
    return out


def shape(r):
    t = r.target
    if isinstance(t, tsm.KeyTarget):
        target = {"kind": "key", "key": t.key}
    elif isinstance(t, tsm.UuidTarget):
        target = {"kind": "uuid", "store": t.store, "uuid": t.uuid}
    else:
        target = {"kind": "path", "store": t.store, "segments": list(t.segments)}
    return {
        "qualifiers": [
            {"dimension": q.dimension, "value": q.value} for q in r.qualifiers
        ],
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


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


if __name__ == "__main__":
    main()
