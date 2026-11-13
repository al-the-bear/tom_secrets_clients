#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The conformance driver of the Tom Secrets Manager's client libraries.

    python3 conformance/tool/conformance.py run [--runner LANG]... [--table T]...
                                               [--case NAME] [--strict]
    python3 conformance/tool/conformance.py gen [--check]
    python3 conformance/tool/conformance.py coverage
    python3 conformance/tool/conformance.py parity [--table T --from RE --to TEXT]
    python3 conformance/tool/conformance.py all     (self-test, gen --check, coverage,
                                                     run --strict)

- `run` builds the fake service and every runner (runners/<lang>/runner.json),
  and for every case of every table starts the fake service with the case's
  script in a fresh runtime directory, hands the case to the runner, and
  compares the runner's result line with the expected one and the frames the
  fake service recorded with the expected frames; every recorded frame is
  validated against the protocol's JSON Schemas. A runner whose toolchain is
  missing is NOT MEASURED, never passed (`--strict` makes that a failure).
- `gen` writes cases/references.json from protocol/vectors/references.json
  (`--check`: fails when it is not what gen writes now).
- `coverage` is the enum-coverage gate: every error kind and every message of
  the client endpoint appears in some case.
- `parity` breaks one expectation and one case input and requires every
  runner to go red on each: proof that every runner runs the tables.

Exit 0 when everything holds. Python 3.9+, with `jsonschema` (4.18+ uses
`referencing`; an older one its `RefResolver`) for the schema validation.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import queue
import re
import shutil
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROTOCOL = ROOT.parent / 'protocol'
CASES = ROOT / 'cases'
EXE = '.exe' if os.name == 'nt' else ''
PLATFORM = {'win32': 'windows', 'darwin': 'macos'}.get(sys.platform, 'linux')
FAKE = f'ztmp/bin/fake_service{EXE}'
GENERATED = 'references.json'

# Client-endpoint messages no library call produces, with why.
NOT_A_LIBRARY_CALL = {
    'match': 'phase B; only the browser host and the helpers ask it (5.5)',
    'matches': 'the answer to match',
    'propose': 'phase B; only the browser host sends it (5.5)',
    'accepted': 'the answer to propose',
}


# --------------------------------------------------------------------------
# Case tables
# --------------------------------------------------------------------------

def load_tables(names: list[str] | None = None) -> dict[str, list[dict]]:
    tables = {}
    for path in sorted(CASES.glob('*.json')):
        if names and path.stem not in names and path.name not in names:
            continue
        data = json.loads(path.read_text(encoding='utf-8'))
        tables[path.stem] = data['cases']
    return tables


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def subset(pattern, actual) -> bool:
    """`pattern` is contained in `actual`: objects by member (`"$absent"`
    requires a member to be missing), lists element by element and of equal
    length, `"$any"` matches anything."""
    if pattern == '$any':
        return True
    if isinstance(pattern, dict):
        if not isinstance(actual, dict):
            return False
        for key, want in pattern.items():
            if want == '$absent':
                if key in actual:
                    return False
            elif key not in actual or not subset(want, actual[key]):
                return False
        return True
    if isinstance(pattern, list):
        return (isinstance(actual, list) and len(pattern) == len(actual)
                and all(subset(p, a) for p, a in zip(pattern, actual)))
    return pattern == actual


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

def schema_validator():
    from jsonschema import Draft202012Validator
    schemas = {p.stem: json.loads(p.read_text()) for p in (PROTOCOL / 'schema').glob('*.json')}
    try:
        from referencing import Registry, Resource
        registry = Registry().with_resources(
            (s['$id'], Resource.from_contents(s)) for s in schemas.values())
        options = {'registry': registry}
    except ImportError:
        # jsonschema before 4.18 (e.g. Debian's 4.10) has no `referencing`.
        from jsonschema import RefResolver
        store = {s['$id']: s for s in schemas.values()}
        options = {'resolver_for': lambda schema: RefResolver.from_schema(schema, store=store)}

    def validate(message: dict) -> list[str]:
        op = message.get('op')
        schema = schemas.get(op)
        if schema is None:
            return [f'no schema for op {op!r}']
        meta = schema['x-tsm']
        problems = []
        if meta['endpoint'] not in ('client', 'any') or meta['direction'] != 'c2s':
            problems.append(f'{op} is not a message a client sends')
        validator = (Draft202012Validator(schema, registry=options['registry'])
                     if 'registry' in options
                     else Draft202012Validator(schema, resolver=options['resolver_for'](schema)))
        problems += [f'{op}{e.json_path[1:]}: {e.message}' for e in validator.iter_errors(message)]
        return problems
    return validate, schemas


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------

def command(cmd: list[str]) -> list[str]:
    return [c.replace('{exe}', EXE) for c in cmd]


def run_quiet(cmd: list[str]) -> tuple[bool, str]:
    try:
        done = subprocess.run(command(cmd), cwd=ROOT, capture_output=True, text=True,
                              shell=os.name == 'nt')
    except OSError as e:
        return False, str(e)
    return done.returncode == 0, done.stdout + done.stderr


class Lines:
    """The lines a process writes, read on a thread, with a timeout."""

    def __init__(self, stream):
        self.queue: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, args=(stream,), daemon=True).start()

    def _pump(self, stream):
        for line in stream:
            self.queue.put(line.rstrip('\r\n'))
        self.queue.put(None)

    def next(self, timeout: float) -> str | None:
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None


_BUILT: dict[str, tuple[list[str], set[str]]] = {}
_FAKE_BUILT = []


def build(runners: list[str]) -> tuple[dict, list[str]]:
    """Builds the fake service and the runners (once per process); answers
    {lang: (run command, supported actions)} and the not-measured notes."""
    (ROOT / 'ztmp' / 'bin').mkdir(parents=True, exist_ok=True)
    notes = []
    ok, out = run_quiet(['dart', '--version'])
    if not ok:
        return {}, ['the fake service needs Dart, which is not installed: nothing measured']
    for step in ([] if _FAKE_BUILT else
                 (['dart', 'pub', 'get', '--directory', 'fake_service'],
                  ['dart', 'compile', 'exe', 'fake_service/bin/fake_service.dart', '-o', FAKE])):
        ok, out = run_quiet(step)
        if not ok:
            raise SystemExit(f'building the fake service failed:\n{out}')
    _FAKE_BUILT.append(True)
    commands = {}
    for lang in runners:
        if lang in _BUILT:
            commands[lang] = _BUILT[lang]
            continue
        spec = json.loads((ROOT / 'runners' / lang / 'runner.json').read_text())
        ok, _ = run_quiet(spec['toolchain'])
        if not ok:
            notes.append(f'{lang}: NOT MEASURED (no toolchain: {" ".join(spec["toolchain"])})')
            continue
        for step in spec['build']:
            ok, out = run_quiet(step)
            if not ok:
                raise SystemExit(f'building the {lang} runner failed:\n{out}')
        commands[lang] = _BUILT[lang] = (command(spec['run']), set(spec['actions']))
    return commands, notes


def all_runners() -> list[str]:
    return sorted(p.parent.name for p in (ROOT / 'runners').glob('*/runner.json'))


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

def run_case(runner, lines: Lines, case: dict, index: int, validate) -> list[str]:
    runtime = f'ztmp/rt/{index}'
    rt = ROOT / runtime
    shutil.rmtree(rt, ignore_errors=True)
    rt.mkdir(parents=True)
    fake = None
    if not case.get('noService'):
        (rt / 'script.json').write_text(json.dumps(case.get('script', {})), encoding='utf-8')
        cmd = [str(ROOT / FAKE), '--dir', runtime, '--script', f'{runtime}/script.json',
               '--record', f'{runtime}/record.json']
        if case.get('transport'):
            cmd += ['--transport', case['transport']]
        fake = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                text=True)
        if Lines(fake.stdout).next(30) != 'ready':
            fake.kill()
            return ['the fake service did not start']
    problems = []
    try:
        runner.stdin.write(json.dumps({'case': case['name'], 'runtimeDir': runtime,
                                       'action': case['action']}) + '\n')
        runner.stdin.flush()
        line = lines.next(60)
    except (BrokenPipeError, OSError) as e:
        line = None
        problems.append(f'the runner is gone: {e}')
    record = {'connections': 0, 'received': []}
    if fake is not None:
        fake.stdin.close()
        try:
            fake.wait(30)
        except subprocess.TimeoutExpired:
            fake.kill()
        if (rt / 'record.json').exists():
            record = json.loads((rt / 'record.json').read_text(encoding='utf-8'))
    if line is None:
        return problems or ['no result line from the runner']
    try:
        answer = json.loads(line)
    except json.JSONDecodeError:
        return [f'not a result line: {line[:200]}']
    if answer.get('case') != case['name']:
        problems.append(f'result line for {answer.get("case")!r}')
    expect = case['expect']
    if canonical(answer.get('result')) != canonical(expect['result']):
        problems.append(f'result {canonical(answer.get("result"))}\n'
                        f'      expected {canonical(expect["result"])}')
    received = [r.get('message', {'invalid': r.get('invalid')}) for r in record['received']]
    if 'sent' in expect and not subset(expect['sent'], received):
        problems.append(f'sent {canonical(received)}\n      expected {canonical(expect["sent"])}')
    sent_ops = {m.get('op') for m in received}
    for op in expect.get('notSent', []):
        if op in sent_ops:
            problems.append(f'the client sent {op}, which it must refuse locally')
    if 'connections' in expect and record['connections'] != expect['connections']:
        problems.append(f'{record["connections"]} connections, expected {expect["connections"]}')
    for i, message in enumerate(received):
        if 'invalid' in message and len(message) == 1:
            problems.append(f'frame {i} sent by the client is invalid: {message["invalid"]}')
            continue
        problems += [f'frame {i}: {p}' for p in validate(message)]
    shutil.rmtree(rt, ignore_errors=True)
    return problems


def cmd_run(args) -> int:
    validate, _ = schema_validator()
    runners = args.runner or all_runners()
    commands, notes = build(runners)
    tables = load_tables(args.table)
    failures = 0
    summary = []
    for lang in runners:
        if lang not in commands:
            continue
        run_command, supported = commands[lang]
        runner = subprocess.Popen(run_command, cwd=ROOT, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, encoding='utf-8')
        lines = Lines(runner.stdout)
        passed = failed = skipped = unsupported = 0
        index = 0
        for table, cases in tables.items():
            for case in cases:
                if args.case and case['name'] != args.case:
                    continue
                platforms = case.get('platforms')
                if platforms and PLATFORM not in platforms:
                    skipped += 1
                    if args.verbose:
                        print(f'  skip  {lang} {table}: {case["name"]} (only {", ".join(platforms)})')
                    continue
                used = {n['do'] for n in walk(case['action'])
                        if isinstance(n, dict) and 'do' in n} - {'pause'}
                if used - supported:
                    unsupported += 1
                    print(f'  n/a   {lang} {table}: {case["name"]} (the library has no '
                          f'{", ".join(sorted(used - supported))})')
                    continue
                index += 1
                problems = run_case(runner, lines, case, index, validate)
                if problems:
                    failed += 1
                    print(f'  FAIL  {lang} {table}: {case["name"]}')
                    for p in problems:
                        print(f'        {p}')
                else:
                    passed += 1
                    if args.verbose:
                        print(f'  ok    {lang} {table}: {case["name"]}')
        runner.stdin.close()
        runner.wait(30)
        failures += failed
        summary.append(f'{lang}: {passed} passed, {failed} failed, {skipped} not for '
                       f'{PLATFORM}, {unsupported} not offered by the library')
    shutil.rmtree(ROOT / 'ztmp' / 'rt', ignore_errors=True)
    for line in summary + notes:
        print(line)
    unmeasured = len(notes) > 0
    ok = failures == 0 and not (unmeasured and args.strict) and commands
    print('CONFORMANCE ' + ('GREEN' if ok else 'RED') +
          (' (some runners NOT MEASURED)' if unmeasured else ''))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# gen: the reference table from the protocol's vectors
# --------------------------------------------------------------------------

def references_table() -> dict:
    vectors = json.loads((PROTOCOL / 'vectors' / 'references.json').read_text(encoding='utf-8'))
    cases = []
    for c in vectors['valid']:
        cases.append({'name': f'parse {c["input"][:60]}', 'noService': True,
                      'action': {'do': 'parse', 'ref': c['input']},
                      'expect': {'result': {'parsed': c['parsed'], 'canonical': c['canonical']}}})
    for c in vectors['invalid']:
        cases.append({'name': f'refuse {c["input"][:60]} ({c["reason"]})', 'noService': True,
                      'action': {'do': 'parse', 'ref': c['input']},
                      'expect': {'result': {'error': {'kind': 'malformed',
                                                      'reason': c['reason']}}}})
    for c in vectors['format']:
        cases.append({'name': f'format {c["formatted"][:60]}', 'noService': True,
                      'action': {'do': 'format', 'parsed': c['parsed']},
                      'expect': {'result': {'formatted': c['formatted']}}})
    return {'note': 'Generated by tool/conformance.py gen from protocol/vectors/references.json; '
                    'do not edit.', 'cases': cases}


def cmd_gen(args) -> int:
    text = json.dumps(references_table(), indent=1, ensure_ascii=False) + '\n'
    path = CASES / GENERATED
    if args.check:
        if not path.exists() or path.read_text(encoding='utf-8') != text:
            print(f'{path.name} is not what gen writes now')
            return 1
        print(f'{path.name} current')
        return 0
    path.write_text(text, encoding='utf-8')
    print(f'wrote {path}')
    return 0


# --------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------

def walk(value):
    yield value
    if isinstance(value, dict):
        for v in value.values():
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)


def cmd_coverage(args) -> int:
    _, schemas = schema_validator()
    tables = load_tables()
    kinds_seen, sent_ops, served_ops, actions = set(), set(), set(), set()
    for cases in tables.values():
        for case in cases:
            for node in walk(case['expect']['result']):
                if isinstance(node, dict) and isinstance(node.get('error'), dict):
                    kinds_seen.add(node['error'].get('kind'))
            for pattern in case['expect'].get('sent', []):
                if isinstance(pattern, dict) and 'op' in pattern:
                    sent_ops.add(pattern['op'])
            script = case.get('script', {})
            if not case.get('noService'):
                served_ops.add('welcome')
            for node in walk(script):
                if isinstance(node, dict):
                    if isinstance(node.get('send'), dict):
                        served_ops.add(node['send'].get('op'))
                    if 'file' in node and isinstance(node['file'], dict):
                        served_ops.update({'file', 'end'})
            for node in walk(case['action']):
                if isinstance(node, dict) and 'do' in node:
                    actions.add(node['do'])
    problems = []
    kinds = set(schemas['common']['$defs']['errorKind']['enum']) | {'not_running'}
    for kind in sorted(kinds - kinds_seen):
        problems.append(f'no case expects the error kind {kind}')
    for op, schema in sorted(schemas.items()):
        meta = schema.get('x-tsm', {})
        if meta.get('endpoint') not in ('client', 'any'):
            continue
        if op in NOT_A_LIBRARY_CALL:
            print(f'  not covered by design: {op} — {NOT_A_LIBRARY_CALL[op]}')
            continue
        seen = sent_ops if meta['direction'] == 'c2s' else served_ops
        if op not in seen:
            problems.append(f'no case {"sends" if meta["direction"] == "c2s" else "serves"} {op}')
    for action in ('connect', 'get', 'getMany', 'getFile', 'parse', 'format',
                   'concurrent', 'sequence'):
        if action not in actions:
            problems.append(f'no case uses the action {action}')
    for p in problems:
        print('FAIL', p)
    print(f'coverage: {len(kinds_seen & kinds)}/{len(kinds)} error kinds, '
          f'{sum(len(c) for c in tables.values())} cases: {"OK" if not problems else "RED"}')
    return 1 if problems else 0


# --------------------------------------------------------------------------
# parity
# --------------------------------------------------------------------------

DEFAULT_MUTATIONS = [
    # An expectation: the value a case expects.
    ('get', r'"text": "demo-password-1"', '"text": "demo-password-2"'),
    # An input: the value the fake service sends (the expectation unchanged).
    ('get', r'"value": "demo-password-1"', '"value": "demo-password-9"'),
]


def cmd_parity(args) -> int:
    mutations = ([(args.table, args.from_, args.to)] if args.from_ else DEFAULT_MUTATIONS)
    runners = args.runner or all_runners()
    stayed_green = []
    for table, pattern, replacement in mutations:
        path = CASES / f'{table}.json'
        original = path.read_text(encoding='utf-8')
        hits = len(re.findall(pattern, original))
        if hits != 1:
            print(f'{table}: the mutation {pattern!r} matches {hits} times, not once')
            return 2
        try:
            path.write_text(re.sub(pattern, replacement, original), encoding='utf-8')
            for lang in runners:
                ns = argparse.Namespace(runner=[lang], table=[table], case=None, strict=True,
                                        verbose=False)
                with open(os.devnull, 'w') as sink:
                    saved = sys.stdout
                    sys.stdout = sink
                    try:
                        status = cmd_run(ns)
                    finally:
                        sys.stdout = saved
                verdict = 'red' if status != 0 else 'GREEN'
                print(f'  {lang} with {table}: {pattern} -> {replacement}: {verdict}')
                if status == 0:
                    stayed_green.append(lang)
        finally:
            path.write_text(original, encoding='utf-8')
    print('PARITY ' + ('OK: every runner went red' if not stayed_green
                       else f'FAILED: {sorted(set(stayed_green))} stayed green'))
    return 0 if not stayed_green else 1


def cmd_all(args) -> int:
    import unittest
    suite = unittest.defaultTestLoader.loadTestsFromName('test_conformance')
    status = 0 if unittest.TextTestRunner(verbosity=0).run(suite).wasSuccessful() else 1
    status |= cmd_gen(argparse.Namespace(check=True))
    status |= cmd_coverage(args)
    status |= cmd_run(argparse.Namespace(runner=args.runner, table=None, case=None,
                                         strict=True, verbose=False))
    print('ALL ' + ('GREEN' if status == 0 else 'RED'))
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run')
    run.add_argument('--runner', action='append')
    run.add_argument('--table', action='append')
    run.add_argument('--case')
    run.add_argument('--strict', action='store_true')
    run.add_argument('--verbose', '-v', action='store_true')
    gen = sub.add_parser('gen')
    gen.add_argument('--check', action='store_true')
    sub.add_parser('coverage')
    parity = sub.add_parser('parity')
    parity.add_argument('--runner', action='append')
    parity.add_argument('--table')
    parity.add_argument('--from', dest='from_')
    parity.add_argument('--to')
    every = sub.add_parser('all')
    every.add_argument('--runner', action='append')
    args = parser.parse_args()
    return {'run': cmd_run, 'gen': cmd_gen, 'coverage': cmd_coverage,
            'parity': cmd_parity, 'all': cmd_all}[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
