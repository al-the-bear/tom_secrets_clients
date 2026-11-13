#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Self-test of the conformance driver's comparison rules.

    python3 conformance/tool/test_conformance.py
"""
import json
import unittest

import conformance as c


class Subset(unittest.TestCase):
    def test_members_and_absent(self):
        self.assertTrue(c.subset({'op': 'get'}, {'op': 'get', 'id': 3}))
        self.assertFalse(c.subset({'op': 'get'}, {'op': 'getMany'}))
        self.assertTrue(c.subset({'field': '$absent'}, {'op': 'get'}))
        self.assertFalse(c.subset({'field': '$absent'}, {'field': 'UserName'}))
        self.assertTrue(c.subset({'id': '$any'}, {'id': 9}))
        self.assertFalse(c.subset({'id': '$any'}, {}))

    def test_lists_have_equal_length(self):
        self.assertTrue(c.subset([{'op': 'hello'}], [{'op': 'hello', 'protocol': 1}]))
        self.assertFalse(c.subset([{'op': 'hello'}], [{'op': 'hello'}, {'op': 'get'}]))
        self.assertFalse(c.subset([1, 2], [2, 1]))

    def test_nested(self):
        self.assertTrue(c.subset({'client': {'name': 'x'}},
                                 {'client': {'name': 'x', 'language': 'dart'}}))
        self.assertFalse(c.subset({'client': {'name': 'x'}}, {'client': 'x'}))


class Canonical(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        self.assertEqual(c.canonical({'b': 1, 'a': [{'d': 1, 'c': 2}]}),
                         c.canonical(json.loads('{"a":[{"c":2,"d":1}],"b":1}')))


class Tables(unittest.TestCase):
    def test_every_case_is_well_formed(self):
        names = set()
        for table, cases in c.load_tables().items():
            for case in cases:
                with self.subTest(table=table, case=case.get('name')):
                    self.assertIn('name', case)
                    self.assertNotIn((table, case['name']), names, 'a name twice')
                    names.add((table, case['name']))
                    self.assertIn('do', case['action'])
                    self.assertIn('result', case['expect'])
                    self.assertTrue(case.get('noService') or 'script' in case)
                    for p in case.get('platforms', []):
                        self.assertIn(p, ('linux', 'macos', 'windows'))

    def test_the_reference_table_is_current(self):
        text = json.dumps(c.references_table(), indent=1, ensure_ascii=False) + '\n'
        self.assertEqual((c.CASES / c.GENERATED).read_text(encoding='utf-8'), text)


if __name__ == '__main__':
    unittest.main()
