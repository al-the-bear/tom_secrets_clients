// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Runs every compiled test (build/test/*.test.js) with node:test. The files
// are named here because `node --test <dir>` and its glob patterns differ
// between the Node versions the package supports (18 and later).

'use strict';

const { spawnSync } = require('node:child_process');
const { readdirSync } = require('node:fs');
const { join } = require('node:path');

const dir = join(__dirname, '..', 'build', 'test');
const files = readdirSync(dir)
  .filter((f) => f.endsWith('.test.js'))
  .sort()
  .map((f) => join(dir, f));
if (files.length === 0) {
  process.stderr.write(`no tests in ${dir}\n`);
  process.exit(1);
}
const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);
