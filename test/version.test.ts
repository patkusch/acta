import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const want = (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;

for (const word of ['--version', 'version']) {
  test(`acta ${word} prints the name and the number from package.json`, () => {
    const r = spawnSync('node', ['--experimental-strip-types', 'bin/acta.mjs', word], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), `acta ${want}`);
  });
}
