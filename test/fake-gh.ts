/**
 * A fake `gh` executable for CLI tests: `gh api ...` answered from the JSON
 * state file named by FAKE_GH_STATE, using the same fake as the unit tests.
 * The CLI under test shells out to plain `gh`, so putting a wrapper for this
 * script first on PATH exercises the real command line with no network.
 */
import { readFileSync, writeFileSync } from 'node:fs';

import { fakeExec, type FakeState } from './fake-github.ts';

const file = process.env.FAKE_GH_STATE!;
const state = JSON.parse(readFileSync(file, 'utf8')) as FakeState;
const input = process.argv.includes('--input') ? readFileSync(0, 'utf8') : undefined;
try {
  process.stdout.write(fakeExec(state)(process.argv.slice(2), input));
  writeFileSync(file, JSON.stringify(state));
} catch (e) {
  process.stderr.write((e as Error).message + '\n');
  process.exit(1);
}
