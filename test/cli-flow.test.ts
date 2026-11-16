import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * The command line as someone would use it: start a ledger, record steps, check it, show it, and
 * what happens when it is edited or misused. Everything runs in a throw-away folder.
 */

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

function folder(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'acta-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function acta(cwd: string, ...args: string[]) {
  const r = spawnSync('node', ['--experimental-strip-types', join(process.cwd(), 'bin/acta.mjs'), ...args], { cwd, encoding: 'utf8' });
  return { status: r.status, out: strip(r.stdout), err: strip(r.stderr) };
}

const step = (dir: string, ledger: string, action: string, ...extra: string[]) =>
  acta(dir, 'step', ledger, '--agent', 'builder', '--stage', 'create', '--action', action, ...extra);

test('init makes a ledger folder with a key pair and says which key it is', (t) => {
  const dir = folder(t);
  const r = acta(dir, 'init', 'ledger');
  assert.equal(r.status, 0, r.err);
  assert.ok(existsSync(join(dir, 'ledger', 'recorder.key')));
  assert.ok(existsSync(join(dir, 'ledger', 'recorder.pub')));
  assert.match(r.out, /recorder key [0-9a-f]{16}/);
  assert.match(r.out, /copy .*recorder\.pub somewhere the agent cannot write/);
});

test('running init again keeps the same key, so an old ledger still checks', (t) => {
  const dir = folder(t);
  const first = acta(dir, 'init', 'ledger').out.match(/recorder key ([0-9a-f]{16})/)![1];
  const second = acta(dir, 'init', 'ledger').out.match(/recorder key ([0-9a-f]{16})/)![1];
  assert.equal(second, first);
});

test('steps are recorded one call each and the ledger then checks out as consistent, exit 0', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  assert.equal(step(dir, 'ledger', 'wrote the file').status, 0);
  assert.equal(step(dir, 'ledger', 'ran tests', '--ref', 'https://example.com/run/1').status, 0);
  const v = acta(dir, 'verify', 'ledger');
  assert.equal(v.status, 0);
  assert.match(v.out, /^CONSISTENT {2}\d+ entries/);
  assert.match(v.out, /consistent is not verified\./);
  assert.match(v.out, /a public key obtained outside the ledger directory \(--key\)/);
});

test('verify --json gives the verdict, the session, the head and what is still missing', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'one');
  const data = JSON.parse(acta(dir, 'verify', 'ledger', '--json').out);
  assert.equal(data.status, 'consistent');
  assert.ok(data.entries >= 3);
  assert.equal(typeof data.session, 'string');
  assert.equal(data.head.hash.length, 64);
  assert.equal(data.head.seq, data.entries - 1);
  assert.deepEqual(data.findings.map((f: { code: string }) => f.code), ['SELF_ATTESTED_KEY']);
  assert.equal(data.missing.length, 2);
});

test('--strict turns "consistent but not independently verified" into exit code 3', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'one');
  assert.equal(acta(dir, 'verify', 'ledger', '--strict').status, 3);
});

test('show prints one numbered line per entry, in order, with what each step did', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'wrote the file');
  step(dir, 'ledger', 'ran tests', '--failed');
  const lines = acta(dir, 'show', 'ledger').out.trim().split('\n');
  assert.match(lines[0], /^0 \S+ open session [0-9a-f-]{36} \(builder\) key [0-9a-f]{16}$/);
  assert.ok(lines.some((l) => /call gitlab\.create \{"action":"wrote the file"\}/.test(l)));
  assert.ok(lines.some((l) => /ok\s+\{"done":"wrote the file"\}/.test(l)));
  assert.ok(lines.some((l) => /fail\s+\{"done":"ran tests"\}/.test(l)));
  const numbers = lines.map((l) => Number(l.trim().split(' ')[0]));
  assert.deepEqual(numbers, numbers.map((_, i) => i), 'entry numbers run 0, 1, 2 with no gaps');
});

test('editing a recorded line is caught: TAMPERED and exit 1', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'wrote the file');
  step(dir, 'ledger', 'ran tests');
  const file = join(dir, 'ledger', 'ledger.jsonl');
  writeFileSync(file, readFileSync(file, 'utf8').replace('wrote the file', 'wrote nothing'));
  const v = acta(dir, 'verify', 'ledger');
  assert.equal(v.status, 1);
  assert.match(v.out, /^TAMPERED/);
});

test('deleting the middle of a ledger is caught too', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'one');
  step(dir, 'ledger', 'two');
  step(dir, 'ledger', 'three');
  const file = join(dir, 'ledger', 'ledger.jsonl');
  const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
  writeFileSync(file, [...lines.slice(0, 3), ...lines.slice(5)].join('\n') + '\n');
  assert.equal(acta(dir, 'verify', 'ledger').status, 1);
});

test('a folder with no ledger is reported as missing, exit 1, not as a crash', (t) => {
  const dir = folder(t);
  const v = acta(dir, 'verify', 'nothere');
  assert.equal(v.status, 1);
  assert.match(v.out, /^TAMPERED {2}0 entries/);
  assert.match(v.out, /MISSING\s+no ledger\.jsonl in .*nothere/);
  assert.doesNotMatch(v.err, /\n\s+at /);
});

test('a step with an unknown stage or missing words is refused with exit 2 and nothing is recorded', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  const bad = acta(dir, 'step', 'ledger', '--agent', 'a', '--stage', 'nonsense', '--action', 'x');
  assert.equal(bad.status, 2);
  assert.match(bad.err, /unknown stage "nonsense"; use one of plan, create, verify/);
  const missing = acta(dir, 'step', 'ledger', '--agent', 'a');
  assert.equal(missing.status, 2);
  assert.match(missing.err, /^usage:/);
  assert.ok(!existsSync(join(dir, 'ledger', 'ledger.jsonl')));
});

test('closing is final: a second close, or a step after it, says so plainly and exits 2 without a stack trace', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  step(dir, 'ledger', 'one');
  assert.equal(acta(dir, 'step', 'ledger', '--close').status, 0);
  for (const again of [acta(dir, 'step', 'ledger', '--close'), step(dir, 'ledger', 'after the close')]) {
    assert.equal(again.status, 2);
    assert.match(again.err, /^refusing to resume a closed session; close is final/);
    assert.doesNotMatch(again.err, /\n\s+at /);
  }
});

test('closing a ledger that was never started says there is nothing to close', (t) => {
  const dir = folder(t);
  acta(dir, 'init', 'ledger');
  const r = acta(dir, 'step', 'ledger', '--close');
  assert.equal(r.status, 2);
  assert.match(r.err, /no ledger at .* to resume/);
  assert.doesNotMatch(r.err, /\n\s+at /);
});

test('an unknown command prints the usage and exits 2', (t) => {
  const dir = folder(t);
  const r = acta(dir, 'bogus');
  assert.equal(r.status, 2);
  assert.match(r.err, /^usage:\n {2}acta init/);
  assert.match(r.err, /acta mcp/);
});
