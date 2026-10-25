import { test } from 'node:test';
import assert from 'node:assert/strict';

import { describe } from '../src/show.ts';
import { GENESIS_PREV, FORMAT_VERSION, fingerprint, generateKeys, publicKeyFromBase64, publicKeyToBase64, seal, type Payload } from '../src/ledger.ts';

const keys = generateKeys();
const pub = publicKeyToBase64(keys.publicKey);
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

let seq = 0;
const entry = (p: Payload) =>
  seal({ v: FORMAT_VERSION, seq: ++seq, prev: GENESIS_PREV, ts: '2026-10-25T10:00:00.000Z', ...p } as never, keys.privateKey);

test('every line starts with the entry number and its time', () => {
  const line = strip(describe(entry({ kind: 'note', text: 'hello' })));
  assert.match(line, /^\s+\d+ 2026-10-25T10:00:00\.000Z note hello$/);
});

test('an open entry shows the session, the actor and a short key fingerprint', () => {
  const line = strip(describe(entry({ kind: 'open', session: 's-1', pub, actor: 'ci-runner' })));
  assert.ok(line.includes('open session s-1 (ci-runner)'));
  assert.ok(line.includes(`key ${fingerprint(publicKeyFromBase64(pub))}`));
});

test('an open entry without an actor leaves out the brackets', () => {
  const line = strip(describe(entry({ kind: 'open', session: 's-1', pub })));
  assert.ok(!line.includes('('));
});

test('a call shows the tool and its arguments, cut off at 100 characters', () => {
  const long = strip(describe(entry({ kind: 'call', id: 'c1', tool: 'read_file', args: { path: 'x'.repeat(300) } })));
  assert.ok(long.includes('call read_file {"path":"xxx'));
  const args = long.slice(long.indexOf('{'));
  assert.equal(args.length, 100);
});

test('a call made against a tool definition says which entry that came from', () => {
  const line = strip(describe(entry({ kind: 'call', id: 'c1', tool: 't', args: {}, def: { seq: 3, digest: 'd' } })));
  assert.ok(line.endsWith('def@3'));
});

test('a result with its body inline shows the body; a large one shows its size and digest', () => {
  const small = strip(describe(entry({ kind: 'result', of: 'c1', ok: true, digest: 'a'.repeat(64), bytes: 9, body: { n: 1 } })));
  assert.ok(small.includes('ok   {"n":1}'));
  const big = strip(describe(entry({ kind: 'result', of: 'c1', ok: true, digest: 'abcdef012345' + '0'.repeat(52), bytes: 5000 })));
  assert.ok(big.includes('5000 bytes abcdef012345…'));
});

test('a failed result says fail', () => {
  const line = strip(describe(entry({ kind: 'result', of: 'c1', ok: false, digest: 'a'.repeat(64), bytes: 1, body: 'boom' })));
  assert.ok(line.includes('fail "boom"'));
});

test('resume, rotate and close each say what happened', () => {
  const resume = strip(describe(entry({ kind: 'resume', from: 7, fromHash: 'f'.repeat(64), actor: 'pid 42' })));
  assert.ok(resume.includes('resume from seq 7 ffffffffffff…'));
  assert.ok(resume.includes('(pid 42)'));
  const rotate = strip(describe(entry({ kind: 'rotate', pub })));
  assert.ok(rotate.includes(`rotate to key ${fingerprint(publicKeyFromBase64(pub))}`));
  assert.ok(strip(describe(entry({ kind: 'close', calls: 3, results: 3, open: [] }))).endsWith('close 3 calls, 3 results'));
  assert.ok(strip(describe(entry({ kind: 'close', calls: 3, results: 2, open: ['c9'] }))).endsWith('3 calls, 2 results, 1 still open'));
});

test('failures are printed in red and the rest of the line is not', () => {
  const failed = describe(entry({ kind: 'result', of: 'c1', ok: false, digest: 'a'.repeat(64), bytes: 1, body: 'x' }));
  const fine = describe(entry({ kind: 'result', of: 'c1', ok: true, digest: 'a'.repeat(64), bytes: 1, body: 'x' }));
  assert.ok(failed.includes('\x1b[31mfail'));
  assert.ok(!fine.includes('\x1b[31m'));
});
