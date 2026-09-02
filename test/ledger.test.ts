import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canon, digest } from '../src/canon.ts';
import { Recorder } from '../src/recorder.ts';
import { readLedger, loadPublicKey, generateKeys, PUB_FILE, LEDGER_FILE, type Entry } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { readAnchors, parseAnchorLine, formatAnchor } from '../src/anchor.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-'));

test('canonical JSON is order-independent and refuses what JSON cannot hold', () => {
  assert.equal(canon({ b: 1, a: [1, { d: 2, c: 3 }] }), '{"a":[1,{"c":3,"d":2}],"b":1}');
  assert.equal(canon({ a: undefined, b: 'x' }), '{"b":"x"}');
  assert.equal(canon([undefined, null]), '[null,null]');
  assert.equal(canon(new Date(0)), '"1970-01-01T00:00:00.000Z"');
  assert.throws(() => canon(NaN));
  assert.throws(() => canon(() => 1));
  assert.equal(digest({ x: 1 }), digest({ x: 1.0 }));
});

test('a recorded session verifies, and reaches "verified" only with key and anchor', async () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { actor: 'test-agent' });
  const tools = rec.wrap({
    read: async (p: { path: string }) => `contents of ${p.path}`,
    boom: async () => {
      throw new Error('disk on fire');
    },
  });
  await tools.read({ path: '/etc/hosts' });
  await assert.rejects(tools.boom());
  rec.note('human approved the read');
  const anchorPath = join(scratch(), 'anchors.jsonl');
  rec.anchor(anchorPath);
  rec.close();

  const { entries, problems } = readLedger(dir);
  assert.equal(problems.length, 0);
  assert.deepEqual(
    entries.map((e) => e.kind),
    ['open', 'call', 'result', 'call', 'result', 'note', 'close'],
  );
  const fail = entries[4] as Extract<Entry, { kind: 'result' }>;
  assert.equal(fail.ok, false);
  assert.deepEqual(fail.body, { name: 'Error', message: 'disk on fire' });

  const bare = verifyLedger(entries);
  assert.equal(bare.status, 'consistent');
  assert.equal(bare.missing.length, 2);

  const full = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)), anchors: readAnchors(anchorPath) });
  assert.equal(full.status, 'verified', JSON.stringify(full.findings));
  assert.deepEqual(full.anchoredTo, { seq: 5, hash: entries[5].hash });
  assert.ok(full.findings.some((f) => f.code === 'UNANCHORED_TAIL'));
});

test('a large result goes to the blob store and is checked against it', async () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { inlineLimit: 64 });
  const id = rec.call('fetch', { url: 'https://example.com' });
  rec.result(id, { body: 'x'.repeat(500) });
  rec.close();
  const { entries } = readLedger(dir);
  const result = entries[2] as Extract<Entry, { kind: 'result' }>;
  assert.equal(result.body, undefined);
  const blobPath = join(dir, 'blobs', result.digest);
  const blob = (d: string) => (d === result.digest ? readFileSync(blobPath) : undefined);
  assert.equal(verifyLedger(entries, { blob }).status, 'consistent');
  writeFileSync(blobPath, canon({ body: 'y'.repeat(500) }));
  const v = verifyLedger(entries, { blob });
  assert.equal(v.status, 'tampered');
  assert.ok(v.findings.some((f) => f.code === 'BLOB_MISMATCH'));
});

test('a ledger signed by a different key is caught only when the verifier brings its own', async () => {
  const dir = scratch();
  const real = generateKeys();
  const rec = Recorder.open(dir, { keys: real });
  rec.note('hello');
  rec.close();
  const { entries } = readLedger(dir);
  const other = generateKeys();
  const v = verifyLedger(entries, { trustedKey: other.publicKey });
  assert.equal(v.status, 'tampered');
  assert.ok(v.findings.some((f) => f.code === 'KEY_MISMATCH'));
  assert.ok(v.findings.some((f) => f.code === 'BAD_SIGNATURE'));
});

test('anchors round-trip through their one-line text form', () => {
  const a = { session: 's-1', seq: 9, hash: 'a'.repeat(64), at: '2026-09-02T20:00:00.000Z' };
  assert.deepEqual(parseAnchorLine(formatAnchor(a)), a);
  assert.deepEqual(parseAnchorLine(`  ${JSON.stringify(a)}`), a);
  assert.equal(parseAnchorLine('nothing to see'), undefined);
});

test('the recorder refuses to append to an existing ledger or answer twice', () => {
  const dir = scratch();
  const rec = Recorder.open(dir);
  const id = rec.call('x', {});
  rec.result(id, 1);
  assert.throws(() => rec.result(id, 2));
  assert.throws(() => rec.result('nope', 2));
  rec.close();
  assert.throws(() => Recorder.open(dir), /one session per ledger/);
  assert.ok(readFileSync(join(dir, LEDGER_FILE), 'utf8').endsWith('\n'));
});

test('a missing ledger is reported as MISSING, not as a parse error', () => {
  const { entries, problems } = readLedger(join(scratch(), 'never-written'));
  const v = verifyLedger(entries, { problems });
  assert.equal(v.status, 'tampered');
  assert.deepEqual(v.findings.map((f) => f.code), ['MISSING']);
});

test('a session that crashed mid-call is a warning, not tampering — and looks the same as a truncation', async () => {
  const dir = scratch();
  const rec = Recorder.open(dir);
  const id = rec.call('shell', { cmd: 'npm test' });
  rec.note('the process died here');
  void id;
  // no result, no close — the recorder was killed.
  const { entries } = readLedger(dir);
  const v = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)) });
  assert.notEqual(v.status, 'tampered');
  assert.deepEqual(
    v.findings.filter((f) => f.severity === 'warn').map((f) => f.code),
    ['UNANSWERED_CALL'],
  );
  // Only an anchor taken after the crash point can tell a crash from a cut.
  const later = { session: rec.session, seq: 5, hash: 'a'.repeat(64), at: '' };
  const cut = verifyLedger(entries, { anchors: [later] });
  assert.ok(cut.findings.some((f) => f.code === 'TRUNCATED'));
});
