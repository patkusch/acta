/**
 * Rotating the recorder's key within a session. A rotation is signed by the
 * outgoing key and declares the next, so trust flows forward along a signed
 * succession: a reviewer who is handed the *original* key can verify the whole
 * chain across every handover, and nobody who lacks the current key can forge a
 * rotation into it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.ts';
import {
  readLedger,
  loadOrCreateKeys,
  generateKeys,
  publicKeyToBase64,
  seal,
  type Body,
  type Entry,
} from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-rotate-'));
let t = Date.UTC(2026, 8, 6, 12, 0, 0);
const clock = () => new Date((t += 1000));

test('a session that rotates its key verifies against the original key, across the handover', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'rot', clock });
  const k0 = loadOrCreateKeys(dir); // the genesis key, before any rotation
  rec.result(rec.call('before', {}), { ok: true });

  const k1 = generateKeys();
  rec.rotate(k1);
  rec.result(rec.call('after', {}), { ok: true });
  const anchor = rec.anchor(join(scratch(), 'anchors.jsonl'));
  rec.close();

  const { entries } = readLedger(dir);
  const rot = entries.find((e) => e.kind === 'rotate');
  assert.ok(rot && rot.kind === 'rotate' && rot.pub === publicKeyToBase64(k1.publicKey), 'the rotate declares the new key');

  const verdict = verifyLedger(entries, { trustedKey: k0.publicKey, anchors: [anchor] });
  assert.equal(verdict.status, 'verified', `handed the original key, the whole chain verifies: ${JSON.stringify(verdict.findings)}`);
});

test('the current key is not enough to verify — the reviewer needs the original', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'rot2', clock });
  rec.result(rec.call('before', {}), {});
  const k1 = generateKeys();
  rec.rotate(k1);
  rec.result(rec.call('after', {}), {});
  rec.close();

  const { entries } = readLedger(dir);
  const verdict = verifyLedger(entries, { trustedKey: k1.publicKey });
  assert.equal(verdict.status, 'tampered');
  assert.ok(verdict.findings.some((f) => f.code === 'KEY_MISMATCH'), 'the genesis key is not the current key');
});

test('a rotation cannot be forged by someone who does not hold the current key', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'rot3', clock });
  const k0 = loadOrCreateKeys(dir);
  rec.result(rec.call('a', {}), {});
  const { entries } = readLedger(dir); // still open
  const last = entries[entries.length - 1];

  // Attacker holds only their own key, not k0, and appends a rotate to take over.
  const attacker = generateKeys();
  const body = { v: 1, seq: last.seq + 1, prev: last.hash, ts: clock().toISOString(), kind: 'rotate', pub: publicKeyToBase64(attacker.publicKey) } as Body;
  const forged = seal(body, attacker.privateKey) as Entry;

  const verdict = verifyLedger([...entries, forged], { trustedKey: k0.publicKey });
  assert.equal(verdict.status, 'tampered');
  assert.ok(verdict.findings.some((f) => f.code === 'BAD_SIGNATURE' && f.seq === forged.seq), 'the rotate is checked against the retiring key, and fails');
});

test('a rotate that declares an unreadable key is caught', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'rot4', clock });
  const k0 = loadOrCreateKeys(dir);
  rec.result(rec.call('a', {}), {});
  const { entries } = readLedger(dir);
  const last = entries[entries.length - 1];

  const body = { v: 1, seq: last.seq + 1, prev: last.hash, ts: clock().toISOString(), kind: 'rotate', pub: 'not-a-real-key' } as Body;
  const forged = seal(body, k0.privateKey) as Entry; // validly signed by k0, but the declared key is junk

  const verdict = verifyLedger([...entries, forged], { trustedKey: k0.publicKey });
  assert.equal(verdict.status, 'tampered');
  assert.ok(verdict.findings.some((f) => f.code === 'BAD_ROTATE_KEY'), 'the unreadable successor key is a tamper finding');
});

test('resume after a rotation continues under the new key and still verifies to the original', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'rot5', clock });
  const k0 = loadOrCreateKeys(dir); // captured before the rotation overwrites the key on disk
  rec.result(rec.call('before', {}), {});
  const k1 = generateKeys();
  rec.rotate(k1); // persists k1 as the current key on disk
  rec.result(rec.call('mid', {}), {});
  // crash: no close

  const resumed = Recorder.resume(dir); // must load k1, the current key, from disk
  resumed.result(resumed.call('after', {}), {});
  const anchor = resumed.anchor(join(scratch(), 'anchors.jsonl'));
  resumed.close();

  const { entries } = readLedger(dir);
  assert.ok(entries.some((e) => e.kind === 'rotate'), 'the rotation is in the chain');
  assert.ok(entries.some((e) => e.kind === 'resume'), 'so is the resume');
  const tools = entries.filter((e): e is Extract<Entry, { kind: 'call' }> => e.kind === 'call').map((c) => c.tool);
  assert.deepEqual(tools, ['before', 'mid', 'after'], 'all three calls, across the rotation and the restart');

  const verdict = verifyLedger(entries, { trustedKey: k0.publicKey, anchors: [anchor] });
  assert.equal(verdict.status, 'verified', `the original key still verifies the whole thing: ${JSON.stringify(verdict.findings)}`);
});
