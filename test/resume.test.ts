/**
 * Resuming a session across a recorder restart. Resume is the one path that
 * reopens a ledger, so its guard rails are the test: it verifies before it
 * continues, refuses a closed or tampered or wrong-key ledger, and marks the
 * restart on the record instead of hiding it behind a seamless chain.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Recorder } from '../src/recorder.ts';
import { readLedger, loadOrCreateKeys, LEDGER_FILE, generateKeys } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { rechain } from '../src/attacks.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-resume-'));

/** An open recorder abandoned without close, as a crashed process leaves it. */
function crashMidSession(dir: string): { answered: string; inFlight: string } {
  let t = Date.UTC(2026, 8, 6, 10, 0, 0);
  const clock = () => new Date((t += 1000));
  const rec = Recorder.open(dir, { session: 'run-1', actor: 'recorder-pid-100', clock });
  rec.note('task: reindex the catalogue');
  const answered = rec.call('read_file', { path: 'a.ts' });
  rec.result(answered, { text: 'ok' });
  const inFlight = rec.call('shell', { cmd: 'reindex --all' }); // no result: died mid-call
  // deliberately no rec.close(): the process is gone
  return { answered, inFlight };
}

test('resume continues the chain, marks the restart, and the whole session verifies', () => {
  const dir = scratch();
  const { inFlight } = crashMidSession(dir);
  const before = readLedger(dir).entries;
  const headBefore = before[before.length - 1];

  const rec = Recorder.resume(dir, { actor: 'recorder-pid-200' });
  const late = rec.call('http_post', { url: 'https://hooks.example/done' });
  rec.result(late, { status: 200 });
  const anchor = rec.anchor(join(scratch(), 'anchors.jsonl'));
  rec.close();

  const { entries } = readLedger(dir);
  const resume = entries.find((e) => e.kind === 'resume');
  assert.ok(resume, 'a resume marker was written');
  assert.equal(resume.kind === 'resume' && resume.from, headBefore.seq, 'it names the pre-crash head seq');
  assert.equal(resume.kind === 'resume' && resume.fromHash, headBefore.hash, 'and that head hash');
  assert.equal(resume.seq, headBefore.seq + 1, 'and it is the next entry in one continuous chain');

  const key = loadOrCreateKeys(dir).publicKey;
  const verdict = verifyLedger(entries, { trustedKey: key, anchors: [anchor] });
  assert.notEqual(verdict.status, 'tampered', `a resumed session must verify: ${verdict.findings.map((f) => f.code)}`);
  assert.equal(verdict.status, 'verified', 'with the key and the post-resume anchor, it reaches verified');

  // The call that was in flight at the crash has no outcome, and the record says so
  // as a warning, not as tampering.
  const openFinding = verdict.findings.find((f) => f.code === 'UNANSWERED_CALL');
  assert.ok(openFinding && openFinding.severity === 'warn', 'the in-flight call is an open warning');
  const close = entries[entries.length - 1];
  assert.ok(close.kind === 'close' && close.open.includes(inFlight), 'and close lists it as legitimately open');
});

test('resume refuses a cleanly closed session — close is final', () => {
  const dir = scratch();
  const rec = Recorder.open(dir, { session: 'run-2' });
  rec.result(rec.call('noop', {}), {});
  rec.close();
  assert.throws(() => Recorder.resume(dir), /closed/i);
});

test('resume refuses a tampered ledger rather than laundering it', () => {
  const dir = scratch();
  crashMidSession(dir);
  // An attacker edits an entry on disk before the recorder comes back.
  const path = join(dir, LEDGER_FILE);
  const lines = readFileSync(path, 'utf8').trim().split('\n');
  const doctored = JSON.parse(lines[1]);
  doctored.tool = 'read_file_but_evil';
  lines[1] = JSON.stringify(doctored);
  writeFileSync(path, lines.join('\n') + '\n');
  assert.throws(() => Recorder.resume(dir), /tampered/i);
});

test('resume refuses a ledger it does not hold the original key for', () => {
  const dir = scratch();
  const original = generateKeys();
  const rec = Recorder.open(dir, { session: 'run-3', keys: original });
  rec.result(rec.call('noop', {}), {});
  // no close; a different recorder with a different key tries to take over
  assert.throws(() => Recorder.resume(dir, { keys: generateKeys() }), /current recorder key/i);
});

test('a resume entry cannot lie about where it continued from, even signed with the real key', () => {
  const dir = scratch();
  crashMidSession(dir);
  const rec = Recorder.resume(dir);
  rec.result(rec.call('noop', {}), {});
  rec.close();

  const { entries } = readLedger(dir);
  const key = loadOrCreateKeys(dir);
  const r = entries.findIndex((e) => e.kind === 'resume');
  // Attacker holding the key rewrites the resume's claimed origin and re-signs.
  (entries[r] as { fromHash: string }).fromHash = 'e'.repeat(64);
  const forged = rechain(entries, r, key.privateKey);

  const verdict = verifyLedger(forged, { trustedKey: key.publicKey });
  assert.equal(verdict.status, 'tampered');
  assert.ok(verdict.findings.some((f) => f.code === 'RESUME_MISMATCH'), 'the fabricated continuity claim is caught');
});
