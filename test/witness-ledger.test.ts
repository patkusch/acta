/**
 * The witness ledger: append-only local record of every GitHub or Rekor
 * witness, a backup that refuses to hide a rewrite, and a verifier that
 * turns "the provider can no longer produce what my ledger says it once
 * held" into a tamper finding while keeping "the provider did not answer"
 * apart from it. For Rekor witnesses specifically, it also checks
 * consistency between each consecutive pair filed — see the "Rekor
 * witnesses" section below.
 *
 * Everything runs against in-memory fakes (fake-github.ts, fake-rekor.ts)
 * through the injectable `ghExec`/`rekorExec`, so `npm test` never touches
 * the network. The GitHub fake sits behind a fake `gh` on PATH for the
 * command-line tests at the bottom. The one real round trip against
 * patkusch/acta-anchors (GitHub) and the real Rekor submissions are separate
 * manual steps, documented in the README.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { writeGitHubAnchor, verifyGitHubWitness, type GitHubWitness } from '../src/github-anchor.ts';
import { writeRekorAnchor, type RekorExec } from '../src/rekor-anchor.ts';
import { formatAnchor, type Anchor } from '../src/anchor.ts';
import {
  WitnessBackupRefused,
  WitnessLedgerError,
  appendWitness,
  backupWitnessLedger,
  parseBackupTarget,
  readWitnessLedger,
  relateLines,
  verifyWitnessLedger,
} from '../src/witness-ledger.ts';
import { recordSampleSession } from '../src/fixtures/session.ts';
import { NETWORK, fakeExec, forcePush, headContent, newState, rewriteHead, type FakeState } from './fake-github.ts';
import { fakeGrowingRekor, testRekorSeed } from './fake-rekor.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-wl-'));
const anchor = (n: number): Anchor => ({ session: 'sess-1234abcd', seq: n, hash: String(n).repeat(64).slice(0, 64), at: `2026-09-18T08:0${n}:00.000Z` });
const REPO = 'patkusch/acta-anchors';

/** Push `n` anchors through the real sink against the fake, and file each witness in a fresh ledger. */
function honest(n: number) {
  const state = newState();
  const ghExec = fakeExec(state);
  const ledger = join(scratch(), 'witnesses.jsonl');
  const witnesses: GitHubWitness[] = [];
  for (let i = 1; i <= n; i++) {
    const w = writeGitHubAnchor(anchor(i), { repo: REPO, ghExec });
    appendWitness(ledger, w);
    witnesses.push(w);
  }
  return { state, ghExec, ledger, witnesses };
}

// --- the ledger and its append-only guard --------------------------------------

test('appendWitness files each witness as one line, keeps every earlier byte, and is a no-op for a repeat', () => {
  const { ledger, witnesses } = honest(2);
  const text = readFileSync(ledger, 'utf8');
  assert.equal(text.split('\n').filter(Boolean).length, 2);
  assert.ok(text.endsWith('\n'));

  const parsed = readWitnessLedger(ledger);
  assert.deepEqual(parsed.problems, []);
  assert.deepEqual(parsed.records.map((r) => r.witness), witnesses);
  // every field the feature promises is in the record
  const w = parsed.records[0].witness as GitHubWitness;
  assert.ok(w.repo && w.branch && w.path && w.commitSha && w.committedAt && w.anchor.hash && w.anchor.session);
  assert.equal(w.line, 0);
  assert.equal((parsed.records[1].witness as GitHubWitness).line, 1);

  assert.deepEqual(appendWitness(ledger, witnesses[0]), { appended: false });
  assert.equal(readFileSync(ledger, 'utf8'), text, 're-filing the same witness changes nothing');
});

test('appendWitness refuses a damaged ledger and leaves its bytes exactly as they were', () => {
  const { ledger, witnesses } = honest(1);
  const damaged = readFileSync(ledger, 'utf8') + 'this is not a witness\n';
  writeFileSync(ledger, damaged);
  assert.throws(() => appendWitness(ledger, { ...witnesses[0], commitSha: 'f'.repeat(40), line: 1 }), (e: unknown) => e instanceof WitnessLedgerError && e.code === 'LEDGER_CORRUPT');
  assert.equal(readFileSync(ledger, 'utf8'), damaged, 'refused, and nothing was appended or repaired');

  // a write that was cut short (no trailing newline) is damage too
  const cut = join(scratch(), 'cut.jsonl');
  writeFileSync(cut, JSON.stringify(witnesses[0]));
  assert.throws(() => appendWitness(cut, { ...witnesses[0], commitSha: 'e'.repeat(40), line: 1 }), /unterminated/);
});

test('appendWitness refuses a second, disagreeing record for the same commit and line', () => {
  const { ledger, witnesses } = honest(1);
  const before = readFileSync(ledger, 'utf8');
  const conflicting = { ...witnesses[0], anchor: anchor(9) };
  assert.throws(() => appendWitness(ledger, conflicting), (e: unknown) => e instanceof WitnessLedgerError && e.code === 'LEDGER_CONFLICT');
  assert.equal(readFileSync(ledger, 'utf8'), before);
});

// --- backup ---------------------------------------------------------------------

test('relateLines tells a stale backup from one that knows too much or disagrees', () => {
  assert.equal(relateLines(['a', 'b'], ['a', 'b']), 'same');
  assert.equal(relateLines(['a', 'b'], ['a']), 'behind');
  assert.equal(relateLines(['a'], ['a', 'b']), 'ahead');
  assert.equal(relateLines(['a', 'b'], ['a', 'x']), 'diverged');
});

test('backup to a local path creates, is idempotent, and only ever appends the newer lines', () => {
  const { ledger, ghExec } = honest(2);
  const dest = join(scratch(), 'usb', 'witnesses.jsonl');

  const first = backupWitnessLedger(ledger, { kind: 'path', path: dest });
  assert.equal(first.status, 'created');
  assert.equal(readFileSync(dest, 'utf8'), readFileSync(ledger, 'utf8'), 'a byte-for-byte copy');

  const again = backupWitnessLedger(ledger, { kind: 'path', path: dest });
  assert.deepEqual([again.status, again.appended], ['unchanged', 0]);

  appendWitness(ledger, writeGitHubAnchor(anchor(3), { repo: REPO, ghExec }));
  const beforeBytes = readFileSync(dest, 'utf8');
  const updated = backupWitnessLedger(ledger, { kind: 'path', path: dest });
  assert.deepEqual([updated.status, updated.appended, updated.total], ['updated', 1, 3]);
  const afterBytes = readFileSync(dest, 'utf8');
  assert.ok(afterBytes.startsWith(beforeBytes), 'the earlier backup bytes were extended, not rewritten');
  assert.equal(afterBytes, readFileSync(ledger, 'utf8'));
  assert.equal(readWitnessLedger(dest).records.length, 3);
});

test('a local backup holding a line the ledger lacks is never overwritten (the tamper signal in the other direction)', () => {
  const { ledger, ghExec } = honest(2);
  const dest = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, writeGitHubAnchor(anchor(3), { repo: REPO, ghExec }));
  backupWitnessLedger(ledger, { kind: 'path', path: dest });
  const backupBytes = readFileSync(dest, 'utf8');

  // the local ledger is truncated after the backup was made
  const lines = readFileSync(ledger, 'utf8').split('\n').filter(Boolean);
  writeFileSync(ledger, lines.slice(0, 2).join('\n') + '\n');
  assert.throws(() => backupWitnessLedger(ledger, { kind: 'path', path: dest }), (e: unknown) => e instanceof WitnessBackupRefused && e.code === 'BACKUP_HAS_UNKNOWN_LINES');
  assert.equal(readFileSync(dest, 'utf8'), backupBytes, 'the backup is untouched');

  // and a rewritten line is a divergence, refused just the same
  const rewritten = lines.slice();
  rewritten[1] = JSON.stringify({ ...JSON.parse(rewritten[1]), commitSha: 'd'.repeat(40) });
  writeFileSync(ledger, rewritten.join('\n') + '\n');
  assert.throws(() => backupWitnessLedger(ledger, { kind: 'path', path: dest }), (e: unknown) => e instanceof WitnessBackupRefused && e.code === 'BACKUP_DIVERGED');
  assert.equal(readFileSync(dest, 'utf8'), backupBytes);
});

test('backup refuses to back a ledger up onto itself, or to copy a damaged one', () => {
  const { ledger } = honest(1);
  assert.throws(() => backupWitnessLedger(ledger, { kind: 'path', path: ledger }), /the ledger itself/);
  writeFileSync(ledger, 'garbage\n');
  assert.throws(() => backupWitnessLedger(ledger, { kind: 'path', path: join(scratch(), 'b.jsonl') }), /damaged/);
});

test('backup to a GitHub repo goes through the anchor sink machinery: created, idempotent, then extended in one commit', () => {
  const { ledger, state, ghExec } = honest(2);
  const target = { kind: 'github' as const, repo: 'patkusch/acta-witness-backup' };
  const putsBefore = state.puts.length;

  const first = backupWitnessLedger(ledger, target, { ghExec });
  assert.deepEqual([first.status, first.appended, first.total], ['created', 2, 2]);
  assert.equal(state.puts.length, putsBefore + 1, 'one commit for the whole ledger');
  assert.equal(headContent(state, target.repo, 'main', 'witnesses.jsonl'), readFileSync(ledger, 'utf8'), 'the remote file is the ledger, byte for byte');

  const again = backupWitnessLedger(ledger, target, { ghExec });
  assert.deepEqual([again.status, again.appended], ['unchanged', 0]);
  assert.equal(state.puts.length, putsBefore + 1, 'idempotent: no second commit');

  appendWitness(ledger, writeGitHubAnchor(anchor(3), { repo: REPO, ghExec }));
  const putsMid = state.puts.length;
  const third = backupWitnessLedger(ledger, target, { ghExec });
  assert.deepEqual([third.status, third.appended, third.total], ['updated', 1, 3]);
  assert.equal(state.puts.length, putsMid + 1);
  assert.equal(headContent(state, target.repo, 'main', 'witnesses.jsonl'), readFileSync(ledger, 'utf8'));
});

test('a GitHub backup that knows more than the ledger, or disagrees with it, is refused and nothing is pushed', () => {
  const { ledger, state, ghExec } = honest(3);
  const target = { kind: 'github' as const, repo: 'patkusch/acta-witness-backup' };
  backupWitnessLedger(ledger, target, { ghExec });
  const backupAt = headContent(state, target.repo, 'main', 'witnesses.jsonl');
  const puts = state.puts.length;

  const lines = readFileSync(ledger, 'utf8').split('\n').filter(Boolean);
  writeFileSync(ledger, lines.slice(0, 2).join('\n') + '\n'); // local ledger lost its newest record
  assert.throws(() => backupWitnessLedger(ledger, target, { ghExec }), (e: unknown) => e instanceof WitnessBackupRefused && e.code === 'BACKUP_HAS_UNKNOWN_LINES');

  const swapped = lines.slice();
  swapped[0] = JSON.stringify({ ...JSON.parse(lines[0]), line: 7 });
  writeFileSync(ledger, swapped.join('\n') + '\n');
  assert.throws(() => backupWitnessLedger(ledger, target, { ghExec }), (e: unknown) => e instanceof WitnessBackupRefused && e.code === 'BACKUP_DIVERGED');

  assert.equal(state.puts.length, puts, 'no PUT was made');
  assert.equal(headContent(state, target.repo, 'main', 'witnesses.jsonl'), backupAt);
});

test('a failed read of the GitHub backup is not mistaken for an empty backup', () => {
  const { ledger, state, ghExec } = honest(1);
  const puts = state.puts.length;
  state.offline = true;
  assert.throws(() => backupWitnessLedger(ledger, { kind: 'github', repo: 'patkusch/acta-witness-backup' }, { ghExec }), new RegExp(NETWORK));
  assert.equal(state.puts.length, puts);
});

test('parseBackupTarget: owner/name is GitHub, anything that looks like or already is a path is a path', () => {
  const dir = scratch();
  assert.deepEqual(parseBackupTarget('patkusch/spare'), { kind: 'github', repo: 'patkusch/spare', branch: undefined, path: undefined });
  assert.deepEqual(parseBackupTarget('github:patkusch/spare:keep', { githubPath: 'w.jsonl' }), { kind: 'github', repo: 'patkusch/spare', branch: 'keep', path: 'w.jsonl' });
  assert.deepEqual(parseBackupTarget('./patkusch/spare'), { kind: 'path', path: resolve('./patkusch/spare') });
  assert.equal(parseBackupTarget(join(dir, 'w.jsonl')).kind, 'path');
  mkdirSync(join(dir, 'usb'));
  const here = process.cwd();
  process.chdir(dir);
  try {
    assert.equal(parseBackupTarget('usb/witnesses.jsonl').kind, 'path', 'a directory that exists makes a bare a/b a path');
  } finally {
    process.chdir(here);
  }
});

// --- verify --witnesses ---------------------------------------------------------

test('verify --witnesses is clean against an honest log, one result per record', () => {
  const { ledger, ghExec } = honest(3);
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'clean');
  assert.equal(report.records.length, 3);
  assert.ok(report.records.every((r) => r.status === 'OK' && r.findings.length === 0));
});

test('a commit the ledger says was pushed but GitHub cannot produce is WITNESS_REWRITTEN, a tamper finding', () => {
  const { ledger, state, ghExec } = honest(2);
  // a force-push discards history and puts a log of the attacker's choosing in its place
  forcePush(state, REPO, 'main', 'anchors.jsonl', formatAnchor(anchor(1)) + '\n' + formatAnchor(anchor(2)) + '\n');
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'tampered');
  assert.deepEqual(report.records.map((r) => r.status), ['WITNESS_REWRITTEN', 'WITNESS_REWRITTEN']);
  assert.ok(report.records[0].findings.every((f) => f.code !== 'WITNESS_COMMIT_NOT_FOUND'), 'not reported as a mere missing commit');
  assert.ok(report.records[0].findings.some((f) => f.code === 'HEAD_STILL_HOLDS_ANCHOR'), 'and it says the head happens to still hold the anchor');
});

test('a rewrite that also dropped the anchor from the head says so', () => {
  const { ledger, state, ghExec } = honest(2);
  forcePush(state, REPO, 'main', 'anchors.jsonl', formatAnchor(anchor(2)) + '\n');
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'tampered');
  const first = report.records[0];
  assert.equal(first.status, 'WITNESS_REWRITTEN');
  assert.ok(first.findings.some((f) => f.code === 'LOG_PREFIX_CHANGED'));
});

test('a network failure is WITNESS_UNREACHABLE — not tamper, and never a pass', () => {
  const { ledger, state, ghExec } = honest(2);
  state.offline = true;
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'unreachable');
  assert.deepEqual(report.records.map((r) => r.status), ['WITNESS_UNREACHABLE', 'WITNESS_UNREACHABLE']);
  assert.ok(report.records.every((r) => r.findings.every((f) => f.severity !== 'tamper')));
});

test('verifyGitHubWitness itself tells "GitHub says it is gone" from "GitHub did not answer"', () => {
  const { state, ghExec, witnesses } = honest(1);
  state.offline = true;
  const down = verifyGitHubWitness(witnesses[0], { ghExec });
  assert.equal(down.ok, false, 'an unanswered check is not a pass');
  assert.equal(down.unreachable, true);
  assert.deepEqual(down.findings.map((f) => [f.code, f.severity]), [['WITNESS_UNREACHABLE', 'warn']]);

  state.offline = false;
  forcePush(state, REPO, 'main', 'anchors.jsonl', 'something else\n');
  const gone = verifyGitHubWitness(witnesses[0], { ghExec });
  assert.equal(gone.unreachable, false);
  assert.deepEqual(gone.findings.map((f) => f.code), ['WITNESS_COMMIT_NOT_FOUND']);
});

test('LOG_PREFIX_CHANGED: the head lost an earlier line even though the old commits can still be fetched', () => {
  const { ledger, state, ghExec } = honest(3);
  // history rewritten, not yet garbage-collected: the head has a different line 1
  const forged = [formatAnchor(anchor(1)), formatAnchor({ ...anchor(2), hash: 'f'.repeat(64) }), formatAnchor(anchor(3))].join('\n') + '\n';
  rewriteHead(state, REPO, 'main', 'anchors.jsonl', forged);
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'tampered');
  const statuses = report.records.map((r) => r.status);
  assert.equal(statuses[0], 'OK', 'line 0 was a prefix of the head and still is');
  assert.equal(statuses[1], 'LOG_PREFIX_CHANGED');
  assert.equal(statuses[2], 'LOG_PREFIX_CHANGED', 'the later commit saw the honest line 1, so it too finds the head changed');
  assert.match(report.records[1].findings[0].message, /line 1 of the head/);
});

test('LOG_PREFIX_CHANGED: a head that has been cut short, or whose file is gone', () => {
  const { ledger, state, ghExec } = honest(3);
  rewriteHead(state, REPO, 'main', 'anchors.jsonl', formatAnchor(anchor(1)) + '\n');
  const shorter = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(shorter.verdict, 'tampered');
  assert.deepEqual(shorter.records.map((r) => r.status), ['OK', 'LOG_PREFIX_CHANGED', 'LOG_PREFIX_CHANGED']);
  assert.match(shorter.records[2].findings[0].message, /only 1 line/);

  delete state.heads[`${REPO}@main@anchors.jsonl`]; // branch or file deleted outright
  const gone = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(gone.verdict, 'tampered');
  assert.ok(gone.records.every((r) => r.status === 'LOG_PREFIX_CHANGED'));
});

test('lines added after the ledger was written are fine: only the earlier prefix has to hold', () => {
  const { ledger, state, ghExec } = honest(2);
  // someone else (another session, another machine) appends honestly
  writeGitHubAnchor(anchor(7), { repo: REPO, ghExec });
  assert.match(headContent(state, REPO, 'main', 'anchors.jsonl')!, /seq=7/);
  assert.equal(verifyWitnessLedger(ledger, { ghExec }).verdict, 'clean');
});

test('tamper outranks unreachable: one disowned record is not diluted by a failure elsewhere', () => {
  const { ledger, state, ghExec } = honest(2);
  const other = writeGitHubAnchor(anchor(5), { repo: 'patkusch/elsewhere', ghExec });
  appendWitness(ledger, other);
  forcePush(state, REPO, 'main', 'anchors.jsonl', 'rewritten\n');
  // the second repo becomes unreachable, the first stays reachable-but-rewritten
  const flaky = (args: string[], input?: string) => {
    if (args[1]?.includes('patkusch/elsewhere')) throw new Error(NETWORK);
    return ghExec(args, input);
  };
  const report = verifyWitnessLedger(ledger, { ghExec: flaky });
  assert.equal(report.verdict, 'tampered');
  assert.equal(report.records[2].status, 'WITNESS_UNREACHABLE');
});

test('an unreadable ledger line is reported, and an empty ledger is not called clean', () => {
  const { ledger, ghExec } = honest(1);
  writeFileSync(ledger, readFileSync(ledger, 'utf8') + '{"half a rec\n');
  const report = verifyWitnessLedger(ledger, { ghExec });
  assert.equal(report.verdict, 'tampered');
  assert.equal(report.ledgerFindings[0].code, 'WITNESS_LEDGER_MALFORMED');
  assert.equal(report.records.length, 1, 'the readable record was still checked');

  const empty = join(scratch(), 'empty.jsonl');
  writeFileSync(empty, '');
  assert.equal(verifyWitnessLedger(empty, { ghExec }).verdict, 'empty');
});

// --- Rekor witnesses, and cross-submission consistency between them --------------
//
// Same fake growing log as rekor-anchor.test.ts (shared via fake-rekor.ts): a
// real, growing RFC 6962 tree, real inclusion proofs, real ECDSA-signed
// checkpoints. Every fake entry here goes through the real `writeRekorAnchor`
// (against the fake's injected exec) so the witness object matches exactly
// what the fake actually stored — the same way a real submission would.
// What is new in this file is the ledger side — filing more than one Rekor
// witness and having `verifyWitnessLedger` check consistency between them,
// in the order they were filed, the way it already checks a GitHub log's
// head against each commit.

function submitFakeRekorAnchor(log: ReturnType<typeof fakeGrowingRekor>, a: Anchor) {
  return writeRekorAnchor(a, { secretKey: testRekorSeed(), exec: log.exec, rekorUrl: 'https://fake' });
}

test('a Rekor ledger of two honest submissions is clean, and the second record carries the consistency check', () => {
  const log = fakeGrowingRekor();
  const w1 = submitFakeRekorAnchor(log, anchor(1));
  const w2 = submitFakeRekorAnchor(log, anchor(2));
  const ledger = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, w1);
  appendWitness(ledger, w2);

  const report = verifyWitnessLedger(ledger, { rekorExec: log.exec, rekorCheckpointPublicKeyPem: log.checkpointPublicKeyPem });
  assert.equal(report.verdict, 'clean');
  assert.equal(report.records.length, 2);
  assert.deepEqual(report.records[0].findings, []);
  assert.deepEqual(report.records[1].findings, []);
});

test('a lone Rekor witness in the ledger is checked (verifyRekorWitness) but has no consistency check to run yet', () => {
  const log = fakeGrowingRekor();
  const w1 = submitFakeRekorAnchor(log, anchor(1));
  const ledger = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, w1);

  const report = verifyWitnessLedger(ledger, { rekorExec: log.exec, rekorCheckpointPublicKeyPem: log.checkpointPublicKeyPem });
  assert.equal(report.verdict, 'clean');
  assert.equal(report.records.length, 1);
});

test('a ledger mixing a GitHub witness and Rekor witnesses checks each against its own provider', () => {
  const { ghExec } = honest(0);
  const log = fakeGrowingRekor();
  const ghWitness = writeGitHubAnchor(anchor(0), { repo: REPO, ghExec });
  const r1 = submitFakeRekorAnchor(log, anchor(1));
  const r2 = submitFakeRekorAnchor(log, anchor(2));
  const ledger = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, ghWitness);
  appendWitness(ledger, r1);
  appendWitness(ledger, r2);

  const report = verifyWitnessLedger(ledger, { ghExec, rekorExec: log.exec, rekorCheckpointPublicKeyPem: log.checkpointPublicKeyPem });
  assert.equal(report.verdict, 'clean');
  assert.equal(report.records.length, 3);
  assert.equal(report.records[0].witness.provider, 'github');
  assert.equal(report.records[1].witness.provider, 'rekor');
  assert.equal(report.records[2].witness.provider, 'rekor');
});

test("a Rekor log that quietly rewrote history between two of the caller's own submissions is caught, even though each entry checks out on its own", () => {
  const log = fakeGrowingRekor();
  const w1 = submitFakeRekorAnchor(log, anchor(1));
  submitFakeRekorAnchor(log, anchor(2));
  const w3 = submitFakeRekorAnchor(log, anchor(3));
  const ledger = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, w1);
  appendWitness(ledger, w3);

  // Both entries are untouched and each verifies fine on its own — the tamper
  // is only in what the log's own /api/v1/log/proof answers for the
  // *consistency* proof between them, which is exactly the case a
  // per-submission check alone cannot catch.
  const rekorExec: RekorExec = (method, url, body) => {
    const real = log.exec(method, url, body);
    if (method === 'GET' && url.includes('/api/v1/log/proof')) {
      const parsed = JSON.parse(real.body) as { hashes: string[]; rootHash: string };
      parsed.hashes = parsed.hashes.map(() => '00'.repeat(32));
      return { status: real.status, body: JSON.stringify(parsed) };
    }
    return real;
  };

  const report = verifyWitnessLedger(ledger, { rekorExec, rekorCheckpointPublicKeyPem: log.checkpointPublicKeyPem });
  assert.equal(report.verdict, 'tampered');
  // The first record (w1) is clean on its own; the second (w3) carries the
  // consistency failure the ledger caught between the two submissions.
  assert.deepEqual(report.records[0].findings, []);
  assert.ok(report.records[1].findings.some((f) => f.code === 'REKOR_CONSISTENCY_PROOF_INVALID'));
});

test('a Rekor entry the log can no longer produce is tamper, and never dilutes a clean earlier record', () => {
  const log = fakeGrowingRekor();
  const w1 = submitFakeRekorAnchor(log, anchor(1));
  const w2 = submitFakeRekorAnchor(log, anchor(2));
  const ledger = join(scratch(), 'witnesses.jsonl');
  appendWitness(ledger, w1);
  appendWitness(ledger, w2);
  log.entries.delete(w2.uuid);

  const report = verifyWitnessLedger(ledger, { rekorExec: log.exec, rekorCheckpointPublicKeyPem: log.checkpointPublicKeyPem });
  assert.equal(report.verdict, 'tampered');
  assert.deepEqual(report.records[0].findings, []);
  assert.ok(report.records[1].findings.some((f) => f.code === 'REKOR_ENTRY_NOT_FOUND'));
});

// --- the command line, end to end, against a fake `gh` on PATH --------------------

function cliEnv() {
  const dir = scratch();
  const stateFile = join(dir, 'gh-state.json');
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  writeFileSync(stateFile, JSON.stringify(newState()));
  writeFileSync(join(bin, 'gh'), `#!/bin/sh\nexec "${process.execPath}" --experimental-strip-types --no-warnings "${resolve('test/fake-gh.ts')}" "$@"\n`);
  chmodSync(join(bin, 'gh'), 0o755);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_GH_STATE: stateFile };
  const acta = (...args: string[]) => {
    const r = spawnSync(process.execPath, ['--experimental-strip-types', '--no-warnings', resolve('bin/acta.mjs'), ...args], { env, encoding: 'utf8' });
    return { code: r.status, out: r.stdout + r.stderr };
  };
  const state = (): FakeState => JSON.parse(readFileSync(stateFile, 'utf8'));
  const save = (s: FakeState) => writeFileSync(stateFile, JSON.stringify(s));
  return { dir, acta, state, save };
}

test('cli: anchor --github files each witness beside the anchors file; verify --witnesses is clean, then unreachable (exit 2), then WITNESS_REWRITTEN (exit 1)', () => {
  const { dir, acta, state, save } = cliEnv();
  const ledgerDir = join(dir, 'run');
  recordSampleSession(ledgerDir, join(dir, 'sample-anchors.jsonl'));
  const anchors = join(dir, 'out', 'anchors.jsonl');

  const a1 = acta('anchor', ledgerDir, '--to', anchors, '--github', REPO);
  assert.equal(a1.code, 0, a1.out);
  const a2 = acta('anchor', ledgerDir, '--to', anchors, '--github', REPO);
  assert.equal(a2.code, 0, a2.out);

  const wl = join(dir, 'out', 'witnesses.jsonl');
  assert.equal(readWitnessLedger(wl).records.length, 2, 'default ledger sits next to the anchors file');

  const clean = acta('verify', '--witnesses', wl);
  assert.equal(clean.code, 0, clean.out);
  assert.match(clean.out, /CLEAN/);
  const plain = clean.out.replace(/\x1b\[\d+m/g, '');
  assert.equal(plain.split('\n').filter((l) => /^OK\s+[0-9a-f]{12}/.test(l)).length, 2, 'one line per record');

  // an explicit --witness-ledger wins over the default
  const custom = join(dir, 'elsewhere', 'w.jsonl');
  assert.equal(acta('anchor', ledgerDir, '--github', REPO, '--witness-ledger', custom).code, 0);
  assert.equal(readWitnessLedger(custom).records.length, 1);
  assert.equal(readWitnessLedger(join(ledgerDir, 'witnesses.jsonl')).exists, false);

  const s = state();
  s.offline = true;
  save(s);
  const down = acta('verify', '--witnesses', wl);
  assert.equal(down.code, 2, down.out);
  assert.match(down.out, /WITNESS_UNREACHABLE/);

  s.offline = false;
  forcePush(s, REPO, 'main', 'anchors.jsonl', 'rewritten\n');
  save(s);
  const bad = acta('verify', '--witnesses', wl);
  assert.equal(bad.code, 1, bad.out);
  assert.match(bad.out, /WITNESS_REWRITTEN/);
  assert.match(bad.out, /TAMPERED/);
});

test('cli: a damaged witness ledger stops anchor --github before anything is pushed', () => {
  const { dir, acta, state } = cliEnv();
  const ledgerDir = join(dir, 'run');
  recordSampleSession(ledgerDir, join(dir, 'sample-anchors.jsonl'));
  writeFileSync(join(ledgerDir, 'witnesses.jsonl'), 'not a record\n');
  const r = acta('anchor', ledgerDir, '--github', REPO);
  assert.equal(r.code, 1, r.out);
  assert.deepEqual(state().puts, [], 'nothing was pushed');
});

test('cli: witness backup is idempotent and exits 1 on a divergent backup', () => {
  const { dir, acta } = cliEnv();
  const ledgerDir = join(dir, 'run');
  recordSampleSession(ledgerDir, join(dir, 'sample-anchors.jsonl'));
  assert.equal(acta('anchor', ledgerDir, '--github', REPO).code, 0);
  const wl = join(ledgerDir, 'witnesses.jsonl');
  const usb = join(dir, 'usb', 'witnesses.jsonl');

  const b1 = acta('witness', 'backup', wl, '--to', usb);
  assert.equal(b1.code, 0, b1.out);
  assert.match(b1.out, /created/);
  const b2 = acta('witness', 'backup', ledgerDir, '--to', usb); // a directory means <dir>/witnesses.jsonl
  assert.equal(b2.code, 0, b2.out);
  assert.match(b2.out, /already current/);

  const backupBytes = readFileSync(usb, 'utf8');
  writeFileSync(wl, ''); // the local ledger is wiped
  const b3 = acta('witness', 'backup', wl, '--to', usb);
  assert.equal(b3.code, 1, b3.out);
  assert.match(b3.out, /BACKUP_HAS_UNKNOWN_LINES/);
  assert.equal(readFileSync(usb, 'utf8'), backupBytes);

  // the surviving backup, checked on its own, still proves the record
  assert.equal(acta('verify', '--witnesses', usb).code, 0);
});

test('cli: witness add files an existing witness.json only if GitHub confirms it', () => {
  const { dir, acta, state, save } = cliEnv();
  const ledgerDir = join(dir, 'run');
  recordSampleSession(ledgerDir, join(dir, 'sample-anchors.jsonl'));
  const wj = join(dir, 'witness.json');
  assert.equal(acta('anchor', ledgerDir, '--github', REPO, '--witness-out', wj, '--witness-ledger', join(dir, 'first.jsonl')).code, 0);

  const wl = join(dir, 'adopted.jsonl');
  const added = acta('witness', 'add', wj, '--ledger', wl);
  assert.equal(added.code, 0, added.out);
  assert.equal(readWitnessLedger(wl).records.length, 1);
  assert.match(acta('witness', 'add', wj, '--ledger', wl).out, /already in/);

  const forged = JSON.parse(readFileSync(wj, 'utf8')) as GitHubWitness;
  const forgedFile = join(dir, 'forged.json');
  writeFileSync(forgedFile, JSON.stringify({ ...forged, commitSha: 'a'.repeat(40) }));
  const other = join(dir, 'other.jsonl');
  const refused = acta('witness', 'add', forgedFile, '--ledger', other);
  assert.equal(refused.code, 1, refused.out);
  assert.equal(readWitnessLedger(other).exists, false, 'a fabricated witness never reaches the ledger');

  const s = state();
  s.offline = true;
  save(s);
  assert.equal(acta('witness', 'add', wj, '--ledger', other).code, 2, 'no answer is not a yes, and not tamper either');
});
