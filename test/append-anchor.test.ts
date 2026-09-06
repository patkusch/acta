/**
 * The append-only anchor sink. The property under test is narrow and it is the
 * whole point: once an anchor is written, the kernel will not let it be removed
 * or rewritten — only appended past. That is exactly the strength an anchor sink
 * needs and no more, because anchors are monotonic evidence. An attacker holding
 * the recorder's key can append a forged anchor that matches their rewritten
 * ledger, but they cannot delete the honest one, and one surviving honest anchor
 * is enough to convict the rewrite.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  appendOnlySupport,
  isAppendOnly,
  writeAppendOnlyAnchor,
  readAnchors,
  type Anchor,
} from '../src/anchor.ts';
import { recordSampleSession } from '../src/fixtures/session.ts';
import { readLedger } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { ATTACKS } from '../src/attacks.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-ao-'));
const support = appendOnlySupport();

// Clear the flag so the scratch file can be cleaned up and the test re-run.
function unflag(path: string): void {
  try {
    execFileSync('chflags', ['nouappnd', path]);
  } catch {
    /* best effort */
  }
}

test('the sink appends, reports its own flag, and the kernel refuses to rewrite it', { skip: !support.supported && `unsupported on ${support.platform}` }, () => {
  const path = join(scratch(), 'anchors.jsonl');
  const a1: Anchor = { session: 's', seq: 3, hash: 'a'.repeat(64), at: '2026-09-06T00:00:00.000Z' };
  const a2: Anchor = { session: 's', seq: 7, hash: 'b'.repeat(64), at: '2026-09-06T00:01:00.000Z' };

  assert.equal(isAppendOnly(path), false, 'an absent file reads as unprotected, not an error');

  writeAppendOnlyAnchor(path, a1);
  assert.equal(isAppendOnly(path), true, 'first write sets the flag');

  writeAppendOnlyAnchor(path, a2);
  assert.deepEqual(readAnchors(path), [a1, a2], 'appends are allowed while flagged');

  assert.throws(() => writeFileSync(path, 'clobbered'), /EPERM|not permitted/i, 'truncating overwrite is refused by the kernel');
  assert.throws(() => rmSync(path), /EPERM|not permitted/i, 'unlink is refused by the kernel');
  assert.deepEqual(readAnchors(path), [a1, a2], 'and the anchors are still there after both attempts');

  unflag(path);
});

test('a surviving honest anchor convicts a full rewrite even when the attacker appends a matching forgery', { skip: !support.supported && `unsupported on ${support.platform}` }, () => {
  const dir = scratch();
  const s = recordSampleSession(dir, join(scratch(), 'plain.jsonl'));
  const honest = readLedger(dir).entries;

  // Operator takes the anchor into an append-only sink, out of the agent's reach.
  const sink = join(scratch(), 'anchors.jsonl');
  for (const a of s.anchors) writeAppendOnlyAnchor(sink, a);
  assert.equal(isAppendOnly(sink), true);

  // Attacker holds the real key: narrow the delete, rechain, re-sign everything.
  const attack = ATTACKS.find((x) => x.name === 'rewrite with the real key')!;
  const doctored = attack.apply(honest, s).entries;

  // The rewrite has a new head hash. The attacker appends an anchor that matches
  // it — the sink permits that. It does not help them: the honest anchor remains.
  const forged: Anchor = { session: s.session, seq: doctored.length - 1, hash: doctored[doctored.length - 1].hash, at: '2026-09-06T00:05:00.000Z' };
  writeAppendOnlyAnchor(sink, forged);

  const verdict = verifyLedger(doctored, { trustedKey: s.keys.publicKey, anchors: readAnchors(sink) });
  assert.equal(verdict.status, 'tampered', 'the rewrite is caught despite passing every signature check');
  assert.ok(
    verdict.findings.some((f) => f.code === 'ANCHOR_MISMATCH' || f.code === 'TRUNCATED'),
    'because a surviving honest anchor no longer matches the ledger it anchored',
  );

  // And the attacker's only escape — deleting the honest anchor — is refused.
  assert.throws(() => writeFileSync(sink, ''), /EPERM|not permitted/i);

  unflag(sink);
});
