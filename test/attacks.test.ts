/**
 * The attack catalogue, asserted. For every attack, which verifier
 * configuration catches it — and, just as deliberately, which does not.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSampleSession } from '../src/fixtures/session.ts';
import { ATTACKS } from '../src/attacks.ts';
import { readLedger } from '../src/ledger.ts';
import { verifyLedger, type Verdict } from '../src/verify.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-'));

const s = recordSampleSession(scratch(), join(scratch(), 'anchors.jsonl'));
const genuine = readLedger(s.dir).entries;

const codes = (v: Verdict) => v.findings.filter((f) => f.severity === 'tamper').map((f) => f.code);

/** What each verifier configuration is expected to catch. `[]` means: not caught. */
const EXPECTED: Record<string, { chain: string[]; key: string[]; anchor: string[] }> = {
  'edit in place': { chain: ['HASH_MISMATCH'], key: ['HASH_MISMATCH'], anchor: ['HASH_MISMATCH'] },
  'delete the entry': { chain: ['SEQ_BREAK', 'CHAIN_BREAK'], key: ['SEQ_BREAK', 'CHAIN_BREAK'], anchor: ['SEQ_BREAK', 'CHAIN_BREAK'] },
  reorder: { chain: ['SEQ_BREAK', 'CHAIN_BREAK'], key: ['SEQ_BREAK', 'CHAIN_BREAK'], anchor: ['SEQ_BREAK', 'CHAIN_BREAK'] },
  truncate: { chain: [], key: [], anchor: ['TRUNCATED'] },
  'forge an approval': { chain: ['BAD_SIGNATURE', 'AFTER_CLOSE'], key: ['BAD_SIGNATURE', 'AFTER_CLOSE'], anchor: ['BAD_SIGNATURE', 'AFTER_CLOSE'] },
  'edit and rechain': { chain: ['BAD_SIGNATURE'], key: ['BAD_SIGNATURE'], anchor: ['BAD_SIGNATURE'] },
  'rewrite under own key': { chain: [], key: ['KEY_MISMATCH', 'BAD_SIGNATURE'], anchor: ['KEY_MISMATCH', 'BAD_SIGNATURE'] },
  'rewrite with the real key': { chain: [], key: [], anchor: ['ANCHOR_MISMATCH'] },
  'lose the outcome, real key': { chain: [], key: [], anchor: ['ANCHOR_MISMATCH'] },
  'after the last anchor, real key': { chain: [], key: [], anchor: [] },
};

test('the genuine ledger is verified', () => {
  const v = verifyLedger(genuine, { trustedKey: s.keys.publicKey, anchors: s.anchors });
  assert.equal(v.status, 'verified', JSON.stringify(v.findings));
});

test('every attack in the catalogue is in the expectation table', () => {
  assert.deepEqual(
    ATTACKS.map((a) => a.name),
    Object.keys(EXPECTED),
  );
});

for (const attack of ATTACKS) {
  test(`attack: ${attack.name} (${attack.needs})`, () => {
    const doctored = attack.apply(genuine, s);
    const expected = EXPECTED[attack.name];

    const chain = verifyLedger(doctored.entries);
    const key = verifyLedger(doctored.entries, { trustedKey: s.keys.publicKey });
    const anchor = verifyLedger(doctored.entries, { trustedKey: s.keys.publicKey, anchors: s.anchors });

    for (const [label, verdict, want] of [
      ['chain only', chain, expected.chain],
      ['chain + key', key, expected.key],
      ['chain + key + anchor', anchor, expected.anchor],
    ] as const) {
      const got = [...new Set(codes(verdict))];
      if (want.length === 0) {
        assert.equal(verdict.status === 'tampered', false, `${label}: expected NOT caught, got ${got.join(',')}`);
      } else {
        assert.equal(verdict.status, 'tampered', `${label}: expected caught`);
        for (const code of want) assert.ok(got.includes(code), `${label}: expected ${code}, got ${got.join(',')}`);
      }
    }
  });
}
