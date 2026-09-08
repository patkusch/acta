/**
 * Binding calls to definitions. A call made through the proxy names the
 * catalogue it was made under and the digest of its tool's definition there;
 * the verifier follows the reference and recomputes. These tests drive the
 * recorder directly so each case is one ledger with one thing wrong.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { digest } from '../src/canon.ts';
import { Recorder } from '../src/recorder.ts';
import { BLOB_DIR, readLedger } from '../src/ledger.ts';
import { verifyLedger, type Verdict } from '../src/verify.ts';
import { CATALOGUE } from '../src/fixtures/session.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-'));
const codes = (v: Verdict) => v.findings.filter((f) => f.severity !== 'info').map((f) => f.code);
const infos = (v: Verdict) => v.findings.filter((f) => f.severity === 'info').map((f) => f.code);
const shell = CATALOGUE.tools.find((t) => t.name === 'shell')!;

function ledgerWith(inlineLimit: number | undefined, body: (rec: Recorder, catalogue: number) => void) {
  const dir = scratch();
  const rec = Recorder.open(dir, { inlineLimit });
  const listing = rec.call('tools/list', {});
  const catalogue = rec.result(listing, CATALOGUE).seq;
  body(rec, catalogue);
  rec.close();
  const { entries } = readLedger(dir);
  return { dir, entries, keys: undefined, verify: (opts = {}) => verifyLedger(entries, opts) };
}

test('a call bound to the catalogue it was shown verifies with nothing to say', () => {
  const l = ledgerWith(undefined, (rec, catalogue) => {
    const id = rec.call('shell', { cmd: 'ls' }, { def: { seq: catalogue, digest: digest(shell) } });
    rec.result(id, { exit: 0 });
  });
  assert.deepEqual(codes(l.verify()), []);
});

test('a call after a catalogue with no binding is UNBOUND_CALL; one to a tool the catalogue lacks is UNLISTED_TOOL', () => {
  const l = ledgerWith(undefined, (rec) => {
    rec.result(rec.call('shell', { cmd: 'ls' }), { exit: 0 });
    rec.result(rec.call('format_disk', { device: '/dev/sda' }), { exit: 0 });
  });
  const v = l.verify();
  assert.deepEqual(codes(v), ['UNBOUND_CALL', 'UNLISTED_TOOL']);
  assert.notEqual(v.status, 'tampered', 'warnings, not tamper: the record is consistent, just less informative');
});

test('a call made before any catalogue was listed is not flagged', () => {
  const dir = scratch();
  const rec = Recorder.open(dir);
  rec.result(rec.call('shell', { cmd: 'ls' }), { exit: 0 });
  rec.close();
  assert.deepEqual(codes(verifyLedger(readLedger(dir).entries)), []);
});

test('a binding to something that is not a catalogue is BAD_DEF_REF, even when honestly signed', () => {
  const l = ledgerWith(undefined, (rec) => {
    // seq 0 is the genesis, not a tools/list result. The recorder signs it happily;
    // the verifier does not care who signed it.
    rec.result(rec.call('shell', { cmd: 'ls' }, { def: { seq: 0, digest: digest(shell) } }), { exit: 0 });
  });
  const v = l.verify();
  assert.deepEqual(codes(v), ['BAD_DEF_REF']);
  assert.equal(v.status, 'tampered');
});

test('a binding whose digest is not the definition in the cited catalogue is DEF_MISMATCH', () => {
  const l = ledgerWith(undefined, (rec, catalogue) => {
    const sandboxed = { ...shell, description: 'Runs in a sandbox.' };
    rec.result(rec.call('shell', { cmd: 'rm -rf /' }, { def: { seq: catalogue, digest: digest(sandboxed) } }), { exit: 0 });
    // And a binding to a tool the cited catalogue does not define at all.
    rec.result(rec.call('format_disk', {}, { def: { seq: catalogue, digest: digest(shell) } }), { exit: 0 });
  });
  const v = l.verify();
  assert.deepEqual(codes(v), ['DEF_MISMATCH', 'DEF_MISMATCH']);
  assert.equal(v.status, 'tampered');
});

test('a catalogue stored out of line is checked through the blob store, and reported unchecked without it', () => {
  const l = ledgerWith(64, (rec, catalogue) => {
    rec.result(rec.call('shell', { cmd: 'ls' }, { def: { seq: catalogue, digest: digest(shell) } }), { exit: 0 });
  });
  const catalogueEntry = l.entries[2];
  assert.equal(catalogueEntry.kind, 'result');
  assert.equal((catalogueEntry as { body?: unknown }).body, undefined, 'the catalogue went to the blob store');

  const without = l.verify();
  assert.deepEqual(codes(without), []);
  assert.ok(infos(without).includes('DEF_UNCHECKED'), JSON.stringify(without.findings));

  const blob = (d: string) => {
    const p = join(l.dir, BLOB_DIR, d);
    return existsSync(p) ? readFileSync(p) : undefined;
  };
  const withBlob = l.verify({ blob });
  assert.deepEqual(codes(withBlob), []);
  assert.ok(!infos(withBlob).includes('DEF_UNCHECKED'), 'with the body available the binding is actually checked');

  // A wrong binding is caught through the blob store too.
  const wrong = ledgerWith(64, (rec, catalogue) => {
    rec.result(rec.call('shell', { cmd: 'ls' }, { def: { seq: catalogue, digest: digest({ ...shell, description: 'x' }) } }), { exit: 0 });
  });
  const wrongBlob = (d: string) => {
    const p = join(wrong.dir, BLOB_DIR, d);
    return existsSync(p) ? readFileSync(p) : undefined;
  };
  assert.deepEqual(codes(wrong.verify({ blob: wrongBlob })), ['DEF_MISMATCH']);
});
