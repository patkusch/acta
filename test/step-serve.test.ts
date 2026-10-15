import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { recordStep, closeSession } from '../src/step.ts';
import { readLedger, LEDGER_FILE, PUB_FILE, loadPublicKey, publicKeyToBase64 } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { makeServer } from '../src/serve.ts';

const tmp = () => mkdtempSync(join(tmpdir(), 'acta-step-'));

test('steps from separate jobs form one verifiable ledger', () => {
  const dir = tmp();
  recordStep(dir, { agent: 'planner', stage: 'plan', action: 'split issue 7 into two tasks' });
  recordStep(dir, { agent: 'fixer', stage: 'secure', action: 'patched a finding', ref: 'mr!5' });
  closeSession(dir);
  const { entries, problems } = readLedger(dir);
  const v = verifyLedger(entries, { problems, trustedKey: loadPublicKey(join(dir, PUB_FILE)) });
  assert.notEqual(v.status, 'tampered');
  assert.ok(entries.some((e) => e.kind === 'resume'), 'the restart is on the record');
  assert.equal(entries.filter((e) => e.kind === 'call').length, 2);
});

test('an unknown stage is refused', () => {
  assert.throws(() => recordStep(tmp(), { agent: 'a', stage: 'nap' as never, action: 'x' }), /unknown stage/);
});

test('the checker says tampered when a line is edited', async () => {
  const dir = tmp();
  recordStep(dir, { agent: 'fixer', stage: 'verify', action: 'ran tests' });
  const path = join(dir, LEDGER_FILE);
  const good = readFileSync(path, 'utf8');
  const server = makeServer().listen(0);
  const port = (server.address() as AddressInfo).port;
  try {
    const key = publicKeyToBase64(loadPublicKey(join(dir, PUB_FILE)));
    const ok = await (await fetch(`http://127.0.0.1:${port}/verify?key=${encodeURIComponent(key)}`, { method: 'POST', body: good })).json();
    assert.notEqual((ok as { status: string }).status, 'tampered');
    const bad = await (await fetch(`http://127.0.0.1:${port}/verify`, { method: 'POST', body: good.replace('ran tests', 'ran nothing') })).json();
    assert.equal((bad as { status: string }).status, 'tampered');
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
  } finally {
    server.close();
  }
  writeFileSync(path, good);
});
