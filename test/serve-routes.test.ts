import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { recordStep } from '../src/step.ts';
import { LEDGER_FILE, PUB_FILE, loadPublicKey, publicKeyToBase64 } from '../src/ledger.ts';
import { makeServer } from '../src/serve.ts';
import { STAGES } from '../src/step.ts';

/** The public checker's routes, one by one, on a real server on this machine's loopback address. */

let server: Server;
let base: string;
let dir: string;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'acta-serve-'));
  recordStep(dir, { agent: 'fixer', stage: 'verify', action: 'ran tests' });
  server = makeServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

const ledger = () => readFileSync(join(dir, LEDGER_FILE), 'utf8');

test('/healthz says it is alive', async () => {
  const r = await fetch(`${base}/healthz`);
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { ok: true });
});

test('the front page explains how to use it and lists the recorded stages', async () => {
  const r = await fetch(`${base}/`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type') ?? '', /^text\/html/);
  const page = await r.text();
  assert.match(page, /POST a ledger\.jsonl body to <code>\/verify<\/code>/);
  assert.match(page, /\?key=BASE64_PUBLIC_KEY/);
  for (const stage of STAGES) assert.ok(page.includes(stage), stage);
});

test('anything else is a JSON 404', async () => {
  for (const [method, path] of [['GET', '/nope'], ['GET', '/verify'], ['POST', '/elsewhere'], ['DELETE', '/']] as const) {
    const r = await fetch(`${base}${path}`, { method });
    assert.equal(r.status, 404, `${method} ${path}`);
    assert.deepEqual(await r.json(), { error: 'not found' });
  }
});

test('a good ledger with no key is "consistent", never "verified", and a good key lets the checker say more', async () => {
  const noKey = (await (await fetch(`${base}/verify`, { method: 'POST', body: ledger() })).json()) as { status: string; findings: { code: string }[] };
  assert.equal(noKey.status, 'consistent');
  assert.ok(noKey.findings.some((f) => f.code === 'SELF_ATTESTED_KEY'));
  const key = publicKeyToBase64(loadPublicKey(join(dir, PUB_FILE)));
  const withKey = (await (await fetch(`${base}/verify?key=${encodeURIComponent(key)}`, { method: 'POST', body: ledger() })).json()) as { status: string; findings: { code: string }[] };
  assert.notEqual(withKey.status, 'tampered');
  assert.ok(!withKey.findings.some((f) => f.code === 'SELF_ATTESTED_KEY'), 'the key the caller holds replaces the self-declared one');
});

test('a ledger that was edited is reported as tampered, with a 200 because the check itself worked', async () => {
  const edited = ledger().replace('ran tests', 'ran nothing');
  const r = await fetch(`${base}/verify`, { method: 'POST', body: edited });
  assert.equal(r.status, 200);
  assert.equal(((await r.json()) as { status: string }).status, 'tampered');
});

test('an empty body or text that is not a ledger gets an answer, not a crash', async () => {
  for (const body of ['', 'not a ledger at all', '{"half":']) {
    const r = await fetch(`${base}/verify`, { method: 'POST', body });
    assert.ok([200, 400].includes(r.status), `${r.status} for ${JSON.stringify(body)}`);
    const data = (await r.json()) as { status?: string; error?: string };
    assert.ok(data.status === 'tampered' || data.status === 'empty' || typeof data.error === 'string', JSON.stringify(data));
  }
});

test('a key that is not a key is a 400 with a plain message', async () => {
  const r = await fetch(`${base}/verify?key=${encodeURIComponent('not-a-key')}`, { method: 'POST', body: ledger() });
  assert.equal(r.status, 400);
  assert.equal(typeof ((await r.json()) as { error: string }).error, 'string');
});

test('a body over five megabytes is refused with 413 before it is checked', async () => {
  const big = 'x'.repeat(5 * 1024 * 1024 + 1024);
  let status: number | undefined;
  try {
    const r = await fetch(`${base}/verify`, { method: 'POST', body: big });
    status = r.status;
  } catch {
    status = 413; // the server may close the connection as soon as the limit is passed
  }
  assert.equal(status, 413);
});
