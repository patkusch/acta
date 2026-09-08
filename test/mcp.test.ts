import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

import { digest } from '../src/canon.ts';
import { readLedger, loadPublicKey, publicKeyFromBase64, PUB_FILE, type Entry } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { readAnchors } from '../src/anchor.ts';

test('the MCP proxy records every tools/call and its response, and anchors on schedule', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'acta-')), 'ledger');
  const anchorTo = join(mkdtempSync(join(tmpdir(), 'acta-anchor-')), 'anchors.jsonl');
  const proxy = spawn(
    process.execPath,
    ['bin/acta.mjs', 'mcp', '--dir', dir, '--anchor-every', '2', '--anchor-to', anchorTo, '--', process.execPath, 'test/fake-mcp-server.mjs'],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
  const stderr: string[] = [];
  createInterface({ input: proxy.stderr }).on('line', (l) => stderr.push(l));

  const responses: Array<Record<string, unknown>> = [];
  const lines = createInterface({ input: proxy.stdout });
  const waitFor = (n: number) =>
    new Promise<void>((resolve) => {
      const check = () => (responses.length >= n ? resolve() : lines.once('line', check));
      check();
    });
  lines.on('line', (l) => responses.push(JSON.parse(l)));

  const send = (m: unknown) => proxy.stdin.write(JSON.stringify(m) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: 'hi' } } });
  send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'explode', arguments: {} } });
  await waitFor(4);
  // Once the catalogue has come back, a call is bound to it; `mutate` also makes
  // the server announce that its definitions changed.
  send({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'mutate', arguments: {} } });
  await waitFor(6); // 5 responses + the list_changed notification
  proxy.stdin.end();
  await new Promise((resolve) => proxy.on('exit', resolve));

  assert.deepEqual(responses.map((r) => r.id), [1, 2, 3, 4, undefined, 5]);
  assert.deepEqual((responses[2].result as { content: { text: string }[] }).content[0].text, 'hi');

  // The first requests were pipelined, so the ledger shows three calls then
  // three results — the order things actually happened in, not the order we'd draw.
  const { entries } = readLedger(dir);
  assert.deepEqual(
    entries.map((e) => e.kind),
    ['open', 'note', 'call', 'call', 'call', 'result', 'result', 'result', 'call', 'note', 'result', 'close'],
  );
  const calls = entries.filter((e): e is Extract<Entry, { kind: 'call' }> => e.kind === 'call');
  assert.deepEqual(calls.map((c) => c.tool), ['tools/list', 'echo', 'explode', 'mutate']);
  assert.deepEqual(calls[1].args, { text: 'hi' });
  const results = entries.filter((e): e is Extract<Entry, { kind: 'result' }> => e.kind === 'result');
  // Each result references its call by the ledger id; explode failed.
  assert.deepEqual(results.map((r) => r.of), calls.map((c) => c.id));
  assert.deepEqual(results.map((r) => r.ok), [true, true, false, true]);
  // The catalogue the agent was shown is in the chain, with the tool definitions verbatim.
  const catalogue = results[0].body as { tools: { name: string }[] };
  assert.deepEqual(catalogue.tools.map((t) => t.name), ['echo', 'explode', 'mutate']);
  // echo and explode were called before the catalogue came back, so they carry no
  // binding; mutate was called after it and is bound to that exact definition.
  assert.equal(calls[1].def, undefined);
  assert.equal(calls[2].def, undefined);
  assert.deepEqual(calls[3].def, { seq: results[0].seq, digest: digest(catalogue.tools[2]) });
  // The server's list_changed is on the record.
  const notes = entries.filter((e): e is Extract<Entry, { kind: 'note' }> => e.kind === 'note');
  assert.ok(notes.some((n) => n.text.startsWith('tools/list_changed')), notes.map((n) => n.text).join('\n'));

  const anchors = readAnchors(anchorTo);
  assert.equal(anchors.length, 2);
  assert.ok(stderr.some((l) => l.startsWith('acta-anchor ')), stderr.join('\n'));

  const v = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)), anchors });
  assert.equal(v.status, 'verified', JSON.stringify(v.findings));
  // The two pipelined calls were made before any catalogue existed, so they are
  // not flagged; nothing else is either.
  assert.deepEqual(v.findings.filter((f) => f.severity !== 'info').map((f) => f.code), []);
});

test('the proxy resumes a crashed run in the same ledger, and the whole thing still verifies', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'acta-')), 'ledger');

  // A helper: run a proxy, drive it, and return once its responses have arrived.
  const drive = (
    extraArgs: string[],
    calls: Array<Record<string, unknown>>,
    onReady: (proxy: ReturnType<typeof spawn>) => void,
  ) =>
    new Promise<void>((resolveDone) => {
      const proxy = spawn(
        process.execPath,
        ['bin/acta.mjs', 'mcp', '--dir', dir, ...extraArgs, '--', process.execPath, 'test/fake-mcp-server.mjs'],
        { stdio: ['pipe', 'pipe', 'pipe'] },
      );
      const responses: Array<Record<string, unknown>> = [];
      const lines = createInterface({ input: proxy.stdout });
      lines.on('line', (l) => {
        responses.push(JSON.parse(l));
        if (responses.length >= calls.length) onReady(proxy);
      });
      proxy.on('exit', () => resolveDone());
      for (const m of calls) proxy.stdin!.write(JSON.stringify(m) + '\n');
    });

  // First run: list, one call, then the recorder is killed mid-flight — no clean close.
  await drive(
    [],
    [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: 'first' } } },
    ],
    (proxy) => proxy.kill('SIGKILL'),
  );

  const crashed = readLedger(dir).entries;
  assert.ok(!crashed.some((e) => e.kind === 'close'), 'a killed proxy leaves no close entry');

  // Second run against the same dir with --resume: it continues rather than refusing.
  await drive(
    ['--resume'],
    [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'second' } } },
    ],
    (proxy) => proxy.stdin!.end(), // clean shutdown this time -> close entry
  );

  const { entries } = readLedger(dir);
  const kinds = entries.map((e) => e.kind);
  assert.ok(kinds.includes('resume'), 'the resume marker is in the chain');
  assert.equal(kinds[kinds.length - 1], 'close', 'and the second run closed cleanly');
  const echoes = entries.filter((e): e is Extract<Entry, { kind: 'call' }> => e.kind === 'call' && e.tool === 'echo');
  assert.deepEqual(echoes.map((c) => (c.args as { text: string }).text), ['first', 'second'], 'both runs are in one ledger');
  // The second run never listed the tools, but the definitions in force are the
  // ones run one recorded, so its call is bound to that catalogue — read back
  // from the ledger on resume, not guessed.
  const listing = entries.find((e): e is Extract<Entry, { kind: 'call' }> => e.kind === 'call' && e.tool === 'tools/list')!;
  const catalogue = entries.find((e): e is Extract<Entry, { kind: 'result' }> => e.kind === 'result' && e.of === listing.id)!;
  assert.equal(echoes[1].def?.seq, catalogue.seq, 'the post-resume call is bound to the pre-crash catalogue');
  assert.equal(echoes[1].def?.digest, digest((catalogue.body as { tools: unknown[] }).tools[0]));

  const v = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)) });
  assert.notEqual(v.status, 'tampered', JSON.stringify(v.findings));
});

test('--rotate-on-resume retires the pre-crash key; the original still verifies the whole chain', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'acta-')), 'ledger');
  const drive = (extraArgs: string[], calls: Array<Record<string, unknown>>, onReady: (p: ReturnType<typeof spawn>) => void) =>
    new Promise<void>((resolveDone) => {
      const proxy = spawn(
        process.execPath,
        ['bin/acta.mjs', 'mcp', '--dir', dir, ...extraArgs, '--', process.execPath, 'test/fake-mcp-server.mjs'],
        { stdio: ['pipe', 'pipe', 'pipe'] },
      );
      const responses: Array<Record<string, unknown>> = [];
      createInterface({ input: proxy.stdout }).on('line', (l) => {
        responses.push(JSON.parse(l));
        if (responses.length >= calls.length) onReady(proxy);
      });
      proxy.on('exit', () => resolveDone());
      for (const m of calls) proxy.stdin!.write(JSON.stringify(m) + '\n');
    });

  await drive(
    [],
    [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'before' } } },
    ],
    (proxy) => proxy.kill('SIGKILL'),
  );

  // Capture the pre-crash public key out of band, before the rotation overwrites it.
  const genesisPub = readFileSync(join(dir, PUB_FILE), 'utf8');

  await drive(
    ['--rotate-on-resume'],
    [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'after' } } },
    ],
    (proxy) => proxy.stdin!.end(),
  );

  const { entries } = readLedger(dir);
  assert.ok(entries.some((e) => e.kind === 'rotate'), 'the resume rotated to a fresh key');
  // The key file on disk is now the fresh key, not the genesis one.
  assert.notEqual(readFileSync(join(dir, PUB_FILE), 'utf8'), genesisPub, 'the pre-crash key was retired on disk');

  // Verified against the ORIGINAL key, captured before the rotation, across the handover.
  const v = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)) });
  assert.equal(v.status, 'tampered', 'the retired key no longer verifies the genesis it did not sign');
  const original = publicKeyFromBase64((entries[0] as Extract<Entry, { kind: 'open' }>).pub);
  const good = verifyLedger(entries, { trustedKey: original });
  assert.notEqual(good.status, 'tampered', `the original key verifies across the rotation: ${JSON.stringify(good.findings)}`);
});
