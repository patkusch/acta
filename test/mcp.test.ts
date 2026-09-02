import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

import { readLedger, loadPublicKey, PUB_FILE, type Entry } from '../src/ledger.ts';
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
  proxy.stdin.end();
  await new Promise((resolve) => proxy.on('exit', resolve));

  assert.deepEqual(responses.map((r) => r.id), [1, 2, 3, 4]);
  assert.deepEqual((responses[2].result as { content: { text: string }[] }).content[0].text, 'hi');

  // The requests were pipelined, so the ledger shows three calls then three
  // results — the order things actually happened in, not the order we'd draw.
  const { entries } = readLedger(dir);
  assert.deepEqual(
    entries.map((e) => e.kind),
    ['open', 'note', 'call', 'call', 'call', 'result', 'result', 'result', 'close'],
  );
  const calls = entries.filter((e): e is Extract<Entry, { kind: 'call' }> => e.kind === 'call');
  assert.deepEqual(calls.map((c) => c.tool), ['tools/list', 'echo', 'explode']);
  assert.deepEqual(calls[1].args, { text: 'hi' });
  const results = entries.filter((e): e is Extract<Entry, { kind: 'result' }> => e.kind === 'result');
  assert.deepEqual(results.map((r) => [r.of, r.ok]), [['rpc-2', true], ['rpc-3', true], ['rpc-4', false]]);
  // The catalogue the agent was shown is in the chain, with the tool definitions verbatim.
  const catalogue = results[0].body as { tools: { name: string }[] };
  assert.deepEqual(catalogue.tools.map((t) => t.name), ['echo', 'explode']);

  const anchors = readAnchors(anchorTo);
  assert.equal(anchors.length, 1);
  assert.ok(stderr.some((l) => l.startsWith('acta-anchor ')), stderr.join('\n'));

  const v = verifyLedger(entries, { trustedKey: loadPublicKey(join(dir, PUB_FILE)), anchors });
  assert.equal(v.status, 'verified', JSON.stringify(v.findings));
});
