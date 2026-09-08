/**
 * A scripted agent session, recorded for real through the Recorder. Every
 * attack in the catalogue and every test runs against a ledger produced here,
 * so the mutations are applied to genuine output rather than to hand-written
 * JSON that might not resemble it.
 *
 * The story: an agent is asked to fix a flaky test. Along the way it deletes
 * a directory (with approval noted) and posts to a webhook. Those are the two
 * actions an attacker would most like to make disappear.
 */
import type { KeyObject } from 'node:crypto';

import { digest } from '../canon.ts';
import { Recorder } from '../recorder.ts';
import { loadOrCreateKeys } from '../ledger.ts';
import type { Anchor } from '../anchor.ts';

export interface SampleSession {
  dir: string;
  session: string;
  keys: { privateKey: KeyObject; publicKey: KeyObject };
  anchorPath: string;
  anchors: Anchor[];
  /** Sequence numbers worth knowing for attacks. */
  marks: { catalogue: number; delete: number; deleteResult: number; approval: number; webhook: number; anchoredAt: number };
}

/** What the agent was told its tools do. `shell` is honest about not being sandboxed. */
export const CATALOGUE = {
  tools: [
    { name: 'read_file', description: 'Read a file from the workspace.', inputSchema: { type: 'object', properties: { path: { type: 'string' } } } },
    { name: 'run_tests', description: 'Run the test suite, optionally filtered by name.', inputSchema: { type: 'object', properties: { filter: { type: 'string' } } } },
    { name: 'edit_file', description: 'Replace a string in a file.', inputSchema: { type: 'object', properties: { path: { type: 'string' }, replace: { type: 'string' }, with: { type: 'string' } } } },
    { name: 'shell', description: 'Run a shell command in the workspace. Not sandboxed: it can delete anything the user can.', inputSchema: { type: 'object', properties: { cmd: { type: 'string' } } } },
    { name: 'http_post', description: 'POST a JSON body to a URL.', inputSchema: { type: 'object', properties: { url: { type: 'string' }, body: { type: 'object' } } } },
    { name: 'git_commit', description: 'Commit the working tree with a message.', inputSchema: { type: 'object', properties: { message: { type: 'string' } } } },
  ],
};

export function recordSampleSession(dir: string, anchorPath: string, keys?: SampleSession['keys']): SampleSession {
  let t = Date.UTC(2026, 8, 2, 21, 0, 0);
  const clock = () => new Date((t += 1000));
  const rec = Recorder.open(dir, { session: 'flaky-test-fix', actor: 'coding-agent', clock, keys });
  const realKeys = keys ?? loadOrCreateKeys(dir);

  rec.note('task: fix the flaky test in billing/');

  // The catalogue the agent was shown goes into the chain first, and every
  // call after it is bound to the definition it was made against.
  let id = rec.call('tools/list', {});
  const catalogue = rec.result(id, CATALOGUE).seq;
  const defs = new Map(CATALOGUE.tools.map((t) => [t.name, { seq: catalogue, digest: digest(t) }]));
  const call = (tool: string, args: unknown) => rec.call(tool, args, { def: defs.get(tool) });

  id = call('read_file', { path: 'src/billing/invoice.ts' });
  rec.result(id, { text: 'export function total(lines) { return lines.reduce((a, l) => a + l.amount, 0) }' });

  id = call('run_tests', { filter: 'billing' });
  rec.result(id, { passed: 11, failed: 1, failing: ['rounds to cents'] }, { ok: false });

  id = call('edit_file', {
    path: 'src/billing/invoice.ts',
    replace: 'a + l.amount',
    with: 'Math.round((a + l.amount) * 100) / 100',
  });
  rec.result(id, { ok: true });

  id = call('run_tests', { filter: 'billing' });
  rec.result(id, { passed: 12, failed: 0 });

  const approval = rec.head.seq + 1;
  rec.note('operator approved: "yes, delete the old fixture directory"');

  const del = rec.head.seq + 1;
  id = call('shell', { cmd: 'rm -rf test/fixtures/old' });
  const deleteResult = rec.head.seq + 1;
  rec.result(id, { exit: 0, stdout: '' });

  const webhook = rec.head.seq + 1;
  id = call('http_post', { url: 'https://hooks.example/notify', body: { status: 'fixed', tests: 12 } });
  rec.result(id, { status: 200 });

  const anchors = [rec.anchor(anchorPath)];
  const anchoredAt = rec.head.seq;

  id = call('git_commit', { message: 'Round invoice totals to cents' });
  rec.result(id, { sha: '9f1c2ab' });

  rec.close();

  return {
    dir,
    session: rec.session,
    keys: realKeys,
    anchorPath,
    anchors,
    marks: { catalogue, delete: del, deleteResult, approval, webhook, anchoredAt },
  };
}
