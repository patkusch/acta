import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSampleSession } from '../src/fixtures/session.ts';
import { readLedger } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { readGitAnchors, writeGitAnchor } from '../src/anchor.ts';
import { ATTACKS } from '../src/attacks.ts';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-'));

test('anchors round-trip through git notes and catch truncation', () => {
  const repo = scratch();
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: 'acta-test',
    GIT_AUTHOR_EMAIL: 'acta@test',
    GIT_COMMITTER_NAME: 'acta-test',
    GIT_COMMITTER_EMAIL: 'acta@test',
  };
  const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-q');
  writeFileSync(join(repo, 'README'), 'hello');
  git('add', 'README');
  git('commit', '-q', '-m', 'first');

  assert.deepEqual(readGitAnchors({ cwd: repo }), [], 'no notes ref yet means no anchors, not an error');

  process.env.GIT_AUTHOR_NAME = process.env.GIT_COMMITTER_NAME = 'acta-test';
  process.env.GIT_AUTHOR_EMAIL = process.env.GIT_COMMITTER_EMAIL = 'acta@test';
  const s = recordSampleSession(scratch(), join(scratch(), 'unused.jsonl'));
  for (const a of s.anchors) writeGitAnchor(a, { cwd: repo });
  writeGitAnchor({ ...s.anchors[0], seq: 1, hash: 'f'.repeat(64), session: 'someone-else' }, { cwd: repo });

  const anchors = readGitAnchors({ cwd: repo });
  assert.equal(anchors.length, 2);
  assert.deepEqual(anchors[0], s.anchors[0]);

  const genuine = readLedger(s.dir).entries;
  assert.equal(verifyLedger(genuine, { trustedKey: s.keys.publicKey, anchors }).status, 'verified');

  const truncate = ATTACKS.find((a) => a.name === 'truncate')!;
  const v = verifyLedger(truncate.apply(genuine, s).entries, { trustedKey: s.keys.publicKey, anchors });
  assert.equal(v.status, 'tampered');
  assert.ok(v.findings.some((f) => f.code === 'TRUNCATED'));
});
