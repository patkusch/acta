/**
 * Unit tests for the GitHub anchor sink and its witness check. Both talk to
 * `gh` through an injectable `ghExec`, so these run offline and are part of
 * `npm test`. They do not touch the network or a real repository.
 *
 * The one real end-to-end push — a genuine commit to a real public repo,
 * fetched back and verified for real, plus a real tamper case against the
 * actual GitHub API — is a separate, documented manual step (see the
 * "Public anchor witness" section of the README). It needs `gh` authenticated
 * against a real account and a real repo to push to, so it is not run here.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { writeGitHubAnchor, verifyGitHubWitness, parseRepoSpec, type GhExec } from '../src/github-anchor.ts';
import type { Anchor } from '../src/anchor.ts';

const anchorA: Anchor = { session: 'flaky-test-fix', seq: 3, hash: 'a'.repeat(64), at: '2026-09-16T09:00:00.000Z' };
const anchorB: Anchor = { session: 'flaky-test-fix', seq: 9, hash: 'b'.repeat(64), at: '2026-09-16T09:05:00.000Z' };

/**
 * A tiny in-memory stand-in for the slice of the GitHub contents/commits API
 * this module uses. It stores one blob (whatever was last written) per
 * branch and remembers every commit it has ever produced by its own fake
 * SHA, so `?ref=<branch>` and `?ref=<sha>` behave the way the real API does:
 * the branch pointer moves, but a commit already handed out stays fetchable
 * by its SHA.
 */
function fakeGitHub() {
  let counter = 0;
  const commits = new Map<string, { content: string; date: string; path: string }>();
  const branchHead = new Map<string, string>(); // "repo@branch@path" -> sha

  const exec: GhExec = (args, input) => {
    if (args[0] !== 'api') throw new Error(`unexpected gh subcommand: ${args[0]}`);
    const isPut = args.includes('-X') && args[args.indexOf('-X') + 1] === 'PUT';
    if (isPut) {
      const target = args[1];
      const m = /^repos\/([^/]+\/[^/]+)\/contents\/(.+)$/.exec(target);
      if (!m) throw new Error(`unexpected PUT target: ${target}`);
      const [, repo, path] = m;
      const body = JSON.parse(input ?? '{}') as { content: string; branch: string; sha?: string };
      counter += 1;
      const sha = `sha-${counter}`;
      const date = new Date(Date.UTC(2026, 8, 16, 12, 0, counter)).toISOString();
      commits.set(sha, { content: body.content, date, path });
      branchHead.set(`${repo}@${body.branch}@${path}`, sha);
      return JSON.stringify({ commit: { sha, committer: { date } } });
    }
    const target = args[1];
    const contentsMatch = /^repos\/([^/]+\/[^/]+)\/contents\/([^?]+)\?ref=(.+)$/.exec(target);
    if (contentsMatch) {
      const [, repo, path, ref] = contentsMatch;
      if (commits.has(ref)) {
        const c = commits.get(ref)!;
        return JSON.stringify({ sha: ref, content: c.content });
      }
      const sha = branchHead.get(`${repo}@${ref}@${path}`);
      if (!sha) throw new Error('404 Not Found');
      const c = commits.get(sha)!;
      return JSON.stringify({ sha, content: c.content });
    }
    const commitMatch = /^repos\/([^/]+\/[^/]+)\/commits\/(.+)$/.exec(target);
    if (commitMatch) {
      const [, , sha] = commitMatch;
      const c = commits.get(sha);
      if (!c) throw new Error('404 Not Found');
      return JSON.stringify({ commit: { committer: { date: c.date } } });
    }
    throw new Error(`unexpected GET target: ${target}`);
  };

  /** Move a branch pointer to a fabricated commit that was never really written, the way a force-push would. */
  const forcePush = (repo: string, branch: string, path: string, sha: string) => branchHead.set(`${repo}@${branch}@${path}`, sha);

  return { exec, forcePush };
}

test('parseRepoSpec splits owner/name from an optional :branch', () => {
  assert.deepEqual(parseRepoSpec('patkusch/acta-anchors'), { repo: 'patkusch/acta-anchors' });
  assert.deepEqual(parseRepoSpec('patkusch/acta-anchors:main'), { repo: 'patkusch/acta-anchors', branch: 'main' });
});

test('writeGitHubAnchor creates the file on first write and appends on the next, never dropping the earlier line', () => {
  const { exec } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };

  const w1 = writeGitHubAnchor(anchorA, opts);
  assert.equal(w1.provider, 'github');
  assert.equal(w1.line, 0);
  assert.equal(w1.anchor.hash, anchorA.hash);
  assert.ok(w1.commitSha);
  assert.ok(w1.committedAt);

  const w2 = writeGitHubAnchor(anchorB, opts);
  assert.equal(w2.line, 1, 'the second anchor lands on the next line, after the first');
  assert.notEqual(w2.commitSha, w1.commitSha, 'each write is its own commit');

  // Both witnesses independently check out, including the first one, even
  // though the branch has since moved past the commit it points at — because
  // verification is pinned to the commit SHA, not the branch.
  assert.equal(verifyGitHubWitness(w1, { ghExec: exec }).ok, true);
  assert.equal(verifyGitHubWitness(w2, { ghExec: exec }).ok, true);
});

test('append-only is enforced in code: the pushed content always extends the exact bytes read back from GitHub, never replaces them', () => {
  const existingLine = `acta-anchor session=other seq=0 hash=${'c'.repeat(64)} at=2026-01-01T00:00:00.000Z`;
  let putCalled = false;

  const exec: GhExec = (args, input) => {
    const isGet = args[0] === 'api' && !args.includes('-X');
    if (isGet) {
      return JSON.stringify({ sha: 'existing-sha', content: Buffer.from(existingLine + '\n').toString('base64') });
    }
    const body = JSON.parse(input!) as { content: string };
    const decoded = Buffer.from(body.content, 'base64').toString('utf8');
    assert.ok(decoded.startsWith(existingLine), 'new content must extend the existing file, not replace it');
    putCalled = true;
    return JSON.stringify({ commit: { sha: 'new-sha', committer: { date: '2026-09-16T12:00:00.000Z' } } });
  };

  const w = writeGitHubAnchor(anchorA, { repo: 'patkusch/acta-anchors', ghExec: exec });
  assert.equal(putCalled, true);
  assert.equal(w.line, 1, 'the existing line counts, so the new anchor is line 1, not 0');
});

test('verifyGitHubWitness rejects a witness pointing at a commit that does not exist', () => {
  const { exec } = fakeGitHub();
  const forged: import('../src/github-anchor.ts').GitHubWitness = {
    provider: 'github',
    repo: 'patkusch/acta-anchors',
    branch: 'main',
    path: 'anchors.jsonl',
    commitSha: 'sha-does-not-exist',
    committedAt: '2026-09-16T12:00:00.000Z',
    line: 0,
    anchor: anchorA,
  };
  const check = verifyGitHubWitness(forged, { ghExec: exec });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'WITNESS_COMMIT_NOT_FOUND'));
});

test('verifyGitHubWitness rejects a witness whose claimed line does not match what the commit actually holds', () => {
  const { exec } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };
  const w = writeGitHubAnchor(anchorA, opts);

  const tampered = { ...w, anchor: anchorB }; // same commit, but claims it holds a different anchor
  const check = verifyGitHubWitness(tampered, { ghExec: exec });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'WITNESS_CONTENT_MISMATCH'));
});

test('verifyGitHubWitness rejects a witness pointing past the end of the file at that commit', () => {
  const { exec } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };
  const w = writeGitHubAnchor(anchorA, opts);

  const tampered = { ...w, line: 5 };
  const check = verifyGitHubWitness(tampered, { ghExec: exec });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'WITNESS_LINE_MISSING'));
});

test('verifyGitHubWitness rejects a witness whose recorded timestamp does not match the commit GitHub actually reports', () => {
  const { exec } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };
  const w = writeGitHubAnchor(anchorA, opts);

  const tampered = { ...w, committedAt: '1999-01-01T00:00:00.000Z' };
  const check = verifyGitHubWitness(tampered, { ghExec: exec });
  assert.equal(check.ok, false);
  assert.ok(check.findings.some((f) => f.code === 'WITNESS_TIMESTAMP_MISMATCH'));
});

test('a witness still verifies after a later, honest write moves the branch on — pinning to the commit SHA is the point', () => {
  const { exec } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };
  const w1 = writeGitHubAnchor(anchorA, opts);
  writeGitHubAnchor(anchorB, opts); // branch head moves on

  assert.equal(verifyGitHubWitness(w1, { ghExec: exec }).ok, true, 'the earlier commit is still fetchable by SHA even though the branch has moved past it');
});

test('the documented limitation: a force-push that discards the commit outright is not caught by this module alone', () => {
  const { exec, forcePush } = fakeGitHub();
  const opts = { repo: 'patkusch/acta-anchors', branch: 'main', path: 'anchors.jsonl', ghExec: exec };
  const w = writeGitHubAnchor(anchorA, opts);

  // Simulate the branch being force-pushed to a fabricated commit; the old
  // commit is no longer reachable from the branch at all (as it would not be
  // from a fresh clone once garbage-collected). A witness re-check by SHA
  // still succeeds here because our fake never actually deletes a commit —
  // exactly the honest boundary the README documents: this sink catches a
  // branch rewrite only for as long as the discarded commit is still
  // fetchable by SHA, which is not forever, and not guaranteed.
  forcePush('patkusch/acta-anchors', 'main', 'anchors.jsonl', 'sha-fabricated-by-attacker');
  const check = verifyGitHubWitness(w, { ghExec: exec });
  assert.equal(check.ok, true, 'still fetchable by SHA — this is exactly the limit the README states, not a bug');
});
