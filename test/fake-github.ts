/**
 * A small in-memory stand-in for the slice of the GitHub contents/commits API
 * that acta uses, shared by the unit tests (as an injected `ghExec`) and the
 * CLI tests (behind a fake `gh` executable, see fake-gh.ts). It never touches
 * the network.
 *
 * It keeps every commit it has ever produced by SHA, and one branch head per
 * repo/branch/path, so `?ref=<branch>` and `?ref=<sha>` behave as the real API
 * does: the head moves on, an old commit stays fetchable — until a test says
 * otherwise. The state is plain JSON so a separate process can share it.
 */
import { createHash } from 'node:crypto';

import type { GhExec } from '../src/github-anchor.ts';

export interface FakeState {
  counter: number;
  /** When true every call fails the way a dropped connection does. */
  offline: boolean;
  commits: Record<string, { repo: string; path: string; content: string; date: string }>;
  /** "repo@branch@path" -> commit sha */
  heads: Record<string, string>;
  /** Every PUT the fake has served, oldest first — lets a test prove that nothing was written. */
  puts: string[];
}

export const newState = (): FakeState => ({ counter: 0, offline: false, commits: {}, heads: {}, puts: [] });

const NOT_FOUND = 'gh: Not Found (HTTP 404)';
const NO_COMMIT = 'gh: No commit found for SHA (HTTP 422)';
export const NETWORK = 'error connecting to api.github.com';

function commit(state: FakeState, repo: string, branch: string, path: string, content: string): { sha: string; date: string } {
  state.counter += 1;
  const sha = createHash('sha1').update(`${state.counter}:${repo}:${path}:${content}`).digest('hex');
  const date = new Date(Date.UTC(2026, 8, 18, 9, 0, state.counter)).toISOString().replace('.000Z', 'Z');
  state.commits[sha] = { repo, path, content, date };
  state.heads[`${repo}@${branch}@${path}`] = sha;
  return { sha, date };
}

export function fakeExec(state: FakeState): GhExec {
  return (args, input) => {
    if (state.offline) throw new Error(NETWORK);
    if (args[0] !== 'api') throw new Error(`unexpected gh subcommand: ${args[0]}`);
    const target = args[1];
    if (args.includes('-X') && args[args.indexOf('-X') + 1] === 'PUT') {
      const m = /^repos\/([^/]+\/[^/]+)\/contents\/(.+)$/.exec(target);
      if (!m) throw new Error(`unexpected PUT target: ${target}`);
      const [, repo, path] = m;
      const body = JSON.parse(input ?? '{}') as { content: string; branch: string; sha?: string };
      const headSha = state.heads[`${repo}@${body.branch}@${path}`];
      if (headSha && body.sha !== headSha) throw new Error('gh: sha does not match (HTTP 409)');
      state.puts.push(`${repo}@${body.branch}:${path}`);
      const c = commit(state, repo, body.branch, path, Buffer.from(body.content, 'base64').toString('utf8'));
      return JSON.stringify({ commit: { sha: c.sha, committer: { date: c.date } } });
    }
    const contents = /^repos\/([^/]+\/[^/]+)\/contents\/([^?]+)\?ref=(.+)$/.exec(target);
    if (contents) {
      const [, repo, path, ref] = contents;
      const sha = state.commits[ref] ? ref : state.heads[`${repo}@${ref}@${path}`];
      const c = sha ? state.commits[sha] : undefined;
      if (!c || c.repo !== repo || c.path !== path) throw new Error(NOT_FOUND);
      return JSON.stringify({ sha, content: Buffer.from(c.content, 'utf8').toString('base64') });
    }
    const one = /^repos\/([^/]+\/[^/]+)\/commits\/(.+)$/.exec(target);
    if (one) {
      const c = state.commits[one[2]];
      if (!c || c.repo !== one[1]) throw new Error(NO_COMMIT);
      return JSON.stringify({ commit: { committer: { date: c.date } } });
    }
    throw new Error(`unexpected GET target: ${target}`);
  };
}

// --- things a hostile or unlucky remote does ---------------------------------

/** A force-push that discards history: every commit for the file is gone and the branch holds `content` in a brand-new commit. */
export function forcePush(state: FakeState, repo: string, branch: string, path: string, content: string): void {
  for (const [sha, c] of Object.entries(state.commits)) if (c.repo === repo && c.path === path) delete state.commits[sha];
  commit(state, repo, branch, path, content);
}

/** The branch head is rewritten to `content`, but the old commits are still fetchable by SHA (a rewrite that has not been garbage-collected yet). */
export function rewriteHead(state: FakeState, repo: string, branch: string, path: string, content: string): void {
  commit(state, repo, branch, path, content);
}

export function headContent(state: FakeState, repo: string, branch: string, path: string): string | undefined {
  const sha = state.heads[`${repo}@${branch}@${path}`];
  return sha ? state.commits[sha].content : undefined;
}
