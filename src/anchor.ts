/**
 * An anchor is the ledger's head — its sequence number and hash — written
 * somewhere the agent cannot write. It is the only thing in this design that
 * defeats an attacker holding the recorder key, and it only defeats them for
 * entries at or before the anchor.
 *
 * Where to put it is an operational decision, not a library one. A file
 * outside the agent's confinement, a git commit message, a chat channel, a
 * ticket, a printout. The library only makes the anchor small enough to go
 * anywhere.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface Anchor {
  session: string;
  seq: number;
  hash: string;
  at: string;
}

/** One line, fit for a commit message or a chat. Parses back with `parseAnchorLine`. */
export function formatAnchor(a: Anchor): string {
  return `acta-anchor session=${a.session} seq=${a.seq} hash=${a.hash} at=${a.at}`;
}

export function parseAnchorLine(line: string): Anchor | undefined {
  const trimmed = line.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('{')) {
    try {
      const o = JSON.parse(trimmed);
      if (typeof o.session === 'string' && typeof o.seq === 'number' && typeof o.hash === 'string') {
        return { session: o.session, seq: o.seq, hash: o.hash, at: String(o.at ?? '') };
      }
    } catch {
      return undefined;
    }
    return undefined;
  }
  const m = /acta-anchor\s+session=(\S+)\s+seq=(\d+)\s+hash=([0-9a-f]{64})(?:\s+at=(\S+))?/.exec(trimmed);
  if (!m) return undefined;
  return { session: m[1], seq: Number(m[2]), hash: m[3], at: m[4] ?? '' };
}

export function writeAnchor(path: string, a: Anchor): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(a) + '\n');
}

/** Read every anchor in a file. Accepts JSONL or the one-line text form, mixed. */
export function readAnchors(path: string): Anchor[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .map(parseAnchorLine)
    .filter((a): a is Anchor => a !== undefined);
}

// --- git notes as an anchor sink --------------------------------------------
//
// A note on HEAD in a dedicated ref. Locally this is no stronger than a file
// the same user can write. Its value is that `git push origin refs/notes/acta`
// puts a copy somewhere the agent needs push rights to alter, and a reviewer
// can `git fetch origin refs/notes/acta:refs/notes/acta` and verify against
// the remote copy rather than the local one.

import { execFileSync } from 'node:child_process';

export interface GitAnchorOptions {
  cwd?: string;
  ref?: string;
}

export const GIT_NOTES_REF = 'acta';

export function writeGitAnchor(a: Anchor, opts: GitAnchorOptions = {}): void {
  execFileSync('git', ['notes', `--ref=${opts.ref ?? GIT_NOTES_REF}`, 'append', '-m', formatAnchor(a), 'HEAD'], {
    cwd: opts.cwd,
    stdio: ['ignore', 'ignore', 'pipe'],
  });
}

/** Every anchor line in every note under the ref. An absent ref is simply no anchors. */
export function readGitAnchors(opts: GitAnchorOptions = {}): Anchor[] {
  const ref = opts.ref ?? GIT_NOTES_REF;
  let list: string;
  try {
    list = execFileSync('git', ['notes', `--ref=${ref}`, 'list'], { cwd: opts.cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return [];
  }
  const anchors: Anchor[] = [];
  for (const line of list.split('\n')) {
    const [noteObject] = line.trim().split(/\s+/);
    if (!noteObject) continue;
    const text = execFileSync('git', ['cat-file', '-p', noteObject], { cwd: opts.cwd, encoding: 'utf8' });
    for (const l of text.split('\n')) {
      const a = parseAnchorLine(l);
      if (a) anchors.push(a);
    }
  }
  return anchors;
}
