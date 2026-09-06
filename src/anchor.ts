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

// --- an append-only file as an anchor sink ----------------------------------
//
// The default anchor file is only as strong as the permissions on it: an agent
// that can write the ledger directory can rewrite the anchors sitting beside it,
// and a rewritten anchor that agrees with a rewritten ledger reads as verified.
// A file the kernel marks append-only closes that gap for an agent whose tools
// perform ordinary file writes. With the flag set, the OS permits appends and
// rejects truncation, in-place rewrite and unlink — so the one thing an attacker
// holding the recorder key needs to do to a past anchor, overwrite it, is the one
// thing the kernel refuses.
//
// The honest boundary: this is `chflags uappnd` (BSD/macOS), a *user* flag the
// file's owner can clear with `chflags nouappnd`. It defeats an agent confined to
// file-read/write/delete tools that do not include chflags; it does not defeat the
// owner, and it is not the system-immutable flag (`schg`), which needs root and a
// reboot to a lower securelevel to clear. On Linux the equivalent is `chattr +a`
// (needs CAP_LINUX_IMMUTABLE), which is not wired up here; on those platforms this
// sink reports itself unsupported rather than writing a file that only looks
// protected.

import { closeSync, openSync } from 'node:fs';

/** UF_APPEND in the BSD st_flags bitfield: user append-only. */
const UF_APPEND = 0x4;

export type AppendOnlySupport =
  | { supported: true; platform: NodeJS.Platform; how: string }
  | { supported: false; platform: NodeJS.Platform; reason: string };

/** Whether this platform can make a file append-only in a way this module sets and reads. */
export function appendOnlySupport(): AppendOnlySupport {
  const platform = process.platform;
  if (platform === 'darwin' || platform === 'freebsd' || platform === 'openbsd' || platform === 'netbsd') {
    return { supported: true, platform, how: 'chflags uappnd' };
  }
  if (platform === 'linux') {
    return { supported: false, platform, reason: 'append-only here is `chattr +a`, which needs CAP_LINUX_IMMUTABLE and is not wired up' };
  }
  return { supported: false, platform, reason: `no append-only file flag is wired up for ${platform}` };
}

/**
 * Does this file currently carry the OS append-only flag? False on platforms
 * this module does not support, and false — not an error — for a file that does
 * not exist, so a caller can treat "unprotected" and "absent" the same way.
 */
export function isAppendOnly(path: string): boolean {
  if (!appendOnlySupport().supported) return false;
  // Node's fs.Stats does not expose BSD st_flags, so read them out of band.
  // A missing file (or any stat failure) reads as unprotected, not an error.
  try {
    const flags = Number(execFileSync('stat', ['-f', '%f', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim());
    return Number.isFinite(flags) && (flags & UF_APPEND) !== 0;
  } catch {
    return false;
  }
}

function setAppendOnly(path: string): void {
  execFileSync('chflags', ['uappnd', path], { stdio: ['ignore', 'ignore', 'pipe'] });
}

/**
 * Append an anchor to a file the OS marks append-only, creating and flagging the
 * file on first use. Appends are all the kernel allows once the flag is set, which
 * is exactly what an anchor sink needs. Throws on a platform where the flag cannot
 * be set, rather than writing an unprotected file that would pass for a protected
 * one — the caller decides whether to fall back to a plain anchor.
 *
 * Flagging an existing unflagged file trusts whatever it already holds; only its
 * future is protected. To start from a clean sink, point this at a fresh path.
 */
export function writeAppendOnlyAnchor(path: string, a: Anchor): void {
  const support = appendOnlySupport();
  if (!support.supported) {
    throw new Error(`append-only anchoring unavailable on ${support.platform}: ${support.reason}`);
  }
  mkdirSync(dirname(path), { recursive: true });
  if (!existsSync(path)) {
    closeSync(openSync(path, 'a')); // create empty; O_APPEND, no truncate
  }
  if (!isAppendOnly(path)) setAppendOnly(path);
  // appendFileSync opens O_APPEND, the one write mode the flag permits.
  appendFileSync(path, JSON.stringify(a) + '\n');
}
