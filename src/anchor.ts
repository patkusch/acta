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
