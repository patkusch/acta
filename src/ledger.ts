/**
 * The ledger: an append-only JSONL file where every entry commits to the one
 * before it and is signed by a key the agent must not hold.
 *
 * Three things bind an entry into place, and each one defeats a stronger
 * attacker than the last:
 *
 *   hash   — the entry's own bytes. Defeats an editor.
 *   prev   — the previous entry's hash. Defeats deletion and reordering.
 *   sig    — the recorder's Ed25519 signature over the hash. Defeats anyone
 *            who understands the format but does not hold the key.
 *
 * None of them defeats someone who holds the key. That is what anchors are
 * for (see anchor.ts), and it is why the README spends so long on it.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { canon, sha256 } from './canon.ts';

export const GENESIS_PREV = '0'.repeat(64);
export const FORMAT_VERSION = 1 as const;

interface Base {
  v: typeof FORMAT_VERSION;
  seq: number;
  prev: string;
  /** Recorder wall-clock time. Ordering is proved by `prev`; time is only asserted. */
  ts: string;
}

export type Body = Base &
  (
    | {
        kind: 'open';
        session: string;
        /** SPKI DER, base64. The key the ledger claims signed it. Self-attested. */
        pub: string;
        /** Free-text label for who is being recorded (a host, a harness, a run id). */
        actor?: string;
      }
    | { kind: 'call'; id: string; tool: string; args: unknown; actor?: string }
    | {
        kind: 'result';
        of: string;
        ok: boolean;
        /** sha256 of the canonical result body. */
        digest: string;
        bytes: number;
        /** Present when the body was small enough to keep inline. */
        body?: unknown;
      }
    | { kind: 'note'; text: string }
    | {
        kind: 'close';
        calls: number;
        results: number;
        /** Calls that were still unanswered when the session closed — legitimately. */
        open: string[];
      }
  );

export type Entry = Body & { hash: string; sig: string };

/** Omit that distributes over a union, so each kind keeps its own fields. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
/** What a caller supplies; the recorder fills in the chain fields. */
export type Payload = DistributiveOmit<Body, 'v' | 'seq' | 'prev' | 'ts'>;
export type Kind = Body['kind'];

// --- hashing and signing -----------------------------------------------------

export function hashBody(body: Body): string {
  return sha256(canon(body));
}

export function signHash(hash: string, key: KeyObject): string {
  return cryptoSign(null, Buffer.from(hash, 'hex'), key).toString('base64');
}

export function verifySignature(hash: string, sig: string, pub: KeyObject): boolean {
  try {
    return cryptoVerify(null, Buffer.from(hash, 'hex'), pub, Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

export function seal(body: Body, key: KeyObject): Entry {
  const hash = hashBody(body);
  return { ...body, hash, sig: signHash(hash, key) };
}

// --- keys --------------------------------------------------------------------

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateKeys(): KeyPair {
  return generateKeyPairSync('ed25519');
}

export function publicKeyToBase64(pub: KeyObject): string {
  return (pub.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
}

export function publicKeyFromBase64(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, 'base64'), type: 'spki', format: 'der' });
}

/** Short, human-comparable identifier for a public key. */
export function fingerprint(pub: KeyObject): string {
  return sha256(pub.export({ type: 'spki', format: 'der' }) as Buffer).slice(0, 16);
}

export const KEY_FILE = 'recorder.key';
export const PUB_FILE = 'recorder.pub';
export const LEDGER_FILE = 'ledger.jsonl';
export const BLOB_DIR = 'blobs';
export const ANCHOR_FILE = 'anchors.jsonl';

/** Load the recorder's key pair from a directory, generating one if absent. */
export function loadOrCreateKeys(dir: string): KeyPair {
  const keyPath = join(dir, KEY_FILE);
  const pubPath = join(dir, PUB_FILE);
  if (existsSync(keyPath)) {
    const privateKey = createPrivateKey(readFileSync(keyPath, 'utf8'));
    return { privateKey, publicKey: createPublicKey(privateKey) };
  }
  mkdirSync(dir, { recursive: true });
  const pair = generateKeys();
  writeFileSync(keyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  writeFileSync(pubPath, pair.publicKey.export({ type: 'spki', format: 'pem' }));
  return pair;
}

export function loadPublicKey(path: string): KeyObject {
  return createPublicKey(readFileSync(path, 'utf8'));
}

// --- reading -----------------------------------------------------------------

export interface ReadProblem {
  line: number;
  message: string;
}

export interface ReadResult {
  entries: Entry[];
  problems: ReadProblem[];
}

/** Parse a ledger file. Unparseable lines are reported, not dropped silently. */
export function parseLedger(text: string): ReadResult {
  const entries: Entry[] = [];
  const problems: ReadProblem[] = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    try {
      const parsed = JSON.parse(line);
      if (typeof parsed !== 'object' || parsed === null || typeof parsed.hash !== 'string') {
        problems.push({ line: i + 1, message: 'not a ledger entry' });
        return;
      }
      entries.push(parsed as Entry);
    } catch (e) {
      problems.push({ line: i + 1, message: `unparseable: ${(e as Error).message}` });
    }
  });
  return { entries, problems };
}

export function readLedger(dir: string): ReadResult {
  const path = join(dir, LEDGER_FILE);
  if (!existsSync(path)) return { entries: [], problems: [{ line: 0, message: `no ${LEDGER_FILE} in ${dir}` }] };
  return parseLedger(readFileSync(path, 'utf8'));
}

/** The body of an entry: everything that is hashed. */
export function bodyOf(entry: Entry): Body {
  const { hash: _h, sig: _s, ...body } = entry;
  return body as Body;
}
