/**
 * The recorder. One session, one ledger file, one key.
 *
 * The key is the trust boundary. This class must run somewhere the agent
 * cannot read `recorder.key` — a separate process, a directory outside every
 * confinement the agent's tools are given, a different user. Recording an
 * agent with a key it can reach produces a ledger that proves only that
 * someone with the key wrote it, and the agent is someone with the key.
 */
import { randomUUID, type KeyObject } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';

import { canon, sha256 } from './canon.ts';
import { formatAnchor, writeAnchor, type Anchor } from './anchor.ts';
import {
  ANCHOR_FILE,
  BLOB_DIR,
  GENESIS_PREV,
  LEDGER_FILE,
  loadOrCreateKeys,
  publicKeyToBase64,
  seal,
  type Body,
  type Entry,
  type Payload,
} from './ledger.ts';

export interface RecorderOptions {
  session?: string;
  actor?: string;
  /** Result bodies larger than this (canonical bytes) go to the blob store. */
  inlineLimit?: number;
  clock?: () => Date;
  /** Supply keys instead of loading them from the directory. */
  keys?: { privateKey: KeyObject; publicKey: KeyObject };
}

export interface ResultOptions {
  ok?: boolean;
}

export class Recorder {
  readonly dir: string;
  readonly session: string;
  private readonly key: KeyObject;
  private readonly fd: number;
  private readonly clock: () => Date;
  private readonly inlineLimit: number;
  private seq = 0;
  private prev = GENESIS_PREV;
  private lastTs = '';
  private readonly calls = new Set<string>();
  private readonly answered = new Set<string>();
  private closed = false;
  private headHash = GENESIS_PREV;

  private constructor(dir: string, key: KeyObject, fd: number, session: string, opts: RecorderOptions) {
    this.dir = dir;
    this.key = key;
    this.fd = fd;
    this.session = session;
    this.clock = opts.clock ?? (() => new Date());
    this.inlineLimit = opts.inlineLimit ?? 4096;
  }

  /** Create a fresh session. Refuses to append to an existing ledger: one session, one file. */
  static open(dir: string, opts: RecorderOptions = {}): Recorder {
    mkdirSync(dir, { recursive: true });
    const ledgerPath = join(dir, LEDGER_FILE);
    if (existsSync(ledgerPath)) throw new Error(`refusing to reopen ${ledgerPath}: one session per ledger`);
    const keys = opts.keys ?? loadOrCreateKeys(dir);
    const fd = openSync(ledgerPath, 'ax');
    const session = opts.session ?? randomUUID();
    const rec = new Recorder(dir, keys.privateKey, fd, session, opts);
    rec.append({ kind: 'open', session, pub: publicKeyToBase64(keys.publicKey), actor: opts.actor });
    return rec;
  }

  get head(): { seq: number; hash: string } {
    return { seq: this.seq - 1, hash: this.headHash };
  }

  /** Record that a tool is about to be called. Returns the id a result must cite. */
  call(tool: string, args: unknown, opts: { id?: string; actor?: string } = {}): string {
    const id = opts.id ?? randomUUID();
    if (this.calls.has(id)) throw new Error(`call id ${id} already recorded`);
    this.calls.add(id);
    this.append({ kind: 'call', id, tool, args, actor: opts.actor });
    return id;
  }

  /** Record what came back. Large bodies are stored by digest in the blob store. */
  result(of: string, body: unknown, opts: ResultOptions = {}): void {
    if (!this.calls.has(of)) throw new Error(`result for unknown call ${of}`);
    if (this.answered.has(of)) throw new Error(`call ${of} already has a result`);
    this.answered.add(of);
    const text = canon(body === undefined ? null : body);
    const digest = sha256(text);
    const bytes = Buffer.byteLength(text);
    if (bytes <= this.inlineLimit) {
      this.append({ kind: 'result', of, ok: opts.ok ?? true, digest, bytes, body: body === undefined ? null : body });
    } else {
      const blobs = join(this.dir, BLOB_DIR);
      mkdirSync(blobs, { recursive: true });
      writeFileSync(join(blobs, digest), text);
      this.append({ kind: 'result', of, ok: opts.ok ?? true, digest, bytes });
    }
  }

  fail(of: string, error: unknown): void {
    const message = error instanceof Error ? { name: error.name, message: error.message } : { message: String(error) };
    this.result(of, message, { ok: false });
  }

  note(text: string): void {
    this.append({ kind: 'note', text });
  }

  /** Write the current head somewhere. Default is inside the ledger dir, which is the weakest place for it. */
  anchor(to: string = join(this.dir, ANCHOR_FILE)): Anchor {
    const a: Anchor = { session: this.session, seq: this.head.seq, hash: this.head.hash, at: this.now() };
    writeAnchor(to, a);
    return a;
  }

  anchorLine(): string {
    return formatAnchor({ session: this.session, seq: this.head.seq, hash: this.head.hash, at: this.now() });
  }

  close(): void {
    if (this.closed) return;
    const open = [...this.calls].filter((id) => !this.answered.has(id));
    this.append({ kind: 'close', calls: this.calls.size, results: this.answered.size, open });
    this.closed = true;
    closeSync(this.fd);
  }

  /**
   * Wrap a bag of async tool functions so every invocation is recorded as a
   * call and a result (or failure) without the caller doing anything.
   */
  wrap<T extends Record<string, (...args: any[]) => unknown>>(tools: T, actor?: string): T {
    const out: Record<string, unknown> = {};
    for (const [name, fn] of Object.entries(tools)) {
      out[name] = async (...args: unknown[]) => {
        const id = this.call(name, args.length === 1 ? args[0] : args, { actor });
        try {
          const value = await fn(...args);
          this.result(id, value);
          return value;
        } catch (e) {
          this.fail(id, e);
          throw e;
        }
      };
    }
    return out as T;
  }

  // --- internals -------------------------------------------------------------

  private now(): string {
    // Never let the recorded clock run backwards, even if the system clock does.
    let ts = this.clock().toISOString();
    if (ts < this.lastTs) ts = this.lastTs;
    this.lastTs = ts;
    return ts;
  }

  private append(partial: Payload): Entry {
    if (this.closed) throw new Error('recorder is closed');
    const body = { v: 1, seq: this.seq, prev: this.prev, ts: this.now(), ...partial } as Body;
    const entry = seal(body, this.key);
    writeSync(this.fd, JSON.stringify(entry) + '\n');
    this.seq += 1;
    this.prev = entry.hash;
    this.headHash = entry.hash;
    return entry;
  }
}
