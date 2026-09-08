/**
 * A stdio MCP proxy that records. It sits between a host and a real MCP
 * server, forwards everything untouched, and writes every `tools/list` and
 * `tools/call` and their responses into the ledger.
 *
 * This process holds the recorder key. The server it wraps, and the agent
 * driving that server, must not be able to read this process's ledger
 * directory — otherwise the key is inside the thing being recorded.
 */
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

import { digest } from '../canon.ts';
import { Recorder, type RecorderOptions } from '../recorder.ts';
import { BLOB_DIR, LEDGER_FILE, generateKeys, readLedger } from '../ledger.ts';

/**
 * The definitions in force: the seq of the ledger entry that recorded the
 * catalogue, and each tool's definition digest taken from those same bytes.
 */
interface Catalogue {
  seq: number;
  tools: Map<string, string>;
}

function catalogueOf(seq: number, body: unknown): Catalogue | undefined {
  const tools = (body as { tools?: unknown } | null)?.tools;
  if (!Array.isArray(tools)) return undefined;
  const map = new Map<string, string>();
  for (const t of tools) {
    if (t && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string') map.set((t as { name: string }).name, digest(t));
  }
  return { seq, tools: map };
}

/**
 * After a restart the definitions in force are whatever the host last listed,
 * and that is in the ledger being resumed. Read it back so calls made before
 * the host lists again are still bound to what the agent was actually shown.
 */
function catalogueFromLedger(dir: string): Catalogue | undefined {
  const { entries } = readLedger(dir);
  const listings = new Set(entries.filter((e) => e.kind === 'call' && e.tool === 'tools/list').map((e) => (e as { id: string }).id));
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i];
    if (e.kind !== 'result' || !listings.has(e.of) || !e.ok) continue;
    let body = e.body;
    if (body === undefined) {
      const path = join(dir, BLOB_DIR, e.digest);
      if (!existsSync(path)) continue;
      body = JSON.parse(readFileSync(path, 'utf8'));
    }
    const found = catalogueOf(e.seq, body);
    if (found) return found;
  }
  return undefined;
}

interface JsonRpc {
  jsonrpc: '2.0';
  id?: number | string;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface ProxyOptions extends RecorderOptions {
  dir: string;
  /** Anchor every N recorded calls to this path. */
  anchorEvery?: number;
  anchorTo?: string;
  /** Make the anchor sink append-only (kernel-enforced); requires anchorTo. */
  anchorAppendOnly?: boolean;
  /** Continue an existing ledger in `dir` if one is there, rather than refusing it. */
  resume?: boolean;
  /** On resume, retire the pre-crash key and continue under a fresh one. */
  rotateOnResume?: boolean;
  onAnchor?: (line: string) => void;
}

export function startProxy(command: string, args: string[], options: ProxyOptions) {
  const resuming = Boolean(options.resume) && existsSync(join(options.dir, LEDGER_FILE));
  const rec = resuming ? Recorder.resume(options.dir, options) : Recorder.open(options.dir, options);
  // Retiring the pre-crash key on resume limits the blast radius if whatever
  // took the recorder down also exposed its key: entries after the restart are
  // signed by a fresh key, and the original still verifies everything before it.
  if (resuming && options.rotateOnResume) rec.rotate(generateKeys());
  const server = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });

  /**
   * A per-run tag on every ledger call id. JSON-RPC ids reset with each host
   * connection, so across a resume the same id recurs — `rpc-2` in run two would
   * collide with `rpc-2` from run one, which is still in the rebuilt call set.
   * The ledger's call-id space is the whole session; this keeps it unique.
   */
  const runTag = randomUUID().slice(0, 8);
  /** JSON-RPC id → ledger call id, for requests we are waiting on. */
  const pending = new Map<string, string>();
  /** Ledger call ids of `tools/list` requests, whose results are catalogues. */
  const listings = new Set<string>();
  /** The catalogue the agent was most recently shown. Every tools/call is bound to it. */
  let catalogue: Catalogue | undefined = resuming ? catalogueFromLedger(options.dir) : undefined;
  /** Completed calls. Anchors are taken on completion, so a pipelined burst cannot double-anchor. */
  let completed = 0;

  const send = (stream: NodeJS.WritableStream, message: JsonRpc) => {
    stream.write(JSON.stringify(message) + '\n');
  };

  rec.note(`mcp server: ${[command, ...args].join(' ')}`);

  // --- server → host: match responses to recorded calls ---------------------
  createInterface({ input: server.stdout }).on('line', (line) => {
    if (!line.trim()) return;
    let message: JsonRpc;
    try {
      message = JSON.parse(line);
    } catch {
      process.stdout.write(line + '\n');
      return;
    }
    if (message.id !== undefined) {
      const callId = pending.get(String(message.id));
      if (callId) {
        pending.delete(String(message.id));
        if (message.error) {
          rec.result(callId, message.error, { ok: false });
        } else {
          const entry = rec.result(callId, message.result ?? null, { ok: !isToolError(message.result) });
          // A fresh catalogue: from here on, calls are bound to this one.
          if (listings.delete(callId)) catalogue = catalogueOf(entry.seq, message.result) ?? catalogue;
        }
        completed += 1;
        maybeAnchor();
      }
    } else if (message.method === 'notifications/tools/list_changed') {
      // The server says its definitions changed. Calls stay bound to the last
      // catalogue the host fetched, because that is still what the agent saw.
      rec.note('tools/list_changed: the server says its definitions changed; calls stay bound to the last catalogue listed');
    }
    send(process.stdout, message);
  });

  // --- host → server: record tools/call on the way past ----------------------
  createInterface({ input: process.stdin }).on('line', (line) => {
    if (!line.trim()) return;
    let message: JsonRpc;
    try {
      message = JSON.parse(line);
    } catch {
      server.stdin.write(line + '\n');
      return;
    }
    if (message.method === 'tools/call' && message.id !== undefined) {
      const name = String(message.params?.name ?? '');
      // Bind the call to the definition the agent was shown. A tool the current
      // catalogue does not list gets no binding, and the verifier says so.
      const def = catalogue?.tools.has(name) ? { seq: catalogue.seq, digest: catalogue.tools.get(name)! } : undefined;
      const callId = rec.call(name, message.params?.arguments ?? {}, { id: `rpc-${runTag}-${message.id}`, def });
      pending.set(String(message.id), callId);
    } else if (message.method === 'tools/list' && message.id !== undefined) {
      // The catalogue is recorded as a call so the definitions the agent was
      // shown sit in the same chain as the calls it made against them.
      const callId = rec.call('tools/list', message.params ?? {}, { id: `rpc-${runTag}-${message.id}` });
      pending.set(String(message.id), callId);
      listings.add(callId);
    } else if (message.method === 'notifications/cancelled') {
      rec.note(`cancelled: ${JSON.stringify(message.params ?? {})}`);
    }
    send(server.stdin, message);
  });

  const finish = () => {
    if (rec) {
      try {
        rec.close();
      } catch {
        // already closed
      }
    }
  };
  process.stdin.on('end', () => {
    server.stdin.end();
  });
  server.on('exit', () => {
    finish();
    process.exit(0);
  });
  process.on('SIGINT', () => {
    finish();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    finish();
    process.exit(143);
  });

  function maybeAnchor() {
    if (!options.anchorEvery || completed % options.anchorEvery !== 0) return;
    rec.anchor(options.anchorTo, { appendOnly: options.anchorAppendOnly });
    options.onAnchor?.(rec.anchorLine());
  }

  return { server, recorder: rec };
}

function isToolError(result: unknown): boolean {
  return typeof result === 'object' && result !== null && (result as { isError?: boolean }).isError === true;
}
