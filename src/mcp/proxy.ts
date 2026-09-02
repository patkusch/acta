/**
 * A stdio MCP proxy that records. It sits between a host and a real MCP
 * server, forwards everything untouched, and writes every `tools/call` and
 * its response into the ledger.
 *
 * This process holds the recorder key. The server it wraps, and the agent
 * driving that server, must not be able to read this process's ledger
 * directory — otherwise the key is inside the thing being recorded.
 */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import { Recorder, type RecorderOptions } from '../recorder.ts';

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
  onAnchor?: (line: string) => void;
}

export function startProxy(command: string, args: string[], options: ProxyOptions) {
  const rec = Recorder.open(options.dir, options);
  const server = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'] });

  /** JSON-RPC id → ledger call id, for requests we are waiting on. */
  const pending = new Map<string, string>();
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
        if (message.error) rec.result(callId, message.error, { ok: false });
        else rec.result(callId, message.result ?? null, { ok: !isToolError(message.result) });
        completed += 1;
        maybeAnchor();
      }
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
      const callId = rec.call(name, message.params?.arguments ?? {}, { id: `rpc-${message.id}` });
      pending.set(String(message.id), callId);
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
    rec.anchor(options.anchorTo);
    options.onAnchor?.(rec.anchorLine());
  }

  return { server, recorder: rec };
}

function isToolError(result: unknown): boolean {
  return typeof result === 'object' && result !== null && (result as { isError?: boolean }).isError === true;
}
