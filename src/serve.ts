import { createServer, type Server } from 'node:http';
import { parseLedger, publicKeyFromBase64 } from './ledger.ts';
import { verifyLedger } from './verify.ts';
import { STAGES } from './step.ts';

const MAX_BYTES = 5 * 1024 * 1024;

/**
 * A small public checker. POST a ledger (the text of ledger.jsonl) and get the
 * verdict back. Optionally send the recorder's public key (base64) that you
 * obtained somewhere else; without it the best answer is "consistent".
 */
export function makeServer(): Server {
  return createServer((req, res) => {
    const send = (code: number, body: unknown, type = 'application/json') => {
      res.writeHead(code, { 'content-type': type });
      res.end(type === 'application/json' ? JSON.stringify(body) : String(body));
    };
    if (req.method === 'GET' && req.url === '/healthz') return send(200, { ok: true });
    if (req.method === 'GET' && req.url === '/') {
      return send(
        200,
        `<!doctype html><title>Acta checker</title><h1>Acta checker</h1><p>POST a ledger.jsonl body to <code>/verify</code>. ` +
          `Add <code>?key=BASE64_PUBLIC_KEY</code> to check it against a key you hold. ` +
          `Stages recorded by the GitLab agents: ${STAGES.join(', ')}.</p>`,
        'text/html',
      );
    }
    if (req.method === 'POST' && req.url?.startsWith('/verify')) {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (c: Buffer) => {
        size += c.length;
        if (size > MAX_BYTES) {
          send(413, { error: 'ledger too large' });
          req.destroy();
        } else chunks.push(c);
      });
      req.on('end', () => {
        if (res.writableEnded) return;
        try {
          const key = new URL(req.url!, 'http://x').searchParams.get('key');
          const { entries, problems } = parseLedger(Buffer.concat(chunks).toString('utf8'));
          const verdict = verifyLedger(entries, { problems, trustedKey: key ? publicKeyFromBase64(key) : undefined });
          send(200, verdict);
        } catch (e) {
          send(400, { error: (e as Error).message });
        }
      });
      return;
    }
    send(404, { error: 'not found' });
  });
}
