/** One line per entry, for humans. */
import { fingerprint, publicKeyFromBase64, type Entry } from './ledger.ts';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const OFF = '\x1b[0m';

export function describe(e: Entry): string {
  const head = `${DIM}${String(e.seq).padStart(4)} ${e.ts}${OFF} `;
  switch (e.kind) {
    case 'open':
      return head + `${BOLD}open${OFF} session ${e.session}${e.actor ? ` (${e.actor})` : ''} key ${fingerprint(publicKeyFromBase64(e.pub))}`;
    case 'call':
      return head + `${BOLD}call${OFF} ${e.tool} ${DIM}${JSON.stringify(e.args).slice(0, 100)}${OFF}`;
    case 'result':
      return head + `${e.ok ? 'ok  ' : `${RED}fail${OFF}`} ${DIM}${e.body !== undefined ? JSON.stringify(e.body).slice(0, 100) : `${e.bytes} bytes ${e.digest.slice(0, 12)}…`}${OFF}`;
    case 'note':
      return head + `note ${e.text}`;
    case 'close':
      return head + `${BOLD}close${OFF} ${e.calls} calls, ${e.results} results${e.open.length ? `, ${e.open.length} still open` : ''}`;
  }
}
