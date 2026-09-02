/**
 * `npm run attack` — the demo. Records a genuine session, then runs every
 * attack in the catalogue against it under three verifier configurations:
 * the chain alone, chain plus a trusted key, and chain plus key plus anchor.
 *
 * The point of the table is the bottom-right cell.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSampleSession } from '../src/fixtures/session.ts';
import { ATTACKS, type Capability } from '../src/attacks.ts';
import { readLedger } from '../src/ledger.ts';
import { verifyLedger, type Verdict } from '../src/verify.ts';
import { describe } from '../src/show.ts';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const OFF = '\x1b[0m';

const scratch = () => mkdtempSync(join(tmpdir(), 'acta-'));
const s = recordSampleSession(scratch(), join(scratch(), 'anchors.jsonl'));
const genuine = readLedger(s.dir).entries;

console.log(`${BOLD}The genuine session${OFF} ${DIM}(${genuine.length} entries, anchored at seq ${s.marks.anchoredAt})${OFF}\n`);
for (const e of genuine) console.log('  ' + describe(e));

const configs: Array<[string, (v: typeof genuine) => Verdict]> = [
  ['chain', (e) => verifyLedger(e)],
  ['+key', (e) => verifyLedger(e, { trustedKey: s.keys.publicKey })],
  ['+anchor', (e) => verifyLedger(e, { trustedKey: s.keys.publicKey, anchors: s.anchors })],
];

const cell = (v: Verdict) => {
  const codes = [...new Set(v.findings.filter((f) => f.severity === 'tamper').map((f) => f.code))];
  return v.status === 'tampered' ? `${GREEN}caught${OFF} ${DIM}${codes.join(', ')}${OFF}` : `${RED}not caught${OFF}`;
};

const needsColour: Record<Capability, string> = { file: DIM, format: '', 'own key': YELLOW, 'real key': RED };

console.log(`\n${BOLD}Attacks${OFF}\n`);
const rows: string[][] = [];
for (const attack of ATTACKS) {
  const doctored = attack.apply(genuine, s);
  console.log(`${BOLD}── ${attack.name}${OFF}  ${needsColour[attack.needs]}needs: ${attack.needs}${OFF}`);
  console.log(`   ${DIM}${attack.intent}${OFF}`);
  const row = [attack.name, attack.needs];
  for (const [label, run] of configs) {
    const v = run(doctored.entries);
    console.log(`   ${label.padEnd(8)} ${cell(v)}`);
    row.push(v.status === 'tampered' ? 'caught' : '—');
  }
  rows.push(row);
  console.log();
}

console.log(`${BOLD}Summary${OFF}\n`);
const w = [34, 10, 8, 8, 8];
const line = (cells: string[]) => cells.map((c, i) => c.padEnd(w[i])).join('');
console.log(DIM + line(['attack', 'needs', 'chain', '+key', '+anchor']) + OFF);
for (const r of rows) {
  console.log(line(r.map((c) => (c === 'caught' ? `${GREEN}caught${OFF}` + ' '.repeat(2) : c === '—' ? `${RED}—${OFF}` + ' '.repeat(7) : c))));
}

const caughtBy = (i: number) => rows.filter((r) => r[i] === 'caught').length;
console.log(`
${BOLD}What the table says${OFF}
  the chain alone catches ${caughtBy(2)} of ${rows.length}: anyone who can write the file but does not understand it.
  a trusted key catches ${caughtBy(3)}: anyone who does not hold the recorder's key.
  an anchor catches ${caughtBy(4)}: anyone who holds the key, for entries up to the anchor.
  ${RED}nothing catches ${rows.length - caughtBy(4)}${OFF}: the key holder, between the last anchor and now.

  So: keep the key out of the agent's reach, and anchor often. Everything else is detail.
`);
