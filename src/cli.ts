/**
 * acta init   [dir]                          create a ledger directory and key pair
 * acta verify [dir] [--key pem] [--anchors file] [--git [--repo path]] [--strict] [--json]
 * acta anchor [dir] [--to file] [--append-to file] [--git [--repo path]]   write the current head as an anchor
 * acta show   [dir]                          print the timeline
 * acta mcp    [--dir d] [--resume] [--anchor-every n] [--anchor-to file | --anchor-append-to file] -- <command...>
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { readAnchors, formatAnchor, writeAnchor, writeGitAnchor, readGitAnchors, writeAppendOnlyAnchor, appendOnlySupport } from './anchor.ts';
import { BLOB_DIR, PUB_FILE, loadOrCreateKeys, loadPublicKey, readLedger, fingerprint, type Entry } from './ledger.ts';
import { verifyLedger, type Verdict } from './verify.ts';
import { startProxy } from './mcp/proxy.ts';
import { describe } from './show.ts';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const OFF = '\x1b[0m';

const argv = process.argv.slice(2);
const command = argv[0];

function flag(name: string): string | undefined {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}
const has = (name: string) => argv.includes(name);
const positional = (): string | undefined => {
  for (let i = 1; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      i += 1;
      continue;
    }
    return argv[i];
  }
  return undefined;
};

function usage(code: number): never {
  console.error(
    [
      'usage:',
      '  acta init   [dir]',
      '  acta verify [dir] [--key recorder.pub] [--anchors anchors.jsonl] [--git [--repo path]] [--strict] [--json]',
      '  acta anchor [dir] [--to anchors.jsonl] [--append-to anchors.jsonl] [--git [--repo path]]',
      '  acta show   [dir]',
      '  acta mcp    [--dir .acta] [--resume] [--anchor-every N] [--anchor-to file | --anchor-append-to file] -- <command> [args...]',
    ].join('\n'),
  );
  process.exit(code);
}

function ledgerDir(): string {
  return resolve(positional() ?? '.acta');
}

const colour = (status: Verdict['status']) => (status === 'verified' ? GREEN : status === 'consistent' ? YELLOW : RED);

switch (command) {
  case 'init': {
    const dir = ledgerDir();
    const keys = loadOrCreateKeys(dir);
    console.log(`${dir}\nrecorder key ${fingerprint(keys.publicKey)}`);
    console.log(`${DIM}copy ${join(dir, PUB_FILE)} somewhere the agent cannot write; that copy is what \`acta verify --key\` should be given.${OFF}`);
    break;
  }

  case 'verify': {
    const dir = ledgerDir();
    const { entries, problems } = readLedger(dir);
    const keyPath = flag('--key');
    const anchorsPath = flag('--anchors');
    const anchors = [
      ...(anchorsPath ? readAnchors(anchorsPath) : []),
      ...(has('--git') ? readGitAnchors({ cwd: flag('--repo') }) : []),
    ];
    const verdict = verifyLedger(entries, {
      problems,
      trustedKey: keyPath ? loadPublicKey(keyPath) : undefined,
      anchors: anchorsPath || has('--git') ? anchors : undefined,
      blob: (digest) => {
        const p = join(dir, BLOB_DIR, digest);
        return existsSync(p) ? readFileSync(p) : undefined;
      },
    });
    if (has('--json')) {
      console.log(JSON.stringify(verdict, null, 2));
    } else {
      printVerdict(verdict);
    }
    process.exit(verdict.status === 'tampered' ? 1 : verdict.status === 'consistent' && has('--strict') ? 3 : 0);
  }

  case 'anchor': {
    const dir = ledgerDir();
    const { entries } = readLedger(dir);
    if (entries.length === 0) {
      console.error('nothing to anchor');
      process.exit(1);
    }
    const head = entries[entries.length - 1];
    const open = entries[0] as Extract<Entry, { kind: 'open' }>;
    const anchor = { session: open.session, seq: head.seq, hash: head.hash, at: new Date().toISOString() };
    const to = flag('--to');
    if (to) writeAnchor(resolve(to), anchor);
    const appendTo = flag('--append-to');
    if (appendTo) {
      const support = appendOnlySupport();
      if (!support.supported) {
        console.error(`${RED}--append-to unavailable on ${support.platform}: ${support.reason}${OFF}`);
        console.error(`${DIM}use --to for a plain anchor; it is not append-only protected.${OFF}`);
        process.exit(1);
      }
      writeAppendOnlyAnchor(resolve(appendTo), anchor);
    }
    if (has('--git')) writeGitAnchor(anchor, { cwd: flag('--repo') });
    console.log(formatAnchor(anchor));
    break;
  }

  case 'show': {
    const dir = ledgerDir();
    const { entries, problems } = readLedger(dir);
    for (const p of problems) console.log(`${RED}line ${p.line}: ${p.message}${OFF}`);
    for (const e of entries) console.log(describe(e));
    break;
  }

  case 'mcp': {
    const sep = argv.indexOf('--');
    const target = sep === -1 ? [] : argv.slice(sep + 1);
    if (target.length === 0) usage(2);
    const every = flag('--anchor-every');
    const anchorAppendTo = flag('--anchor-append-to');
    if (anchorAppendTo) {
      const support = appendOnlySupport();
      if (!support.supported) {
        console.error(`${RED}--anchor-append-to unavailable on ${support.platform}: ${support.reason}${OFF}`);
        console.error(`${DIM}use --anchor-to for a plain sink; it is not append-only protected.${OFF}`);
        process.exit(1);
      }
    }
    const anchorTo = anchorAppendTo ?? flag('--anchor-to');
    startProxy(target[0], target.slice(1), {
      dir: resolve(flag('--dir') ?? '.acta'),
      actor: flag('--actor'),
      anchorEvery: every ? Number(every) : undefined,
      anchorTo: anchorTo ? resolve(anchorTo) : undefined,
      anchorAppendOnly: anchorAppendTo !== undefined,
      resume: has('--resume'),
      onAnchor: (line) => console.error(line),
    });
    break;
  }

  default:
    usage(command === undefined || command === '--help' ? 0 : 2);
}

function printVerdict(v: Verdict) {
  console.log(`${BOLD}${colour(v.status)}${v.status.toUpperCase()}${OFF}  ${v.entries} entries` + (v.head ? `  head seq ${v.head.seq} ${v.head.hash.slice(0, 12)}…` : ''));
  if (v.anchoredTo) console.log(`${DIM}anchored at seq ${v.anchoredTo.seq}${OFF}`);
  for (const f of v.findings) {
    const c = f.severity === 'tamper' ? RED : f.severity === 'warn' ? YELLOW : DIM;
    console.log(`  ${c}${f.severity.padEnd(6)}${OFF} ${f.code.padEnd(18)} ${f.seq !== undefined ? `@${f.seq}`.padEnd(5) : '     '} ${f.message}`);
  }
  if (v.status === 'consistent') {
    console.log(`${YELLOW}consistent is not verified.${OFF} still missing:`);
    for (const m of v.missing) console.log(`  - ${m}`);
  }
}
