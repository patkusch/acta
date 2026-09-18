/**
 * acta init   [dir]                          create a ledger directory and key pair
 * acta verify [dir] [--key pem] [--anchors file] [--git [--repo path]] [--strict] [--json]
 * acta anchor [dir] [--to file] [--append-to file] [--git [--repo path]]   write the current head as an anchor
 * acta witness backup [ledger] --to <path | owner/name[:branch]>   copy the witness ledger somewhere else you control
 * acta witness add <witness.json> [--ledger path]                  file an existing witness in the ledger
 * acta verify --witnesses <witnesses.jsonl>                        check every recorded witness against GitHub
 * acta show   [dir]                          print the timeline
 * acta mcp    [--dir d] [--resume [--rotate-on-resume]] [--anchor-every n] [--anchor-to file | --anchor-append-to file] -- <command...>
 */
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { readAnchors, formatAnchor, writeAnchor, writeGitAnchor, readGitAnchors, writeAppendOnlyAnchor, appendOnlySupport } from './anchor.ts';
import { writeGitHubAnchor, verifyGitHubWitness, parseRepoSpec, type GitHubWitness } from './github-anchor.ts';
import {
  WITNESS_LEDGER_FILE,
  WitnessBackupRefused,
  WitnessLedgerError,
  appendWitness,
  assertLedgerAppendable,
  backupWitnessLedger,
  parseBackupTarget,
  verifyWitnessLedger,
  type WitnessLedgerReport,
} from './witness-ledger.ts';
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
      '  acta verify [dir] [--key recorder.pub] [--anchors anchors.jsonl] [--git [--repo path]] [--witness witness.json] [--strict] [--json]',
      '  acta verify --witnesses witnesses.jsonl [--json]',
      '  acta anchor [dir] [--to anchors.jsonl] [--append-to anchors.jsonl] [--git [--repo path]] [--github owner/name[:branch] [--github-path file] [--witness-out file] [--witness-ledger witnesses.jsonl]]',
      '  acta witness backup [witnesses.jsonl | dir] --to <path | owner/name[:branch]> [--backup-path file]',
      '  acta witness add witness.json [--ledger witnesses.jsonl]',
      '  acta show   [dir]',
      '  acta mcp    [--dir .acta] [--resume [--rotate-on-resume]] [--anchor-every N] [--anchor-to file | --anchor-append-to file] -- <command> [args...]',
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
    const witnessesPath = flag('--witnesses');
    if (witnessesPath) {
      // A different question from the ledger's own verdict: not "is this
      // session intact" but "does GitHub still agree with everything I was
      // once told it holds". It needs no session directory.
      const report = verifyWitnessLedger(resolve(witnessesPath));
      if (has('--json')) console.log(JSON.stringify(report, null, 2));
      else printWitnessLedger(report, resolve(witnessesPath));
      process.exit(report.verdict === 'tampered' ? 1 : report.verdict === 'unreachable' ? 2 : report.verdict === 'empty' ? 3 : 0);
    }
    const dir = ledgerDir();
    const { entries, problems } = readLedger(dir);
    const keyPath = flag('--key');
    const anchorsPath = flag('--anchors');
    const witnessPath = flag('--witness');

    // A witness is not trusted just because the file says so: it is re-fetched
    // from GitHub by commit SHA and checked against the anchor it claims before
    // that anchor is allowed to count towards the verdict at all.
    let witness: GitHubWitness | undefined;
    let witnessCheck: { ok: boolean; unreachable?: boolean; findings: { code: string; severity: string; message: string }[] } | undefined;
    if (witnessPath) {
      witness = JSON.parse(readFileSync(resolve(witnessPath), 'utf8')) as GitHubWitness;
      witnessCheck = verifyGitHubWitness(witness);
    }

    const anchors = [
      ...(anchorsPath ? readAnchors(anchorsPath) : []),
      ...(has('--git') ? readGitAnchors({ cwd: flag('--repo') }) : []),
      ...(witness && witnessCheck?.ok ? [witness.anchor] : []),
    ];
    const verdict = verifyLedger(entries, {
      problems,
      trustedKey: keyPath ? loadPublicKey(keyPath) : undefined,
      anchors: anchorsPath || has('--git') || witness ? anchors : undefined,
      blob: (digest) => {
        const p = join(dir, BLOB_DIR, digest);
        return existsSync(p) ? readFileSync(p) : undefined;
      },
    });
    if (has('--json')) {
      console.log(JSON.stringify({ ...verdict, witness: witnessCheck }, null, 2));
    } else {
      printVerdict(verdict);
      if (witnessCheck) printWitnessCheck(witness!, witnessCheck);
    }
    const witnessTamper = witnessCheck?.findings.some((f) => f.severity === 'tamper') ?? false;
    const witnessUnreachable = witnessCheck !== undefined && !witnessCheck.ok && !witnessTamper;
    process.exit(verdict.status === 'tampered' || witnessTamper ? 1 : witnessUnreachable ? 2 : verdict.status === 'consistent' && has('--strict') ? 3 : 0);
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
    const appendTo = flag('--append-to');
    const github = flag('--github');
    // The witness ledger sits beside the anchors file by default, or in the
    // ledger directory when there is none. Checked before anything is written
    // or pushed: a damaged ledger must stop the run, not turn up afterwards.
    const witnessLedger = resolve(flag('--witness-ledger') ?? join(to ? dirname(resolve(to)) : appendTo ? dirname(resolve(appendTo)) : dir, WITNESS_LEDGER_FILE));
    if (github) {
      try {
        assertLedgerAppendable(witnessLedger);
      } catch (e) {
        console.error(`${RED}${(e as Error).message}${OFF}`);
        process.exit(1);
      }
    }
    if (to) writeAnchor(resolve(to), anchor);
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
    if (github) {
      const { repo, branch } = parseRepoSpec(github);
      const witness = writeGitHubAnchor(anchor, { repo, branch, path: flag('--github-path') });
      console.log(`${DIM}pushed to ${witness.repo}@${witness.branch} as ${witness.commitSha.slice(0, 12)} (${witness.committedAt})${OFF}`);
      try {
        appendWitness(witnessLedger, witness);
        console.log(`${DIM}witness filed in ${witnessLedger} — \`acta witness backup\` copies it somewhere the repo's owner cannot reach; until then a rewrite is not detectable.${OFF}`);
      } catch (e) {
        // The commit is already public. Do not lose the only record of it.
        console.error(`${RED}could not file the witness in ${witnessLedger}: ${(e as Error).message}${OFF}`);
        console.error(JSON.stringify(witness));
        process.exit(1);
      }
      const witnessOut = flag('--witness-out');
      if (witnessOut) {
        writeFileSync(resolve(witnessOut), JSON.stringify(witness, null, 2) + '\n');
        console.log(`${DIM}witness also written to ${witnessOut}${OFF}`);
      } else {
        console.log(JSON.stringify(witness));
      }
    }
    console.log(formatAnchor(anchor));
    break;
  }

  case 'witness': {
    const sub = argv[1];
    // Positional args after the subcommand: skip every `--flag value` pair.
    const rest: string[] = [];
    for (let i = 2; i < argv.length; i++) {
      if (argv[i].startsWith('--')) i += 1;
      else rest.push(argv[i]);
    }
    const ledgerArg = (p: string | undefined) => {
      const target = resolve(p ?? '.acta');
      return existsSync(target) && statSync(target).isDirectory() ? join(target, WITNESS_LEDGER_FILE) : target;
    };
    try {
      if (sub === 'backup') {
        const to = flag('--to');
        if (!to) usage(2);
        const ledgerPath = ledgerArg(rest[0]);
        const target = parseBackupTarget(to, { githubPath: flag('--backup-path') });
        const result = backupWitnessLedger(ledgerPath, target);
        const verb = result.status === 'unchanged' ? 'already current' : result.status;
        console.log(`${GREEN}${verb}${OFF}  ${result.where}  ${result.total} record(s)${result.appended ? `, ${result.appended} written` : ''}${result.commitSha ? `  commit ${result.commitSha.slice(0, 12)}` : ''}`);
        if (target.kind === 'github') console.log(`${DIM}a GitHub backup is only as private as that repository; a public one shows your session ids.${OFF}`);
      } else if (sub === 'add') {
        if (!rest[0]) usage(2);
        const witness = JSON.parse(readFileSync(resolve(rest[0]), 'utf8')) as GitHubWitness;
        const check = verifyGitHubWitness(witness);
        if (!check.ok) {
          printWitnessCheck(witness, check);
          console.error(`${RED}not filed: GitHub does not confirm this witness right now.${OFF}`);
          process.exit(check.unreachable && !check.findings.some((f) => f.severity === 'tamper') ? 2 : 1);
        }
        const ledgerPath = ledgerArg(flag('--ledger'));
        const { appended } = appendWitness(ledgerPath, witness);
        console.log(appended ? `${GREEN}filed${OFF}  ${witness.repo}@${witness.commitSha.slice(0, 12)}  in ${ledgerPath}` : `${DIM}already in ${ledgerPath}${OFF}`);
      } else {
        usage(2);
      }
    } catch (e) {
      if (e instanceof WitnessBackupRefused) {
        console.error(`${RED}${BOLD}${e.code}${OFF}  ${e.message}`);
        process.exit(1);
      }
      if (e instanceof WitnessLedgerError) {
        console.error(`${RED}${e.code}${OFF}  ${e.message}`);
        process.exit(1);
      }
      console.error(`${RED}${(e as Error).message.trim()}${OFF}`);
      process.exit(2);
    }
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
      resume: has('--resume') || has('--rotate-on-resume'),
      rotateOnResume: has('--rotate-on-resume'),
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

function printWitnessLedger(report: WitnessLedgerReport, path: string) {
  const sev = (s: string) => (s === 'tamper' ? RED : s === 'warn' ? YELLOW : DIM);
  for (const f of report.ledgerFindings) console.log(`${RED}${f.code}${OFF}  ${f.message}`);
  for (const r of report.records) {
    const w = r.witness;
    const colourOf = r.status === 'OK' ? GREEN : r.status === 'WITNESS_UNREACHABLE' ? YELLOW : RED;
    console.log(
      `${colourOf}${r.status.padEnd(22)}${OFF} ${w.commitSha.slice(0, 12)}  ${w.repo}@${w.branch} ${w.path}:${w.line}  seq ${w.anchor.seq}  ${w.anchor.session.slice(0, 8)}  ${w.committedAt}`,
    );
    for (const f of r.findings) console.log(`  ${sev(f.severity)}${f.severity.padEnd(6)}${OFF} ${f.code.padEnd(24)} ${f.message}`);
  }
  const n = report.records.length;
  const count = `${n} record${n === 1 ? '' : 's'} in ${path}`;
  if (report.verdict === 'clean') console.log(`${BOLD}${GREEN}CLEAN${OFF}  ${count}, every one still on GitHub, and no log has lost a line it had.`);
  else if (report.verdict === 'tampered') {
    const bad = report.records.filter((r) => r.findings.some((f) => f.severity === 'tamper')).length;
    console.log(`${BOLD}${RED}TAMPERED${OFF}  ${bad} of ${count} failed. Your ledger proves these existed; GitHub no longer agrees.`);
  } else if (report.verdict === 'unreachable') {
    const bad = report.records.filter((r) => r.status === 'WITNESS_UNREACHABLE').length;
    console.log(`${BOLD}${YELLOW}UNREACHABLE${OFF}  GitHub did not answer for ${bad} of ${count}. That is not a finding either way; try again.`);
  } else console.log(`${BOLD}${YELLOW}EMPTY${OFF}  ${path} holds no records, so there is nothing to check.`);
}

function printWitnessCheck(w: GitHubWitness, check: { ok: boolean; unreachable?: boolean; findings: { code: string; severity: string; message: string }[] }) {
  const label = check.ok ? `${GREEN}WITNESSED${OFF}` : check.unreachable && !check.findings.some((f) => f.severity === 'tamper') ? `${YELLOW}WITNESS UNREACHABLE${OFF}` : `${RED}WITNESS FAILED${OFF}`;
  console.log(`${label}  ${w.repo}@${w.commitSha.slice(0, 12)}  ${w.path}:${w.line}`);
  for (const f of check.findings) {
    const c = f.severity === 'tamper' ? RED : f.severity === 'warn' ? YELLOW : DIM;
    console.log(`  ${c}${String(f.severity).padEnd(6)}${OFF} ${f.code.padEnd(24)} ${f.message}`);
  }
}
