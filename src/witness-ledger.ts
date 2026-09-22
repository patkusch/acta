/**
 * The witness ledger: a local, append-only, one-record-per-line file of every
 * witness `acta anchor --github` or `acta anchor --rekor` has ever been
 * handed back.
 *
 * Why it exists. A GitHub witness is a commit SHA. The party who can push to
 * the witness repository can also force-push it, and once the discarded commit
 * is garbage-collected a lookup by SHA just says "not found" — which, on its
 * own, looks the same as a typo. What turns "not found" into evidence is a
 * record, kept somewhere that party cannot reach, saying the commit was there.
 * This file is that record, and this module does the three things the record
 * needs:
 *
 *   - append to it, and refuse to do anything else to it (`appendWitness`);
 *   - copy it somewhere else the user controls, and refuse to overwrite a copy
 *     that knows something this one does not (`backupWitnessLedger`);
 *   - check every record against its provider, and tell "the provider says
 *     this is gone" (tamper) apart from "the provider did not answer" (not
 *     tamper) (`verifyWitnessLedger`).
 *
 * **Rekor witnesses, and cross-submission consistency — added 2026-09-23.**
 * A Rekor witness does not have GitHub's mutable-branch problem — Rekor has
 * no equivalent of a force-push a caller can ask for — but it has its own:
 * `verifyRekorWitness` checks one submission at a time against Rekor's own,
 * now checkpoint-verified, word for its own history. Two witnesses recorded
 * here from the same log, in the order they were filed, are exactly what a
 * real RFC 6962 consistency proof needs: `verifyWitnessLedger` now runs
 * `verifyLogConsistency` (`src/rekor-anchor.ts`) between each consecutive
 * pair of Rekor records it holds, in ledger order, so a log that answers
 * every single-entry check honestly but quietly rewrites history *between*
 * two of a caller's own submissions is still caught.
 *
 * What it cannot do is written in the README and worth repeating here: a
 * rewrite that happens before the first backup leaves nothing to compare, and
 * a ledger nobody backed up is only as safe as the disk it sits on.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { formatAnchor } from './anchor.ts';
import {
  appendLinesToGitHubFile,
  nonEmptyLines,
  readGitHubFile,
  verifyGitHubWitness,
  type Finding,
  type GhExec,
  type GitHubWitness,
} from './github-anchor.ts';
import { verifyRekorWitness, verifyLogConsistency, type RekorExec, type RekorWitness } from './rekor-anchor.ts';

export const WITNESS_LEDGER_FILE = 'witnesses.jsonl';

export class WitnessLedgerError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

// --- records -----------------------------------------------------------------

const HEX64 = /^[0-9a-f]{64}$/;

/** A ledger line is one of the two witness shapes this project produces. Nothing is stored twice, so nothing can disagree with itself. */
export type StoredWitness = GitHubWitness | RekorWitness;

function parseAnchor(a: any): GitHubWitness['anchor'] | undefined {
  const str = (v: unknown) => typeof v === 'string' && v.length > 0;
  if (!a || !str(a.session) || !Number.isInteger(a.seq) || typeof a.hash !== 'string' || !HEX64.test(a.hash) || typeof a.at !== 'string') return undefined;
  return { session: a.session, seq: a.seq, hash: a.hash, at: a.at };
}

function parseGitHubWitness(o: any): GitHubWitness | undefined {
  const str = (v: unknown) => typeof v === 'string' && v.length > 0;
  if (!str(o.repo) || !str(o.branch) || !str(o.path) || !str(o.commitSha) || typeof o.committedAt !== 'string') return undefined;
  if (!Number.isInteger(o.line) || o.line < 0) return undefined;
  const anchor = parseAnchor(o.anchor);
  if (!anchor) return undefined;
  return { provider: 'github', repo: o.repo, branch: o.branch, path: o.path, commitSha: o.commitSha, committedAt: o.committedAt, line: o.line, anchor };
}

function parseRekorWitness(o: any): RekorWitness | undefined {
  const str = (v: unknown) => typeof v === 'string' && v.length > 0;
  if (!str(o.rekorUrl) || !str(o.uuid) || !str(o.logID) || !str(o.publicKeyHex)) return undefined;
  if (!Number.isInteger(o.logIndex) || !Number.isInteger(o.integratedTime)) return undefined;
  const anchor = parseAnchor(o.anchor);
  if (!anchor) return undefined;
  return { provider: 'rekor', rekorUrl: o.rekorUrl, uuid: o.uuid, logIndex: o.logIndex, logID: o.logID, integratedTime: o.integratedTime, publicKeyHex: o.publicKeyHex, anchor };
}

/** A ledger line is a `GitHubWitness` (repo, branch, path, commit SHA, commit timestamp, line number) or a `RekorWitness` (rekorUrl, uuid, logIndex, logID, integratedTime, publicKeyHex) — always plus the anchor (session id and ledger-head digest) it witnesses. */
export function parseWitnessRecord(line: string): StoredWitness | undefined {
  let o: any;
  try {
    o = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!o || typeof o !== 'object') return undefined;
  if (o.provider === 'github') return parseGitHubWitness(o);
  if (o.provider === 'rekor') return parseRekorWitness(o);
  return undefined;
}

export interface LedgerRecord {
  /** 1-based line number in the ledger file. */
  ledgerLine: number;
  raw: string;
  witness: StoredWitness;
}

export interface LedgerProblem {
  ledgerLine: number;
  message: string;
}

export interface WitnessLedger {
  exists: boolean;
  records: LedgerRecord[];
  problems: LedgerProblem[];
}

export function readWitnessLedger(path: string): WitnessLedger {
  if (!existsSync(path)) return { exists: false, records: [], problems: [] };
  const text = readFileSync(path, 'utf8');
  const records: LedgerRecord[] = [];
  const problems: LedgerProblem[] = [];
  const lines = text.split('\n');
  const unterminated = text.length > 0 && !text.endsWith('\n');
  lines.forEach((raw, i) => {
    if (raw.length === 0) return;
    const witness = parseWitnessRecord(raw);
    if (!witness) problems.push({ ledgerLine: i + 1, message: 'not a witness record' });
    else if (unterminated && i === lines.length - 1) problems.push({ ledgerLine: i + 1, message: 'final line is unterminated (a write was cut short)' });
    else records.push({ ledgerLine: i + 1, raw, witness });
  });
  return { exists: true, records, problems };
}

const describeProblems = (ps: LedgerProblem[]) => ps.map((p) => `line ${p.ledgerLine}: ${p.message}`).join('; ');

/** Throws if the ledger at `path` could not safely be appended to. Call before pushing anything, so a bad ledger stops the run before it creates a witness it cannot file. */
export function assertLedgerAppendable(path: string): void {
  const ledger = readWitnessLedger(path);
  if (ledger.problems.length > 0) {
    throw new WitnessLedgerError('LEDGER_CORRUPT', `${path} has lines that are not witness records (${describeProblems(ledger.problems)}); refusing to append to a ledger that is already damaged`);
  }
}

/** Two records claim the same spot in the same underlying log — the thing that makes a second, disagreeing record a conflict rather than just another entry. */
function sameSpot(a: StoredWitness, b: StoredWitness): boolean {
  if (a.provider !== b.provider) return false;
  if (a.provider === 'github') return a.repo === (b as GitHubWitness).repo && a.branch === (b as GitHubWitness).branch && a.path === (b as GitHubWitness).path && a.commitSha === (b as GitHubWitness).commitSha && a.line === (b as GitHubWitness).line;
  return a.rekorUrl === (b as RekorWitness).rekorUrl && a.uuid === (b as RekorWitness).uuid;
}

function describeSpot(w: StoredWitness): string {
  return w.provider === 'github' ? `${w.repo}@${w.commitSha.slice(0, 12)} line ${w.line}` : `${w.rekorUrl} ${w.uuid}`;
}

/**
 * Append one witness. Append-only is enforced here, like the remote log's is:
 * the file is only ever opened for append, a damaged ledger is refused rather
 * than extended, and the bytes that were there before are read back afterwards
 * and must still be there. The same record twice is a no-op; a *different*
 * record claiming the same spot is refused, because one of the two is wrong
 * and the ledger will not choose.
 */
export function appendWitness(path: string, witness: StoredWitness): { appended: boolean } {
  const before = existsSync(path) ? readFileSync(path, 'utf8') : '';
  assertLedgerAppendable(path);

  for (const r of readWitnessLedger(path).records) {
    if (!sameSpot(r.witness, witness)) continue;
    if (JSON.stringify(r.witness) === JSON.stringify(witness)) return { appended: false };
    throw new WitnessLedgerError('LEDGER_CONFLICT', `${path} already holds a different record for ${describeSpot(witness)}; refusing to add a second, disagreeing one`);
  }

  const line = JSON.stringify(witness) + '\n';
  const next = before + line;
  if (!next.startsWith(before)) throw new WitnessLedgerError('NOT_APPEND_ONLY', 'refusing to write: the new ledger content does not extend the existing bytes');
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, line); // O_APPEND: the OS itself will not let this overwrite

  const after = readFileSync(path, 'utf8');
  if (!after.startsWith(before) || !after.endsWith(line)) {
    throw new WitnessLedgerError('LEDGER_CHANGED_UNDERFOOT', `${path} changed while it was being appended to; check it before trusting it`);
  }
  return { appended: true };
}

// --- backup ------------------------------------------------------------------

export type BackupTarget = { kind: 'path'; path: string } | { kind: 'github'; repo: string; branch?: string; path?: string };

/**
 * `owner/name[:branch]` (or `github:owner/name[:branch]`) is a GitHub repo;
 * anything else is a local path. A bare `a/b` that already exists on disk — or
 * whose parent directory does — is a path: guessing wrong toward GitHub would
 * publish a file the user meant to keep on a USB stick.
 */
export function parseBackupTarget(spec: string, opts: { githubPath?: string } = {}): BackupTarget {
  const gh = (s: string): BackupTarget => {
    const i = s.indexOf(':');
    return { kind: 'github', repo: i === -1 ? s : s.slice(0, i), branch: i === -1 ? undefined : s.slice(i + 1), path: opts.githubPath };
  };
  if (spec.startsWith('github:')) return gh(spec.slice('github:'.length));
  const explicitPath = /^([./\\]|[A-Za-z]:)/.test(spec) || existsSync(spec) || (dirname(spec) !== '.' && existsSync(dirname(spec)));
  if (!explicitPath && /^[\w.-]+\/[\w.-]+(:[\w./-]+)?$/.test(spec)) return gh(spec);
  return { kind: 'path', path: resolve(spec) };
}

export type LineRelation = 'same' | 'behind' | 'ahead' | 'diverged';

/**
 * How a backup relates to the local ledger, line for line and byte for byte.
 * `behind`: the backup is a strict prefix — it just needs the newer lines.
 * `ahead`: the backup has lines the local ledger lacks. `diverged`: a line
 * they both have differs. The last two are the tamper signal.
 */
export function relateLines(local: string[], backup: string[]): LineRelation {
  const n = Math.min(local.length, backup.length);
  for (let i = 0; i < n; i++) if (local[i] !== backup[i]) return 'diverged';
  if (backup.length === local.length) return 'same';
  return backup.length < local.length ? 'behind' : 'ahead';
}

export class WitnessBackupRefused extends Error {
  code: 'BACKUP_HAS_UNKNOWN_LINES' | 'BACKUP_DIVERGED';
  constructor(code: WitnessBackupRefused['code'], message: string) {
    super(message);
    this.code = code;
  }
}

function refuse(relation: 'ahead' | 'diverged', where: string, local: string[], backup: string[]): never {
  if (relation === 'ahead') {
    throw new WitnessBackupRefused(
      'BACKUP_HAS_UNKNOWN_LINES',
      `the backup at ${where} holds ${backup.length - local.length} record(s) that this ledger does not (backup ${backup.length}, ledger ${local.length}). ` +
        'Either this ledger was truncated or rewritten after that backup was made, or something else wrote to the backup. ' +
        'Nothing was overwritten. Treat this ledger as suspect: run `acta verify --witnesses` on the backup to see what GitHub still says.',
    );
  }
  let i = 0;
  while (local[i] === backup[i]) i += 1;
  throw new WitnessBackupRefused(
    'BACKUP_DIVERGED',
    `the backup at ${where} and this ledger disagree at record ${i + 1}. ` +
      'Either this ledger was rewritten after that backup was made, or the backup was altered. ' +
      'Nothing was overwritten. Run `acta verify --witnesses` on both and see which one GitHub agrees with.',
  );
}

export interface BackupResult {
  where: string;
  status: 'created' | 'updated' | 'unchanged';
  /** Records written by this call. */
  appended: number;
  /** Records in the backup afterwards. */
  total: number;
  /** For a GitHub backup that wrote something: the commit it landed in. */
  commitSha?: string;
}

/**
 * Copy the ledger to a second place. Idempotent (a backup that is already
 * current is left alone, and no commit is made), append-only (a stale backup
 * is extended with the newer lines, never rewritten), and it refuses — writing
 * nothing — to touch a backup that holds lines the ledger lacks or disagrees
 * with. The GitHub target goes through `appendLinesToGitHubFile`, the same
 * write path the anchor sink uses, so it inherits the same byte-extension
 * guard and "a failed read is not an empty file" rule.
 */
export function backupWitnessLedger(ledgerPath: string, target: BackupTarget, opts: { ghExec?: GhExec } = {}): BackupResult {
  const ledger = readWitnessLedger(ledgerPath);
  if (!ledger.exists) throw new WitnessLedgerError('LEDGER_MISSING', `no witness ledger at ${ledgerPath}`);
  if (ledger.problems.length > 0) {
    throw new WitnessLedgerError('LEDGER_CORRUPT', `${ledgerPath} has lines that are not witness records (${describeProblems(ledger.problems)}); not backing up a damaged ledger`);
  }
  const local = ledger.records.map((r) => r.raw);

  if (target.kind === 'path') {
    const dest = target.path;
    if (dest === resolve(ledgerPath)) throw new WitnessLedgerError('BACKUP_IS_SOURCE', 'the backup location is the ledger itself');
    if (!existsSync(dest)) {
      if (local.length === 0) return { where: dest, status: 'unchanged', appended: 0, total: 0 };
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, local.join('\n') + '\n', { flag: 'wx' }); // wx: never clobber a file that appeared meanwhile
      return { where: dest, status: 'created', appended: local.length, total: local.length };
    }
    const text = readFileSync(dest, 'utf8');
    const backup = nonEmptyLines(text);
    const rel = relateLines(local, backup);
    if (rel === 'ahead' || rel === 'diverged') refuse(rel, dest, local, backup);
    if (rel === 'same') return { where: dest, status: 'unchanged', appended: 0, total: backup.length };
    const tail = local.slice(backup.length);
    appendFileSync(dest, (text.length === 0 || text.endsWith('\n') ? '' : '\n') + tail.join('\n') + '\n');
    return { where: dest, status: 'updated', appended: tail.length, total: local.length };
  }

  const where = `${target.repo}@${target.branch ?? 'main'}:${target.path ?? WITNESS_LEDGER_FILE}`;
  let remoteCount = 0;
  let tailLength = 0;
  const done = appendLinesToGitHubFile(
    {
      repo: target.repo,
      branch: target.branch,
      path: target.path,
      ghExec: opts.ghExec,
      defaultPath: WITNESS_LEDGER_FILE,
      message: `witness backup: ${local.length} record(s)`,
    },
    (backup) => {
      remoteCount = backup.length;
      const rel = relateLines(local, backup);
      if (rel === 'ahead' || rel === 'diverged') refuse(rel, where, local, backup);
      tailLength = local.length - backup.length;
      return local.slice(backup.length);
    },
  );
  if (!done) return { where, status: 'unchanged', appended: 0, total: remoteCount };
  return { where, status: remoteCount === 0 ? 'created' : 'updated', appended: tailLength, total: local.length, commitSha: done.commitSha };
}

// --- verify ------------------------------------------------------------------

export type WitnessVerdict = 'clean' | 'tampered' | 'unreachable' | 'empty';

export interface WitnessRecordResult {
  ledgerLine: number;
  witness: StoredWitness;
  /** `OK`, or the code of the most serious finding. */
  status: string;
  findings: Finding[];
}

export interface WitnessLedgerReport {
  verdict: WitnessVerdict;
  records: WitnessRecordResult[];
  /** Findings about the ledger file itself (unreadable lines). */
  ledgerFindings: Finding[];
}

type Head = { lines: string[] } | { absent: true } | { unreachable: string };

function firstDifference(head: string[], base: string[]): string | undefined {
  for (let i = 0; i < base.length; i++) {
    if (head[i] === undefined) return `the head has only ${head.length} line(s) but this commit had ${base.length}`;
    if (head[i] !== base[i]) return `line ${i} of the head is not what it was at this commit`;
  }
  return undefined;
}

/** Per-record check for a GitHub witness — see `verifyWitnessLedger`'s doc for the three questions this answers. */
function checkGitHubRecord(w: GitHubWitness, ghExec: GhExec | undefined, heads: Map<string, Head>): Finding[] {
  const check = verifyGitHubWitness(w, { ghExec });
  const findings: Finding[] = check.findings.map((f) =>
    f.code === 'WITNESS_COMMIT_NOT_FOUND'
      ? {
          code: 'WITNESS_REWRITTEN',
          severity: 'tamper' as const,
          message:
            `your ledger records commit ${w.commitSha} as pushed to ${w.repo}@${w.branch} at ${w.committedAt}, and GitHub can no longer produce it. ` +
            `It existed, so it was discarded: the branch was force-pushed or the repository was replaced. (${f.message})`,
        }
      : f,
  );

  const key = `${w.repo}@${w.branch}:${w.path}`;
  let head = heads.get(key);
  if (!head) {
    try {
      const file = readGitHubFile(w.repo, w.branch, w.path, ghExec);
      head = file ? { lines: nonEmptyLines(file.raw) } : { absent: true };
    } catch (e) {
      head = { unreachable: (e as Error).message.trim() };
    }
    heads.set(key, head);
  }

  if ('unreachable' in head) {
    if (!check.unreachable) findings.push({ code: 'WITNESS_UNREACHABLE', severity: 'warn', message: `could not read ${w.path} at the head of ${w.repo}@${w.branch}: ${head.unreachable}` });
  } else if ('absent' in head) {
    findings.push({ code: 'LOG_PREFIX_CHANGED', severity: 'tamper', message: `${w.repo}@${w.branch} no longer has ${w.path} at its head; the log this record was written into is gone` });
  } else if (check.lines) {
    const why = firstDifference(head.lines, check.lines);
    if (why) findings.push({ code: 'LOG_PREFIX_CHANGED', severity: 'tamper', message: `the head of ${w.repo}@${w.branch} no longer begins with the log as this witness saw it: ${why}` });
  } else if (findings.some((f) => f.code === 'WITNESS_REWRITTEN')) {
    // The commit is gone; all the ledger can still ask is whether the head kept the anchor.
    if (head.lines[w.line] === formatAnchor(w.anchor)) {
      findings.push({ code: 'HEAD_STILL_HOLDS_ANCHOR', severity: 'info', message: `the head of ${w.repo}@${w.branch} still has this anchor on line ${w.line}; the history around it was rewritten, the anchor itself survived` });
    } else {
      findings.push({ code: 'LOG_PREFIX_CHANGED', severity: 'tamper', message: `the head of ${w.repo}@${w.branch} does not have this anchor on line ${w.line} either; it is gone from the log, not only from history` });
    }
  }
  return findings;
}

export interface VerifyWitnessLedgerOptions {
  ghExec?: GhExec;
  rekorExec?: RekorExec;
  /** Override the key `verifyRekorWitness`/`verifyLogConsistency` check checkpoints against — tests only; production always uses the real rekor.sigstore.dev key. */
  rekorCheckpointPublicKeyPem?: string;
}

/**
 * Check every record in the ledger against the provider it names.
 *
 * A GitHub record answers three questions, all from GitHub, none from the
 * ledger: is the commit still fetchable by SHA (`WITNESS_REWRITTEN` if not —
 * the ledger is the proof it once existed); does the branch head still begin
 * with the log as this witness saw it (`LOG_PREFIX_CHANGED`); could GitHub be
 * asked at all (`WITNESS_UNREACHABLE`, never tamper on its own).
 *
 * A Rekor record is checked with `verifyRekorWitness` (checkpoint-signature
 * verified, inclusion proof recomputed against that verified root). Two or
 * more Rekor records in the same ledger get one more check `verifyGitHubWitness`
 * has no equivalent of: `verifyLogConsistency` between each consecutive pair,
 * in the order they were filed, so a log that answers every single-entry
 * check honestly but rewrites history *between* two of a caller's own
 * submissions does not pass unnoticed — its findings are attached to the
 * later record of the pair.
 *
 * Tamper anywhere outranks an unreachable record in the verdict: one record
 * its provider disowns is a finding no network failure elsewhere can dilute.
 */
export function verifyWitnessLedger(ledgerPath: string, opts: VerifyWitnessLedgerOptions = {}): WitnessLedgerReport {
  const ledger = readWitnessLedger(ledgerPath);
  const ledgerFindings: Finding[] = ledger.problems.map((p) => ({
    code: 'WITNESS_LEDGER_MALFORMED',
    severity: 'tamper',
    message: `ledger line ${p.ledgerLine}: ${p.message}. A record that cannot be read cannot be checked, and a damaged ledger cannot vouch for anything it skipped.`,
  }));

  const heads = new Map<string, Head>();
  const findingsByLine = new Map<number, Finding[]>();
  for (const { ledgerLine, witness } of ledger.records) {
    findingsByLine.set(
      ledgerLine,
      witness.provider === 'github' ? checkGitHubRecord(witness, opts.ghExec, heads) : verifyRekorWitness(witness, { exec: opts.rekorExec, checkpointPublicKeyPem: opts.rekorCheckpointPublicKeyPem }).findings,
    );
  }

  // Cross-submission consistency: every consecutive pair of Rekor records,
  // in the order the ledger holds them (append-only, so that is filing
  // order — the ledger's own chronological order).
  const rekorRecords = ledger.records.filter((r): r is LedgerRecord & { witness: RekorWitness } => r.witness.provider === 'rekor');
  for (let i = 1; i < rekorRecords.length; i++) {
    const consistency = verifyLogConsistency(rekorRecords[i - 1].witness, rekorRecords[i].witness, { exec: opts.rekorExec, checkpointPublicKeyPem: opts.rekorCheckpointPublicKeyPem });
    const line = rekorRecords[i].ledgerLine;
    findingsByLine.set(line, [...(findingsByLine.get(line) ?? []), ...consistency.findings]);
  }

  // Status stays the single marker 'WITNESS_UNREACHABLE' regardless of which
  // provider's own finding code (WITNESS_UNREACHABLE, REKOR_UNREACHABLE,
  // REKOR_CONSISTENCY_UNREACHABLE) produced it — everything downstream
  // (the CLI, the exit-code logic) only ever needs "reachable or not".
  const records: WitnessRecordResult[] = ledger.records.map(({ ledgerLine, witness }) => {
    const findings = findingsByLine.get(ledgerLine) ?? [];
    const firstTamper = findings.find((f) => f.severity === 'tamper');
    const isUnreachable = !firstTamper && findings.some((f) => f.severity === 'warn');
    return { ledgerLine, witness, status: firstTamper?.code ?? (isUnreachable ? 'WITNESS_UNREACHABLE' : 'OK'), findings };
  });

  const tampered = ledgerFindings.length > 0 || records.some((r) => r.findings.some((f) => f.severity === 'tamper'));
  const unreachable = records.some((r) => r.status === 'WITNESS_UNREACHABLE');
  const verdict: WitnessVerdict = tampered ? 'tampered' : unreachable ? 'unreachable' : records.length === 0 ? 'empty' : 'clean';
  return { verdict, records, ledgerFindings };
}
