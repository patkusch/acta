/**
 * A public GitHub repository as an anchor sink and witness.
 *
 * This sink was built on 2026-09-16 because a dedicated transparency log
 * (Sigstore Rekor) looked blocked: `hashedrekord` needs an Ed25519ph
 * signature (the prehashed variant, RFC 8032 §5.1.6), and Node's
 * `node:crypto` only signs pure Ed25519. Re-checked for real on 2026-09-22,
 * that blocker turned out not to hold any more — `@noble/curves` implements
 * Ed25519ph, and Rekor's public write path is live — so `src/rekor-anchor.ts`
 * now exists alongside this one. This module is kept as-is, not replaced:
 * it does not need `@noble/curves`, it is a real, independent witness in its
 * own right, and the README explains what each one proves that the other
 * does not.
 *
 * What a transparency log actually buys — independent of the protocol — is
 * two things: an existence proof (this value existed by this time) and
 * append-only history (rewriting it later is detectable). A commit to a
 * public GitHub repository gives both, weaker but real and checkable today:
 *
 *   - existence:    a commit has a SHA computed from its content and parents,
 *                   and a committer timestamp GitHub itself assigns.
 *   - append-only:  under normal history a branch only grows; a past commit
 *                   stays fetchable by its SHA even after the branch moves on.
 *
 * What it does NOT buy, and the README says so: GitHub (or an attacker who
 * compromises the token this sink pushes with) *can* force-push and rewrite
 * a branch's history. A commit SHA that is no longer reachable from any ref
 * is eventually garbage-collected and this sink's own re-fetch-by-branch
 * would then show a shorter file with no sign the anchor was ever there.
 * `verifyGitHubWitness` defends against this exactly as far as it can: it
 * fetches by the *commit SHA* the witness recorded, not by branch name, so a
 * force-push that moves the branch does not by itself hide the commit — the
 * commit is still fetchable until it is actually GC'd. The honest remaining
 * gap: nothing stops the GC. The only real defence is the one this module
 * cannot provide from inside itself — a copy of past witness records
 * somewhere this sink's own write access cannot reach. `src/witness-ledger.ts`
 * turns that from advice into a feature: every witness is appended to a local
 * ledger, the ledger is backed up on request, and a commit the ledger proves
 * was pushed but GitHub can no longer produce is reported as a rewrite.
 */
import { execFileSync } from 'node:child_process';

import { type Anchor, type AnchorSink, formatAnchor } from './anchor.ts';

export type Severity = 'tamper' | 'warn' | 'info';

export interface Finding {
  code: string;
  severity: Severity;
  message: string;
}

/** Runs `gh` and returns stdout, or throws with `gh`'s stderr on a non-zero exit. Injectable so tests never touch the network. */
export type GhExec = (args: string[], input?: string) => string;

function defaultGhExec(args: string[], input?: string): string {
  return execFileSync('gh', args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

/** What `gh` said on stderr when it failed, or the error's own message when it said nothing (an injected exec, a spawn failure). */
function errorText(e: unknown): string {
  const stderr = (e as { stderr?: unknown }).stderr;
  const text = typeof stderr === 'string' ? stderr : Buffer.isBuffer(stderr) ? stderr.toString('utf8') : '';
  return (text.trim() ? text : e instanceof Error ? e.message : String(e)).trim();
}

/**
 * Did GitHub answer "that is not there", as opposed to failing to answer at
 * all? The difference is the whole tamper signal: a missing commit is
 * evidence, a dropped connection, a rate limit or an expired token is not.
 * GitHub answers a SHA it does not hold with 422 ("No commit found") and a
 * missing path or ref with 404. Anything else — no network, 5xx, 401, 403 — is
 * "could not check", and is never read as "not there".
 *
 * Caveat, stated where it bites: for a *private* repo GitHub also answers 404
 * to an account that cannot see it, so the wrong `gh` login reads as "not
 * there". Public repos, which is what a witness should be, do not have that.
 */
export function isNotFound(e: unknown): boolean {
  return /HTTP (404|410|422)\b|not found|no commit found/i.test(errorText(e));
}

export interface GitHubAnchorOptions {
  /** "owner/name" of a public repository the active `gh` account can push to. */
  repo: string;
  /** Default 'main'. */
  branch?: string;
  /** The append-only log file inside the repo. Default 'anchors.jsonl'. */
  path?: string;
  ghExec?: GhExec;
}

/** What `writeGitHubAnchor` hands back: enough for `verifyGitHubWitness` to independently re-check it later, without trusting this record on its own. */
export interface GitHubWitness {
  provider: 'github';
  repo: string;
  branch: string;
  path: string;
  commitSha: string;
  /** The committer date GitHub's API reported for that commit. */
  committedAt: string;
  /** 0-based line number the anchor landed on inside `path`, at `commitSha`. */
  line: number;
  anchor: Anchor;
}

function parseRepoSpec(spec: string): { repo: string; branch?: string } {
  const i = spec.indexOf(':');
  return i === -1 ? { repo: spec } : { repo: spec.slice(0, i), branch: spec.slice(i + 1) };
}

function decodeContent(base64: string): string {
  return Buffer.from(base64.replace(/\n/g, ''), 'base64').toString('utf8');
}

export function nonEmptyLines(text: string): string[] {
  return text.split('\n').filter((l) => l.length > 0);
}

const REPO_SPEC = /^[\w.-]+\/[\w.-]+$/;

/**
 * Read a file at a ref (branch name or commit SHA). Returns undefined when
 * GitHub says the file is not there; throws on anything else, so a network
 * failure can never be mistaken for an empty log.
 */
export function readGitHubFile(repo: string, ref: string, path: string, exec: GhExec = defaultGhExec): { sha: string; raw: string } | undefined {
  let out: string;
  try {
    out = exec(['api', `repos/${repo}/contents/${path}?ref=${ref}`]);
  } catch (e) {
    if (isNotFound(e)) return undefined;
    throw e;
  }
  const json = JSON.parse(out) as { sha: string; content: string };
  return { sha: json.sha, raw: decodeContent(json.content) };
}

/**
 * The one place this project writes to a GitHub file. `plan` sees the lines
 * already in the file and returns the lines to add (throw from it to refuse;
 * return none to write nothing). Append-only is enforced here, not left to
 * convention: the new file content is built by extending the exact bytes read
 * back from GitHub, and the write is refused — nothing is pushed — if the
 * content about to be sent does not literally begin with what was already
 * there. Both the anchor log and a witness-ledger backup go through this.
 */
export function appendLinesToGitHubFile(
  opts: GitHubAnchorOptions & { message: string; defaultPath: string },
  plan: (existingLines: string[]) => string[],
): { commitSha: string; committedAt: string; firstLine: number } | undefined {
  if (!REPO_SPEC.test(opts.repo)) throw new Error(`not an "owner/name" repo spec: ${opts.repo}`);
  const repo = opts.repo;
  const branch = opts.branch ?? 'main';
  const path = opts.path ?? opts.defaultPath;
  const exec = opts.ghExec ?? defaultGhExec;

  // Only "no file here" means a fresh log. A failed read must not: writing on
  // top of a file that could not be read is exactly the mistake to refuse.
  const existing = readGitHubFile(repo, branch, path, exec);
  const existingRaw = existing?.raw ?? '';
  const existingLines = nonEmptyLines(existingRaw);

  const toAdd = plan(existingLines);
  if (toAdd.length === 0) return undefined;

  const addition = toAdd.join('\n') + '\n';
  const newRaw = existingRaw.length === 0 || existingRaw.endsWith('\n') ? existingRaw + addition : existingRaw + '\n' + addition;

  if (!newRaw.startsWith(existingRaw)) {
    // Cannot happen given how newRaw is built above; kept as a hard stop in
    // case this function is ever refactored to build content another way.
    throw new Error('refusing to write to the GitHub sink: new content does not extend the existing file byte-for-byte');
  }

  const body = {
    message: opts.message,
    content: Buffer.from(newRaw, 'utf8').toString('base64'),
    branch,
    ...(existing?.sha ? { sha: existing.sha } : {}),
  };

  const out = exec(['api', `repos/${repo}/contents/${path}`, '-X', 'PUT', '--input', '-'], JSON.stringify(body));
  const resp = JSON.parse(out) as { commit: { sha: string; committer?: { date?: string }; author?: { date?: string } } };
  const committedAt = resp.commit.committer?.date ?? resp.commit.author?.date ?? '';
  return { commitSha: resp.commit.sha, committedAt, firstLine: existingLines.length };
}

/**
 * Commit one more line to the public anchor file and return a witness a
 * verifier can check independently later. See `appendLinesToGitHubFile` for
 * how append-only is enforced.
 */
export function writeGitHubAnchor(anchor: Anchor, opts: GitHubAnchorOptions): GitHubWitness {
  const branch = opts.branch ?? 'main';
  const path = opts.path ?? 'anchors.jsonl';
  const done = appendLinesToGitHubFile(
    { ...opts, branch, path, defaultPath: 'anchors.jsonl', message: `anchor: ${anchor.session} seq=${anchor.seq} ${anchor.hash.slice(0, 12)}` },
    () => [formatAnchor(anchor)],
  )!;
  return { provider: 'github', repo: opts.repo, branch, path, commitSha: done.commitSha, committedAt: done.committedAt, line: done.firstLine, anchor };
}

export interface WitnessCheck {
  /** True only when nothing was wrong AND every fetch was answered. An unanswered fetch is not a pass. */
  ok: boolean;
  /** True when at least one fetch failed for a reason other than "GitHub says it is not there" (network, rate limit, auth). Not a tamper signal. */
  unreachable: boolean;
  findings: Finding[];
  /** The non-empty lines of the file as it stood at the witnessed commit; absent when the file could not be read there. */
  lines?: string[];
}

/**
 * Fetch the commit and the file *pinned to that commit's SHA* — not the
 * branch — and confirm the anchor this witness claims is really the line it
 * claims, at the position it claims. Fetching by SHA rather than by branch
 * is the point: it is what still catches the anchor after the branch has
 * moved on, and stops catching it only once the commit itself is no longer
 * fetchable (see the module doc for that honest limit).
 *
 * "GitHub says it is not there" is a tamper finding; "GitHub did not answer"
 * is `WITNESS_UNREACHABLE`, a warning that leaves `ok` false but is not
 * evidence of anything.
 */
export function verifyGitHubWitness(witness: GitHubWitness, opts: { ghExec?: GhExec } = {}): WitnessCheck {
  const exec = opts.ghExec ?? defaultGhExec;
  const findings: Finding[] = [];
  let unreachable = false;
  const add = (code: string, severity: Severity, message: string) => findings.push({ code, severity, message });
  const cannotReach = (what: string, e: unknown) => {
    unreachable = true;
    add('WITNESS_UNREACHABLE', 'warn', `could not check ${what}: ${errorText(e)}`);
  };
  const done = (lines?: string[]): WitnessCheck => ({ ok: !unreachable && !findings.some((f) => f.severity === 'tamper'), unreachable, findings, lines });

  let commitDate: string | undefined;
  try {
    const out = exec(['api', `repos/${witness.repo}/commits/${witness.commitSha}`]);
    const json = JSON.parse(out) as { commit?: { committer?: { date?: string }; author?: { date?: string } } };
    commitDate = json.commit?.committer?.date ?? json.commit?.author?.date;
  } catch (e) {
    if (isNotFound(e)) add('WITNESS_COMMIT_NOT_FOUND', 'tamper', `commit ${witness.commitSha} does not exist in ${witness.repo}: ${errorText(e)}`);
    else cannotReach(`commit ${witness.commitSha} in ${witness.repo}`, e);
    return done();
  }

  if (commitDate !== witness.committedAt) {
    add(
      'WITNESS_TIMESTAMP_MISMATCH',
      'tamper',
      `commit ${witness.commitSha} is timestamped ${commitDate ?? '(unknown)'}, but the witness record claims ${witness.committedAt}`,
    );
  }

  let lines: string[] | undefined;
  try {
    const file = readGitHubFile(witness.repo, witness.commitSha, witness.path, exec);
    if (!file) {
      add('WITNESS_FILE_NOT_FOUND', 'tamper', `${witness.path} does not exist at commit ${witness.commitSha}`);
    } else {
      lines = nonEmptyLines(file.raw);
      const actual = lines[witness.line];
      const expected = formatAnchor(witness.anchor);
      if (actual === undefined) {
        add('WITNESS_LINE_MISSING', 'tamper', `commit ${witness.commitSha} has no line ${witness.line} in ${witness.path} (file has ${lines.length} lines)`);
      } else if (actual !== expected) {
        add('WITNESS_CONTENT_MISMATCH', 'tamper', `line ${witness.line} of ${witness.path} at commit ${witness.commitSha} does not match the anchor this witness claims`);
      }
    }
  } catch (e) {
    cannotReach(`${witness.path} at commit ${witness.commitSha}`, e);
  }

  return done(lines);
}

export class GitHubAnchorSink implements AnchorSink<GitHubWitness> {
  private opts: GitHubAnchorOptions;
  constructor(opts: GitHubAnchorOptions) {
    this.opts = opts;
  }
  write(anchor: Anchor): GitHubWitness {
    return writeGitHubAnchor(anchor, this.opts);
  }
}

/** Parses `--github owner/name[:branch]` from the CLI into repo/branch. */
export { parseRepoSpec };
