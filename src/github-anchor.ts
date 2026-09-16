/**
 * A public GitHub repository as an anchor sink and witness.
 *
 * The blocker on a dedicated transparency log (Sigstore Rekor) is narrow but
 * real: Rekor's `hashedrekord` entry needs an Ed25519ph signature (the
 * prehashed variant, RFC 8032 §5.1.6), and Node's `node:crypto` only signs
 * pure Ed25519 (§5.1.6's PH mode is not exposed). The `rekord` entry type
 * sidesteps that by taking the artifact itself rather than a prehash, but it
 * depends on the v1 public instance, which is mid-migration. Neither is
 * ready to build on today.
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
 * cannot provide from inside itself — keep your own copy of past witness
 * records (they are a few hundred bytes of JSON) somewhere this sink's own
 * write access cannot reach, the same discipline the append-only file sink
 * already asks for.
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

function nonEmptyLines(text: string): string[] {
  return text.split('\n').filter((l) => l.length > 0);
}

/**
 * Commit one more line to the public anchor file and return a witness a
 * verifier can check independently later. Append-only is enforced here, not
 * left to convention: the new file content is built by extending the exact
 * bytes read back from GitHub, and the write is refused — nothing is pushed
 * — if the content about to be sent does not literally begin with what was
 * already there.
 */
export function writeGitHubAnchor(anchor: Anchor, opts: GitHubAnchorOptions): GitHubWitness {
  if (!/^[\w.-]+\/[\w.-]+$/.test(opts.repo)) throw new Error(`not an "owner/name" repo spec: ${opts.repo}`);
  const repo = opts.repo;
  const branch = opts.branch ?? 'main';
  const path = opts.path ?? 'anchors.jsonl';
  const exec = opts.ghExec ?? defaultGhExec;

  let existingRaw = '';
  let sha: string | undefined;
  try {
    const out = exec(['api', `repos/${repo}/contents/${path}?ref=${branch}`]);
    const json = JSON.parse(out) as { sha: string; content: string };
    sha = json.sha;
    existingRaw = decodeContent(json.content);
  } catch {
    // No file yet on this branch (first anchor, or the branch/repo is fresh).
    // Nothing to preserve; the write below creates it.
  }

  const newLine = formatAnchor(anchor);
  const newRaw = existingRaw.length === 0 || existingRaw.endsWith('\n') ? existingRaw + newLine + '\n' : existingRaw + '\n' + newLine + '\n';

  if (!newRaw.startsWith(existingRaw)) {
    // Cannot happen given how newRaw is built above; kept as a hard stop in
    // case this function is ever refactored to build content another way.
    throw new Error('refusing to write to the GitHub anchor sink: new content does not extend the existing file byte-for-byte');
  }

  const line = nonEmptyLines(existingRaw).length;
  const body = {
    message: `anchor: ${anchor.session} seq=${anchor.seq} ${anchor.hash.slice(0, 12)}`,
    content: Buffer.from(newRaw, 'utf8').toString('base64'),
    branch,
    ...(sha ? { sha } : {}),
  };

  const out = exec(['api', `repos/${repo}/contents/${path}`, '-X', 'PUT', '--input', '-'], JSON.stringify(body));
  const resp = JSON.parse(out) as { commit: { sha: string; committer?: { date?: string }; author?: { date?: string } } };
  const committedAt = resp.commit.committer?.date ?? resp.commit.author?.date ?? '';

  return { provider: 'github', repo, branch, path, commitSha: resp.commit.sha, committedAt, line, anchor };
}

/**
 * Fetch the commit and the file *pinned to that commit's SHA* — not the
 * branch — and confirm the anchor this witness claims is really the line it
 * claims, at the position it claims. Fetching by SHA rather than by branch
 * is the point: it is what still catches the anchor after the branch has
 * moved on, and stops catching it only once the commit itself is no longer
 * fetchable (see the module doc for that honest limit).
 */
export function verifyGitHubWitness(witness: GitHubWitness, opts: { ghExec?: GhExec } = {}): { ok: boolean; findings: Finding[] } {
  const exec = opts.ghExec ?? defaultGhExec;
  const findings: Finding[] = [];
  const add = (code: string, severity: Severity, message: string) => findings.push({ code, severity, message });

  let commitDate: string | undefined;
  try {
    const out = exec(['api', `repos/${witness.repo}/commits/${witness.commitSha}`]);
    const json = JSON.parse(out) as { commit?: { committer?: { date?: string }; author?: { date?: string } } };
    commitDate = json.commit?.committer?.date ?? json.commit?.author?.date;
  } catch (e) {
    add('WITNESS_COMMIT_NOT_FOUND', 'tamper', `commit ${witness.commitSha} does not exist in ${witness.repo}: ${(e as Error).message.trim()}`);
    return { ok: false, findings };
  }

  if (commitDate !== witness.committedAt) {
    add(
      'WITNESS_TIMESTAMP_MISMATCH',
      'tamper',
      `commit ${witness.commitSha} is timestamped ${commitDate ?? '(unknown)'}, but the witness record claims ${witness.committedAt}`,
    );
  }

  try {
    const out = exec(['api', `repos/${witness.repo}/contents/${witness.path}?ref=${witness.commitSha}`]);
    const json = JSON.parse(out) as { content: string };
    const lines = nonEmptyLines(decodeContent(json.content));
    const actual = lines[witness.line];
    const expected = formatAnchor(witness.anchor);
    if (actual === undefined) {
      add('WITNESS_LINE_MISSING', 'tamper', `commit ${witness.commitSha} has no line ${witness.line} in ${witness.path} (file has ${lines.length} lines)`);
    } else if (actual !== expected) {
      add('WITNESS_CONTENT_MISMATCH', 'tamper', `line ${witness.line} of ${witness.path} at commit ${witness.commitSha} does not match the anchor this witness claims`);
    }
  } catch (e) {
    add('WITNESS_FILE_NOT_FOUND', 'tamper', `could not read ${witness.path} at commit ${witness.commitSha}: ${(e as Error).message.trim()}`);
  }

  return { ok: !findings.some((f) => f.severity === 'tamper'), findings };
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
