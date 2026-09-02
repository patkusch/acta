/**
 * The verifier. It takes a ledger and, optionally, two things the ledger
 * cannot supply for itself: a public key obtained out of band, and anchors
 * written somewhere the agent could not reach.
 *
 * The verdict is deliberately three-valued:
 *
 *   tampered   — at least one check failed.
 *   consistent — the ledger agrees with itself. Nothing more. A ledger
 *                rewritten end to end by whoever holds the key is consistent.
 *   verified   — consistent, signed by a key you supplied, and matching an
 *                anchor you supplied. This is the only verdict that means
 *                "what happened is what it says happened", and even then only
 *                up to the anchor.
 */
import type { KeyObject } from 'node:crypto';

import { canon, digest, sha256 } from './canon.ts';
import type { Anchor } from './anchor.ts';
import {
  GENESIS_PREV,
  bodyOf,
  fingerprint,
  hashBody,
  publicKeyFromBase64,
  publicKeyToBase64,
  verifySignature,
  type Entry,
  type ReadProblem,
} from './ledger.ts';

export type Severity = 'tamper' | 'warn' | 'info';

export interface Finding {
  code: string;
  severity: Severity;
  seq?: number;
  message: string;
}

export type Status = 'tampered' | 'consistent' | 'verified';

export interface Verdict {
  status: Status;
  findings: Finding[];
  entries: number;
  session?: string;
  head?: { seq: number; hash: string };
  /** The highest anchor that matched, if any. */
  anchoredTo?: { seq: number; hash: string };
  /** What is missing before this ledger could be called verified. */
  missing: string[];
}

export interface VerifyOptions {
  /** The recorder's public key, obtained somewhere other than the ledger directory. */
  trustedKey?: KeyObject;
  anchors?: Anchor[];
  /** Fetch a result body stored out of line, by digest. */
  blob?: (digest: string) => Buffer | undefined;
  problems?: ReadProblem[];
}

export function verifyLedger(entries: Entry[], opts: VerifyOptions = {}): Verdict {
  const findings: Finding[] = [];
  const add = (code: string, severity: Severity, message: string, seq?: number) =>
    findings.push({ code, severity, message, seq });
  /** Anchors for this session; filled in once the genesis entry names it. */
  let relevant: Anchor[] = [];

  for (const p of opts.problems ?? []) {
    if (p.missing) add('MISSING', 'tamper', `${p.message} — if an anchor exists for this session, the record was removed whole`);
    else add('UNPARSEABLE', 'tamper', `line ${p.line}: ${p.message}`);
  }

  if (entries.length === 0) {
    if (!findings.some((f) => f.code === 'MISSING')) add('EMPTY', 'tamper', 'no entries');
    return conclude();
  }

  // --- genesis ---------------------------------------------------------------
  const first = entries[0];
  let session: string | undefined;
  let key: KeyObject | undefined;

  if (first.kind !== 'open' || first.seq !== 0 || first.prev !== GENESIS_PREV) {
    add('BAD_GENESIS', 'tamper', 'first entry is not a genesis `open` at seq 0', 0);
  } else {
    session = first.session;
    let declared: KeyObject | undefined;
    try {
      declared = publicKeyFromBase64(first.pub);
    } catch {
      add('BAD_KEY', 'tamper', 'genesis entry carries an unreadable public key', 0);
    }
    if (opts.trustedKey) {
      key = opts.trustedKey;
      if (declared && publicKeyToBase64(declared) !== publicKeyToBase64(opts.trustedKey)) {
        add(
          'KEY_MISMATCH',
          'tamper',
          `ledger declares key ${fingerprint(declared)} but the trusted key is ${fingerprint(opts.trustedKey)} — signed by someone else`,
          0,
        );
      }
    } else {
      key = declared;
      add(
        'SELF_ATTESTED_KEY',
        'info',
        'signatures checked against the key the ledger itself declares; whoever rewrote the ledger could have declared their own',
      );
    }
  }

  // --- the chain -------------------------------------------------------------
  const calls = new Map<string, number>();
  const answered = new Map<string, number>();
  let prevHash = GENESIS_PREV;
  let prevTs = '';
  let closedAt: number | undefined;

  entries.forEach((entry, i) => {
    if (entry.seq !== i) add('SEQ_BREAK', 'tamper', `expected seq ${i}, found ${entry.seq}`, i);

    const recomputed = hashBody(bodyOf(entry));
    if (recomputed !== entry.hash) add('HASH_MISMATCH', 'tamper', 'entry bytes do not match their hash', i);

    if (i > 0 && entry.prev !== prevHash) add('CHAIN_BREAK', 'tamper', 'prev does not match the previous entry', i);
    if (i > 0 && entry.kind === 'open') add('SECOND_GENESIS', 'tamper', 'a second `open` entry', i);

    if (key && !verifySignature(entry.hash, entry.sig, key)) {
      add('BAD_SIGNATURE', 'tamper', 'signature does not verify', i);
    }

    if (entry.ts < prevTs) add('CLOCK_REGRESSION', 'warn', `timestamp ${entry.ts} precedes ${prevTs}`, i);

    if (closedAt !== undefined) add('AFTER_CLOSE', 'tamper', `entry after close at seq ${closedAt}`, i);

    switch (entry.kind) {
      case 'call':
        if (calls.has(entry.id)) add('DUPLICATE_CALL', 'tamper', `call id ${entry.id} reused`, i);
        calls.set(entry.id, i);
        break;
      case 'result': {
        if (!calls.has(entry.of)) add('ORPHAN_RESULT', 'tamper', `result for unknown call ${entry.of}`, i);
        else if (answered.has(entry.of)) add('DUPLICATE_RESULT', 'tamper', `second result for call ${entry.of}`, i);
        answered.set(entry.of, i);
        if ('body' in entry && entry.body !== undefined) {
          if (digest(entry.body) !== entry.digest) add('BODY_MISMATCH', 'tamper', 'inline result body does not match its digest', i);
          if (Buffer.byteLength(canon(entry.body)) !== entry.bytes) add('BODY_MISMATCH', 'tamper', 'inline result length does not match', i);
        } else if (opts.blob) {
          const blob = opts.blob(entry.digest);
          if (!blob) add('BLOB_MISSING', 'warn', `result body ${entry.digest.slice(0, 12)}… not found in blob store`, i);
          else if (sha256(blob) !== entry.digest) add('BLOB_MISMATCH', 'tamper', 'stored result body does not match its digest', i);
        }
        break;
      }
      case 'close': {
        closedAt = i;
        if (entry.calls !== calls.size || entry.results !== answered.size) {
          add('COUNT_MISMATCH', 'tamper', `close says ${entry.calls} calls / ${entry.results} results; ledger has ${calls.size} / ${answered.size}`, i);
        }
        break;
      }
    }

    prevHash = entry.hash;
    prevTs = entry.ts;
  });

  // --- unanswered calls ------------------------------------------------------
  const closing = closedAt !== undefined ? (entries[closedAt] as Extract<Entry, { kind: 'close' }>) : undefined;
  for (const [id, seq] of calls) {
    if (answered.has(id)) continue;
    if (closing && !closing.open.includes(id)) {
      add('RESULT_REMOVED', 'tamper', `call ${id} has no result, and the close entry does not list it as open`, seq);
    } else {
      add('UNANSWERED_CALL', 'warn', `call ${id} has no recorded outcome`, seq);
    }
  }

  // --- anchors ---------------------------------------------------------------
  const head = entries[entries.length - 1];
  let anchoredTo: Verdict['anchoredTo'];
  relevant = (opts.anchors ?? []).filter((a) => a.session === session);
  for (const a of relevant.sort((x, y) => x.seq - y.seq)) {
    const at = entries[a.seq];
    if (!at || at.seq !== a.seq) {
      add('TRUNCATED', 'tamper', `anchor records seq ${a.seq} (${a.hash.slice(0, 12)}…) but the ledger ends at seq ${head.seq}`, a.seq);
    } else if (at.hash !== a.hash) {
      add('ANCHOR_MISMATCH', 'tamper', `entry ${a.seq} is ${at.hash.slice(0, 12)}… but was anchored as ${a.hash.slice(0, 12)}…`, a.seq);
    } else {
      anchoredTo = { seq: a.seq, hash: a.hash };
    }
  }
  if (anchoredTo && anchoredTo.seq < head.seq) {
    add('UNANCHORED_TAIL', 'info', `${head.seq - anchoredTo.seq} entries after the last anchor are unanchored`, anchoredTo.seq + 1);
  }

  return conclude(session, { seq: head.seq, hash: head.hash }, anchoredTo);

  function conclude(sess?: string, hd?: Verdict['head'], anch?: Verdict['anchoredTo']): Verdict {
    const tampered = findings.some((f) => f.severity === 'tamper');
    const missing: string[] = [];
    if (!opts.trustedKey) missing.push('a public key obtained outside the ledger directory (--key)');
    if (!anch) missing.push(relevant.length ? 'an anchor that matches' : 'an anchor written where the agent cannot write (--anchors)');
    const status: Status = tampered ? 'tampered' : missing.length ? 'consistent' : 'verified';
    return { status, findings, entries: entries.length, session: sess, head: hd, anchoredTo: anch, missing };
  }
}
