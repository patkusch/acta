/**
 * Sigstore Rekor's public transparency log as an anchor sink and witness.
 *
 * The README used to record this as blocked, and it was, on 2026-09-16: a
 * `hashedrekord` entry needs an Ed25519ph signature (the prehashed variant,
 * RFC 8032 §5.1.6), and Node's `node:crypto` only signs pure Ed25519 — the PH
 * mode is not exposed. Re-checked for real on 2026-09-22, both pieces that
 * were missing are now available:
 *
 *   - `@noble/curves` 2.4.0 exports `ed25519ph` (`@noble/curves/ed25519.js`),
 *     an RFC 8032 §5.1 implementation. Signed and verified against the
 *     RFC's own §7.3 Ed25519ph test vector (message "abc") byte-for-byte
 *     before this module was written. This is the project's first runtime
 *     dependency (pinned exact, not a range — the one piece of supply
 *     chain this design now trusts). Node's own `generateKeyPairSync('ed25519')`
 *     keys are usable with it — confirmed the two libraries derive the same
 *     public key from the same seed and cross-verify each other's plain
 *     Ed25519 signatures — so key export (PEM/SPKI) still goes through
 *     `node:crypto`, not `@noble/curves`, everywhere it can.
 *   - `rekor.sigstore.dev` (Rekor v1) is still the public-good instance's
 *     default log; `hashedrekord` v0.0.1 has taken Ed25519ph keys since
 *     sigstore/rekor#1945 (merged 2024-03-04) — this was never actually the
 *     blocker, Node's signing was. `/api/v1/log/entries` answered a live GET
 *     and a live POST when checked. Rekor v2 (rekor-tiles) is GA but the
 *     public-good instance has not cut over to it, so v1 is still the
 *     reachable public write path.
 *
 * What Ed25519ph means for a hashedrekord entry, confirmed by reading
 * sigstore/sigstore's `pkg/signature/ed25519ph.go`: the log only accepts
 * `crypto.SHA512` for this key type, so `data.hash.algorithm` must be
 * `sha512`, its `value` is SHA-512 of the artifact, and the signature is
 * produced by signing the artifact directly with Ed25519ph (which performs
 * that same SHA-512 prehash internally, per RFC 8032) — not by signing an
 * externally-computed digest. The "artifact" this sink signs is the anchor
 * line itself (`formatAnchor`), the same bytes every other sink anchors.
 *
 * What this sink adds over the GitHub witness: independent operators run
 * (or could run) copies of a real transparency log's Merkle tree, and this
 * module's `verifyRekorWitness` recomputes the RFC 6962 inclusion proof
 * from scratch (leaf hash, audit path, root) rather than trusting the
 * server's word for it — ported from and checked against
 * `transparency-dev/merkle`'s `proof.VerifyInclusion` (what Rekor's own
 * client code uses) and proven against a real, independently-fetched log
 * entry before this module was written: the recomputed root matched the
 * server's claimed root exactly.
 *
 * What it did not add yet, until 2026-09-23: verifying the checkpoint's own
 * signature (the signed tree head that vouches for the root hash
 * `verifyRekorWitness` checks the leaf against), and log consistency across
 * repeated submissions the way the witness ledger does for the GitHub sink.
 * A dishonest server could forge the root hash it hands back; it could not
 * do so without also forging a valid Ed25519ph signature from the key this
 * witness names over content that is not the anchor, which is the part this
 * module actually anchors its trust in.
 *
 * HTTP goes through `curl` (execFileSync), the same shape as `github-anchor.ts`'s
 * injectable `GhExec` — synchronous, so `write()` returns a `RekorWitness`
 * directly and matches `AnchorSink` the same way `GitHubAnchorSink` does,
 * and swappable for a fake in tests so `npm test` never touches the network.
 *
 * **Checkpoint-signature verification — added 2026-09-23.** Rekor bundles a
 * *checkpoint* with every inclusion proof it returns: a signed statement of
 * exactly the tree size and root hash the proof claims, in the "signed
 * note" format `transparency-dev/formats` defines and `sigstore/rekor`'s own
 * `pkg/util/signed_note.go` implements. Without checking that signature, the
 * root the inclusion proof was checked against was simply whatever the
 * response asserted — a compromised or spoofed intermediary could still lie
 * about it.
 *
 * The plan for this work assumed the checkpoint signature would be Ed25519,
 * by analogy with the hashedrekord entry signature above — checked for real
 * instead of assumed, and it does not hold for `rekor.sigstore.dev`:
 * `GET /api/v1/log/publicKey` returns an ECDSA P-256 SPKI key, not Ed25519.
 * Confirmed, not just asserted: this key's SHA-256 hash's first 4 bytes
 * equal both the key hint on a real checkpoint's signature line and the
 * `logID` every entry from this instance reports
 * (`c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d`), and
 * `crypto.verify('sha256', note, key, sig)` — an ASN.1 DER ECDSA signature
 * over SHA-256 of the note text — returns true against a real fetched
 * checkpoint. No new dependency was needed: Node's `node:crypto` verifies
 * ECDSA P-256 natively; `@noble/curves` (above) is only for the Ed25519ph
 * *entry* signatures, a separate scheme entirely. Sigstore's own
 * `trusted_root.json` shows this is instance-specific — a Rekor v2 instance
 * (`log2025-1.rekor.sigstore.dev`) does use Ed25519 for its checkpoints — so
 * the type had to be confirmed per-instance, not assumed from the format.
 *
 * `verifyRekorWitness` now parses and verifies the checkpoint bundled with
 * the inclusion proof, confirms it attests to exactly the size and root the
 * proof claims, and recomputes the inclusion proof against that *verified*
 * root rather than the root the response merely asserts.
 *
 * **Cross-submission log consistency — added 2026-09-23, same day.** One
 * verified checkpoint proves an entry existed at some tree state; it says
 * nothing about whether *later* tree states Rekor shows are honest
 * extensions of that one, the way the witness ledger checks for the GitHub
 * sink. `verifyLogConsistency` checks two Rekor witnesses against each
 * other: both checkpoints verified independently first, then a real RFC
 * 6962 consistency proof (ported from and checked against
 * `transparency-dev/merkle`'s `proof.go`, the same source the inclusion-proof
 * math above came from, and cross-checked against 1,640 cases from an
 * independent textbook RFC 6962 reference implementation in this module's
 * own test file) confirms the newer tree is a genuine append-only extension
 * of the older one.
 *
 * One more real check, not assumed: `GET /api/v1/log/proof`'s own `rootHash`
 * field cannot be trusted as "the root at `lastSize`". Requesting the same
 * `(firstSize, lastSize, treeID)` three times in a row against the active
 * shard came back with the `hashes` array (the actual consistency proof)
 * byte-for-byte identical every time, but a *different* `rootHash` every
 * time. Trillian's semantics explain why: that field is the tree's root as
 * of the request, not as of `lastSize` — harmless on Rekor's own reference
 * client (`pkg/verify/verify.go`'s `ProveConsistency`), which never reads it
 * either. `verifyLogConsistency` does the same: it ignores that field and
 * checks the proof against two independently checkpoint-verified roots
 * instead. Proven against a real fetch before being wired in: two genuine
 * checkpoints (one from the existing 2026-09-22 witness, one from a fresh
 * `GET /api/v1/log`) plus a real fetched consistency proof reconstructed the
 * second checkpoint's own already-verified root exactly.
 */
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { ed25519ph } from '@noble/curves/ed25519.js';

import { type Anchor, type AnchorSink, formatAnchor } from './anchor.ts';

export type Severity = 'tamper' | 'warn' | 'info';

export interface Finding {
  code: string;
  severity: Severity;
  message: string;
}

/** Runs one HTTP request and returns its status and body. Throws only when the request could not be made at all (DNS, connection refused, timeout) — an HTTP error status is a normal return, not a throw, so callers can tell "the server said no" from "there was no answer." */
export type RekorExec = (method: 'GET' | 'POST', url: string, body?: string) => { status: number; body: string };

function defaultRekorExec(method: 'GET' | 'POST', url: string, body?: string): { status: number; body: string } {
  const args = ['-s', '-w', '\n%{http_code}', '-X', method, url, '-H', 'Content-Type: application/json', '-H', 'Accept: application/json'];
  if (body !== undefined) args.push('--data-binary', '@-');
  const out = execFileSync('curl', args, { input: body, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  const splitAt = out.lastIndexOf('\n');
  return { status: Number(out.slice(splitAt + 1)), body: out.slice(0, splitAt) };
}

export interface RekorAnchorOptions {
  /** Default https://rekor.sigstore.dev — the public-good v1 instance. */
  rekorUrl?: string;
  /** Raw 32-byte Ed25519 seed. Caller manages persistence — this module does not read or write key files. */
  secretKey: Uint8Array;
  exec?: RekorExec;
}

export interface RekorWitness {
  provider: 'rekor';
  rekorUrl: string;
  uuid: string;
  logIndex: number;
  logID: string;
  integratedTime: number;
  /** Raw 32-byte Ed25519 public key, hex. Same key for pure Ed25519 and Ed25519ph — RFC 8032 keygen does not depend on which scheme signs. */
  publicKeyHex: string;
  anchor: Anchor;
}

const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
function fromHex(s: string): Buffer {
  return Buffer.from(s, 'hex');
}

/** SPKI PEM for a raw 32-byte Ed25519 public key, via node:crypto's own JWK import — no hand-rolled DER. */
function spkiPemFromRawPublicKey(pub: Uint8Array): string {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub).toString('base64url') };
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  return (key.export({ type: 'spki', format: 'pem' }) as string).trim() + '\n';
}

/** The inverse: recover the raw 32-byte public key from an SPKI PEM, via node:crypto — used to check a fetched entry's key against the witness, not to trust the PEM's bytes on faith. */
function rawPublicKeyFromSpkiPem(pem: string): Buffer {
  const key = createPublicKey({ key: pem, format: 'pem' });
  const jwk = key.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('not an Ed25519 SPKI key');
  return Buffer.from(jwk.x, 'base64url');
}

interface RekorApiEntry {
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification?: {
    inclusionProof?: {
      logIndex: number;
      rootHash: string;
      treeSize: number;
      hashes: string[];
      checkpoint: string;
    };
    signedEntryTimestamp?: string;
  };
}

/**
 * Submit one hashedrekord entry for `anchor` and return a witness a verifier
 * can check independently later. Signs with Ed25519ph (`@noble/curves`);
 * everything else (JSON, base64, PEM, HTTP) goes through the same
 * primitives the rest of this project uses.
 */
export function writeRekorAnchor(anchor: Anchor, opts: RekorAnchorOptions): RekorWitness {
  const rekorUrl = opts.rekorUrl ?? DEFAULT_REKOR_URL;
  const exec = opts.exec ?? defaultRekorExec;

  const artifact = Buffer.from(formatAnchor(anchor), 'utf8');
  const hashValue = createHash('sha512').update(artifact).digest('hex');
  const signature = ed25519ph.sign(artifact, opts.secretKey);
  const publicKey = ed25519ph.getPublicKey(opts.secretKey);
  const publicKeyPem = spkiPemFromRawPublicKey(publicKey);

  const requestBody = JSON.stringify({
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: { hash: { algorithm: 'sha512', value: hashValue } },
      signature: {
        content: Buffer.from(signature).toString('base64'),
        publicKey: { content: Buffer.from(publicKeyPem, 'utf8').toString('base64') },
      },
    },
  });

  const { status, body: responseBody } = exec('POST', `${rekorUrl}/api/v1/log/entries`, requestBody);
  if (status < 200 || status >= 300) {
    throw new Error(`rekor rejected the entry: HTTP ${status} ${responseBody}`.trim());
  }
  const json = JSON.parse(responseBody) as Record<string, RekorApiEntry>;
  const uuid = Object.keys(json)[0];
  if (!uuid) throw new Error('rekor response had no entry');
  const entry = json[uuid];

  return {
    provider: 'rekor',
    rekorUrl,
    uuid,
    logIndex: entry.logIndex,
    logID: entry.logID,
    integratedTime: entry.integratedTime,
    publicKeyHex: toHex(publicKey),
    anchor,
  };
}

export class RekorAnchorSink implements AnchorSink<RekorWitness> {
  private opts: RekorAnchorOptions;
  constructor(opts: RekorAnchorOptions) {
    this.opts = opts;
  }
  write(anchor: Anchor): RekorWitness {
    return writeRekorAnchor(anchor, this.opts);
  }
}

// --- RFC 6962 Merkle inclusion proof --------------------------------------
//
// Ported from and checked against transparency-dev/merkle's proof.go
// (chainInner / chainBorderRight / decompInclProof), which is what Rekor's
// own client code (pkg/verify/verify.go) uses. Proven against a real,
// independently-fetched log entry (rekor.sigstore.dev, logIndex 1, a
// 22-hash proof against a ~4.16M-entry tree) before this module was
// written: the recomputed root matched the server's claimed root exactly.

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}
function hashLeaf(leaf: Buffer): Buffer {
  return sha256(Buffer.from([0x00]), leaf);
}
function hashChildren(l: Buffer, r: Buffer): Buffer {
  return sha256(Buffer.from([0x01]), l, r);
}
function bitLength(x: bigint): number {
  let n = 0;
  while (x > 0n) {
    x >>= 1n;
    n++;
  }
  return n;
}
function onesCount(x: bigint): number {
  let c = 0;
  while (x > 0n) {
    c += Number(x & 1n);
    x >>= 1n;
  }
  return c;
}
function decompInclProof(index: bigint, size: bigint): { inner: number; border: number } {
  const inner = bitLength(index ^ (size - 1n));
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}
function chainInner(seed: Buffer, proof: Buffer[], index: bigint): Buffer {
  for (let i = 0; i < proof.length; i++) {
    seed = ((index >> BigInt(i)) & 1n) === 0n ? hashChildren(seed, proof[i]) : hashChildren(proof[i], seed);
  }
  return seed;
}
function chainBorderRight(seed: Buffer, proof: Buffer[]): Buffer {
  for (const h of proof) seed = hashChildren(h, seed);
  return seed;
}

/** Recompute the Merkle root implied by an inclusion proof. Throws on a malformed (wrong-length) proof rather than silently accepting it. */
export function rootFromInclusionProof(index: number, size: number, leafHash: Buffer, proof: Buffer[]): Buffer {
  const bIndex = BigInt(index);
  const bSize = BigInt(size);
  if (bIndex >= bSize) throw new Error(`index ${index} is beyond tree size ${size}`);
  const { inner, border } = decompInclProof(bIndex, bSize);
  if (proof.length !== inner + border) {
    throw new Error(`wrong inclusion proof length ${proof.length}, want ${inner + border}`);
  }
  let res = chainInner(leafHash, proof.slice(0, inner), bIndex);
  res = chainBorderRight(res, proof.slice(inner));
  return res;
}

// --- checkpoint parsing and signature verification --------------------------
//
// Rekor's checkpoint is the "signed note" format `sigstore/rekor`'s own
// `pkg/util/signed_note.go` and `pkg/util/checkpoint.go` implement (heavily
// borrowed, per their own comment, from `transparency-dev/formats/log`):
//
//   <origin>\n<decimal size>\n<base64 root hash>\n\n— <name> <base64(4-byte key hint + signature)>\n
//
// The key hint is the first 4 bytes of SHA-256 of the signer's SPKI-DER
// public key — the same computation Rekor uses for `logID`, confirmed by
// checking it against a real fetched checkpoint below.

export interface ParsedCheckpoint {
  origin: string;
  size: number;
  rootHash: Buffer;
  /** The exact bytes that were signed: "<origin>\n<size>\n<base64 root>\n". */
  note: string;
  signatures: { name: string; keyHint: Buffer; signature: Buffer }[];
}

const CHECKPOINT_SIG_LINE = /^— (\S+) (\S+)$/;

/** Parses the common signed-note format. Does not verify anything — see `verifyCheckpointSignature`. */
export function parseCheckpoint(text: string): ParsedCheckpoint {
  const split = text.lastIndexOf('\n\n');
  if (split < 0) throw new Error('malformed checkpoint: no blank line separating the note from its signature block');
  const note = text.slice(0, split + 1);
  const sigBlock = text.slice(split + 2);
  if (sigBlock.length === 0 || !sigBlock.endsWith('\n')) {
    throw new Error('malformed checkpoint: signature block missing or not newline-terminated');
  }

  const signatures: ParsedCheckpoint['signatures'] = [];
  for (const line of sigBlock.split('\n')) {
    if (line.length === 0) continue;
    const m = CHECKPOINT_SIG_LINE.exec(line);
    if (!m) throw new Error(`malformed checkpoint: unparseable signature line ${JSON.stringify(line)}`);
    const raw = Buffer.from(m[2], 'base64');
    if (raw.length < 5) throw new Error('malformed checkpoint: signature too short to hold a 4-byte key hint');
    signatures.push({ name: m[1], keyHint: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  if (signatures.length === 0) throw new Error('malformed checkpoint: no signature lines found');

  const noteLines = note.split('\n');
  if (noteLines.length < 4) throw new Error('malformed checkpoint: note body has too few lines');
  const origin = noteLines[0];
  if (!origin) throw new Error('malformed checkpoint: empty origin line');
  if (!/^\d+$/.test(noteLines[1])) throw new Error(`malformed checkpoint: size line is not a plain integer: ${JSON.stringify(noteLines[1])}`);
  const size = Number(noteLines[1]);
  const rootHash = Buffer.from(noteLines[2], 'base64');
  if (rootHash.length !== 32) throw new Error(`malformed checkpoint: root hash line does not decode to 32 bytes (got ${rootHash.length})`);

  return { origin, size, rootHash, note, signatures };
}

/**
 * rekor.sigstore.dev's real checkpoint-signing public key, from a live
 * `GET /api/v1/log/publicKey` (checked 2026-09-22). ECDSA P-256, confirmed —
 * not assumed — by reading a real checkpoint: this key's SHA-256 hash's
 * first 4 bytes equal both the key hint on a real checkpoint signature line
 * and the `logID` every entry from this instance reports
 * (`c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d`), and
 * `crypto.verify('sha256', note, key, sig)` against that real checkpoint
 * returns true. This is a different key from the hashedrekord *entry*
 * signing scheme this module's own anchors use (Ed25519ph) — Rekor signs
 * checkpoints and entries with different key material for different roles.
 */
export const REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n' +
  'kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n' +
  '-----END PUBLIC KEY-----\n';

function spkiKeyHint(publicKeyPem: string): Buffer {
  const der = createPublicKey({ key: publicKeyPem, format: 'pem' }).export({ type: 'spki', format: 'der' }) as Buffer;
  return createHash('sha256').update(der).digest().subarray(0, 4);
}

export interface CheckpointCheck {
  ok: boolean;
  checkpoint?: ParsedCheckpoint;
  findings: Finding[];
}

/**
 * Parse `checkpointText` and verify one of its signatures against
 * `publicKeyPem` (default: rekor.sigstore.dev's real key, above). ECDSA
 * P-256 over SHA-256 — Node's `node:crypto` verifies this natively; no
 * `@noble/curves` involved, that library is for the Ed25519ph entry
 * signatures elsewhere in this module, a different scheme entirely.
 */
export function verifyCheckpointSignature(checkpointText: string, publicKeyPem: string = REKOR_SIGSTORE_DEV_CHECKPOINT_PUBLIC_KEY_PEM): CheckpointCheck {
  const findings: Finding[] = [];
  let checkpoint: ParsedCheckpoint;
  try {
    checkpoint = parseCheckpoint(checkpointText);
  } catch (e) {
    findings.push({ code: 'CHECKPOINT_UNPARSEABLE', severity: 'tamper', message: (e as Error).message });
    return { ok: false, findings };
  }
  const hint = spkiKeyHint(publicKeyPem);
  const sig = checkpoint.signatures.find((s) => s.keyHint.equals(hint));
  if (!sig) {
    findings.push({
      code: 'CHECKPOINT_KEY_MISMATCH',
      severity: 'tamper',
      message: `no signature on this checkpoint matches key hint ${hint.toString('hex')} for the given public key`,
    });
    return { ok: false, checkpoint, findings };
  }
  let valid: boolean;
  try {
    const key = createPublicKey({ key: publicKeyPem, format: 'pem' });
    valid = cryptoVerify('sha256', Buffer.from(checkpoint.note, 'utf8'), key, sig.signature);
  } catch (e) {
    findings.push({ code: 'CHECKPOINT_SIGNATURE_INVALID', severity: 'tamper', message: `could not verify the checkpoint's ECDSA signature: ${(e as Error).message}` });
    return { ok: false, checkpoint, findings };
  }
  if (!valid) {
    findings.push({ code: 'CHECKPOINT_SIGNATURE_INVALID', severity: 'tamper', message: `checkpoint's ECDSA signature does not verify against the given key` });
  }
  return { ok: valid, checkpoint, findings };
}

export interface RekorWitnessCheck {
  /** True only when nothing was wrong AND the entry was actually fetched. An unreachable log is not a pass. */
  ok: boolean;
  unreachable: boolean;
  findings: Finding[];
}

type FetchedEntry = { ok: true; entry: RekorApiEntry } | { ok: false; unreachable: boolean; finding: Finding };

/** Fetch one entry by UUID. Shared by `verifyRekorWitness` and `verifyLogConsistency` so both draw the same "not found" vs "unreachable" line. */
function fetchEntry(rekorUrl: string, uuid: string, exec: RekorExec): FetchedEntry {
  let status: number;
  let responseBody: string;
  try {
    ({ status, body: responseBody } = exec('GET', `${rekorUrl}/api/v1/log/entries/${uuid}`));
  } catch (e) {
    return { ok: false, unreachable: true, finding: { code: 'REKOR_UNREACHABLE', severity: 'warn', message: `could not reach ${rekorUrl}: ${(e as Error).message}` } };
  }
  if (status === 404) {
    return { ok: false, unreachable: false, finding: { code: 'REKOR_ENTRY_NOT_FOUND', severity: 'tamper', message: `${uuid} does not exist at ${rekorUrl} any more` } };
  }
  if (status < 200 || status >= 300) {
    return { ok: false, unreachable: true, finding: { code: 'REKOR_UNREACHABLE', severity: 'warn', message: `${rekorUrl} answered HTTP ${status} for ${uuid}` } };
  }
  try {
    const json = JSON.parse(responseBody) as Record<string, RekorApiEntry>;
    const entry = json[uuid];
    if (!entry) return { ok: false, unreachable: false, finding: { code: 'REKOR_ENTRY_NOT_FOUND', severity: 'tamper', message: `${rekorUrl} did not return ${uuid} for its own UUID` } };
    return { ok: true, entry };
  } catch (e) {
    return { ok: false, unreachable: true, finding: { code: 'REKOR_UNREACHABLE', severity: 'warn', message: `${rekorUrl} answered something unparseable for ${uuid}: ${(e as Error).message}` } };
  }
}

/**
 * Fetch the entry *by UUID* from Rekor (not trusting the witness's own
 * cached fields) and confirm: the entry's data really is our anchor, signed
 * by the key this witness names, and the inclusion proof Rekor hands back
 * recomputes to a root that Rekor's own checkpoint signature actually
 * vouches for — not merely the root the inclusion-proof JSON asserts.
 */
export function verifyRekorWitness(witness: RekorWitness, opts: { exec?: RekorExec; checkpointPublicKeyPem?: string } = {}): RekorWitnessCheck {
  const exec = opts.exec ?? defaultRekorExec;
  const findings: Finding[] = [];
  let unreachable = false;
  const add = (code: string, severity: Severity, message: string) => findings.push({ code, severity, message });
  const done = (): RekorWitnessCheck => ({ ok: !unreachable && !findings.some((f) => f.severity === 'tamper'), unreachable, findings });

  const fetched = fetchEntry(witness.rekorUrl, witness.uuid, exec);
  if (!fetched.ok) {
    unreachable = fetched.unreachable;
    findings.push(fetched.finding);
    return done();
  }
  const entry = fetched.entry;

  if (entry.logID !== witness.logID) {
    add('REKOR_LOG_ID_MISMATCH', 'tamper', `entry logID ${entry.logID} does not match the witness's ${witness.logID}`);
  }
  if (entry.integratedTime !== witness.integratedTime) {
    add('REKOR_INTEGRATED_TIME_MISMATCH', 'tamper', `entry integratedTime ${entry.integratedTime} does not match the witness's ${witness.integratedTime}`);
  }

  let entryBytes: Buffer;
  let spec: { data?: { hash?: { algorithm?: string; value?: string } }; signature?: { content?: string; publicKey?: { content?: string } } };
  try {
    entryBytes = Buffer.from(entry.body, 'base64');
    const decoded = JSON.parse(entryBytes.toString('utf8')) as { spec: typeof spec };
    spec = decoded.spec;
  } catch (e) {
    add('REKOR_BODY_UNPARSEABLE', 'tamper', `entry body at ${witness.uuid} could not be decoded: ${(e as Error).message}`);
    return done();
  }

  // The entry really is our anchor: recompute the hash it claims and check the signature.
  const artifact = Buffer.from(formatAnchor(witness.anchor), 'utf8');
  const expectedHash = createHash('sha512').update(artifact).digest('hex');
  if (spec.data?.hash?.algorithm !== 'sha512' || spec.data?.hash?.value !== expectedHash) {
    add('REKOR_HASH_MISMATCH', 'tamper', `entry's data.hash does not match sha512 of the anchor this witness claims`);
  }
  const sigB64 = spec.signature?.content;
  const pubB64 = spec.signature?.publicKey?.content;
  if (!sigB64 || !pubB64) {
    add('REKOR_SIGNATURE_MISSING', 'tamper', `entry has no signature or public key`);
  } else {
    try {
      const entryPub = rawPublicKeyFromSpkiPem(Buffer.from(pubB64, 'base64').toString('utf8'));
      if (toHex(entryPub) !== witness.publicKeyHex) {
        add('REKOR_PUBLIC_KEY_MISMATCH', 'tamper', `entry's public key ${toHex(entryPub)} does not match the witness's ${witness.publicKeyHex}`);
      } else {
        const sig = Buffer.from(sigB64, 'base64');
        const valid = ed25519ph.verify(sig, artifact, fromHex(witness.publicKeyHex));
        if (!valid) add('REKOR_SIGNATURE_INVALID', 'tamper', `entry's Ed25519ph signature does not verify against the anchor and public key this witness claims`);
      }
    } catch (e) {
      add('REKOR_SIGNATURE_INVALID', 'tamper', `could not check the entry's public key or signature: ${(e as Error).message}`);
    }
  }

  const proof = entry.verification?.inclusionProof;
  if (!proof) {
    add('REKOR_INCLUSION_PROOF_MISSING', 'tamper', `entry has no inclusion proof`);
    return done();
  }

  // The root the inclusion proof is checked against must itself be one Rekor
  // actually signed and published, not merely a field in the response JSON.
  // `proof.checkpoint` is a signed note bundled with the proof, naming the
  // same tree size and root hash the proof claims — verify that signature
  // first, and use ITS root, not `proof.rootHash` on its own word.
  if (!proof.checkpoint) {
    add('CHECKPOINT_MISSING', 'tamper', `entry's inclusion proof carries no checkpoint to verify the claimed root against`);
    return done();
  }
  const checkpointCheck = verifyCheckpointSignature(proof.checkpoint, opts.checkpointPublicKeyPem);
  if (!checkpointCheck.ok || !checkpointCheck.checkpoint) {
    findings.push(...checkpointCheck.findings);
    return done();
  }
  const checkpoint = checkpointCheck.checkpoint;
  if (checkpoint.size !== proof.treeSize || checkpoint.rootHash.toString('hex') !== proof.rootHash) {
    add(
      'CHECKPOINT_ROOT_MISMATCH',
      'tamper',
      `the signed checkpoint attests to size ${checkpoint.size} and root ${checkpoint.rootHash.toString('hex')}, but the inclusion proof claims size ${proof.treeSize} and root ${proof.rootHash} — they do not name the same tree state`,
    );
    return done();
  }
  const verifiedRoot = checkpoint.rootHash;

  try {
    const leafHash = hashLeaf(entryBytes);
    const hashes = proof.hashes.map((h) => fromHex(h));
    const calcRoot = rootFromInclusionProof(proof.logIndex, proof.treeSize, leafHash, hashes);
    if (!calcRoot.equals(verifiedRoot)) {
      add('REKOR_INCLUSION_PROOF_INVALID', 'tamper', `recomputed Merkle root ${toHex(calcRoot)} does not match the checkpoint-verified root ${toHex(verifiedRoot)}`);
    }
  } catch (e) {
    add('REKOR_INCLUSION_PROOF_INVALID', 'tamper', `could not recompute the inclusion proof: ${(e as Error).message}`);
  }

  return done();
}

// --- RFC 6962 consistency proof, and cross-submission log consistency ------
//
// Ported from and checked against transparency-dev/merkle's proof.go
// (RootFromConsistencyProof / rootFromSubtreeConsistencyProof), the same
// source the inclusion-proof math above came from. Specialised to the
// start=0 case (a full consistency proof between two states of the whole
// log), which is all `verifyLogConsistency` needs — the general subtree
// variant (for a consistency proof rooted partway into the tree) is not
// something Rekor's public API exposes.
//
// Proven against real, independently-fetched data before being wired in:
// two genuine checkpoints (an existing witness's, and a freshly fetched
// `GET /api/v1/log`) plus a real consistency proof fetched between their
// sizes reconstructed the second checkpoint's own already-verified root
// hash exactly. See the module doc for why the proof's `hashes` are used
// but its own `rootHash` field is not.

function trailingZeros(x: bigint): number {
  if (x === 0n) return 64;
  let n = 0;
  while ((x & 1n) === 0n) {
    x >>= 1n;
    n++;
  }
  return n;
}
function chainInnerRight(seed: Buffer, proof: Buffer[], index: bigint): Buffer {
  for (let i = 0; i < proof.length; i++) {
    if (((index >> BigInt(i)) & 1n) === 1n) seed = hashChildren(proof[i], seed);
  }
  return seed;
}
function decompSubtreeProof(start: bigint, end: bigint, size: bigint, border: number, proof: Buffer[]): { subInner: Buffer[]; subBorder: Buffer[] } {
  const h = bitLength((end - 1n) ^ start);
  const forkLevel = bitLength((end - 1n) ^ (size - 1n));
  const shift = trailingZeros(end - start);
  const subInnerLen = Math.min(h, forkLevel) - shift;
  const innerLen = forkLevel - shift;
  const subBorderLen = Math.max(0, border - onesCount((end - 1n) >> BigInt(h)));
  return { subInner: proof.slice(0, subInnerLen), subBorder: proof.slice(innerLen, innerLen + subBorderLen) };
}

/**
 * Recompute the root of a tree of size `size2`, given the (already trusted)
 * root of the same tree at the earlier size `size1` and a consistency proof
 * between them. Requires `0 < size1 <= size2`. Throws on a malformed proof
 * or a size1/size2 that make no sense, rather than silently accepting them.
 */
export function rootFromConsistencyProof(size1: number, size2: number, proof: Buffer[], root1: Buffer): Buffer {
  const s1 = BigInt(size1);
  const s2 = BigInt(size2);
  if (s2 < s1) throw new Error(`size2 (${size2}) < size1 (${size1})`);
  if (s1 === 0n) throw new Error('consistency proof from an empty tree is meaningless');
  if (s1 === s2) {
    if (proof.length > 0) throw new Error('size1=size2, but the proof is not empty');
    return root1;
  }
  if (proof.length === 0) throw new Error('empty consistency proof');

  const start = 0n;
  const end = s1;
  const size = s2;
  const { inner: forkLevel, border } = decompInclProof(end - 1n, size);
  const shift = trailingZeros(end - start);
  const inner = forkLevel - shift;
  let seed = proof[0];
  let pStart = 1;
  if (end - start === 1n << BigInt(shift)) {
    seed = root1;
    pStart = 0;
  }
  if (proof.length !== pStart + inner + border) {
    throw new Error(`wrong consistency proof length ${proof.length}, want ${pStart + inner + border}`);
  }
  const rest = proof.slice(pStart);
  const mask = (end - 1n) >> BigInt(shift);

  if (pStart === 1) {
    const { subInner, subBorder } = decompSubtreeProof(start, end, size, border, rest);
    let hash1 = chainInnerRight(seed, subInner, mask);
    hash1 = chainBorderRight(hash1, subBorder);
    if (!hash1.equals(root1)) {
      throw new Error(`consistency proof does not chain to the given root at size ${size1}: got ${toHex(hash1)}, want ${toHex(root1)}`);
    }
  }

  let hash2 = chainInner(seed, rest.slice(0, inner), mask);
  hash2 = chainBorderRight(hash2, rest.slice(inner));
  return hash2;
}

export interface ConsistencyCheck {
  ok: boolean;
  unreachable: boolean;
  findings: Finding[];
  oldSize?: number;
  newSize?: number;
}

/**
 * Confirm the tree `newWitness` was submitted into is a genuine append-only
 * extension of the tree `oldWitness` was submitted into: both checkpoints
 * are verified independently (real Ed25519ph... no — ECDSA, see above), and
 * a real consistency proof fetched between their two tree sizes is checked
 * to actually chain the older, already-verified root to the newer one.
 *
 * Deliberately does not trust `/api/v1/log/proof`'s own `rootHash` field —
 * see the module doc for why that field cannot mean "the root at lastSize"
 * on a log that keeps growing while the request is in flight. Only its
 * `hashes` are used, checked against the two roots this function already
 * verified on its own.
 *
 * `oldWitness` must be the chronologically earlier submission — pass them in
 * ledger order. A same-tree-size pair (a witness compared with itself, or
 * two anchors that landed in the same tree snapshot) is checked too: the
 * proof must then be empty and the two roots must agree.
 */
export function verifyLogConsistency(oldWitness: RekorWitness, newWitness: RekorWitness, opts: { exec?: RekorExec; checkpointPublicKeyPem?: string } = {}): ConsistencyCheck {
  const exec = opts.exec ?? defaultRekorExec;
  const findings: Finding[] = [];
  let unreachable = false;
  const add = (code: string, severity: Severity, message: string) => findings.push({ code, severity, message });
  const done = (oldSize?: number, newSize?: number): ConsistencyCheck => ({
    ok: !unreachable && !findings.some((f) => f.severity === 'tamper'),
    unreachable,
    findings,
    oldSize,
    newSize,
  });

  if (oldWitness.rekorUrl !== newWitness.rekorUrl) {
    add('REKOR_CONSISTENCY_DIFFERENT_LOG', 'tamper', `witnesses name different Rekor instances (${oldWitness.rekorUrl} vs ${newWitness.rekorUrl}); consistency cannot be checked across logs`);
    return done();
  }

  // A verified checkpoint for each witness, independent of one another and
  // of the fetch below — this is what makes it safe to ignore the
  // consistency-proof endpoint's own claimed root.
  const checkpointFor = (w: RekorWitness): { checkpoint?: ParsedCheckpoint; treeID?: string } => {
    const fetched = fetchEntry(w.rekorUrl, w.uuid, exec);
    if (!fetched.ok) {
      if (fetched.unreachable) unreachable = true;
      findings.push(fetched.finding);
      return {};
    }
    const proof = fetched.entry.verification?.inclusionProof;
    if (!proof?.checkpoint) {
      add('CHECKPOINT_MISSING', 'tamper', `${w.uuid}'s inclusion proof carries no checkpoint to verify`);
      return {};
    }
    const check = verifyCheckpointSignature(proof.checkpoint, opts.checkpointPublicKeyPem);
    if (!check.ok || !check.checkpoint) {
      findings.push(...check.findings);
      return {};
    }
    if (check.checkpoint.size !== proof.treeSize || check.checkpoint.rootHash.toString('hex') !== proof.rootHash) {
      add('CHECKPOINT_ROOT_MISMATCH', 'tamper', `${w.uuid}'s checkpoint does not attest to the same tree state its inclusion proof claims`);
      return {};
    }
    // origin is "<name> - <treeID>"; the treeID is what /api/v1/log/proof needs.
    const treeID = check.checkpoint.origin.split(' - ').pop();
    return { checkpoint: check.checkpoint, treeID };
  };

  const older = checkpointFor(oldWitness);
  const newer = checkpointFor(newWitness);
  if (!older.checkpoint || !newer.checkpoint) return done();

  if (older.treeID !== newer.treeID) {
    // A real, honest possibility — Rekor rotates to a fresh shard once one
    // fills up, and the old shard is listed forever after as `inactiveShards`
    // in `GET /api/v1/log`, not silently dropped. That is not evidence of
    // tampering, only that this particular check cannot run across the
    // rotation boundary; a real Merkle consistency proof only exists within
    // one physical tree.
    add(
      'REKOR_CONSISTENCY_SHARD_ROTATED',
      'info',
      `${oldWitness.uuid} and ${newWitness.uuid} landed in different Rekor tree shards (${older.treeID} vs ${newer.treeID}); the log rotated shards between these two submissions, so no single consistency proof spans both`,
    );
    return done(older.checkpoint.size, newer.checkpoint.size);
  }

  const oldSize = older.checkpoint.size;
  const newSize = newer.checkpoint.size;
  if (oldSize > newSize) {
    add('REKOR_CONSISTENCY_ORDER', 'tamper', `${oldWitness.uuid} (tree size ${oldSize}) claims to be older than ${newWitness.uuid} (tree size ${newSize}), but its tree is larger — check the ledger order`);
    return done(oldSize, newSize);
  }
  if (oldSize === newSize) {
    if (!older.checkpoint.rootHash.equals(newer.checkpoint.rootHash)) {
      add('REKOR_CONSISTENCY_PROOF_INVALID', 'tamper', `both witnesses claim tree size ${oldSize} but disagree on the root hash`);
    }
    return done(oldSize, newSize);
  }

  let status: number;
  let responseBody: string;
  try {
    ({ status, body: responseBody } = exec('GET', `${oldWitness.rekorUrl}/api/v1/log/proof?firstSize=${oldSize}&lastSize=${newSize}&treeID=${older.treeID}`));
  } catch (e) {
    unreachable = true;
    add('REKOR_CONSISTENCY_UNREACHABLE', 'warn', `could not fetch a consistency proof between sizes ${oldSize} and ${newSize}: ${(e as Error).message}`);
    return done(oldSize, newSize);
  }
  if (status < 200 || status >= 300) {
    unreachable = true;
    add('REKOR_CONSISTENCY_UNREACHABLE', 'warn', `${oldWitness.rekorUrl} answered HTTP ${status} for the consistency proof between ${oldSize} and ${newSize}`);
    return done(oldSize, newSize);
  }

  try {
    const parsed = JSON.parse(responseBody) as { hashes: string[] };
    const hashes = (parsed.hashes ?? []).map((h) => fromHex(h));
    const calc = rootFromConsistencyProof(oldSize, newSize, hashes, older.checkpoint.rootHash);
    if (!calc.equals(newer.checkpoint.rootHash)) {
      add(
        'REKOR_CONSISTENCY_PROOF_INVALID',
        'tamper',
        `the tree at size ${newSize} does not extend the tree at size ${oldSize}: chaining the fetched consistency proof onto the verified root at ${oldSize} gives ${toHex(calc)}, not the verified root at ${newSize} (${toHex(newer.checkpoint.rootHash)})`,
      );
    }
  } catch (e) {
    add('REKOR_CONSISTENCY_PROOF_INVALID', 'tamper', `could not recompute the consistency proof: ${(e as Error).message}`);
  }

  return done(oldSize, newSize);
}
