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
 * What it does not yet add: this does not verify the checkpoint's own
 * signature (the signed tree head that vouches for the root hash
 * `verifyRekorWitness` checks the leaf against), and it checks one entry
 * once, not log consistency over time the way the witness ledger does for
 * the GitHub sink. A dishonest server could still forge the root hash it
 * hands back; it could not do so without also forging a valid Ed25519ph
 * signature from the key this witness names over content that is not the
 * anchor, which is the part this module actually anchors its trust in.
 * That is a real, narrower gap than "no transparency log," not a
 * decorative one — see the README.
 *
 * HTTP goes through `curl` (execFileSync), the same shape as `github-anchor.ts`'s
 * injectable `GhExec` — synchronous, so `write()` returns a `RekorWitness`
 * directly and matches `AnchorSink` the same way `GitHubAnchorSink` does,
 * and swappable for a fake in tests so `npm test` never touches the network.
 */
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
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

export interface RekorWitnessCheck {
  /** True only when nothing was wrong AND the entry was actually fetched. An unreachable log is not a pass. */
  ok: boolean;
  unreachable: boolean;
  findings: Finding[];
}

/**
 * Fetch the entry *by UUID* from Rekor (not trusting the witness's own
 * cached fields) and confirm: the entry's data really is our anchor, signed
 * by the key this witness names, and the inclusion proof Rekor hands back
 * recomputes to the root it claims.
 */
export function verifyRekorWitness(witness: RekorWitness, opts: { exec?: RekorExec } = {}): RekorWitnessCheck {
  const exec = opts.exec ?? defaultRekorExec;
  const findings: Finding[] = [];
  let unreachable = false;
  const add = (code: string, severity: Severity, message: string) => findings.push({ code, severity, message });
  const done = (): RekorWitnessCheck => ({ ok: !unreachable && !findings.some((f) => f.severity === 'tamper'), unreachable, findings });

  let status: number;
  let responseBody: string;
  try {
    ({ status, body: responseBody } = exec('GET', `${witness.rekorUrl}/api/v1/log/entries/${witness.uuid}`));
  } catch (e) {
    unreachable = true;
    add('REKOR_UNREACHABLE', 'warn', `could not reach ${witness.rekorUrl}: ${(e as Error).message}`);
    return done();
  }
  if (status === 404) {
    add('REKOR_ENTRY_NOT_FOUND', 'tamper', `${witness.uuid} does not exist at ${witness.rekorUrl} any more`);
    return done();
  }
  if (status < 200 || status >= 300) {
    unreachable = true;
    add('REKOR_UNREACHABLE', 'warn', `${witness.rekorUrl} answered HTTP ${status} for ${witness.uuid}`);
    return done();
  }

  let entry: RekorApiEntry | undefined;
  try {
    const json = JSON.parse(responseBody) as Record<string, RekorApiEntry>;
    entry = json[witness.uuid];
  } catch (e) {
    unreachable = true;
    add('REKOR_UNREACHABLE', 'warn', `${witness.rekorUrl} answered something unparseable for ${witness.uuid}: ${(e as Error).message}`);
    return done();
  }
  if (!entry) {
    add('REKOR_ENTRY_NOT_FOUND', 'tamper', `${witness.rekorUrl} did not return ${witness.uuid} for its own UUID`);
    return done();
  }

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
  try {
    const leafHash = hashLeaf(entryBytes);
    const hashes = proof.hashes.map((h) => fromHex(h));
    const claimedRoot = fromHex(proof.rootHash);
    const calcRoot = rootFromInclusionProof(proof.logIndex, proof.treeSize, leafHash, hashes);
    if (!calcRoot.equals(claimedRoot)) {
      add('REKOR_INCLUSION_PROOF_INVALID', 'tamper', `recomputed Merkle root ${toHex(calcRoot)} does not match the claimed root ${proof.rootHash}`);
    }
  } catch (e) {
    add('REKOR_INCLUSION_PROOF_INVALID', 'tamper', `could not recompute the inclusion proof: ${(e as Error).message}`);
  }

  return done();
}
