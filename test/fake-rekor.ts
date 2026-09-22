/**
 * A small in-memory stand-in for the slice of Rekor's v1 API this project
 * uses, shared by the rekor-anchor unit tests and the witness-ledger unit
 * tests (as an injected `RekorExec`). It never touches the network.
 *
 * Every leaf, inclusion proof, and checkpoint is computed for real from a
 * real, growing RFC 6962 Merkle tree — the textbook recursive construction
 * (RFC 6962 §2.1.1/§2.1.2), independent of this project's own ported-from-Go
 * `rootFromInclusionProof`/`rootFromConsistencyProof` in `src/rekor-anchor.ts`,
 * which are the code under test. Checkpoints are signed with a real ECDSA
 * P-256 key (the same shape rekor.sigstore.dev's own checkpoints use, see
 * that module's doc) — a fresh per-fake key unless one is shared via
 * `opts.keyPair`, which a test does deliberately to model two shards of the
 * same real log signing checkpoints with the same key.
 */
import { createHash, createPublicKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';

import type { RekorExec, RekorWitness } from '../src/rekor-anchor.ts';
import type { Anchor } from '../src/anchor.ts';

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}
function refLeafHash(leaf: Buffer): Buffer {
  return sha256(Buffer.from([0x00]), leaf);
}
function refNodeHash(l: Buffer, r: Buffer): Buffer {
  return sha256(Buffer.from([0x01]), l, r);
}
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function refMTH(leaves: Buffer[]): Buffer {
  if (leaves.length === 1) return refLeafHash(leaves[0]);
  const k = largestPowerOfTwoBelow(leaves.length);
  return refNodeHash(refMTH(leaves.slice(0, k)), refMTH(leaves.slice(k)));
}
/** RFC 6962 §2.1.1 PATH — the textbook recursive inclusion-proof construction. */
function refIncl(m: number, D: Buffer[]): Buffer[] {
  const n = D.length;
  if (n === 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) return [...refIncl(m, D.slice(0, k)), refMTH(D.slice(k))];
  return [...refIncl(m - k, D.slice(k)), refMTH(D.slice(0, k))];
}
/** RFC 6962 §2.1.2 SUBPROOF/PROOF — the textbook recursive consistency-proof construction. */
function refSubproof(m: number, D: Buffer[], b: boolean): Buffer[] {
  const n = D.length;
  if (m === n) return b ? [] : [refMTH(D)];
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) return [...refSubproof(m, D.slice(0, k), b), refMTH(D.slice(k))];
  return [...refSubproof(m - k, D.slice(k), false), refMTH(D.slice(0, k))];
}
function refConsistencyProof(m: number, D: Buffer[]): Buffer[] {
  return refSubproof(m, D, true);
}

/** Signs a fake checkpoint the same way rekor.sigstore.dev's real one is shaped: ECDSA P-256 over SHA-256 of the note text, 4-byte key-hint-prefixed signature line. */
export function signFakeCheckpoint(priv: KeyObject, origin: string, size: number, rootHash: Buffer): string {
  const note = `${origin}\n${size}\n${rootHash.toString('base64')}\n`;
  const sig = cryptoSign('sha256', Buffer.from(note, 'utf8'), priv);
  const pubDer = createPublicKey(priv).export({ type: 'spki', format: 'der' }) as Buffer;
  const keyHint = createHash('sha256').update(pubDer).digest().subarray(0, 4);
  const sigLine = Buffer.concat([keyHint, sig]).toString('base64');
  return `${note}\n— fake-log ${sigLine}\n`;
}

export function fakeCheckpointKeyPair(): { privateKey: KeyObject; checkpointPublicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, checkpointPublicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string };
}

/** Deterministic-enough 32-byte Ed25519 seed for a test key — not used for anything real. */
export function testRekorSeed(): Uint8Array {
  const { privateKey } = generateKeyPairSync('ed25519');
  return Buffer.from((privateKey.export({ format: 'jwk' }) as { d: string }).d, 'base64url');
}

/**
 * A growing in-memory log: every POST appends a leaf and returns a real
 * inclusion proof and a real, freshly re-signed checkpoint for the tree as
 * it stands after that append. `GET /api/v1/log/proof` answers with a real
 * consistency proof (the textbook construction above) — and, to prove
 * calling code really does ignore that response's own `rootHash` field the
 * way `src/rekor-anchor.ts`'s module doc says it must, this fake
 * deliberately hands back a wrong one.
 */
export function fakeGrowingRekor(opts: { treeID?: string; uuidPrefix?: string; keyPair?: { privateKey: KeyObject; checkpointPublicKeyPem: string } } = {}) {
  const treeID = opts.treeID ?? '111';
  const uuidPrefix = opts.uuidPrefix ?? '';
  const leaves: Buffer[] = [];
  const entries = new Map<string, any>();
  const { privateKey, checkpointPublicKeyPem } = opts.keyPair ?? fakeCheckpointKeyPair();
  let counter = 0;

  const exec: RekorExec = (method, url, body) => {
    if (method === 'POST' && url.endsWith('/api/v1/log/entries')) {
      counter += 1;
      const uuid = `${uuidPrefix}uuid-${counter}`;
      const submitted = JSON.parse(body!) as { spec: unknown };
      const entryBodyB64 = Buffer.from(JSON.stringify({ kind: 'hashedrekord', apiVersion: '0.0.1', spec: submitted.spec, n: counter })).toString('base64');
      const entryBytes = Buffer.from(entryBodyB64, 'base64');
      const index = leaves.length;
      leaves.push(entryBytes);
      const size = leaves.length;
      const root = refMTH(leaves);
      const proofHashes = size === 1 ? [] : refIncl(index, leaves);
      const checkpoint = signFakeCheckpoint(privateKey, `fake-log - ${treeID}`, size, root);
      const entry = {
        body: entryBodyB64,
        integratedTime: 1700000000 + counter,
        logID: 'fake-log-id',
        logIndex: 1000 + counter,
        verification: {
          inclusionProof: { logIndex: index, treeSize: size, hashes: proofHashes.map((h) => h.toString('hex')), rootHash: root.toString('hex'), checkpoint },
          signedEntryTimestamp: 'fake-set',
        },
      };
      entries.set(uuid, entry);
      return { status: 201, body: JSON.stringify({ [uuid]: entry }) };
    }
    const getEntry = /\/api\/v1\/log\/entries\/(.+)$/.exec(url);
    if (method === 'GET' && getEntry) {
      const entry = entries.get(getEntry[1]);
      if (!entry) return { status: 404, body: 'Not Found' };
      return { status: 200, body: JSON.stringify({ [getEntry[1]]: entry }) };
    }
    if (method === 'GET' && url.includes('/api/v1/log/proof')) {
      const q = new URL(url).searchParams;
      const firstSize = Number(q.get('firstSize'));
      const lastSize = Number(q.get('lastSize'));
      const reqTreeID = q.get('treeID');
      if (reqTreeID !== treeID) return { status: 400, body: JSON.stringify({ message: `unknown treeID ${reqTreeID}` }) };
      if (lastSize > leaves.length) return { status: 400, body: JSON.stringify({ message: 'requested tree size larger than observed' }) };
      const proof = refConsistencyProof(firstSize, leaves.slice(0, lastSize));
      // Deliberately not the real root at lastSize — see the function doc.
      return { status: 200, body: JSON.stringify({ hashes: proof.map((h) => h.toString('hex')), rootHash: 'ff'.repeat(32) }) };
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  };

  return { exec, entries, checkpointPublicKeyPem, treeID };
}

export function fakeWitnessFor(entry: { verification: { inclusionProof: { logIndex: number } } }, uuid: string, rekorUrl: string, anchor: Anchor): RekorWitness {
  return {
    provider: 'rekor',
    rekorUrl,
    uuid,
    logIndex: entry.verification.inclusionProof.logIndex,
    logID: 'fake-log-id',
    integratedTime: 0,
    publicKeyHex: '00'.repeat(32),
    anchor,
  };
}
