/**
 * The attack catalogue. Each attack is a function from a genuine ledger to a
 * doctored one, labelled with what the attacker needs to pull it off. The
 * catalogue is the threat model, in a form that can be run rather than read.
 *
 * Attackers get stronger down the list:
 *
 *   file     — can write to the ledger file.
 *   format   — also understands hashing and chaining, so can recompute them.
 *   own key  — also replaces the declared public key with their own.
 *   real key — holds the recorder's private key. This is the agent, if the
 *              key was ever within its reach.
 */
import type { KeyObject } from 'node:crypto';

import { generateKeys, hashBody, bodyOf, publicKeyToBase64, seal, signHash, type Entry } from './ledger.ts';
import type { SampleSession } from './fixtures/session.ts';

export type Capability = 'file' | 'format' | 'own key' | 'real key';

export interface Doctored {
  entries: Entry[];
  /** The key the attacker wants the verifier to trust, if they replaced it. */
  declaredKey?: KeyObject;
}

export interface Attack {
  name: string;
  /** What the attacker is trying to make the record say. */
  intent: string;
  needs: Capability;
  apply: (entries: Entry[], s: SampleSession) => Doctored;
}

/** Recompute the chain from `from` onwards. Re-sign if a key is given; otherwise keep the old signatures. */
export function rechain(entries: Entry[], from: number, key?: KeyObject): Entry[] {
  const out = entries.slice(0, from);
  let prev = from === 0 ? '0'.repeat(64) : entries[from - 1].hash;
  for (let i = from; i < entries.length; i++) {
    const body = { ...bodyOf(entries[i]), seq: i, prev };
    const hash = hashBody(body);
    const sig = key ? signHash(hash, key) : entries[i].sig;
    const entry = { ...body, hash, sig } as Entry;
    out.push(entry);
    prev = hash;
  }
  return out;
}

const clone = (entries: Entry[]): Entry[] => structuredClone(entries);

function narrowTheDelete(entries: Entry[], seq: number): Entry[] {
  const e = clone(entries);
  const call = e[seq] as Extract<Entry, { kind: 'call' }>;
  call.args = { cmd: 'rm -rf test/fixtures/old/tmp' };
  return e;
}

export const ATTACKS: Attack[] = [
  {
    name: 'edit in place',
    intent: 'make `rm -rf test/fixtures/old` read as a narrower delete',
    needs: 'file',
    apply: (entries, s) => ({ entries: narrowTheDelete(entries, s.marks.delete) }),
  },
  {
    name: 'delete the entry',
    intent: 'remove the delete and its result, as if it never ran',
    needs: 'file',
    apply: (entries, s) => {
      const e = clone(entries);
      e.splice(s.marks.delete, 2);
      return { entries: e };
    },
  },
  {
    name: 'reorder',
    intent: 'move the approval note to before the destructive call it did not cover',
    needs: 'file',
    apply: (entries, s) => {
      const e = clone(entries);
      const [note] = e.splice(s.marks.approval, 1);
      e.splice(s.marks.approval - 4, 0, note);
      return { entries: e };
    },
  },
  {
    name: 'truncate',
    intent: 'drop everything after the tests passed, hiding the delete and the webhook',
    needs: 'file',
    apply: (entries, s) => ({ entries: clone(entries).slice(0, s.marks.approval) }),
  },
  {
    name: 'forge an approval',
    intent: 'append a note saying the operator approved, with a correct hash and chain',
    needs: 'format',
    apply: (entries) => {
      const e = clone(entries);
      const last = e[e.length - 1];
      const forged = {
        v: 1 as const,
        seq: e.length,
        prev: last.hash,
        ts: last.ts,
        kind: 'note' as const,
        text: 'operator approved: "delete whatever you need to"',
      };
      const hash = hashBody(forged);
      e.push({ ...forged, hash, sig: last.sig });
      return { entries: e };
    },
  },
  {
    name: 'edit and rechain',
    intent: 'narrow the delete, then recompute every downstream hash so the chain closes',
    needs: 'format',
    apply: (entries, s) => ({ entries: rechain(narrowTheDelete(entries, s.marks.delete), s.marks.delete) }),
  },
  {
    name: 'rewrite under own key',
    intent: 'narrow the delete, rechain, re-sign everything with a new key and declare that key in genesis',
    needs: 'own key',
    apply: (entries, s) => {
      const mine = generateKeys();
      const e = narrowTheDelete(entries, s.marks.delete);
      (e[0] as Extract<Entry, { kind: 'open' }>).pub = publicKeyToBase64(mine.publicKey);
      return { entries: rechain(e, 0, mine.privateKey), declaredKey: mine.publicKey };
    },
  },
  {
    name: 'rewrite with the real key',
    intent: 'narrow the delete, rechain, re-sign with the recorder\'s own key',
    needs: 'real key',
    apply: (entries, s) => ({ entries: rechain(narrowTheDelete(entries, s.marks.delete), s.marks.delete, s.keys.privateKey) }),
  },
  {
    name: 'lose the outcome, real key',
    intent: 'drop the delete\'s result so the record shows an attempt with no outcome, and fix the close entry to match',
    needs: 'real key',
    apply: (entries, s) => {
      const e = clone(entries);
      const call = e[s.marks.delete] as Extract<Entry, { kind: 'call' }>;
      e.splice(s.marks.deleteResult, 1);
      const close = e[e.length - 1] as Extract<Entry, { kind: 'close' }>;
      close.results -= 1;
      close.open = [...close.open, call.id];
      return { entries: rechain(e, s.marks.deleteResult, s.keys.privateKey) };
    },
  },
  {
    name: 'after the last anchor, real key',
    intent: 'rewrite the commit message recorded after the anchor was taken',
    needs: 'real key',
    apply: (entries, s) => {
      const e = clone(entries);
      const i = s.marks.anchoredAt + 1;
      (e[i] as Extract<Entry, { kind: 'call' }>).args = { message: 'Minor cleanup' };
      return { entries: rechain(e, i, s.keys.privateKey) };
    },
  },
];

/** Seal a body the way the recorder would; exported for tests that build entries by hand. */
export { seal };
