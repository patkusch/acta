# Acta

**A tamper-evident record of what an agent actually did — and an honest account of what that record does not prove.**

An agent runs for an hour and takes two hundred actions. Afterwards someone asks
what happened. The usual answer is a log written by the same process that took
the actions, on a disk the agent could write to, in a format the agent could
edit. That is not a record. That is the agent's account of itself.

Acta is a small library, a verifier, and an MCP proxy. Every tool call and its
result goes into an append-only ledger where each entry commits to the one
before it and is signed by a key the agent must not hold. The verifier tells
you whether the ledger has been touched — and, more usefully, exactly which
attackers it can and cannot catch.

```bash
npm install
npm test          # 19 tests: the chain, the recorder, the proxy, and every attack in the catalogue
npm run attack    # the demo: ten attacks, three verifier configurations, one cell that stays red

# record a real MCP server
node bin/acta.mjs mcp --dir /var/acta/run-42 --anchor-every 10 --anchor-to /var/anchors/run-42 \
  -- npx @modelcontextprotocol/server-filesystem ~/projects

# afterwards
node bin/acta.mjs show   /var/acta/run-42
node bin/acta.mjs verify /var/acta/run-42 --key /var/anchors/recorder.pub --anchors /var/anchors/run-42
```

No runtime dependencies. Node 22.6 or later (it runs TypeScript directly).

---

## The mechanism

Three things bind an entry into place. Each one defeats a stronger attacker than
the last, and none of them defeats the strongest.

| | binds | defeats |
|:--|:--|:--|
| `hash` | the entry's own bytes | anyone who edits a line |
| `prev` | the previous entry's hash | anyone who deletes or reorders lines |
| `sig` | Ed25519 over the hash, by the recorder's key | anyone who understands the format but does not hold the key |
| **anchor** | the head hash, written somewhere the agent cannot write | **anyone who holds the key**, for entries up to the anchor |

An entry looks like this. Everything except `hash` and `sig` is hashed, in a
canonical form (sorted keys, no whitespace, nothing JSON cannot represent).

```json
{"v":1,"seq":7,"prev":"3d0a…","ts":"2026-09-02T21:00:08.000Z","kind":"call",
 "id":"c3f1…","tool":"shell","args":{"cmd":"rm -rf test/fixtures/old"},
 "hash":"9b41…","sig":"MEUCIQ…"}
```

Five kinds: `open` (genesis, declares the session and the public key), `call`,
`result` (which cites its call and carries the body inline or by digest),
`note`, and `close` (which records the counts and which calls were still open).

## Three verdicts, not two

`acta verify` does not say "valid". It says one of:

- **tampered** — a check failed. The findings say which entry and how.
- **consistent** — the ledger agrees with itself. That is all. A ledger rewritten
  end to end by whoever holds the key is consistent. So is one that was truncated
  to hide its last twenty actions.
- **verified** — consistent, signed by a key *you* supplied from outside the ledger
  directory, and matching an anchor *you* supplied from somewhere the agent could
  not write. This is the only verdict that means what people want "valid" to mean,
  and even then only up to the anchor.

The verifier lists what is missing before a `consistent` ledger could become
`verified`. `--strict` makes `consistent` a non-zero exit, for CI.

```
$ acta verify run-42
CONSISTENT  4 entries  head seq 3 db121670a2ec…
  info   SELF_ATTESTED_KEY   signatures checked against the key the ledger itself declares; whoever rewrote the ledger could have declared their own
consistent is not verified. still missing:
  - a public key obtained outside the ledger directory (--key)
  - an anchor written where the agent cannot write (--anchors)

$ acta verify run-42 --key safe/recorder.pub --anchors safe/anchors.jsonl
VERIFIED  4 entries  head seq 3 db121670a2ec…
anchored at seq 2
  info   UNANCHORED_TAIL    @3    1 entries after the last anchor are unanchored
```

## The attack table

`npm run attack` records a genuine session — an agent fixing a flaky test,
deleting a fixture directory with a noted approval, posting to a webhook — then
runs ten attacks against it. Each attack is labelled with what the attacker
needs. Each is verified three ways: the chain alone, chain plus a trusted key,
chain plus key plus anchor. The catalogue is in
[`src/attacks.ts`](src/attacks.ts) and asserted in
[`test/attacks.test.ts`](test/attacks.test.ts), so the table below cannot drift
from the code.

```
attack                            needs     chain   +key    +anchor
edit in place                     file      caught  caught  caught
delete the entry                  file      caught  caught  caught
reorder                           file      caught  caught  caught
truncate                          file      —       —       caught
forge an approval                 format    caught  caught  caught
edit and rechain                  format    caught  caught  caught
rewrite under own key             own key   —       caught  caught
rewrite with the real key         real key  —       —       caught
lose the outcome, real key        real key  —       —       caught
after the last anchor, real key   real key  —       —       —

  the chain alone catches 5 of 10: anyone who can write the file but does not understand it.
  a trusted key catches 6: anyone who does not hold the recorder's key.
  an anchor catches 9: anyone who holds the key, for entries up to the anchor.
  nothing catches 1: the key holder, between the last anchor and now.
```

Two rows deserve a second look.

**Truncate** is caught by nothing but the anchor. A ledger with its last twenty
lines cut off is a perfectly valid shorter ledger; it looks exactly like a
session that crashed. Hash chains do not protect against this and it is the
easiest attack on the list — it needs no understanding of the format at all.

**After the last anchor** is caught by nothing. If the agent holds the key, or
the key was ever within its reach, every entry since the last anchor is the
agent's word. This is not a limitation to engineer around; it is the shape of
the problem. The two operational rules follow directly from it:

1. **The key lives where the agent cannot read it.** A separate process, a
   directory outside every confinement the agent's tools are given, a different
   user. The MCP proxy holds the key in its own process for this reason.
2. **Anchor often, somewhere else.** An anchor is one line — it fits in a commit
   message, a chat channel, a ticket, an append-only file owned by another user.
   `--anchor-every N` in the proxy, `rec.anchor(path)` in the library.

## What this does not prove

- **Only what passed through the recorder.** If the agent has a channel that
  bypasses the recorded tool surface, the ledger is silent about it. Acta records
  a boundary; it does not discover one.
- **Ordering, not time.** `prev` proves that entry 8 was written after entry 7.
  `ts` is the recorder's clock and is only asserted. A key holder can write any
  timestamp they like, subject to the verifier's monotonicity warning.
- **An anchor is as good as where you put it.** An anchor the agent can overwrite
  is decoration. The library makes anchors small; it cannot make them safe.
- **Single writer.** One recorder, one key, one session per file. This is not a
  distributed log and does not pretend to be. There is no consensus and no
  witness set. If you need multiple independent parties to attest, the anchor is
  the thing to hand them.
- **A missing ledger is not a finding.** If the whole directory is deleted, the
  only evidence it existed is an anchor somewhere else with no ledger to match.
  `verify` on an empty directory reports `EMPTY`, which is all it can do.
- **Large results are stored by digest.** Bodies over 4 KiB go to a blob store
  beside the ledger. A missing blob is reported as a warning — evidence lost, not
  evidence altered — and the digest still binds whatever is later produced.

## Using it as a library

```ts
import { Recorder } from './src/recorder.ts';

const rec = Recorder.open('/var/acta/run-42', { actor: 'coding-agent' });

// wrap a bag of async tools; every call and result is recorded
const tools = rec.wrap({ read_file, edit_file, shell, http_post });
await tools.shell({ cmd: 'npm test' });          // → call, then result (or a recorded failure)

// or record by hand
const id = rec.call('approve', { what: 'delete fixtures' });
rec.result(id, { by: 'operator', decision: 'yes' });
rec.note('operator was shown the consent card, not a summary of it');

rec.anchor('/var/anchors/run-42');               // one line, appended
console.log(rec.anchorLine());                   // acta-anchor session=… seq=… hash=… — paste it anywhere
rec.close();
```

Verification is a pure function over parsed entries, so it can run anywhere:

```ts
import { readLedger, loadPublicKey } from './src/ledger.ts';
import { readAnchors } from './src/anchor.ts';
import { verifyLedger } from './src/verify.ts';

const { entries, problems } = readLedger('/var/acta/run-42');
const verdict = verifyLedger(entries, {
  problems,
  trustedKey: loadPublicKey('/var/anchors/recorder.pub'),
  anchors: readAnchors('/var/anchors/run-42'),
});
// verdict.status: 'tampered' | 'consistent' | 'verified'
// verdict.findings: [{ code, severity, seq, message }]
// verdict.missing: what stands between this ledger and 'verified'
```

## The MCP proxy

`acta mcp -- <command>` wraps any stdio MCP server. Everything is forwarded
untouched; every `tools/call` and its response is recorded, with `isError`
results marked as failures. Anchors are taken on call *completion*, so a
pipelined burst of requests cannot double-anchor. The proxy prints each anchor
line to stderr as it takes one, which is a cheap way to get anchors into a
host's own log.

```
acta init   [dir]                                   create a ledger directory and key pair
acta verify [dir] [--key pem] [--anchors file] [--strict] [--json]
acta anchor [dir] [--to file]                       write the current head as an anchor
acta show   [dir]                                   print the timeline
acta mcp    [--dir d] [--anchor-every N] [--anchor-to file] -- <command> [args...]
```

Exit codes from `verify`: 0 verified (or consistent without `--strict`),
1 tampered, 3 consistent under `--strict`.

## Findings reference

| code | severity | meaning |
|:--|:--|:--|
| `HASH_MISMATCH` | tamper | entry bytes do not hash to their `hash` |
| `CHAIN_BREAK` | tamper | `prev` is not the previous entry's hash |
| `SEQ_BREAK` | tamper | sequence numbers are not contiguous from 0 |
| `BAD_SIGNATURE` | tamper | signature does not verify against the key in use |
| `KEY_MISMATCH` | tamper | the ledger declares a different key than the one you trust |
| `BAD_GENESIS`, `SECOND_GENESIS` | tamper | the first entry is not a valid `open`, or there is another |
| `AFTER_CLOSE` | tamper | entries follow the `close` |
| `ORPHAN_RESULT`, `DUPLICATE_RESULT`, `DUPLICATE_CALL` | tamper | a result without a call, or a second of either |
| `RESULT_REMOVED` | tamper | a call has no result and `close` does not list it as open |
| `COUNT_MISMATCH` | tamper | `close` counts disagree with the ledger |
| `BODY_MISMATCH`, `BLOB_MISMATCH` | tamper | a result body does not match its digest |
| `TRUNCATED` | tamper | an anchor points past the end of the ledger |
| `ANCHOR_MISMATCH` | tamper | the anchored entry has a different hash |
| `UNPARSEABLE` | tamper | a line is not an entry |
| `UNANSWERED_CALL` | warn | a call has no outcome and the session did not close |
| `CLOCK_REGRESSION` | warn | a timestamp precedes the one before it |
| `BLOB_MISSING` | warn | a large result body is not in the blob store |
| `SELF_ATTESTED_KEY` | info | no `--key` was given; the ledger vouched for itself |
| `UNANCHORED_TAIL` | info | entries after the last anchor are the key holder's word |

## Layout

```
<dir>/
  ledger.jsonl      the record, one entry per line, append-only
  recorder.key      Ed25519 private key, mode 0600 — keep this away from the agent
  recorder.pub      the public key; copy it somewhere else and verify against the copy
  blobs/<digest>    result bodies too large to inline
  anchors.jsonl     the default anchor file, which is the weakest place to put one
```

## Not built

- An anchor sink that is append-only by construction — a git note, a signed
  transparency log, a file under `chflags uappnd`. Today the anchor file is
  wherever you point it.
- Key rotation within a session, and resuming a session across a recorder restart.
- Recording tool *definitions* alongside calls, so a later reader can tell what
  the agent was told a tool would do.

## License

MIT.
