# Acta

[![test](https://github.com/patkusch/acta/actions/workflows/test.yml/badge.svg)](https://github.com/patkusch/acta/actions/workflows/test.yml)

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
npm test          # 44 tests: the chain, the recorder, the proxy, resume, key rotation, definition binding, and every attack in the catalogue
npm run attack    # the demo: twelve attacks, three verifier configurations, one cell that stays red

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
 "def":{"seq":3,"digest":"e0b4…"},
 "hash":"9b41…","sig":"MEUCIQ…"}
```

Seven kinds: `open` (genesis, declares the session and the public key), `call`,
`result` (which cites its call and carries the body inline or by digest),
`note`, `rotate` (retires the signing key and declares its successor), `resume`
(marks a recorder restart and names the head it continues from), and `close`
(which records the counts and which calls were still open).

A `call` may also carry `def`: the seq of the recorded `tools/list` result the
agent was shown and the digest of this tool's definition in it. The verifier
follows that reference and recomputes the digest, so a call cannot quietly
drift away from the definition it was made against — see
[binding calls to definitions](#binding-calls-to-definitions).

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

A session that crashed mid-call is not tampering. Its last call has no result
and there is no `close`; the verifier reports `UNANSWERED_CALL` as a warning
and the verdict stands. The same file with its tail cut off looks identical —
which is why the truncate row in the table below is caught by nothing but an
anchor. A result that is missing when the `close` entry says it should be there
is a different matter: that is `RESULT_REMOVED`, and it is tampering.

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
runs twelve attacks against it. Each attack is labelled with what the attacker
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
redefine the tool, real key       real key  caught  caught  caught
redefine and rebind, real key     real key  —       —       caught
after the last anchor, real key   real key  —       —       —

  the chain alone catches 6 of 12: anyone who can write the file but does not understand it.
  a trusted key catches 7: anyone who does not hold the recorder's key.
  an anchor catches 11: anyone who holds the key, for entries up to the anchor.
  nothing catches 1: the key holder, between the last anchor and now.
```

Three rows deserve a second look.

**Truncate** is caught by nothing but the anchor. A ledger with its last twenty
lines cut off is a perfectly valid shorter ledger; it looks exactly like a
session that crashed. Hash chains do not protect against this and it is the
easiest attack on the list — it needs no understanding of the format at all.

**Redefine the tool** is a real-key attack that the chain alone catches. Not
because the chain can see through a signature — it cannot — but because every
call carries the digest of the definition it was made against, and the attacker
rewrote the definition without rewriting the calls. The next row is what
happens when they do: caught by the anchor, and by nothing else. A
cross-reference costs the key holder one more edit. It does not stop them.

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
  is decoration. The library makes anchors small, and `--append-to` makes a local
  sink the kernel will not let the agent rewrite, but neither can beat putting the
  anchor somewhere the agent has no write at all.
- **Single writer.** One recorder, one key, one session per file. This is not a
  distributed log and does not pretend to be. There is no consensus and no
  witness set. If you need multiple independent parties to attest, the anchor is
  the thing to hand them.
- **A missing ledger is not a finding.** If the whole directory is deleted, the
  only evidence it existed is an anchor somewhere else with no ledger to match.
  `verify` on a directory with no ledger reports `MISSING`, which is all it can do.
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
rec.anchor('/var/anchors/run-42', { appendOnly: true }); // kernel-enforced append-only sink
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
results marked as failures. `tools/list` is recorded too, as a call whose
result is the catalogue, so the definitions the agent was shown sit in the same
chain as the calls it made against them, and every `tools/call` after it is
bound to that catalogue — a later reader can tell what the agent was told a
tool would do, not just what it did. Anchors are taken on call *completion*, so a
pipelined burst of requests cannot double-anchor. The proxy prints each anchor
line to stderr as it takes one, which is a cheap way to get anchors into a
host's own log.

```
acta init   [dir]                                   create a ledger directory and key pair
acta verify [dir] [--key pem] [--anchors file] [--strict] [--json]
acta anchor [dir] [--to file] [--append-to file]    write the current head as an anchor
acta show   [dir]                                   print the timeline
acta mcp    [--dir d] [--resume [--rotate-on-resume]] [--anchor-every N] [--anchor-to file | --anchor-append-to file] -- <command> [args...]
```

Exit codes from `verify`: 0 verified (or consistent without `--strict`),
1 tampered, 3 consistent under `--strict`.

### Binding calls to definitions

A tool is what its definition says it is. `shell` described as "not sandboxed"
is a different tool from `shell` described as "runs in a throwaway sandbox",
and an agent that read the second and did the first was misled, not reckless.
So the proxy treats a `tools/list` result as the catalogue in force, and every
`tools/call` after it carries `def`: the seq of that catalogue entry and the
sha256 of this tool's definition inside it, computed from the same bytes the
ledger recorded. The verifier follows the reference and recomputes the digest.

What that buys, and what it does not:

- **Each call names the definition it was made against.** When a server
  changes its definitions mid-session and the host lists again, the ledger has
  two catalogues, and every call says which one it was made under. A
  `notifications/tools/list_changed` from the server is recorded as a note;
  calls stay bound to the last catalogue the host actually fetched, because
  that is what the agent saw. After a `--resume`, the definitions in force are
  read back from the ledger, so calls before the host lists again are still
  bound.
- **Calls the catalogue does not cover are flagged.** A call to a tool the
  catalogue in force does not list is `UNLISTED_TOOL`: the agent called
  something it was never shown. A call after a catalogue with no binding at
  all is `UNBOUND_CALL`. Both are warnings — the record is consistent, just
  less informative. Calls made before any catalogue was listed are not flagged.
- **It is one more thing a key holder must keep consistent.** Rewriting the
  recorded definition of `shell` to say it was sandboxed — the edit a tool
  author would most want — now needs every `shell` call rebound as well, or
  `DEF_MISMATCH` fires with the chain alone. Rebinding is not hard for someone
  with the key; the attack table has both rows, and the second is caught only
  by an anchor. This is a cross-reference, not a defence against the key
  holder. Nothing in this file is.
- **It says nothing about what the server did with the call.** A server that
  lists one definition and executes another is outside the recorded boundary,
  exactly as the tool's side effects are. The ledger proves what the agent was
  told and what it asked for; it never saw what ran.

### Resuming after a restart

One session is one ledger file, and by default the recorder refuses to reopen
one — a second `open` would be a second genesis, and the verifier says so. But a
recorder that *crashed* leaves a ledger with no `close`, and the run is not over.
`acta mcp --resume` (and `Recorder.resume(dir)` in the library) continues that
ledger instead of refusing it, so a restarted proxy records into the same
session rather than starting a fresh one beside it.

Resume is deliberately narrow, because reopening a record is exactly where a
forgery would hide:

- **It verifies before it continues.** The existing chain is checked against the
  recorder's own key first; a tampered, wrong-key, or broken ledger is refused,
  not appended to. Resuming onto a corrupt base would launder it.
- **A clean `close` is final.** The verifier reads anything after a `close` as
  tampering, so there is nowhere sound to append. To continue past a close, start
  a new session. Only an un-closed (crashed) ledger can be resumed.
- **The restart is on the record.** The first entry written is a `resume` marker
  naming the head it continues from. `RESUME_MISMATCH` makes that claim
  uncounterfeitable — its `fromHash` must equal its own `prev` — so even a key
  holder cannot forge a continuity that did not happen.
- **A call in flight at the crash stays open.** Its outcome happened in the gap
  and was never seen, so it is reported as `UNANSWERED_CALL`, not invented.

### Rotating the key

The signing key can change without ending the session. `Recorder.rotate(newKeys)`
retires the current key and continues under a new one, writing a `rotate` entry
that declares the successor. Two things make this safe:

- **The rotation is signed by the *outgoing* key.** It is the current holder's
  authorisation of the next key, so trust flows forward along a signed
  succession. Someone who cannot sign with the current key cannot insert a
  rotation — the `rotate`'s own signature is checked against the retiring key,
  and a forged one is `BAD_SIGNATURE`.
- **You verify with the *original* key, and it covers the whole chain.** Hand a
  reviewer the genesis key; the verifier follows each rotation to the next and
  checks every entry against the key in force when it was written. The current
  on-disk key is *not* the verification key — verifying against it fails at
  genesis with `KEY_MISMATCH`, which is the point: the root of trust is the key
  the session opened with, not the one it happens to hold now.

`acta mcp --rotate-on-resume` rotates on restart, before recording anything more.
If whatever took the recorder down also exposed its key, the blast radius stops
at the restart: entries after it are signed by a fresh key, and the original
still verifies everything before it. This is the answer to the resume caveat that
a recorder coming back holds a key that may have been exposed in the gap.

### Anchoring into git

`acta anchor <dir> --git` appends the anchor line as a git note on `HEAD` under
`refs/notes/acta`; `acta verify <dir> --git` reads every anchor back from that
ref. Locally this is no stronger than a file the same user can write. The point
is the next step:

```bash
git push origin refs/notes/acta                      # a copy the agent needs push rights to alter
git fetch origin refs/notes/acta:refs/notes/acta     # a reviewer verifies against that copy, not the local one
```

### An append-only anchor sink

Anchoring off the machine is the strong move; when it has to stay local, the
anchor file is only as safe as its permissions. `acta anchor <dir> --append-to
<file>` (and `acta mcp --anchor-append-to <file>`) writes to a file the kernel
marks append-only — `chflags uappnd` on macOS and the BSDs. With the flag set,
the OS permits appends and refuses truncation, in-place rewrite and unlink.

Append-only is precisely the right strength, and no more, because **anchors are
monotonic evidence**. An attacker holding the recorder key can append a new
anchor that matches a rewritten ledger — the sink allows that — but cannot
remove the honest anchor already in the file, and one surviving honest anchor no
longer matches the rewrite, so the rewrite is caught. More anchors can only
catch more, never fewer.

The honest boundary: `uappnd` is a *user* flag its owner can clear with `chflags
nouappnd`. It stops an agent whose tools are read, write and delete but not
`chflags`; it does not stop the file's owner, and it is not the system-immutable
flag (`schg`, root and a reboot to clear). On Linux — where the equivalent is
`chattr +a` and needs `CAP_LINUX_IMMUTABLE` — the command refuses rather than
writing a file that only looks protected. This is a higher local bar, not a
substitute for anchoring somewhere the agent has no write at all.

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
| `DEF_MISMATCH` | tamper | a call's bound definition digest is not what the cited catalogue holds, or that catalogue does not define the tool |
| `BAD_DEF_REF` | tamper | a call is bound to a seq that is not an earlier `tools/list` result |
| `COUNT_MISMATCH` | tamper | `close` counts disagree with the ledger |
| `BODY_MISMATCH`, `BLOB_MISMATCH` | tamper | a result body does not match its digest |
| `TRUNCATED` | tamper | an anchor points past the end of the ledger |
| `ANCHOR_MISMATCH` | tamper | the anchored entry has a different hash |
| `RESUME_MISMATCH` | tamper | a `resume` marker names an origin that is not the entry before it |
| `BAD_ROTATE_KEY` | tamper | a `rotate` entry declares an unreadable successor key |
| `UNPARSEABLE` | tamper | a line is not an entry |
| `MISSING`, `EMPTY` | tamper | no ledger file, or a ledger with no entries |
| `UNANSWERED_CALL` | warn | a call has no outcome and the session did not close |
| `CLOCK_REGRESSION` | warn | a timestamp precedes the one before it |
| `BLOB_MISSING` | warn | a large result body is not in the blob store |
| `UNLISTED_TOOL` | warn | a call names a tool the catalogue in force does not list |
| `UNBOUND_CALL` | warn | a call made after a catalogue carries no binding to a definition |
| `SELF_ATTESTED_KEY` | info | no `--key` was given; the ledger vouched for itself |
| `UNANCHORED_TAIL` | info | entries after the last anchor are the key holder's word |
| `DEF_UNCHECKED` | info | the bound catalogue's body is not available here, so the binding was not checked |

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

- A signed transparency log as an anchor sink. A local append-only file
  (`--append-to`, `chflags uappnd`) and git notes pushed to a remote are both
  supported; a public append-only log with independent witnesses is not.

## License

MIT.
