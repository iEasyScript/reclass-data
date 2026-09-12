# Cache updates — how content reaches us, and what it can break

> How a Jagex content update propagates into this project, how we measure what it changed, and
> which of our own artifacts a given change invalidates. Companion to `decode-coverage.md`
> (what we can read) and `gameval_index67.md` (the gameval/RSCM name tables).
>
> ⛔ No addresses, opcodes or per-build values here. Mechanism only.

## Two independent things called "an update"

They are routinely conflated and have almost nothing in common:

| | **client update** | **content update** |
|---|---|---|
| what moves | the `rs2client` binary | the JS5 cache |
| signal | `server_version` / `launcher_sub_version` in `jav_config` | index crc / version in the master index |
| breaks | offsets, structs, hooks, and on a major bump the whole wire protocol | definitions, interfaces, scripts, assets |
| owned by | `rs3-update-migrator`, `ghidra-reverse-engineer` | this document |

A content update with an **unchanged revision** is the common case: Jagex reships cache data
several times a month without touching the binary. Nothing in the offset/protocol migration flow
notices it, and nothing in the client forces us to notice it either — our server keeps serving
whatever cache is on disk.

## Where the data comes from

Two JS5 hosts, and they are not interchangeable:

- **live** — serves the cache the real game runs on. This is what our server should serve.
- **beta** — a separate content branch. It is the **only** source of index 67 (the gameval/RSCM
  id↔name tables); live ships that index empty.

Each host is reached with a token from its own `jav_config`. The token **regenerates on every
fetch**, so it must be fetched in the same shell command that uses it, and a live token is
rejected by the beta host and vice versa.

The two branches drift apart in both directions. Beta can be ahead (new content named before it
ships) or behind (live shipping content beta has not rebuilt for). Which way they are pointing
right now determines how much of the gameval name coverage is usable — see *Gameval drift*.

## The change signal, at three resolutions

**Index level** — the master index (archive 255, group 255) carries a crc, version, file count and
size per index. Cheap, one request, and enough to answer "is anything stale". This is what a scan
reports. It cannot tell you *what* changed.

**Archive level** — each index's reference table carries a crc, version and file count **per
archive**, plus name hashes when the index sets the names flag. Reference tables are small, so
this resolution is nearly as cheap as the index level and vastly more informative. Critically it
works for **every** index, including ones we cannot decode at all: we can always say which models
or textures changed even with no model or texture decoder. This is the layer the snapshot captures.

**Field level** — requires a decoder. Gives per-definition, per-field differences.

The practical consequence: **never reason about a content update at index level.** "Index 47
changed" is not information; "385 model archives added and 12 modified" is.

## The snapshot / diff model

A **snapshot** is an unpacked, gitignored capture of one cache at one point in time. Snapshots are
kept as history so any two can be diffed after the fact — including a pre-update capture against a
post-update one, which is the only way to explain what an update did once it has landed.

The ordering rule that makes this work:

> **Snapshot before you download.** A cache is overwritten in place. The pre-update state is
> unrecoverable the moment the downloader runs, and with it any chance of explaining that update.

Because archive identity comes from the reference table's own crc and version, a snapshot needs no
blob hashing — hashing would mean reading the entire cache to learn what the reference table
already states. A whole-cache snapshot is therefore small and fast.

## What an update can break, and how you find out

| what changed | what it invalidates | how it surfaces |
|---|---|---|
| a config definition gains a field | **that definition, silently and completely** | decode report: trailing bytes / unknown opcode |
| an interface gains or loses a component | **gameval component ids after the insertion point** | archive diff on the interface index, then shape alignment |
| an interface is rebuilt wholesale | that interface's component names become unusable | alignment reports it as unalignable |
| a definition is renamed or removed | code resolving that name | loud failure on the strict resolve path, silent null on the soft path |
| clientscripts change | CS2 behaviour our scripts depend on | crc only — this index carries no meaningful version |
| assets change (models, textures, graphics) | rendering only | archive diff |

The first two are the dangerous ones because both are **silent**.

### Silent failure 1 — a new field desynchronizes a decoder

Definition records are an opcode loop. An opcode the decoder does not recognise consumes no
payload bytes, so the loop reads that field's first payload byte as the next opcode and every
subsequent field of the record is garbage. No exception, no log. The only reliable detector is
checking that the decoder consumed the record to its last byte. See `decode-coverage.md`.

### Silent failure 2 — gameval component drift

This is the one that keeps biting, and it is worth understanding precisely.

Component names in `re-resources/gamevals/component.json` are keyed by **slot position within an
interface**. Insert one component into an interface and every slot after it shifts by one. The name
now addresses the wrong component — and because the id still exists and still resolves, nothing
errors. A window renders in the wrong place, or a button does nothing, and the cause is invisible.

Compounding it: index 67 is beta-only, so every component id we ship is a **beta** slot, while the
server serves the **live** layout. The two must be reconciled, which is what the alignment step
does — it aligns each interface's component sequence between the two caches and re-keys the names
onto the served layout. Re-run it whenever **either** cache moves, not just the beta one.

**A changed component count proves a shift, but is not required for one.** An interface can keep
its total count and still reorder slots — an insertion and a deletion cancel out in the count while
every name between them moves. Counting components therefore *under-reports* drift, and has been
observed to miss interfaces carrying hundreds of named components. Treat a count change as a
sufficient alarm and a crc change as the actual trigger: every interface whose crc moved needs the
shape alignment run over it before drift can be ruled out.

Names reach the resolver as enum constructor arguments, as constants behind local helpers, from
content DSL callers and from data files — and component keys are usually assembled by
concatenation, so the full key never appears as a literal anywhere in the source. **Grepping for
affected names does not work.** Capture the set of names actually resolved at runtime instead.

## Order of operations for a content update

1. Scan live at index level — is anything stale.
2. Descend to archive level as a **dry run** — what exactly would be fetched, and how much.
3. **Snapshot the current cache.** Before anything else touches it.
4. Stop any process holding the cache open. The server holds it while running, and a download
   opens it read-write.
5. Download.
6. Snapshot again.
7. Diff the two snapshots.
8. If any interface archive changed, re-run the gameval alignment and read its summary.
9. Run the decode report; new unknown opcodes are new fields and need decoder work.
10. Update the coverage ledger if anything moved.

## Hard rules

- **Never open a cache read-write** unless you are deliberately downloading into it. A read-write
  open takes a lock, rewrites the SQLite header and leaves sidecar files that can force a
  multi-gigabyte re-download. Read-only is a first-class mode in the cache library; shell reads
  must use a read-only URI.
- **Never download into a cache another process owns.** Stop the server first.
- **A clean parse is not proof of correctness** — only that the decoder consumed the bytes. It can
  be pointed at entirely the wrong data and still report success.
