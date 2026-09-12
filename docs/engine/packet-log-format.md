# Packet log storage format

How the engine stores captured packets on disk, and what a reader in any language has to implement.

This describes the container only. It deliberately contains no opcode, offset or address: prot
identity is `(revision, direction, opcode)` and the meaning of those numbers lives in `:core`'s
prot tables and the Ghidra database, never here.

## Why it is not a row per packet

A packet log is dominated by small, highly repetitive bodies. Storing one database row per packet
costs more than the packets themselves once an index exists, so packets live in compressed chunks
and only coarse per-chunk metadata is indexed. Grouping bodies by prot before compressing them is
worth roughly a third of the total, because packets of one type share structure; a reader still
needs arrival order, and the format gets both without paying for a permutation (see *Ordering*).

## Databases

### One database per session

⛔ **Sessions never share a file.** Two clients on one machine is ordinary - two accounts, or one
account on live and another on a local server - and a shared database would put two writers on one
file and, worse, let each one's crash recovery close out the other's *live* session and re-seal its
spill from under it. A file per session removes the possibility instead of guarding against it: one
writer, one file, for the whole life of the session.

Ownership is an OS file lock rather than a pid file, because the kernel releases it however the
process dies - which is the case that matters, since the client is killed outright often enough that
clean shutdown is the exception. Recovery therefore finishes only files no live process holds.

The session id names the file, travels in the upload manifest, and identifies the session on the
server, all in the same spelling - so a local capture and a remote one can be lined up at a glance.

Three roles, one schema, so a chunk is byte-identical wherever it lands and a misrouted session can
be moved rather than re-encoded:

- **capture** — the in-flight session, the spill table, and sealed chunks.
- **archive** — the durable append-only store. One session row per session, forever. Never opened
  read-write while the client is running, so a client crash cannot damage it.
- **quarantine** — same schema, contents we cannot vouch for: withheld bodies, overflow markers,
  frames that failed verification, and sessions whose server could not be attributed.

Live-game and local-server captures live in separate directories and never mix.

Which of the two a session belongs to is decided by the server the client connects to, which is not
knowable at injection time. Capture is therefore armed immediately but the session opens on the
first packet, once there is a connection to attribute it to; packets captured before that are held
rather than dropped. If the client later moves between the two servers, the session is closed and a
new one opened, so no session ever spans both.

### Density invariant

Within one session uuid, the sequence number is dense across the union of archive and quarantine.
Every gap in the archive is explained by a row elsewhere with the same uuid and sequence. Nothing is
ever silently absent — a body that could not be read is recorded as withheld, never fabricated and
never quietly skipped.

## Chunk frame

Little-endian. A 40-byte header followed by the compressed payload.

| Field | Meaning |
|---|---|
| magic | `UPK1` |
| format | container version |
| codec | store, raw deflate, or raw LZMA1 |
| flags | whether bodies are prot-grouped, and which optional sections are present |
| prot count | distinct prots in this chunk |
| count | events in this chunk |
| plain length / compressed length | payload sizes |
| payload checksum | CRC-32C over the uncompressed payload |
| codec properties | codec-private; raw LZMA1 stores its properties here so a chunk is self-describing |
| header checksum | CRC-32C over the preceding header bytes |

Two independent checksums, so a torn write is detectable whichever half survived. They serve reads;
the database separately stores a SHA-256 over the *uncompressed* payload as the transfer identity,
which is what makes re-compressing an archive to another codec provably the same data.

The payload opens with a section directory of `(id, length)` pairs, so a reader can skip a section a
newer writer added instead of rejecting the frame.

### Sections

Delta columns are unsigned LEB128; every column is non-negative by construction, so a zigzag
encoding would spend a bit per value on a sign that never occurs.

| Section | Contents |
|---|---|
| prot dictionary | the distinct `(direction, opcode)` pairs this chunk uses |
| timestamps | absolute first value, then per-event deltas |
| prot | per-event index into the prot dictionary |
| size | per-event body length |
| tick | absolute first value, then per-event deltas |
| quality | sparse; present only when some event is flagged |
| body | bodies concatenated, no framing |

Timestamps and ticks lead with their absolute base, so a frame decodes with no database context.

### Ordering

The index columns are in **arrival order**; the body section is in **prot-grouped order**. A reader
rebuilds the original sequence by walking the prot column and taking the next body from that prot's
group:

```
cursor[p] = start of prot group p        (from the prot and size columns, one pass)
for each event i:
    body = bodies[cursor[prot[i]] ..< cursor[prot[i]] + size[i]]
    cursor[prot[i]] += size[i]
```

The prot column in arrival order *is* the interleaving, so the permutation costs nothing. This also
keeps the timestamp deltas monotonic, and resolves ties within a millisecond by position — which is
how byte-identical repeats of the same packet keep their true relative order.

## Capture policy

Some prots carry nothing worth keeping, and two groups dominate the byte budget while saying nothing
about game content:

- **Telemetry** — the server's own instrumentation grid. Its body is dropped unconditionally.
- **Client input events** — mouse movement, mouse clicks and keypresses the client sends outbound.
  These exist on the wire only as a coarse echo of input the input recorder already captures
  directly, at OS event rate, in far more detail. Their bodies are kept **only while input training
  capture is running**, which is their sole consumer; otherwise they are dropped. Mouse movement
  alone is the largest prot by bytes in a normal session.

Dropping a body never drops the event. The record stays in sequence with a zero-length body, so
timing and frequency survive and the density invariant holds. A mode that removes the event outright
exists but is never a default, precisely because it would break that invariant.

The policy is a table in the database rather than a constant in code, so it can be edited per
revision and takes effect on the next session.

## The investigation index

The archive answers "keep everything, cheaply". Investigation asks a different question - *what
happened around this* - and the two want opposite layouts, so they are separate artifacts. The index
is **derived and disposable**: it is rebuilt from archives, never edited, and throwing it away costs
only the time to rebuild it.

That separation is also what makes a decoder written months later useful. The bytes were kept, so
adding a decoder and rebuilding gives every past capture the new fields; the capture itself is never
touched. A capture is decoded with the codec for **its own** revision, because a prot table is only
meaningful alongside the capture it framed.

### Two primitives

Every investigation has the same shape whatever it is about, so the index supports exactly two
operations and composes them:

- **anchor** - locate events by any decoded field
- **window** - everything around that point, in tick order, decoded

Nothing in the query layer knows what an interface or an npc is. The field dictionary does, and it
is populated from the decoders' declared schemas, so a decoder added later becomes queryable with no
schema change.

### Layout

| Table | Holds |
|---|---|
| `event` | One row per captured packet: session, sequence, tick, direction, prot, and its decoded fields as JSON. This is the tick axis, and why a window query never touches a compressed frame. |
| `field_def` | Every field that exists, per revision, with its reference domain and whether it is indexed |
| `field_index` | Constant-time lookup for the ids an investigation starts from |
| `field_text` | Full-text over prose fields - chat, interface text. Ids are found by value, not by search |
| `session_decode_state` | Per-prot decode coverage, which is what says where a decoder is worth writing next |

Everything is filterable; the index decides only what is filterable in *constant* time. A field
without an index is still found by scanning that prot's events, which is bounded because the prot
itself is indexed.

## Sharing

Captures stream to the ingest server in the background, on their own thread, while the session is
still being written - a long play session reaches the server as it happens rather than all at once
at the end. Nothing about it can slow capture down or lose data: a failed cycle leaves the chunks on
disk and retries with backoff, because the archive is the source of truth and the upload is a mirror
of it.

Work is scoped per session file, which is what keeps concurrent uploads independent. A session is
owned by exactly one writer, uploaded under its own identity, and the server keys chunks by
`(session, ordinal)` - so two clients on one machine, or two people entirely, cannot collide even
when their uploads land at the same instant.

A session that is still open is streamed but never completed; completing it is what seals it, and
that happens only once it has actually ended.

## Identity

Two hashes, for two different jobs, neither stored per event (at observed packet rates they would
cost several times the entire budget, and every input is already in the chunk):

- **event id** — over session uuid, sequence, timestamp, direction, quality, opcode and body. The
  sequence is what makes it injective: byte-identical packets in the same millisecond are distinct
  events, and a hash over content and time alone would silently discard real ones.
- **body hash** — content address of the body alone, for a content-addressed store.

Upload identity is the chunk, keyed by `(session uuid, ordinal)` and committed by the payload
SHA-256, so re-sending is a structural no-op.

## Durability

Events are spilled to a row-per-packet table as they arrive and deleted only in the same transaction
that commits the chunk replacing them. A process killed mid-chunk therefore loses nothing that
reached a flush: recovery re-seals the spill into the session it belongs to and marks that session
recovered, rather than discarding the tail or passing it off as complete.

Chunks are immutable once sealed; mutable upload bookkeeping lives in its own table so the chunk row
is written exactly once.

Promotion between databases cannot be made atomic while either side uses a write-ahead log, so it is
idempotent instead: every insert is conflict-tolerant, frames are verified against their checksums
before the source rows are dropped, and a re-run converges rather than duplicating.
