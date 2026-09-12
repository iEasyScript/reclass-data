# Cache decode coverage — what we can read, and what we still cannot

> **Purpose.** A living ledger of how much of the JS5 cache the `:core` cache library actually
> understands. It exists so the undecoded surface shrinks deliberately instead of staying
> invisible. Regenerate the measurements with `:tools:cacheSnapshot`; do not hand-maintain the
> numbers.
>
> ⛔ **No opcode values, addresses or offsets in this file.** Decoder opcode tables are per-build
> facts and live in the Ghidra DB; concrete unknown-opcode numbers live in the generated,
> gitignored snapshot output. This file records *status and format knowledge* only.

## Prioritisation

This is a **library**. A decoder is either faithful to the format or it is not; whether anything
currently calls it is irrelevant to that judgement, and "nothing consumes it" is never a reason to
leave a known defect in place. A field that is misnamed, fabricated, or silently truncated is a
defect the moment it exists, because the first caller to trust it inherits the bug.

Order of work, accordingly:

1. **Make every decoder we already have flawless** — zero trailing bytes, zero unknown opcodes,
   no fabricated fields, no misleading names.
2. **Then** extend coverage to indices that have no decoder.

Archive-level identity already makes every index diffable (see *Coverage tiers*), so deferring new
decoders costs visibility of *what changed inside* an archive, not visibility of *that* it changed.
That is what makes step 1 affordable to finish first.

## The two questions this answers

1. **Can we read it at all?** — is there a decoder for this index/archive.
2. **Do we read it completely?** — does the decoder consume every byte of every record.

These are independent. A decoder can exist and still be wrong, and a clean parse does not prove
correct semantics (see *Limits of the trailing-byte check* below).

## Coverage tiers

Every index is captured at **archive granularity** regardless of decoder status, because the
reference table carries a per-archive crc, version and file count for every index. An index with
no decoder is therefore still fully diffable — we can always say *which* archives changed, even
when we cannot say *what* changed inside them. Only field-level detail requires a decoder.

| tier | what we get | applies to |
|---|---|---|
| **field** | every decoded field of every definition | indices with a working decoder |
| **archive** | per-archive crc / version / file count / name hash | **every** populated index |
| **none** | — | nothing; archive tier is always available |

## Status by index

Measured against the served cache. "archives" is the reference-table entry count.

| idx | name | archives | status | notes |
|----:|------|---------:|--------|-------|
| 1 | animation-skeletons | 5,321 | none | |
| 2 | configs | 39 | **partial** | 24 of 39 archives decoded; see *Config archives* |
| 3 | interfaces | 1,883 | **partial** | `InterfaceDecoder` aborts on a bounds error; component bytes are still read raw by the alignment tooling |
| 5 | maps | 8,675 | **partial** | `MapDecoder` reads a subset; see *Maps* |
| 8 | graphics | 36,425 | **partial** | `GraphicDecoder` aborts; only the legacy indexed-palette layout is implemented |
| 10 | huffman | 1 | special | consumed directly, not a definition type |
| 12 | client-scripts | 21,097 | **container** | One implementation. The cache library owns the container framing — name, counts, switch tables — and carries the instruction stream as an opaque blob; the CS2 toolchain walks that blob with the per-build width table and round-trips every script byte-identically. See `clientscript-cs2.md`. |
| 13 | font-metrics | 60 | full | |
| 14 | vorbis | 60,065 | none | audio |
| 16 | objects (locs) | 548 | full | small residual trailing-byte population, one unhandled opcode |
| 17 | enums | 69 | full | |
| 18 | npcs | 257 | full | |
| 19 | items | 249 | full | |
| 20 | animations (seq) | 298 | full | |
| 21 | spotanims | 37 | full | two definitions with trailing bytes |
| 22 | structs | 1,664 | full | |
| 23 | world-map | 5 | **partial** | three decoders, two non-functional |
| 24 | quick-chat | 2 | full | phrases have a small trailing-byte population |
| 26 | texture-definitions | 1 | full | metadata only, not pixels |
| 27 | particles | 2 | none | |
| 28 | defaults | 11 | **partial** | 1 of 11 archives decoded |
| 29 | billboards | 1 | none | |
| 32–35 | loading-graphics, game-tips, cutscenes | 79 | none | |
| 40 | audio-streams (music) | 85,927 | none | HTTP transport |
| 41–42 | world-map areas / labels | 913 | none | |
| 47 | models | 145,735 | none | largest single gap |
| 48 | anim-frames | 33,534 | none | |
| 49 | dbtableindex | 261 | full | |
| 52–55 | textures (dds/png/bmp/ktx) | 154,725 | none | |
| 56 | anim-keyframes | 2,936 | none | |
| 57 | achievements | 40 | full | |
| **58** | **unidentified** | 225 | none | **archives are name-hashed** — the hashes are a lead for identifying it |
| **59** | **unidentified** | 5 | none | one of the archives the client requests first |
| **60** | **unidentified** | 319 | none | |
| **61** | **unidentified** | 1,344 | none | |
| **62** | **unidentified** | 7 | none | one of the archives the client requests first |
| **65** | **unidentified** | 2 | none | |
| **66** | **unidentified** | 9 | none | |
| 67 | gameval / RSCM | 36 | full | beta-only; see `gameval_index67.md` |

**Roughly seven eighths of all archives sit in indices with no decoder**, dominated by models,
music, textures and vorbis — i.e. bulk binary assets. The *definition* layer, which is what
gameplay depends on, is in much better shape than that ratio suggests.

### Seven indices nobody has identified

Indices 58, 59, 60, 61, 62, 65 and 66 are populated and **nothing in the repo names them** — no
constant, no doc, no comment. Two of them are among the archives the client requests earliest,
so they are not vestigial. Index 58 sets the ref-table names flag, so its archive name hashes can
be brute-forced against a candidate wordlist — that is the cheapest available lead. Identifying
these is reverse-engineering work; the result belongs in `Index.kt` and the Ghidra DB.

### Config archives (index 2)

39 archives exist; 24 have decoders. `Config.kt` additionally carries several constants no decoder
references, and several var-domain archives have no decoder at all. Because the archive→type
assignment has been observed to be **wrong** for some types, always confirm an archive's identity
against two independent sources before trusting it:

1. the **file count** of the archive in the served cache, and
2. the **entry count** of the matching `re-resources/gamevals/<type>.json` table.

An exact match between those two is strong evidence; a decoder that parses cleanly is *not*, on
its own (see below). The authoritative answer is the client binary, which builds its config group
table by enum ordinal and hands each group id to a type-list factory — reading the consumers back
gives an unambiguous archive-to-type mapping.

**This has actually gone wrong.** Four config types were found mislabelled at once, each decoder
reading the archive belonging to a neighbouring type. It went unnoticed for a long time because
one of the mismatched decoders consumed its wrong archive perfectly — every byte, zero trailing —
while producing entirely wrong values. The tell was not a parse failure but a *semantic* one: the
decoded string fields read like world-map menu options rather than the type they claimed to be.

Two lessons worth keeping:

- **Verify archive identity by count against the gameval tables, then sanity-read the decoded
  strings.** A decoder that produces plausible-looking bytes for the wrong type is the failure mode
  the trailing-byte check cannot see.
- **A config type can disappear entirely between builds.** One of the four had no counterpart in
  the client at all — the name survived only as renderer state, not as a config type. Do not assume
  a `Config` constant corresponds to anything the client still loads.

### Maps (index 5)

`MapDecoder` reads five file slots per map square. The object and tile slots are known to be
incomplete — the format carries header sections the decoder does not consume — and failures were
historically swallowed entirely. Failures now surface through the decode report. The byte-level
format is documented in `mapsv2-format.md`. RS3 maps carry **no XTEA**; do not add key handling.

## Decode health

Enable the decode report (see *Telemetry*) and the snapshot tool records, per definition:

- **trailing bytes** — the record was not fully consumed. This is the authoritative "we do not
  understand this" signal.
- **unknown opcodes** — exact, for decoders that have an explicit unknown-opcode arm.
- **zero-advance opcodes** — a heuristic that localises *where* a desync began. Some opcodes are
  legitimately zero-payload flags, so this over-reports and must never be treated as proof.

The definition layer currently parses **every** record of every decoder the sweep drives to its exact
end — zero trailing bytes, zero unknown opcodes, zero failures.

⚠️ **Read that sentence precisely, because the sweep's own decoder set is part of the claim.** The
sweep was once given a hand-written list, and a decoder absent from that list contributes no failures
and no records — it simply is not measured. The clientscript decoder was excluded that way, so the
headline number never covered the single most volatile index in the cache; a tool that enumerated
decoders from the classpath instead surfaced it immediately, and every record failed. **Prefer
discovering the decoder set over listing it** — a hand-maintained list silently narrows the very claim
it is used to support, and it narrows most where someone deliberately excluded something and moved on.
The sweep now enumerates from the classpath and prints what the registry could not drive itself, so an
unmeasured decoder is visible rather than absent. Treat the clean headline as the baseline to defend on
update day, not as a finished state: it means we consume every byte, not that every field is
understood. Several decoders store values under placeholder names, and
at least one type's layout is known only by inference from the data rather than from the client.

## A decoder pointed at a non-existent archive reports nothing, not an error

The most dangerous decoder failure in this cache library is not a crash or a trailing-byte count — it
is a decoder wired to an archive id that does not exist. Asking the index for the last file of a
missing archive yields nothing, so the decoder loads **zero records and raises no error**. Every health
signal we have then reads clean: no failures, no trailing bytes, and the type does not even appear in
the sweep's offender list, because a type with nothing decoded has nothing to be wrong about. The
result is indistinguishable from "this type is legitimately empty".

This is not hypothetical. Two var domains sat at zero for a long time behind exactly this: their config
constants still held **pre-RS3 archive ids** that no longer exist in the index, while the domain enum
beside them carried the correct ones. The two disagreed and nothing noticed, because disagreement
between a constant and an enum is not something any test asserted. Thousands of records were simply
invisible.

**So a zero is a finding that needs explaining, never a result to accept.** When a type decodes nothing,
check the index's actual archive list before concluding the type is empty — the archive ids present in
an index are enumerable, and a constant pointing outside that set is provable in seconds. Where two
places in the code both name an archive (a constants file and a domain enum, say), they are a
consistency check on each other and worth asserting as one.

**Confirm an archive's identity from the data, not from a name that looks right.** Where records in one
index reference records in another — a table whose every entry names both a domain and a base record —
the referencing table constrains which archive can possibly serve that domain: only an archive holding
*every* referenced base, at the right type, is viable. Run that test across all candidate archives and
the mapping usually falls out uniquely. Validate the method on the subset you can confirm independently
before trusting it on the rest — when this was done here, it reproduced every independently-known
mapping and then *overturned* one that had been assigned by name similarity alone.

One consequence worth keeping: an archive can be real, populated and internally consistent while the
**client never touches it**. Several var domains here are fetched by nothing in the binary and have no
name anywhere in it. Server-side-only data is still data — its archive identity rests on the cache's own
internal consistency, which is exactly what a decoder needs, and the absence of a client reference is
not evidence against it.

## An unknown opcode is not automatically a missing field

The reflex on seeing an unknown opcode is to assume the client gained a field we have not modelled,
and that the record desynchronizes from that point. That reflex is right often enough to be
dangerous, and the floor types are the counter-example: the client's own switch has **no arm** for
several opcodes the live cache emits, and consumes nothing for them. Its decode loop reads an
opcode, dispatches, and repeats — an unmatched opcode falls through to a bare return, so a
zero-width no-arm opcode is a perfectly consistent thing for the client to ship and for the cache
to contain.

Two consequences. First, **establish the width before inventing a field**: parse the whole affected
population at each candidate width and keep the one where every record lands exactly on its
terminator. That test is decisive and needs no binary. Second, a zero-width unknown opcode does
**not** desync anything — only an opcode whose payload we fail to consume does. Reporting the two
as the same severity wastes the triage.

The corollary is the more valuable half: reading the client's decode loop to settle one unknown
opcode also tells you whether the arms you already implement agree with it. On the floor types the
unknown opcodes turned out to be nothing, while the *implemented* arms held real divergences —
a value the client discards that we retain, a signedness mismatch, and a units difference. Check
the arms you think you know while you are in there.

### Why this matters on update day

A game update that adds a field to a config type appears as an **unknown opcode**. Because the
opcode loop reads a length-prefixed stream, an unrecognised opcode consumes no payload, so the
next payload byte is read as an opcode and the record desynchronizes — every subsequent field of
that definition becomes silently wrong. Without the trailing-byte check there is no error and no
symptom until something misbehaves in game. Run the check after every cache update.

## String readers are not interchangeable

> This cost us an entire type. The version-prefixed reader **already existed** in the buffer layer
> and was already in use by another decoder — the broken type simply called the plain one. When a
> whole type fails, check which string reader it uses before assuming the format is unknown.


The cache uses **two distinct string encodings**, and they are separate functions in the client:

- a **plain** NUL-terminated CP1252 string; and
- a **version-prefixed** string, which consumes a leading version byte before the body. The version
  byte must be zero; if it is non-zero the string is empty and *only* that byte is consumed.

Which one a field uses is per-field, not per-type — a single type can use both, and one has been
observed using the version-prefixed form for its name fields and the plain form for its description
fields. There is no way to tell them apart from the data alone, because a plain reader pointed at a
version-prefixed field simply reads a leading NUL as an empty string and then runs one byte behind
forever.

This single mistake left an entire type **100% unparsed** — every record desynced from its first
field because the type's first opcode is a name. It is invisible without the trailing-byte check
and trivially fixed once seen, so it is the first thing to suspect when a whole type fails at once.

## Client behaviour worth knowing before mirroring it

The client's quest **varbit-requirement "met" check bounds-checks against the varbit requirement
count but then reads the element out of the varp requirement array.** This is a bug in the client,
confirmed at instruction level, and it does not affect decoding at all. It matters only if we
reimplement that check server-side: matching the client means matching the bug, and diverging from
it means diverging from observable game behaviour. Decide deliberately rather than by accident.

## A wrong diagnosis, and why

The interface decoder's crash was initially diagnosed from our own source as a local bounds bug: one
block sizes an array from the first index it reads, and a later block writes a second, larger index
into it. That reasoning was sound and the bug is real — the client has no bounds check there either,
so a crafted file would overflow it — **but it was not the cause of the crash.** The client reads at
most two entries in that block regardless of the count, confirmed at the instruction level by an
unconditional jump with no back-edge, so our shape was already correct on the wire.

The out-of-range index was garbage arriving from a desync that began in an *earlier* field. Reading
our own code told us how it crashed; only the binary told us why.

The general lesson: **a plausible bug found by reading our source is a hypothesis, not a diagnosis.**
A desync surfaces as an exception at some arbitrary later field, so the crash site is evidence about
where the record went wrong, not about which field is misread.

## ⛔ The sweep only measures what it is pointed at

A third failure mode, distinct from the two below and the most dangerous because it looks like
success. The map index turned out to hold **nine** files per archive where the decoder only ever
requested five. Every requested file decoded to exact end-of-buffer, so the sweep reported the index
completely clean — while the largest file in the index, the only one present in *every* archive, was
never read at all.

A decoder cannot report a field it does not know exists. Before trusting a clean result for an
index, **enumerate what the archives actually contain** (`cache.files(index, archive)`) and compare
that against what the decoder requests. Byte-level correctness within the files you read says
nothing about the files you skipped.

## ⛔ An open question about collision

Terrain flags feeding server-side collision are currently read from one of the tile files. If the
client genuinely reads the larger undecoded file for terrain instead — as the binary evidence
suggests, since nothing in the image decodes the grid shape those tile files use — then the server
may be clipping against data the client no longer honours. **Settle this before doing any other
work in this area**; it is a correctness question about live gameplay, not a decoding nicety.

## ⛔ Silent decoders report nothing, which is not the same as clean

A fourth failure mode, and the quietest. Several decoders never called into the decode report at
all — they overrode the read loop entirely and so were **invisible** to the sweep rather than clean
in it. Absence of a line in the results looked exactly like a pass.

Wiring them up immediately exposed long-standing gaps: one type leaves a fixed-size tail unread on
**every single record**, another falls short on 255 of 261, another leaves bytes at the end of its
single bulk record. None of these were regressions; all had simply never been measured.

When auditing coverage, check that every decoder **appears** in the sweep's accounting, not merely
that it is absent from the problem list.

## ⛔ The sweep under-reports without an unknown-opcode arm

An unrecognised opcode **consumes nothing**. In a decoder that has no explicit unknown-opcode arm,
the `when` simply falls through, the loop reads the next payload byte as an opcode, and the record
misparses — but it frequently still terminates on some later zero byte having consumed every byte.
It then reports **zero trailing bytes and zero failures while being completely wrong.**

This is not hypothetical. One type reported a handful of trailing-byte records; the real figure was
**nine hundred** mishandled records — one unknown opcode and one unknown parameter type, neither of
which cost a single trailing byte.

So: **a decoder without an explicit unknown-opcode arm cannot be trusted by the sweep.** "Clean"
there means "did not happen to end short", not "understood". Give every opcode-loop decoder an
explicit unknown arm; until it has one, treat its clean result as unverified.

## The same discipline applies to offset tables

Two engine offset fields were found to be named for behaviour they do not have — one flagged as a
"removed" marker that is actually the **hidden** flag written by the clientscript hide operation,
and a pair named as position inputs that are really **size** inputs, fed through the anchor formula
into the component's width and height. The position inputs are a different pair entirely.

Both had been carried forward across builds unchallenged. The tell was available the whole time:
the table's own notes described one mode as "centre / right-anchor" (unmistakably position) and the
other as "fraction-of-parent-width" (unmistakably size), and the fields were wired to the wrong one.

**A renamed offset is not cosmetic.** Correcting the first one exposed a live semantic question:
the engine's component lookup returns *nothing* when that flag is set, so under the correct reading
it treats every hidden component as non-existent. The rename makes that visible for a decision
rather than fixing it silently — changing lookup behaviour could break scripts that depend on it.

## Naming discipline: a marker is not a failure, a guess is

Field names carried over from a deobfuscated 2012 client — the `anIntNNNN` / `aBooleanNNNN` family —
were removed wholesale. Those numbers were that client's *field offsets*; they are not Jagex names,
they mean nothing in the current build, and their false precision reads as knowledge we do not have.

Of the 67 removed, **one** could be named from evidence and **66** became honest markers. That ratio
is the finding, not a shortfall: **recovering an opcode table is not the same as recovering the
semantics.** For the two largest types the client's own decompiled structs label those same fields
unknown too. Where the binary does not say what a field means, neither do we.

Rules that fell out of it:

- **Key a marker to the opcode that writes it**, not to a sequence counter. The opcode is the one
  fact that *is* evidenced, and the name then survives field reordering.
- **A wrong name is worse than an unknown one.** Three fields were found to be actively mislabelled
  and were corrected against four independent corroborations each — two lighting fields that were
  named for the wrong property, and one that was named for a modifier it does not apply.
- **Do not inherit a label that has no provenance.** Two structs carried the same descriptive label
  applied by one analyst in two places; that is one opinion, not two findings, and both stayed
  unknown.

### Verifying a pure-rename change

To prove a rename changed no behaviour, **mechanically invert every rename on a copy and diff
against the original** — byte-identical files prove the edit was pure identifier substitution.
That is stronger than reading the diff, and much stronger than re-running a test suite that would
pass either way.

## Limits of the trailing-byte check

A clean parse proves the decoder consumed the record. It does **not** prove the decoder was
pointed at the right data. A decoder whose opcode table happens to fit a different type's records
will report a perfect parse while producing entirely wrong values — this has actually occurred in
this codebase. Guard against it with the two-independent-sources rule above, and by sanity-checking
decoded string fields against what the type is supposed to contain.

## Running the check

`:tools:decodeCheck` sweeps every constructible decoder over a cache with telemetry enabled and
prints one line per decoder that failed to fully consume its records. A clean run prints nothing
but the summary. Run it after every cache update: a decoder that gains a new unknown opcode is a
config type that gained a field, and its definitions are silently mis-decoded from that field on.

## Telemetry

The decode report is **opt-in and off by default** — the running server pays nothing for it. It
attaches to a decoder instance and works for both the eager whole-index load and the lazy per-id
path. See `DecodeReport` in `:core` for the query surface; `:tools:cacheSnapshot` wires it up and
writes the results into the snapshot.

## Recently closed

**The sweep is clean: every decoder now consumes every record completely.** The three that had held
out were not what their symptom suggested. Two were container-level misreadings rather than missing
tails: in the db-table-index the **file id is the column id**, so reading only file 0 meant every
column but the first was silently never decoded, and the fixed header skip only appeared to work
because it happened to equal the length of a one-column, one-value record. The material index holds a
single group with one file per material and no bulk table at all, so the decoder was reading one
material's record as if it were a table of them — the "one definition" the sweep reported was one
misread material, and the true count is four orders of magnitude larger. Both had passed unnoticed
because a wrong container still yields *a* parse.

The font decoder was a faithful port of the previous format, which is a different failure again: not
a gap, but correct code for the wrong revision. ⚠️ Its client routine was **not located** in this
build — the old build inlined it in the config provider's main loop, and that vtable no longer
carries it. The layout is proven from the data and the field meanings are inference, so they are
named as inference. That distinction is the point: a clean sweep proves we consume every byte, never
that we have understood what the bytes mean.

One carried-forward assumption worth remembering: a value type the previous build treated as a
4-byte coordinate is 13 bytes here, under the same tag. Nothing in the record length would have
revealed that — only reading the current binary did.

**The floor types are clean, and the interesting part was not the unknown opcodes.** Both floor
decoders were flagged for opcodes the live cache emits and neither handled. Reading the client's own
decode loops settled it the other way: the client has **no arm** for any of them and consumes zero
bytes, so they were never a missing field and never a desync. Explicit no-op arms closed the report.
The same read paid for itself several times over on the arms we *already* implemented, which is where
the real defects were — one type read a colour the client advances past and discards, two scale reads
were signed where the client reads unsigned, three opcodes were read and thrown away rather than
stored, and a post-decode transform was folding the definition id into an unrelated field with no
reader anywhere depending on the result. Where our representation deliberately differs from the
client's — a colour we keep that it discards, and a scale in our own units — that is now a recorded
choice with its reasoning, not an accident waiting to be "fixed" by the next reader.

**loc, spotanim and seq are now clean** — zero trailing bytes, zero unknown opcodes across every
definition. Closed by recovering the three decode tables from the binary and validating them by
walking every definition of each type to an exact end-of-buffer landing, rather than by inferring
arms from sibling decoders.

**The quest type is fixed** — it went from every one of its records unparsed to all of them exact.
The cause was a single wrong string reader on its first field (see below), but fixing that alone
would only have produced a clean parse of *wrong data*: cross-checking decoded values against live
game data showed several fields were also misnamed, one requirement field was being read and
discarded, and two payloads were being skipped wholesale. Structural correctness came first and
semantic correctness had to be established separately — as always.

**Graphics, quick-chat and interface components are now decoded in full.** Graphics turned out to have
two layouts selected by a **trailing** marker rather than a header — a leading discriminator is
impossible, because the first byte is identical across both layouts for thousands of groups. The
interface component record proved far richer than the old implementation: version-gated branches,
a dozen per-type blocks, a fixed-order script-hook table and several genuine loops, any one of which
desyncs the rest of the record when read short.

Both replaced third-party or legacy partial implementations that were confidently wrong. A raw
graphic decoder living outside the cache library had the right idea and the wrong details in three
places, including assuming a single frame where groups carry up to forty.

**Two fabricated-value defects are also closed.** A set of animation booleans were being written
from opcodes the client writes nothing for — carried-over pre-RS3 semantics — and have been removed
rather than left as plausible-looking fiction. A pair of spotanim scale fields were named for the
wrong axis and stored the raw wire value where the client derives a float; both now report what the
format means.

Neither of those moved the decode report by a single byte, which is the point: **the trailing-byte
check cannot see a field that is fabricated or misnamed, only one that is truncated.** A clean sweep
is necessary but not sufficient. The remaining verification for that class of defect is semantic —
check decoded values against an independent naming source and against plausible ranges.

The derivation check that settled the scale fields is worth reusing: invert the derivation across
every definition in the index and confirm the raw values land where they must. Every scale came back
an exact multiple of 1/128 and every rotation an exact whole number of degrees, across the whole
index. A wrong derivation cannot produce that.

Worth keeping from that pass:

- The loc table's variable-length light-source opcode carries a **leading length field** that the
  client discards. Its observed values are exactly `1 + stride*N` for the entry count that follows,
  which independently confirms the record stride from the data rather than from consumption
  arithmetic alone. Look for that kind of self-checking structure when validating a recovered table.
- Semantic confirmation beat structural confirmation: the recovered records were cross-read against
  their gameval names, and a firepit decoded to an orange light at high intensity while every other
  light in the cache is a dim grey. That is what proves a table means what you think, as opposed to
  merely consuming the right number of bytes.
- A second variable-length loc opcode was found in a small number of definitions that had been
  hiding behind the same symptom, because the two never co-occur.

## Open items

Ordered by how much they improve an update report, not by size.

| item | status | needs |
|---|---|---|
| **map index only partly decoded** | five of **nine** files per archive are decoded | Archives in the map index carry files 0–8, not 0–4. The decoder only ever asked for the first five. The largest file — present in **every** archive and the only one that is — is undecoded, and the client appears to read *it* for terrain rather than the tile files we do decode. Two further files are also untouched. See the collision question below. |
| **dormant decoders** | four decoders exist with no call site | wire up or delete. One of them is the only reader for an index whose changes are otherwise invisible. |
| **seven unidentified indices** | populated, unnamed | RE. One sets the ref-table names flag, so its archive name hashes are brute-forceable — the cheapest lead. |
| **config constants pointing at dedicated indices** | latent | several config constants correspond to types the client now loads from their own indices rather than from the config index. Our decoders work today, so the config index evidently still carries copies — but they are not where the client looks, which is a trap on a future update. |

## Taking an entry off this ledger

1. Confirm the format from the **client binary** (ghidra-reverse-engineer). Never infer a field
   layout from our existing Kotlin, and never port one from the outdated reference binary.
2. Implement the decoder in `:core` (cache-library-engineer).
3. Verify with the decode report: zero trailing bytes and zero unknown opcodes across the whole
   index.
4. Cross-check decoded ids against the matching gameval table where one exists.
5. Re-run `:tools:cacheSnapshot` and update this file's status column.
