# RS3 NXT config index — the ten previously unidentified groups

Scope: the config index's ten groups that had no identified type. Two of them are live and are
documented here field by field; the other eight are proven dead **in the client and in the data**.

Source of truth is the Ghidra DB for the desktop `rs2client`. Per this repository's documentation
standard, **no addresses, struct offsets or numeric opcode keys appear here** — those are per-build
and live in the Ghidra DB, on a comment attached to each type's `DecodeType`. What is recorded here
is the part that survives a rebuild: how a group is bound to a type, the record framing, and each
type's *ordered set of entries* with its payload kinds, scale factors, block structure and meaning.

Evidence is labelled per claim:

* **[client]** — read out of the client's own parser in the Ghidra DB.
* **[cache]** — verified by parsing the served JS5 cache read-only.

---

## 1. How the client binds a config group to a type

Three stages, all in the config provider. [client]

1. **Group-id registry.** A static initialiser fills one table entry per config-type ordinal with
   `{ group id, category tag, spare }`. The group id always equals the ordinal itself, with a
   sentinel value marking an ordinal that has no group. The category tag says whether the type is
   read out of the config index or has been promoted to a JS5 index of its own (the promoted types
   keep the group id their legacy config-index archive had). **Registration here does not mean the
   client reads the group** — it only reserves the ordinal.
2. **Type-list construction.** A second pass builds one type list per *consumed* type. Each list is
   constructed from a per-group format value; a zero value means "group absent" and the list is not
   built at all. A group that is registered but has no branch in this pass is never read.
3. **Storage strategy.** Every list constructor then dispatches on that same format value to one of
   three provider objects — a fully cached hash-map provider, an LRU-evicting provider, and an
   uncached provider. Any other value leaves the list with no provider. This choice affects caching
   only, never the bytes.

A type instance is produced from a pooled allocator that stamps the type's vtable, and the group's
file bytes are then run through the type's `DecodeType`.

### Record framing — shared by every config type

One config **file** is one record. The shared record driver is a single loop: [client]

```
loop:
    op = read 1 byte
    if op == 0: record ends, success
    result = type.DecodeType(packet, op)
    if result == failure: record ends, failure
```

There is **no length prefix and no bounds check**. The driver never validates that the payload a
given entry consumed stayed inside the buffer; a `DecodeType` arm that reads nothing simply leaves
the cursor where it was and the next byte is taken as the next opcode.

Two different behaviours for an unrecognised key exist and they matter to a writer:

* Most types (including the group-31 type below) return the **failure** sentinel, which aborts the
  record.
* Some types (including the group-76 type below) fall through their dispatch, consume **nothing**
  and return **success** — the driver then reads the *next* byte as an opcode. Such a type cannot
  report a malformed record; it silently desynchronises instead. A repacker must therefore never
  emit a key the target build does not implement.

---

## 2. The ten groups

| Group | Status in this build | Type |
|-------|---------------------|------|
| 2  | **dead** — registered, never read | none |
| 7  | **dead** — registered, never read | none |
| 18 | **dead** — registered, never read | none |
| 31 | live | `jag::game::EffectAnimType` (§4) |
| 42 | **dead** — registered, never read | none |
| 48 | **dead** — registered, never read | none |
| 49 | **dead** — registered, never read | none |
| 70 | **dead** — registered, never read | none |
| 73 | **dead** — ordinal registered with the "no group" sentinel | none |
| 76 | live | positional name `ConfigGroup76Type` (§5) — a water-surface shading preset |

### Naming provenance — read before quoting a name

Neither the stripped target nor the unstripped reference binary contains a config-type name table,
and the target carries no RTTI for these classes. **`EffectAnimType` and `ConfigGroup76Type` are
both names assigned by reverse engineering, not attested Jagex identifiers.** `EffectAnimType` was
assigned by earlier analysis in this DB and is kept for continuity; `ConfigGroup76Type` is
deliberately positional so that it cannot be mistaken for a real name. Do not propagate either as
official.

---

## 3. The eight dead groups

Two independent lines of evidence, and they agree.

**[client]** For groups 2, 7, 18, 42, 48, 49 and 70, the group-id registry entry is *written* by the
static initialiser and *read nowhere else in the binary*. Group 73's ordinal is registered with the
"no group" sentinel, so it does not even have a group id. None of the eight gets a type list, and no
code path anywhere parses their bytes.

**[cache]** In the served cache every file of all eight groups is exactly **one byte, the record
terminator** — an empty record, no entries at all:

| Group | Files | All files a bare terminator |
|-------|-------|------------------------------|
| 2  | 747  | yes |
| 7  | 351  | yes |
| 18 | 2889 | yes |
| 42 | 1026 | yes |
| 48 | 20   | yes |
| 49 | 2    | yes |
| 70 | 367  | yes |
| 73 | 46   | yes |

This was cross-checked against the raw cache rather than only against an unpacked tree: for each of
these groups the container's own declared uncompressed length equals exactly
`fileCount + 4*fileCount + 1` — one payload byte per file, the four-byte-per-file chunk delta table,
and the single chunk-count byte. There is no room in the group for anything else.

So there is no field structure to recover for these eight, from either source: they are id-space
placeholders that the content pipeline still emits a stub record for. A codec should round-trip them
as empty records and must not invent a schema. Note this is a statement about *this* build and *this*
served cache — a group that is empty and unread today can be revived by a future update, and the
right response then is to re-derive it, not to reuse a guess.

---

## 4. Group 31 — `jag::game::EffectAnimType`

**Binding [client]:** ordinal 31 is registered as a plain config-index group; the provider builds its
list, whose version-1 provider allocates instances that carry this type's vtable, whose `DecodeType`
is the one documented in the DB.

Opcode-keyed record, 13 entries, no conditional blocks and no nesting. Ordered by key; the numeric
keys are in the Ghidra DB.

| # | Payload | Meaning |
|---|---------|---------|
| 1  | `g1`   | small mode/selector — only 0..3 occur [cache] |
| 2  | `g2`   | angle in 1/4096-turn units — only quarter- and half-turn values occur [cache] |
| 3  | `g2`   | u16 magnitude |
| 4  | `g2s`  | signed i16 magnitude |
| 5  | `gFloat` | float A |
| 6  | `gFloat` | float B |
| 7  | `gFloat` | float C |
| 8  | `gFloat` | float D |
| 9  | *(none)* | flag; the key itself is the value, no payload bytes |
| 10 | `g4`   | u32 A |
| 11 | `g4`   | u32 B |
| 12 | `gFloat` | float E |
| 13 | `gFloat` | float F |

Any other key aborts the record with the failure sentinel.

Two record shapes occur in the served cache and they are strictly disjoint: 35 of the 37 records
carry only entries 1–4 (one of those carries entry 1 alone), and the remaining 2 carry only entries
8–13. Entries 5, 6 and 7 never occur. The type is therefore a union of two variants discriminated by
which entries are present, not by a version field. [cache]

---

## 5. Group 76 — water-surface shading preset (`ConfigGroup76Type`)

**Binding [client]:** ordinal 76 is registered as a plain config-index group; the provider builds its
list, the version-1 provider allocates instances through a pooled allocator that runs the type's
constructor (which pre-seeds a large block of float defaults) and stamps its vtable.

**What it is [cache].** The identification is from the material ids the records carry, resolved
through the gameval material dictionary. Every one of the 40 records names materials from the water
set:

* the shore/edge entry is the `html5_water_edge` material in **all 40** records;
* the mask entry is `html5_water_mask` wherever present;
* two entries always carry a **paired normal-map set** — `ocean_a`/`ocean_b`,
  `ocean_foam_a`/`ocean_foam_b`, `ocean_diffuse_a`/`ocean_diffuse_b`, `river_a`/`river_b`,
  `pool_a`/`pool_b`, or the `test_b` normal;
* where the ocean-diffuse normals are used, two further entries carry the matching
  `ocean_diffuse_a`/`ocean_diffuse_b` **diffuse** materials.

This is a water *surface shading* preset and is a different thing from the config type already known
as `WaterType` (group 77), which stores smart-encoded id sets with per-id weights — i.e. which tiles
count as water — rather than how water is shaded.

### Record structure

An opcode-keyed list again, but much larger and with one repeating block structure. Scale factors
below are applied by the client at decode time, so a writer must pre-multiply by the inverse.

**Scalar entries** — 60 keys outside the repeating block, plus the block's 48, for 108 in all.
Payload kinds used, with what the client does with them:

| Payload | Client transform | Entries of this shape |
|---------|------------------|-----------------------|
| `g1`    | stored as a bool / raw byte | 3 |
| `g1`    | `× 1/32` into a float | 2 |
| `g1`    | `× 1/100` into a float | 1 |
| `g2`    | stored raw (ids, counts, magnitudes) | 16 |
| `g2`    | `× 1/256` into a float | 8 |
| `g2`    | widened to float unscaled | 1 |
| `g2s`   | signed, stored raw | 1 |
| `g3`    | packed RGB24 | 1 |
| `g4`    | stored raw | 2 |
| `g4`    | unpacked as a colour: the **top three bytes** become R, G, B, each `÷ 255`; the low byte is **ignored** | 2 |
| `gFloat`| stored as-is | 19 |
| `g2` ×2 | a pair | 1 |
| `g2` ×3 | a triple, each `× 1/256` | 1 |
| `gFloat` ×2 | a pair | 1 |
| `gFloat` ×3 | a triple | 1 |

**The material-id entries** (all `g2`, stored raw) are: shore/edge material; mask material;
normal-map layer A; normal-map layer B; diffuse layer A; diffuse layer B; and one further id entry
that never occurs in the served cache. Each of the two normal-map layers has an adjacent
`g2 × 1/256` scalar of its own — a per-layer scroll/scale term.

**One entry is read and thrown away.** A `gFloat` entry consumes its four bytes and stores nothing.
It does occur in the served data, so a byte-exact writer must still emit it.

**The repeating block.** A contiguous run of keys forms **six identical sub-records** of eight
entries each, laid out consecutively in the type. Sub-record entries, in key order:

| # | Payload | Note |
|---|---------|------|
| 1 | `g1`     | enable flag for this sub-record |
| 2 | `gFloat` | scalar |
| 3 | `gFloat` | scalar |
| 4 | `gFloat` | scalar |
| 5 | `gFloat` ×2 | pair |
| 6 | `gFloat` ×2 | pair |
| 7 | `gFloat` | scalar |
| 8 | `gFloat` | scalar |

Sub-record *n*'s keys are the *n*-th consecutive run of eight; that is the only "conditional" in the
type — there is no selector byte anywhere, presence of a key is the only condition, and every entry
is independent. In the served cache sub-records 0, 1, 3 and 4 are populated and 2 and 5 only ever
appear with their enable flag clear. [cache]

**Unknown keys are silently ignored** (see §1) — this decoder consumes nothing and continues, so a
stray byte desynchronises the whole record without any error.

---

## 6. Validation

A parser built from the models above was run over **every file of all ten groups** in the served
cache and required to finish exactly on the record terminator with zero trailing bytes.

| Group | Files | Parsed | Ended exactly on the terminator | Failures |
|-------|-------|--------|--------------------------------|----------|
| 31 | 37 | 37 | 37 | 0 |
| 76 | 40 | 40 | 40 | 0 |
| 2, 7, 18, 42, 48, 49, 70, 73 | 5448 | 5448 | 5448 (all empty records) | 0 |

Total 5525 files, zero slack, zero failures. [cache]
