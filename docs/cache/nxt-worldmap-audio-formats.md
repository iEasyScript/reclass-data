# RS3 NXT world-map and audio/font cache formats

Scope: the cache indices that carry the world-map area data, the audio streams, and the fonts —
every one of them structurally undocumented until now.

Source of truth is the Ghidra DB for the desktop `rs2client`. Per this repository's documentation
standard **no addresses or struct offsets appear here**; what is recorded is the durable part — how
a group is addressed, the payload structure in field order with its read kinds, every conditional
and its selector, and what the client derives from each field. File-format flag bits *are* recorded,
because unlike an address they are part of the format itself.

Evidence is labelled per claim:

* **[client]** — read out of the client's own parser in the Ghidra DB.
* **[cache]** — verified by parsing the served JS5 cache read-only. "Verified across every file"
  means a parser built from the stated model consumed every file in that index to exactly
  end-of-buffer with no slack.

Read-side shorthands (`g1`, `g2`, `g4`, `gSmart1or2`, …) are the ones in the project's buffer-op
table; they map one-to-one onto the `JagExtensions` helpers.

---

## 1. World map — indices 41, 42 and their relationship to 23

### 1.1 Addressing, and the name formula

Indices **41** (`worldmap_area_data`) and **42** (`worldmap_area_coords`) are name-addressed: the
client resolves a group by hashing a string rather than by numeric id. The hash is the standard
Jagex 31-polynomial, read straight out of the client's own unrolled loop: [client]

```
h = 0
for each byte c of the name:
    h = h * 31 + (int8_t)c        # 32-bit wrap, signed byte
nameHash = (int32) h
```

There is **no case folding** — the bytes are hashed exactly as stored.

**The string that is hashed is the map area's internal name, and that name is in the cache.** Index
**23** (`worldmapdata`) archive 0, file *areaId*, begins with two NUL-terminated strings —
`internalName`, then the human-readable display name — ahead of the rest of the area descriptor. So:

```
index-41 group id == index-42 group id == area id == file id within index 23's archives
nameHash(index 41 group g) == nameHash(index 42 group g) == jagexHash(internalName(g))
```

Verified for **all 771 index-41 groups and all 142 index-42 groups**: every stored name hash
reproduces exactly from the internal name, with no collisions. [cache] Worked examples:
`ardougne_underground`, `zanaris`, `troll_stronghold`, `pioneer_cave_full`,
`construction_neighbourhood_basic`.

Consequences a dumper and a repacker both need:

* A dumper can give the index-41/42 directories **real names** by reading index 23 archive 0, file
  *groupId*, and taking the first NUL-terminated string.
* A repacker regenerates the name-hash section from those same strings. If it drops the section the
  world-map lookups fail silently.

**Index 23 is *not* name-addressed.** Its reference table carries no name section at all; it is keyed
by (archive = render layer, file = area id). Only 41 and 42 use name hashes. This corrects the
earlier index catalogue, which listed 23 alongside them.

### 1.2 Group and file shape

* Index 41 — 771 groups, ids contiguous from zero. 629 groups hold one file; **142 hold two**.
* Index 42 — 142 groups, and they are **exactly** the index-41 groups that have two files, with the
  same ids and the same name hashes.
* **Index 41's file 1 is byte-identical to index 42's file 0** for all 142 — verified over every
  byte. [cache] The map-element table is simply stored twice, once inline in the area group and once
  in its own index. A writer must emit both, identically.

So there are two payload kinds in total: the *area data* (index 41 file 0) and the *area
map-element list* (index 41 file 1 == index 42 file 0).

### 1.3 Area map-element list — index 41 file 1 / index 42 file 0

```
g2                       count
count × {
    g4    packedCoord    level = (v >> 28) & 3, x = (v >> 14) & 0x3fff, z = v & 0x3fff
                         all-ones = "no coordinate"
    g2    mapElementId   a map-element config type id
    g1    flag           the client only acts on records whose flag is zero
}
```

The client keeps each record as `{level, x, z, mapElementId, flag}`. `mapElementId` is passed to the
config provider's map-element type getter, which is what makes the field's meaning certain rather
than positional [client]; corroborating this, **all 2726 distinct ids used across the served cache
are valid map-element type ids**. [cache]

Observed ranges [cache]: `count` 1..1689, `level` 0..3, `x` 352..5784, `z` 95..12625,
`mapElementId` 0..5806, `flag` 0..1.

### 1.4 Area data — index 41 file 0

Two id palettes, then a run of map-square / chunk records to the end of the buffer. There is no
record count and no length prefix: the loop runs until the buffer is exhausted.

```
g1                       paletteACount
paletteACount × gSmart1or2   paletteA          floor-underlay config ids
g1                       paletteBCount
paletteBCount × gSmart1or2   paletteB          floor-overlay config ids

repeat until end of buffer:
    g1  tag
    tag == 0:                       whole map square
        g1        mapSquareX
        g1        mapSquareZ
        8 × g1    chunkMask         byte i, bit j -> chunk (sqX*8 + i, sqZ*8 + j) is in the area
        4096 × CELL                 a 64 x 64 tile block, in the client's walk order
    tag != 0:                       one 8 x 8 chunk (only the value 1 occurs in the served cache)
        g1        mapSquareX
        g1        mapSquareZ
        g1        chunkDX           0..7
        g1        chunkDZ           0..7
        g1        value             membership flag, stored as (value != 0)
        64 × CELL                   an 8 x 8 tile block
```

`tag` is the only record selector, and it is a plain presence/shape discriminator, not a count.

**CELL** — one tile. The leading byte is a bitfield and is the sole selector for everything that
follows:

```
g1 f
(f & 0x01) == 0:                     SIMPLE cell
    k = f >> 2                       a 6-bit inline field
    k == 0x3E:      nothing more     blank tile
    k == 0x3F:      gSmart1or2 id    escape: an id the palette cannot address
    otherwise:      k is a 1-BASED index into (paletteA ++ paletteB); 0 means "none"
    if f & 0x02:    gSmart1or2 idU   a further floor-underlay id
(f & 0x01) != 0:                     LAYERED cell
    n = ((f >> 1) & 3) + 1           1..4 layers; a layer's ordinal is its plane
    repeat n times:
        gSmart1or2  idU              floor-underlay id
        if f & 0x08:
            gSmart1or2  idO          floor-overlay id
            g1          packed       one packed byte, decomposition not established
        if f & 0x10:
            g1  locCount             0..3
            repeat locCount times:
                gSmart2or4  locId    a loc config type id
                g1          shapeRot shape = b & 0x3f, rotation = b >> 6
```

Flag-bit summary: `0x01` simple-vs-layered; `0x02` extra underlay id (simple form only); `0x06`
layer count (layered form only); `0x08` an overlay id plus one packed byte per layer; `0x10` a loc
list per layer; `0xFC` the 6-bit inline field (simple form only).

**Writer caveat.** The client reads the two "extra id" fields with the *signed* smart while the
served data is written with the *unsigned* smart, so read signed they come back as large negatives.
The framing is byte-identical either way — write them as plain `gSmart1or2`. [client] [cache]

**What the client actually derives.** Only the `0x10` loc sub-records are retained. Each becomes
`{layer, tileX, tileZ, locId, shapeRot}` and is drained later: the loc id is resolved through the loc
type list, the type's varbit/varp multi-type transform is followed, the resulting type's map-element
id is resolved through the map-element type list, and `shape`/`rotation` are unpacked to emit the
wall and door line segments and the map-scene marks drawn on the world map. **Everything else in the
cell stream — both palettes and every underlay/overlay id — is parsed for framing only and
discarded by this build.** The visible map imagery comes from the pre-rendered images in index 23,
not from these ids. [client]

### 1.5 Why the palette reading is certain, not a guess

The id-space of every field was checked against the config type lists in the same cache [cache]:

| Field | distinct values | max | member of underlay ids | member of overlay ids |
|-------|-----------------|-----|------------------------|-----------------------|
| `paletteA` | 442 | 724 | yes | no |
| `paletteB` | 312 | 581 | no | yes |
| layered `idU` | 475 | 724 | yes | no |
| escape id | 331 | 717 | yes | no |
| simple extra id | 402 | 720 | yes | no |
| layered `idO` | 375 | 590 | no | yes |
| `locId` | 12797 | 139158 | — (all are valid loc ids) | — |

And the palette-index reading is settled by two facts. Across **9,271,760** inline simple cells the
6-bit field never once exceeds `paletteACount + paletteBCount`; and in 770 of the 771 files every
escape/extra/layered id is already a palette member. The single exception is the one giant surface
area, which is also the only file whose two palettes are both at their maximum size — its combined
palette overruns what a 6-bit index can reach, which is precisely what the escape form exists for.

### 1.6 Validation

| Payload | Files | Consumed to exactly end-of-buffer | Failures |
|---------|-------|-----------------------------------|----------|
| index 41 file 0 — area data | 771 | 771 | 0 |
| index 41 file 1 — map elements | 142 | 142 | 0 |
| index 42 file 0 — map elements | 142 | 142 | 0 |

Zero slack and zero overruns anywhere. Consumed in total: 3419 whole-map-square records, 11,028
single-chunk records, **14,710,016 cells** (3,651,606 blank, 9,549,933 simple, 1,508,477 layered),
987,299 loc sub-records and 5452 map-element coordinate records. Name hashes: 771/771 and 142/142
reproduce from the internal names. [cache]

Observed ranges [cache]: palette counts 0..62 each; `paletteA` 1..724; `paletteB` 1..581; `tag` 0..1;
`mapSquareX` 0..92; `mapSquareZ` 0..197; cell flag byte 0..254 across 141 distinct values (commonest
are the plain layered and blank forms); inline 6-bit field 0..61; escape id 1..717; simple extra id
0..720; layer count 1..4; layered underlay id 0..724; layered overlay id 0..590; the packed byte
0..203 across 45 distinct values; `locCount` 0..3; `locId` 9..139158.

---

## 2. Audio — indices 14 (`vorbis`) and 40 (`audio_streams`)

### 2.1 Correcting two long-standing beliefs

Both need saying before the format, because both have shaped earlier work:

* **Index 40 is not "raw Ogg Vorbis".** It uses the **same `JAGA` container as index 14**. Only the
  stream *headers* carry the magic — 2657 of its groups do — and the remaining 83,270 groups are the
  bare Ogg chunks those headers point at. Reading the index as "every group is an Ogg file" happens
  to work for 97% of the groups and silently mis-reads the other 3%. [cache]
* **There is no shared setup header, and index 14's group 0 is not one.** Group 0 of index 14 and
  group 0 of index 40 are the *same* nine-byte placeholder container: compression "none", a declared
  length of four, and the four ASCII bytes `OggS` as the payload. Both reference tables carry the
  same CRC for it, and that CRC is exactly the CRC32 of those nine bytes. Index 14's entry declares a
  zero size pair and a zero uncompressed CRC — generator noise — which is why a downloader never
  fetches it. **Nothing is shared between chunks or between groups: every chunk carries its own
  identification, comment and setup headers.** [cache]

### 2.2 Group shape

Every group in both indices is single-file, so the group payload *is* the file — no chunk table, no
name-hash section. Reference tables are format 7 with the sizes + uncompressed-CRC flags and no
names. Index 14 holds ~60k groups with ids contiguous from zero; index 40 ~86k, likewise
contiguous. Container compression is a free mix of none, gzip and bzip2 in both. [cache]

### 2.3 The `JAGA` container

All integers big-endian. Fields in order:

| Kind | Name | Meaning |
|------|------|---------|
| `char[4]` | magic | `JAGA`. The client compares the four bytes **individually**, so there is no 32-bit magic constant in the code to search for. A mismatch aborts the load. [client] |
| `g4` | version | **Never read.** Both of the client's branches seek straight past it. Zero in every group in the served cache. [client] [cache] |
| `g4` | sampleCount | total PCM frames of the whole logical stream |
| `g4` | sampleRate | Hz — 22050, 44100 or 32000 in the served cache |
| `g4` | channels | 1 or 2 |
| `g4` | chunkCount | 1..32 in index 14, 1..293 in index 40 |
| `chunkCount × { g4, g4 }` | chunk table | per chunk: byte length, then **chunk group id** |
| bytes | inline chunk data | the chunks whose group id is zero, concatenated in table order |

**The chunk-group-id column is the field earlier descriptions were missing.** It is the whole reason
the two indices differ:

* **zero** — the chunk is stored **inline**, appended after the table in table order;
* **non-zero** — the chunk *is* group *n* of the **same index**, and that group's entire payload is
  the chunk's bytes. Its declared byte length equals that group's payload length exactly.

In index 14 every entry is zero — all 63,012 chunks are inline. In index 40 the first entry is always
zero (the inline head of the stream) and the rest always name sibling groups. So a group's total size
is always exactly `header + 8 × chunkCount + Σ(inline chunk lengths)`. [cache]

### 2.4 What a chunk is

Each chunk is a **complete, independent, self-contained Ogg Vorbis physical bitstream** — not a
fragment, and not a packet stream needing Ogg reconstruction:

* it opens with a beginning-of-stream page and closes with an end-of-stream page, page sequence
  numbers run contiguously from zero, and the bitstream serial number is always zero;
* its first logical packet is always the Vorbis identification header, followed by the comment and
  setup headers;
* the identification header's channel count and sample rate always agree with the `JAGA` header's;
* comment headers carry no user comments and a stock libVorbis vendor string.

Verified across **all 148,938 chunks** of both indices: none fails any of those. [cache]

Non-final chunks are cut at a fixed PCM budget rather than a fixed byte size — roughly 600 KiB of
16-bit PCM per chunk in index 14 and 675 KiB in index 40, i.e. the granule count halves when the
stream is stereo. The final chunk is the remainder.

`sampleCount` equals the sum of the chunks' end granules for all but a handful of streams, and every
exception is a 44100 Hz stream whose header retained a 48 kHz source length (the ratio is exactly
48000/44100). That is an encoder artefact, not a format feature — a writer should emit the true
total. [cache]

### 2.5 How the client picks between the two indices

The sound engine holds both archive handles side by side in one object and keys its resource cache
by the sound id combined with a one-bit **kind** flag. The container walker branches on that flag,
and the two branches walk the *same* container differently — which is what pins the flag's meaning:
[client]

* **kind clear → index 14.** Reads the header, then **skips the entire chunk table** (safe, because
  every chunk in that index is inline) and hands the whole remaining buffer to the decoder in one
  shot.
* **kind set → index 40.** On the first step it reads only the chunk count, allocates an id array,
  and walks the table **skipping the length and keeping the group id** — i.e. it harvests exactly the
  chunk-group-id column. Chunk zero is the inline remainder of this group; the rest are fetched as
  their own groups as playback advances, and the total-length queries extrapolate from the chunks
  loaded so far.

So the flag is a **residency** flag, not a "music versus effect" flag: clear means "the whole sound
is one cache group, decode it now", set means "the sound is a chunk-addressed stream, fetch chunk
groups as you go". The one-shot sound and speech paths pass it clear; the preload and looping-track
paths pass it set.

### 2.6 Decoding

The client does **not** link libogg/libvorbis. A dedicated worker thread receives one message per
chunk, and each message begins with a **one-byte framing byte** that is not part of the Ogg data:
one value means "start a new logical stream" (tear down the current decoder and open a fresh
push-mode decoder over the rest of the message), another means "continue the current stream"
(re-queue from the second byte, no reset), and anything else is ignored. The decoder entry point
itself is a single large function that references the `vorbis` literal and takes
`(data, length, out consumed, out error)` — consistent with a push-mode `stb_vorbis`, recorded in the
DB as a labelled hypothesis rather than a rename. [client]

The practical consequence for a server or a repacker: the cache already stores real Ogg pages, so
nothing needs to synthesise page headers.

### 2.7 Validation

| Index | Groups in the local cache | Parsed | Consumed to exactly end-of-buffer | Failures |
|-------|---------------------------|--------|-----------------------------------|----------|
| 14 | 60,064 | 60,064 | 60,064 | 0 |
| 40 | 85,927 | 85,927 | 85,927 | 0 |

Index 40 breaks down as 1 placeholder, 2657 `JAGA` stream headers and 83,269 bare-Ogg chunk groups.
**Every one of those 83,269 chunk groups is referenced by exactly one stream header, with a
byte-exact declared length — zero orphans and zero double-references.** [cache]

---

## 3. Index 59 — `fonts`

Reference table: format 7, sizes + uncompressed CRC, **no names**, five groups, all single-file,
ordinary JS5 containers with a mix of gzip and bzip2. [cache]

**The group payload is a bare `sfnt` file — there is no Jagex wrapper of any kind.** No magic, no
length prefix, no trailer: the payload begins at the sfnt version tag and ends exactly at the last
table's four-byte-padded end. [cache]

Three groups are TrueType-flavoured and two are OpenType/CFF-flavoured. Tables always present are the
core sfnt set — `head`, `hhea`, `maxp`, `cmap`, `hmtx`, `name`, `post`, `OS/2` — plus `GPOS` and
`GSUB`; TrueType flavours add `glyf` and `loca`, CFF flavours add `CFF `. `GDEF` is present on three
of the five, so the earlier catalogue note that `GDEF` is always present is not right. The faces are
a Noto Sans family (regular, bold, semibold) and a Cinzel family (regular, bold).

**The rasteriser is FreeType, not an in-house one.** The binary carries FreeType's environment
property string and its auxiliary-driver literals, and contains no custom sfnt table parser.
[client]

Validation: 5 groups, 5 parsed, 5 consumed to exactly end-of-buffer with a self-consistent sfnt
table directory (the binary-search fields all correct, no table starting inside the directory, no
table overrunning the payload), 0 failures. [cache]

---

## 4. Index 58 — `font_glyph_metrics`

Documented here because no other document covers it. Reference table: format 7, **names** + sizes +
uncompressed CRC, 225 groups with sparse ids, all single-file. Groups are addressed by name hash —
the same 31-polynomial as §1.1. [cache]

Index 58 is the **dispatch table for font handles**. Every record is a *fixed-size* block whose shape
is chosen by a leading version byte, and in the served cache each record is exactly one of two sizes
— there is no length field and no variable part.

### 4.1 Scalable-font binding (the majority shape, 165 records)

Fields in order:

| Size | Kind | Name | Meaning |
|------|------|------|---------|
| 1 | `g1` | version | selects this shape |
| 4 | `g4` | fontFileId | an index-**59** group id |
| 1 | `g1` | pixelSize | 9..70 in the served cache |

So the record says *"this font handle is index-59 face N, rendered by FreeType at S pixels"*. Only
the three Noto faces are ever referenced; the Cinzel faces are not reachable from index 58.

The field split is not positional guesswork. Solving each record's own name hash for the prefix,
under the assumption that the name is a role prefix followed by the decimal pixel size, yields **one
identical prefix hash across all 41 records that share a font-file id of 1**. A 41-way agreement on a
32-bit hash settles both the boundary between the two fields and the naming convention. The prefix
*strings* themselves were not recovered — nothing in the binary spells them out. [cache]

### 4.2 Legacy bitmap-font metrics (60 records)

Fields in order:

| Size | Kind | Name | Meaning / observed |
|------|------|------|--------------------|
| 1 | `g1` | version | selects this shape |
| 5 | big-endian integer | fontMetricsGroupId | a group id in index **13** (`fontmetrics`); its top byte is always zero |
| 256 | `g1[256]` | per-character table A | indexed by character code; 0..108 |
| 256 | `g1[256]` | per-character table B | 0..112, same non-zero mask as A |
| 256 | `g1[256]` | per-character table C | 0..114, a *different* non-zero mask |
| 2 | `g2` | per-font scalar 1 | 73..966 |
| 2 | `g2` | per-font scalar 2 | 53..1036 |
| 512 | `g2[256]` | per-character table D | 0..944, same non-zero mask as A and B |
| 512 | `g2[256]` | per-character table E | 0..970, same non-zero mask as A and B |
| 6 | `g1[6]` | trailer | last byte is always 1 or 2 |

In all five tables the first 32 entries are always zero — ASCII control characters have no glyph —
which is what proves they are indexed by **character code** and not by glyph index.

**The index-13 link is proved, not inferred.** Index 13 holds exactly 60 groups; there are exactly 60
records of this shape; every record's five-byte id hits an existing index-13 group whose reference
table name hash is **byte-for-byte identical** to the index-58 group's own name hash — 60 of 60, no
mismatches. The cross-check also confirms §4.1's field split: one scalable-font record's id field
coincidentally equals a valid index-13 id, but its name hash does not match, so that field is *not*
an index-13 reference. [cache]

So the two shapes are: a legacy bitmap font, whose glyph imagery lives in index 13 and whose
per-character metrics live here; and a modern scalable font, which is just a FreeType face plus a
size. The client-side parser for the bitmap block was **not** located, so tables A–E and the trailer
are reported as measured structure only, with positional names — do not invent meanings for them.

Validation: 225 records, 225 parsed, 225 exactly the size their shape requires with every stated
invariant holding, 0 failures. [cache]

---

## 5. Consolidated validation

| Index / payload | Files | Parsed | Consumed to exactly end-of-buffer | Failures |
|-----------------|-------|--------|-----------------------------------|----------|
| 41 file 0 — area data | 771 | 771 | 771 | 0 |
| 41 file 1 — area map elements | 142 | 142 | 142 | 0 |
| 42 file 0 — area map elements | 142 | 142 | 142 | 0 |
| 14 — `JAGA` audio | 60,064 | 60,064 | 60,064 | 0 |
| 40 — `JAGA` audio + Ogg chunks | 85,927 | 85,927 | 85,927 | 0 |
| 58 — font handles | 225 | 225 | 225 | 0 |
| 59 — sfnt fonts | 5 | 5 | 5 | 0 |

Cross-index integrity, all exact: 771/771 and 142/142 name hashes reproduce from the index-23
internal names; index 41's second file equals index 42's file byte-for-byte for all 142 groups;
83,269/83,269 index-40 chunk groups referenced exactly once by a stream header; 60/60 index-58 bitmap
records matched to an index-13 group with an identical name hash; 148,938/148,938 Ogg chunks
self-describing and consistent with their `JAGA` header.

All cache reads throughout were read-only (`immutable=1` URIs); no cache file was opened for writing
and no journal sidecar was created.
