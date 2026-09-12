# MAPSV2 — JS5 index 5 map data

Byte-level, round-trippable specification of every file slot in a MAPSV2 archive.

Everything below was established against the 949-5 `rs2client` decoders in Ghidra and then
**validated by re-implementing each grammar and replaying it over the whole shipped index**: a
conforming reader consumes every file to EOF with zero bytes left over. Where a slot has no
decoder in the client at all, that is stated explicitly and the grammar's provenance is the data.

---

## 1. Archive addressing

An archive holds one map square. The archive id encodes the region directly:

```
archiveId = regionX | (regionY << 7)
```

The index's reference table carries **no names and no name hashes** — its flags are lengths and
uncompressed checksums only — so the region cannot be recovered any other way. Region ids are
therefore dense in `regionX` and sparse in `regionY`.

## 2. Encryption

**MAPSV2 is not XTEA encrypted.** Every container in the index decompresses with no key. There is
no key negotiation for map data anywhere in the client, and no decode path takes a key argument.
(The legacy pre-NXT map-archive cipher does not apply to this index.)

## 3. File slots

Nine slots exist. Which subset an archive carries is fixed by a small number of combinations:

| slots present | archives |
|---|---|
| 5 only (and empty) | 3502 |
| 0, 1, 3, 4, 5, 6, 7, 8 | 3302 |
| 0, 3, 5, 6, 7, 8 | 1826 |
| 0, 1, 2, 3, 4, 5, 6, 7, 8 | 41 |
| 0, 2, 3, 5, 6, 7, 8 | 4 |

Slot 5 is the only slot present in **every** archive; in the 3502 archives that carry nothing else
it is zero bytes long. Slots 0/3/5/6/7/8 always appear together and always non-empty. Slots 1 and 4
always appear together. Slot 2 is rare.

| slot | contents | read by the 949-5 client |
|---|---|---|
| 0 | locations (scenery placement), primary layer | yes |
| 1 | locations, secondary layer — identical grammar to slot 0 | yes |
| 2 | NPC spawns | **no** |
| 3 | legacy terrain tiles, four levels, plus an environment tail | **no** |
| 4 | legacy terrain tiles, one level (the secondary layer) | **no** |
| 5 | terrain grid (the modern replacement for 3 and 4) | yes |
| 6 | environment / atmosphere record | yes |
| 7 | point lights | yes |
| 8 | placed oriented patches | yes |

### What the client actually requests — a firm negative result

The MAPSV2 index handle is referenced from exactly twelve places in the 949-5 binary: the index
registration, the login-packet index-version list, two engine-init sites, and six decoders. Each of
the six decoders passes a **literal** file id, and those literals are 0, 1, 5, 6, 7 and 8. There is
no code path that requests file 2, 3 or 4. The client downloads those bytes as part of the group and
never decodes them.

Consequently slots 3 and 4 are legacy data that Jagex still regenerates but the client no longer
consumes, and slot 2 is server-side-only data. Their grammars below are derived from the shipped
data, not from client code — see §12.

## 4. Read primitives

| name | width | meaning |
|---|---|---|
| `g1` / `g1s` | 1 | unsigned / signed byte |
| `g2` / `g2s` | 2 | big-endian unsigned / signed short |
| `g4` | 4 | big-endian unsigned int |
| `gFloat` | 4 | big-endian IEEE-754 single |
| `gVector3f` | 12 | three `gFloat` |
| `gSmart1or2` | 1–2 | if the next byte's high bit is clear, that byte; else the big-endian short plus `0x8000`, truncated to 16 bits |
| `gSmartVar` | 1–N | repeat `gSmart1or2`, accumulating; stop at the first value that is not `32767`; the total is the sum |

`gSmart1or2` is used for every id in this index. Ids are stored **biased by one** so that zero can
mean "none": the decoder computes `id = gSmart1or2 - 1`, and `-1` means absent.

## 5. Container header

Slots 3, 4 and 5 begin with a five-byte header: the four ASCII bytes `jagx` followed by a version
byte, which is `1` throughout the shipped index. The client **skips five bytes unconditionally** and
never compares the magic or the version — the literal string `jagx` does not occur anywhere in the
binary, in any byte order. Slots 0, 1, 2, 6, 7 and 8 have no header.

One exception matters for a byte-exact re-encode: 145 slot-4 files have **no header at all** and
start straight at the tile data. They are the all-zero files. A codec must record header presence
per file rather than assume it. Slot 3 and slot 5 always carry the header.

---

## 6. Slot 5 — terrain grid (the modern format)

A sequence of **level blocks**, each a bordered 66×66 grid of tile records, running to EOF. There is
no block count and no terminator; the reader loops while the position is short of the file length.

```
skip header (5 bytes)
while (position < size) {
    level = g1
    for (x = 0; x < 66; x++)
        for (y = 0; y < 66; y++)
            <tile record>
}
```

66 is 64 tiles plus a one-tile border on each side, and the outer index is x. Grid cell
`(x + 1, y + 1)` is map-square tile `(x, y)`; the border ring carries the neighbouring square's
edge so that lighting and blending are continuous.

Level blocks are emitted only for levels that have content, and each carries its own level index, so
a file holds between one and four blocks in ascending level order. Roughly 44% of archives carry all
four, 21% carry level 0 alone.

### Tile record

```
flags = g1
if (flags == 0) {
    height = g2                                   // 3-byte record, no material
} else {
    settings       = ((flags >> 1) & 7) | (((flags >> 5) & 3) << 3)
    hasSecondLayer = (flags & 0x10) != 0
    height = g2
    if (hasSecondLayer) secondLayerHeight = g2
    underlayId = gSmart1or2 - 1
    if (underlayId != -1) underlayColour = g2
    overlayId = gSmart1or2 - 1
    if (hasSecondLayer) secondLayerOverlayId = gSmart1or2 - 1
    if (overlayId != -1) {
        packedShape     = g1
        overlayShape    = packedShape >> 2         // indexes a 12-entry shape table; >= 12 means none
        overlayRotation = packedShape & 3
        if (hasSecondLayer) secondLayerUnderlayId = gSmart1or2 - 1
    }
}
```

**Flag byte.** Bit 0 is set on every non-zero flags byte in the whole index and is never consulted
beyond the `flags == 0` fast path — it is the "record is populated" marker. Bit 4 is the second-layer
flag. Bits 1–3 and 5–6 carry the five-bit `settings` field. Bit 7 is never set anywhere in the index
and the decoder ignores it. Observed flag bytes are exactly `1, 3, 5, 7, 9, 11, 17, 19, 21, 23, 27,
33, 35, 37, 39, 65, 67`.

**Field naming is cross-validated, not guessed.** Replaying slot 3's legacy grid alongside slot 5's
for the same archive and aligning by the one-tile border gives, over 1.8M compared tiles, exact
equality between

- slot 5 `settings` and slot 3's tile settings byte,
- slot 5 `height` and slot 3's tile short,
- slot 5 `underlayId` and slot 3's underlay smart,
- slot 5 `overlayId` and slot 3's overlay smart,

at **100%** in regions where slot 3 is still being regenerated, and around 86–92% averaged over
random archives — the shortfall being regions where the legacy file has gone stale. That
correspondence is what names these four fields, and it also settles what slot 3's short is: a
height, not a second spelling of the underlay id.

`height` is absolute on level 0 and additive above it — a level-1 block over flat ground reads as a
constant storey height with 0 where the level has no tile.

`underlayColour` is a 16-bit per-tile colour written only when the tile has an underlay. Its values
track the underlay type's own hue and lightness and vary smoothly across neighbouring tiles, which
is consistent with the conventional 6/3/7-bit packed HSL, but the packing is **not confirmed** — no
consumer of that field has been traced. Treat it as an opaque `u16` for round-tripping.

The second-layer fields describe a second surface over the same tile (a bridge or water plane): its
own height, its own overlay and, only when the tile also has a primary overlay, its own underlay.
Note the ordering asymmetry — `secondLayerOverlayId` is read before the primary overlay's shape
byte, `secondLayerUnderlayId` after it.

Ids resolve through two separate config type lists: `underlayId` and `secondLayerUnderlayId` through
one, `overlayId` and `secondLayerOverlayId` through the other. A companion prescan pass walks the
same grid before decode purely to harvest those two id sets per level and preload the types.

**Size.** A file is `5 + sum over blocks of (1 + 4356 * recordSize)`; the minimum non-empty block is
`1 + 4356 * 3` bytes.

---

## 7. Slots 3 and 4 — legacy terrain tiles

Same grammar for both; slot 3 has four levels, slot 4 has one. There is no count anywhere — the
level and tile counts are implied.

```
skip header (5 bytes, if present — see §5)
for (level = 0; level < levels; level++)
    for (x = 0; x < 64; x++)
        for (y = 0; y < 64; y++) {
            flags = g1
            if (flags & 0x01) { packedShape = g1 ; overlayId  = gSmart1or2 }   // shape = >> 2, rotation = & 3
            if (flags & 0x02) { settings    = g1 }
            if (flags & 0x04) { underlayId  = gSmart1or2 }
            if (flags & 0x08) { height      = g2 }
        }
```

Ids here are **not** bias-corrected by the file; the `- 1` is the reader's job, exactly as in slot 5.
No flag byte in the index has a bit above bit 3 set. Bits 2 and 3 are independent — each occurs
without the other — which is why bit 3 cannot be a second encoding of the underlay id; §6 identifies
it as the tile height.

Slot 4 ends exactly at its tile data in all 3343 archives. **Slot 3 does not** — every slot-3 file
carries a tail.

### Slot 3 tail — the legacy environment block

Eight head bytes, then a bare list of opcode records with no count and no terminator, running to EOF.

The eight head bytes take 124 distinct values across the index and look like per-row or
per-quadrant bitmasks (runs such as all-`ff` then all-`fe`, or a `00`/`f0` split). **Their meaning is
unknown**; their width is not in doubt.

| opcode | payload |
|---|---|
| 0 | environment record (below) |
| 1 | point light list (below) |
| 2 | three `gFloat` |
| 3 | `g2` then `gFloat` |
| 0x80 | skybox: `g2` id then four more shorts (10 bytes) |
| 0x81 | four levels, each a mode byte, and 256 signed samples when the mode is not 0 (only modes 0 and 1 occur) |
| 0x82 | no payload |

**Opcode 0** — a flag byte, then, per set bit in ascending order: sun colour `g4`, sun ambient `g2`,
sun light `g2`, sun backlight `g2`, sun position three `g2s`, fog colour `g4`, fog depth `g2`, and a
bit-7 field that is **two bytes** (not the six material ids the 727-era cache carried there).

**Opcode 1** — a count byte, then per light: packed level `g1`, x `g2`, z `g2`, height offset `g2`,
packed radius `g1`, `(packedRadius * 2 + 1)` × `g2` row ranges, colour `g2`, packed type `g1`, an
extra `g2` that the 727 format does not have, and a light-type `g2` only when
`packedType & 0x1f == 0x1f`.

This is the same record shape slot 7 carries in its modern form — see §10, whose field list is read
off live client code and is the better reference for the shared fields.

**The client has no decoder for any of this.** The tail's grammar is derived by replaying it over the
whole index. It is superseded by slots 6 and 7, which carry the same data — the first fields of a
slot-6 record are literally the same sun colour, sun position, sun ambient/light/backlight, fog
colour and fog depth, in a different order and followed by a great deal more.

---

## 8. Slots 0 and 1 — locations

An id-delta / position-delta stream. Both slots use the identical grammar; slot 1 is the secondary
layer and appears in exactly the archives that also carry slot 4.

```
locId = -1
while (true) {
    idDelta = gSmartVar                    // accumulate while each value == 32767
    if (idDelta == 0) break                // end of file
    locId += idDelta

    position = 0
    while (true) {
        posDelta = gSmart1or2
        if (posDelta == 0) break           // end of this id's placements
        position += posDelta - 1

        y     =  position        & 0x3f
        x     = (position >>  6) & 0x3f
        level =  position >> 12

        data     = g1
        rotation = data & 3
        shape    = (data >> 2) & 0x1f
        if (data & 0x80) <transform block>
    }
}
```

`position` accumulates across the inner loop, so the delta is relative to the previous placement of
the same id, minus one.

### Transform block

```
t = g1
if (t & 0x01) { g2s ; g2s ; g2s ; g2s }    // rotation quaternion, each component scaled;
                                           // components 1 and 3 are negated on load
if (t & 0x02) { g2s }                      // translate, first axis
if (t & 0x04) { g2s }                      // translate, second axis (negated on load)
if (t & 0x08) { g2s }                      // translate, third axis
if (t & 0x10) { g2s }                      // UNIFORM scale — bits 5..7 are then NOT read
else {
    if (t & 0x20) { g2s }                  // scale, first axis
    if (t & 0x40) { g2s }                  // scale, second axis
    if (t & 0x80) { g2s }                  // scale, third axis
}
```

Bit 4 short-circuits bits 5–7 entirely: a uniform scale consumes one short and the per-axis arms are
skipped. This is visible in the data — the only transform flag bytes that occur across 6.9M
locations are `0x00`–`0x1f` and `0xe0`–`0xef`, so bits 5, 6 and 7 always appear together and never
alongside bit 4.

Shapes observed run 0–22. No file has a single trailing byte past its terminator.

---

## 9. Slot 2 — NPC spawns

A flat stream of four-byte records to EOF. No count, no header, no terminator; the record count is
the file length divided by four, and every file in the index is a whole multiple of four bytes.

```
while (position < size) {
    packed = g2
    npcId  = g2
}
```

```
y     =  packed        & 0x7f
x     = (packed >>  7) & 0x7f
level =  packed >> 14
```

The seven-bit fields each use their full 0–63 range and never exceed it; the two-bit level runs 0–3
with the expected falling distribution. Records are strictly ascending by `packed`. Every `npcId` in
the index is a valid NPC type id.

This is **not** the polymorphic handler-dispatch format older notes describe — at least not in the
shipped data, and the client has no decoder to contradict it.

---

## 10. Slot 6 — environment record

One fixed-layout record, no count and no opcodes, **always exactly 227 bytes**. When the file is
absent the client falls back to a default instance held in a global.

In order:

| field | primitive |
|---|---|
| sun colour | `g4` (alpha forced opaque) |
| sun position | `g2s` ×3 (second component negated on load) |
| sun ambient, light, backlight | `g2` ×3 (each scaled) |
| — | `gFloat` ×3 |
| fog colour | `g4` (alpha forced opaque) |
| fog depth | `g2` |
| flag A | `g1` — when false the preceding id slot is reset to a float-max sentinel |
| — | `gFloat` ×4 |
| flag B | `g1` — when false the following block is zeroed |
| — | `gFloat` ×4 |
| — | `gVector3f` ×3 |
| — | `gFloat` ×8 |
| colour A | `g4`, three bytes each scaled by 1/255 |
| colour B | `g4`, three bytes each scaled by 1/255 |
| — | `gFloat` |
| flag C | `g1` |
| mode | `g1` (small enum, default 3) |
| — | `gFloat` ×5 (each paired with a slot the decoder zeroes) |
| — | `gFloat` ×6 — three defaults then three overrides; a non-zero override replaces its default |
| id A, id B | `g2s` ×2 |
| flag D | `g1` |
| id, weight | `g2s` then `gFloat` |
| id, weight | `g2s` then `gFloat` |
| — | `gFloat` |
| — | `gVector3f` |

The first six rows are the same quantities the slot-3 tail's opcode-0 record carries, which is what
identifies them; everything after that has no legacy counterpart and is named by position. The two
packed-RGB fields, the direction vectors and the id/weight pairs are what make this an
environment/atmosphere record rather than geometry — the byte layout is read directly off the code,
the semantics beyond the named rows are inferred.

---

## 11. Slot 7 — point lights

```
count = g1
count × <light record>
```

```
flags = g1                     // bits 0-2 -> small enum, bit 3 -> bool, bit 4 -> bool
x      = g2                    // fine units within the map square, rejected at or above 64 * 512
z      = g2                    // same bound
height = g2                    // fine units, unbounded
n      = g1                    // rejected above 64; footprint side = 2n + 1 tiles,
                               // stored radius = n * 512 + 256
(2n + 1) × g2                  // one row-coverage entry per footprint row:
                               //   high byte = start index, low byte = run length,
                               //   clamped so start + length <= 2n + 1
colour = g2                    // 16-bit HSL, converted through the RGB lookup
packed = g1                    // packed & 0x1f -> five-bit index; ((packed >> 5) & 7) << 8 -> a second field
       = g2s                   // -1 means none
if ((packed & 0x1f) == 0x1f) g2    // 0x1f is the escape sentinel for a 16-bit id
       = gFloat ×3
       = g1                    // bool
       = gFloat                // clamped to 0.0 .. 1.0
       = g1                    // bool
       = gFloat ×4
       = g2s ×3                // read as one seven-byte block
       = g1                    // three bit flags
```

The escape test is exactly `(packed & 0x1f) == 0x1f` and nothing else — this is the authoritative
predicate, and it also governs the equivalent field in the slot-3 tail's opcode-1 record.

If every row-coverage entry is `{0, 2n + 1}` the whole array is the identity full-square cover and
the client discards it, which is why exported data is usually `2n + 1` copies of the value `2n + 1`.

Record size is `54 + 2 * (2n + 1)` bytes, plus two more when the escape id is present.

---

## 12. Slot 8 — placed oriented patches

```
count = g1
count × {
    g1s      // local position, first axis   (scaled and biased into a float)
    g1s      // local position, second axis  (same)
    g1s      // extent, first axis           (shifted into fine units, 512 per tile)
    g1s      // extent, second axis          (same)
    g2s      // stored as a float
    gFloat ×3   // rotation AXIS
    gFloat      // rotation ANGLE
    g2       // observed values are few and round — a range or distance, with 0xffff as "none"
    g1s      // direction, first component  (scaled)
    g1s      // direction, second component (scaled)
    g2       // type id, 0..39; also appended to a parallel preload list
}
```

Exactly 28 bytes per record.

**The axis-and-angle pair is not a stored quaternion.** The client reads three floats and then a
fourth, and combines them — `sincos` of half the angle, scaled by the axis, then normalised — into a
quaternion at load time. A codec that treats the four floats as `(x, y, z, w)` will round-trip the
bytes but mis-state the format; the common value `(0, 1, 0)` with angle `0` is an up-axis with no
rotation.

Semantics beyond the geometry are unconfirmed. The type id's observed range lies inside the water
type list, which is suggestive but not proof; nothing in the decoder or its caller references water
types.

---

## 13. How this was verified

For every slot, the grammar above was implemented as a standalone reader and run over the entire
shipped index-5 corpus of 8675 archives, checking that the read position lands exactly on the file
length. Results:

| slot | files | outcome |
|---|---|---|
| 0 | 5173 | all consumed exactly |
| 1 | 3343 | all consumed exactly |
| 2 | 45 | all a whole multiple of the record size, strictly ascending, every id valid |
| 3 | 5173 | tiles consumed exactly; a tail always remains (§7) |
| 4 | 3343 | all consumed exactly, once headerless files are handled |
| 5 | 5173 | all consumed exactly |
| 6 | 5173 | all consumed exactly, all 227 bytes |
| 7 | 5173 | all consumed exactly |
| 8 | 5173 | all consumed exactly |

An off-by-one in any width or presence condition shows up immediately as a length mismatch on
thousands of files, so the widths and conditions are settled. What remains open is **meaning**, not
layout: the slot-3 tail's eight head bytes, its opcode-0 bit-7 field, slot 5's `underlayColour`
packing, and most of slot 6's float block.

Function names, prototypes, the `MapSquareTile` layout and the full per-slot grammars are recorded
in the Ghidra database against the 949-5 target; that database, not this file, is the source of
truth for anything build-specific.
