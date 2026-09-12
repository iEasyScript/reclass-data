# RS3 NXT cache — skeletal animation formats (indices 1, 48, 56)

Scope: the three cache formats that make up the RS3 skeletal animation system, in enough detail to
write a byte-exact codec.

* **index 1** — *framebases* / skeletons. One archive per skeleton, one file per archive.
* **index 48** — *multipart* skeletal animations. One archive per animation, one file per frame,
  every archive stored as three JS5 chunks.
* **index 56** — *single* skeletal animations. One archive per animation, one file per archive.

Source of truth is the Ghidra DB for the desktop `rs2client`; this document carries only the durable,
cross-revision structure. **No addresses, offsets or opcodes appear here by design.** Field *order*,
field *kinds*, and fixed-vs-variable structure are what a codec needs and are what is recorded.

Two independent evidence sources are used and labelled per claim:

* **[client]** — read out of the client's own parser in the Ghidra DB. The three parsers are the
  framebase constructor (named `jag::graphics::AnimBase::AnimBase` in the DB), the index-48 loader,
  the index-56 loader, and the keyframe-curve reader the index-56 loader calls. The latter three
  carry the full wire order as entry comments but are deliberately left `FUN_`-named: no attested
  Jagex symbol exists for those classes and a wrong name is worse than none.
* **[cache]** — verified by parsing the served JS5 cache read-only. "Verified across every group"
  means a parser built from the stated model consumed every group in that index to exactly
  end-of-buffer with no slack. Counts are in §6.

---

## 1. Primitives

All multi-byte integers and floats are **big-endian**. Records are **not aligned or padded** — a
`f32` may start at any byte.

Three variable-length integer encodings appear. They are distinguished only by the high bit of the
first byte, so the *length* rule is shared; the *bias* differs.

| Name here | Encoding | Range |
|---|---|---|
| `usmart` | high bit clear → 1 byte, value = `b`. High bit set → 2 bytes BE, value = `u16 & 0x7FFF`. | 0 .. 32767 |
| `ssmart` | high bit clear → 1 byte, value = `b - 64`. High bit set → 2 bytes BE, value = `u16 - 49152`. | -64 .. 16383 |

`jagString` is a NUL-terminated byte string.

**Group framing.** Index 1 and index 56 have exactly one file per archive, so the decompressed group
*is* the file and there is no chunk table. Index 48 is multi-file; its chunk table is the standard
JS5 one (trailing chunk count byte, then `chunks x files` big-endian per-file size deltas). Reference
tables for all three indices are format 7 with the flags that carry sizes and uncompressed CRCs and
**no name section**, so all three are addressed by numeric id only. [cache]

---

## 2. Index 1 — framebase (skeleton)

One file per archive; the archive id is the framebase id. Two logically distinct things live in one
file: a **transform list** (the legacy animation-transform table that index 48 frames edit) and a
**bone/skeleton block** (the bind pose that index-56 tracks address).

### 2.1 Field order

```
u16     transformCount
        if transformCount == 0xFFFF:            -- sentinel, selects the extended header
            u8  version
            u16 transformCount
        else:
            version = 4                          -- implied, not stored

u8      transformType   [transformCount]
u8      unusedA         [transformCount]         -- skipped, never read by the client
u16     unusedB         [transformCount]         -- skipped, never read by the client
usmart  labelCount      [transformCount]
usmart  label           [sum of labelCount]      -- concatenated, split by labelCount

u16     boneCount
u8      matrixSetCount
        boneCount x {
            u16 boneLabel                        -- 0xFFFF means "none"
            matrixSetCount x { 19 x f32 }        -- see 2.3
        }

i16     remapCount                               -- SIGNED; a negative value reads no array
u16     remap           [remapCount]             -- 0xFFFF means "none"

u8      extraCount
        if version > 4:
            extraCount x {
                jagString name
                u16       key
                u16       b
                7 x f32
            }
```

Everything before `boneCount` is the transform list; everything from `boneCount` on is the skeleton
block. Both are always present — an archive with no skeleton simply writes `boneCount = 0` and
`matrixSetCount = 0`. **`extraCount` is read unconditionally**; only its record array is gated on
`version > 4`. [client] [cache — this is what makes the shortest archives come out exact]

### 2.2 What the fields mean

| Field | Meaning |
|---|---|
| `transformCount` | number of animation transforms this skeleton exposes. Up to 800 in the served cache. |
| `version` | 4 unless the `0xFFFF` sentinel is used, in which case it is stored. Only 5 is observed. |
| `transformType` | the transform's kind. Drives how an index-48 frame encodes that transform's values (§3.3) and, at runtime, how the decoded values are scaled. Observed values 0,1,2,3,4,5,7,8,9,10. |
| `unusedA`, `unusedB` | present in every file, **never parsed** — the client advances the cursor over them. Degenerate in the served cache (`unusedA` is 0 or 1; `unusedB` is `0xFFFF` with a single exception), which is exactly what you would expect of fields nothing consumes. A re-encoder must still round-trip them verbatim. |
| `labelCount` / `label` | per transform, the model labels (vertex groups) it moves. Labels reach 399 and label counts reach 400, so the two-byte `usmart` form is genuinely used — reading these as `u8` will desynchronise. |
| `boneCount` | number of bones in the skeleton block. |
| `matrixSetCount` | how many 19-float sets each bone carries. Uniform across the file. |
| `boneLabel` | the label this bone binds to; `0xFFFF` is "none". |
| `remap` | a bone/label remap table; `0xFFFF` is "none". |
| extra records | named float attachments. Never populated in the served cache. |

### 2.3 The 19 floats per bone

The first sixteen are a **4x4 matrix in row-major order** — read as a bind-pose transform, they come
out as a rotation with the translation in the last row and a 1.0 in the final element. Verified by
inspection: the first bone of a typical skeleton is exactly the identity, later bones are proper
rotation-plus-translation matrices.

The remaining three floats are a fixed per-bone suffix whose meaning is not established. They are
byte-identical across every bone of a given skeleton in the files inspected, which is consistent with
a bind-pose scale or a bounding value rather than anything per-bone.

**A codec must not assume 16.** The stride is `matrixSetCount x 19` floats and the 19 is what makes
the file end exactly.

### 2.4 Lossy folds a re-encoder must respect

* The client **rewrites a `transformType` of 6 to 2** as it stores it. No file in the served cache
  carries a 6, so the fold is never exercised — but a decoder that folds is not one you can encode
  from. Keep the file's byte.
* `boneLabel` and `remap` entries of `0xFFFF` are **stored as 0**, which a decoded 0 cannot be told
  apart from. Keep the raw `0xFFFF`.
* `unusedA` and `unusedB` are dropped entirely by the client. Keep them.

---

## 3. Index 48 — multipart skeletal animation

**One archive is one animation. One file inside it is one frame.** The archive id is the animation
id.

### 3.1 File id is the frame time

File ids are *not* positional. They are ascending, usually start at 1, and **skip the frames the
animation does not key** — a six-file group may hold ids 1, 2, 3, 5, 6, 9. A single-file group keeps
whatever id its one frame has (1 in most, but 0, 2, 8, 20 and 33 all occur), which is what proves the
id is a time and not an index. So the reference table's file-id list *is* the animation's keyframe
schedule, and a codec must preserve it exactly. [cache]

Groups hold up to **397** files.

### 3.2 How a file names its framebase

Each file carries its own framebase id in its header, and the client memoises the resulting skeleton
in a map keyed by that id so the frames of one animation share one decoded skeleton. **Every group in
the served cache uses exactly one distinct framebase across all of its files**, but the field is
per-file and a codec should read it per-file. [client] [cache]

The dependency is hard: **you cannot decode an index-48 frame without first decoding its index-1
framebase**, because the per-transform value encoding is selected by the framebase's
`transformType` for that transform.

### 3.3 File field order

```
u8      version                                  -- 2 throughout the served cache
u16     frameBaseId                              -- index 1, that group, file 0
u16     transformCount

u8      mask [transformCount]

values:
        for i in 0 .. transformCount-1:
            m = mask[i]
            if m == 0: continue                  -- transform absent, zero payload
            t = framebase.transformType[i]
            pairs = (t == 2) or (version > 1 and t == 7)
            if m & 0x1:  x  = ssmart ; if pairs: xw = ssmart
            if m & 0x2:  y  = ssmart ; if pairs: yw = ssmart
            if m & 0x4:  z  = ssmart ; if pairs: zw = ssmart
```

* `mask` bits `0x1 / 0x2 / 0x4` select the x / y / z components the frame moves. An axis whose bit is
  clear has **no bytes at all**; the client substitutes a default, so the raw mask is what a codec
  must store.
* `mask` bits `0x8 | 0x10` are a two-bit per-transform mode (`(mask >> 3) & 3`), not payload. All
  four values occur. Bits `0x20`, `0x40`, `0x80` are never set in the served cache.
* A `mask` that is non-zero but has no axis bit set is legal and produces a transform entry with no
  values — only `mask == 0` means "absent".
* The `pairs` case writes **two** `ssmart`s per present axis. For `transformType == 2` the client
  keeps both; for `transformType == 7` (and only when `version > 1`) it reads both and **discards the
  second**, so a decoder that drops it cannot re-encode.
* `transformCount == 0` is legal — an empty frame. 3642 files in the served cache are empty.

At runtime the decoded integers are scaled by the framebase's transform type before use (angle-like
types are in units of 1/16384 of a turn, scale-like types are divided by 128, and one type negates
its y). That is presentation, not wire format; a codec stores the raw `ssmart` values.

### 3.4 How the three chunks map onto the structure

Every multi-file group in index 48 is stored as **exactly three JS5 chunks**, and the split is not
arbitrary metadata — it is the file format's own three sections:

| Chunk | Holds | Length, per file |
|---|---|---|
| 0 | the header: version, framebase id, transform count | always **5** |
| 1 | one `mask` byte per transform | `transformCount` |
| 2 | the values | everything left |

So the layout is **derivable from the frames** and does not have to be recorded anywhere: chunk 0 is
5 bytes, chunk 1 is the frame's declared transform count, chunk 2 is the remainder. Verified on all
986 494 files of all 32 965 multi-file groups — every single per-file chunk length matched
`(5, transformCount, rest)`. [cache]

The 569 single-file groups carry no chunk table at all and get none.

This mirrors the reason the client can use a second cursor over the same buffer: it walks the mask
array twice (a pre-pass to size its output array, then the real pass) while a separate cursor reads
the values starting immediately after the mask array.

---

## 4. Index 56 — single skeletal animation

**One archive is one animation and holds exactly one file** (file id 0). The archive id is the
animation id. Unlike index 48 there are no per-frame files: the whole animation is one buffer of
keyframed curves.

### 4.1 Field order

```
u8      version                                  -- 1 throughout; the client SKIPS it without reading
u16     frameBaseId                              -- index 1, that group, file 0
u16     unknownA                                 -- 0 in every group but one
u16     duration
u8      unknownC                                 -- 0 in every group but one
u16     trackCount

trackCount x {
    u8      kind
    ssmart  channelIndex
    u8      curveType                            -- 1-based
    -- curve:
    u16     keyCount
    u8      curveKind
    u8      unusedD                              -- 0 throughout
    u8      unusedE                              -- 0 throughout
    u8      flag                                 -- stored as a bool; 0 or 1
    keyCount x {
        u16     time
        f32     value
        f32     inTangentX
        f32     inTangentY
        f32     outTangentX
        f32     outTangentY
    }
}
```

A track header is therefore **8 bytes plus the length of `channelIndex`** (9 or 10), and a key is
**22 bytes**, unaligned.

### 4.2 What the fields mean

**`duration`** is the animation length. It equals the highest keyframe time in 2844 of the 2936
groups; where it does not, the last key runs past it. Values run 1 .. 4310.

**`kind`** selects what `channelIndex` addresses and how many curve channels the track group has:

| `kind` | channels | `channelIndex` addresses | occurrences |
|---|---|---|---|
| 1 | 9 | a **bone** of the framebase — always `< boneCount` | 2 915 923 |
| 2 | 9 | a framebase **transform** — always `< transformCount` | 35 |
| 3 | 3 | a framebase transform | 712 |
| 4 | 1 | a framebase transform | 976 |

(The client's table also defines kind 0 with 0 channels and kind 5 with 3; neither occurs in the
served cache, and kinds ≥ 6 reserve nothing.) The bound is exact in every one of the 2 917 646 tracks
in the cache — no track addresses a bone or transform the framebase does not have. [cache]

**`curveType`** is 1-based and selects the channel slot within the track group. The client maps
1..9 → slots 0..8, 10..15 → slots 0..5, and 16 → slot 0. Which types appear is fully determined by
`kind`:

| `kind` | `curveType` values used |
|---|---|
| 1 | 1..9 |
| 2 | 3, 7, 8 |
| 3 | 10..15 |
| 4 | 16 |

For `kind == 3`, a `curveType` whose slot is greater than 2 is **decoded and thrown away** — the
payload is still consumed. Half of the kind-3 tracks (types 13, 14, 15) fall in that bucket.

**`curveKind`** is the transform kind of the channel group. For `kind == 1` it is fully determined by
`curveType`: 1..3 → 0, 4..6 → 1, 7..9 → 3. That grouping is the classic translate / rotate / scale
triple, so `curveType` 1..3 is a translation's x,y,z, 4..6 a rotation's, 7..9 a scale's. For the
other kinds it varies independently and must be stored.

**`unusedD` / `unusedE`** are read into the curve object and are 0 in every curve in the cache.
**`flag`** is stored as a bool and is 0 or 1.

### 4.3 The five floats per key

The client copies them as raw 32-bit words (byte-swapped on a little-endian host), so their meaning
is not established by the parser. The data settles it: they are **`value`, then an in-tangent pair,
then an out-tangent pair**.

* A flat curve reads `{0.0, 1.0, 0.0, 1.0, 0.0}` — value 0 with both tangents `(1, 0)`.
* The **first** key's in-tangent is the flat default `(1, 0)` in 80% of curves, and the **last**
  key's out-tangent in 90% — exactly what you expect of end-of-curve tangents.
* Interior tangent pairs are frequently unit length, and a key's out-tangent often equals the next
  key's in-tangent (about half the time), i.e. they are independent controls with C1 continuity
  where the exporter chose it.
* Not every pair is normalised — pairs like `(30, 0)` occur — so treat them as tangent vectors, not
  as angles.

`time` values are almost always strictly increasing within a curve (8 414 902 ascending pairs against
80 550 descending and none equal), but a codec should not *rely* on it.

---

## 5. How the three fit together

```
index 56  animation ──frameBaseId──▶ index 1 framebase
   one file, curves keyed by time            transformType[] ── used only for scaling
   kind 1 track ──channelIndex──▶ bone[]
   kind 2/3/4  ──channelIndex──▶ transform[]

index 48  animation
   archive = animation, file = one frame, file id = that frame's time
   each file ──frameBaseId──▶ index 1 framebase
                                  transformType[i]  ── SELECTS the value encoding of transform i
   frame edits transform[i] through mask[i]
```

The two animation indices are two different representations of the same idea: index 48 stores a
**sparse per-frame edit** of the skeleton's transform list as quantised smart integers, addressed by
file id; index 56 stores **continuous float curves with tangents**, addressed by keyframe time inside
one buffer. Index 48 leans on the framebase for its *encoding*; index 56 leans on it only to bound
its channel ids.

---

## 6. Validation

Every model above was implemented as a standalone parser and run over the whole served cache,
requiring the cursor to land on exactly end-of-buffer with zero bytes of slack.

| Index | Unit | Result |
|---|---|---|
| 1 | groups | **5321 / 5321** exact, zero slack |
| 48 | groups | **33 480 / 33 534** exact (a decoder must refuse the one ambiguous group too, see below) |
| 48 | files | **986 081 / 987 063** exact |
| 48 | per-file chunk split `(5, transformCount, rest)` | **986 494 / 986 494** multi-file-group files matched |
| 48 | distinct framebases per group | **33 534 / 33 534** groups use exactly one |
| 56 | groups | **2936 / 2936** exact, zero slack |
| 56 | `kind == 1` channel id `< boneCount` | **2 915 923 / 2 915 923** |
| 56 | other kinds, channel id `< transformCount` | **1723 / 1723** |

### The 54 index-48 failures are broken cache entries, not a gap in the model

54 archives name a **stub framebase** — a skeleton declaring two transforms — while their frames
declare tens or hundreds. 1018 files across those archives declare more transforms than their
framebase has, and for each of them the client's own per-transform lookup
(`framebase.transformType[i]`) runs past the end of the framebase's type array. Since that type is
what selects one-smart-versus-two, **the frame's byte length is not determined by the format at
all**, and no consistent substitute reproduces them: of the 1018, substituting type 0 for the
out-of-range indices ends exactly for 36, substituting 2 or 7 for 209, and 774 end exactly under
none of them (one file ends exactly under every substitute - an ambiguity, not a decode, so a
codec keeps that archive verbatim as well: 54 archives stay opaque, not 53). These animations cannot render correctly in the client either. This is the same class of
defect as the long-known legacy packer quirks, and a codec should carry the raw bytes for these
archives rather than pretend to model them.

### Served-cache facts worth knowing when writing a codec

* index 1: version 4 in 5317 archives, 5 in 4 (exactly the archives using the `0xFFFF` sentinel);
  `matrixSetCount` 0 in 5054, 1 in 266, 2 in 1; `extraCount` 0 everywhere so the extra-record block
  is never populated; 267 archives carry a skeleton block and 214 a remap array; `remapCount` is
  never negative; no `transformType` of 6 exists.
* index 48: file `version` is 2 in all 987 063 files; `mask` never exceeds `0x1F`.
* index 56: `version` is 1 in all 2936; `unknownA` is non-zero in one archive and `unknownC` in one
  other; only track kinds 1, 2, 3 and 4 occur.
