# RT7 model format — JS5 index 47 (`models`)

The RuneTek 7 model format: the payload of every group in the model index. Enough here to write a
byte-exact reader and writer.

Source of truth is the Ghidra DB for the desktop `rs2client`; this document carries only the
durable, cross-revision structure. **No addresses or memory offsets appear here by design** — the
decoder functions are named in the DB (`jag::ModelRT7::DecodeFile`, `::DecodeGeometry`,
`::DecodeVertexBlock`, and the little-endian helpers on `jag::ModelBuffer`). Those class names are
*assigned descriptive* names: neither the stripped target nor the outdated reference build contains
an RT7 model symbol, so no attested Jagex spelling exists.

Evidence labels used below:

* **[client]** — read out of the client's own parser in the Ghidra DB.
* **[cache]** — verified by parsing the served JS5 cache read-only.

**Validation: a parser built from the model below consumed all 145,735 groups of the served index
to exactly end-of-buffer — zero slack, zero errors.** [cache]

---

## 1. Container

Every group in this index holds exactly **one file**, so the decompressed group payload *is* the
model file. In the served cache all but ten groups are LZMA; the ten are stored uncompressed.
Sizes span 17 bytes to just under 2 MB. The group id is the model id.

## 2. Endianness — read this before anything else

The model reader is **not** `jag::Packet`. It is a separate buffer class, and its byte-swap guard
tests the *inverse* of `jag::Packet`'s host-order constant. The practical consequence:

> **The RT7 model file is predominantly LITTLE-endian**, which is the opposite of every other
> Jagex wire and cache format in this client, and it **mixes** endianness within a single file.

Exactly three streams are big-endian:

| Big-endian stream | Where |
|---|---|
| `f32` vertex positions | vertex block, when the float-position flag is set |
| `u16` texture coordinates | vertex block, always |
| `u32` triangle indices | submesh index list, wide-index models only |

plus the never-exercised attachment block D (§7). **Everything else in the file is little-endian.**

Each of the three was proved from data, not only from the guard constant: [cache]

* **u32 indices** — on the one model with at least 65,536 vertices, big-endian indices are all
  below the vertex count; little-endian gives values in the billions. Decisive.
* **f32 positions** — little-endian yields denormals and NaN for ~90% of vertices; big-endian
  yields plausible model coordinates for 99.4–99.8%.
* **u16 UV** — mean absolute delta between consecutive vertices is roughly six times smaller
  big-endian, and big-endian is the smoother reading in 293 of 300 sampled models.

## 3. Header — fixed size, little-endian

| # | Kind | Name | Notes |
|---|---|---|---|
| 1 | u8 | `version` | read and **discarded** by the client |
| 2 | u8 | `format` | selects the decoder. The modern value dispatches to everything below. A lower value routes to a legacy decoder that is dead for this cache; one specific lower value instead forces `countD` to zero. |
| 3 | u8 | `field_opaque` | **never loaded** — the read position advances past it and the byte is not consumed by any code path. Carry verbatim. |
| 4 | u16 LE | `submeshCount` | 1..87 observed |
| 5 | u8 | `countA` | attachment block A record count |
| 6 | u8 | `countB` | attachment block B record count |
| 7 | u8 | `countC` | attachment block C record count |
| 8 | u8 | `countD` | attachment block D record count; present only on the modern `format`. **Zero in every served group.** |
| 9 | u32 LE | `vertexFlags` | per-vertex attribute-presence bitmask (§4) |

## 4. `vertexFlags`

The bitmask gates optional per-vertex streams. Five bits are consumed by the client; the union of
bits actually observed in the served cache is larger than that set. [client] [cache]

| Bit | Effect |
|---|---|
| position-float bit | positions are `3 × f32` big-endian instead of `3 × i16` little-endian |
| skinning bit | per-vertex bone/weight lists are present |
| stream bits (three of them) | each adds one `u16 LE` per vertex, at three *different* points in the block order (§5) |
| one further bit | **set in 611 served models and read by nothing.** It does not change the layout. Carry verbatim. |

Bits outside that set never occur in the served cache. The client unpacks the five it consumes
into booleans; nothing else about the word is retained.

## 5. Vertex block

```
u32 LE  vertexCount
if vertexCount == 0:   the block ends immediately — no further vertex bytes at all
```

Ten served groups take that early exit and consist of a header plus submeshes only. [cache]

Then, strictly in this order — every stream is `vertexCount` elements long, stored plane-major
(all positions, then all normals, …), never interleaved:

| Present when | Element | Meaning |
|---|---|---|
| always | `3 × i16` **LE**, *or* `3 × f32` **BE** if the float-position bit is set | position x, y, z |
| always | `3 × i8` | normal x, y, z. Magnitude is exactly 127, i.e. a unit vector scaled by 127. |
| always | `4 × u8` | colour; the fourth byte is 127 on opaque vertices |
| always | `2 × u16` **BE** | texture coordinates |
| stream bit 1 | `u16` LE | positional name `field_streamA` |
| skinning bit | variable | see below |
| stream bit 2 | `u16` LE | positional name `field_streamB` |
| always | `u8` | positional name `field_byte`; observed 0, 155 and 255, overwhelmingly 255 |
| stream bit 3 | `u16` LE | positional name `field_streamC` |

**Note the unconditional single-byte stream sits *between* two of the optional streams, not at the
end of the block.** Getting that order wrong is the easiest way to mis-parse a model.

**Skinning**, per vertex, in vertex order:

```
u16 LE  boneCount
boneCount × u16 LE   bone / label indices
u16 LE  weightCount
weightCount × u8     weights
```

`boneCount` and `weightCount` are two independent fields; nothing in the decoder requires them to
be equal. 34,094 served models exercise this path. [cache]

## 6. Submeshes

`submeshCount` records, back to back:

```
u32 LE  submeshFlags
u8      field_a
u16 LE  field_b
u8      field_c
u16 LE  indexCount        -- must satisfy indexCount % 3 == 0
indexCount × index        -- u16 LE when vertexCount < 65536, else u32 BE
```

The fixed part is eight bytes; `indexCount` is a separate field that follows it. The index element
width is chosen from the **model's** vertex count, not per submesh.

`submeshFlags`: 49 distinct values occur; the client consumes four bits and unpacks them into
render-state booleans. The remaining bits are stored nowhere and do not affect the layout — carry
them verbatim. `field_a`, `field_b` and `field_c` are byte-exact but their roles are unproven, so
they carry positional names.

### 6.1 Two client behaviours a writer must know [client]

**The divisible-by-three test gates the entire index read.** If `indexCount % 3 != 0` the client
consumes *zero* index bytes and leaves the reader positioned mid-record, so every later submesh in
the same model decodes garbage. This is a hard client limitation, not a parse subtlety: a model
that fails the test is effectively unloadable.

**The index count overflows at 16 bits, and six shipped assets hit it.** Six served groups store a
true index count above 65,535, which wrapped in the `u16` field. Adding 65,536 until the value is
divisible by three reproduces the exact file length for all six — including one nine-submesh model
where only the fifth submesh overflowed and every later submesh still lands byte-exact. That
recovery is *inference*: **the wire field is 16 bits and the high bits are stored nowhere in the
file.** A repacker must carry these six models verbatim. That same model is also the only asset in
the whole index that exercises the `u32 BE` index path, and is therefore the sole evidence for it.
[cache]

## 7. Attachment blocks

Four counted blocks follow the submeshes, strictly in the order **A, then B, then C, then D**,
each driven by its own header count. [client]

### 7.1 Block A — fixed-size records

```
u8      field_a
u16 LE  field_b        (the client keeps field_b - 1)
u16 LE  field_c
u16 LE  subCount
subCount × sub-record:
    5 × f32 LE         first three read as x, y, z; the last two are a paired value
                       (e.g. -669.33, -0.0, -24.33, 1201.0, 1201.0)
    u16 LE  field_f
    u8      field_g
    4 × u16 LE  id0..id3     a sentinel of all-ones means "none"
    u8      field_h
```

Each `id` is looked up in a per-model table; **both branches of that lookup consume exactly two
bytes**, so the sentinel never changes the record length. `subCount` is 1 in all 41,829 served
records, so the sub-record stride comes from the loop back-edge in the binary and is **not**
independently confirmed by data variation — the one stride in this format in that position. [client]

### 7.2 Block B — fixed-size records

```
u16 LE  id
3 × point:
    f32 LE x, f32 LE y, f32 LE z
    u16 LE a
    u16 LE b          (all-ones in every served record)
```

Three points; reads as a triangle. The point record is byte-identical to block C's body.

### 7.3 Block C — fixed-size records

```
u16 LE  id
f32 LE x, f32 LE y, f32 LE z
u16 LE  a
u16 LE  b             (all-ones in every served record)
```

### 7.4 Block D — UNVERIFIED

`countD` is zero in all 145,735 served groups, so this block never executes and its layout comes
from the binary alone. [client]

```
u8 tag
if tag == 0:   NUL-terminated C string (an empty string still costs its terminator)
fixed 30-byte record
```

Unlike the rest of the file, this record's scalars use the `jag::Packet`-style guard, i.e. they are
**big-endian**. Treat the whole block as unconfirmed.

## 8. Derived by the client versus literally in the file

**In the file:** every count and every byte listed above, and nothing else.

**Derived at load time, never on the wire:**

* the interleaved runtime vertex struct — the file stores parallel plane-major attribute streams
  and the client weaves them into one struct per vertex
* the per-model id lookup tables that block A's ids resolve through; the file stores raw ids and
  the client allocates local slot numbers on first sight
* the submesh render-state booleans unpacked from `submeshFlags`
* the vertex-block booleans unpacked from `vertexFlags`
* bounding volumes, LOD selection and GPU buffers — all built after decode, by post-processing that
  never touches the file bytes
* the true index count for the six overflowed assets

## 9. Bytes that stay opaque, and how to carry them

A repacker that cannot fully re-derive these must copy them through unchanged:

1. **Header byte 3** (`field_opaque`) — one byte per file, never loaded by this build.
2. **`submeshFlags` bits outside the four the client consumes** — stored nowhere.
3. **The unused `vertexFlags` bit** — present in 611 models, read by nothing.
4. **The six overflowed index counts** — the true value is not recoverable from the field alone;
   copy those six model files byte-for-byte.

Everything else in the file is accounted for by the layout above.

## 10. Residual unknowns

* Block A's sub-record stride rests on the binary only (`subCount` never varies in the cache).
* Block D is entirely unexercised, in the cache and therefore in the evidence.
* The legacy low-`format` decoder is unexercised and not documented here.
* Field *semantics* — as opposed to sizes and order — are positional where the role was not proven:
  the three submesh header fields, the four bit-gated per-vertex streams and the unconditional
  per-vertex byte, and most of blocks A, B and C.
