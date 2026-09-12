# RS3 NXT cache — index catalogue, reference-table format, group framing, image payloads

Scope: what each JS5 index in the RS3 NXT cache holds, how a format-7 reference table is laid
out, how a multi-file group is framed, and the exact structural shape of the graphic and texture
payloads — enough to write codecs that round-trip byte-exactly.

Source of truth is the Ghidra DB for the desktop `rs2client`; this document carries only the
durable, cross-revision structure. **No addresses, offsets or opcodes appear here by design** —
per-build values live in the Ghidra DB and in the updater's generated tables. Field *order*,
field *kinds*, and fixed-vs-variable structure are stable across revisions and are what a codec
needs, so those are recorded.

Two independent evidence sources are used throughout and are labelled per claim:

* **[client]** — read out of the client binary's own parser in the Ghidra DB.
* **[cache]** — verified by parsing the served JS5 cache read-only. Where a claim says "verified
  across every group", a parser built from the stated model consumed every group in that index to
  exactly end-of-buffer with no slack.

---

## 1. Index catalogue

### 1.1 How the client decides which indices exist

At startup the client builds a registry of JS5 archive handles: one descriptor per index,
allocated and stored in a global vector slotted by index id. The descriptor carries the index id,
an *enabled* flag, a cached-group budget, and a few per-index behaviour bits. Registration is
gated by a per-index availability table sized for indices 0..66 inclusive — that table is the
client's own statement of the highest index number it knows about. **An index that is never
registered is never read by this build, even if the served cache populates it.** [client]

This registry is therefore an exhaustive, authoritative list: any index absent from it is unused
by the client. In the current build the unused-but-populated indices are **32, 33, 34, 35 and
53**; every other populated index is registered.

Indices 16–22 and 24 are registered through the config-type-list path and are consumed by the
config provider, which binds each one to a named type list. [client]

**The binary names no index.** Every archive descriptor gets its name field written by one of two
factory helpers or by the one hand-rolled descriptor, and all three write the **empty string**; no
other code path ever writes that field. Every index name in the table below is therefore either the
legacy directory name, a name recovered from Jagex's own gameval tables via the *group* name hashes
(indices 10 and 58 do this), or a description coined from behaviour — never a string lifted from the
binary. [client]

### 1.2 Table

Confidence key: **HIGH** = client-side consumer identified *and* the payload agrees; **MEDIUM** =
family established but the exact name is a description rather than an attested identifier;
**UNIDENTIFIED** = no confident identification. Anything marked UNIDENTIFIED must stay unidentified
downstream — a wrong name propagates further than no name.

Names below that match the legacy RuneScape directory naming are marked *(legacy name)*; the rest
are descriptive names coined here from the evidence and must not be treated as attested.

| Idx | Name | Registered | Evidence | Conf. |
|-----|------|-----------|----------|-------|
| 1 | `skeletons` / framebases *(legacy name)* | yes | paired into every skeletal-animation object as the framebase source | HIGH |
| 2 | `config` *(legacy name)* | yes | the config provider binds its named type lists to this handle | HIGH |
| 3 | `interfaces` *(legacy name)* | yes | multi-file groups; bulk-preloaded by the config provider alongside clientscripts | MEDIUM |
| 5 | `maps` *(legacy name)* | yes | handle already named in the DB as the MapsV2 index; map-square loader | HIGH |
| 8 | `sprites` *(legacy name)* | yes (registered inline) | payload is the graphic-sheet format of §4; also the interface-graphic source of the texture manager | HIGH |
| 10 | `binary` *(legacy name)* | yes | one name-addressed group (`huffman`) holding a 256-entry canonical-Huffman code-length table for chat compression; the Kraft sum is exactly 1. Full format in `nxt-misc-formats.md` | HIGH |
| 12 | `clientscripts` *(legacy name)* | yes | CS2 toolchain round-trips this index | HIGH |
| 13 | legacy bitmap font metrics *(the DB's `fontmetrics` name)* | registered, **never parsed** | the **same record format as index 58**, at its oldest version (no graphic-group field — the group id serves as it). Its 60 group ids are exactly the 60 graphic-group ids index 58's bitmap files name, and are all real index-8 groups. This build registers the handle for the login CRC set and the readiness check only: nothing decodes it. Jagex's own `fontmetrics` gameval type matches index **58**, not this one. See `nxt-misc-formats.md` | HIGH |
| 14 | `vorbis` *(legacy name)* | yes | every group is a `JAGA` container of self-contained Ogg Vorbis chunks, all stored inline. Full format in `nxt-worldmap-audio-formats.md` | HIGH |
| 16 | `config_loc` *(legacy name)* | yes | bound to the LOC type list | HIGH |
| 17 | `config_enum` *(legacy name)* | yes | bound to the ENUM type list | HIGH |
| 18 | `config_npc` *(legacy name)* | yes | bound to the NPC type list | HIGH |
| 19 | `config_obj` *(legacy name)* | yes | bound to the OBJ type list | HIGH |
| 20 | `config_seq` *(legacy name)* | yes | bound to the SEQ type list | HIGH |
| 21 | `config_spotanim` *(legacy name)* | yes | bound to the GRAPHIC type list | HIGH |
| 22 | `config_struct` *(legacy name)* | yes | bound to the STRUCT type list — **22 is struct, not varbit** | HIGH |
| 23 | `worldmapdata` *(legacy name)* | yes | world-map subsystem pulls bare PNG tiles out of it; groups addressed by area name | HIGH |
| 24 | `quickchat` *(legacy name)* | yes | payload is quick-chat phrase text | HIGH |
| 26 | `materials` *(legacy name)* | yes | handle already named in the DB; supplies the texture records driving 52/54/55 | HIGH |
| 27 | `config_particle` *(legacy name)* | yes | member of the material/texture/shader resource set | MEDIUM |
| 28 | `defaults` *(legacy name)* | yes | eleven independent records, one shape per group id, each a bare tag loop with no version byte and no count. Eight ids are polled by a dedicated loader (not a per-file callback); three populated groups have no decoder case. Holds the default light-source set, the skill table + XP curves, and an environment record. Full format in `nxt-misc-formats.md` | HIGH |
| 29 | `config_billboard` *(legacy name)* | yes | member of the material/texture/shader resource set | MEDIUM |
| 32 | `dlls` *(legacy name)* | **no** | populated but never registered | n/a |
| 33 | — | **no** | populated but never registered, so no parser exists; the legacy `shaders` name is NOT supported by anything in this binary. Three groups, names-only reference table, name hashes unrecovered; one embeds the literal `Preparing Your Greatest Adventure`. Bytes-only description in `nxt-misc-formats.md` — carry verbatim | UNIDENTIFIED |
| 34 | `loading_sprites` *(legacy name)* | **no** | populated but never registered | n/a |
| 35 | — | **no** | populated but never registered, so no parser exists; the legacy `loading_screens` name is NOT supported by anything in this binary. 54 groups sharing a fixed six-byte header in exactly two variants, then a tag-driven variable-length stream. Bytes-only description in `nxt-misc-formats.md` — carry verbatim | UNIDENTIFIED |
| 36 | — | **no** | not registered and not populated; **the client contains no reference to index 36 at all** | n/a |
| 40 | `audio_streams` | yes | **not raw Ogg**: the same `JAGA` container as index 14, but only the stream-header groups carry the magic — the rest are the bare Ogg chunks those headers name. The per-request boolean that selects between 14 and 40 is a residency flag. Full format in `nxt-worldmap-audio-formats.md` | HIGH |
| 41 | `worldmap_area_data` | yes | payload **is** established — palette header then map-square/chunk records of bitfield-selected tile cells; file 1, where present, is a copy of index 42's file. The hashed name is the area's internal name from index 23. See `nxt-worldmap-audio-formats.md` | HIGH |
| 42 | `worldmap_area_coords` | yes | per-map-area table: count, then records of `{packed world coord, map-element type id, flag}`; the id is resolved through the map-element type list. Byte-identical to index 41's file 1. See `nxt-worldmap-audio-formats.md` | HIGH (format), MEDIUM (name) |
| 47 | `models` *(legacy name)* | yes | model / loc-prefetch path; the largest flat archive in the cache. Payload is the RT7 model format — **predominantly little-endian, with three big-endian streams**. Full format in `rt7-model-format.md`, validated across every group | HIGH |
| 48 | `skeletal_anim_multipart` | yes | skeletal keyframe animation; the object holds an **array** of packets each naming its own index-1 framebase | HIGH (kind), MEDIUM (which of 48/56) |
| 49 | — | yes | **UNIDENTIFIED, and specifically NOT a db-table index** — the db-table and db-row decoders belong to index-2 type-list slots with no path from 49. Its only consumer is the config provider's bulk preloader, which parks the raw groups in RAM; **nothing in the client parses a byte of it.** The stored payloads look like short sorted id lists | UNIDENTIFIED |
| 52 | `textures_dxt` | yes | payload is a DDS container (§5.1); enabled with 55 at the compressed-texture setting | HIGH |
| 53 | `textures_png` | **no** | payload is one PNG per face (§5.3); populated over the same group set as 52/55 but **never registered** | HIGH (format), n/a (unused) |
| 54 | `textures_png_mipped` | yes | payload is a per-face PNG mip chain (§5.4); enabled at the uncompressed-texture setting. See §5.5 for the unresolved reader mismatch | HIGH (format) |
| 55 | `textures_etc` | yes | payload is a KTX 1.0 container (§5.2); enabled with 52 at the compressed-texture setting | HIGH |
| 56 | `skeletal_anim` | yes | same decoder family as 48 — framebase id, counts, then per-transform keyframe tracks of `{u16 time, 5 big-endian f32}`; one group per animation | HIGH (kind), MEDIUM (which of 48/56) |
| 57 | `achievement` | yes | config type list whose per-file type objects are `jag::game::AchievementType`; the cache payloads carry achievement names and descriptions in plain text | HIGH |
| 58 | `fontmetrics` — font glyph metrics | yes | a version byte selects a scalable font (an index-59 face plus a point size) or a bitmap font (per-glyph cell sizes, top bearings and atlas positions, plus the index-**8** graphic group holding the glyph imagery). All 225 group name hashes match Jagex's own `fontmetrics` gameval table exactly, so this — not index 13 — is the index Jagex calls `fontmetrics`. Full format in `nxt-misc-formats.md` | HIGH |
| 59 | `fonts` — TrueType/OpenType files | yes | every group is a bare `sfnt` font file with no Jagex wrapper; both TrueType and OpenType/CFF flavours occur and `GDEF` is not universal. Rasterised by FreeType. See `nxt-worldmap-audio-formats.md` | HIGH |
| 60 | `stylesheet` — widget style sheets | yes | **IDENTIFIED.** A parent style-sheet id (`-1` = root, single inheritance) then counted `{kind, nameHash, value}` records; the keys are 31-hashes of the UI style-property strings in the binary (243 of 246 resolved), the decoder is registered by the interface manager, and the group ids match Jagex's `stylesheet` gameval table. Values type-check against indices 8 and 58. Full format in `nxt-misc-formats.md` | HIGH |
| 61 | `particle_effects` — VFX system presets | yes | one self-contained preset per group: version, name, emitter list; each emitter names a **material id (index 26, confirmed through the material gameval table)** and carries a modifier list over an 18-entry type dispatch built from shared curve and shape primitives. Full format in `nxt-misc-formats.md` | HIGH (kind), MEDIUM (name) |
| 62 | `anim_state_machines` | yes | one self-contained machine per group: a form selector picks a single blend layer or a counted state list; layers hold clips and transitions, clips hold a **seq id (confirmed through the seq gameval table)** or a recursive blend expression. Full format in `nxt-misc-formats.md` | HIGH (kind), MEDIUM (name) |
| 65 | `ui_anim` / `ui_anim_curve` — interface animations | yes | **IDENTIFIED.** Owned by the interface manager; the decoded objects are exactly what the `if_anim_*` / `cc_if_anim_*` clientscript opcodes drive. Group id selects the payload kind: one group is the easing-curve table (file id = curve id) and the other the animation presets (file id = the id the play opcode takes). Full format in `nxt-misc-formats.md` | HIGH |
| 66 | `cutscene_overlays` — cutscene 2-D overlays | yes | **group id == cutscene id**: the decoder is registered from the main loop, its capture holds the cutscene-2D manager, and that manager's play method — driven by the `_cutscene2d_play` opcode — keys its map by group id. Elements carry image tracks (**graphic id**, keyframe channels), sound refs (**sound id**) and subtitle refs into a **config-enum id**, all three confirmed through the gameval tables. Full format in `nxt-misc-formats.md` | HIGH |
| 67 | `gamevals` | n/a — beta host only | outside the client's index range | HIGH |

### 1.3 Two structural notes that affect codec design

**Uniform group size is padding, not stream splitting — a correction.** Indices **61, 62 and 66**
decompress to the same size for every group, and an earlier revision of this document read that as
one logical byte stream cut into equal blocks, with the advice to concatenate all groups in id order
before parsing. **That was wrong and is superseded.** Each group is an *independent, self-contained
record*: it opens with its own version byte, every count that bounds it comes out of the record
itself, no decoder carries state across groups, and none of them ever consults the group length. The
uniform size is a **ceiling** the encoder pads to — the largest served particle record fills about
93% of it and the smallest about 1%. Parse each group on its own and treat the zero remainder as
padding. Verified from the binary and by parsing every group of all three indices to its own
declared end with an all-zero tail. [client] [cache]

**Name-addressed archives.** Some indices resolve a group by hashing a name rather than by numeric
id. For the world-map subsystem that is indices **41 and 42 only** — index 23's reference table sets
no names flag and is keyed by (archive = render layer, file = area id). Name-addressed indices are
exactly the ones whose reference table sets the names flag. A repacker must preserve the name-hash
section or those lookups fail silently; the hash function and the strings that feed it are in
`nxt-worldmap-audio-formats.md`.

---

## 2. Reference table — format 7

Every populated index in the served cache uses **format 7**. [cache]

### 2.1 Section order

Read strictly in this order. `smart` = 1-or-2-byte unsigned when the first byte's high bit is
clear, else a 4-byte big-endian value with the high bit masked off. All multi-byte integers are
big-endian.

```
u8      format                      (7)
i32     table version               (present for format >= 6)
u8      flags
smart   groupCount
groupCount x smart                  group-id deltas, running sum -> group ids
[flags & 0x01]  groupCount x u32     group name hashes
groupCount x u32                     CRC32 of the group's COMPRESSED container
[flags & 0x08]  groupCount x u32     CRC32 of the group's UNCOMPRESSED payload
[flags & 0x02]  groupCount x 64 B    Whirlpool digest of the compressed container
[flags & 0x04]  groupCount x (u32, u32)
                                     per group, a PAIR: (compressed container length,
                                     uncompressed payload length)
groupCount x u32                     group version
groupCount x smart                   file count per group
per group: fileCount x smart         file-id deltas, running sum -> file ids
[flags & 0x01]  (sum of fileCounts) x u32   file name hashes
```

**The 0x08 section precedes the 0x04 section.** That ordering is easy to get backwards and is the
one structural detail most likely to be assumed wrong. [client] [cache]

### 2.2 Meaning of the two sections asked about

Both were confirmed directly against real cache data, not inferred from position: [cache]

* **0x04 — sizes.** Two ints per group, in this order:
  1. the **length of the compressed container**, i.e. its header plus the compressed payload and
     *excluding* the 2-byte version trailer — equal to the byte length of the blob the local cache
     stores for that group, and to the wire container's length minus two,
  2. the **uncompressed payload length**, which equals the container header's own declared
     uncompressed length and the actual inflated size.
* **0x08 — uncompressed CRC.** One int per group: `CRC32` of the group's **decompressed**
  payload bytes.

The always-present int array that precedes them is `CRC32` of the **compressed container** —
verified equal to the CRC the cache stores alongside each group. The always-present int array
that follows them is the **group version** — verified equal to the version the cache stores
alongside each group.

### 2.3 What the client actually validates against a downloaded group

Only two things: [client]

1. **CRC32 of the compressed container, excluding its trailing 2-byte version trailer.** The
   client computes CRC32 over the received container minus its last two bytes and compares it
   with the reference table's always-present per-group CRC array. A mismatch fails the response.
   (In the local disk cache the container is stored *without* the version trailer, and the stored
   CRC covers the whole stored blob — the two views agree.)
2. **Whirlpool digest over that same byte range**, when the request carries one (i.e. when the
   table declared the `0x02` section). A mismatch also fails the response.

The `0x08` uncompressed-CRC value and the *second* int of each `0x04` pair are parsed and then
discarded — the client never checks them. The *first* int of each `0x04` pair is used only to
accumulate a total byte count for download accounting. A server may therefore emit any values it
likes there without the client noticing, but a byte-exact cache writer should emit the real ones.

### 2.4 Flags seen in the served cache

`0x0c` (sizes + uncompressed CRC) on almost every index; `0x0d` (the same plus names) on the
indices whose groups are addressed by name; `0x01` (names only, no sizes and no uncompressed CRC)
on the legacy indices the client no longer registers. No populated index used the Whirlpool
section. [cache]

---

## 3. Group framing

### 3.1 Container

A stored/served group is a standard JS5 container:

```
u8      compression type      0 = none, 1 = bzip2, 2 = gzip, 3 = LZMA
i32     compressed length     length of the payload that follows the header
i32     uncompressed length   present only when compression type != 0
bytes   payload
[u16]   version trailer       present on the wire; absent in the local disk cache
```

The local disk cache also accepts a second, private container shape: a 4-byte `"ZLB\x01"` magic,
a big-endian u32 uncompressed length, then a raw zlib stream. That shape never appears on the
JS5 wire. [client]

### 3.2 Multi-file groups — the trailing chunk table

This is the only multi-file layout the client parses. There is **no** alternative wire layout.
[client] [cache]

A group whose file count is **1** has no table at all: the decompressed payload *is* the file.
The client shortcuts on that case before touching any table. [client]

A group whose file count is greater than 1 is laid out as:

```
bytes                         file payload, ordered chunk-major then file-major:
                                for chunk in 0..chunkCount-1:
                                  for file in 0..fileCount-1:
                                    that file's slice for that chunk
(chunkCount * fileCount) x i32   delta table, big-endian. Within one chunk the running sum of
                                 the deltas gives each file's slice length in that chunk; the
                                 running sum RESTARTS at the beginning of every chunk.
u8                            chunkCount   (the very last byte of the group)
```

`fileCount` is not stored in the group — it comes from the reference table. The client locates
the table by seeking backwards from the end: one byte for `chunkCount`, then
`chunkCount * fileCount * 4` bytes for the delta table.

The client immediately rewrites this into a random-access form in memory (a pad byte, then
`fileCount + 1` absolute big-endian start offsets, then the file bytes concatenated in file
order). That rewritten form is internal only and never appears in a cache or on the wire —
do not confuse the two. [client]

Verified on real multi-file groups: the running sums reconstruct exactly the payload byte count,
with no slack. [cache]

---

## 4. Graphic payload — index 8

One group is one graphic sheet holding one or more frames. Groups are single-file, so the group
payload is the sheet directly. Two layouts share the archive and are discriminated by the last
two bytes. [client, from the verified decoder analysis recorded in the Ghidra DB]

```
seek to (length - 2)
u16   trailer
      frameCount = trailer & 0x7fff
      bit 15 set   -> RAW layout
      bit 15 clear -> INDEXED-PALETTE layout
```

A buffer shorter than 2 bytes is rejected.

### 4.1 RAW layout

Read forwards from the start:

```
u8    formatVersion    must be 0; any other value yields zero frames (and is not an error)
u8    alphaPresent     an alpha plane is read only when this is exactly 1
u16   width            shared by every frame
u16   height           shared by every frame
repeat frameCount times:
    width*height x { u8 r, u8 g, u8 b }      alpha defaults to 0xff
    if alphaPresent == 1:
        width*height x u8 alpha
```

Both planes are plain row-major; there is no traversal flag, and frames carry no per-frame size
or offset.

### 4.2 Indexed-palette layout

Three separate reads at computed positions, all measured back from the end of the buffer.

**Trailer block** — starts `7 + 8*frameCount` bytes before the end:

```
u16   maxWidth
u16   maxHeight
u8    paletteSize - 1        so the palette holds 2..256 entries
frameCount x u16  offsetX
frameCount x u16  offsetY
frameCount x u16  width
frameCount x u16  height
```

**Palette block** — starts a further `3 * (paletteSize - 1)` bytes earlier:

```
palette[0] is the transparent sentinel and is not stored
(paletteSize - 1) x u24 (big-endian) colour, with a stored value of 0 remapped to 1
```

**Frame block** — starts at position 0, one entry per frame in order:

```
u8    flags
        bit0  traversal: 0 = row-major, 1 = column-major
        bit1  a second alpha plane follows the index plane
width*height x u8  palette index, in the bit0 traversal order
if bit1:
    width*height x u8  alpha, in the SAME traversal order
```

Palette index 0 writes a fully transparent pixel; any other index writes RGB with alpha `0xff`.
A frame may legitimately be 0×0 and still consumes its flags byte. When every alpha byte in a
frame's alpha plane is `0xff` the plane is discarded.

The trailer's bit 15 is the only discriminator: the first byte cannot serve, because it is 0 for
every RAW sheet *and* for every indexed sheet whose first frame has flags 0.

Every frame satisfies `offsetX + width <= maxWidth` and `offsetY + height <= maxHeight`, and the
whole archive decodes to exactly end-of-buffer under this model. [cache]

---

## 5. Texture payloads — indices 52, 53, 54, 55

All four texture indices share one group id space: **the group id is the texture id, and the file
id is always 0** — one file per group, so the group payload is the texture payload directly.
The mip level is *not* a file id. [client] [cache]

All four share the same outer framing idea: a leading count byte, then a run of length-prefixed
sub-images. `u32 BE` below always means the Jagex big-endian outer length; the bytes *inside* a
DDS or KTX container are little-endian as those formats require.

The leading count is the **face count**: 1 for a 2-D texture, 6 for a cube map.

### 5.1 Index 52 — DXT

```
u8    faceCount          always 1 in the served cache
u32 BE  ddsLength
bytes   a complete DDS file (4-byte magic + 124-byte DDS_HEADER + pixel data)
```

The whole mip chain lives inside the DDS, contiguous, with no per-level length prefix. Cube maps
are expressed inside the DDS rather than as multiple faces, which is why the face count is
always 1 here.

The client reads `dwHeight`, `dwWidth` and `dwMipMapCount` out of the DDS header, skips
everything else, and copies the pixel data as one blob. Note it puts the header's *height* field
into its width slot and vice versa — harmless because RS3's textures are square, but a writer
should mirror the real DDS field order and keep the textures square. The pixel format field is
read and thrown away: **the block format is chosen client-side from GPU capability and the
texture-quality setting, never from the file.** In practice this index carries DXT5/BC3. [client]

No magic bytes and no version byte are validated anywhere in this path. [client]

### 5.2 Index 55 — ETC

```
u8    faceCount           1 or 6
repeat faceCount times:
    u32 BE  ktxLength
    bytes   a complete KTX 1.0 file (64-byte header, optional key/value block,
            then per level: u32 LE imageSize followed by that level's data)
```

Only the **first** entry's KTX header is parsed; for entries 2..N the length and header are
skipped, and the client assumes every entry has identical length, key/value size and per-level
sizes. The decoded levels of all faces are concatenated into one contiguous blob with no reset
between faces. A writer must therefore emit **identical-size** KTX files for every face of a
cube map. [client]

The client also ignores KTX's 4-byte per-level padding rule (it copies exactly `imageSize`
bytes); with ETC2 block sizes the sizes are already 4-aligned, so a conformant writer is safe.

### 5.3 Index 53 — PNG, no mips

```
u8    faceCount           1 or 6
repeat faceCount times:
    u32 BE  pngLength
    bytes   a complete PNG file
```

Verified across every group in the index. [cache] This index is **not registered by the client**
and is never read by this build.

### 5.4 Index 54 — PNG, mipped

```
u8    faceCount           1 or 6
repeat faceCount times:
    u8   mipCount         8..11 in practice for a 2-D texture
    repeat mipCount times:
        u32 BE  pngLength
        bytes   a complete PNG file
```

Levels run largest first and halve each step (128×128, 64×64, … down to 1×1). Verified across
every group in the index: the model consumes each group to exactly end-of-buffer. [cache]

### 5.5 Unresolved: the client's uncompressed-texture reader

Flagged explicitly rather than papered over. The client's *uncompressed* texture path — the one
selected when the GPU supports neither compressed format, or when the texture-quality setting
picks RGBA8 — reads the index-54 handle and parses a **different** layout:

```
u8    mipCount
u32 BE  width
u32 BE  height
bytes   a contiguous raw RGBA8 mip chain, 4 bytes per texel,
        (width >> level)^2 texels per level, times 6 for a cube map
```

That does not describe the served index-54 data, which is PNG-based (§5.4). The DXT and ETC
readers agree exactly with the served data for indices 52 and 55, so the disagreement is specific
to this one path. Possible explanations — a legacy reader kept alive for an archive shape Jagex
no longer ships, or a path the shipping client never actually takes because the compressed
formats are always available — were **not** resolved. Treat §5.4 as authoritative for what the
bytes are, and do not build anything on the raw-RGBA shape.

The same uncompressed reader has a third mode used for interface graphics: it decodes an index-8
graphic group with the RAW graphic decoder (§4) and copies `width * height * 4`. Graphics are only
ever served through the uncompressed path; the DXT and ETC readers bail out immediately for them.

### 5.6 No pixel transforms

None of the three texture paths flips, swizzles or premultiplies: each ends in a plain copy from
the cache buffer to the upload blob. (Two transforms that *do* exist elsewhere and must not be
confused with these: the decoder for PNGs compiled into the binary vertically flips its rows, and
the 3-D/volume LUT path transposes a strip into a volume.) [client]
