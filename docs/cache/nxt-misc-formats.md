# RS3 NXT cache — the minor index formats

Byte-level structure for the JS5 indices that the index catalogue lists but does not specify:
the chat Huffman table, `defaults`, font glyph metrics, widget style sheets, particle presets,
animation blend state machines, interface animations, cutscene overlays, and the two populated
indices the client never opens.

Source of truth is the Ghidra DB for the desktop `rs2client`; this document carries only durable,
cross-revision structure. **No addresses or memory offsets appear here by design.** Field order,
field kinds, and the in-file discriminators that select a conditional block *are* the format and
are recorded; per-build binary coordinates are not, and live in the DB against the named decoders.

Evidence labels: **[client]** = read out of the client's own parser; **[cache]** = verified by
parsing the served JS5 cache read-only.

Every model below was validated by parsing **every group of its index** and asserting the parse
ends exactly where the model says:

| Index | Subject | Groups | Result |
|---|---|---|---|
| 10 | chat Huffman code lengths | 1 | 1 exact, 0 fail |
| 13 | font glyph metrics, legacy shape | 60 | 60 exact, 0 fail |
| 28 | `defaults` | 11 | 8 exact, 0 fail; 3 have no decoder in this build |
| 33 | unregistered | 3 | bytes only — no parser exists |
| 35 | unregistered | 54 | bytes only — no parser exists |
| 58 | font glyph metrics | 225 | 225 exact, 0 fail |
| 60 | widget style sheets | 319 | 319 exact, 0 fail |
| 61 | particle / VFX presets | 1344 | 1344 exact, 0 fail |
| 62 | animation blend state machines | 7 | 7 exact, 0 fail |
| 65 | interface animations | 2 (30 files) | 30 exact, 0 fail |
| 66 | cutscene 2-D overlays | 9 | 9 exact, 0 fail |

---

## 0. Two facts that apply to all of them

### 0.1 The binary names no JS5 index

Every archive descriptor the client builds gets its name field written by one of two factory
helpers, plus one hand-rolled descriptor. All three write the **empty string**, and no other code
path ever writes that field. **No JS5 index carries a name in this build.** [client]

Every index identity in the Ghidra DB and in these documents therefore rests on *behaviour* — which
manager owns the handle, which opcode drives the decoded object, which id space the payload
resolves into — never on a string in the binary. Where a name below matches Jagex's own naming it is
because the *group* names resolve against the gameval tables (indices 10 and 58 do this), not
because the index is named.

Group names are a different matter and are real: an index whose reference table sets the names flag
addresses its groups by a 31-based string hash (`h = h*31 + c`), the same hash the reference table
uses everywhere.

### 0.2 The "fixed-size stream splitting" claim was wrong — correction

Earlier revisions of the index catalogue stated that indices 61, 62 and 66 are *one logical byte
stream cut into equal fixed-size blocks*, and that a codec must concatenate all groups in id order.
**That is incorrect and is superseded here.**

Each group in those indices is an **independent, self-contained record**. It opens with its own
version byte, every count that bounds it comes out of the record itself, no decoder carries state
from one group to the next, and none of them ever consults the group length. What made the old
reading look plausible is that all three indices zero-pad every group to the same decompressed
size. That size is a **ceiling**, not a slice width: the largest served particle record uses about
93% of it and the smallest uses about 1%. [client] [cache]

Proof from both directions: the state-machine decoder rejects a group shorter than two bytes and
then reads a version and a form selector; the particle decoder reads a version, a name and an
emitter count; the cutscene decoder reads a version and refuses anything but the one it knows. All
three terminate on their own counts. And the validators parse every group of all three indices and
find the record ends early with the entire remainder zero. [cache]

---

## 1. Index 10 — chat Huffman code lengths

One group, addressed **by name** (the group name hashes to `huffman`), holding one file.

```
u8 codeLength[256]        one canonical-Huffman code length per byte value 0..255
```

No header, no count, no terminator, no version. 256 bytes, and that is the whole file.

The Kraft sum over the served table is **exactly 1.0**, i.e. a complete prefix code — which both
confirms the reading and proves the file is complete as stored. Served lengths run 3..22.

**Derived, not stored:** the entire decode tree. The client allocates a small fixed-size tree object
right after the fetch and performs the canonical assignment (sort by length, then by symbol, assign
increasing codes) itself. Nothing about the tree shape is in the file. [client]

**No opaque bytes.** Every byte is accounted for.

---

## 2. Indices 58 and 13 — font glyph metrics

These two indices share **one format**. Index 58 carries the two modern versions; index 13 carries
only the oldest, and this build registers index 13 for CRC and readiness purposes but **never parses
it** — no decoder consumes it and no manager holds its handle. [client] [cache]

Index 58 is name-addressed and its group names resolve exactly against Jagex's own `fontmetrics`
gameval table — all 225 group name hashes match, and the id sets are identical. Index 58 is
therefore the index that Jagex calls `fontmetrics`. Index 13's group ids are all valid graphic-sheet
group ids, which is exactly what its version demands (see below). [cache]

```
u8 version                anything above the highest known version aborts the decode
```

### 2.1 Vector-font version — the short shape

```
u32 BE  fontFileId        index into the TrueType/OpenType font-file archive
u8      pointSize         also kept as a float
```

The file ends there. Two thirds of index 58 is this shape, and every `fontFileId` in the served
cache is a real group of the font-file index. [cache]

### 2.2 Bitmap-font versions — the fixed-size shape

```
u8      flags             low bit selects the trailing block (see below)
u32 BE  graphicGroupId     PRESENT ONLY ON THE NEWER OF THE TWO BITMAP VERSIONS.
                          On the older version the field is absent from the wire and the client
                          substitutes the file's own group id — which is why index 13's group ids
                          are all graphic group ids.
u8      cellWidth[256]    per byte value 0..255
u8      cellHeight[256]
i8      topBearing[256]   signed
u16 BE  atlasWidth
u16 BE  atlasHeight
u16 BE  atlasX[256]
u16 BE  atlasY[256]
u8      baseline          ONLY when the low bit of flags is CLEAR
u8      pad0
u8      pad1
u8      pad2
u8      pad3
u8      downscale
```

The file ends there; the fixed size decomposes exactly and there is **no tail**. Every served file
has the low flag bit clear, so `baseline` is always present; when that bit is set the client instead
reads a variable-length block whose layout is **unknown and unexercised**. [client] [cache]

`downscale`, when it is not 1, integer-divides `cellWidth`, `cellHeight`, `topBearing`, `baseline`
and `pad0..pad3` on the way in.

**Derived, not stored:** [client]

* the glyph advance is a copy of `cellWidth` after the downscale divide
* the atlas rect per glyph is `{x, y, w, h}` where only `x` and `y` come from the file — `w` and `h`
  are copies of `cellWidth`/`cellHeight`
* the TAB glyph is overwritten wholesale: its advance becomes the `M` glyph's advance times four and
  everything else is zeroed. Its on-disk values are ignored.

**Independent cross-check:** for every bitmap file, the 256 rects lie entirely inside the declared
atlas and **overlap in zero pixels**. That is what proves the two 256-byte arrays are atlas cell
sizes rather than advance-only metrics. [cache]

**Opaque:** `pad0..pad3` — four bytes, read and scaled and stored, consumers not traced. Carry
verbatim. Also the set-flag variant of the trailing block, and the oldest version's presence in
index 58 (modelled, never served there).

---

## 3. Index 60 — widget style sheets

Style sheets for the widget layer, with single inheritance. The identity is settled four ways: the
keys are hashes of UI style-property strings that sit in the binary's own string table
(`button.text.font`, `combo.interaction.selected.bg`, `list.scrollbar.handle.sprite.edge.horizontal`
and 240 more, 243 of 246 distinct served keys resolved); the decoder is registered by the interface
manager; the resulting global table's named consumers are the widget size-estimation and header-
construction opcodes; and Jagex's own `stylesheet` gameval table is a superset of the served group
ids, with names like `background_default`, `button_makex_available`, `rect_dark`. [client] [cache]

```
i16 BE  parentStyleId     the style sheet this one inherits from; -1 marks a root
u16 BE  propertyCount
propertyCount × record:
    i8      kind          must be zero
    u32 BE  nameHash      31-based hash of the style property name
    u32 BE  value
```

The file ends immediately after the last record; total size is always the fixed header plus a fixed
record stride times the count.

`kind` is the only place a value-type discriminator could live and **only zero is implemented**. A
non-zero value makes the client abandon the whole file mid-parse and never register the object. All
served records use zero. [client] [cache]

`value`'s interpretation is **per property name**, not encoded in the record — a graphic group id for
`*.sprite`, a font-metrics group id for `*.font`, 24-bit RGB for `*.rgb`, 32-bit RGBA for the
interaction-background and text colours, a pixel count for sizes/heights/margins, 0/1 for the
boolean-named properties, a small enum for alignments, and an all-ones sentinel for "unset". Every
`*.font` value in the served cache is a real font-metrics group and every `*.sprite` value is a real
graphic group, which is what confirms the reading. [cache]

**Inheritance:** a second pass resolves `parentStyleId` by group id after all files are loaded. In
the served cache every non-root parent exists, the graph is acyclic, and 82 sheets are roots. Sheets
with zero properties exist purely to introduce an inheritance node. [cache]

**Insertion behaviour a writer must know.** Each record is binary-search inserted into a
key-ascending array, so: [client] [cache]

* on-disk order need **not** be ascending — 96 of the 319 served sheets are unsorted
* a **duplicate key is dropped, not replaced** — the insert only fires when the new key sorts before
  the existing one. Three served sheets carry a duplicate key, and its second occurrence is lost.

**Opaque:** three of the 246 key hashes do not resolve to any string in the binary and are not
reachable from any prefix-by-suffix combination of the 243 that do — either the string is built at
runtime or the property was removed. Carry the hash and its value verbatim. The non-zero meanings of
`kind` have no implementation to describe.

---

## 4. Index 28 — `defaults`

Eleven groups, each an **independent record with its own shape selected by group id**. There is no
per-file callback on this archive: the loader polls a fixed set of eight group ids and switches on
the id. Three populated groups are outside that set and are **never read by this build** — one of
them carries a five-byte payload whose shape is therefore unknown. [client] [cache]

### 4.1 Framing — the one thing all eight share

**There is no version byte and no count prefix.** Every group is a bare tag loop:

```
loop:
    u8 tag
    if tag == 0:  the record ends — and the file ends exactly here
    read that tag's payload
```

All eight parse to exact end-of-buffer under that rule, with zero slack. [cache]

> **Scope note.** The per-group tag→payload dispatch is a numeric table of exactly the kind this
> project keeps out of prose because it is re-numbered on update day. It lives in the Ghidra DB on
> the named `defaults` decoder, which carries the complete table with byte-level comments. What
> follows is the *durable* part: the framing above, which groups exist, and the internal structure
> of the sub-records — which is what a server actually has to reproduce.

### 4.2 What the eight groups hold

| Group role | Content |
|---|---|
| two single-slot records | one holds a pair of 16-bit slots, one holds a single 32-bit slot |
| the large environment record | ~29 distinct tags: paired 16-bit tables whose length is set by an earlier tag, 24-bit values assembled from three individually-indexed bytes (**not** a plain big-endian 24-bit read), smart 2-or-4-byte integers, and two identical fixed 10-by-4 nested curve blocks of `{u16, u16 n, n × u16}` |
| a byte-array record | several independent counted `u8` arrays, one of which reuses an **earlier tag's count and carries no count byte of its own**, and stores each byte decremented by one |
| the default light-source set | see §4.3 |
| the skill and XP-curve record | see §4.4 |
| a grid record | scalars, three 32-bit values stored **rotated** by one byte rather than raw, a long run of payload-less tags, and a high tag range that writes into a 5-wide by 8-tall grid **transposed** into a flat array |
| a smart-integer record | a pair of smart 2-or-4-byte integers and a counted 16-bit array |

`smart 2-or-4`: peek the next byte; high bit clear reads a `u16 BE`, high bit set reads a `u32 BE`
masked to 31 bits.

Unknown tags are **not** uniformly ignored: two of the eight groups skip them and continue, two
treat them as a hard error, and the rest fall through with no payload. [client]

### 4.3 Light source

```
u8 kind
  kind 0 -> i8, u8, u8 n, n × u8
  kind 1 -> u8, u8
  kind 2 -> u8 n, n × u8
  other  -> a null light; nothing further is consumed
```

The record appears in three roles inside its group: as a single light into one of four slots, as an
*array* of lights (which is the kind-2 body on its own, `u8 n` then `n × u8`), and — for three tags —
parsed and then **discarded**, so those bytes must still be emitted.

### 4.4 Skills and XP curves

Skill record — variable length:

| # | Field | Kind | Present when |
|---|---|---|---|
| 1 | `skillId` | u8 | always; also the array slot the record lands in |
| 2 | `levelBound` | u16 BE | always |
| 3 | `flags` | u8 | always |
| 4 | *(second level bound)* | u8 | only when the second flag bit is set |
| 5 | `curveIndex` | u8 | only when the third flag bit is set; otherwise a built-in default curve is used |
| 6 | *(bound adjustment)* | i8 | only when the fourth flag bit is set; **defaults to 1** when clear |
| 7 | *(boolean)* | u8 | always; the client stores `value == 1` |

The lowest flag bit has no wire payload — it gates whether the client computes an XP threshold at
all, from the selected curve and the level bounds.

Curve list:

```
u8 curveCount             allocates that many slots, each PRE-FILLED client-side with the classic
                          RuneScape pow() XP formula
repeat:
    u8 curveIndex         an all-ones byte terminates the list
    u16 BE levelCount
    levelCount × u32 BE   cumulative XP, replacing that slot's default curve
```

The served file declares one slot and overrides it with the 150-level elite-skill curve
(0, 830, 1861, 2902, …). **Derived, not stored:** the default curve for every slot the file does not
override — the client generates it. [client] [cache]

**Opaque:** the never-read group's five-byte payload (carry verbatim); the two single-byte groups
outside the read set; and, within the read groups, the semantics — not the sizes or order — of the
large environment record's scalar tags and the grid record's rotated 32-bit values.

---

## 5. Index 61 — particle / VFX system presets

Owned by the VFX manager, which is handed this archive alongside the texture, graphic, material and
billboard archives; the owning module carries the engine's particle-system build paths. [client]

All multi-byte scalars are **big-endian**, `f32` is big-endian IEEE-754. Strings use the
version-prefixed reader: **one version byte; a non-zero value means the empty string and consumes
nothing more, a zero byte is followed by a NUL-terminated run** (the terminator is consumed). No
CP1252 remapping. That is why every string in this index is preceded by a zero byte.

```
u8      version           the served cache is uniformly at the current version
string  name              preset name, e.g. RedFire, LitFire_Particle, vfx_zaros_lightplate_skirt
u8      systemFlags
u8      emitterCount      1..51 observed
emitterCount × Emitter
```

The decoder still contains live branches for six earlier versions. They change which emitter fields
are present and add one extra byte before one modifier's payload; a writer targeting this client
should emit the current version, at which every field below is present.

### 5.1 Emitter

| # | Field | Kind | Meaning |
|---|---|---|---|
| 1 | `name` | string | e.g. `Flame1`, `Smoke2`, `Embers`, `Glow`; 3134 distinct in the cache |
| 2 | `field_a` | u8 | always zero in the cache |
| 3 | `field_b` | u8 | |
| 4 | `field_c` | u8 | |
| 5 | `flags` | u8 | the client keeps the low five bits; one of them sets a per-emitter boolean |
| 6 | `materialId` | u16 | **a material id** — see §5.2 |
| 7 | `particleCap` | u16 | 1..1000; caps the derived particle-count estimate |
| 8 | `uvCols` | u8 | 1..10; divides a UV span, i.e. a sprite-sheet tile count |
| 9 | `uvRows` | u8 | 1..5; same |
| 10 | `vec2A` | 2 × f32 | |
| 11 | `vec2B` | 2 × f32 | |
| 12 | `field_g` | f32 | compared against a constant to select a UV-scroll derivation |
| 13 | `field_j` | u8 | always zero in the cache |
| 14 | `field_k` | f32 | |
| 15 | `field_l` | f32 | |
| 16 | `field_m` | f32 | |
| 17 | `vecC` | 3 × f32 | |
| 18 | `vecD` | 3 × f32 | `vecC` and `vecD` are combined through an Euler-to-matrix helper, so one is a rotation triple and the other a translation; **which is which is not settled** |
| 19 | `modifierCount` | u8 | 3..8 observed |
| 20 | `modifiers` | `modifierCount` × `{u8 type, payload}` | §5.4 |

### 5.2 `materialId` is confirmed

The `RedFire` preset's six emitters — `Flame1, Flame2, Smoke1, Smoke2, Embers, Glow` — carry
material ids that resolve through the material gameval table to
`vfx_redfire_flame2, vfx_redfire_flame1, vfx_redfire_smoke1, vfx_redfire_smoke2, vfx_redfire_ember1,
vfx_redfire_glow1`. `Distortion_Test`'s two smoke emitters resolve to `smokedistortion1` and
`smokedistortion2`. Across the index the field takes 4000 distinct values, all inside the material
id space. Conclusive. [cache]

### 5.3 Shared payload primitives

| Primitive | Shape |
|---|---|
| `ScalarCurve` | `u8 n`; `n == 0` reads nothing; `n == 1` is a **constant-value shortcut** of one `(f32, f32)`; otherwise `n` segments of four `f32` |
| `Vec2Curve` | `u8 n`; `n == 1` → `f32` + 2 × `f32`; otherwise `n` segments of two × (`f32` + 2 × `f32`) |
| `Vec3Curve` | `u8 n`; `n == 1` → `f32` + 3 × `f32`; otherwise `n` segments of two × (`f32` + 3 × `f32`) |
| `Vec4Curve` | `u8 n`; `n == 1` → `f32` + 4 × `f32`; otherwise `n` segments of two × (`f32` + 4 × `f32`) |
| `Shape` | `u8 kind`, `u8 boolean`, 3 × `f32` position, 3 × `f32` Euler, then a kind-dependent tail of zero, one, two or three `f32` |

The general curve form stores **two Bezier control points per segment**; the `n == 1` form is a
constant. The sampled table the renderer actually uses is tessellated at load time and is **not** in
the file.

### 5.4 Modifiers

A modifier is a `u8 type` followed by a fixed payload shape drawn from the primitives above:
`Shape`s, curve primitives, and runs of `f32`/`u8`. **A type above the highest known value aborts
the whole decode.** The complete type→payload table lives in the Ghidra DB on the named particle
decoder, one comment per modifier decoder.

What matters for a codec: eleven of the eighteen types occur in the served cache and are
byte-confirmed; **seven exist in code only and are never exercised**, so their layouts are read off
the binary alone and are not confirmed. [client] [cache]

### 5.5 Derived, not stored

The per-emitter particle-count estimate, the tessellated curve sample tables, the rotation matrix
built from `vecC`/`vecD`, and the UV step derived from `uvCols`/`uvRows`.

### 5.6 Opaque

The four single bytes `field_a`, `field_b`, `field_c`, `field_j` (two of them always zero); the
`flags` bits other than the one boolean; the six float slots `vec2A`, `vec2B`, `field_g`, `field_k`,
`field_l`, `field_m`; the `vecC`/`vecD` translation-versus-rotation split; the rarer `systemFlags`
values; the seven never-exercised modifier types; and the physical meaning — not the shape — of
every float inside every modifier payload.

---

## 6. Index 62 — animation blend state machines

Big-endian throughout. Strings here use the **bare** reader — a NUL-terminated run with **no**
version prefix, unlike indices 61 and 66.

```
u8  version
u8  form                  a group shorter than two bytes is rejected outright
```

`form` selects the whole record: one value means a single **Layer** and that is the entire file;
another means `u32 stateCount` followed by that many **States**; any other value leaves the entry
null and reads nothing further.

**Layer**

```
string  name
u32     clipCount
clipCount × Clip
u32     transitionCount
transitionCount × Transition
```

**State** — a Layer inline, then `u32 field_value`, `string name`, `u64 field_t1`, `u64 field_t2`.
Both 64-bit fields hold the same constant in every served group and read as a fixed-point or
nanosecond duration pair, but nothing in this build pins the unit. Carry verbatim.

**Clip** — `string name`, `u32 kind`, then by kind: nothing, one **AnimRef** inline, or one **Expr**.
Any other kind reads nothing.

**Transition** — `string from`, `string to`, `u64 duration`, `u32 field_a`, `u32 field_b`,
`string var`, `u32 field_c`. `var` is the blend variable that gates the transition (`Attack`,
`AnimMode` in the served data). One boolean inside the object is set locally and is **not** read from
the file.

**AnimRef**

| # | Field | Kind | Notes |
|---|---|---|---|
| 1 | `seqId` | u32 | **a config-seq id** — one served machine's `Idle/Walk/Run/Attack` states resolve through the seq gameval table to `…_bear_pet_idle/_walk/_run/_attack`. Conclusive. |
| 2 | `field_a` | u32 | |
| 3 | `field_b` | u32 | |
| 4 | `field_c` | u32 | a max-int sentinel in every served group |
| 5 | `flag` | u8 | stored as a boolean |
| 6 | `hasOverride` | u8 | stored as a boolean; **if false the record ends here** |
| 7 | *(discarded)* | u32 | only when `hasOverride`; **read and thrown away** — the client never stores it, so a re-encoder must still emit four bytes |
| 8 | `overrideName` | string | only when `hasOverride` |
| 9 | `overrideValue` | u32 | only when `hasOverride` |

**Expr** — a recursive blend tree. `u32 kind`, then one of: a leaf holding one AnimRef; a two-way
blend of `f32, f32`, a variable name, and two child Exprs; a weighted list of `f32, f32`, a variable
name, `u32 n`, and `n` × `{f32 weight, Expr}`; or a four-part form of two strings, a counted list of
`{f32, f32, Expr}`, and a trailing counted list of `u32`. Any other kind is a null node that reads
nothing.

> Decompiler trap worth recording: the weighted-list element loop appears **twice** in the
> decompiled output — once for the have-capacity path and once for the must-grow path of the vector —
> and Ghidra types one copy's four-byte read as `float` and the other as `uint`. It is the same four
> bytes.

**Opaque:** `State.field_value`, both `State` 64-bit fields, `Transition.duration/field_a/field_b/
field_c`, `AnimRef.field_a/field_b/field_c`, the four discarded bytes, the two leading floats on the
blend forms, and the four-part Expr's trailing integer list.

---

## 7. Index 65 — interface animations (`ui_anim`, `ui_anim_curve`)

Owned by the interface manager; the decoded objects are what every `if_anim_*` / `cc_if_anim_*`
clientscript opcode operates on. Two groups, each holding many files, with **disjoint payload kinds
selected by the group id**. Big-endian throughout. [client]

**The two names here are attested, not coined.** Jagex's own gameval tables carry `ui_anim_curve`
and `ui_anim`, and their id sets are *exactly* the file-id sets of this index's two groups. The
curve names also match the geometry of the files they name — `linear` is a straight
`(0,0,0,0)/(1,1,1,1)`, `inout_sine` is `(0,0,0.37,0)/(1,1,0.63,1)` i.e. `cubic-bezier(0.37,0,0.63,1)`,
`ease_out_elastic` carries the >1 overshoot control, `cubic_out` the fast-out control. The upper half
of the curve table duplicates the lower half byte-for-byte, production names beside test names.
[cache]

### 7.1 `ui_anim_curve` — the easing curves

One file is one curve; the **file id is the curve id** the animation presets and the opcodes refer
to.

```
u8 knotCount
knotCount × { f32 knotX, f32 knotY, f32 ctrlX, f32 ctrlY }
```

Each knot carries its point plus **one** control point: the segment from knot *i* to knot *i+1* is
the cubic bezier whose two controls are `knot[i].ctrl` and `knot[i+1].ctrl`. A two-knot curve is
therefore an ordinary CSS-style `cubic-bezier`; the three-knot curves chain two such segments.
[cache]

**Derived, not stored:** a boolean per knot, set when the control point coincides with the knot on
*both* this knot and the previous one, i.e. "the segment ending here is linear".

### 7.2 `ui_anim` — the animation presets

One file is one preset; the **file id is the animation id** the play opcode takes.

```
u8  curveRefKind
    kind 1 ->  u32 curveId          resolved at load to a pointer into the curve table
    kind 2 ->  u32 curveId
               u8  reverseFlag      stored as (byte == 1)
    any other kind -> the record ENDS here and nothing further is read
u8  propertyKind
u8  valueSpaceKind
u16 keyCount
keyCount × N × u32                  N is DERIVED from propertyKind, see below
```

`propertyKind` is an eight-valued property selector. Its **arity is derived by the client, not
stored**: one value selects a three-component property, two values select two-component properties,
and the remaining five select single-component properties. That derivation is what sets how many
32-bit words each keyframe occupies.

This is cross-confirmed by the opcode argument validators, the only other place the two enums are
range-checked: the three-axis ease opcode demands the three-component property exactly, the two-axis
one demands either of the two-component properties, the single-axis one accepts the remaining five
plus the three-component property, and all of them bound `propertyKind` and `valueSpaceKind` to the
same ranges the decoder uses. [client]

`valueSpaceKind` selects how the client reads each 32-bit word. One value means "signed integer
thousandths" and the client multiplies by one thousandth on the way in; the others store the raw
32-bit value. In the served cache the raw spaces carry 0..255 colour channels and signed pixel
offsets, and the scaled space carries fractions. [cache]

**Derived, not stored:** the thousandths scaling, the per-element tag byte the client uses to keep a
track homogeneous, and the resolved curve pointer for the first `curveRefKind`. **Keyframes carry no
timestamp** — the duration comes from the opcode argument and the curve supplies the interpolation.

**Opaque:** the semantic identity of the eight `propertyKind` values and the three `valueSpaceKind`
values; only their arity and scaling behaviour are established.

---

## 8. Index 66 — cutscene 2-D overlays

Big-endian throughout; strings use the same version-prefixed reader as index 61.

Identity is conclusive rather than inferred: the main loop registers the decoder against this
archive, the callback capture holds the cutscene-2D manager, and that manager's play method — the one
the `_cutscene2d_play` opcode drives — looks the decoded record up in its map **keyed by group id**.
So **group id == cutscene id**. (The generic provider sits between the archive handle and the
decoder and dispatches through a hash map, which is why the decoder is not reachable from the
archive handle by cross-reference alone.) [client]

```
u8      version           the decoder accepts exactly one value and skips the whole group otherwise
u16     width             a fixed display width in every served group; the client defaults to the same
u16     height            likewise
u16     subtitleEnumId    a config-enum id; the client's default is the all-ones sentinel
u8      elementCount
elementCount × Element
```

**Element**

```
string  name              the English subtitle line, or an asset/layer label
f32     start             seconds
f32     end               seconds
u8      trackCount
trackCount × Track
u8      soundRefCount
soundRefCount × SoundRef
u8      subtitleRefCount
subtitleRefCount × SubtitleRef
```

Every served element has **exactly one** of the three lists non-empty, but the format permits all
three at once. [cache]

**Track** — an animated image layer

```
string  asset             a .tga file name
u16     srcWidth
u16     srcHeight
u32     graphicId         a graphic id
u8 n, n × { f32 time, f32 value }        scalar channel 1
u8 n, n × { f32 time, f32 value }        scalar channel 2
u8 n, n × { f32 time, f32 x, f32 y }     vec2 channel 1
u8 n, n × { f32 time, f32 x, f32 y }     vec2 channel 2
```

`n == 0` is legal and reads nothing. **Unlike the index-61 curves there is no `n == 1` special
case** — these are plain flat keyframe arrays.

**SoundRef** — `string name` (a `.wav` file name), `u32 soundId`.

**SubtitleRef** — `string key`, `u32 ordinal`, `f32 start`, `f32 end`. `ordinal` is 1-based and
indexes the enum named by `subtitleEnumId`; `key` is either a symbolic key or a verbatim copy of the
English line.

### 8.1 Confirmed id semantics [cache]

* `subtitleEnumId` resolves through the enum gameval table for **all nine** groups, and every one is
  a `*_subtitles` enum that matches its own content — including a group whose only sound reference is
  a `…_duchess.wav` and whose enum is the duchess variant of that scene's subtitle enum.
* `Track.graphicId` resolves through the graphic gameval table to names that match the track's own
  `.tga` asset name.
* `SoundRef.soundId` resolves through the sound gameval table to names that match the ref's own
  `.wav` file name.

### 8.2 Derived, not stored

All playback state, and the localized subtitle text — that lives in the enum named by
`subtitleEnumId`; the strings embedded in the group are the English fallbacks.

### 8.3 Opaque

Which of the two scalar channels is opacity (channel 1 swings between 0 and 1, which reads as a
fade, but that is inference) and which of the two vec2 channels is position versus scale (channel 2
frequently holds a unit pair). `srcWidth`/`srcHeight` where they disagree with the referenced
graphic's real size. `Element.name` on track-only elements, where it is a layer label with no
further use found.

---

## 9. Indices 33 and 35 — populated, and never read

The client never parses them, so nothing here is client-derived. The formats the library decodes
and encodes for both (`LoadingScreenDecoder`, `CutsceneDecoder`) were established from the served
bytes alone and reproduce every archive; `record-index-formats.md` describes them.

### 9.1 The negative result, stated plainly

The client's master-index construction contains the **complete** archive-registration list. Every
JS5 index the client can ever open is registered there, because a read requires a descriptor and
only that one function populates the descriptor registry — all 41 registration call sites live
inside it and nowhere else. **Indices 33 and 35 are absent from it.** There is therefore no parser
for either anywhere in this build, and none should be invented. [client]

Supporting negative results: no string in the binary matches the human-readable text embedded in
index 33; no shader-blob loader and no loading-screen layout reader references either index; and the
per-index availability table gates registration only — it cannot make an unregistered index readable.

Everything below describes **bytes**, with no semantics claimed.

### 9.2 Index 33

Three groups, single-file, and the reference table sets **names only** — no sizes, no uncompressed
CRCs. The three group name hashes were **not** recovered: an exhaustive search over short lowercase
identifiers under the 31-based hash produced only collisions, so the names are longer than eight
characters or use a wider alphabet.

The three payloads are 40, 329 and 4 bytes. The smallest is a single tag byte followed by a 3-byte
value; the 329-byte group opens with a different tag byte and **the same 3-byte value**, which is the
only cross-group regularity. The 40-byte group opens with two small bytes, then fourteen values all
in the range 1..2, then a sentinel and a run of zeros, then a short tail containing two occurrences
of the same 16-bit value and one 24-bit value.

The 329-byte group is a stream of roughly 11-byte entries followed by **three near-identical
blocks**, each of the form: a two-byte prefix, a NUL-terminated ASCII/CP1252 literal
(`Preparing Your Greatest Adventure`), a 32-bit counter that runs 1, 2, 0 across the three blocks, a
byte that runs 4, 5, 3, a fixed ten-byte constant run, a four-byte slot that is zero in the first
two blocks and all-ones in the third, and three trailing zeros. Note the literal is preceded by a
**two**-byte prefix, not the single zero byte that indices 61 and 66 use for their strings.

### 9.3 Index 35

54 groups, single-file, sizes and uncompressed CRCs present, **no** names. Decompressed sizes run
375 to 9437 bytes.

Every group opens with the same six-byte header: a zero byte, two 16-bit values, and an all-ones
byte. Only two headers occur across the index — one pair reads as a 4:3 display shape and the other
as a 16:9 aspect pair — which is suggestive but **not verified**.

After the header comes a **tag-driven variable-length** record stream; no single stride divides any
group length. Its opening section is highly regular: 10-byte entries in groups of four where only
the top nibble of the first byte and one index byte change, the nibble and the index running 0,1,2,3
in lockstep. After those the stream switches to other shapes — a two-byte tag followed by shorter
entries, and in some groups a two-byte tag followed by a six-byte value repeated twice then two
zeros.

### 9.4 How to carry 33 and 35

**Verbatim, as opaque blobs.** Serve the stored group bytes byte-for-byte with their reference-table
CRCs and versions unchanged. Do not attempt to re-encode either index: there is no decoder in the
client to validate against, so the only available correctness criterion is byte identity.
