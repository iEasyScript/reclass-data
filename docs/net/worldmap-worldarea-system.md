# WorldArea / Worldmap system — REBUILD_NORMAL `worldAreaTypeId`

Target binary: `rs2client` **949-1** (Ghidra name `rs2client.949-1`, port 8080). Cross-checked against
`rs2client.948-5`. No `librs2client.so` reference binary was loaded this session; symbol *names* below
come from `re-resources/symbols/parsed_functions.txt` (old build — names only, addresses/offsets do NOT
apply) and every byte-level claim was verified in the 949-1 target unless explicitly flagged otherwise.

TL;DR for the server bug: the `worldAreaTypeId` in REBUILD_NORMAL is a **direct config id into config
group 83** (`WorldAreaType`). The client does **not** recompute it from colours or coordinates — it looks
up `WorldAreaTypeList[worldAreaTypeId]` and builds the entire `jag::game::World` from that type. Send the
wrong id → wrong/empty `WorldAreaType` → the world composites the wrong (or no) map squares → every
non-mainland area (instances, Prifddinas, Menaphos, dungeons, POH, …) fails to assemble. Mainland
"works" only because id 474 happens to be the overworld surface.

---

## 1. `WorldAreaType` config decode (config group / JS5 archive 83)

`jag::game::WorldAreaType::DecodeType` — **verified @ `rs2client.949-1` <addr in DB>** (948-5: <addr in DB>).

Group id confirmed by `jag::game::ConfigProvider::RegisterConfigGroupIds`, which sets the
WorldArea config-type-enum global `_DAT_01692a44 = 0x53` (= **83**). This matches the server's existing
`WorldAreaType` decoder (CONFIGS index 2, archive 83). Loaded eagerly (load-all) via
`ConfigProvider::EnsureTypeListsLoaded`, list slot `ConfigProvider+0x1e0`, list ctor
`jag::game::WorldAreaTypeList::WorldAreaTypeList` (renamed this session), list object 0xb68 B.

The opcode scheme is exactly `{2,3,4}`. All multi-byte reads are big-endian; the g4 packed-coord reader
is `jag::Packet::gT<unsigned_int>` (renamed this session).

| op | wire | client action | stored |
|----|------|---------------|--------|
| **2** | `g3` (3-byte BE, `b0<<16 \| b1<<8 \| b2`) | store verbatim | `this+0x38` (uint) — the **colour** (RGB24). NOT masked, NOT `&`<in Ghidra DB>`-ed (already 24-bit). |
| **3** | two `g4` packed coords A,B | `BuildArea::DecodePackedCoord` each, insert into rbtree `@this+0x70` | rectangle node (0x38 B): `+0x20`=coord A (SW) key, `+0x2c`=coord B (NE, init `0xFFFFFFFF`), `+0x28`=int (the coord's `y`-hi word). Also expands bbox `@this+0xa0`. |
| **4** | one `g4` packed coord + one `g4` int | `DecodePackedCoord` the coord, read the int | rbtree `@this+0x40`; node (0x30 B): `+0x20`=coord key, `+0x28`=int (coord hi-word), `+0x2c`=the int value. Also expands bbox `@this+0xa0`. |

Terminating: `DecodeType` returns the shared success sentinel `&<in Ghidra DB>` (a `DataStatus`), not a
`WorldAreaType*`. The default/empty `shared_ptr<WorldAreaType>` is `&<in Ghidra DB>`.

### Packed coord layout (`jag::game::BuildArea::DecodePackedCoord`
```
plane = (v >> 28) & 0x3
x     = (v >> 14) & 0x3FFF     // absolute tile X
y     =  v        & 0x3FFF     // absolute tile Y
v == 0xFFFFFFFF  => null coord
```
`this+0xa0` bounding box is accumulated in **map-square** units via `x>>6`, `y>>6` (64 tiles = 1 map square).

### `WorldAreaType` struct (partial, verified offsets)
```c
struct WorldAreaType {           // config group 83, list slot ConfigProvider+0x1e0
    /* +0x38 */ uint   colour;   // op2, RGB24 (worldmap fromColour key)
    /* +0x40 */ rbtree op4_coordValues;  // key=packed coord, val=int  (eastl::map<coord,int>)
    /* +0x70 */ rbtree op3_rectangles;   // key=SW packed coord, {NE coord, int}
    /* +0xa0 */ ...    boundingBox;       // min/max map-square, from op3/op4 coords >> 6
};
```
op3/op4 rbtrees are keyed by the packed-coord comparator `<in Ghidra DB>` (an `eastl::less`-style
coord compare; used as the rbtree predicate). rbtree node layout (eastl): `[0]`=child, `[1]`=child,
`[2]`=parent, `[3]`=colour, value at `+0x20`.

---

## 2. REBUILD_NORMAL — how `worldAreaTypeId` is consumed (the answer)

Handler: `jag::PacketHandlers::RebuildNormal` — **** (949-1). ServerProt **op 64**,
var-short. (In 948-5 this was op81; the packed constants below are player-independent and server-supplied.)

### Simple-form body (18 bytes, after the optional GPI-init prefix)
| off | size | type/transform | field | notes |
|-----|------|----------------|-------|-------|
| 0 | 2 | `g2` (u16 BE) | playerX | local-scene X anchor |
| 2 | 2 | `g2_add` (hi raw, lo `+0x80`) | playerY | `(b2<<8) \| (b3+0x80)` |
| 4 | 2 | u16 | (unused by handler) | constant `0x7F00` in captures |
| 6 | 1 | `g1` raw | npcInfoCoordW | stored **raw** to NPC list `+0x428` (949 dropped the 948 byteAdd) |
| 7 | 1 | `g1` raw | magic | **must == 5**, else handler returns early |
| 8 | 2 | `g2` (u16 BE) | **worldAreaTypeId** | direct config-83 id |
| 10 | 4 | `g4` packed coord | worldSouthWest.id | `DecodePackedCoord` → SW corner |
| 14 | 4 | `g4` packed coord | worldNorthEast.id | `DecodePackedCoord` → NE corner |

Matches the server encoder (`writeShort(worldAreaTypeId)`, then the two packed-coord ints).

### The lookup (verified) — NO local getWorldArea computation
```
cfg   = client->configProvider (Client + [reloc 0xca6])
list  = (cfg->fieldAt(0x3c)==4) ? cfg->domains[0x80][ <in Ghidra DB>==83 ]->list : null
sp    = list ? list->vtable[0x40](list, worldAreaTypeId, 0)   // virtual List(id) -> shared_ptr
             : &<in Ghidra DB>                                   // empty shared_ptr<WorldAreaType>
worldAreaPtr = sp[1]     // shared_ptr::get
```
The client then:
1. Compares `worldAreaPtr` to the **active world's** current world-area (`GetActiveWorld`).
   If **equal** → skips the rebuild entirely (`goto` past the teardown) — only camera/positions update.
2. If **different** → tears down all existing worlds/entities, then calls:
```
SceneManager::CreateWorldFromWorldArea(sceneMgr, &sp,
    SW.x>>6, SW.y>>6, NE.x>>6, NE.y>>6)   // map-square rectangle corners
```

### `CreateWorldFromWorldArea` → `World::World` (verified)
`jag::game::SceneManager::CreateWorldFromWorldArea` — **real entry** (949-1; the
`<addr in DB>` alias is the task-queue wrapper). It allocates one `jag::game::World` (`<in Ghidra DB>` B) via
`jag::game::World::World` **** passing the `shared_ptr<WorldAreaType>` and the four
map-square corners, pushes it onto `sceneMgr+0x58` (worlds vector), records index at `sceneMgr+0x70`.

`World::World` stores the corners (949 offsets): swX `+`<in Ghidra DB>`, swY `+`<in Ghidra DB>`-region, neX `+`<in Ghidra DB>`,
neY, then `width=neX-swX @+`<in Ghidra DB>`, `height=neY-swY @+`<in Ghidra DB>`, and allocates the
`(width+1)×(height+1)` grid of 24-byte `MapSquareStatus` cells (vector-of-vectors, outer=X). Cell lookup:
`jag::game::World::GetMapSquare(x,y)` **** = `grid[x-swX][y-swY]`, 0x18-byte stride,
out-of-range → `&<in Ghidra DB>` (null cell).

**So the `WorldAreaType` IS the world.** Its op3 rectangles / op4 per-coord values are what
`World::Build` uses to know which map squares belong to the area and how to composite/remap them
(non-region composite for instanced/multi-surface areas). A wrong `worldAreaTypeId` yields the wrong
`WorldAreaType` (or the empty `&<in Ghidra DB>`), so:
- The world grid is sized to the wrong rectangle, and/or
- The composite pulls the wrong (or no) map-square set from cache.

Mainland surface (id 474) uses the fixed SW `<addr in DB>`=(x1664,y2368)=mapsq(26,37) and NE
`<in Ghidra DB>`=(x4664,y9144)=mapsq(72,142) → a 47×106 grid. Non-mainland areas each have their own
`WorldAreaType` (rectangles + composite) that only assembles when the correct id is sent.

---

## 3. `fromColour` and the worldmap colour grid (index 23 / archive 3) — the friend's `getWorldArea`

This is a **separate subsystem** from §2. §2 (REBUILD → World build) never touches colours; the
`worldAreaTypeId` is authoritative from the server. The colour system exists to (a) render the world-map
UI area overlay and (b) let the server *derive* which `WorldAreaType` id a given tile belongs to.

Verified facts:
- op2 stores a 3-byte value at `WorldAreaType+0x38` (§1). In the entire runtime scene-build path it is
  **not read** — confirming it is a worldmap/derivation concern, consistent with the friend calling it a
  colour.
- `WorldAreaType` is loaded **eagerly (load-all)** and its list object carries an internal hashmap
  (init 0x20 buckets), i.e. a load-time reverse index is structurally present — consistent with a
  `fromColour(colour) -> WorldAreaType` map keyed by the `+0x38` value.

Symbol-level (names from the old dump; **not byte-verified in the loaded 948/949 builds** — the functions
are unnamed there and no reference binary was loaded):
- `jag::game::WorldAreaTypeList::GetAreaColoursForMapSquare(MapSquareWorldAreaCompositeInner&, uint x, uint y)`
  — produces the per-map-square colour grid.
- `jag::game::ClientCompositeData::DecodeFromWorldArea(shared_ptr<WorldAreaType>, shared_ptr<MapSquareWorldAreaCompositeInner>, int, int)`
- `jag::game::World::BuildNonRegionComposite(shared_ptr<MapSquareWorldAreaCompositeInner>&, int, int)`
- LRU cache: `eastl::rbtree<ulong, LRUCacheWrapper<MapSquareWorldAreaCompositeInner>>` keyed by a
  ulong map-square key (96-byte fixed nodes).

### Confidence on the friend's reconstruction

| friend's claim | status |
|----------------|--------|
| Index 23 (WORLD_MAP) archive 3, one file per map square | **plausible/standard**, NOT byte-verified this session |
| RLE grid: `g3` colour then `g1` run-length, fill 64 entries (8×8 zones) | **plausible/standard**, NOT byte-verified |
| `colors[i]==0 -> fallback = final target value` | **UNVERIFIED** — treat as unconfirmed; verify against the actual decoder before relying on it |
| `worldArea = worldAreas.fromColour(colour); mapped[i] = worldArea?.id ?: 1` (default **1**) | reverse map exists structurally; `?: 1` default is **UNVERIFIED** |
| `fromColour` = exact match on the 24-bit colour (not masked) | consistent with op2 storing a full 24-bit value verbatim; exact-match is the natural reading, **not byte-confirmed** |
| file id = `mapSquareX \| (mapSquareY << 7)` | **UNVERIFIED** here; standard RS3 worldmap packing (7 bits/axis). Note the *World* grid (§2) is indexed `[x-swX][y-swY]`, X-major — a different structure. |
| zone index = `(zoneX & 7) * 8 + (zoneY & 7)` | **UNVERIFIED** here; X-major over the 8×8 zones of a map square is the standard convention and matches the `World`-grid X-major ordering, but confirm against `GetAreaColoursForMapSquare` before trusting the axis order. |

Recommended next RE step (needs the reference binary loaded, or deeper archaeology): locate
`GetAreaColoursForMapSquare` in 949 (via the composite LRU / `World::Build`), then byte-verify the RLE
loop bounds, the `colors[i]==0` fallback, the `?: 1` default, and the file-id/zone-index arithmetic.

---

## 4. Discrepancies vs the friend's reconstruction

1. **Two systems, not one.** The friend's `getWorldArea` (colour grid → `fromColour` → id) and the
   REBUILD `worldAreaTypeId` are related but distinct. REBUILD carries a **direct** id; the client never
   recomputes it from colours. The colour path is the *server-side* way to derive which id to send (and
   the client's worldmap-UI path). Do not assume the client validates the sent id against a colour
   computation — it does not; it trusts it verbatim (only comparing against the currently-active area).

2. **op2 default / fallback details unverified.** The friend's `colors[i]==0 -> target` fallback and the
   `?: 1` area-id default are not confirmed in the binary this session. Verify before shipping — a wrong
   default silently mislabels edge zones.

3. **File-id vs World-grid indexing are different mappings.** The worldmap file-id packing
   (`x | y<<7`, if correct) is unrelated to the runtime `World` map-square grid, which is
   `grid[x-swX][y-swY]` (X-major, origin at the REBUILD SW corner). Keep them separate in the server.

4. **op3/op4 semantics.** The friend's model didn't cover op3/op4. They are the coordinate data the
   `World` actually consumes: op3 = a set of packed-coord **rectangles** (SW/NE) with an int; op4 = a set
   of packed-coord → int values. These, plus the bbox `@+0xa0`, are how a `WorldAreaType` describes its
   map-square footprint/remap. If the server needs to emit correct SW/NE corners in REBUILD for a
   non-mainland area, they must match that area's `WorldAreaType` op3/op4 footprint.

---

## Function / address index (949-1 target)

| symbol | addr | status |
|--------|------|--------|
| `jag::game::WorldAreaType::DecodeType` | <addr in DB> | verified, commented |
| `jag::Packet::gT<unsigned_int>` (g4 BE) | <addr in DB> | verified, **renamed** |
| `jag::game::BuildArea::DecodePackedCoord` | <addr in DB> | pre-named |
| coord rbtree comparator | <addr in DB> | verified (not renamed) |
| `jag::PacketHandlers::RebuildNormal` (op64) | <addr in DB> | verified, commented |
| `jag::game::SceneManager::CreateWorldFromWorldArea` (real) | <addr in DB> | verified (wrapper <addr in DB>) |
| `jag::game::World::World` | <addr in DB> | verified |
| `jag::game::World::GetMapSquare` | <addr in DB> | verified |
| `jag::game::ConfigProvider::RegisterConfigGroupIds` | <addr in DB> | verified (WorldArea group = 83) |
| `jag::game::ConfigProvider::EnsureTypeListsLoaded` | <addr in DB> | verified (WorldArea slot +0x1e0) |
| `jag::game::WorldAreaTypeList::WorldAreaTypeList` (ctor) | <addr in DB> | **renamed** |
| WorldArea group-id global `_DAT_01692a44` | <addr in DB> (=0x53) | verified |
| empty `shared_ptr<WorldAreaType>` `<in Ghidra DB>` | <addr in DB> | verified |
| `jag::game::WorldAreaTypeList::CacheReset` | <addr in DB> | verified, **renamed** (sec 5) |
| WorldAreaTypeList LRU-trim (slot 5) | <addr in DB> | commented (name unconfirmed) |
| WorldAreaTypeList derived vtable `PTR_FUN_01420580` | <addr in DB> | verified (9 slots) |
| `jag::game::WorldAreaTypeList` List(id)->shared_ptr (slot 8) | <addr in DB> | verified |
| QuickChat-phrase LRU cache decode (LRU-shell reference) | <addr in DB> | verified, commented |

---

## 5. Colour-grid decode — investigation result (reference binary NOT available)

**Session constraint (read first).** The project cross-version workflow for this task requires the
unstripped reference `librs2client.so` to be loaded in Ghidra (for symbol names + code shape to
sig-scan into 949). **It was NOT loaded this session and there is no MCP tool to load a program into
Ghidra** (that needs a user-opened CodeBrowser). `list_binaries`/`discover_ghidra_instances` show only
`rs2client.949-1` (8080) and `rs2client.948-5` (8081). All work below is 949-target archaeology.
`re-resources/symbols/parsed_functions.txt` (the reference's symbol table) confirms the four target
symbols exist — `WorldAreaTypeList::GetAreaColoursForMapSquare(shared_ptr<MapSquareWorldAreaCompositeInner>&,uint,uint)`,
`ClientCompositeData::DecodeFromWorldArea(...)`, `World::BuildNonRegionComposite(...)`,
`WorldAreaTypeList::{OnLoad,CacheReset}` — but their old addresses do not map to 949.

**Net result: `GetAreaColoursForMapSquare` could not be located in the 949 target this session, so
Q1, Q2 and the Q4 axis order remain UNCONFIRMED.** Q3 is partially confirmed (fromColour map exists);
Q5 is answered structurally. Full detail + a strong reframing below.

### 5.1 `WorldAreaTypeList` runtime object — verified layout (949)

Constructed in `ConfigProvider::EnsureTypeListsLoaded` at the group-83 slot (`ConfigProvider+0x1e0`,
`<in Ghidra DB>=0x53`): `<in Ghidra DB>(0xb68)` then base ctor `WorldAreaTypeList::WorldAreaTypeList`, then derived vtable `PTR_FUN_01420580` is stamped.

| off | field | notes |
|-----|-------|-------|
| +0x00 | vtable | derived `PTR_FUN_01420580` (9 slots) |
| +0x38 | loader strategy | base ConfigTypeList loader (`this+7*8`), set by base ctor |
| +0x48 | base id->type map | eastl `hash_map` (bucketArray init `&<in Ghidra DB>`, 1 bucket) — the id-keyed WorldAreaType store |
| +0x78 | **fromColour reverse map** | eastl `hash_map`, **0x20 buckets** (bucketArray @+0x80). Key = `WorldAreaType+0x38` colour (RGB24). Cleared by CacheReset. |
| +0x70/+0x74 | LRU budget / size | `0x20`/`0x20` init; CacheReset sets size(+0x74)=budget(+0x70) |
| +0xb28 | **composite LRU** | eastl rbtree anchor, `ulong` key = map-square key. Recency list head/tail @+0xb50/+0xb58 (self when empty). Clock/counter @+0xb60. Caches `MapSquareWorldAreaCompositeInner`. |

Derived vtable `PTR_FUN_01420580` slots (verified): `[0]/[1]` dtor `<in Ghidra DB>`/`<in Ghidra DB>`,
`[4]` **CacheReset** `<addr in DB>`, `[5]` LRU-trim `<addr in DB>`, `[8]` `List(id)->shared_ptr`
`<addr in DB>` (the `vtable[0x40]` used by RebuildNormal in sec 2). `GetAreaColoursForMapSquare` is
**non-virtual** (not a vtable slot) and is called directly by `ClientCompositeData::DecodeFromWorldArea`.

`CacheReset` (renamed this session) clears the fromColour map (+0x78) **and** the composite
LRU (+0xb28) and resets the loader — confirming both caches live on this object.

### 5.2 The composite-cache get/decode SHAPE (from the sibling QuickChat cache

`GetAreaColoursForMapSquare` was not found, but its structural sibling — the QuickChat-phrase LRU cache
`<in Ghidra DB>` (callers are `MessageQuickchat*`/`chatphrase_*`, unambiguously chat) — shows the exact
get-or-decode shell these `LRUCacheWrapper<...Inner>` caches use, and it is **not** a fixed RLE:

```
get(out_sharedptr, cache_this, uint key):
  node = rbtree_lookup(cache_this+0x40, key)           // recency list @+0xd10/+0xd20
  if hit: return cached shared_ptr
  file = Js5group[key * 0x20]                           // (*(*(*(this+0x20)+0x10)+0x18)) + key*0x20
  pkt  = jag::Packet(file.data, file.len)
  inner = alloc(0x90); vtable = PTR_FUN_0141f248
  loop:                                                 // OPCODE-based, terminator 0
     op = pkt.g1
     switch(op){ 0: break; 1: ...; 2: ...; 3: ...; 4: ... }
  rbtree_insert(cache_this, key, inner); return
```

The important takeaway: in this engine these per-key composite caches decode with an **opcode loop**,
allocate a `0x90`-byte inner, and fetch a whole Js5 group entry by `key*0x20`. This does **not** resemble
the friend's `g3`+`g1` fixed 64-entry RLE.

### 5.3 Answers

**Q1 — RLE `g3`+`g1` fill-64 loop, terminal condition, stride: UNCONFIRMED, and now doubted.**
`GetAreaColoursForMapSquare` not located. Three independent reasons the friend's
"index 23 / archive 3, per-map-square colour file, `g3` colour + `g1` runlength, fill 64" model likely
does **not** describe the 949 client:
1. Sec 2 already proved the client never recomputes `worldAreaTypeId` from colours — the colour path is
   worldmap-UI/derivation only, so it is not on any hot world-build path (hence hard to reach).
2. The sibling composite caches (5.2) decode via **opcode loops**, not a fixed g3+g1 RLE.
3. A 949 WorldAreaType fully describes its footprint via **op3 rectangles + op4 per-coord values in
   config group 83** (sec 1, re-verified 5.4). The client can derive a per-zone colour grid on the fly by
   testing each zone against op3/op4 coverage and reading the covering type's `+0x38` colour — no separate
   colour-grid cache file needed. The friend's RLE is most likely an artifact of an **older cache-based
   worldmap** revision. **Treat the RLE model as NOT applicable to 949 until the decoder is found.**

**Q2 — `colors[i]==0` fallback: UNCONFIRMED.** Depends on the unlocated decoder / its caller.

**Q3 — colour->area default + fromColour exactness: PARTIALLY CONFIRMED.**
- The `fromColour` reverse map **exists and is exact on the full 24-bit colour**: it is the 0x20-bucket
  eastl `hash_map` @`WorldAreaTypeList+0x78`, and `op2` stores the colour as a full 24-bit value **verbatim
  at `WorldAreaType+0x38`, not masked/quantised** (re-verified in DecodeType 5.4). A generic `hash_map`
  keys on the whole `uint`, so lookup is an exact 24-bit match. This matches the friend's "exact match".
- The `?: 1` (or 0/-1) default id for an unmatched colour is **UNCONFIRMED** — that lives in the fromColour
  caller (`DecodeFromWorldArea`), which was not located.

**Q4 — file-id packing (`x | y<<7`) + zone-index axis order: UNCONFIRMED (critical gap).**
Not verifiable without the decoder. Do NOT ship an axis-order assumption. For reference, the runtime
`World` map-square grid is **X-major** (`grid[x-swX][y-swY]`, sec 2), but the worldmap colour-grid
zone-index is a **separate** structure and its axis order is not confirmed here. This must be resolved by
loading `librs2client.so` and sig-scanning `GetAreaColoursForMapSquare` into 949 (the intended workflow).

**Q5 — REBUILD SW/NE vs op3/op4 bbox; op3 remap vs inclusion: ANSWERED (structural).**
- A `WorldAreaType` maintains a bounding box @`this+0xa0`, accumulated from **both** op3 and op4 coords in
  **map-square units** (`coord.x>>6`, `coord.y>>6`) via `<in Ghidra DB>(this+0xa0, ...)` (re-verified 5.4).
  This bbox is exactly the min/max of the type's op3/op4 footprint.
- **op3 is an INCLUSION-rectangle set, not a src->dst two-pair remap.** Each op3 entry (rbtree @`type+0x70`,
  0x38-byte node) holds `{coordA(SW) key @+0x20, coordB(NE) @+0x2c (init 0xffffffff), int @+0x34}` — one
  rectangle (SW..NE) plus one int. There is no second coord-pair for a destination; any instancing/remap is
  carried by the int (plane/level/rotation), not by op3 encoding a dst rectangle.
- **op4** (rbtree @`type+0x40`, 0x30-byte node) = `{coord key @+0x20, int @+0x2c}` — a per-coord value.
- The client does **not** derive REBUILD SW/NE from the type (they are server-supplied packed coords, sec 2).
  But `type+0xa0` **is** the natural source: the mainland (474) SW=(1664,2368)/NE=(4664,9144) should equal
  `min`/`max` over 474's op3/op4 tile coords (i.e. `type+0xa0` bbox × 64). **Server recipe for non-mainland
  areas: SW = min over the type's op3/op4 coords, NE = max** (in tiles). 474's actual op3 data was not dumped
  (needs the live cache / a runtime read) — the arithmetic identity is inferred from the verified bbox
  accumulation, not from a byte-diff of 474.

### 5.4 Re-verified this session (DecodeType, byte-exact)

- `op2`: `g3` (`b0<<16 | b1<<8 | b2`) -> `WorldAreaType+0x38`, verbatim (no mask).
- `op3`: two `g4` packed coords (A=SW, B=NE) via `DecodePackedCoord`; 0x38-byte rbtree node into
  `type+0x70` keyed by A@+0x20; B stored @+0x2c, int @+0x34; bbox `type+0xa0` expanded from A (`>>6`).
- `op4`: one `g4` packed coord + one `g4` int; 0x30-byte rbtree node into `type+0x40` keyed by coord@+0x20;
  int @+0x2c; bbox `type+0xa0` expanded (`>>6`).
- coord comparator = `<in Ghidra DB>`; `g4` = `jag::Packet::gT<unsigned_int>`.

### 5.5 Exact next step to close Q1/Q2/Q4

Load `librs2client.so` in a Ghidra CodeBrowser, then:
`decompile_function(name="jag::game::WorldAreaTypeList::GetAreaColoursForMapSquare", binary_name="librs2client.so")`
to read the decode shape, take ~16 body bytes (wildcard `E8`/`48 8B 05` immediates),
`search_memory_pattern` into `rs2client.949-1`, confirm, then byte-verify the 64-fill loop bounds, the
`colors[i]==0` fallback, the fromColour default id, and the file-id/zone-index axis order against the 949
body. Same for `ClientCompositeData::DecodeFromWorldArea` and `World::BuildNonRegionComposite`.

---

## 6. Server-side resolution — verified against the live 949-1 cache

The binary decoder (Q1/Q2/Q4) couldn't be reached in the stripped 949 body, but every open item was
settled empirically by decoding the live cache (`data/cache`, 949-1) and cross-checking against the one
known live capture (mainland area 474 rebuild: SW=(1664,2368) NE=(4664,9144)). These are the answers the
server implementation is built on.

### 6.1 WorldmapSquareType — index 23 (WORLD_MAP), archive 3

- **One file per map square**, file id = `mapSquareX | (mapSquareY << 7)` (7 bits/axis) — same packing as
  the MAPS index. **Verified:** area 474's colour-grid X bounding box (`1664..4664`) matches the live
  rebuild's X corners *exactly*; 5144 files, ids 132..25387, decode cleanly.
- **Body = RLE colour grid of 64 zones** (8×8 per map square): repeat { `g3` 24-bit colour; if bytes
  remain, `g1` run-length delta advancing a fill cursor, else fill to 64 } until 64 filled. Confirmed by
  clean decode of all 5144 files (max 7 distinct colours in one square; 307 multi-colour border squares).
- **Zone-index axis order = X-major: `index = (zoneX & 7) * 8 + (zoneY & 7)`.** Settled by a cross-square
  edge-continuity test over the whole map: X-major beats the transpose on both horizontal (23002 vs 22151)
  and vertical (22367 vs 21523) shared-edge matches. Consistent with the runtime `World` grid X-major
  ordering and the MAPS decoder's X-outer loop.

### 6.2 Colour → area id (`fromColour`)

- **Exact match on the full 24-bit `WorldAreaType` op2 value** (RE-confirmed: verbatim at `+0x38`, the
  list carries a 0x20-bucket hash_map @`WorldAreaTypeList+0x78`). 864 distinct colours over 865 areas
  (1 collision — resolved lowest-id-wins server-side; negligible).
- **Unmapped / colour-0 default → area id 1.** Only `0x0` is unmapped, appearing in just 2 squares; a
  colour-0 zone therefore resolves to 1 (matches the friend's `?: 1`). The friend's separate
  `colors[i]==0 -> target` pre-step is redundant here — both paths yield "no match → 1" for the only case
  that occurs, so the server omits it.

### 6.3 REBUILD_NORMAL SW/NE corners — do NOT derive from the WorldAreaType

The op3/op4 footprint recipe from §5.3 is **refuted** by the cache: 474's op3/op4 tile bbox is
`(2176,2536)-(3896,4224)`, but the live rebuild sends the larger `(1664,2368)-(4664,9144)` — the full
surface-0 rectangle, not the area's own footprint. So SW/NE is a **fixed surface bound**, not area-derived;
the server keeps its configured world bounds (env `WORLD_BOUNDS_*`, defaulting to the live mainland
rectangle) and only the `worldAreaTypeId` varies per zone. Non-mainland surfaces whose map squares fall
inside that rectangle (e.g. Darkmeyer at mapsq ~49,108) then assemble correctly once the *right* id is sent.

### 6.4 The server fix

`Cache.worldAreaTypeAt(x, y)` = decode the worldmap square `(x>>6, y>>6)`, read zone `(x>>3)&7, (y>>3)&7`
from its 64-entry grid → area id. `SceneBuilder` already feeds this into REBUILD_NORMAL's `worldAreaTypeId`.
This replaces the old largest-bounding-box heuristic that returned 474 (mainland) for essentially every
tile — the reason non-mainland areas never assembled. Spot-checks: Lumbridge/Burthorpe/Varrock → 474,
Darkmeyer → 662, Anachronia → 433.

**Still open (needs `librs2client.so` loaded):** byte-level confirmation of the client's own decoder for
Q1/Q2/Q4, and a live capture from a *non-mainland* surface to confirm its SW/NE handling. The server-side
derivation above is cache-verified and self-consistent, but the client-decoder byte-match remains the
belt-and-suspenders check.

---

## 7. Composite vs plain-surface areas + the uncovered-tile fallback

Verified from the live 949-1 cache (config group 83 op3/op4 presence):

- **41 of 865 WorldAreaTypes are composites** (have op3 rectangles / op4 points) — e.g. area **474** = the
  main overworld surface (49 rects, 1517 points). A composite's `World::Build` only assembles the squares
  its op3/op4 reference; a tile outside that set renders as nothing even if MAPS terrain exists there.
- **823 are plain surfaces** (no op3/op4) — e.g. area **1** (colour `<in Ghidra DB>`), Darkmeyer **662**,
  Anachronia **433**. A plain surface region-builds the *literal* MAPS squares over the REBUILD SW/NE.

**Worldmap colour grid (archive 3) is sparse.** It covers msx≈1..98, msy≈1..198, but has genuine gaps
inside covered territory — e.g. mapsq (65,51) (tile 4186,3302) has MAPS terrain but no colour file; its one
covered neighbour (64,50) maps to area 1. For such tiles `worldAreaTypeAt` returns null.

**Fallback fix.** The old fallback for an uncovered tile was area **474** — but 474 is a *composite* that
omits any square outside its footprint, so off-worldmap overworld regions never assembled. The fallback is
now the plain default surface **area 1** (`WORLD_AREA_TYPE_FALLBACK`, env-overridable), which region-builds
whatever literal terrain exists. This only affects tiles with no colour file (mainland is colour-covered and
unaffected). **Still worth a live capture** to confirm the exact id the real server sends in these gaps.

**Also fixed:** the worldmap file-id must NOT mask `mapSquareY` (`id = (msx & 0x7f) | (msy << 7)`); msy runs
0..~198 (far north above tile-y 8192), so masking to 7 bits mis-resolved northern squares.

---

## 8. REBUILD_NORMAL SW/NE corners — the general rule (capture-verified)

Verified against 8 authentic REBUILD_NORMAL captures (op64) spanning mainland, far-north, far-east,
Mazcab, and single-square instance areas. Parse of the fixed 18-byte body tail confirms:
`[8..9] worldAreaTypeId g2`, `[10..13] SW packed`, `[14..17] NE packed` (packed = plane<<28 | x<<14 | y).

**Rule:** `SW/NE = the map-square-snapped UNION of (a) the area's worldmap colour-grid zone bounding box
and (b) the area's op3/op4 coordinate bounding box`:
```
minX/minY/maxX/maxY = union over { every zone tile (msx*64+zx*8, msy*64+zy*8) whose colour maps to the area }
                                ∪ { every op3 rect corner and op4 point coord of the area }
SW = (minMapSqX*64,  minMapSqY*64)                 // floor to map square
NE = (maxMapSqX*64 + 56, maxMapSqY*64 + 56)        // zone-7 base of the max map square
```
The client only uses `SW>>6`/`NE>>6` (map-square corners), so the `+56` low bits are cosmetic but match
the wire exactly.

Neither source alone suffices — both are required:
- **Plain-surface areas** (no op3/op4: 243, 368, 415, 435, 765) → colour-zone bbox IS the answer.
- **Composite areas** → the union: **474** (mainland) is colour-zone-dominant (op3/op4 covers only
  Misthalin/Asgarnia; the colour grid supplies the full 26,37..72,142 overworld); **762** is
  op3-dominant (op3 reaches east of its colour footprint). **474's computed bounds equal the old
  `WORLD_BOUNDS_*` env values exactly** — so this generalization is zero-regression for the mainland.

Result vs the 8 captures: **7/8 byte-exact, 1 safe superset** (857: our SW.x is 3 map squares wider —
still contains the player and all composite squares, since the grid origin only needs to be ≤ all content).

**Implementation:** `Cache.worldAreaBounds(id)` (lazy one-pass scan of index-23/archive-3 building a
per-area extent map, merged with op3/op4). `SceneBuilder` now sends these bounds for every area, falling
back to the env-widened scene only when the tile has no worldmap coverage at all.

**KEY correction to earlier sections:** the worldAreaTypeId derivation (colour grid → id) was already
correct; the actual login-fails-outside-mainland bug was the SW/NE corners — we were sending the fixed
mainland rectangle for every area, which clipped any separate surface (e.g. Mazcab area 857 at y≈1152–2040,
south of the mainland box) so its world could not assemble.

### 8.1 op3 corner2 is a per-area anchor — exclude it from bounds

Each op3 rect decodes to two coords; **corner2 is a single constant value per area** (rbtree node value,
not a rect corner) — 474→(2176,3968), 762→(5696,2560), 857→(3008,1344). Including it wrongly pulls the
bbox toward that anchor (broke area 857: SW.x 3008/mapsq47 vs authentic 3200/mapsq50). Using **corner1
only** (the rbtree key, which varies) unioned with the colour-zone bbox reproduces authentic **8/8 byte-
exact**. `Cache.worldAreaExtents` accumulates op3 corner1 + op4 coords + colour zones, never op3 corner2.
Verified: `Tile(3200,1152).id = `<in Ghidra DB>` and `Tile(3960,2040).id = `<in Ghidra DB>` match the wire exactly.
