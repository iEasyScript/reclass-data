# ServerProt: ClientState Category

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

## Overview

The ClientState packet handler category manages map rebuilds, world entity operations, minimap toggling, zone data lifecycle, and connection state flags. The primary constructor is at `<addr in DB>` (`jag::packethandlers::ClientState::ClientState`), which binds 12 lambda handlers to ServerProt globals in the address range `<addr in DB>` - `<addr in DB>`. An additional 4 ClientState handlers (CLEAR_PENDING_UPDATES, DESTROY_ZONE_DATA, RESET_CLIENT_STATE, UPDATE_ZONE_PARTIAL) are registered by the Variables constructor at `<addr in DB>`. Two more handlers (SET_TICK_TIMER, SET_READY_FLAG) are registered inline in `BindHandlers` (<addr in DB>).

All handlers follow the standard ServerProt invocation pattern:
- Called via `ServerProt.invokePtr(ServerProt.callableData, Packet*, &packetSize)`
- `callableData` contains a pointer to the Client struct
- Return value: `&<in Ghidra DB>` (success), `&<in Ghidra DB>` (yield), `&<in Ghidra DB>` (error)

## ServerProt Opcode Table

| Opcode | Size | Handler Name | Handler Address | ServerProt Global |
|--------|------|--------------|-----------------|-------------------|
| 22 | 2 | SET_TICK_TIMER | `<addr in DB>` | `<addr in DB>` |
| 32 | 0 | RESET_CLIENT_STATE | `<addr in DB>` | `<addr in DB>` |
| 35 | 0 | SET_READY_FLAG | `<addr in DB>` | `<addr in DB>` |
| 65 | var-byte | UPDATE_ZONE_PARTIAL | `<addr in DB>` | `<addr in DB>` |
| 104 | 0 | DESTROY_ZONE_DATA | `<addr in DB>` | `<addr in DB>` |
| 129 | 6 | SET_MAP_FLAG | `<addr in DB>` | `<addr in DB>` |
| 142 | 1 | WORLDENTITY_INFO_V4 | `<addr in DB>` | `<addr in DB>` |
| 151 | 3 | MINIMAP_TOGGLE | `<addr in DB>` | `<addr in DB>` |
| 153 | 2 | WORLDENTITY_INFO_V2 | `<addr in DB>` | `<addr in DB>` |
| 156 | 6 | WORLDENTITY_INFO_V1 | `<addr in DB>` | `<addr in DB>` |
| 157 | 3 | WORLDENTITY_INFO_V3 | `<addr in DB>` | `<addr in DB>` |
| 178 | var-short | REBUILD_WORLDENTITY | `<addr in DB>` | `<addr in DB>` |
| 186 | var-short | REBUILD_NORMAL | `<addr in DB>` | `<addr in DB>` |
| 191 | 2 | CLEAR_MAP_FLAG | `<addr in DB>` | `<addr in DB>` |
| 206 | 0 | CLEAR_PENDING_UPDATES | `<addr in DB>` | `<addr in DB>` |
| 208 | 3 | WORLDENTITY_INFO_V5 | `<addr in DB>` | `<addr in DB>` |
| 211 | 5 | REBUILD_REGION | `<addr in DB>` | `<addr in DB>` |
| 215 | 3 | REORDER_MAP_FLAG | `<addr in DB>` | `<addr in DB>` |

## Key Data Structures

### Build Area Entry (0x68 bytes)

World entity build data is stored in a vector of 0x68-byte entries. Each entry represents a world entity's map configuration:

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0x00 | 8 | long* | Unknown pointer |
| 0x08 | 8 | long* | Region tile data (allocated array) |
| 0x20 | 24 | vector<uint> | Zone IDs (map square identifiers) |
| 0x38 | 24 | vector<int> | Sort order indices (-1 = unset, 0xFFFFFFFF = sentinel) |
| 0x50 | 24 | vector<xor_group> | XOR group data (0x18 per entry, nested uint arrays) |

### Zone Data Object (0x38 bytes)

Allocated by RESET_CLIENT_STATE and stored at `ClientVarDomain+0x5238`:

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0x00 | 8 | void** | Vtable pointer (`PTR_FUN_01493600`) |
| 0x08 | 8 | void* | Map data structure |
| 0x10 | 8 | void* | Secondary data pointer (`<in Ghidra DB>`) |
| 0x18 | 8 | long | Reference count (initialized to 1) |
| 0x20 | 8 | - | Zero-initialized |
| 0x28 | 8 | float[2] | `{1.0f, 2.0f}` (packed as `<in Ghidra DB>`3f800000) |
| 0x30 | 4 | int | Zero-initialized |

---

## Handler Reference

### Map Rebuild Operations

#### RESET_CLIENT_STATE (opcode 32, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:** No data (zero-length packet).

**Behavior:** Allocates a new zone data object (0x38 bytes) with vtable `PTR_FUN_01493600`, initializes it with default values (reference count = 1, float pair = {1.0, 2.0}), and stores it at `ClientVarDomain+0x5238`. If a previous zone data object exists, calls its destructor via `vtable+0x08`.

---

#### DESTROY_ZONE_DATA (opcode 104, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:** No data (zero-length packet).

**Behavior:** Clears the zone data object pointer at `ClientVarDomain+0x5238` to zero. If the previous pointer was non-null, calls the destructor via `vtable+0x08`. This is the inverse of RESET_CLIENT_STATE.

---

#### REBUILD_NORMAL (opcode 81, size varShort) — 948-5

> The previous entry in this file (opcode 186, "build-area count" loop) was an old-build format and is
> WRONG for 948-5. The 948-5 body is a fixed 18-byte header. Verified in rs2client 948-5.

**Handler:** `jag::PacketHandlers::RebuildNormal | ProtEntry `<addr in DB>`

On the first scene rebuild after (re)login the 18-byte header is preceded by the bit-packed GPI
player-position init block (consumed by `PlayerList::HandleAbsolutePlayerPositions
when `ConnectionManager(Client+`<in Ghidra DB>`)+0x49` is set); subsequent rebuilds are the 18-byte header
alone. See the Ghidra DB.

**18-byte header (real byte offsets, read order derived from the handler disassembly):**

| Off | Size | Wire | Server write | Client read | Field | Notes |
|-----|------|------|--------------|-------------|-------|-------|
| 0 | 1 | pad | p1 | (skipped) | — | consumed, value unused |
| 1..2 | 2 | LE u16 | p2LE | g2LE | playerZoneX | scene-base zone; baseTile = (zone-16)*8 |
| 3 | 1 | 0x85 | p1 | g1 (== 0x85) | MAGIC | equality check ONLY (`@`<in Ghidra DB>`); mismatch -> PacketError. Not a size. |
| 4..5 | 2 | BE u16 | p2 | g2 | playerZoneY | scene-base zone; baseTile = (zone-16)*8 |
| 6 | 1 | v+0x80 | p1_add | g1_add | npcInfoCoordBitWidth | `(raw-0x80)&0xff` -> `NpcManager(Client+`<in Ghidra DB>`)+0xc0e8`; NPC-info local-coord bit width |
| 7 | 1 | pad | p1 | (skipped) | — | consumed, value unused |
| 8..9 | 2 | BE u16 | p2 | g2 | **worldAreaType** | `jag::game::WorldAreaType` cache config id (see below) |
| 10..13 | 4 | BE u32 | p4 | g4 | worldAreaSW | packed coord -> SW map-square corner |
| 14..17 | 4 | BE u32 | p4 | g4 | worldAreaNE | packed coord -> NE map-square corner |

`centerOffset = Camera(Client+`<in Ghidra DB>`)[0x610] >> 4`. `Camera[0x610]` is a fixed `0x100` (256) set only
by the Camera ctor and never written elsewhere in `.text`, so `centerOffset = 16` (constant) for both
overworld and instances. Scene size is not sent. playerZoneX/Y are stored symmetrically into one 64-bit
scene-base word at `Camera+0x608` by `SetSceneBase (<in Ghidra DB>)`; the handler does not distinguish X
from Y (the X-then-Y labels above follow the working server layout).

**worldAreaType (body[8..9], BE u16) — client usage (hard evidence):**

Read at `<addr in DB>` (`MOVZX R8D, word [R11]` + `ROL R8W,8`), stored to `local_6a` / `[RSP+0x1e]`.
Observed: 474 (0x01da) overworld surface, 674 (0x02a2). At `<addr in DB>`-`<addr in DB>`:

1. Zero-extended (`MOVZX`), no arithmetic, passed as the `id` arg to a virtual call
   `[vtable+0x40](list, worldAreaType, 0)`.
   - `list` = configProviderRegistry(`Client+`<in Ghidra DB>`)`[+0x80]` array `[ordinal <in Ghidra DB> = 0x53]` `-> [+0x38]`.
   - `[vtable+0x40]` == `jag::game::ConfigTypeListLoadAll<WorldAreaType>::List(int id, DataStatus** = null)`
     — returns the `shared_ptr<jag::game::WorldAreaType>` for that id by indexing `list+0x58` at `id*0x10`.
2. The returned `shared_ptr<WorldAreaType>`:
   - region `[ret+8]` is compared to the current renderer's bound region (`renderer+`<in Ghidra DB>`): equal -> skip
     rebuild (`LAB_`<in Ghidra DB>`); else teardown + rebuild.
   - is passed to `jag::game::SceneManager::CreateWorldFromWorldArea(sharedPtr, swMapSqX, swMapSqY,
     neMapSqX, neMapSqY), which builds a `jag::game::World` (`World::World`) over the
     map-square rectangle, storing the WorldAreaType as that World's area definition.

So worldAreaType is a **raw `WorldAreaType` cache config id / lookup key** (turned into an `id*0x10` array
index inside `List`) — NOT coordinates, NOT a bitfield, NOT a worldId/instance id. `WorldAreaType` is a
genuine cache config type: `WorldAreaType::DecodeType` opcodes 2 (g3 field), 3 (CoordGrid->CoordGrid
map-square remap rbtree), 4 (CoordGrid->int + composite map-square set) — it defines which/how map-squares
compose the area (overworld and instanced areas). `0x53` is the runtime-assigned config-provider ordinal,
not the JS5 archive index. No `worldarea` gameval dictionary exists (internal config, unnamed).

**worldAreaSW / worldAreaNE (body[10..17], two BE u32 packed coords) — client usage:**

Each is decoded by `game::BuildArea::DecodePackedCoord(v) ->
`{plane=(v>>28)&3, x=(v>>14)&0x3FFF, y=v&0x3FFF}` (v == 0xFFFFFFFF -> null coord). The two coords'
`x>>6, y>>6` (tile -> map-square) become the SW (min) and NE (max) map-square corners passed to
`CreateWorldFromWorldArea`; `World::World` allocates a `(neX-swX+1) x (neY-swY+1)` grid of
`jag::game::MapSquareStatus` cells. Together they are the world area's inclusive map-square bounding
rectangle. Surface-login observed: SW `<addr in DB>` = tile(1664,2368) = mapsq(26,37); NE `<in Ghidra DB>` =
tile(4664,9144) = mapsq(72,142) -> a 47x106 map-square grid. Player-independent, server-supplied.

---

#### REBUILD_REGION (opcode 211, size 5)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| 4 bytes (custom LE) | uint | Map square ID (byte-swapped: b0*0x100 + b2*`<in Ghidra DB>` + b3*`<in Ghidra DB>` + b1) |
| g1_sub128 | byte | Build area index (-128 transform) |

**Behavior:** Rebuilds a single region within an existing build area. Reads the map square ID with a custom 4-byte little-endian ordering, then calls `<in Ghidra DB>` (load map) + `<in Ghidra DB>` (finalize) targeting the specific build area index. Used for incremental map updates when moving between regions.

---

#### REBUILD_WORLDENTITY (opcode 178, size var-short)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| Triple-nested loop (sentinel-terminated, -1 = 0xFF) | | |
| Outer: g1 | byte | World entity index (-1 = end) |
| Middle: g1 | byte | Zone index (-1 = end) |
| Inner: g1 | byte | Tile index (-1 = end) |
| Per tile: g4 BE | uint | Tile data value |

**Behavior:** Populates world entity location data using a triple-nested sentinel-terminated loop. For each (worldEntity, zone, tile) triple, reads a big-endian 4-byte value and stores it in the XOR group data array at `buildArea[worldEntity].xorGroup[zone][tile]`. Uses endianness-aware decoding (checks `<in Ghidra DB> == `<in Ghidra DB>` for little-endian).

---

### World Entity Management

#### WORLDENTITY_INFO_V1 (opcode 156, size 6)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_sub128 | byte | Insertion position (-128 transform, -1 = append) |
| g1 | byte | World entity index |
| g4 BE | uint | Map square ID (big-endian) |

**Behavior:** Adds a map square to a world entity's zone vector (+0x20). Inserts at the specified position (or appends if position is -1). Also inserts a sentinel sort entry (-1) at the corresponding position in the sort array (+0x38), and allocates a new XOR group data entry (+0x50). After insertion, re-validates sort indices by calling `<in Ghidra DB>` for any out-of-order entries.

---

#### WORLDENTITY_INFO_V2 (opcode 153, size 2)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_add128 | byte | Position (+128 transform) |
| g1_sub128 | byte | World entity index (-128 transform) |

**Behavior:** Removes a map square from a world entity. Removes the entry at the specified position from the zone vector (+0x20), sort array (+0x38), and XOR group data (+0x50) using memmove to shift remaining entries. Frees the removed XOR group's allocated memory. After removal, re-validates sort indices.

---

#### WORLDENTITY_INFO_V3 (opcode 157, size 3)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_sub128 | byte | Position (-128 transform) |
| g1 | byte | World entity index |
| g1 | byte | Flag value |

**Behavior:** Sets a sort order entry for a world entity. If the flag byte equals `0x7F`, sets the sort value to the position index; otherwise sets it to -1 (effectively clearing the entry). Writes to the sort array at `buildArea[worldEntity].sortArray[position]` (offset +0x38).

---

#### WORLDENTITY_INFO_V4 (opcode 142, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1s | byte (signed) | World entity index |

**Behavior:** Removes an entire world entity from the build area vector. Reads the index as a signed byte, then shifts all entries after the removed one in the 0x68-sized entry vector (using element-by-element copy and swap), freeing sub-arrays (zone IDs, sort indices, XOR groups) for the removed entry. Decrements the vector size by one entry (0x68 bytes).

---

#### WORLDENTITY_INFO_V5 (opcode 208, size 3)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_sub128 | byte | Position (-128 transform) |
| g1 | byte | Unknown parameter |
| g1_add128 | byte | World entity index (+128 transform) |

**Behavior:** Reorders world entity data entries. Calls `<in Ghidra DB>` to swap/reorder entries at the given positions, then iterates the sort array and updates all non-sentinel entries to sequential indices (0, 1, 2, ...), ensuring sort order consistency after the reorder.

---

### Map Flag Operations

#### SET_MAP_FLAG (opcode 129, size 6)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1 | byte | World entity index |
| g1_sub128 | byte | Insertion position (-128 transform, -1 = append) |
| 4 bytes (custom LE) | uint | Map ID (3-byte LE packed: b0 + b1*0x100 + b2*`<in Ghidra DB>` + b3*`<in Ghidra DB>`) |

**Behavior:** Adds a region map square to a world entity. Checks for duplicates and maximum capacity (8 entries, 0x20 bytes at 4 bytes each). Inserts into the region vector (+0x08/+0x10/+0x18) at the specified position. Also inserts sentinel entries (`<in Ghidra DB>`) into all parallel XOR group data arrays (+0x50) at the corresponding position, growing them with reallocation as needed.

---

#### CLEAR_MAP_FLAG (opcode 191, size 2)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_add128 | byte | Position (+128 transform) |
| g1_sub128 | byte | World entity index (-128 transform) |

**Behavior:** Removes a region map square from a world entity. Removes from the region vector (+0x08) using memmove, then iterates all parallel XOR group arrays (+0x50) and removes the corresponding element from each, shrinking them.

---

#### REORDER_MAP_FLAG (opcode 215, size 3)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_add128 | byte | New position (+128 transform) |
| g1 | byte | Old position (negated) |
| g1_sub128 | byte | World entity index (-128 transform) |

**Behavior:** Reorders a region map square within a world entity. Removes the entry at the old position from the region vector (+0x08) and reinserts it at the new position. Also performs the same remove+reinsert operation on all parallel XOR group data arrays (+0x50), preserving the values during the move.

---

### Zone Operations

#### UPDATE_ZONE_PARTIAL (opcode 65, size var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g2 BE | ushort | Zone type ID (big-endian, byte-swapped on LE) |
| (variable) | - | Zone-type-specific data (read via virtual call) |

**Behavior:** Partial zone update. If no zone data object exists at `ClientVarDomain+0x5238`, creates one (same as RESET_CLIENT_STATE). Looks up the zone type config from a type manager via virtual call (`vtable+0x40`), then reads zone data from the packet via another virtual call (`vtable+0x20`) on the type's reader object. Stores the result in the zone data map. Tracks modified zone IDs in a circular buffer at `ClientVarDomain+0x88/0x90` (64-entry ring buffer, 4 bytes per entry).

---

#### CLEAR_PENDING_UPDATES (opcode 206, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:** No data (zero-length packet).

**Behavior:** Iterates over pending client var updates stored in a vector at `ClientVarDomain+0x5170/0x5178`. Each update entry is 0x28 bytes with a type byte at offset 0x20. For each entry, if the type is not 4 (unset) or 0xFF, calls a type-specific cleanup function from a dispatch table at `PTR_FUN_014ada60`. Resets the type to 4 (unset). After processing all entries, sets the update count at `ClientVarDomain+0x5188` to zero and resets the vector end pointer to match the start.

---

### Minimap

#### MINIMAP_TOGGLE (opcode 151, size 3)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1_sub128 | byte | Position 1 (-128 transform) |
| g1_sub128 | byte | Position 2 (-128 transform) |
| g1_sub128 | byte | World entity index (-128 transform) |

**Behavior:** Sets a visibility/toggle flag in a world entity's XOR group data. Writes the sentinel value `<in Ghidra DB>` at `buildArea[worldEntity].xorGroup[pos1][pos2]`, effectively clearing/hiding that entry. Used to toggle minimap tile visibility for specific world entity positions.

---

### Connection State

#### SET_TICK_TIMER (opcode 22, size 2)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g2 BE | ushort | Timer value (big-endian, byte-swapped on LE) |

**Behavior:** Sets the client's tick timer duration. Reads a 2-byte unsigned short, then multiplies by a state-dependent factor:
- **Game state 0x14** (loading/in-game): `(value * 5 * 5) / 10` = effectively `value * 2.5` (rounded to integer)
- **Other states**: `value * 30`

The computed duration is stored at `ConnectionManager+0x0C`. After setting the timer, copies a counter from the connection state at `ClanManager+0xF8 → +0x10` into `ClanManager+0x100`.

**Client References:**
- `__DT_SYMTAB[0x4dc]`: Game state check (== 0x14 for loading/in-game)
- Connection manager pointer: via `__DT_SYMTAB` offset from client
- `__DT_SYMTAB[0x49c]`: Clan system manager (counter sync)

---

#### SET_READY_FLAG (opcode 35, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:** No data (zero-length packet).

**Behavior:** Sets a ready/loaded flag to 1. This is a minimal handler that reads no packet data:

1. Sets `*(int*)(readyFlagPtr + 0x10) = 1` (via `__DT_SYMTAB[0x49a]`)
2. Copies a counter from `ClanManager+0xE8 → +0x10` into `ClanManager+0xF0`

The ready flag likely signals to the server that the client has finished processing a map rebuild or state transition.

**Client References:**
- `__DT_SYMTAB[0x49a]`: Ready flag structure (+0x10 = flag value)
- `__DT_SYMTAB[0x49c]`: Clan system manager (counter at +0xE8/+0xF0)

---

## Byte Transform Reference

Many handlers apply byte transforms when reading single-byte values:

| Transform | Formula | Description |
|-----------|---------|-------------|
| g1_sub128 | `value - 128` (equivalently `0x80 - value`) | Subtracts 128, used for signed-range encoding |
| g1_add128 | `value + 128` (equivalently `value + 0x80`) | Adds 128 |
| g1s | Signed byte cast | Reads as signed char, sign-extended to int |
| g1 (negated) | `-(value & 0xFF)` | Negates the unsigned byte |

These transforms are RuneScape's standard packet obfuscation for single-byte values, making raw packet captures harder to interpret without knowing the specific handler.
