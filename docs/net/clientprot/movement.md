# ClientProt: Movement Packets

> **Rev 947-1**: Opcodes and many sizes changed significantly from 946. See `clientprot-table.md` for the 947-1 table.

Packets related to player movement, including minimap clicks and game-world walking.

## MOVE_GAME (Primary Movement)

### MOVE_GAME (Standard)
| Field | Description |
|-------|-------------|
| **Opcode** | 102 |
| **Size** | VAR_SHORT |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |
| **Category** | Movement |

This is the primary movement packet sent when the player clicks to walk/run in the game world. It is VAR_SHORT sized because it can contain a variable-length path.

**Packet Format:**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 2 | ushort | pathLength | Number of path waypoints (x4 bytes each) |
| 2 | N*4 | int | waypoints | Packed coordinate waypoints |
| varies | 1 | byte | runFlag | 0 = walk, 1 = run (ctrl-click) |

### MOVE_GAME (From Minimenu)
| Field | Description |
|-------|-------------|
| **Opcode** | 33 |
| **Size** | 5 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |
| **Category** | Movement |

Simplified movement packet sent when clicking an action in the minimenu that requires walking to a location. Fixed 5-byte format.

**Packet Format (5 bytes):**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 2 | ushort | destX | Destination X coordinate |
| 2 | 2 | ushort | destY | Destination Y coordinate |
| 4 | 1 | byte | runFlag | 0 = walk, 1 = run |

### MOVE_GAME (Extended Form)
| Field | Description |
|-------|-------------|
| **Opcode** | 92 |
| **Size** | 18 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (same as opcode 33) |
| **Category** | Movement |

Extended movement packet with additional data, used for specific minimenu interactions that carry extra context (e.g., when clicking on an entity at a location).

**Packet Format (18 bytes):**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 2 | ushort | destX | Destination X coordinate |
| 2 | 2 | ushort | destY | Destination Y coordinate |
| 4 | 1 | byte | runFlag | 0 = walk, 1 = run |
| 5 | 13 | mixed | extendedData | Additional context data (entity/target info) |

---

## Notes

- Three distinct MOVE_GAME variants exist for different contexts:
  - **Opcode 102** (VAR_SHORT): Full pathfinding with variable-length waypoint list
  - **Opcode 33** (5 bytes): Simple single-destination walk from minimenu actions
  - **Opcode 92** (18 bytes): Extended form with entity/target context data
- The `runFlag` field is present in all variants and is set when the player holds Ctrl while clicking
- The sender function at `<addr in DB>` handles both opcode 33 and opcode 92 -- it chooses the extended form when additional target data is available
- Movement from the minimap likely uses the same opcode 102 path

---

# 948-5 (current build) — single-destination click-walk (op74 / op78)

> Byte-precise, read directly from the 948-5 target `rs2client`. Supersedes the rev-947
> section above for these opcodes (the 947 field ORDER and transforms were only partially
> correct). Opcodes and byte layout re-verified against the binary — do not reuse 947 offsets.

## Builder and registration (binary facts)

- Both opcodes are emitted by one builder: `jag::ClientProt::SendMoveMinimapClick.
- It selects the opcode from `moveEvent(param_2+8) + 0x48`:
  - `== 0` → **op74**, descriptor `<addr in DB>`, fixed size **5**.
  - `== 1` → **op78**, descriptor `<addr in DB>`, fixed size **18**.
- `RegisterAll`: `register(<addr in DB>, opcode=0x4A=74, size=5)`;
  `register(<addr in DB>, opcode=0x4E=78, size=18)`.
- Fixed-size ClientProts (positive size) carry NO length prefix — payload starts right after
  the (ISAAC-enciphered) opcode byte.
- Destination fields come from the move event: `moveEvent+0x4c = destX (tile)`,
  `moveEvent+0x50 = destY (tile)` (confirmed via the local walk setter
  `<in Ghidra DB>(this, destX*512+256, destY*512+256, plane)`).
- op78's tail block includes the local player's CURRENT fine position — needed because a
  minimap click can target a tile outside the loaded scene, so the server can validate/path it.
  op74 omits it (destination is inside the loaded scene → game-world click).

## Official names

| Opcode | Size | Official `jag::ClientProt` name | Confidence |
|--------|------|--------------------------------|------------|
| 74 | 5 | `MOVE_GAMECLICK` | CONFIRMED (user, from live client) — game-world click-to-walk, single destination |
| 78 | 18 | `MOVE_MINIMAPCLICK` | HIGH — oracle CLIENT_ID_HIGH + reference with-target branch + identical 13-byte tail + carries current player pos |

**op74 / op58 resolved.** op74 = `MOVE_GAMECLICK` is confirmed. That frees op58, which had
carried a now-wrong `MOVE_GAMECLICK` label. op58 is a *separate* packet (VAR_SHORT multi-waypoint
PATH, builder `jag::ClientProt::SendMoveGame, descriptor `<addr in DB>`, opcode `0x3A`).
op58's official enum name is **`UNKNOWN_58`** — see the op58 section below. The reference's four move
enums are all fixed-size and are accounted for elsewhere (`MOVE_GAMECLICK`=op74, `MOVE_MINIMAPCLICK`
=op78, `MOVE_SCRIPTED`=op17 fixed-5B CS2 single-coord, `CLICKWORLDMAP`=op16); op58's varShort path
form has no counterpart in the older reference.

## op74 — wire format (5 bytes, fixed)

Server decodes (CLIENT→server). All offsets are payload offsets (after the opcode byte).

| Offset | Size | Client write (`jag::Packet`) | Server read (JagExtensions) | Field | Notes |
|--------|------|------------------------------|-----------------------------|-------|-------|
| 0 | 1 | `pT<unsigned_char>` (p1) | `readUByte` (g1) | run | `(client[0x490] >> 2) & 1`; 0 = walk, 1 = run |
| 1 | 2 | `writeShortAdd` (p2_add) | `readUShortAdd` (g2_add) | destY | Big-endian: hi byte raw, low byte `+128` |
| 3 | 2 | `writeShortLittle` (p2LE) | `readUShortLittle` (g2LE) | destX | Little-endian: low byte, hi byte; no transform |

Decoder pseudocode:
```
run   = readUByte          // 0/1
destY = readUShortAdd      // BE, low byte carries +128 add-transform
destX = readUShortLittle   // LE, raw
```

## op78 — wire format (18 bytes, fixed)

Identical first 5 bytes as op74, followed by a 13-byte target-context block. In this builder the
block is hardcoded except the two player-position shorts (this path is a walk with no live entity
target — the target slots are sentinels).

| Offset | Size | Client write | Server read | Field | Value / notes |
|--------|------|--------------|-------------|-------|----------------|
| 0 | 1 | p1 | readUByte (g1) | run | 0 = walk, 1 = run |
| 1 | 2 | p2_add | readUShortAdd (g2_add) | destY | BE, low byte +128 |
| 3 | 2 | p2LE | readUShortLittle (g2LE) | destX | LE, raw |
| 5 | 1 | p1 | readUByte (g1) | targetSentinelA | const `0xFF` (-1 → "no target") |
| 6 | 1 | p1 | readUByte (g1) | targetSentinelB | const `0xFF` (-1) |
| 7 | 2 | raw u16 | readUShort (g2) | pad0 | const `0x0000` |
| 9 | 1 | p1 | readUByte (g1) | tagA | const `0x39` |
| 10 | 1 | p1 | readUByte (g1) | zeroA | const `0x00` |
| 11 | 1 | p1 | readUByte (g1) | zeroB | const `0x00` |
| 12 | 1 | p1 | readUByte (g1) | tagB | const `0x59` |
| 13 | 2 | p2 (BE) | readUShort (g2) | playerFineX | current player fine X (`entity[0xd0]`, float→i16) |
| 15 | 2 | p2 (BE) | readUShort (g2) | playerFineY | current player fine Y (`entity[0xd4]`, float→i16) |
| 17 | 1 | p1 | readUByte (g1) | tagC | const `0x3F` |

The 13-byte tail (offsets 5..17) is a serialized "target/interaction" descriptor. As emitted by
`SendMoveMinimapClick` for a plain walk it is fixed (`FF FF 00 00 39 00 00 59 <playerX:2> <playerY:2> 3F`);
only `playerFineX/Y` are dynamic. For a byte-compatible decoder the server should consume all 18
bytes; `destX/destY/run` are the actionable fields, `playerFineX/Y` give the client's position at
click time, the constant bytes are opaque protocol tags.

## What op74/op78 are NOT

- NOT `<in Ghidra DB>` — that adjacent function is `jag::ClientProt::SendOpLocU` (a location-op
  packet using descriptor `<addr in DB>`), a different opcode. The op74/op78 builder is
  `SendMoveMinimapClick.
- NOT op58 `MOVE_GAMECLICK` (VAR_SHORT waypoint path, `SendMoveGame — that is a
  separate packet; op74/op78 are fixed single-destination.

---

# 948-5 — op58 (VAR_SHORT waypoint-path move) = `UNKNOWN_58`

- **Opcode 58** (`0x3A`), size **-2 (VAR_SHORT)**, descriptor `<addr in DB>`.
- **Builder:** `jag::ClientProt::SendMoveGame (body <addr in DB>–<addr in DB>). Registered
  in `RegisterAll`. (The stub table's ` is WRONG — that address is inside
  `<in Ghidra DB>` and has no xrefs; correct builder is `<addr in DB>`.)
- **Wire shape:** `[p2 count][segment0][segment1][segment2][p1 runFlag]` where each segment is a
  variable-length packed waypoint (`<in Ghidra DB>`, size measured by `<in Ghidra DB>`); `count` =
  Σ segment sizes + 1. runFlag = `param5 | 2` when the run modifier is set, else `param5`. Full
  byte-level layout of the segment encoding is not yet reversed (not required to name the opcode).
- **Trigger:** CS2 clientscript opcodes — callers `<in Ghidra DB>` and `<in Ghidra DB>` pop the script
  int stack (`state+0x100`) and string stack (`state+0x10a8`) and call `SendMoveGame`. So op58 is a
  script-driven multi-waypoint walk.

**Official name = `UNKNOWN_58`.** It is NOT `MOVE_GAMECLICK` (that is op74, user-confirmed). It is
structurally unlike every move enum present in the older unstripped reference — all four
(`MOVE_GAMECLICK`, `MOVE_MINIMAPCLICK`, `MOVE_SCRIPTED`, `CLICKWORLDMAP`) are fixed-size, and the
best match for a CS2-driven scripted move (reference `jag::opcode::Entities` lambda emitting
`MOVE_SCRIPTED`) is a **fixed 5-byte single packed-coordinate** packet = target **op17**, not a
varShort path. The reference build predates any varShort path-move opcode, so no confident official
name can be assigned. Flag as `UNKNOWN_58` until a newer symbol source is available.
