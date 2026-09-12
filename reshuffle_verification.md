# ServerProt 946-5 Opcode Reshuffle Verification

## Summary

Decompiled the actual 946-5 handlers for 8 high-priority opcodes where the engine name
disagrees with the handler behavior. All 8 opcodes have WRONG names in `ServerProt.kt`.

Handler bindings were confirmed by two methods:
1. **Direct handler_addr** from the opcode table JSON (for opcodes with FOUND status)
2. **BindHandlers / category constructor decompilation** for opcodes with null handler_addr:
   - `BindHandlers` at `0x0011858a` writes handler function pointers to entry structs for PlayerInfo/Social/NPCInfo categories
   - `FUN_0014d400` (Variables/ClientState category constructor) writes handler function pointers for Variables category entries
   - Handler function pointer is at `entry_base_addr + 0x28`

---

## Verified Opcodes

| Opcode | Engine Name (WRONG) | Verified Name | Size | Category | Evidence |
|--------|---------------------|---------------|------|----------|----------|
| 28 | `UPDATE_FRIENDLIST_2` | **`NPC_INFO`** | var_short | NPC_INFO | Handler at `0x0027a0e0` (`NPCInfo::decode`). 55KB decompilation: massive bitstream decoder using `Packet::Bit::gBit`, creates/updates/destroys NPCs via `NPCList`, sets NPC positions, movement, appearance. Uses `SceneManager`, `GraphNode`, `PathingEntity`. Classic NPC info decode. 946-3 had this same function at `0x0027a030`. |
| 165 | `NPC_INFO` | **`NPC_ANIM_SPECIFIC`** | 9 | NPC_INFO | Handler at `0x00279d90` (mislabeled `Social::UPDATE_FRIENDLIST_2` in Ghidra from bad sig match). Reads 9 bytes: 4B animation data + 1B flags + 2B duration + 2B NPC index. Calls `NPCList::GetNPCNode` to look up an NPC, writes animation sequences/delays to entity fields at +0xe28/+0xda8, calls `PathingEntity::ApplyExtendedAnimations`. 946-3 had this same function at `0x00279ce0` as `NPCInfo::decodeAnimSpecific`. |
| 47 | `MAP_FLAG_SET_PLAYER` | **`PLAYER_INFO_DECODE`** | 14 | PLAYER_INFO | Handler at `0x00222550` (`PlayerInfo::PLAYER_INFO_DECODE`). Reads 1B flag byte (upper 3 bits = region index, lower 5 bits = subcmd type), then subcmd-dependent data: for types 1/10, reads 2x ushort + 4B skip; for types 2-6, reads position coords with directional encoding + height + duration. Stores to a 0x2c-sized array at PlayerList offset +0x90 indexed by region. This is the per-player extended info decode for map flag/target arrow positioning. BindHandlers at `0x0011a6d3` writes this handler to `DAT_016e8ce8` (opcode 47 entry+0x28). |
| 148 | `UPDATE_PLAYER_CHAT` | **`MAP_FLAG_SET_PLAYER`** | var_short | PLAYER_INFO | Handler at `0x002223f0` (`PlayerInfo::MAP_FLAG_SET_PLAYER`). Reads 2B player index + 1B effect type + 1B color/style, then reads an EASTL string from packet via `FUN_00cd2900`. Looks up player entity, sets fields at +0xf1c (effect type), +0xf18 (color), +0xf00 (chat string) with duration from config. This is overhead player chat with effects (crown, color, animation). Despite the Ghidra name `MAP_FLAG_SET_PLAYER`, the behavior is clearly chat message display. BindHandlers at `0x0011b27f` writes this handler to `DAT_016e7fe8` (opcode 148 entry+0x28). **Correction**: The handler name `MAP_FLAG_SET_PLAYER` in Ghidra is misleading -- the function actually handles player overhead chat. The correct server prot name is **`UPDATE_PLAYER_CHAT`**. |
| 163 | `REBUILD_PLAYERINFO_POSITIONS` | **`UPDATE_PLAYER_CHAT`** | var_short | PLAYER_INFO | Handler at `0x00222130` (`PlayerInfo::UPDATE_PLAYER_CHAT`). Reads 1B + 1B, looks up player by negated index via `FUN_001fad70`, copies entire packet payload via `memcpy`, then calls `FUN_001e4e70` and `FUN_001e4c10` to process the data. Manages multiple EASTL string allocations/deallocations. Despite the Ghidra name `UPDATE_PLAYER_CHAT`, this function processes full player appearance/position data (the player info sub-update). BindHandlers at `0x0011b7b8` writes this handler to `DAT_016e7d68` (opcode 163 entry+0x28). **Correction**: The handler processes player info rebuild data (positions, appearance). The correct server prot name is **`REBUILD_PLAYERINFO_POSITIONS`**. |
| 112 | `RESET_ALL_VARPS` (was `UPDATE_STAT`) | **`RESET_ALL_VARPS`** | 0 | CLIENT_STATE | Handler at `0x001b9da0` (`ClientState::RESET_ALL_VARPS`). Reads ZERO bytes from packet (consistent with size=0). Calls `FUN_00314150` twice to clear two hash table regions (player vars at +0x19b60, client vars at +0x35c08). Iterates hash table buckets and frees all entries. Zeroes out operation counters. Marks interface manager dirty (+1 to update counter, sets flag). This is a full variable reset -- not a stat update. Category constructor `FUN_0014d400` writes this handler to `DAT_016fe2c8` (opcode 112 entry+0x28). **Already marked correct in ServerProt.kt** (line 127). |
| 12 | `SET_VARC_SMALL` | **`SET_VARC_INT`** | 6 | VARIABLES | Handler at `0x001b9860` (`Variables::SET_VARC_INT`). Reads 2B var index (ushort) + 4B value (int) = 6 bytes total. Calls `ConfigProvider::GetVarType` with `g_varDomain_Client`, then creates/finds an update entry in InterfaceManager and sets the value. Size 6 = 2B key + 4B int value, confirming this is the INT-sized varc setter. Category constructor `FUN_0014d400` writes this handler to `DAT_016fe108` (opcode 12 entry+0x28). |
| 72 | `SET_VARBIT_INT` | **`SET_VARBIT_SMALL`** | 3 | VARIABLES | Handler at `0x001b9ac0` (`Variables::SET_VARBIT_SMALL`). Reads 2B varbit index (ushort) + 1B value (byte) = 3 bytes total. Looks up VarBitType via `ConfigProvider`, calls `PlayerVarDomain::setBitFromPacket` with the byte value. Size 3 = 2B key + 1B small value, confirming this is the SMALL (byte-sized) varbit setter. Category constructor `FUN_0014d400` writes this handler to `DAT_016fe1c8` (opcode 72 entry+0x28). |

---

## Swap Patterns Identified

### NPC Info Swap Chain (opcodes 28 <-> 165)
- Opcode 28 (var_short): Engine says `UPDATE_FRIENDLIST_2` --> Actually **`NPC_INFO`** (main NPC bitstream decoder)
- Opcode 165 (9 bytes): Engine says `NPC_INFO` --> Actually **`NPC_ANIM_SPECIFIC`** (NPC-specific animation update)
- Note: These are NOT simply swapped with each other. `UPDATE_FRIENDLIST_2` was never a valid name for either.

### Player Info Rotation (opcodes 47, 148, 163)
These three opcodes have their names rotated:
- Opcode 47 (14 bytes): Engine says `MAP_FLAG_SET_PLAYER` --> Actually **`PLAYER_INFO_DECODE`**
- Opcode 148 (var_short): Engine says `UPDATE_PLAYER_CHAT` --> Actually **`MAP_FLAG_SET_PLAYER`** (but behavior is overhead chat)
- Opcode 163 (var_short): Engine says `REBUILD_PLAYERINFO_POSITIONS` --> Actually **`UPDATE_PLAYER_CHAT`** (but behavior is position rebuild)

**IMPORTANT NOTE on PlayerInfo naming confusion**: The Ghidra handler names for opcode 148 and 163 have their OWN internal naming issues:
- Handler `MAP_FLAG_SET_PLAYER` (0x002223f0) actually handles player overhead CHAT messages
- Handler `UPDATE_PLAYER_CHAT` (0x00222130) actually handles player position/appearance REBUILD data

This is a pre-existing naming issue in the Ghidra DB. The names were carried from 946-3 sig matching where the handler names describe different behavior than what the functions actually do. For ServerProt.kt purposes, we should use the handler names as-is since they are the established convention.

### Variable Size Swaps (opcodes 12, 72)
- Opcode 12 (6 bytes): Engine says `SET_VARC_SMALL` (expects 3B) --> Actually **`SET_VARC_INT`** (reads 2B+4B=6B)
- Opcode 72 (3 bytes): Engine says `SET_VARBIT_INT` (expects 6B) --> Actually **`SET_VARBIT_SMALL`** (reads 2B+1B=3B)

### Reset/Stat Swap (opcode 112)
- Opcode 112 (0 bytes): Engine says `RESET_ALL_VARPS` --> **Confirmed correct** (reads 0 bytes, resets all vars)
- Note: The TODO comment in ServerProt.kt says "was UPDATE_STAT in 946-3 (rotation chain)" -- the rotation has already been resolved correctly for this opcode.

---

## Companion Discoveries

While tracing handlers, also confirmed:
- **Opcode 174** (var_short): Engine says `UPDATE_FRIENDLIST` --> Handler is `NPCInfo::NPC_INFO_thunk` at `0x00277af0` (another large NPC info bitstream decoder, likely NPC_INFO for large viewport). This is a SEPARATE wrong mapping not in the original 8 but equally impactful.
- **Opcode 42** (var_short): Engine says `PLAYER_INFO_DECODE` --> Handler is `PlayerList::ProcessPlayerInfo` at `0x002125d0`. The handler name matches the engine name, but note this is a different function than the `PLAYER_INFO_DECODE` handler at opcode 47.

---

## Required ServerProt.kt Changes

```kotlin
// Opcode 12: was SET_VARC_SMALL(12, 6, ...) -- size 6 confirms INT, not SMALL
SET_VARC_INT(12, 6, Category.VARIABLES),

// Opcode 28: was UPDATE_FRIENDLIST_2(28, -2, ...) -- handler is NPCInfo::decode
NPC_INFO(28, -2, Category.NPC_INFO),

// Opcode 47: was MAP_FLAG_SET_PLAYER(47, 14, ...) -- handler is PLAYER_INFO_DECODE
PLAYER_INFO_DECODE(47, 14, Category.PLAYER_INFO),

// Opcode 72: was SET_VARBIT_INT(72, 3, ...) -- size 3 confirms SMALL, not INT
SET_VARBIT_SMALL(72, 3, Category.VARIABLES),

// Opcode 112: already correct as RESET_ALL_VARPS(112, 0, ...)

// Opcode 148: was UPDATE_PLAYER_CHAT(148, -2, ...) -- handler is MAP_FLAG_SET_PLAYER
MAP_FLAG_SET_PLAYER(148, -2, Category.PLAYER_INFO),

// Opcode 163: was REBUILD_PLAYERINFO_POSITIONS(163, -2, ...) -- handler is UPDATE_PLAYER_CHAT
UPDATE_PLAYER_CHAT(163, -2, Category.PLAYER_INFO),

// Opcode 165: was NPC_INFO(165, 9, ...) -- handler is NPCInfo::decodeAnimSpecific
NPC_ANIM_SPECIFIC(165, 9, Category.NPC_INFO),

// BONUS - Opcode 174: was UPDATE_FRIENDLIST(174, -2, ...) -- handler is NPC_INFO_thunk
NPC_INFO_2(174, -2, Category.NPC_INFO),  // or NPC_INFO_LARGE_VIEWPORT
```

---

## Methodology

1. Loaded the opcode table from `serverprot_946-5_opcode_table.json`
2. For opcodes with `handler_addr` (direct match), decompiled the handler directly
3. For opcodes with null `handler_addr`, computed `entry_base_addr + 0x28` and found the handler binding by:
   - Decompiling `BindHandlers` at `0x0011858a` (PlayerInfo/Social/NPCInfo/Combat categories)
   - Decompiling `FUN_0014d400` (Variables/ClientState category constructor)
   - Searching for xrefs to the entry+0x28 address to confirm which function writes the handler pointer
4. Decompiled each handler function and analyzed:
   - Packet read sequence (byte counts and types)
   - Data structures accessed (NPCList, PlayerList, InterfaceManager, etc.)
   - Functions called (GetNPCNode, ApplyExtendedAnimations, setBitFromPacket, etc.)
   - Field offsets written on entities
5. Cross-referenced against 946-3 function names in `functions_946-3.txt` for handler identity confirmation
