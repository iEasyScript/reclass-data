# ServerProt: Miscellaneous (Uncategorized) Handlers

> **Rev 947-1 update**: All opcodes reshuffled. See `serverprot-table.md` for the 947-1 opcode/size table.
> Key verified 947 opcodes: NO_TIMEOUT=216, LOGOUT=147, LOGOUT_TRANSFER=209, UPDATE_REBOOT_TIMER=132,
> SERVER_TICK_END=171, UPDATE_RUNENERGY=19, JCOINS_UPDATE=59, RESET_ENTITY_LISTS=43.

## Overview

This document covers the miscellaneous ServerProt handlers that are registered in `BindHandlers` (<addr in DB> in 947-1) but do not belong to any of the named packet handler categories. These include critical handlers such as PLAYER_INFO, LOGOUT, UPDATE_STAT, UPDATE_REBOOT_TIMER, and various entity/state management packets.

All handlers follow the standard ServerProt invocation pattern:
- Called via `ServerProt.invokePtr(ServerProt.callableData, Packet*, &packetSize)`
- `callableData` contains a pointer to the Client struct
- Return value: `&<in Ghidra DB>` (success)

## Identified Handlers

### PLAYER_INFO (opcode 189, var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Primary player update packet. This is an extremely large and complex handler (56K+ chars decompiled) that decodes the bit-packed player position, appearance, animation, and extended info update stream for all visible players. Sent every game tick. Comparable in complexity to NPC_INFO.

---

### LOGOUT (opcode 134, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Forces full client logout. Sequence:
1. Closes the `ClientStream` TCP connection
2. Calls `jag::Client::SetMainState(INITIAL)` to reset to title screen
3. Destroys connection data objects (0x280 byte allocation)
4. Clears player list shared_ptrs (releases all ref-counted entries)
5. Resets interface manager state
6. Sets connection ready flag at +0x260 to 1

---

### LOGOUT_TRANSFER (opcode 131, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Initiates a world transfer (world hop). Unlike LOGOUT which returns to title screen:
1. Closes the active connection object at `ClanManager+0xC0` (0x280 byte object)
2. Sets state to 3 (reconnecting)
3. Sets a 30-second reconnect timer via `system_clock::now / 1000000 + 30000`
Used for seamless world switching.

---

### NOOP (opcode 146, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Empty handler. Returns success immediately with no processing. Used as a keepalive or placeholder.

---

### SET_RUN_ENERGY (opcode 27, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1 | byte | Run energy value (0-100) |

**Behavior:** Sets the player's run energy. Stores the value at `__DT_SYMTAB[0x49a]+0x60`.

---

### RESET_ENTITY_LISTS (opcode 25, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Resets both the PlayerList (`__DT_SYMTAB[0x499]`) and NPCManager (`__DT_SYMTAB[0x497]`) entity data. Called before REBUILD_NORMAL to clear old entity state when the player teleports or changes regions.

---

### TRIGGER_ONDIALOGABORT (opcode 212, size 0)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Behavior:** Increments a global counter, calls `<in Ghidra DB>`, sets a flag at `__DT_SYMTAB[0x496]+0x154` to 1. Signals dialog abort / scene reset.

---

## Partially Identified Handlers

These handlers have been decompiled and analyzed but need further confirmation on their exact RS protocol name.

### SET_INTERACTION_FLAG_A (opcode 23, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte, stores at `__DT_SYMTAB[0x492]+0x50`. Also calls `<in Ghidra DB>` (connection state update). May trigger reconnection logic based on game state checks.

### SET_INTERACTION_FLAG_B (opcode 161, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte with +0x80 transform, stores at `__DT_SYMTAB[0x4dc]+0xA0`.

### SET_INTERACTION_FLAG_C (opcode 169, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte with +0x80 transform, stores at `__DT_SYMTAB[0x4dc]+0xA4`.

### SET_CHAT_FILTER_A (opcode 204, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte, validates against bitmask `0xFE3`, stores at `__DT_SYMTAB[0x490]+0x38`.

### SET_CHAT_FILTER_B (opcode 188, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte, validates against bitmask `<in Ghidra DB>`FE3`, stores at `__DT_SYMTAB[0x490]+0x30`.

### SET_CHAT_FILTER_C (opcode 164, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte, validates against bitmask `0xE3`, stores at `__DT_SYMTAB[0x490]+0x3C`. Also clears an EASTL string at +0x40.

### SET_NPC_UPDATE_FLAG (opcode 181, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte, sets `__DT_SYMTAB[0x493]+0x14` to 1, increments counter at +0x10, sets `NPCManager+0x6A` to `(byte == 1)`.

### UPDATE_URL_STRING (opcode 155, var-short)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 4 bytes + null-terminated CP1252 string. Updates counter at `ClanManager+0x130`. Processes string with CP1252-to-UTF8 conversion.

### REMOVE_PLAYER_FROM_LIST (opcode 205, size 1)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads 1 byte (negated + offset transform). Binary searches a sorted player vector at `PlayerList+0x1DDC`, removes the matching entry by shifting.

### UPDATE_FRIENDLIST_DELTA (opcode 168, var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Complex handler accessing FriendList (`__DT_SYMTAB[0x498]`) and world lookup. Processes 0xB0-byte friend entries with zone data objects.

### UPDATE_IGNORELIST (opcode 17, var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

Reads byte flag + CP1252 string triplets in a loop. Accesses `__DT_SYMTAB[0x49a]` list of 0x50-byte entries (3 EASTL strings + flag byte each). Max 400 entries. Resets PlayerList at end.

---

## Complete Uncategorized Handler Reference Table

All 74 uncategorized handlers registered inline in BindHandlers, sorted by opcode. All have been decompiled, named in Ghidra, and documented.

| Opcode | Size | Handler Address | Confirmed Name | Status |
|--------|------|-----------------|----------------|--------|
| 9 | var_byte | `<addr in DB>` | **SET_NPC_OP** | Verified |
| 13 | 1 | `<addr in DB>` | **SET_PLAYER_OP_3** | Verified |
| 17 | var_byte | `<addr in DB>` | **UPDATE_IGNORELIST** | Verified |
| 18 | var_byte | `<addr in DB>` | **UPDATE_SITESETTINGS** | Verified |
| 20 | var_byte | `<addr in DB>` | **IF_OPENSUB_ACTIVE** | Verified |
| 23 | 1 | `<addr in DB>` | **SET_INTERACTION_FLAG_A** | Verified |
| 25 | 0 | `<addr in DB>` | **RESET_ENTITY_LISTS** | Verified |
| 27 | 1 | `<addr in DB>` | **SET_RUN_ENERGY** | Verified |
| 29 | var_short | `<addr in DB>` | **CLANSETTINGS_FULL** | Verified |
| 36 | var_byte | `<addr in DB>` | **IF_SETPLAYERMODEL_OTHER** | Verified |
| 41 | 10 | `<addr in DB>` | **LOC_ADD_CHANGE** | Verified (was UPDATE_INV_STOPTRANSMIT) |
| 42 | var_short | `<addr in DB>` | **PLAYER_INFO_DECODE** | Verified |
| 47 | 14 | `<addr in DB>` | **MAP_FLAG_SET_PLAYER** | Verified |
| 53 | 35 | `<addr in DB>` | **CUTSCENE_DATA** | Verified |
| 54 | 25 | `<addr in DB>` | **PROJANIM** | Verified |
| 66 | var_short | `<addr in DB>` | **FRIENDLIST_LOADED** | Verified (was FRIEND_STATUS) |
| 73 | 2 | `<addr in DB>` | **SET_PLAYER_CHAT_EFFECTS** | Verified |
| 80 | 1 | `<addr in DB>` | **SET_MULTIWAY_STATE** | Verified |
| 84 | var_byte | `<addr in DB>` | **DETAIL_OPTIONS** | Verified (confirmed by symbol) |
| 85 | 4 | `<addr in DB>` | **SET_DISPLAY_INT** | Verified |
| 86 | var_short | `<addr in DB>` | **NPC_HEADICON_SPECIFIC** | Verified |
| 91 | 12 | `<addr in DB>` | **SPOTANIM_SPECIFIC** | Verified (was SPOTANIM_MAP) |
| 94 | 19 | `<addr in DB>` | **NPC_HITMARKS_AND_HEADBARS** | Verified |
| 97 | 2 | `<addr in DB>` | **SET_PLAYER_OP_2** | Verified |
| 101 | 3 | `<addr in DB>` | **REMOVE_TRACKED_ENTRY** | Verified |
| 102 | 1 | `<addr in DB>` | **SET_NPC_UPDATE_ORIGIN** | Verified |
| 103 | 10 | `<addr in DB>` | **SET_PLAYER_GROUP** | Verified (was PLAYER_GROUP_FULL) |
| 109 | var_byte | `<addr in DB>` | **REBUILD_NORMAL** | Verified |
| 111 | var_short | `<addr in DB>` | **NOOP_VAR** | Verified (true no-op) |
| 128 | 3 | `<addr in DB>` | **IF_SETANGLE_ACTIVE** | Verified |
| 131 | 0 | `<addr in DB>` | **LOGOUT_TRANSFER** | Verified |
| 133 | 1 | `<addr in DB>` | **SET_CHAT_FILTER_D** | Verified |
| 134 | 0 | `<addr in DB>` | **LOGOUT** | Verified |
| 135 | 1 | `<addr in DB>` | **SET_WEIGHT** | Verified |
| 139 | 4 | `<addr in DB>` | **PLAYER_OP** | Verified |
| 141 | var_short | `<addr in DB>` | **UPDATE_ZONE_FULL_FOLLOWS_3** | Verified (was UPDATE_INV_STOPTRANSMIT_2) |
| 143 | 8 | `<addr in DB>` | **SET_CAMERA_TARGET** | Verified (was SET_WORLD_TARGET_2) |
| 144 | 4 | `<addr in DB>` | **SET_SYSUPDATE_TIMER** | Verified |
| 145 | 8 | `<addr in DB>` | **IF_SETHIDE_ACTIVE** | Verified |
| 146 | 0 | `<addr in DB>` | **NOOP** | Verified |
| 148 | var_short | `<addr in DB>` | **UPDATE_PLAYER_CHAT** | Verified (was NPC_ANIM_SPECIFIC) |
| 152 | var_short | `<addr in DB>` | **UPDATE_IGNORELIST** | Verified |
| 154 | var_byte | `<addr in DB>` | **UPDATE_PLAYER_GROUP** | Verified |
| 155 | var_short | `<addr in DB>` | **UPDATE_URL_STRING** | Verified |
| 161 | 1 | `<addr in DB>` | **SET_INTERACTION_FLAG_B** | Verified |
| 162 | var_short | `<addr in DB>` | **IF_SETGRAPHIC_ACTIVE** | Verified |
| 163 | var_byte | `<addr in DB>` | **REBUILD_PLAYERINFO_POSITIONS** | Verified |
| 164 | 1 | `<addr in DB>` | **SET_CHAT_FILTER_C** | Verified |
| 167 | 2 | `<addr in DB>` | **SKIP_2_BYTES** | Verified (deprecated no-op) |
| 168 | var_byte | `<addr in DB>` | **UPDATE_FRIENDLIST_DELTA** | Verified |
| 169 | 1 | `<addr in DB>` | **SET_INTERACTION_FLAG_C** | Verified |
| 170 | var_byte | `<addr in DB>` | **NOOP_VAR** | Verified (true no-op) |
| 171 | var_byte | `<addr in DB>` | **SET_URL_STRING** | Verified |
| 172 | 5 | `<addr in DB>` | **IF_SETNPCMODEL_ACTIVE** | Verified |
| 173 | var_byte | `<addr in DB>` | **IF_SETMODEL_ACTIVE** | Verified |
| 175 | 3 | `<addr in DB>` | **SET_INTERACTION_FLAG_D** | Verified |
| 177 | var_byte | `<addr in DB>` | **REBUILD_REGION** | Verified |
| 179 | 2 | `<addr in DB>` | **FRIENDCHAT_SYSUPDATE** | Verified |
| 181 | 1 | `<addr in DB>` | **SET_NPC_UPDATE_FLAG** | Verified |
| 185 | 33 | `<addr in DB>` | **MAP_PROJANIM** | Verified (was MAP_FLAG_SET_2) |
| 187 | 4 | `<addr in DB>` | **PLAYER_GROUP_DELTA** | Verified |
| 188 | 1 | `<addr in DB>` | **SET_CHAT_FILTER_B** | Verified |
| 189 | var_byte | `<addr in DB>` | **PLAYER_INFO** | Verified |
| 190 | 3 | `<addr in DB>` | **IF_MOVESUB_ACTIVE** | Verified |
| 192 | var_byte | `<addr in DB>` | **SKIP_DATA** | Verified (deprecated) |
| 193 | 15 | `<addr in DB>` | **MAP_FLAG_SET** | Verified |
| 195 | 3 | `<addr in DB>` | **IF_SETPOSITION_ACTIVE** | Verified |
| 197 | 3 | `<addr in DB>` | **IF_SETCLICKMASK_ACTIVE** | Verified |
| 203 | 8 | `<addr in DB>` | **SERVER_TICK_END** | Verified (was SET_COMBAT_STYLE) |
| 204 | 1 | `<addr in DB>` | **SET_CHAT_FILTER_A** | Verified |
| 205 | 1 | `<addr in DB>` | **REMOVE_PLAYER_FROM_LIST** | Verified |
| 210 | 4 | `<addr in DB>` | **IF_SETRECOL_ACTIVE** | Verified |
| 212 | 0 | `<addr in DB>` | **TRIGGER_ONDIALOGABORT** | Verified |
| N/A | 28 | `<addr in DB>` | **SET_UID** | Verified (not in RegisterAll, login-time) |

## Statistics

- **Total ServerProt opcodes**: 216 registered
- **Named handler categories**: 12 (142 handlers)
- **Uncategorized inline handlers**: 74 (this document)
- **Fully identified and named in Ghidra**: 74/74 (100%)
- **Remaining unknown**: 0
- **Significant name corrections**: 7 (LOC_ADD_CHANGE, FRIENDLIST_LOADED, SET_PLAYER_GROUP, UPDATE_PLAYER_CHAT, SERVER_TICK_END, MAP_PROJANIM, UPDATE_ZONE_FULL_FOLLOWS_3)

## DT_SYMTAB Client Offset Reference

These `__DT_SYMTAB` indices are used by the handlers to access client subsystems:

| Index | Purpose | Example Handlers |
|-------|---------|-----------------|
| 0x441 | ConnectionManager/Stream | LOGOUT |
| 0x442 | World Lookup Service | UPDATE_FRIENDLIST_DELTA |
| 0x490 | Chat Filter Settings | SET_CHAT_FILTER_A/B/C |
| 0x491 | Interface Manager | LOGOUT |
| 0x492 | Interaction State | SET_INTERACTION_FLAG_A |
| 0x493 | Scene Update State | SET_NPC_UPDATE_FLAG |
| 0x495 | Player Entity Manager | LOGOUT |
| 0x496 | Connection/Dialog State | TRIGGER_ONDIALOGABORT |
| 0x497 | NPCManager | RESET_ENTITY_LISTS, SET_NPC_UPDATE_FLAG |
| 0x498 | FriendList | UPDATE_FRIENDLIST_DELTA |
| 0x499 | PlayerList | RESET_ENTITY_LISTS, REMOVE_PLAYER_FROM_LIST |
| 0x49a | Run Energy / State Flags | SET_RUN_ENERGY, UPDATE_IGNORELIST |
| 0x49b | Scene Graph | LOGOUT |
| 0x49c | ClanManager / Connection | LOGOUT_TRANSFER, UPDATE_URL_STRING |
| 0x4dc | Game State / Interaction | SET_INTERACTION_FLAG_B/C |

---

## Interaction Marker Packet (949-5)

> **Name provenance.** The name our tables carry for this packet (`SET__TARGET__MARKER`) is
> **ASSIGNED, not attested** — it appears in neither `official_names` nor `assigned_names` in
> `re-resources/prot-names.json`, and neither client binary contains prot-name strings at all.
> Treat it as a placeholder. The handler is named `jag::PacketHandlers::SetInteractionTarget` in
> both the Linux and Windows 949-5 Ghidra DBs; the opcode and size live only in the DB.

Fixed-size packet. Drives the **on-target interaction marker/indicator**, which is an
`InterfaceManager` *component update entry*, not an entity field. It does **not** touch any
`PathingEntity` face/interaction-target field — model facing is a separate subsystem.

### Structural shape

Ten bytes, consumed as six independent single-byte fields followed by one four-byte field:

| Field | Read | Meaning |
|-------|------|---------|
| tagB | `g1` | Leading int of marker record **B**. Record **A**'s equivalent is hardcoded to `-1` by the client and is not on the wire. |
| pointA.y | `g1` | Point **A** tile offset, Y axis |
| pointA.x | `g1_inv` | Point **A** tile offset, X axis. Decoded value `0xFF` means *no point A*; the client then uses `(-1, -1)` verbatim with no base or scale applied. |
| slotLo | `g1_sub` (signed) | Low 32 bits of the packet's 64-bit marker slot. The value `-1` **also** suppresses point B's tile→fine conversion. |
| pointB.y | `g1_sub` | Point **B** tile offset, Y axis |
| pointB.x | `g1_inv` | Point **B** tile offset, X axis |
| slotHi | `g4_alt3` | High 32 bits of the 64-bit marker slot |

Note the mod-256 trap on `slotLo`: the Linux decompilation renders it `0x80 - b` and the Windows one
`-0x80 - b`. Both are the **subtract** shape (operand negated), i.e. `readByteSubtract` — not add.

### Coordinate model

Both points are **tile offsets relative to the camera's zone-aligned scene origin**, converted to
world-fine units by the standard 512-per-tile scale:

```
worldFine = (sceneOriginTile + tileOffset) * 512
```

Verified against a live 949-5 client: the two scene-origin fields held `15648` / `7200` while the
local player stood on tile `(15751, 7358)`; both origins are multiples of 32. The lower-addressed
origin field is X, which fixes the axis order above.

### What the client stores

The handler forwards everything to `InterfaceManager::SetInteractionMarkerEntry`, which writes a
component update entry of kind `0xE` holding three slots:

```
record A = { -1,   (float) pointA.x, 0, (float) pointA.y }
slot     = (slotHi << 32) | (uint32) slotLo
record B = { tagB, (float) pointB.x, 0, (float) pointB.y }
```

### Observed on the wire

Nearly every captured body is the **cleared** form: point A null, `slotLo` = 0, point B decoding to
`(255, 255)`, and `slotHi` = `-1`. Bodies carrying a real point A occur throughout normal play; a
real point B was seen once in a full session, one tile away from point A.

### Open question (do not implement on guesswork)

`slotLo` reads like a plane/level or a "point B present" flag, and `slotHi` like a target/entity
reference with `-1` = none — but **the client does not distinguish them**. It concatenates the pair
into one opaque 64-bit blob for the interface component to read back, so nothing in the binary
proves either meaning. An earlier pre-binary guess of "entity ref plus a 4-byte `-1` sentinel" is
**wrong**: the trailing four bytes are the high half of that 64-bit slot, whose low half is a
single earlier byte, and the packet's bulk is two coordinate points.
