# Lobby ServerProt Handler Mapping (Build 947-1)

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Name convention update**: Some names in this doc use fabricated RE names.
> See `serverprot-table.md` for canonical names.

Binary: rs2client (rev 947-1, STRIPPED) — verified in Ghidra on port 8083.
Cross-referenced with: rs2client (rev 946-5) on port 8082, librs2client.so (rev ~890) on port 8080.

## Architecture: Lobby Handlers Share the Game ServerProt Table

**Critical finding:** Lobby handlers are NOT in a separate protocol table. They share the same `g_serverProtVector` (218 entries at `<addr in DB>`) used during game phase. The `BindHandlers` function at `<addr in DB>` binds handler functions to ServerProt entries, and the same entries serve both lobby and game phases.

### How Lobby Packets Work

During the lobby phase, the client uses TcpIn to dispatch incoming packets through `g_serverProtVector`, the exact same dispatch path as game-phase packets. Lobby-specific handlers are among the 218 ServerProt entries. There is no separate "lobby ServerProt table."

This means the server must register all 218 ServerProt opcodes even during the lobby phase (or at minimum, the client expects valid entries for all opcodes that could arrive during lobby).

## Confirmed Lobby Handler Mappings (rev 947-1)

Handlers identified from BindHandlers at `<addr in DB>` with named handler functions, cross-referenced with RegisterAll at `<addr in DB>` for opcodes/sizes.

### Definitively Matched

| Rev 947-1 Opcode | Size | Handler Name | Notes |
|------------------|------|--------------|-------|
| 0xD8 (216) | 0 (fixed) | **NO_TIMEOUT** | Trivial return handler (keepalive) |
| 0x1E (30) | varShort | **CHANGE_LOBBY** | handler: Lobby::CHANGE_LOBBY |
| 0x41 (65) | 0 (fixed) | **SET_READY_FLAG** | handler: ClientState::SET_READY_FLAG |
| 0x30 (48) | 0 (fixed) | **RESET_CLIENT_VARCACHE** | handler: ClientState::RESET_ALL_VARPS |
| 0x9C (156) | 1 (fixed) | **CREATE_CHECK_EMAIL_REPLY** | handler: AccountCreation::CREATE_CHECK_EMAIL_REPLY, bitmask `<in Ghidra DB>`, ProtEntry at `<addr in DB>` |
| 0x8F (143) | 1 (fixed) | **CREATE_CHECK_NAME_REPLY** | handler: AccountCreation::CREATE_CHECK_NAME_REPLY, bitmask 0xFE3, ProtEntry at `<addr in DB>` |

### Not Found in rev 947-1 (4 of 8)

The following old binary lobby handlers have no clear equivalent among the unnamed handlers in rev 947-1's `BindHandlers`:

| Old Handler Name | Old Signature | Status |
|-----------------|---------------|--------|
| **CREATE_ACCOUNT_REPLY** | Bitmask `<in Ghidra DB>`fe3`, check `< 0x2a`, writes +0x30 | No matching handler found. Account creation may have been moved to a web-based flow. |
| **CREATE_SUGGEST_NAME_ERROR** | Bitmask `0xe3`, check `< 8`, writes +0x3c, clears string | No matching handler found. |
| **CREATE_SUGGEST_NAME_REPLY** | Reads CP1252 string, writes +0x3c=2, assigns string to +0x40 | No matching handler found. |
| **LOBBY_APPEARANCE** | Calls `PlayerEntity::SetBaseAppearanceAsPlayer` | No direct handler found. `SetBaseAppearanceAsPlayer` (at `<addr in DB>`) is called through a vtable chain: `<in Ghidra DB>` -> `<in Ghidra DB>` -> `<in Ghidra DB>` -> `SetBaseAppearanceAsPlayer`. This may be triggered by the player info/update system rather than a dedicated lobby packet. |

## All Unnamed Handlers in BindHandlers (Complete List)

Every ServerProt entry with an unnamed (FUN_) invoke handler, with opcode and size from `RegisterAll`:

| Opcode | Size | Entry Base | Invoke | Identification |
|--------|------|------------|--------|---------------|
| 0x05 | 10 | `<addr in DB>` | `<in Ghidra DB>` | SpotAnim/entity handler: reads int + byte + short + byte + short |
| 0x11 | varShort | `<addr in DB>` | `<in Ghidra DB>` | **CHANGE_LOBBY** (probable): reads CP1252 strings, builds vector |
| 0x12 | varShort | `<addr in DB>` | `<in Ghidra DB>` | `SiteSettings::UPDATE_SITESETTINGS` (Ghidra has type info) |
| 0x17 | 1 | `<addr in DB>` | `<in Ghidra DB>` | Reads 1 byte to struct+0x50, calls sub functions, triggers interface update |
| 0x21 | 0 | `<addr in DB>` | `<in Ghidra DB>` | Accesses client field, optionally calls `<in Ghidra DB>` |
| 0x31 | 10 | `<addr in DB>` | `<in Ghidra DB>` | SpotAnim/entity handler (identical pattern to 0x05) |
| 0x6D | varShort | `<addr in DB>` | `<in Ghidra DB>` | ISAAC-decrypted chat/message: delegates to `<in Ghidra DB>` |
| 0x6F | varByte | `<addr in DB>` | `<in Ghidra DB>` | Trivial return (NONE) — unused/placeholder |
| 0x85 | 1 | `<addr in DB>` | `<in Ghidra DB>` | UNKNOWN (was incorrectly labeled CREATE_CHECK_EMAIL_REPLY in rev 946) |
| 0x92 | 0 | `<addr in DB>` | `<in Ghidra DB>` | **NO_TIMEOUT** |
| 0x9B | varByte | `<addr in DB>` | `<in Ghidra DB>` | `Misc::UPDATE_URL_STRING`: reads 4 bytes + CP1252 string |
| 0xA1 | 1 | `<addr in DB>` | `<in Ghidra DB>` | Reads 1 byte + 0x80, writes to struct+0xa0 |
| 0xA6 | 0 | `<addr in DB>` | `<in Ghidra DB>` | Accesses client field, calls `<in Ghidra DB>` |
| 0xA8 | varShort | `<addr in DB>` | `<in Ghidra DB>` | VarPlayer handler: uses `ConfigProvider::GetVarPlayerTypeList` |
| 0xA9 | 1 | `<addr in DB>` | `<in Ghidra DB>` | Reads 1 byte + 0x80, writes to struct+0xa4 |
| 0xAA | varShort | `<addr in DB>` | `<in Ghidra DB>` | Trivial return (NONE) — unused/placeholder |
| 0xB1 | varShort | `<addr in DB>` | `<in Ghidra DB>` | ISAAC-decrypted chat/message: delegates to `<in Ghidra DB>` |
| 0xB5 | 1 | `<addr in DB>` | `<in Ghidra DB>` | Reads 1 byte, sets boolean flag, increments counter |
| 0xBB | 4 | `<addr in DB>` | `<in Ghidra DB>` | Reads 4 bytes (mixed-endian int), writes to struct+0x40, triggers script |
| 0xC4 | varShort | `<addr in DB>` | `<in Ghidra DB>` | Trivial return (NONE) — unused/placeholder |
| 0xCC | 1 | `<addr in DB>` | `<in Ghidra DB>` | UNKNOWN (was incorrectly labeled CREATE_CHECK_NAME_REPLY in rev 946) |

## Old Binary Handler Reference

From `jag::packethandlers::Lobby::Lobby(jag::Client&)` in librs2client.so (rev ~890):

| Lambda | ServerProt Name | Old Opcode | Old Size | Invoke Address | Behavior |
|--------|----------------|------------|----------|----------------|----------|
| #1 | NO_TIMEOUT | 0xBB | 0 | `<addr in DB>` | Returns `PacketError::NONE` immediately |
| #2 | CREATE_CHECK_EMAIL_REPLY | 0x60 | 1 | `<addr in DB>` | Bitmask `<in Ghidra DB>`, writes `client+0x7d8+0x34` |
| #3 | CREATE_ACCOUNT_REPLY | 0x80 | 1 | `<addr in DB>` | Bitmask `<in Ghidra DB>`fe3`, writes `client+0x7d8+0x30` |
| #4 | CREATE_CHECK_NAME_REPLY | 0x6C | 1 | `<addr in DB>` | Bitmask `0xfe3`, writes `client+0x7d8+0x38` |
| #5 | CREATE_SUGGEST_NAME_ERROR | 0xA3 | 1 | `<addr in DB>` | Bitmask `0xe3`, writes `+0x3c`, clears string at `+0x40` |
| #6 | CREATE_SUGGEST_NAME_REPLY | 0xBF | varShort | `<addr in DB>` | Reads CP1252 string, writes `+0x3c`=2, assigns string to `+0x40` |
| #7 | LOBBY_APPEARANCE | 0x75 | varShort | `<addr in DB>` | Skips 1 byte, calls `PlayerEntity::SetBaseAppearanceAsPlayer` |
| #8 | CHANGE_LOBBY | 0x1E | varShort | `<addr in DB>` | Reads CP1252 string + 3 unsigned shorts (worldId, port1, port2) |

## Zone Update Sub-Opcodes (g_clientProtVector)

The 18 entries in `g_clientProtVector` at `<addr in DB>` are zone update sub-opcodes, NOT lobby entries. They are dispatched by `UPDATE_ZONE_PARTIAL` during game phase. Registered via `ClientProt::InitEntry` at `<addr in DB>`.

| Sub-Opcode | Size | Entry Address | Zone Update Type |
|------------|------|--------------|-----------------|
| 0 | 11 | `<addr in DB>` | LOC_ANIM |
| 1 | varByte | `<addr in DB>` | LOC_CUSTOMISE |
| 2 | 5 | `<addr in DB>` | OBJ_ADD |
| 3 | 3 | `<addr in DB>` | OBJ_DEL |
| 4 | 14 | `<addr in DB>` | MAP_ANIM_SPECIFIC |
| 5 | 7 | `<addr in DB>` | LOC_PREFETCH |
| 6 | 20 | `<addr in DB>` | MAP_PROJANIM |
| 7 | 7 | `<addr in DB>` | OBJ_COUNT |
| 8 | 11 | `<addr in DB>` | MAP_ANIM |
| 9 | 2 | `<addr in DB>` | LOC_DEL |
| 10 | 10 | `<addr in DB>` | LOC_ANIM_SPECIFIC |
| 11 | 28 | `<addr in DB>` | MAP_PROJANIM_HALT |
| 12 | 29 | `<addr in DB>` | PROJANIM_SPECIFIC_HALT |
| 13 | 5 | `<addr in DB>` | LOC_MERGE |
| 14 | varByte | `<addr in DB>` | SOUND_AREA |
| 15 | 21 | `<addr in DB>` | PROJANIM_SPECIFIC |
| 16 | varByte | `<addr in DB>` | LOC_ADD |
| 17 | 7 | `<addr in DB>` | OBJ_REVEAL |

## Implementation Priority for Lobby

To get the client into the lobby screen, the server must handle:

1. **Login protocol** (see `login-protocol.md`) — complete the login handshake
2. **NO_TIMEOUT** (opcode 0x92, size 0) — respond to client keepalive pings
3. **CHANGE_LOBBY** (opcode 0x11, varShort) — send world list/lobby data
4. Potentially **LOBBY_APPEARANCE** — player preview (may be handled through player info system)

The account creation packets (CREATE_CHECK_EMAIL_REPLY at opcode 0x9C, CREATE_CHECK_NAME_REPLY at opcode 0x8F) are only needed if implementing in-client account creation. CREATE_ACCOUNT_REPLY, CREATE_SUGGEST_NAME_ERROR, and CREATE_SUGGEST_NAME_REPLY have not been found in rev 947-1 and may have been removed (web-based account creation).

## Login Protocol Step Opcodes

Registered via `jag::LoginProt::InitEntry` at `<addr in DB>`. Active during login handshake only.

| Opcode | Hex | Size | Ghidra Label |
|--------|-----|------|-------------|
| 14 | 0x0E | 0 | `LoginProt::STEP_0E` |
| 15 | 0x0F | varByte (-1) | `LoginProt::STEP_0F` |
| 16 | 0x10 | varShort (-2) | `LoginProt::STEP_10` |
| 19 | 0x13 | varShort (-2) | `LoginProt::STEP_13` |
| 23 | 0x17 | 4 | `LoginProt::STEP_17` |
| 24 | 0x18 | varByte (-1) | `LoginProt::STEP_18` |
| 26 | 0x1A | 0 | `LoginProt::STEP_1A` |
| 27 | 0x1B | 0 | `LoginProt::STEP_1B` |
| 28 | 0x1C | varShort (-2) | `LoginProt::STEP_1C` |
| 29 | 0x1D | varShort (-2) | `LoginProt::STEP_1D` |
| 30 | 0x1E | varShort (-2) | `LoginProt::STEP_1E` |
| 31 | 0x1F | 4 | `LoginProt::STEP_1F` |
