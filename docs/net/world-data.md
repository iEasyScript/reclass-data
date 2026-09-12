# World Data Protocol

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


## Overview

The NXT client manages world/lobby connection targets through `WorldLobbyData` objects. These are created when the server instructs the client to connect to a specific game world or lobby node, and also through console commands for testing.

## Data Structures

### WorldLobbyData (0x30 = 48 bytes)

Ghidra struct: `WorldLobbyData` in `/jag`

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0x00 | 8 | long | vtable | vtable pointer (from client + `<in Ghidra DB>`) |
| 0x08 | 4 | int | worldId | World number |
| 0x0C | 4 | int | flags | Reserved / padding |
| 0x10 | 24 | eastl::string | hostname | Server hostname (e.g., "world2.runescape.com") |
| 0x28 | 2 | short | port1 | Primary port (443 for SSL, or computed from worldId) |
| 0x2A | 2 | short | port2 | Secondary/fallback port |
| 0x2C | 1 | byte | isWorld | 1 = game world, 0 = lobby |

**Symbol dump confirms:** `jag::WorldLobbyData::WorldLobbyData(...)`, `jag::WorldLobbyData::GetHTTPURL`

The WorldLobbyData is always wrapped in a shared_ptr (allocated as 0x50 bytes = 0x20 shared_ptr header + 0x30 data).

## Server Packet Handler

### SET_WORLD_TARGET

**Address:** `<addr in DB>`
**Ghidra name:** `jag::packethandlers::WorldData::SET_WORLD_TARGET`

**Packet format:**
```
string hostname     // gStringCP1252ToUTF8 (e.g., "world72.runescape.com")
ushort worldId      // big-endian
ushort port1        // big-endian
ushort port2        // big-endian
```

**Behavior:**
1. Reads hostname, worldId, port1, port2 from packet
2. Checks if a WorldLobbyData already exists at `param_1.0x49d.0x30`
3. If null:
   - Allocates a new WorldLobbyData (0x30 bytes)
   - Sets vtable, worldId, hostname, ports, isWorld=1
   - Wraps in shared_ptr (0x18 byte header)
   - Stores at `param_1.0x49d.0x28` (shared_ptr) and `param_1.0x49d.0x30` (raw ptr)
4. If existing:
   - Updates worldId, hostname, port1, port2 in-place

## Console Commands

### cmd_setworld

**Address:** `<addr in DB>`
**Ghidra name:** `jag::Console::cmd_setworld`

**Usage:** `setworld <worldId> [hostname]`
**Example:** `setworld 72 tws17`

**Behavior:**
1. Parses worldId and optional hostname from console arguments
2. Validates game state is login screen or lobby (states 0x14 or 0x0A)
3. Constructs hostname as `%.*s.runescape.com` from the hostname parameter
4. Computes ports from worldId:
   - If using special development mode: port1=0xAA4A (43594), port2=0x1BB (443)
   - Otherwise: port1 = worldId - 0x63C0, port2 = worldId - 0x3CB0
5. Calls `jag::WorldSwitcher::SetWorldTarget` to create/update the WorldLobbyData
6. Logs "Client configured to connect to World node %d on %.*s"

### cmd_setlobby

**Address:** `<addr in DB>`
**Ghidra name:** `jag::Console::cmd_setlobby`

**Usage:** `setlobby <lobbyId> [hostname]`
**Example:** `setlobby 25 tws14`

Similar to `cmd_setworld` but creates a lobby WorldLobbyData. Logs "Client configured to connect to Lobby node %d on %.*s"

## WorldSwitcher

### SetWorldTarget

**Address:** `<addr in DB>`
**Ghidra name:** `jag::WorldSwitcher::SetWorldTarget`

**Parameters:**
- `param_1`: WorldSwitcher object
- `param_2`: worldId (int)
- `param_3`: hostname (eastl::string*)
- `param_4`: port1 (ushort)
- `param_5`: port2 (ushort)

**Behavior:**
1. Checks if `param_1+0x20` (raw WorldLobbyData ptr) is null
2. If null: allocates new WorldLobbyData, wraps in shared_ptr
3. If existing: updates fields in-place
4. Returns 1 on success

**Symbol dump confirms:** `jag::WorldSwitcher::SwitchWorld`, `jag::WorldSwitcher::ServicePings`, `jag::WorldSwitcher::compareToInner`, `jag::WorldSwitcher::ListSort` (all at different-build addresses)

## Port Computation

The NXT client uses a formula to derive connection ports from the world ID:

```
// Standard port computation (for non-dev worlds):
port1 = worldId - 0x63C0  // = worldId - 25536
port2 = worldId - 0x3CB0  // = worldId - 15536

// Dev/special mode:
port1 = 0xAA4A  // 43594 (RuneScape game port)
port2 = 0x1BB   // 443 (HTTPS/SSL)
```

## Network Diagnostics

**Address:** `<addr in DB>`

A debug overlay function that displays network statistics:
- Connection status via `jag::game::ServerConnection::IsConnected`
- Ping via `jag::ClientStream::GetPing` (displayed as "Ping: %dms")
- Data sent/received totals
- Separate display for Game World and Lobby connections

## UID System

### SET_UID

**Address:** `<addr in DB>`
**Ghidra name:** `jag::UID::SetUID`

**Symbol dump confirms:** `jag::UID::SetUID(jag::Packet&)`, `jag::UID::InitUID`

**Packet format:**
```
byte[24] uidData       // 24 bytes of UID payload
uint     crc32         // CRC32 checksum of uidData (using table at <in Ghidra DB>)
```

**Behavior:**
1. Computes CRC32 over the 24-byte UID payload (8 bytes at a time, using lookup table at `<in Ghidra DB>`)
2. Reads the 4-byte CRC32 from the packet (big-endian if needed)
3. Verifies `~computed_crc == packet_crc` -- returns error if mismatch
4. Copies the 24-byte UID data to the connection object at offset `+0xA8`
5. Formats the UID as a hex string (each byte formatted with `%02x`)
6. Stores the hex UID string via `Settings::Set("uid", hexString)`

## CS2 Script Opcodes

### player_group_member_get_same_world_var

**Address:** `<addr in DB>`
**Ghidra name:** `jag::opcode::player_group_member_get_same_world_var`

Checks if a player group member is on the same world as the local player.

## Related Strings

| Address | String |
|---------|--------|
| <addr in DB> | "Game World" |
| <addr in DB> | "Lobby" |
| <addr in DB> | "Game World Login Result: %d (%s)" |
| <addr in DB> | "Pre-loading world..." |
| <addr in DB> | "setworld" |
| <addr in DB> | "setlobby" |
| <addr in DB> | "Client configured to connect to World node %d on %.*s" |
| <addr in DB> | "Client configured to connect to Lobby node %d on %.*s" |
| <addr in DB> | "Auto world select disabled" |
| <addr in DB> | "Attempting to login to lobby" |
| <addr in DB> | "Attempting to login to world using OAuth2 credentials" |
| <addr in DB> | "World Map" |

## Related Functions

| Address | Name | Description |
|---------|------|-------------|
| <addr in DB> | jag::packethandlers::WorldData::SET_WORLD_TARGET | Server packet: set world/lobby target |
| <addr in DB> | jag::WorldSwitcher::SetWorldTarget | Create/update WorldLobbyData |
| <addr in DB> | jag::Console::cmd_setworld | Console: set game world target |
| <addr in DB> | jag::Console::cmd_setlobby | Console: set lobby target |
| <addr in DB> | jag::UID::SetUID | Server packet: set/verify client UID |
| <addr in DB> | <in Ghidra DB> | Network diagnostics display |
| <addr in DB> | jag::opcode::player_group_member_get_same_world_var | CS2: check same world |
