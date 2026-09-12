# ServerProt: WorldData Category

> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

## Overview

The WorldData packet handler category contains a single handler for setting the game world target (hostname and ports for world switching). Registered inline in `BindHandlers` (<addr in DB>), not via a separate constructor call.

All handlers follow the standard ServerProt invocation pattern:
- Called via `ServerProt.invokePtr(ServerProt.callableData, Packet*, &packetSize)`
- `callableData` contains a pointer to the Client struct
- Return value: `&<in Ghidra DB>` (success)

## ServerProt Opcode Table

| Opcode | Size | Handler Name | Handler Address | ServerProt Global |
|--------|------|--------------|-----------------|-------------------|
| 149 | var-size | SET_WORLD_TARGET | `<addr in DB>` | `<addr in DB>` |

---

## Handler Reference

### SET_WORLD_TARGET (opcode 149, size var-size)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| gStringCP1252ToUTF8 | string | Hostname |
| g2 BE | ushort | World ID (byte-swapped on LE) |
| g2 BE | ushort | Port 1 (byte-swapped on LE) |
| g2 BE | ushort | Port 2 (byte-swapped on LE) |

**Behavior:** Sets the target game world for world switching. Two code paths depending on whether a WorldLobbyData object already exists:

**First connection (no existing data at `FriendChat+0x30`):**
Allocates a new WorldLobbyData object (0x50 bytes total: 0x20 for shared_ptr header + 0x30 for data). The data portion is initialized as:

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0x00 | 8 | long | Base pointer (Client+`<in Ghidra DB>`) |
| 0x08 | 4 | uint | World ID |
| 0x0C | 1 | byte | isWorld flag (set to 1) |
| 0x10 | 24 | eastl::string | Hostname |
| 0x28 | 2 | ushort | Port 1 |
| 0x2A | 2 | ushort | Port 2 |
| 0x2C | 4 | int | World type (set to 1) |

The wrapper uses shared_ptr vtable `PTR_FUN_01490718` with reference counting. The data pointer is stored at `FriendChat+0x28` (shared_ptr control block) and `FriendChat+0x30` (data pointer).

**Subsequent updates (existing data):**
Updates the existing WorldLobbyData in-place:
- Assigns the hostname string via `eastl::basic_string::assign`
- Updates the World ID at +0x08
- Updates Port 1 at +0x28
- Updates Port 2 at +0x2A

**Client References:**
- `__DT_SYMTAB[0x49d]`: FriendChat/WorldData system (+0x08=Client reference, +0x28=shared_ptr, +0x30=data pointer)
