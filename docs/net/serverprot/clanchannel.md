# ServerProt: ClanChannel Category

> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

## Overview

The ClanChannel packet handler category manages full and incremental clan channel data updates. Two handlers are registered inline in `BindHandlers` (<addr in DB>), not via a separate constructor call. Both handlers manage clan channel member lists stored in vectors of 0x50-byte entries.

All handlers follow the standard ServerProt invocation pattern:
- Called via `ServerProt.invokePtr(ServerProt.callableData, Packet*, &packetSize)`
- `callableData` contains a pointer to the Client struct
- Return value: `&<in Ghidra DB>` (success)

## ServerProt Opcode Table

| Opcode | Size | Handler Name | Handler Address | ServerProt Global |
|--------|------|--------------|-----------------|-------------------|
| 83 | var-byte | CLANCHANNEL_FULL | `<addr in DB>` | `<addr in DB>` |
| 123 | var-size | CLANCHANNEL_DELTA | `<addr in DB>` | `<addr in DB>` |

---

## Handler Reference

### CLANCHANNEL_FULL (opcode 83, size var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1 | byte | Channel slot selector |
| (variable) | - | Full clan channel data decoded via `<in Ghidra DB>` |

**Slot Selection:**
- `0` or `1`: Slot index (active or guest channel)
- `-1`: Clear active channel slot
- `< -1`: Clear both channel slots

**Behavior:** Allocates a ClanChannel object (0x80 bytes) via `<in Ghidra DB>`, decodes full channel data from the Packet via `<in Ghidra DB>`, wraps in a `shared_ptr`, and stores in the Client's clan channel slots at `__DT_SYMTAB[0x490]` offsets +0x20/+0x30/+0x50. If a previous ClanChannel object exists in the target slot, its reference count is decremented. This is the full-state version sent on login, clan join, or when too many deltas have accumulated.

**Client References:**
- `__DT_SYMTAB[0x490]`: Client state (clan channel slots)
- `__DT_SYMTAB[0x49c]`: Clan system manager

---

### CLANCHANNEL_DELTA (opcode 123, size var-size)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| gStringCP1252ToUTF8 | string | Display name |
| g1 | byte | Has previous name flag (1 = yes) |
| (if has previous name) gStringCP1252ToUTF8 | string | Previous display name |
| g2 BE | ushort | World ID (byte-swapped on LE) |
| g1s | byte (signed) | Rank value |
| (if rank != -128) gStringCP1252ToUTF8 | string | Clan name |

**Behavior:** Processes incremental clan channel updates. The operation depends on the rank value:

- **Rank == -128 (DELETE):** Searches the member list by display name and world ID. When found, removes the entry by shifting subsequent entries using `<in Ghidra DB>` (EASTL move operations) and shrinks the vector. Each member entry is 0x50 bytes containing strings (display name, previous name, clan name) at 0x18-byte EASTL string size with SSO.

- **Rank != -128 (ADD/UPDATE):** First checks if user already exists by comparing display names (using SSO-aware string comparison with `memcmp`). If found, updates the existing entry's fields (rank, name, clan name) via `<in Ghidra DB>`. If not found, appends a new entry to the end of the vector (with capacity growth via `HeapInterface::Alloc` and element-by-element copy via `<in Ghidra DB>`).

After any modification, if more than one member exists, re-sorts the member list via `<in Ghidra DB>`. Finally, invokes a callback at `channel+0x70` if set (notifies UI of clan channel change).

**Member Entry Layout (0x50 bytes):**

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0x00 | 24 | eastl::string | Display name |
| 0x18 | 24 | eastl::string | Previous display name |
| 0x30 | 4 | uint | World ID |
| 0x34 | 4 | int | Rank |
| 0x38 | 24 | eastl::string | Clan name |

**Client References:**
- `__DT_SYMTAB[0x494]`: Client reference (for local player rank update)
- `__DT_SYMTAB[0x49c]`: Clan system manager
- `__DT_SYMTAB[0x4dc]`: Privacy/filtering settings (for ignore check)

---

## Key Subsystem Functions

| Address | Name | Description |
|---------|------|-------------|
| `<addr in DB>` | HeapInterface::Alloc | Allocates memory for ClanChannel objects |
| `<addr in DB>` | ClanChannel::Decode | Decodes full clan channel from Packet |
| `<addr in DB>` | ClanChannel::SortMembers | Sorts member list after modification |
| `<addr in DB>` | ClanChannel::CopyEntry | Copies a 0x50-byte member entry |
| `<addr in DB>` | eastl::string::assign | EASTL string assignment |
| `<addr in DB>` | eastl::move | EASTL move operation for entry shifting |
| `<addr in DB>` | ComparePlayerName | Compares player names for local player detection |
