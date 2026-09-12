# ServerProt: ClanSettings Category

> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

## Overview

The ClanSettings packet handler category manages full and incremental clan settings updates. Two handlers are registered inline in `BindHandlers` (<addr in DB>), not via a separate constructor call. ClanSettings objects are 0xF0 bytes and managed as shared pointers with reference counting.

All handlers follow the standard ServerProt invocation pattern:
- Called via `ServerProt.invokePtr(ServerProt.callableData, Packet*, &packetSize)`
- `callableData` contains a pointer to the Client struct
- Return value: `&<in Ghidra DB>` (success)

## ServerProt Opcode Table

| Opcode | Size | Handler Name | Handler Address | ServerProt Global |
|--------|------|--------------|-----------------|-------------------|
| 39 | var-byte | CLANSETTINGS_FULL | `<addr in DB>` | `<addr in DB>` |
| 63 | var-byte | CLANSETTINGS_DELTA | `<addr in DB>` | `<addr in DB>` |

---

## Handler Reference

### CLANSETTINGS_FULL (opcode 39, size var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1 | byte | Slot selector |
| (remaining) | - | Full clan settings data decoded by `ClanSettings::ClanSettings` constructor |

**Slot Selection:**
- `0` or `1`: Slot index (active or guest clan)
- `-1` (0xFF): Clear active clan settings
- `< -1`: Clear both clan settings slots

**Behavior:** Allocates a ClanSettings object wrapper (0xF0 bytes total: 0x20 for shared_ptr header + 0xD0 for ClanSettings data). The internal structure is initialized with:
- `+0x20`: ClanSettings vtable (`PTR_FUN_0148c308`)
- `+0x28`: Zero
- `+0x30`: Zero
- `+0x47`: SSO marker (0x17)
- `+0xC8`: Reference count (`0x01`)
- `+0xD0`: Zero
- `+0xD8`: Float pair `{1.0f, 2.0f}` (packed as `<in Ghidra DB>`3f800000`)
- `+0xE0`: Zero
- `+0xE8`: Data pointer (`<in Ghidra DB>`)

After allocation, calls `ClanSettings::ClanSettings(data, packet)` to decode the full settings from the Packet. The wrapper is then stored as a shared_ptr in the Client's clan settings slots at `__DT_SYMTAB[0x490]` with reference counting via `ref_counter_base::DecRef`.

Wrapper vtable: `PTR_FUN_0148bcd0` (shared_ptr control block)
Reference count: atomic increment/decrement with LOCK prefix

**Client References:**
- `__DT_SYMTAB[0x490]`: Client state (clan settings slots at +0x40/+0x48 for slot 0, +0x00/+0x08 for slot 1)
- `__DT_SYMTAB[0x49c]`: Clan system manager (sequence counters at +0x118/+0x120)

---

### CLANSETTINGS_DELTA (opcode 63, size var-byte)
**Handler Address:** `<addr in DB>` | **ServerProt Global:** `<addr in DB>`

**Packet Format:**
| Read | Type | Description |
|------|------|-------------|
| g1 | byte | Slot selector (active/guest) |
| gT_ulong | ulong | Sequence number (first read, discarded) |
| gT_ulong | ulong | Sequence number (kept for verification) |
| g1 | byte | First delta entry type |
| (loop until type == 0) | | Delta entries |

**Delta Entry Types:**

| Type | Size | Vtable | Description |
|------|------|--------|-------------|
| 1 | 0x30 | `PTR_Decode_0148ca88` | Add/Update member (V1/V2) |
| 3 | 0x10 | `PTR_Decode_0148bee0` | Small delta (rank change, muted flag) |
| 4 | 0x30 | `PTR_Decode_0148ca28` | String delta (name change, etc.) |
| 5 | 0x40 | `PTR_Decode_0148ca58` | Full member update |
| 0 | - | - | End of deltas (sentinel) |

**Behavior:** Reads a sequence of delta entries from the packet. Each entry is allocated via `operator_new` with its type-specific size, initialized with the corresponding vtable, and decoded via the `Decode` virtual method. Successfully decoded entries are collected into a vector.

After reading all entries, verifies that the stored sequence number matches the expected value at `ClanSettings+0x30`. If the slot byte is negative, accesses the settings via direct pointer at `Client+0x58`; otherwise looks up the slot via `<in Ghidra DB>`.

If verification passes, applies all delta entries **in reverse order** (LIFO): iterates the vector from end to start, calling the `Apply` virtual method (`vtable+0x08`) on each entry against the ClanSettings object, then calling the `Destroy` method (`vtable+0x18`) to free each entry.

After applying, increments the sequence counter at `ClanSettings+0x30`.

If verification fails (sequence mismatch or null settings), skips application and just frees all entries.

**Client References:**
- `__DT_SYMTAB[0x490]`: Client state (clan settings access)
- `__DT_SYMTAB[0x49c]`: Clan system manager (sequence counters at +0x128/+0x130)
