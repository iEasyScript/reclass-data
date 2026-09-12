# ServerProt: Variables Category

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Rev 947-1 update**: Opcodes reshuffled, some byte transforms changed. See `serverprot-947-matched.md`
> for detailed byte transform changes (UPDATE_STAT, VARP_SMALL, VARP_LARGE, CLIENT_SETVARC_LARGE all changed).
> See `serverprot-table.md` for the canonical 947-1 opcode/size table.

Packet handlers for all variable-related server protocol opcodes. These handlers
are registered by the Variables constructor at `<addr in DB>` (947-1).

The constructor also registers several `ClientState` handlers and `StatTable::UpdateStat`
alongside the variable handlers. All are documented below.

## Engine Offset Cross-References

| Engine Object       | Offset                | Description                          |
|---------------------|-----------------------|--------------------------------------|
| `OPlayerVarDomain`  | `HASH_TABLE = `<in Ghidra DB>`| PlayerVarDomain hash table           |
| `OPlayerVarDomain`  | `VAR_ID = 0x0`        | Var entry ID field                   |
| `OPlayerVarDomain`  | `VAR_VALUE = 0x8`     | Var entry value field                |
| `OClientVarDomain`  | `HASH_TABLE = 0x18`   | ClientVarDomain hash table           |
| `OClientVarDomain`  | `VAR_ID = 0x0`        | Var entry ID field                   |
| `OClientVarDomain`  | `VAR_VALUE = 0x8`     | Var entry value field                |

## Key Addresses & Constants

| Address      | Name                      | Description                            |
|--------------|---------------------------|----------------------------------------|
| `<addr in DB>` | `VAR_PLAYER_TYPE`         | ConfigProvider type constant for VarPlayer |
| `<addr in DB>` | `VAR_CLIENT_TYPE`         | ConfigProvider type constant for VarClient |
| `<addr in DB>` | `VAR_BIT_TYPE`            | ConfigProvider fallback/VarBit type    |
| `<addr in DB>` | `PACKET_HANDLER_SUCCESS`  | Return value for successful handling   |

## Client Structure Offsets (Relevant)

| Offset       | Description                                    |
|--------------|------------------------------------------------|
| `+`<in Ghidra DB>`   | PlayerVarDomain base (used by VARP/VARBIT handlers) |
| `+`<in Ghidra DB>`   | PlayerVarDomain hash table 1 (cleared by RESET_ALL_VARPS) |
| `+`<in Ghidra DB>`   | PlayerVarDomain hash table 2 / clan vars (cleared by RESET_ALL_VARPS) |

---

## Variable Handlers

### SET_VARP_SMALL

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| Address     | `<addr in DB>`                                       |
| Namespace   | `jag::packethandlers::Variables::SET_VARP_SMALL`   |

**Packet Format (3 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 1    | byte   | raw                                | varp_id low byte (multiplied by 0x100) |
| 1      | 1    | byte   | +0x80 signed transform             | varp_id high byte |
| 2      | 1    | byte   | subtract 0x80 (signed)             | value       |

**varp_id** = `byte[0] * 256 + (byte[1] + 0x80)`

**Action:** Calls `ConfigProvider::GetVarType(configProvider, VAR_PLAYER_TYPE, varp_id)` to
resolve the var type, then `PlayerVarDomain::set(Client+`<in Ghidra DB>`, varType, &value)` with the
value as a 32-bit int (type flag = 0 = int).

---

### SET_VARP_INT

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::SET_VARP_INT`    |

**Packet Format (6 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 2    | ushort | big-endian (byte[1]*256 + byte[0]) | varp_id     |
| 2      | 4    | int    | big-endian (manual byte swap)      | value       |

**Action:** Same as SET_VARP_SMALL but reads a full 4-byte int value. Calls
`ConfigProvider::GetVarType` then `PlayerVarDomain::set` with type flag = 0 (int).

---

### SET_VARP_LONG

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::SET_VARP_LONG`   |

**Packet Format (10 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 8    | long   | big-endian (full 8-byte byte swap) | value       |
| 8      | 2    | ushort | big-endian with +0x80 on byte[9]   | varp_id     |

**Action:** Reads the long value first (with full big-endian byte swap on little-endian
systems), then the varp_id. Sets value type flag to 1 (long). Calls
`ConfigProvider::GetVarType` then `PlayerVarDomain::set`.

---

### SET_VARBIT_SMALL

| Field       | Value                                               |
|-------------|-----------------------------------------------------|
| Address     | `<addr in DB>`                                        |
| Namespace   | `jag::packethandlers::Variables::SET_VARBIT_SMALL`  |

**Packet Format (3 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 2    | ushort | big-endian byte swap if LE         | varbit_id   |
| 2      | 1    | byte   | signed                             | value       |

**Action:** Looks up the VarBit definition using ConfigProvider. If the game state is 4
(logged in), resolves the backing varp via a virtual call (`vtable+0x40` on the config
provider's varbit list). Calls `PlayerVarDomain::setBitFromPacket(Client+`<in Ghidra DB>`,
varbitConfig, value)` which reads the current varp value, extracts the relevant bit
range (using lowBit at config+0x48 and highBit at config+0x4C), and writes back the
modified varp.

---

### SET_VARBIT_INT

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::SET_VARBIT_INT`  |

**Packet Format (6 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 4    | int    | big-endian byte swap if LE         | value       |
| 4      | 2    | ushort | big-endian byte swap if LE         | varbit_id   |

**Action:** Same as SET_VARBIT_SMALL but reads a full 4-byte int value.

---

### SET_VARC_SMALL

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::SET_VARC_SMALL`  |

**Packet Format (3 bytes):**

| Offset | Size | Type   | Encoding                                | Description |
|--------|------|--------|-----------------------------------------|-------------|
| 0      | 1    | byte   | signed (negated then subtract 0x80)     | value       |
| 1      | 2    | ushort | little-endian (byte[2]*256 + byte[1])   | varc_id     |

**Action:** Calls `ConfigProvider::GetVarType(configProvider, VAR_CLIENT_TYPE, varc_id)`.
Gets the ClientVarDomain pointer via `__DT_SYMTAB[0x493]` offset from the client.
Increments the update counter at `clientVarDomain+0x10` and sets the dirty flag at
`clientVarDomain+0x14 = 1`. Allocates a var entry via `<in Ghidra DB>(clientVarDomain, 1,
varTypeId)` (type 1 = int), inserts it via `<in Ghidra DB>`, then sets the int value at
`entry+0x20` via `<in Ghidra DB>`.

---

### SET_VARC_INT

| Field       | Value                                           |
|-------------|-------------------------------------------------|
| Address     | `<addr in DB>`                                    |
| Namespace   | `jag::packethandlers::Variables::SET_VARC_INT`  |

**Packet Format (6 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 2    | ushort | big-endian byte swap if LE         | varc_id     |
| 2      | 4    | int    | big-endian (manual byte assembly)  | value       |

**Action:** Same as SET_VARC_SMALL but reads a full 4-byte int value. Uses same
ClientVarDomain update counter increment and dirty flag pattern.

---

### RESET_VARC_SMALL

| Field       | Value                                               |
|-------------|-----------------------------------------------------|
| Address     | `<addr in DB>`                                        |
| Namespace   | `jag::packethandlers::Variables::RESET_VARC_SMALL`  |

**Packet Format (3 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 1    | byte   | negated signed                     | value       |
| 1      | 2    | ushort | big-endian byte swap if LE         | varc_id     |

**Action:** If the game state is 4 (logged in), looks up the VarBit config to resolve the
backing varc (same pattern as VARBIT handlers). Gets the ClientVarDomain pointer,
increments update counter, sets dirty flag. Calls `<in Ghidra DB>(clientVarDomain, varConfig,
value)` to reset/overwrite the var entry.

---

### RESET_VARC_INT

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::RESET_VARC_INT`  |

**Packet Format (6 bytes):**

| Offset | Size | Type   | Encoding                           | Description |
|--------|------|--------|------------------------------------|-------------|
| 0      | 2    | ushort | big-endian byte swap if LE         | varc_id     |
| 2      | 4    | int    | big-endian (manual byte assembly)  | value       |

**Action:** Same as RESET_VARC_SMALL but reads a full 4-byte int value.

---

### SET_VARC_STR

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| Address     | `<addr in DB>`                                      |
| Namespace   | `jag::packethandlers::Variables::SET_VARC_STR`    |

**Packet Format (variable length):**

| Offset | Size     | Type   | Encoding                           | Description |
|--------|----------|--------|------------------------------------|-------------|
| 0      | variable | string | CP1252 null-terminated             | string value |
| N      | 2        | ushort | little-endian (byte[N+1]*256 + byte[N]) | varc_id |

**Action:** Reads the string first (CP1252 encoding, converted to UTF-8 via
`Packet::gStringCP1252ToUTF8_basic_string`), then reads the varc_id. Calls
`ConfigProvider::GetVarType` with `VAR_CLIENT_TYPE`. Allocates a var entry with type 2
(string) via `<in Ghidra DB>(clientVarDomain, 2, varTypeId)`. Copies the string to
`entry+0x20` via `<in Ghidra DB>`. Frees temporary string allocations.

---

### SET_VARC_STR_SMALL

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| Address     | `<addr in DB>`                                           |
| Namespace   | `jag::packethandlers::Variables::SET_VARC_STR_SMALL`   |

**Packet Format (variable length):**

| Offset | Size     | Type   | Encoding                           | Description |
|--------|----------|--------|------------------------------------|-------------|
| 0      | 2        | ushort | big-endian (byte[0]*256 + (byte[1]+0x80)) | varc_id |
| 2      | variable | string | CP1252 null-terminated             | string value |

**Action:** Same as SET_VARC_STR but reads the varc_id first (with +0x80 transform on the
second byte), then the string. Same ClientVarDomain entry allocation and string copy pattern.

---

### SET_VARC_COORD

| Field       | Value                                               |
|-------------|-----------------------------------------------------|
| Address     | `<addr in DB>`                                        |
| Namespace   | `jag::packethandlers::Variables::SET_VARC_COORD`    |

**Packet Format (10 bytes):**

| Offset | Size | Type   | Encoding                           | Description     |
|--------|------|--------|------------------------------------|-----------------|
| 0      | 2    | ushort | big-endian with +0x80 on byte[0]   | varc_id         |
| 2      | 4    | int    | g4_alt1 encoding                   | coord_x (or y?) |
| 6      | 4    | int    | g4_alt1 encoding                   | coord_y (or x?) |

**Action:** Calls `ConfigProvider::GetVarType` with `VAR_CLIENT_TYPE`. Allocates a var entry
in the ClientVarDomain. Stores the coordinates as a combined 8-byte value
(`CONCAT44(coord_x, coord_y)`) at `entry+0x20`. Sets the entry type to 1 (long/coord) at
`entry+0x38`. If the entry already existed with type 1, directly overwrites the value.

---

### RESET_ALL_VARPS

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| Address     | `<addr in DB>`                                         |
| Namespace   | `jag::packethandlers::Variables::RESET_ALL_VARPS`    |

**Packet Format (0 bytes):** No packet data.

**Action:** Clears all player variables by:
1. Calling `<in Ghidra DB>(Client+`<in Ghidra DB>`, ...)` to clear the primary PlayerVarDomain hash table
2. Calling `<in Ghidra DB>(Client+`<in Ghidra DB>`, ...)` to clear the secondary/clan hash table
3. Setting the clan var index to -1 (4 bytes at specific offset)
4. Zeroing clan var state (8 bytes)
5. Incrementing the ClientVarDomain update counter by 0x41
6. Setting the ClientVarDomain dirty flag to 1, clean flag to 0

---

## ClientState Handlers (Also Registered by Variables Constructor)

### CLEAR_PENDING_UPDATES

| Field       | Value                                                       |
|-------------|-------------------------------------------------------------|
| Address     | `<addr in DB>`                                                |
| Namespace   | `jag::packethandlers::ClientState::CLEAR_PENDING_UPDATES`   |

**Packet Format (0 bytes):** No packet data.

**Action:** Iterates over a vector of pending client variable update entries (at
`ClientVarDomain+0x5170..0x5178`). For each entry (0x28 bytes each), resets the type
byte at `entry+0x20` to 4 (unset/empty), calling type-specific destructors as needed
(via `PTR_FUN_014ada60` dispatch table). Resets the pending update count at
`ClientVarDomain+0x5188` to 0 and the vector end pointer to match the begin pointer.

---

### DESTROY_ZONE_DATA

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| Address     | `<addr in DB>`                                              |
| Namespace   | `jag::packethandlers::ClientState::DESTROY_ZONE_DATA`     |

**Packet Format (0 bytes):** No packet data.

**Action:** Clears the zone data pointer at `ClientVarDomain+0x5238` (sets to null). If the
previous pointer was non-null, calls the object's destructor via `vtable+0x8`.

---

### RESET_CLIENT_STATE

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| Address     | `<addr in DB>`                                              |
| Namespace   | `jag::packethandlers::ClientState::RESET_CLIENT_STATE`    |

**Packet Format (0 bytes):** No packet data.

**Action:** Allocates a fresh zone data object (0x38 bytes) with vtable `PTR_FUN_01493600`.
Initializes default values (scale = 1.0f at appropriate offset). Sets it as the current
zone data at `ClientVarDomain+0x5238`. Destroys the previous zone data via `vtable+0x8`
if one existed.

---

### UPDATE_ZONE_PARTIAL

| Field       | Value                                                      |
|-------------|-------------------------------------------------------------|
| Address     | `<addr in DB>`                                               |
| Namespace   | `jag::packethandlers::ClientState::UPDATE_ZONE_PARTIAL`    |

**Packet Format (variable length):**

| Offset | Size     | Type   | Encoding                           | Description      |
|--------|----------|--------|------------------------------------|------------------|
| 0      | 2        | ushort | big-endian byte swap if LE         | zone_type_id     |
| 2      | variable | varies | determined by zone type config     | zone update data |

**Action:** If no zone data exists at `ClientVarDomain+0x5238`, creates one (same as
RESET_CLIENT_STATE). Looks up the zone type config via ConfigProvider. Resolves the zone
type's deserializer via the config's resource table. Reads the zone data from the packet
using a virtual call on the deserializer (`vtable+0x20`). Stores the zone data in the
zone data map (keyed by zone_type_id). Tracks modified zone IDs in a circular buffer
(max 64 entries) at `ClientVarDomain+0x88/0x90`.

---

### StatTable::UpdateStat

| Field       | Value                                          |
|-------------|------------------------------------------------|
| Address     | `<addr in DB>`                                   |
| Namespace   | `jag::StatTable::UpdateStat`                   |

Already documented elsewhere. Registered as the last handler in the Variables constructor.

---

## Handler Registration Order (Constructor)

The constructor at `<addr in DB>` registers handlers to global function pointer slots in this
order:

| # | Slot Address  | Manager FP      | Handler FP      | Handler Name         |
|---|---------------|-----------------|-----------------|----------------------|
| 1 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | RESET_ALL_VARPS      |
| 2 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARP_SMALL       |
| 3 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARP_INT         |
| 4 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARP_LONG        |
| 5 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARBIT_SMALL     |
| 6 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARBIT_INT       |
| 7 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARC_SMALL       |
| 8 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARC_INT         |
| 9 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARC_COORD       |
|10 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | RESET_VARC_SMALL     |
|11 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | RESET_VARC_INT       |
|12 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARC_STR         |
|13 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | SET_VARC_STR_SMALL   |
|14 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | CLEAR_PENDING_UPDATES|
|15 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | DESTROY_ZONE_DATA    |
|16 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | RESET_CLIENT_STATE   |
|17 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | UPDATE_ZONE_PARTIAL  |
|18 | `<addr in DB>`  | `<in Ghidra DB>`  | `<addr in DB>`    | UpdateStat           |

Each registration follows the pattern:
1. Save old manager function pointer to stack
2. Set new manager (wrapper that validates params and calls handler)
3. Set new handler function pointer
4. Swap old captured client reference with the registration's client ref
5. If old manager existed, call it to destroy old state

## Packet Reading Conventions

The packet structure uses:
- `packet+0x10` = data buffer pointer
- `packet+0x18` = current read position (pos)
- All multi-byte integers use big-endian encoding in the wire format
- The client detects endianness via `<in Ghidra DB> == `<in Ghidra DB>` (true = little-endian system)
- When on little-endian, manual byte-swap is performed
- Some ID fields use a +0x80 transform on one byte (signed bias)
- String values use CP1252 encoding, converted to UTF-8 internally
- `Packet::g4_alt1` at `<addr in DB>` reads a 4-byte int with alternative encoding

## Var Type System

Variables are stored with a type discriminator:
- Type 0 / flag=0: **int** (4 bytes at entry+0x20)
- Type 1 / flag=1: **long** (8 bytes at entry+0x20, used by SET_VARP_LONG and SET_VARC_COORD)
- Type 2: **string** (EASTL string at entry+0x20, used by SET_VARC_STR/STR_SMALL)
- Type 4: **empty/unset** (cleared state)
- Type 0xFF: **uninitialized** (needs type-specific initialization before use)

The type byte is stored at `entry+0x20` for pending updates, and at `entry+0x38` for
ClientVarDomain entries.

## PlayerVarDomain vs ClientVarDomain

**PlayerVarDomain** (VARP/VARBIT handlers):
- Located at `Client+`<in Ghidra DB>`
- Uses `PlayerVarDomain::set(domain, varType, valuePtr)` for direct value assignment
- Uses `PlayerVarDomain::setBitFromPacket(domain, varbitConfig, value)` for bit manipulation
- Hash table at `Client+`<in Ghidra DB>`
- Engine: `OPlayerVarDomain.HASH_TABLE = `<in Ghidra DB>` (relative to PlayerVarDomain base at +`<in Ghidra DB>`, so absolute = `<in Ghidra DB>`+`<in Ghidra DB>` = `<in Ghidra DB>`)

**ClientVarDomain** (VARC handlers):
- Accessed via `__DT_SYMTAB[0x493]` offset from client
- Has update counter at `+0x10` and dirty flag at `+0x14`
- Uses `<in Ghidra DB>(domain, valueType, varTypeId)` to allocate entries
- Uses `<in Ghidra DB>(domain, entry)` to insert entries
- Value stored at `entry+0x20`; type discriminator at `entry+0x38`
- Engine: `OClientVarDomain.HASH_TABLE = 0x18`
