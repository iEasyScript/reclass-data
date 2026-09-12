# ServerProt: WORLDLIST_FETCH_REPLY

> **Binary**: rs2client rev 947-1 (stripped, x86_64, Ghidra port 8083)
> **Handler**: `packethandlers::Social::WORLDLIST_FETCH_REPLY` at `<addr in DB>`
> **Opcode**: 159 (varShort)
> **947 ProtEntry**: at `g_serverProt_WORLDLIST_FETCH_REPLY`
> **946 Opcode**: 150
> **Last verified**: 2026-03-26 (full decompilation trace of handler + all subfunctions)

## Overview

The WORLDLIST_FETCH_REPLY packet delivers the world list to the client. It supports multi-segment reassembly (the client accumulates data across multiple packets until the frame byte indicates the final segment) and two operational modes controlled by the refresh flag.

The Ghidra label `UPDATE_FRIENDCHAT_CHANNEL` was misleading — this is the world list handler, confirmed by structural analysis of the read format and world hashtable population.

## Handler Architecture

The handler accesses the WorldList subsystem via `__DT_SYMTAB[0x49d]` (same vtable slot as the WorldData/FriendChat system). The WorldList object lives at offset `+0x10` from that subsystem pointer.

### Reassembly Buffer

The handler maintains a reassembly buffer wrapped as a `jag::Packet` struct at subsystem offset `+0xd0`:
- `+0xd8` (`+0x08` in Packet): buffer capacity
- `+0xe0` (`+0x10` in Packet): buffer data pointer
- `+0xe8` (`+0x18` in Packet): current read/write position

On first invocation (when `+0xd8` is NULL), a 20,000-byte buffer is allocated via `jag::Packet::ResizeBuffer`. Subsequent data (after the frame byte) is appended via `memcpy`. When the frame byte is `0x01` (final segment), the reassembled buffer is parsed.

## Packet Format

### Outer Framing (from the raw ServerProt packet)

| Offset | Size | Read | Type | Description |
|--------|------|------|------|-------------|
| 0 | 1 | g1 | byte | **Frame byte**: `0` = more segments follow, `1` = final segment. If not `1`, remaining bytes are appended to the reassembly buffer and the handler returns. |

Bytes 1..N (the rest of the ServerProt payload after the frame byte) are appended to the reassembly buffer. When frame == 1, the full reassembled buffer is parsed as described below.

### Reassembled Payload Format

The reassembled payload position starts at 0. All reads below are from the reassembled buffer, NOT the original packet.

| Pos | Size | Read | Type | Description |
|-----|------|------|------|-------------|
| 0 | 1 | g1 | byte | **Refresh flag**: `2` = active refresh (definitions and/or player counts), anything else = no-op (rebuild vector from cache) |

---

### Active Refresh (refreshFlag == 2)

When refreshFlag == 2, the handler sets position to 2 (consuming both the refresh flag at byte 0 AND the separator at byte 1).

| Pos | Size | Read | Type | Description |
|-----|------|------|------|-------------|
| 1 | 1 | g1 | byte | **Separator**: `1` = has world definitions section followed by player counts, `0` = player counts only |

**The separator byte is always consumed (position advances to 2).** Its value determines whether world definitions are read before the player counts.

#### When separator == 1: World Definitions Section

On separator==1, the handler first clears the existing world hashtable and country array, then reads:

##### 1. Country List

| Read | Type | Description |
|------|------|-------------|
| getUnsignedSmart | smart | **countryCount**: number of country entries |

For each country (countryCount times):

| Read | Type | Description |
|------|------|-------------|
| getUnsignedSmart | smart | **countryId**: numeric country identifier |
| gjStr2 | JagString | **countryName**: country display name (version-byte-prefixed, null-terminated CP1252) |

The country entries are stored in an array at `WorldListObj+0x48`/`+0x50`/`+0x58`. Each entry is a 0x20-byte struct containing:
- `+0x00` (4 bytes): countryId
- `+0x08` (24 bytes): countryName (eastl::string, SSO capacity 0x17)

**Important**: Multiple country entries MAY share the same `countryId`. For example, Jagex's live worldlist has three entries with countryId=225 ("United States (East Coast 1)", "United States (East Coast 2)", "United States (West Coast)") and two with countryId=77 ("UK (London)", "UK"). Each world references a country entry by array index, not by countryId.

##### 2. World ID Range and Count

| Read | Type | Description |
|------|------|-------------|
| getUnsignedSmart | smart | **minWorldId**: lowest actual world number (e.g., `1`). Stored at `WorldListObj+0x38`. Used as base for worldNumberOffset calculations. |
| getUnsignedSmart | smart | **maxWorldId**: highest actual world number (e.g., `259`). Stored at `WorldListObj+0x3C`. Used as upper bound in post-processing iteration (inclusive). |
| getUnsignedSmart | smart | **worldCount**: number of world entries to follow. Stored at `WorldListObj+0x40`. Also used as iteration count for the player count section. |

**CRITICAL**: `maxWorldId` is the actual highest world number, NOT max+1. The post-processing loop iterates `for (i = minWorldId; i <= maxWorldId; i++)` inclusive. Sending max+1 wastes one lookup but does not crash.

##### 3. World Entries

For each world (worldCount times):

| Read | Type | Description |
|------|------|-------------|
| getUnsignedSmart | smart | **worldNumberOffset**: offset from `minWorldId`. The **hashtable key** is this raw offset value, NOT `minWorldId + offset`. |
| g1 | byte | **countryIndex**: index into the country array (0-based) |
| g4 (BE) | int | **flags**: world flags bitmask (see Flags section below) |
| getUnsignedSmart | smart | **activityPresence**: `0` = no activity string follows, non-zero = activity string follows. The raw value is stored at entry `+0x34`. |
| gjStr2 (conditional) | JagString | **activity**: only read if `activityPresence != 0`. See String Semantics below. |
| gjStr2 | JagString | **hostname**: stored at entry `+0x58`. See String Semantics below. |
| gjStr2 | JagString | **serverAddress**: stored at entry `+0x70`. This is the actual server hostname used for connections. |

**Hashtable keying**: The world entry is inserted into the hashtable keyed by `worldNumberOffset` (the raw smart value), NOT by `minWorldId + worldNumberOffset`. This is critical for the player count section, which must use the same offset values.

The display world number (`minWorldId + worldNumberOffset`) is stored separately at entry `+0x50`.

Each world entry struct is 0x98 bytes:

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 4 | uint | hashtable key (= worldNumberOffset, the raw smart value) |
| 0x08 | 4 | uint | countryIndex (country array index) |
| 0x10 | 4 | uint | countryId (resolved from `countryArray[countryIndex].id`) |
| 0x18 | 24 | string | countryName (copied from `countryArray[countryIndex].name`) |
| 0x30 | 4 | uint | flags |
| 0x34 | 4 | uint | activityPresence (raw smart value) |
| 0x38 | 24 | string | activity (empty if activityPresence was 0) |
| 0x50 | 4 | uint | displayWorldNumber (= minWorldId + worldNumberOffset) |
| 0x58 | 24 | string | hostname |
| 0x70 | 24 | string | serverAddress |
| 0x88 | 8 | long | playerCount (initialized to -1/0xFFFFFFFF) |
| 0x90 | 8 | ptr | next pointer (hashtable chain) |

##### 4. Revision

| Read | Type | Description |
|------|------|-------------|
| g4 (BE) | int | **revision**: world list revision/CRC. Stored at `WorldListObj+0x60`. Client sends this back in WORLDLIST_FETCH to enable delta updates. |

After storing the revision, `WorldListObj` byte 0 is set to `1` (marks as initialized).

---

### Player Count Section (only when refreshFlag == 2)

**This section is only read when refreshFlag == 2.** It is read regardless of the separator value (both separator=1 and separator=0). It is NOT read for delta refresh (refreshFlag != 2).

Read for each world (`worldCount` iterations, using `WorldListObj+0x40` as the count):

| Read | Type | Description |
|------|------|-------------|
| (see below) | smart | **worldNumberOffset**: the offset value (same as the hashtable key from the world definitions section) |
| g2 (BE) | ushort | **playerCount**: player count for this world. `0xFFFF` means "use previous value" (i.e., no change) |

**CRITICAL**: The world number in the player count section is a `worldNumberOffset` (= `worldNumber - minWorldId`), NOT the actual world number. The client looks up this value in the hashtable, which is keyed by offsets. Sending actual world numbers here will cause all lookups to fail silently (player counts show as -1).

#### World Number Offset Encoding in Player Counts

The world number offset uses a custom encoding that is functionally identical to `getUnsignedSmart`:

1. **Peek** at the next byte without consuming it
2. If the byte's **high bit is set** (value >= 0x80):
   - Read a **g2 (BE unsigned short)** and subtract `0x8000` from the result
   - This yields the world number offset
3. If the high bit is **clear** (value < 0x80):
   - Consume that single byte as the world number offset directly

Encoding for `writeSmart(value)`:
- Value 0..127: write 1 byte (the value)
- Value 128..32767: write 2 bytes big-endian (`value + 0x8000`)

#### Player Count Sentinel

When the g2 read returns `0xFFFF`, the handler uses the **previous playerCount value** (initialized to `0xFFFFFFFF` at loop start). This allows the server to skip worlds whose counts haven't changed.

After decoding, the handler looks up the world number offset in the hashtable. If found AND the entry is NOT the sentinel entry at the end of the bucket chain, the entry's `+0x88` field (playerCount) is updated.

---

### No-Op Refresh (refreshFlag != 2)

When the refresh flag is NOT `2`:
- The separator byte is NOT consumed (position stays at 1)
- No country, world definition, or player count data is read from the buffer
- The handler proceeds directly to post-processing (rebuild the pointer vector from cached state)

This mode is used when the client's cached worldlist is already current. The buffer typically contains just the refresh flag byte and nothing else.

**Encoder note**: To send player-count-only updates (no world redefinition), use `refreshFlag=2, separator=0`. Do NOT use `refreshFlag=0` — that skips all data reading including player counts.

---

### Post-Processing: World Pointer Vector

After parsing, the handler builds a vector of pointers to world entries (at subsystem offsets `+0x120`/`+0x128`/`+0x130`). It iterates from `minWorldId` to `maxWorldId` **inclusive**:

```
for (i = minWorldId; i <= maxWorldId; i++) {
    offset = i - minWorldId;
    entry = hashtable.lookup(offset);
    if (entry != null && entry != sentinel) {
        vector.append(entry + 0x08);  // skip hashtable key field
    }
}
```

This vector is used by the lobby UI to display worlds in sorted order.

Finally:
- Subsystem `+0xB0` is set to `0` (refresh complete flag)
- The reassembly buffer is freed (capacity/data/position zeroed)
- A timestamp is recorded at `+0xB8` (steady_clock / 1000000, in milliseconds)

---

## String Field Semantics (from Jagex live capture analysis)

The three string fields per world entry have specific semantic roles that differ from what the field names suggest:

### When activityPresence == 0 (most worlds)

| Client Field | Contains | Example |
|-------------|----------|---------|
| (activity) | *(not read)* | — |
| hostname (+0x58) | **UI display text** (activity label) | `"Trade - Members"`, `"Dungeoneering"`, `"Clan Recruitment"` |
| serverAddress (+0x70) | **Actual server hostname** | `"world1.runescape.com"` |

### When activityPresence != 0 (region-specific worlds)

The activityPresence value appears to be a country/region code.

| Client Field | Contains | Example (world 4, actPres=38=Canada) |
|-------------|----------|---------|
| activity (+0x38) | **Region/country display text** | `"Canada"` |
| hostname (+0x58) | **Placeholder** | `"-"` |
| serverAddress (+0x70) | **Actual server hostname** | `"world4.runescape.com"` |

### Key Insight

**The actual server hostname is ALWAYS in the `serverAddress` field (+0x70), never in `hostname` (+0x58).** The `hostname` field is used for UI display purposes. When implementing a server, write the activity/display text as the `hostname` gjStr2 and the actual server address as the `serverAddress` gjStr2.

---

## Flags Bitmask

World flags are a 32-bit integer. Known bits from capture analysis:

| Bit | Hex | Meaning |
|-----|-----|---------|
| 0 | <addr in DB> | Members world |
| 1 | <addr in DB> | Quick Chat only |
| 2 | <addr in DB> | PvP / Wilderness |
| 3 | <addr in DB> | Loot Share |
| 4 | <addr in DB> | VIP / Premium |
| 14 | <addr in DB> | Classic Only (Legacy Combat) |
| 15 | <addr in DB> | (observed, meaning TBD) |
| 17 | <addr in DB> | EoC Only |

**There is NO port field.** No flag-based conditional read exists in the 947-1 handler. Port information comes from `SET_WORLD_TARGET` packet or jav_config params.

---

## Encoder Checklist (common bugs)

These are verified requirements from the binary that are easy to get wrong:

1. **refreshFlag must be 2** for any data to be read. Using 0 causes the client to skip ALL buffer reading.
2. **separator byte is always consumed** when refreshFlag==2. Write `1` for full definitions, `0` for player-count-only updates.
3. **maxWorldId** must be the actual highest world number (e.g., 259), NOT max+1.
4. **Player count world numbers** must be `worldNumberOffset` values (= `worldNumber - minWorldId`), NOT actual world numbers. The hashtable is keyed by offsets.
5. **All strings must use gjStr2 format**: `0x00` version byte + string bytes + `0x00` null terminator. If the version byte is not 0, the client returns empty and only consumes 1 byte, desynchronizing all subsequent reads.
6. **Country array indices** are 0-based and must match the order countries were written.

---

## String Encoding: gjStr2

The string reading function at `<addr in DB>` implements `gjStr2`:

```
1. Read 1 byte (version)
2. If version != 0:
   - Return empty string
   - Only 1 byte consumed (version byte only!)
   - WARNING: This desynchronizes all subsequent reads
3. If version == 0:
   - Compute string length via strlen(data + position)
   - If length == 0: advance position by 1 (past null terminator), return empty
   - If length > 0: copy string, advance position past null terminator
```

The server MUST write strings in this format:
- Write `0x00` (version byte)
- Write string bytes in CP1252 encoding
- Write `0x00` (null terminator)

For empty strings: write `0x00 0x00` (version byte + null terminator).

---

## getUnsignedSmart Encoding

Decompiled from `<addr in DB>`:

```c
ushort getUnsignedSmart(Packet* pkt) {
    byte b = pkt->data[pkt->position];
    if (b < 0x80) {
        pkt->position += 1;
        return b;           // 0..127
    }
    ushort v = g2(pkt);    // reads 2 bytes big-endian (0x8000..0xFFFF)
    return v - 0x8000;     // 0..32767
}
```

**Note**: The decompiled code shows `(short)g2 + 0x8000` due to signed/unsigned casting, but this is mathematically equivalent to `g2 - 0x8000` (since g2 >= 0x8000 when first byte >= 0x80).

Encoding (`writeSmart`):
- Value 0..127: write 1 byte
- Value 128..32767: write 2 bytes big-endian as `value + 0x8000`

---

## Read Function Reference

| Function | Address | Description |
|----------|---------|-------------|
| g1 | inline | Read 1 unsigned byte, advance position by 1 |
| g2 (BE) | `<addr in DB>` | Read 2-byte big-endian unsigned short, advance by 2. On LE platforms: read native ushort, byte-swap. |
| g4 (BE) | `<addr in DB>` | Read 4-byte big-endian unsigned int, advance by 4. On LE platforms: read native uint, byte-swap. |
| getUnsignedSmart | `<addr in DB>` | Peek byte: if < 0x80, consume 1 byte (return 0..127); else read g2, return g2 - 0x8000 (0..32767) |
| gjStr2 | `<addr in DB>` | Read version byte (must be 0), then null-terminated CP1252 string. Version mismatch returns empty and consumes only 1 byte. |

---

## Live Capture Examples (Jagex rev 947-1)

### Full Refresh — First World Entry

Raw bytes (after country list and world range):
```
00 01 00 00 00 01 00 00 54 72 61 64 65 20 2D 20 4D 65 6D 62 65 72 73 00 00 77 6F 72 6C 64 31 2E 72 75 6E 65 73 63 61 70 65 2E 63 6F 6D 00
```

Decoded:
| Bytes | Read | Value |
|-------|------|-------|
| `00` | smart(0) | worldNumberOffset = 0 |
| `01` | g1 | countryIndex = 1 ("United States (East Coast 1)") |
| `00 00 00 01` | g4 | flags = 0x01 (members) |
| `00` | smart(0) | activityPresence = 0 (no activity string) |
| `00 54...73 00` | gjStr2 | hostname = "Trade - Members" (UI display) |
| `00 77...6D 00` | gjStr2 | serverAddress = "world1.runescape.com" (actual server) |

### Full Refresh — World with activityPresence

Raw bytes for world 4 (offset 3):
```
03 03 00 00 00 09 26 00 43 61 6E 61 64 61 00 00 2D 00 00 77 6F 72 6C 64 34 2E 72 75 6E 65 73 63 61 70 65 2E 63 6F 6D 00
```

Decoded:
| Bytes | Read | Value |
|-------|------|-------|
| `03` | smart(3) | worldNumberOffset = 3 |
| `03` | g1 | countryIndex = 3 ("United States (West Coast)") |
| `00 00 00 09` | g4 | flags = 0x09 (members + lootshare) |
| `26` | smart(38) | activityPresence = 38 (non-zero → read activity) |
| `00 43...61 00` | gjStr2 | activity = "Canada" |
| `00 2D 00` | gjStr2 | hostname = "-" (placeholder) |
| `00 77...6D 00` | gjStr2 | serverAddress = "world4.runescape.com" |

### Player Count Section

Raw bytes (after revision `53 A6 67 DD`):
```
00 00 5B 01 00 CF 02 00 C6 03 02 46 04 00 B1 ...
```

Decoded:
| Bytes | Offset | Count | Actual World |
|-------|--------|-------|--------------|
| `00` `00 5B` | 0 | 91 | world 1 |
| `01` `00 CF` | 1 | 207 | world 2 |
| `02` `00 C6` | 2 | 198 | world 3 |
| `03` `02 46` | 3 | 582 | world 4 |
| `04` `00 B1` | 4 | 177 | world 5 |

Note: Player count world numbers are **offsets from minWorldId**, matching the hashtable keys from the world definitions.
