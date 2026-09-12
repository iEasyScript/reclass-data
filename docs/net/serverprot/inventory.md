# ServerProt: Inventory Category

Byte-precise wire format for the RS3 NXT **948-5** server→client inventory (container) update
packets, plus the per-item **obj-var / `var_object`** sub-encoding.

Source of truth: the `rs2client.948-5` Ghidra DB. Handlers were named by the structural ServerProt
registration campaign (see `948-5-prot-source-of-truth`) as flat `jag::PacketHandlers::<CamelName>`.
Opcodes/sizes come from the Ghidra DB — never mirrored here.

| Opcode | Size | Name | Handler | Address |
|--------|------|------|---------|---------|
| 20  | 3 (fixed)     | `UPDATE_INV_STOP_TRANSMIT` | `jag::PacketHandlers::UpdateInvStopTransmit` | `<addr in DB>` |
| 85  | -2 (varShort) | `UPDATE_INV_FULL`          | `jag::PacketHandlers::UpdateInvFull`         | `<addr in DB>` |
| 121 | -2 (varShort) | `UPDATE_INV_PARTIAL`       | `jag::PacketHandlers::UpdateInvPartial`      | `<addr in DB>` |

These are the **only** three inventory opcodes, and the **only** carriers of obj-vars — there is no
separate `SET_OBJ_VAR` packet. Obj-vars are embedded per-slot inside FULL/PARTIAL (gated by a flag).

All multi-byte integers below are the payload **after** the opcode + (for varShort) the 2-byte
length prefix, which the framing layer handles. Byte transforms use the shorthand from
`../buffer-transform-patterns.md`; every one maps to a helper in
`core/.../buffer/JagExtensions.kt` (exceptions flagged).

---

## Engine Offset Cross-References

| Engine object | Offset | Meaning |
|---------------|--------|---------|
| `OClient.INVENTORY_MANAGER` | `Client + `<in Ghidra DB>` | `jag::game::InventoryManager` (sorted container vector) |
| (redraw ring)               | `Client + `<in Ghidra DB>` | 64-entry container-refresh ring (`+0xA8` base, `+0xB0` counter) |
| `OInventory.INVENTORY_ID`   | `inv + 0x08` | containerKey (`GetInventory`/`CreateInventory` arg) |
| `OInventory.INVENTORY_ITEMS`| `inv + 0x10` | items array `{int id, int amount}` stride 8 |
| (obj-var array)             | `inv + 0x28` | per-slot ObjVarDomain array, stride `0x38` |

Manager methods (verified in rs2client): `jag::game::InventoryManager::GetInventory
(engine `INVENTORYMANAGER_GETINVENTORY`), `...::CreateInventory.

---

## Container Key & Flags (shared by all three packets)

The client `InventoryManager` holds a vector of containers sorted by an **internal key**:

```
internalKey = containerKey * 2 | keyFlag
```

- **`containerKey`** — a 16-bit id. It is the container / **inv** id (e.g. backpack 93, worn 94,
  bank 95 — the `InvType` config id), NOT an interface-component packed value (those are 32-bit and
  would not fit). `GetInventory(mgr, containerKey, keyFlag)` / `CreateInventory(...)` binary-search
  this vector by `internalKey`.
- **`keyFlag`** — a 1-bit discriminator (bit 0 of the FULL/PARTIAL `flags` byte). Lets two logical
  containers share one `containerKey`. **Normally 0.**

FULL/PARTIAL carry a **`flags`** byte:

| Bit | Mask | Meaning |
|-----|------|---------|
| 0 | `0x01` | `keyFlag` (into the internal key, above) |
| 1 | `0x02` | **has obj-vars**: each slot record carries a trailing obj-var block |

(No other bits are read.)

---

## UPDATE_INV_FULL (opcode 85, varShort)

Rebuilds an entire container: slots `0 .. slotCount-1` are all present (dense).

**Header**

| Off | Type | Name | Description |
|-----|------|------|-------------|
| 0 | g2 (`readUShort`, BE) | `containerKey` | inv id |
| 2 | g1 (`readUByte`)      | `flags`        | bit0 keyFlag, bit1 hasVars |
| 3 | g2 (`readUShort`, BE) | `slotCount`    | number of slots that follow |

**Then `slotCount` slot records**, each:

| Field | Type | Description |
|-------|------|-------------|
| `objId` | g3 (`readUMedium`, BE) | **wire = objId + 1**; `0` = empty slot (stored internally as id `-1`). Widened from g2 in 949 — see [Obj-id width](#obj-id-width) |
| `amount` | g1 (`readUByte`); if that byte `== 0xFF` then g4 (`readInt`, BE) | 1-byte amount `0..254`, else `0xFF` sentinel + full 4-byte int |
| `varCount` | g1 (`readUByte`) — **only if `flags & 0x02`** | number of obj-var entries for this slot |
| `vars` | `varCount` × { g2 varId (BE) + g4 value (BE int) } | see [Obj-Var Domain](#obj-var--var_object-domain) |

Notes:
- The amount byte is read **unconditionally** for every slot (even empty ones → send `objId=0`,
  `amount=0`). When `flags & 0x02`, the `varCount` byte is likewise present for every slot (send
  `varCount=0` for slots with no vars).
- The container is obtained via `CreateInventory(mgr, containerKey, keyFlag)` — FULL always
  (re)creates, so a prior container of the same key is discarded.

---

## UPDATE_INV_PARTIAL (opcode 121, varShort)

Applies only the changed slots to an existing container (created on demand if absent). The record
list is **self-delimited by the varShort length** — the handler loops until the read cursor reaches
the packet end; there is no slot count.

**Header** (identical to FULL minus `slotCount`)

| Off | Type | Name | Description |
|-----|------|------|-------------|
| 0 | g2 (`readUShort`, BE) | `containerKey` | inv id |
| 2 | g1 (`readUByte`)      | `flags`        | bit0 keyFlag, bit1 hasVars |

Container = `GetInventory(mgr, containerKey, flags&1)`, or `CreateInventory(...)` if not found.

**Then, until end-of-packet, repeated slot records**, each:

| Field | Type | Description |
|-------|------|-------------|
| `slotIndex` | **gSmart1or2** (`readSmart`) | 1 byte if `< 0x80`, else 2-byte BE with `& 0x7FFF` |
| `objId` | g3 (`readUMedium`, BE) | **wire = objId + 1**; `0` = empty (clears the slot). Widened from g2 in 949 — see [Obj-id width](#obj-id-width) |
| `amount` | g1 (`readUByte`); `0xFF` → g4 (`readInt`, BE) | **omitted entirely when `objId == 0`** |
| `varCount` | g1 (`readUByte`) — only if `objId != 0` **and** `flags & 0x02` | obj-var entry count |
| `vars` | `varCount` × { g2 varId (BE) + g4 value (BE int) } | obj-var entries |

**Key difference from FULL:** in PARTIAL an empty slot is encoded as just `[gSmart slotIndex][g3 0]`
— no amount byte and no var block. FULL always emits amount (and, if hasVars, varCount) for every
slot.

### Obj-id width

949 widened the inventory obj-id field from **g2 to g3**, client-wide — it is not specific to one
packet. Both decoders select the width at runtime on `<in Ghidra DB> >= 0x3b5`; on 949-1 that gate is
satisfied, so g3 is the live encoding. A g2 encoder desyncs the whole record stream, not just the
id, because every following field shifts by one byte.

`Rev949ServerCodecsInventory.kt` already emits `writeMedium`. Anything else that writes an
inventory obj id must match, and pre-949 revisions keep g2.

---

## UPDATE_INV_STOP_TRANSMIT (opcode 20, fixed 3 bytes)

Tells the client to stop tracking/rendering a container: it binary-searches the manager vector for
`internalKey`, destroys and erases that container, and pushes `containerKey` onto the redraw ring.

**Wire (3 bytes)** — the client reconstructs `(containerKey, keyFlag)` from a different byte layout
than FULL/PARTIAL:

| Off | Server writes | Client decode |
|-----|---------------|---------------|
| 0 | `writeByteSubtract(keyFlag)` | `keyFlag = (0x80 - byte0) & 1` |
| 1 | `writeByteAdd(containerKey & 0xFF)` | low byte of containerKey |
| 2 | `writeByte(containerKey >> 8)` | high byte of containerKey |

Bytes 1–2 together are exactly `writeShortAddLittle(containerKey)` (low byte add-transformed, then
raw high byte). So the whole payload is:

```
writeByteSubtract(keyFlag)        // byte0  (keyFlag normally 0 -> 0x80)
writeShortAddLittle(containerKey) // bytes1-2
```

`internalKey = containerKey*2 | keyFlag` is then reconstructed identically to `CreateInventory`.

---

## Obj-Var / `var_object` Domain

Per-item variables (the `var_object` domain; gamevals `var_object.json`) are transmitted **inline**
inside FULL/PARTIAL — never as a standalone packet. When `flags & 0x02`, each non-empty slot record
ends with:

```
varCount : g1                       // number of entries
entry  : varCount × {
    varId  : g2  (readUShort, BE)   // the var_object id
    value  : g4  (readInt,   BE)    // signed 4-byte int
}
```

The wire value is **always a 4-byte int** (variant type 0). The domain can physically hold other
variant types (long/string), but the inventory protocol only ever sends int.

### Client-side attachment

Each inventory slot owns an **ObjVarDomain** (a `jag::game::VarDomain` — an open-hash map keyed by
`uint varId`) at `inv+0x28 + slotIndex*0x38 + 0x08`. For each wire `(varId, value)` the handler
calls `jag::game::VarDomain::FindOrCreateEntry` (`<addr in DB>`) then assigns the int value via the
shared variant-assign helper (`<addr in DB>`).

Domain object (open-hash table):

| Offset | Type | Meaning |
|--------|------|---------|
| `+0x08` | `void**` | bucket pointer array |
| `+0x10` | `ulong`  | bucket count (hash modulus) |
| `+0x18` | `long`   | element count |

`bucket = varId % bucketCount`; collisions chain via each node's `next`.

**ObjVarEntry** node (`0x30` bytes; Ghidra struct `/jag/ObjVarEntry`):

| Offset | Type | Field | Description |
|--------|------|-------|-------------|
| `0x00` | int   | `varId` | key (from wire g2) |
| `0x08` | variant (0x18) | `value` | inventory wire = int (type 0) |
| `0x20` | byte  | `valueType` | `0`=int, `1`=long, `2`=string, `4`=empty, `0xFF`=uninit |
| `0x28` | ObjVarEntry* | `next` | next node in the bucket chain |

This matches the player/client var entry layout in `variables.md` (`VAR_ID=0x0`, `VAR_VALUE=0x8`) —
the same generic `VarDomain`/variant machinery, reused per inventory slot.

### Server mapping

The server maps an item stack's metadata attributes → `(varId, value)` int pairs. Emit them in the
slot's var block; the client stores them keyed by `varId` on that slot's item. There is no ordering
or terminator requirement beyond the leading `varCount`.

---

## Encoder Pseudocode

`writeByte`/`writeShort`/`writeInt` are big-endian g1/g2/g4. `writeSmart`, `writeByteAdd`,
`writeByteSubtract`, `writeShortAddLittle` are the JagExtensions helpers of the same name.

> ⚠️ **Missing helper:** the container **amount** ("1 byte if `0..254`, else `0xFF` + 4-byte int")
> has no JagExtensions counterpart. Add one (e.g. `writeInventoryAmount`) or inline it — do not
> reuse `writeSmart`/`writeBigSmart` (different boundary and encoding).

```
fun writeInventoryAmount(amount):
    if 0 <= amount <= 254:
        writeByte(amount)
    else:
        writeByte(255)
        writeInt(amount)            // BE, signed

fun writeVarBlock(slotVars):        // only when hasVars
    writeByte(slotVars.size)        // varCount, g1
    for (varId, value) in slotVars:
        writeShort(varId)           // g2 BE
        writeInt(value)             // g4 BE int

fun UPDATE_INV_FULL(containerKey, keyFlag, hasVars, slots):   // varShort
    writeShort(containerKey)
    writeByte((if hasVars then 2 else 0) or (keyFlag and 1))
    writeShort(slots.size)                       // slotCount
    for slot in slots (index 0..size-1):
        writeMedium(slot.objId + 1)              // 0 => empty
        writeInventoryAmount(slot.amount)        // even for empty (objId 0, amount 0)
        if hasVars:
            writeVarBlock(slot.vars)             // varCount present for EVERY slot

fun UPDATE_INV_PARTIAL(containerKey, keyFlag, hasVars, changedSlots):   // varShort
    writeShort(containerKey)
    writeByte((if hasVars then 2 else 0) or (keyFlag and 1))
    for (slotIndex, slot) in changedSlots:
        writeSmart(slotIndex)
        writeMedium(slot.objId + 1)
        if slot.objId != 0:                      // objId 0 => empty, stop here
            writeInventoryAmount(slot.amount)
            if hasVars:
                writeVarBlock(slot.vars)

fun UPDATE_INV_STOP_TRANSMIT(containerKey, keyFlag = 0):   // fixed 3 bytes
    writeByteSubtract(keyFlag)                   // byte0
    writeShortAddLittle(containerKey)            // bytes1-2 (low add, high raw)
```

---

## Verification

- `[Verified in rs2client / <addr in DB> / <addr in DB>]` — the three handlers decompiled
  and annotated; prototypes + entry comments committed to the Ghidra DB.
- `[Verified in rs2client / <addr in DB>]` — `CreateInventory`/`GetInventory` confirm
  `internalKey = containerKey*2 | keyFlag` and `containerKey` stored at `inv+0x08`.
- `[Verified in rs2client` — obj-var domain find-or-create; ObjVarEntry node layout.
- `[Pattern hint from librs2client.so — NOT a byte-layout source]` — reference confirms the class
  name `jag::game::VarDomain` and the shared variant type system; offsets taken only from the target.
