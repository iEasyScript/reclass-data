# ClientProt: Action Packets

> **Rev 947-1**: Opcodes and many sizes changed significantly from 946. See `clientprot-table.md` for the 947-1 table.

Entity interaction packets sent when the player interacts with game objects (locations), NPCs, other players, or ground items.

## OPLOC (Location/Object Actions)

Location actions are dispatched by the minimenu system via `DoOpLoc` functions.

### OPLOC1 (Walk Here / Primary Action)
| Field | Description |
|-------|-------------|
| **Opcode** | 70 |
| **Size** | 4 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (DoOpLoc, op=1) |

**Packet Format:**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | int | packedCoordAndId | Packed location coord + type ID |

### OPLOC_T (Use Item on Location)
| Field | Description |
|-------|-------------|
| **Opcode** | 27 |
| **Size** | 12 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

**Packet Format:**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 12 | mixed | targetData | Location target + item source info |

### OPLOC_T (Long Form)
| Field | Description |
|-------|-------------|
| **Opcode** | 16 |
| **Size** | 11 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

### OPLOC_T (Extended Form)
| Field | Description |
|-------|-------------|
| **Opcode** | 37 |
| **Size** | 15 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

### OPLOC_CS2 (Script-Triggered Location Action)
| Field | Description |
|-------|-------------|
| **Opcode** | 94 |
| **Size** | VAR_BYTE |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |

---

## OPNPC (NPC Actions)

NPC actions are dispatched via a switch statement in `<addr in DB>` that selects from 6 different ClientProt objects based on the action op (1-6).

### OPNPC1 (Primary/Attack)
| Field | Description |
|-------|-------------|
| **Opcode** | 26 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

### OPNPC2
| Field | Description |
|-------|-------------|
| **Opcode** | 25 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

### OPNPC3
| Field | Description |
|-------|-------------|
| **Opcode** | 23 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

### OPNPC4
| Field | Description |
|-------|-------------|
| **Opcode** | 90 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

### OPNPC5
| Field | Description |
|-------|-------------|
| **Opcode** | 77 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

### OPNPC6
| Field | Description |
|-------|-------------|
| **Opcode** | 103 |
| **Size** | 7 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | via OPNPC dispatch switch |

**Common OPNPC Packet Format (all 7 bytes):**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 2 | ushort | npcServerIndex | Server index of the target NPC |
| 2 | 1 | byte | ctrlRun | 1 if ctrl-click (run), 0 otherwise |
| 3 | 4 | int | packedCoord | Packed coordinate data |

### OPNPC_CS2 (Script-Triggered NPC Action)
Handled by `<addr in DB>` at opcode 104 (DAT `<addr in DB>`, VAR_BYTE). The CS2 script provides the NPC target and action data from the script string stack.

---

## OPOBJ (Ground Item Actions)

Ground item actions are dispatched via a switch statement in `<addr in DB>` that selects from 10 different ClientProt objects based on the action op (1-10).

### OPOBJ1-10 Opcodes
| Op | Opcode | Size | DAT Address |
|----|--------|------|-------------|
| 1 | 20 | 3 | `<addr in DB>` |
| 2 | 46 | 3 | `<addr in DB>` |
| 3 | 115 | 3 | `<addr in DB>` |
| 4 | 96 | 3 | `<addr in DB>` |
| 5 | 6 | 3 | `<addr in DB>` |
| 6 | 60 | 3 | `<addr in DB>` |
| 7 | 14 | 3 | `<addr in DB>` |
| 8 | 59 | 3 | `<addr in DB>` |
| 9 | 91 | 3 | `<addr in DB>` |
| 10 | 30 | 3 | `<addr in DB>` |

**Common OPOBJ Packet Format (3 bytes):**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 1 | byte | runFlag | Bit 15 = ctrl-run, combined with delta bytes |
| 1 | 2 | ushort | objIdAndCoord | Object ID and location data |

### OPOBJ_T (Use Item on Ground Object)
| Field | Description |
|-------|-------------|
| **Opcode** | 105 |
| **Size** | 11 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

### OPOBJ_CS2 (Script-Triggered Object Action)
| Field | Description |
|-------|-------------|
| **Opcode** | 98 |
| **Size** | VAR_BYTE |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |

---

## OPPLAYER (Player Actions)

### OPPLAYER_T (Use Item on Player)
| Field | Description |
|-------|-------------|
| **Opcode** | 120 |
| **Size** | 11 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

### OPPLAYER_T (Extended)
| Field | Description |
|-------|-------------|
| **Opcode** | 58 |
| **Size** | 17 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

### OPPLAYER_CS2 (Script-Triggered Player Action)
| Field | Description |
|-------|-------------|
| **Opcode** | 119 |
| **Size** | VAR_BYTE |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |

---

## Notes

- All action packets are triggered by the minimenu (right-click menu) system through `DoActionEntry` (`<addr in DB>`)
- The `_T` suffix indicates "targeted" variants where an item is being used ON an entity
- The `_CS2` suffix indicates the action was triggered by a ClientScript (CS2) rather than direct player interaction
- OPNPC and OPOBJ use dispatch switches to select the correct opcode based on the action operation number (1-N)
- The `ctrlRun` / `runFlag` field indicates whether the player held Ctrl to force-run to the target
