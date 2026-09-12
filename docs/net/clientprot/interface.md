# ClientProt: Interface Packets

> **Rev 947-1**: Opcodes and many sizes changed significantly from 946. See `clientprot-table.md` for the 947-1 table.

Packets related to interface (UI) interactions, button clicks, dialog responses, and modal management.

## IF_BUTTON System

### IF_BUTTON Pointer Table
The IF_BUTTON opcodes (1-10) are dispatched via a pointer table at `<addr in DB>`. Each entry is a pointer to a ClientProt object, indexed by `(buttonOp - 1)`.

`IfButtonXInner` (`<addr in DB>`) handles two cases:
1. **No target string**: Sends `IF_BUTTON{N}` (opcode from table) with component hash, slot, and opValue
2. **With target string**: Sends `IF_BUTTONT` (opcode 107) with string data, button op, slot, opValue, and target name

### IF_BUTTONT (Button with Target)
| Field | Description |
|-------|-------------|
| **Opcode** | 107 |
| **Size** | VAR_BYTE |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `IfButtonXInner` (`<addr in DB>`) |

**Packet Format:**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | varies | string | targetName | Name of the target being acted upon |
| varies | 1 | byte | buttonOp | Button operation number (1-10) |
| varies | 2 | ushort | slot | Interface slot |
| varies | 4 | int | opValue | Operation value |

### IF_BUTTON_TARGETMENU
| Field | Description |
|-------|-------------|
| **Opcode** | 75 |
| **Size** | VAR_SHORT |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

---

## CLOSE_MODAL

### CLOSE_MODAL (Close Active Modal)
| Field | Description |
|-------|-------------|
| **Opcode** | 87 |
| **Size** | 0 (no payload) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |
| **Category** | Interface |

No payload -- opcode only. Tells the server to close the currently active modal interface.

### CLOSE_MODAL_COMPONENT
| Field | Description |
|-------|-------------|
| **Opcode** | 117 |
| **Size** | 6 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` |

**Packet Format:**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | int | componentHash | Interface ID << 16 | Component ID |
| 4 | 2 | ushort | unknown | Additional parameter |

---

## RESUME Packets

These packets resume server-side script execution after the client has shown a dialog and the player has responded.

### RESUME_PAUSEBUTTON
| Field | Description |
|-------|-------------|
| **Opcode** | 10 |
| **Size** | VAR_SHORT |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |

Sent when the player clicks "Continue" on a pause dialog. VAR_SHORT allows for variable-length response data.

### RESUME_COUNTDIALOG
| Field | Description |
|-------|-------------|
| **Size** | fixed, one 32-bit int |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (the `resume_countdialog` CS2 opcode; `resume_countdialog_long` is the 64-bit sibling) |

Sent when the player submits a number in a count dialog (e.g., "How many?"). The payload is the
typed string parsed with `strtol` on the client, so the server never sees the text.

**How a number box is opened.** The client owns the keyboard; the server only points it at a box.
Every text-entry box in an interface is a *listener* component whose `onvarctransmit` hook watches
the `p_dialog_listener` and `p_dialog_mode` varcs. The server sets `p_dialog_listener` to that
component's hash, `p_dialog_mode` to the count-dialog mode and `p_dialog_maxchar` to the length
limit; the listener's own script then shows the caret, takes key input and answers with this
packet (or ABORT_P_DIALOG). After answering, the client resets the three varcs itself.

### RESUME_NAMEDIALOG
| Field | Description |
|-------|-------------|
| **Opcode** | 56 |
| **Size** | VAR_BYTE |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (CS2 opcode handler) |

Sent when the player submits a name/text in a name dialog (e.g., search boxes).

---

## IF_BUTTON_TARGETMENU_SEND (opcode 114)

Complex interface interaction packet for component-level operations.

| Field | Description |
|-------|-------------|
| **Opcode** | 114 |
| **Size** | 22 (fixed) |
| **DAT Address** | `<addr in DB>` |
| **Sender** | `<addr in DB>` (InterfaceManager) |

**Packet Format (22 bytes):**
| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | int | opValue | Operation value (via <in Ghidra DB>) |
| 4 | 4 | int | param2 | Second parameter (p4_alt1) |
| 8 | 4 | int | componentHash | Target component (via <in Ghidra DB>) |
| 12 | 4 | int | param4 | Fourth parameter (p4_alt1) |
| 16 | 4 | int | param5 | Fifth parameter (via <in Ghidra DB>) |
| 20 | 2 | short | slotId | Slot identifier (short, custom encoding) |

---

## IF_DROPDOWN_SELECT (native dropdown and list selection)

| Field | Description |
|-------|-------------|
| **Size** | fixed, 11 bytes |
| **Sender** | `jag::InterfaceManager::SendIfDropdownSelect`, reached from `SendIfButtonTargetMenu` |

A native dropdown (`if_add_child_dropdown` / the combo widget) and a multi-select list report their
selection with this packet rather than with IF_BUTTON. It is only sent for a component whose
IF_SETEVENTS carries the "allow target send" bit (bit 24) - that bit is what the server arms on the
settings pane's row layer, and it is the reason every dropdown row there answers.

**Wire order:** `int componentHash`, `byte committed` (0x00 or 0xFF), `int value` (little-endian),
`short slot` written low byte + 128 then high byte.

A combo sends twice per change: the entry the player picked with `committed = 0`, then the widget's
settled value with `committed = 1`; the second is the one to act on. A multi-select list sends one
packet per entry that changed, with `committed` carrying that entry's selected flag. The value is
the entry's value (the enum key the script added it with), not its row index.

## Notes

- The IF_BUTTON dispatch table at `<addr in DB>` holds pointers to ClientProt objects for buttons 1-10
- RESUME packets resume server-side CS2 scripts that are waiting for player input
- CLOSE_MODAL has zero payload -- it just sends the opcode byte
- The `_COMPONENT` variant of CLOSE_MODAL specifies which component to close rather than closing all modals
