# TcpIn ISAAC Opcode Decoding (rs2client rev 946)

**Binary:** rs2client (Ghidra port 8080)
**Function:** `jag::ConnectionManager::TcpIn` at `<addr in DB>`
**Supporting:** `jag::Isaac::TakeNextValue` at `<addr in DB>`

## Summary

**ISAAC is applied to BOTH bytes of a 2-byte opcode.** Each byte consumes one ISAAC value via `Isaac::TakeNextValue`. The server's current encoding is correct.

## Detailed Decoding Flow

### Step 1: Read First Byte

The function reads 1 byte from the connection into a buffer at `lVar5 + 0x2d0`:

```c
ClientStream::Read(*(ClientStream **)(lVar5 + 8), *(void **)(lVar5 + 0x2d0), 1);
```

### Step 2: Peek for ISAAC (Pre-Check)

Before formally consuming the ISAAC value, the code peeks at the raw byte and subtracts the *current* ISAAC value to check if it will be >= 128 (i.e., a 2-byte opcode marker). This is done to know whether a second byte needs to be read *before* blocking:

```c
bVar4 = **(byte **)(lVar5 + 0x2d0);  // raw first byte from wire

// Peek at current ISAAC value WITHOUT consuming it
if (pIVar9->randcnt == 0) {
    Isaac::Generate(pIVar9);
    pIVar9->randcnt = 0x100;
    uVar25 = 0xff;
} else {
    uVar25 = (ulong)(pIVar9->randcnt - 1);
}

// Check: (rawByte - isaacPeek) & 0xFF > 0x7F ?
if (0x7f < ((uint)bVar4 - (&pIVar9->randrsl)[uVar25] & 0xff)) {
    // Need second byte -- read it now
    ClientStream::Read(..., (void *)(*(long *)(lVar5 + 0x2d0) + 1), 1);
}
```

**Important:** This peek does NOT consume the ISAAC value. It reads `randrsl[randcnt-1]` directly without decrementing `randcnt`. The value is only consumed in the next step.

### Step 3: Decode First Byte with ISAAC (Formal Consumption)

```c
bVar4 = **(byte **)(lVar5 + 0x2d0);          // raw first byte (re-read)
uVar14 = Isaac::TakeNextValue(pIVar9);        // CONSUMES isaac value #1
uVar23 = bVar4 - uVar14 & 0xff;              // decoded first byte
```

`TakeNextValue` decrements `randcnt` and returns `randrsl[randcnt]`. This is the same value that was peeked at in Step 2, now formally consumed.

### Step 4: Check if 2-Byte Opcode

```c
if (0x7f < uVar23) {
    // decoded first byte >= 128 --> this is a 2-byte opcode
```

### Step 5: Decode Second Byte with ISAAC

```c
lVar28 = *(long *)(lVar5 + 0x2d8);           // buffer offset (= 1, pointing to second byte)
*(long *)(lVar5 + 0x2d8) = lVar28 + 1;       // advance offset
bVar4 = *(byte *)(*(long *)(lVar5 + 0x2d0) + lVar28);  // raw second byte
uVar14 = Isaac::TakeNextValue(pIVar9);        // CONSUMES isaac value #2
uVar23 = (uVar23 - 0x80) * 0x100 + (bVar4 - uVar14 & 0xff);  // final opcode
```

### Step 6: Final Opcode Assembly

The final 16-bit opcode is:

```
opcode = (decodedByte1 - 128) * 256 + decodedByte2
```

Where:
- `decodedByte1 = (rawByte1 - isaac_value_1) & 0xFF` -- must be >= 128
- `decodedByte2 = (rawByte2 - isaac_value_2) & 0xFF`

## Server Encoding (Verified Correct)

The server must encode as:

```
byte1 = ((opcode >> 8) + 128 + isaac.nextInt) & 0xFF
byte2 = (opcode + isaac.nextInt) & 0xFF
```

This is correct because the client decodes:
1. `decodedByte1 = (byte1 - isaac1) & 0xFF` = `(opcode >> 8) + 128` (which is >= 128, triggering 2-byte path)
2. `decodedByte2 = (byte2 - isaac2) & 0xFF` = `opcode & 0xFF`
3. `finalOpcode = (decodedByte1 - 128) * 256 + decodedByte2` = `(opcode >> 8) * 256 + (opcode & 0xFF)` = `opcode`

## 1-Byte Opcode Path (for completeness)

When `decodedByte1 < 128`, the opcode is simply `decodedByte1`. Only one ISAAC value is consumed. No second byte is read.

## Non-ISAAC Path (for completeness)

When `pIVar9 == NULL` (ISAAC not yet initialized, e.g., during login), the function uses `Packet::gSmart1or2` instead:
- If the first byte's high bit is 0 (value < 128): opcode = that byte (1 byte consumed)
- If the first byte's high bit is 1 (value >= 128): reads 2 bytes as big-endian unsigned short, subtracts 0x8000

No ISAAC values are consumed in this path.

## Key Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `g_serverProtVector` | `<addr in DB>` | Server protocol handler table |
| Max opcode | `0xd8` (216) | Opcodes > 216 are rejected as unknown |
| ISAAC pool size | `0x100` (256) | Values generated per batch |

## ISAAC Value Consumption Summary

| Scenario | ISAAC Values Consumed |
|----------|----------------------|
| 1-byte opcode (decoded < 128) | 1 |
| 2-byte opcode (decoded >= 128) | 2 |
| No ISAAC (pre-login) | 0 |
