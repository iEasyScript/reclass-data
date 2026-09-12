# Server-to-Client Packet Framing (NXT 946-3)

## Overview

`jag::ConnectionManager::TcpIn` (address `<addr in DB>`) is the main server packet receive handler.
It runs in the main game loop and processes up to **100 packets per tick**. Each incoming packet
consists of an opcode, an optional variable-length size field, and a payload.

## Packet Frame Format

```
+----------+----------+-------------------+
|  Opcode  |  Size    |     Payload       |
| 1-2 bytes| 0/1/2 B  |  N bytes          |
+----------+----------+-------------------+
```

All multi-byte integers in the framing layer are **big-endian**.

---

## 1. Opcode Encoding

### Pre-Login (No Isaac Cipher)

Before the Isaac cipher is initialized (during login handshake), opcodes use a "smart 1-or-2 byte"
encoding via `Packet::gSmart1or2` (`<addr in DB>`):

| Byte 0 range | Opcode bytes | Opcode value                |
|--------------|-------------|-----------------------------|
| 0x00 - 0x7F  | 1 byte      | `byte0`                     |
| 0x80 - 0xFF  | 2 bytes     | `(byte0 << 8 | byte1) - 0x8000` |

### Post-Login (Isaac Cipher Active)

After login, each opcode byte is encrypted by subtracting the next Isaac PRNG value.

**Single-byte opcode (0x00 - 0x7F):**

```
raw_byte0 = read_byte
isaac_val0 = Isaac::TakeNextValue
opcode = (raw_byte0 - isaac_val0) & 0xFF

if opcode <= 0x7F:
    // single-byte opcode, value = opcode
```

**Two-byte opcode (0x80 - 0xD8):**

```
raw_byte0 = read_byte
isaac_val0 = Isaac::TakeNextValue
decoded0 = (raw_byte0 - isaac_val0) & 0xFF

if decoded0 > 0x7F:
    raw_byte1 = read_byte
    isaac_val1 = Isaac::TakeNextValue
    decoded1 = (raw_byte1 - isaac_val1) & 0xFF
    opcode = ((decoded0 - 0x80) * 256 + decoded1) & 0xFFFF
```

### Detection Logic (Peek Before Consume)

The client uses a two-phase approach to handle partial reads:

1. **Peek**: Read the first raw byte from the socket and subtract `randrsl[randcnt-1]` directly
   (without calling `TakeNextValue`, so the Isaac counter is NOT advanced). This determines
   whether the opcode needs a second byte.

2. **Read second byte if needed**: If the peek result > 0x7F, check if a second byte is available
   on the socket. If not, return and retry next tick (the Isaac state is unchanged since we only
   peeked).

3. **Consume**: Once all required bytes are available, call `Isaac::TakeNextValue` once (or
   twice for two-byte opcodes) to actually advance the counter and compute the final decoded
   opcode.

This ensures the Isaac PRNG state stays synchronized even when the socket buffer is partially
filled.

### Opcode Range

Valid opcodes are **0x00 through 0xD8** (decimal 0-216). The dispatch table
(`eastl::fixed_vector<ServerProt const*, 193>`) holds up to 217 entries indexed by opcode.
Of the 217 possible slots, **202 are populated** in build 946-3. If an opcode exceeds `0xD8` or
the dispatch table entry is `NULL`, the client stores the opcode in a "last invalid opcode" field
and resets the connection state.

### Isaac Cipher Details

- Isaac instance is stored at `ServerConnection + 0x2b8`
- Uses **subtraction** to decrypt: `decrypted = raw_byte - isaac_value`
- Each byte consumes one Isaac output via `Isaac::TakeNextValue` (`<addr in DB>`)
- Isaac `randcnt` starts at 256 (0x100); when it reaches 0, `Isaac::Generate` (`<addr in DB>`)
  refills the pool and resets `randcnt` to 256
- For outgoing (client-to-server) packets, the client uses **addition**:
  `encrypted = raw_byte + isaac_value` (see `WriteOpcodeWithIsaac` at `<addr in DB>`)

---

## 2. Size Encoding (Three Modes)

The size mode is determined by the `ServerProt.fixedSize` field (offset `+0x04` in the ServerProt
struct):

| fixedSize value | Mode          | Wire bytes | Payload size range |
|-----------------|---------------|------------|--------------------|
| >= 0            | Fixed         | 0          | Exactly `fixedSize` bytes |
| -1 (0xFFFFFFFF) | Variable Byte | 1          | 0 - 255 bytes      |
| -2 (`<in Ghidra DB>`) | Variable Short| 2          | 0 - 65535 bytes    |

### Fixed Size
No additional bytes on the wire. The payload length is known statically from the ServerProt
registration.

### Variable Byte (`fixedSize == -1`)
One unsigned byte follows the opcode, giving the payload length (0-255).

```
payload_size = read_byte   // unsigned, 0-255
```

### Variable Short (`fixedSize == -2`)
Two bytes follow the opcode, read as a big-endian unsigned short via `Packet::gT_ushort`
(`<addr in DB>`).

```
payload_size = read_ushort_be  // unsigned, 0-65535
```

### Size Encoding in Wire Format

```
Fixed size (e.g., fixedSize=7):
  [opcode: 1-2B] [payload: 7B]

Variable byte:
  [opcode: 1-2B] [size: 1B] [payload: size bytes]

Variable short:
  [opcode: 1-2B] [size: 2B BE] [payload: size bytes]
```

---

## 3. Dispatch Table

### Global Location

```
Address:    <addr in DB> (jag::ServerProt::g_dispatchTable)
Type:       eastl::fixed_vector<ServerProt const*, 193>
Layout:     [begin_ptr, end_ptr, capacity_ptr, inline_storage[193]]
            begin  = *(long*)<addr in DB>
            end    = *(long*)<addr in DB>
            cap    = *(long*)<addr in DB>
```

The dispatch table is an array of `ServerProt*` pointers indexed by opcode number:
```c
ServerProt *prot = dispatch_table[opcode];  // may be NULL
```

### Registration

All ServerProt entries are registered in `jag::ServerProt::RegisterAll` (`<addr in DB>`).
Each entry is a global `ServerProt` object constructed with:
```c
ServerProt::ServerProt(this, opcode, fixedSize);  // at <addr in DB>
```
Then pushed into the dispatch vector.

Handler functions are bound separately in `jag::ServerProt::BindHandlers` (`<addr in DB>`), which
assigns `std::function` invoke wrappers and handler function pointers to the ServerProt objects.

---

## 4. ServerProt Struct (48 bytes)

```c
// Category: /jag in Ghidra Data Type Manager
struct ServerProt {          // 0x30 (48) bytes total
    /* 0x00 */ int    opcode;         // Opcode number (0-216)
    /* 0x04 */ int    fixedSize;      // Fixed payload size. -1=var_byte, -2=var_short
    /* 0x08 */ char  *name;           // Protocol name string (default empty)
    /* 0x10 */ long   callableData;   // std::function embedded callable data
    /* 0x18 */ long   callableData2;  // std::function additional storage
    /* 0x20 */ void  *handlerTarget;  // Handler target ptr (NULL = no handler)
    /* 0x28 */ void  *invokePtr;      // std::function invoke function pointer
};
```

### Handler Presence Check

Before dispatching, TcpIn checks `ServerProt.handlerTarget` (offset `+0x20`):
- If **NULL**: No handler registered. The packet is consumed but treated as unrecognized
  (opcode stored as "last opcode", state reset).
- If **non-NULL**: The handler is invoked.

---

## 5. Handler Dispatch

### Calling Convention

Handlers are invoked through a `std::function`-like mechanism:

```c
result = ServerProt.invokePtr(
    &ServerProt.callableData,  // RDI: this pointer for std::function (ServerProt + 0x10)
    &packet_buffer,            // RSI: Packet* (ServerConnection + 0x2C0)
    &packet_size,              // RDX: int* (copy of fixedSize or resolved variable size)
    &isaac_ptr                 // RCX: Isaac** (saved from ServerConnection + 0x2B8)
);
```

The invoke wrapper unpacks the callable and calls the actual handler. Known handler signatures
(e.g., `UPDATE_INV_FULL`) receive:
```c
void *handler(long *client, long packet);
// client = pointer derived from ConnectionManager
// packet = Packet structure for reading payload
```

### Return Values

The handler returns a pointer to an `int` result code:

| Value | Meaning | TcpIn Behavior |
|-------|---------|----------------|
| 0     | Success | Reset opcode state, continue processing next packet |
| 1     | Yield   | Keep TcpConnectionMessage alive, increment pending counter, return (retry next tick) |
| other | Error   | Reset opcode state, continue processing |

When a handler yields (returns 1), TcpIn sets `connectionMgr + 0x48 = 1` and increments the
yield counter at `ServerConnection + 0x38`. If the yield counter exceeds 499, a flag at
`ServerConnection + 0x3c` is set (likely a "too many yields" warning).

---

## 6. Connection State Machine

### ServerConnection Fields Used by TcpIn

| Offset  | Type     | Name              | Description |
|---------|----------|-------------------|-------------|
| +0x08   | void*    | clientStream      | Socket wrapper (ClientStream) |
| +0x20   | int      | readTimeout       | Timeout counter, reset to 0 on each read |
| +0x28   | byte     | handlerActive     | Set to 0 when handler completes |
| +0x2C   | int      | currentOpcode     | Current opcode being processed (-1 = none) |
| +0x30   | int      | payloadSize       | Resolved payload size for current packet |
| +0x34   | byte     | opcodeReadDone    | 1 = opcode has been fully read |
| +0x35   | byte     | payloadReadDone   | 1 = payload has been fully read |
| +0x38   | int      | yieldCounter      | Number of consecutive handler yields |
| +0x3C   | byte     | yieldOverflow     | Set to 1 if yieldCounter > 499 |
| +0x2B8  | Isaac*   | isaacDecrypt      | Isaac cipher instance for decryption |
| +0x2C0  | Packet   | packetBuffer      | Packet structure for reading payload |
| +0x2D0  | byte*    | readBuffer        | Raw byte buffer for stream reads |
| +0x2D8  | long     | bufferOffset      | Current position in readBuffer |
| +0x2E0  | int      | lastOpcode        | Last successfully processed opcode |
| +0x2E8  | int      | bytesRead         | Running total of bytes read from stream |

### State Reset (After Handler Completes)

After each successful or error handler return:
```
currentOpcode  = -1     (no pending opcode)
payloadReadDone = 0
handlerActive  = 0
yieldCounter   = 0
yieldOverflow  = 0
```

---

## 7. Complete Wire Format Example

### Fixed-size packet (opcode 0x03, fixedSize = 7)

```
Stream bytes (with Isaac):
  [E1]              Encrypted opcode byte: 0xE1
                    Isaac value: 0xDE
                    Decrypted: (0xE1 - 0xDE) & 0xFF = 0x03
  [AA BB CC DD      7 bytes of payload (not encrypted)
   EE FF 11]
```

### Variable-byte packet (opcode 0x01, fixedSize = -1)

```
  [4F]              Encrypted opcode: 0x4F - isaac = 0x01
  [0C]              Size byte: 12 bytes of payload follow
  [payload: 12 bytes]
```

### Two-byte opcode (opcode 0xA0 = 160, fixedSize = 6)

The two-byte opcode formula is: `opcode = (decoded0 - 0x80) * 256 + decoded1`.

Since the maximum opcode is 216 (< 256), `decoded0` is always `0x80` for valid two-byte
opcodes, making the formula simplify to `opcode = decoded1`. The first byte serves purely
as a "two-byte marker."

Summary:
- **Opcodes 0-127**: Single byte. `decoded0` directly equals the opcode.
- **Opcodes 128-216**: Two bytes. `decoded0 = 0x80` (marker), `decoded1 = opcode`.

```
  [XX]              First byte: (XX - isaac0) & 0xFF = 0x80
                    Since 0x80 > 0x7F: read second byte
  [YY]              Second byte: (YY - isaac1) & 0xFF = 0xA0
                    Opcode = (0x80 - 0x80) * 256 + 0xA0 = 160 = 0xA0
  [payload: 6 bytes]
```

Server-side encryption for this opcode:
```
  wire_byte0 = (0x80 + isaac_val0) & 0xFF
  wire_byte1 = (0xA0 + isaac_val1) & 0xFF
```

---

## 8. TcpConnectionMessage Pool

TcpIn uses a pool of `TcpConnectionMessage` objects to wrap packets for dispatch. The pool is
a thread-safe fixed-size allocator at globals `<addr in DB>` - `<addr in DB>`, protected by a mutex
at `<addr in DB>`.

Each `TcpConnectionMessage` is 0x58 bytes:
```
+0x00: vtable pointer     (PTR_FUN_0148bc70)
+0x08: ref_count           (initialized to `<in Ghidra DB>`1 = strong=1, weak=1)
+0x10: self pointer
+0x18: packet pointer      (points to +0x20)
+0x20: Packet data         (initialized by InitPacket)
```

The `InitPacket` function (`<addr in DB>`) copies the opcode from the ServerProt, stores the
payload size, allocates a buffer, and stores the ServerProt pointer at `Packet + 0x30`.

---

## 9. Complete Opcode Table (Build 946-3)

202 registered opcodes out of 217 possible slots (0x00-0xD8).

Size legend: positive = fixed bytes, `-1` = variable byte, `-2` = variable short.

| Opcode | Size | Opcode | Size | Opcode | Size | Opcode | Size |
|--------|------|--------|------|--------|------|--------|------|
| 0x00   |   28 | 0x01   |   -1 | 0x02   |   -2 | 0x03   |    7 |
| 0x04   |   10 | 0x05   |   10 | 0x06   |   10 | 0x07   |   29 |
| 0x08   |    6 | 0x09   |   -1 | 0x0A   |   -1 | 0x0B   |   -2 |
| 0x0C   |    6 | 0x0D   |    1 | 0x0E   |    3 | 0x0F   |   -2 |
| 0x10   |   -2 | 0x11   |   -2 | 0x12   |   -2 | 0x13   |    3 |
| 0x14   |   -2 | 0x15   |   32 | 0x16   |    2 | 0x17   |    1 |
| 0x18   |   20 | --     |   -- | 0x1A   |    8 | 0x1B   |    1 |
| 0x1C   |   -2 | 0x1D   |   -1 | 0x1E   |   -1 | 0x1F   |   -1 |
| --     |   -- | --     |   -- | 0x22   |    5 | --     |   -- |
| 0x24   |   -2 | 0x25   |   -1 | 0x26   |   23 | 0x27   |   -2 |
| 0x28   |   -1 | 0x29   |   10 | 0x2A   |   -2 | 0x2B   |   -2 |
| 0x2C   |    6 | 0x2D   |    5 | 0x2E   |   -1 | 0x2F   |   14 |
| 0x30   |    5 | 0x31   |   10 | 0x32   |    4 | 0x33   |    6 |
| 0x34   |    1 | 0x35   |   35 | 0x36   |   25 | 0x37   |    4 |
| 0x38   |   -1 | 0x39   |   -2 | 0x3A   |    6 | 0x3B   |   12 |
| 0x3C   |   -1 | 0x3D   |    8 | 0x3E   |   10 | 0x3F   |   -2 |
| 0x40   |    2 | 0x41   |   -1 | 0x42   |   -2 | 0x43   |   25 |
| 0x44   |   -1 | --     |   -- | 0x46   |    5 | 0x47   |    8 |
| 0x48   |    3 | 0x49   |    2 | 0x4A   |    8 | 0x4B   |   10 |
| 0x4C   |    8 | 0x4D   |    4 | 0x4E   |    7 | 0x4F   |    6 |
| 0x50   |    1 | 0x51   |   -2 | 0x52   |   -1 | 0x53   |   -2 |
| 0x54   |   -2 | 0x55   |    4 | 0x56   |   -1 | 0x57   |    5 |
| 0x58   |    3 | 0x59   |    8 | 0x5A   |    3 | 0x5B   |   12 |
| 0x5C   |   -2 | 0x5D   |   10 | 0x5E   |   19 | 0x5F   |   -2 |
| 0x60   |    4 | 0x61   |    2 | 0x62   |    3 | --     |   -- |
| 0x64   |   10 | 0x65   |    3 | 0x66   |    1 | 0x67   |   10 |
| --     |   -- | 0x69   |    8 | 0x6A   |    4 | 0x6B   |   -1 |
| 0x6C   |    6 | 0x6D   |   -2 | 0x6E   |   -2 | 0x6F   |   -1 |
| --     |   -- | 0x71   |   10 | 0x72   |    6 | 0x73   |    6 |
| 0x74   |   25 | 0x75   |   11 | --     |   -- | 0x77   |    8 |
| 0x78   |    3 | 0x79   |   -2 | 0x7A   |   11 | 0x7B   |   -1 |
| 0x7C   |    6 | 0x7D   |    8 | 0x7E   |   19 | 0x7F   |    7 |
| 0x80   |    3 | 0x81   |    6 | 0x82   |   -1 | --     |   -- |
| 0x84   |    5 | 0x85   |    1 | --     |   -- | 0x87   |    1 |
| 0x88   |    2 | 0x89   |    9 | 0x8A   |   10 | 0x8B   |    4 |
| 0x8C   |    5 | 0x8D   |   -2 | 0x8E   |    1 | 0x8F   |    8 |
| 0x90   |    4 | 0x91   |    8 | --     |   -- | 0x93   |   29 |
| 0x94   |   -2 | 0x95   |   -1 | 0x96   |   -2 | 0x97   |    3 |
| 0x98   |   -1 | 0x99   |    2 | 0x9A   |   -2 | 0x9B   |   -1 |
| 0x9C   |    6 | 0x9D   |    3 | 0x9E   |   12 | 0x9F   |   28 |
| 0xA0   |    6 | 0xA1   |    1 | 0xA2   |   -1 | 0xA3   |   -2 |
| 0xA4   |    1 | 0xA5   |    9 | --     |   -- | 0xA7   |    2 |
| 0xA8   |   -2 | 0xA9   |    1 | 0xAA   |   -2 | 0xAB   |   -1 |
| 0xAC   |    5 | 0xAD   |   -2 | 0xAE   |   -2 | 0xAF   |    3 |
| 0xB0   |   14 | 0xB1   |   -2 | 0xB2   |   -2 | 0xB3   |    2 |
| 0xB4   |    5 | 0xB5   |    1 | 0xB6   |    5 | 0xB7   |   10 |
| 0xB8   |    4 | 0xB9   |   33 | 0xBA   |   -2 | 0xBB   |    4 |
| 0xBC   |    1 | 0xBD   |   -2 | 0xBE   |    3 | 0xBF   |    2 |
| 0xC0   |   -2 | 0xC1   |   15 | 0xC2   |   14 | 0xC3   |    3 |
| 0xC4   |   -2 | 0xC5   |    3 | 0xC6   |   -1 | 0xC7   |   -1 |
| 0xC8   |    4 | 0xC9   |   -1 | 0xCA   |    9 | 0xCB   |    8 |
| 0xCC   |    1 | 0xCD   |    1 | --     |   -- | 0xCF   |    2 |
| 0xD0   |    3 | 0xD1   |    4 | 0xD2   |    4 | 0xD3   |    5 |
| --     |   -- | 0xD5   |    6 | 0xD6   |   21 | 0xD7   |    3 |
| 0xD8   |    2 |

**Unregistered opcodes** (15 gaps): 0x19, 0x20, 0x21, 0x23, 0x45, 0x63, 0x68, 0x70, 0x76,
0x83, 0x86, 0x92, 0xA6, 0xCE, 0xD4.

---

## 10. Key Addresses

| Symbol | Address | Description |
|--------|---------|-------------|
| `jag::ConnectionManager::TcpIn` | `<addr in DB>` | Main packet receive loop |
| `jag::ServerProt::RegisterAll` | `<addr in DB>` | Registers all 202 ServerProt entries |
| `jag::ServerProt::ServerProt` | `<addr in DB>` | ServerProt constructor |
| `jag::ServerProt::BindHandlers` | `<addr in DB>` | Binds handler functions to ServerProt objects |
| `jag::ServerProt::g_dispatchTable` | `<addr in DB>` | Dispatch vector (begin ptr) |
| `jag::Isaac::TakeNextValue` | `<addr in DB>` | Get next Isaac PRNG value |
| `jag::Isaac::Generate` | `<addr in DB>` | Refill Isaac PRNG pool |
| `jag::ClientStream::GetAvailable` | `<addr in DB>` | Check bytes available on socket |
| `jag::ClientStream::Read` | `<addr in DB>` | Read bytes from socket into buffer |
| `jag::Packet::gSmart1or2` | `<addr in DB>` | Read 1-or-2 byte smart value |
| `jag::Packet::gT_ushort` | `<addr in DB>` | Read big-endian unsigned short |
| `jag::game::TcpConnectionMessage::InitPacket` | `<addr in DB>` | Initialize packet in message |
| `jag::ConnectionManager::g_messagePool` | `<addr in DB>` | TcpConnectionMessage object pool |

---

## 11. Implementation Notes for Server Emulation

### Sending a Packet

To send a valid server packet to the NXT client:

1. **Choose the opcode** and look up its `fixedSize` from the table above.
2. **Encrypt the opcode** with the server-side Isaac instance:
   - Opcodes 0-127: One byte. `wire_byte = (opcode + isaac_val) & 0xFF`
   - Opcodes 128-216: Two bytes.
     ```
     wire_byte0 = (0x80 + isaac_val0) & 0xFF    // marker byte
     wire_byte1 = (opcode + isaac_val1) & 0xFF   // opcode value
     ```
   Note: The server uses **addition** (matching the client's subtraction for decryption).
   The first byte always decrypts to `0x80` (the two-byte marker); the second byte
   decrypts to the actual opcode value.
3. **Write the size** if variable:
   - `fixedSize == -1`: Write 1 byte (payload length, 0-255)
   - `fixedSize == -2`: Write 2 bytes big-endian (payload length, 0-65535)
   - `fixedSize >= 0`: No size bytes (client knows the fixed length)
4. **Write the payload** (unencrypted, `fixedSize` or `size` bytes).

### Isaac Synchronization

Both client and server must initialize their Isaac cipher with the same seed during login.
The client uses one Isaac instance for decrypting incoming opcodes and a separate instance
(stored in `ConnectionManager.WriteOpcodeWithIsaac`) for encrypting outgoing opcodes.
Each opcode byte consumes one Isaac value. **Payload bytes are NOT encrypted.**

### Flow Control

The client processes up to 100 packets per tick. If a handler returns "yield" (1), the client
stops processing and retries next tick. After 500 consecutive yields, a warning flag is set.
