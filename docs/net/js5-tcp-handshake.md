# JS5 TCP Handshake Protocol (Byte-Level Specification)

Reverse-engineered from the NXT client binary (`rs2client`) via Ghidra MCP.

**Key Functions Analyzed:**
- `<in Ghidra DB>` -- Builds the JS5 init packet
- `jag::ConnectionManager::MainLogic` -- JS5 TCP connection state machine
- `jag::Js5WorkerThread::OnMessage` -- Worker thread message handler
- `jag::Js5WorkerThread::CreateQueues` -- Connection/queue setup
- `<in Ghidra DB>` -- Sends individual file requests over TCP

---

## Connection State Machine

The JS5 TCP connection runs on a dedicated `Js5WorkerThread` and uses a 4-state machine stored at `this+0x2a4`:

```
State 0 (CONNECTING)
    |  Send handshake bytes, transition immediately
    v
State 1 (AWAITING_RESPONSE)
    |  Read 1 byte response
    |  If 0 (SYNC) -> State 2
    |  Otherwise -> disconnect, reconnect with backoff
    v
State 2 (READING_PREFETCH_KEYS)
    |  Read N prefetch key ints (N * 4 bytes)
    |  Send encryption ACK (opcode 6)
    |  Send connection ready (opcode 3)
    |  Transition to State 3
    v
State 3 (CONNECTED)
    |  Process file request queues
    |  Read file responses
```

A 30-second timeout applies in State 3. If no data is received within 30 seconds, the connection is closed.

---

## Step 1: Client Sends Handshake (State 0)

Built by `<in Ghidra DB>`. The complete byte layout:

```
Offset  Size   Type           Value/Description
------  ----   ----           -----------------
0       1      uint8          JS5_INIT opcode = 15 (0x0F)
1       1      uint8          Payload size = token_length + 10
2       4      int32 (BE)     Major version (946 = <addr in DB>)
6       4      int32 (BE)     Minor version (1 = <addr in DB>)
10      N      string         JS5 token (NOT null-terminated here, raw bytes)
10+N    1      uint8          Null terminator (0x00)
11+N    1      uint8          Platform/language byte (read from client config)
```

**Total packet size** = 12 + token_length bytes.

**Size byte calculation**: The size byte at offset 1 covers everything after itself: `4 (major) + 4 (minor) + token_length + 1 (null) + 1 (platform) = token_length + 10`.

### Critical Finding: Trailing Byte

The existing `JS5Connection.kt` and `Diagnostic.kt` send `payloadSize = 4 + 4 + tokenBytes.size + 1`, which equals `token_length + 9`. This is **off by 1** because they omit the trailing platform/language byte.

The correct size should be `token_length + 10`, and a trailing byte must be appended after the null terminator.

**Source evidence** from `<in Ghidra DB>`:
```c
// Write opcode (15)
*(char *)(buf + pos) = (char)<in Ghidra DB>;  // <in Ghidra DB> = 0x0F
pos++;

// Write size byte
*(char *)(buf + pos) = (char)iVar3 + '\n';  // '\n' = 10
pos++;

// Write major version as big-endian int
Packet::pT_int(buf, 0x3b2);  // 946

// Write minor version as big-endian int
Packet::pT_int(buf, 1);

// Write token string + null terminator
memcpy(buf + pos, token_str, token_len);
*(buf + pos + token_len) = 0;  // null terminator
pos += token_len + 1;

// Write trailing byte (platform/config value)
*(char *)(buf + pos) = (char)**(uint32_t **)(config_ptr);
pos++;
```

---

## Step 2: Server Response (State 1)

The client reads exactly **1 byte**:

| Value | Meaning | Client Action |
|-------|---------|---------------|
| 0 | JS5_SYNC (success) | Transition to State 2 |
| 6 | GAME_UPDATE (version mismatch) | Disconnect, show `js5connect_outofdate` |
| 7 | WORLD_FULL | Disconnect, show `js5connect_full` |
| 26 (0x1A) | Also WORLD_FULL | Same as 7 |
| 48 (0x30) | SESSION_EXPIRED | Disconnect, show `sessionexpired` |
| Other | Generic error | Disconnect, show `js5connect` |

**From `LoginProtocolHandler` at `<addr in DB>`:**
- Response code is stored at `this_01->field_0x2c`
- Code 6 = `js5connect_outofdate` (line 666)
- Codes 7, 0x1A = `js5connect_full` (line 735)
- Code 0x30 = `sessionexpired` (line 706)
- All other non-zero = generic `js5connect` error (line 756)

---

## Step 3: Read Prefetch Keys (State 2)

After receiving SYNC (0), the client reads **N * 4 bytes** where N is the prefetch key count.

The prefetch key count `N` is stored at `Js5WorkerThread+0x250` and is set during worker thread initialization via a `gT_ushort` read from the internal init message (see `OnMessage` case 2, second `gT_ushort`). This value is passed from the main thread when the JS5 system is initialized.

Each key is read as a **big-endian 4-byte int** via `Packet::gT_uint`.

### N = 0 Case (Confirmed)

**The NXT client fully supports N = 0.** When N is 0, the code path in `MainLogic` State 2 has an explicit guard:

```c
iVar10 = *(int *)&this->field_0x250;  // N
iVar10 = iVar10 * 4;                  // bytes needed
if ((ulong)(long)iVar10 <= available) {
    if ((long)iVar10 != 0) {           // <-- SKIP if N == 0
        ClientStream::Read(..., iVar10);
        // parse N uint32 keys
    }
    // transition to State 3 regardless
}
```

When N = 0:
- The condition `0 <= available` is always true
- The inner `if ((long)iVar10 != 0)` is false, so the read is skipped entirely
- The client immediately sends ACK + CONNECTION_READY and transitions to State 3

**Empirical confirmation:** Our working cache downloader tool connects to Jagex's live JS5 server (`content.runescape.com:43594`) without reading any prefetch keys after SYNC, and downloads the complete cache successfully. This proves Jagex's production server sends **0 prefetch keys** over TCP.

**Server implementation**: The server sends ONLY the 1-byte SYNC (0x00). No prefetch keys are sent.

```
Offset  Size      Type         Description
------  ----      ----         -----------
0       N * 4     int32 (BE) Prefetch keys (N = 0 for current NXT TCP connections)
```

---

## Step 4: Client Sends Acknowledgments (State 2 -> State 3)

After reading all prefetch keys, the client sends **two** TCP writes:

### Write 1: Encryption/Version ACK (10 bytes)

The buffer was pre-allocated to 10 bytes by `CreateQueues` via `Packet::ResizeBuffer(plVar6 + 0xb, 10)`.
The `ClientStream::Write` call uses the buffer capacity (10), not the write position.

```
Offset  Size  Type       Value
------  ----  ----       -----
0       1     uint8      6 (opcode: ENCRYPTION_ACK / CONNECTION_INFO)
1       1     uint8      0
2       1     uint8      0
3       1     uint8      5
4       4     int32 (BE) Major version (946 = <addr in DB>)
8       2     zeros      Buffer padding (from ResizeBuffer zeroing)
```

**Source evidence** from `MainLogic` State 2:
```c
Packet::pT_uchar(plVar17, 6);       // opcode 6
// 3 manually written bytes:
*(buf + pos++) = 0;
*(buf + pos++) = 0;
*(buf + pos++) = 5;
Packet::pT_int(plVar17, iVar10);    // iVar10 = field_0x308 = 0x3B2 (946)
ClientStream::Write(stream, buf, bufCapacity);  // writes full 10 bytes
```

The bytes `[0, 0, 5]` may encode: `padding(1) + padding(1) + encryption_type(1)` where 5 indicates no encryption, or they form a 3-byte medium value of `<in Ghidra DB>`.

### Write 2: Connection Ready (10 bytes)

The same 10-byte buffer is reused. Only byte 0 (opcode) is overwritten; bytes 1-9 are residual from the ACK.

```
Offset  Size  Type       Value
------  ----  ----       -----
0       1     uint8      3 (opcode: CONNECTION_READY)
1-9     9     residual   00 00 05 00 00 03 B2 00 00 (from ACK write)
```

**Source evidence:**
```c
plVar4[0xe] = 0;                     // reset write position
Packet::pT_uchar(plVar17, 3);       // write ONLY byte 0 = 3
ClientStream::Write(stream, buf, bufCapacity);  // writes full 10 bytes
ClientStream::Flush(stream);
```

After this, `ClientStream::Flush` is called and the connection transitions to **State 3 (CONNECTED)**.

---

## Step 5: File Requests (State 3)

Once connected, the client sends file requests using `<in Ghidra DB>`. **All NXT JS5 client messages are 10 bytes** — both file requests and control opcodes share the same frame size.

### File Request (10 bytes)

Only 6 bytes are meaningfully written by `<in Ghidra DB>`; the remaining 4 are buffer padding (zeros).

```
Offset  Size  Type        Description
------  ----  ----        -----------
0       1     uint8       Flags: (priority_enum << 4) | is_urgent
1       1     uint8       Archive ID (index)
2       4     int32 (BE)  Group ID
6       4     zeros       Buffer padding (from 10-byte pre-allocated buffer)
```

**Flags byte breakdown:**
- Bit 0: `is_urgent` flag (1 = urgent/high priority, 0 = prefetch)
- Bits 4-7: `priority_enum` value (request priority level)
- Valid flags: 0x00 (prefetch), 0x01 (urgent), 0x10, 0x11, 0x20, 0x21, etc.
- File request if `(flags & 0x0E) == 0`

### Control Opcode (10 bytes)

```
Offset  Size  Type        Description
------  ----  ----        -----------
0       1     uint8       Opcode (2=STATUS_LOGGED_IN, 3=STATUS_LOGGED_OUT, 4=ENCRYPTION_KEY_UPDATE, 6=ACKNOWLEDGE)
1       3     medium (BE) Padding/encryption type (typically `<in Ghidra DB>`)
4       2     int16 (BE)  Padding (0)
6       2     int16 (BE)  Major version
8       2     int16 (BE)  Padding (0)
```

**Request for master index**: flags=0x21, archive=255, group=255.

**Confirmed from**: Working cache downloader (`tools/.../JS5Protocol.kt`) tested against Jagex production servers.

---

## File Response Format (State 3)

Each response from the server follows the NXT JS5 response format:

```
Offset  Size  Type       Description
------  ----  ----       -----------
0       1     uint8      Archive ID (index)
1       4     int32 (BE) Group ID (top bit: 0 = urgent, 1 = prefetch)
5       1     uint8      Compression type (0=none, 1=bzip2, 2=gzip, 3=lzma)
6       4     int32 (BE) Compressed data length
10      ...   bytes      Data payload (block-framed, see below)
```

The response data is **block-framed** with a block size of **102,400 bytes**. The first block starts after the 10-byte response header (so the first block has 102,390 bytes of payload capacity). At each block boundary, a **5-byte continuation header** is inserted:

```
Offset  Size  Type       Description
------  ----  ----       -----------
0       1     uint8      Archive ID (same as response header)
1       4     int32 (BE) Group ID with prefetch bit (same as response header)
```

**NOT the legacy RS2/OSRS format** — NXT does NOT use 512-byte chunks or 0xFF separator bytes.

---

## Complete Handshake Byte Sequence (Example)

Using token `j4mhSS8dVoheay-bfgy69x*nmrCTmAEk` (32 chars), platform byte 0:

### Client -> Server (44 bytes):
```
0F                          -- JS5_INIT opcode (15)
2A                          -- Size byte (32 + 10 = 42)
00 00 03 B2                 -- Major version (946)
00 00 00 01                 -- Minor version (1)
6A 34 6D 68 53 53 38 64     -- "j4mhSS8d"
56 6F 68 65 61 79 2D 62     -- "Voheay-b"
66 67 79 36 39 78 2A 6E     -- "fgy69x*n"
6D 72 43 54 6D 41 45 6B     -- "mrCTmAEk"
00                          -- Null terminator
00                          -- Platform byte (0)
```

### Server -> Client (1 byte):
```
00                          -- JS5_SYNC (success)
                            -- No prefetch keys (N = 0)
```

### Client -> Server (10 + 10 = 20 bytes):

The client writes these using a 10-byte pre-allocated buffer. The ACK fills all 10 bytes, then the
READY overwrites only byte 0 (opcode), leaving bytes 1-9 from the ACK as residual data.

```
06                          -- Encryption ACK opcode
00 00 05                    -- Bytes: [0, 0, 5] (manually written)
00 00 03 B2                 -- int32 BE: major version (946) from field_0x308
00 00                       -- Residual zeros from buffer init

03                          -- Connection Ready opcode (overwrites byte 0)
00 00 05                    -- Residual from ACK (NOT re-written)
00 00 03 B2                 -- Residual from ACK
00 00                       -- Residual from ACK
```

**Note:** The READY message reuses the same 10-byte buffer, resetting only the write position and
writing `pT_uchar(3)` (1 byte). The remaining 9 bytes are leftover from the ACK write. Both
messages are written and flushed together.

### Client -> Server (file requests, 10 bytes each):
```
21                          -- Flags: priority=2, urgent=1
FF                          -- Archive 255 (master index)
00 00 00 FF                 -- Group 255 (master index)
03 B2                       -- Major version (946)
00 00                       -- Padding
```

---

## Server Implementation Notes

The JS5 server should:

1. Read the handshake: opcode(1) + size(1) + major(4) + minor(4) + token(N) + null(1) + platform(1)
2. Validate version and token
3. Send: SYNC byte (0x00) ONLY — no prefetch keys (N = 0 for NXT TCP)
4. Read: opcode 6 ACK (10 bytes: `06 00 00 05 00 00 03 B2 00 00`)
5. Read: opcode 3 ready (10 bytes: `03 00 00 05 00 00 03 B2 00 00`)
6. Enter file request/response loop (all client messages are 10 bytes)

**Prefetch keys are NOT sent over TCP.** The prefetch key count N is set internally by the client
from its JS5 initialization message. Jagex's live server (`content.runescape.com:43594`) sends only
the 1-byte SYNC response with no additional data before the client sends ACK + READY. This is
confirmed by both binary analysis (the code handles N=0 gracefully) and empirical testing (our
cache downloader tool works against Jagex without reading any prefetch keys).
