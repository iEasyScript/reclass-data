# JS5 TCP Response Format (Byte-Level Specification)

Reverse-engineered from the NXT client binary (`librs2client.so`) via Ghidra MCP.

**Key Functions Analyzed:**
- `jag::Js5WorkerThread::OnInterval` (librs2client.so) -- State machine including response reader
- `jag::Js5NetQueue::RequestData` (librs2client.so) -- Request key encoding
- `jag::Js5NetQueueRequest::Js5NetQueueRequest` (librs2client.so) -- Request structure
- `jag::Js5WorkerThread::GroupDownloaded` (librs2client.so) -- Group response handler
- `jag::Js5WorkerThread::IndexDownloaded` (rs2client) -- Index response handler
- `jag::Js5MasterIndex::Js5MasterIndex` (librs2client.so) -- Master index parser
- `jag::Js5ResourceProvider::WorkerOnMessage` (rs2client) -- Main-thread response dispatch
- `<in Ghidra DB>` (rs2client) -- Master index download callback

---

## Overview

The JS5 TCP response format uses a two-phase header followed by block-framed data. The client reads responses in a polling loop (up to 500 iterations per interval tick) from the connected TCP stream.

**Key constant:** Block size = `<in Ghidra DB>` = **102,400 bytes**.

---

## Response Header (10 bytes)

Each JS5 response begins with a 10-byte header, read in two sequential 5-byte phases:

### Phase 1: Response Identifier (5 bytes)

Used to match the response to the originating request.

```
Offset  Size  Type        Field          Description
------  ----  ----        -----          -----------
0       1     uint8       archive        Archive ID (index number, 0-255)
1       4     int32 (BE)  group          Group ID with optional prefetch flag
```

**Prefetch flag:** The top bit (bit 31) of the `group` field indicates whether this response is for a prefetch (low-priority) or urgent (high-priority) request:
- `group & `<in Ghidra DB>` == 0` --> urgent response (searched in urgent queue)
- `group & `<in Ghidra DB>` != 0` --> prefetch response (searched in prefetch queue)

**Lookup key construction:** The client combines these fields into a 32-bit lookup key:
```
combinedKey = (uint32)(group << 8) | archive
```

Because `group` is shifted left by 8 bits, the prefetch flag (bit 31) is shifted to bit 39, which overflows a 32-bit uint and is naturally discarded. This means the lookup key matches the stored request key (`group << 8 | archive`) regardless of the prefetch flag. The prefetch bit is used **only** to select which queue (urgent vs prefetch) to search.

**Example (master index):** archive=255 (0xFF), group=255 (0xFF):
- Response bytes: `FF 00 00 00 FF`
- `group` field = `<addr in DB>`
- `(int)group < 0` is false --> search urgent queue
- lookup key = `(0xFF << 8) | 0xFF` = `0xFFFF`

### Phase 2: Container Header (5 bytes)

Read immediately after Phase 1. Contains the data format and size.

```
Offset  Size  Type        Field             Description
------  ----  ----        -----             -----------
5       1     uint8       compression       Compression type (0-3)
6       4     int32 (BE)  compressedSize    Size of compressed data payload
```

**Validation (causes disconnect if failed):**
- `compression > 3` --> close connection
- `compressedSize < 0` (signed) --> close connection

**Compression types:**

| Value | Type | Notes |
|-------|------|-------|
| 0 | None | Raw data, no decompressedSize field |
| 1 | BZIP2 / Raw Deflate | |
| 2 | GZIP | Validates 0x1F magic byte |
| 3 | LZMA | 5-byte properties header at data start |

---

## Data Payload

After the 10-byte header, the client reads the data payload. The total payload size depends on compression:

- **compression == 0:** `payloadSize = compressedSize`
- **compression != 0:** `payloadSize = compressedSize + 4` (extra 4 bytes for decompressedSize)

The payload contains:
```
For compression != 0:
  [4 bytes: decompressedSize (BE int32)] [compressedSize bytes: compressed data]

For compression == 0:
  [compressedSize bytes: raw data]
```

Additionally, if the request carried extra metadata (e.g., CRC + whirlpool for index requests), those bytes are appended AFTER the payload. For master index requests, the extra data size is 0.

---

## Block Framing

The response data is divided into blocks of **102,400 bytes**. The block byte counter includes the header bytes.

### First Block

The 10-byte response header counts toward the first block:
- Block offset starts at 0 after the TCP read begins
- After Phase 1 (5 bytes): block offset = 5
- After Phase 2 (5 bytes): block offset = 10
- Remaining capacity in first block: `102,400 - 10 = 102,390 bytes`

### Continuation at Block Boundaries

When exactly 102,400 bytes have been consumed (header + data), the client:
1. Resets the block byte counter to 0
2. Resets the current response state (expects a new 5-byte Phase 1 header)
3. Reads a **5-byte continuation header** with the same format as Phase 1

```
Offset  Size  Type        Field          Description
------  ----  ----        -----          -----------
0       1     uint8       archive        Same archive ID as original response
1       4     int32 (BE)  group          Same group ID (with prefetch flag) as original response
```

After the continuation header:
- Block offset = 5
- Remaining capacity: `102,400 - 5 = 102,395 bytes`
- Data reading resumes into the same response buffer

The client looks up the continuation header to verify it matches an active request, then continues filling the same response packet buffer.

### Block Framing Summary

```
Block 0:  [archive(1) group(4)] [compression(1) compressedSize(4)] [data...]
           |--- Phase 1 (5) ---|  |--- Phase 2 (5) --------------|  |-- up to 102,390 --|
           |<----------------------- 102,400 bytes total --------------------------->|

Block N:  [archive(1) group(4)] [data continues...]
           |-- continuation (5)-|  |--- up to 102,395 --|
           |<----------- 102,400 bytes total ---------->|
```

---

## Response Completion

When all expected data has been read (`payloadSize + extraDataSize` bytes after the container header), the client:

1. Invokes the download callback associated with the request
2. Removes the request from the queue
3. Resets `currentResponseId = -1` to prepare for the next response header

### Callback Chain by Request Type

**Master Index (archive=255, group=255):**
1. Callback wraps data as message type 10: `opcode(1=0x0A) + dataSize(2=ushort) + containerData(N)`
2. Posts to main thread via `Task::Response`
3. Main thread `WorkerOnMessage` case 10:
   - Reads ushort data size (if 0, master index failed)
   - Passes raw container data to `Js5MasterIndex::Js5MasterIndex`
   - MasterIndex constructor does RSA decryption + Whirlpool verification
   - Creates memory cache + disk cache infrastructure

**Archive Index (archive=255, group=0-N):**
1. `IndexDownloaded` callback:
   - Reads 4-byte CRC from request extra data packet
   - Computes CRC32 of raw container data (excluding last 2 bytes if size allows)
   - **Rejects if CRC mismatch** --> `FailGetIndexResponse`
   - Checks 1-byte whirlpool flag; if 1, compares 64-byte Whirlpool hash
   - Decompresses container via `Js5Compression::Decompress`
2. Posts decompressed index to main thread as message type 0x14
3. Main thread loads index via `Js5Index::LoadIndex`

**Group Data (archive=0-N, group=0-N):**
1. `GroupDownloaded` callback:
   - **Requires container data >= 3 bytes** (checked by `GroupDownloadedCallback` wrapper)
   - Reads 4-byte format version from response metadata
   - Reads 1-byte flag + 4-byte CRC from response metadata
   - Computes CRC32 of raw container data
   - **Rejects if CRC mismatch** --> `FailGetGroupResponse(reason=1)`
   - Optional whirlpool verification (reason=2 on failure)
   - Decompresses container (reason=5 on failure)
2. Posts decompressed data to main thread as message type 0x1E
3. Main thread stores in disk cache + memory cache

---

## Master Index Format

**Full specification:** See `docs/cache/master-index-format.md` for the complete byte-level format.

The master index is served as a **raw container** (compression=0, no decompression by WorkerOnMessage):

```
Offset  Size  Type        Field              Description
------  ----  ----        -----              -----------
0       1     uint8       compression        Always 0 (no compression)
1       4     uint32 BE   compressedSize     = 1 + archiveCount*80 + rsaSignatureSize
5       1     uint8       archiveCount       Number of archive index entries (N)

Per archive (N entries, 80 bytes each, starting at offset 6):
+0      4     uint32 BE   crc                CRC32 of the archive's raw index container
+4      4     uint32 BE   version            Archive revision/version number
+8      4     uint32 BE   fileCount          Number of files/groups in archive
+12     4     uint32 BE   uncompressedSize   Total uncompressed size of archive
+16     64    bytes       whirlpool          Whirlpool hash of the archive's raw index container

After per-archive data (offset 6 + N*80):
...     var   bytes       rsaSignature       RSA-encrypted [0x01 + 64B Whirlpool hash]
```

**RSA Verification:**
1. RSA block = bytes from offset (6 + N*80) to end of compressedSize data
2. Decrypted using `modPow(data, publicExponent, modulus)`
3. Decrypted result must be exactly 65 bytes, first byte must be 0x01
4. Whirlpool hash is computed over bytes [5 .. 6 + N*80) (archiveCount byte + all entries)
5. Decrypted bytes [1..64] compared against computed 64-byte Whirlpool hash
6. If any check fails, master index is rejected

---

## Request Key Encoding

For reference, the client encodes request keys as:

```
requestKey = (group << 8) | archive
```

Both the urgent queue and prefetch queue use this same key encoding. The queues are sorted by this key for binary search lookup.

**Request wire format (6 meaningful bytes, padded to 10):**
```
Offset  Size  Type        Field
------  ----  ----        -----
0       1     uint8       flags = (priority << 4) | isUrgent
1       1     uint8       archive
2       4     int32 (BE)  group
6       4     zero-padded (Packet buffer padding to allocated size)
```

---

## Potential Disconnect Causes

The client will close the JS5 TCP connection if any of the following occur:

1. **Invalid compression type:** `compression > 3` in the container header
2. **Negative compressed size:** `compressedSize < 0` (signed int32)
3. **Unknown response ID:** The 5-byte response identifier doesn't match any pending request in either the urgent or prefetch queue
4. **30-second timeout:** No data received for 30 seconds in State 3
5. **CRC mismatch:** For index/group responses, the CRC32 doesn't match the expected value from the request metadata
6. **Whirlpool mismatch:** RSA-signed hash verification fails
7. **Decompression failure:** Container data cannot be decompressed
8. **Master index rejection:** RSA signature verification fails, or data size is 0
9. **Socket error:** Any TCP send/receive error

---

## Comparison with Current Server Implementation

Our `FileProvider.kt` implements the response format as:
```
write.writeByte(index)              // archive (1 byte)
write.writeInt(hash)                // group with prefetch flag (4 bytes)
write.writeByte(compression)        // compression type (1 byte)
write.writeInt(compressedSize)      // compressed size (4 bytes)
// ... data with 102,400-byte block framing and 5-byte continuation headers
```

This matches the client's expected format. The `hash` field correctly includes the prefetch flag: `if (prefetch) group | `<in Ghidra DB>` else group`.

### Key Verification Points

| Aspect | Expected | Our Implementation | Status |
|--------|----------|-------------------|--------|
| Header size | 10 bytes (5+5) | 10 bytes | Correct |
| Archive byte | Index/archive ID | `index.toByte` | Correct |
| Group field | Group ID, top bit = prefetch | `archive or (1 shl 31)` for prefetch | Correct |
| Compression byte | 0-3 | From container data[0] | Correct |
| CompressedSize | BE int32 | From container data[1..4] | Correct |
| Block size | 102,400 | `BLOCK_SIZE = 102400` | Correct |
| Continuation header | archive(1) + group(4) | `index(1) + hash(4)` | Correct |
| First block data capacity | 102,390 | `BLOCK_SIZE - RESPONSE_HEADER_LEN` | Correct |
| Continuation block data capacity | 102,395 | `BLOCK_SIZE - CONTINUATION_HEADER_LEN` | Correct |

---

## Appendix: State Machine Summary (OnInterval)

The JS5 response reader operates within the `Js5NetQueue` state in `OnInterval`:

```
currentResponseId == -1 (no active response)
    |
    | Read 5 bytes: archive(1) + group(4)
    | Compute combinedKey = (group << 8) | archive
    | Binary search urgent or prefetch queue
    | If not found: DISCONNECT
    |
    v
currentResponseId set, responsePacket == null
    |
    | Read 5 bytes: compression(1) + compressedSize(4)
    | Validate: compression <= 3, compressedSize >= 0
    | If invalid: DISCONNECT
    | Allocate Packet: size = compressedSize + 9 + adjustment + extraDataSize
    | Write compression + compressedSize to Packet (5 bytes)
    | blockBytesRead = 10
    |
    v
Reading data payload
    |
    | Read min(blockRemaining, dataRemaining) bytes from socket
    | Append to Packet buffer
    | Update blockBytesRead, dataRemaining
    |
    +-- If dataRemaining == 0: RESPONSE COMPLETE
    |       Invoke callback, reset state
    |
    +-- If blockBytesRead == 102,400:
    |       Reset blockBytesRead = 0
    |       Reset currentResponseId = -1
    |       (Next iteration reads new 5-byte continuation header)
    |
    +-- Otherwise: continue reading
```
