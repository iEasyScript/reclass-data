# JS5 Cache Protocol

The JS5 (Jagex Store 5) protocol handles downloading and caching game assets (models, textures, animations, scripts, configs, etc.) from the game servers. It operates on a worker thread that manages HTTP and TCP-based downloads, disk caching via SQLite, and decompression of archived data.

## Architecture Overview

```
Main Thread                Worker Thread              Network/Disk
    |                          |                          |
    |  -- Request (msg) -->    |                          |
    |                          |  -- HTTP/TCP request --> |
    |                          |  <-- Raw response -----  |
    |                          |  [CRC32 verify]          |
    |                          |  [RSA verify (optional)] |
    |                          |  [Decompress]            |
    |  <-- Response (msg) --   |                          |
    |  [Parse index/group]     |                          |
    |                          |  -- SQLite write ------> |
```

### Key Classes

| Class | Role |
|-------|------|
| `Js5WorkerThread` | Worker thread handling network I/O, decompression, CRC/RSA verification |
| `Js5ResourceProvider` | Main-thread interface for requesting and retrieving cached files |
| `Js5Compression` | Container format decompression (none/bzip2/gzip/LZMA) |
| `Js5MasterIndex` | Parses the RSA-signed master index listing all archives |
| `Js5NetQueue` | Network request queue with download callbacks |
| `Js5DiskCache` | SQLite-based persistent cache (`%sjs5-%d.jcache` files) |

## Connection Handshake

The JS5 connection is established during the login protocol. The client sends a `js5connect` request that includes:
- Client version/build information
- Connection type identifier

The server responds with one of:
- **Success**: Connection established, followed by initialization data (case 2 in OnResponse)
- **`js5connect_outofdate`**: Client version mismatch
- **`js5connect_full`**: Server at capacity

### Initialization Response (OnResponse Case 2)

On successful connection, the server sends:
1. **3 URL strings** (content delivery URLs) -- stored at worker thread offsets 0x1F0, 0x1D8, 0x208
2. **1 byte**: Encryption flag
3. **Key data**: Encryption keys (if encryption enabled)
4. **Port information**: Connection port

## Worker Thread Message Dispatch

`Js5WorkerThread::OnResponse` (<addr in DB>) reads the first byte of each response packet and dispatches based on message type:

| Type | Hex | Handler | Description |
|------|-----|---------|-------------|
| 2 | 0x02 | Inline | Initialize -- reads URLs, encryption settings, port |
| 7 | 0x07 | SetURLs | Change content delivery URLs |
| 10 | 0x0A | Inline | Master index request |
| 20 | 0x14 | IndexDownloaded | Archive index response (RSA-signed) |
| 30 | 0x1E | GroupDownloaded | Group data response |
| 40 | 0x28 | Inline | Master index over HTTP |

## Container Format

All JS5 data (indices, groups, and the master index) uses a common container format:

```
+--------+-----------------+--------------------+-------------------+
| 1 byte | 4 bytes (BE)    | 4 bytes (BE)       | N bytes           |
| compTy | compressedLen   | decompressedLen*   | compressed data   |
+--------+-----------------+--------------------+-------------------+
* decompressedLen only present when compressionType != 0
```

### Compression Types

| Value | Type | Implementation |
|-------|------|----------------|
| 0 | None | Raw memcpy |
| 1 | BZIP2 / Raw Deflate | `Js5Compression::Decompress` path at <addr in DB> |
| 2 | GZIP | Validates 0x1f magic byte, uses `inflateInit2_` with window bits 0x2f |
| 3 | LZMA | Calls <in Ghidra DB> |

### Decompression Function

**`jag::Js5Compression::Decompress`**

```c
// Prototype (reconstructed)
void Js5Compression::Decompress(
    Packet *output,    // RDI - receives decompressed data
    Packet *input,     // RSI - container data to decompress
    int *status        // RDX - output: 0=success, 1=error
);
```

**Flow:**
1. Read 1 byte from input position 0: compression type
2. Read 4 bytes (big-endian): compressed length
3. If type == 0: memcpy compressed data directly to output
4. If type != 0: Read 4 more bytes: decompressed length
5. Switch on compression type:
   - Type 1: Initialize deflate stream, decompress
   - Type 2: Verify gzip magic (0x1f at data+9), inflate with gzip window bits
   - Type 3: Call LZMA decompressor
6. Set status to 0 on success, 1 on error

## Master Index

The master index is a signed catalog of all archive indices. It is requested at startup and verified using RSA + Whirlpool hashing.

### Master Index Format

**`jag::Js5MasterIndex::Js5MasterIndex`**

After RSA decryption and Whirlpool verification:

```
+-------------------+------------------+
| 4 bytes (gT_uint) | Format version   |
+-------------------+------------------+
| 1 byte            | Archive count    |
+-------------------+------------------+

Per archive (archive_count entries):
+-------------------+------------------+
| 2x <in Ghidra DB>   | Version (2 reads)|
+-------------------+------------------+
| 4 bytes (gT_uint) | CRC32            |
+-------------------+------------------+
| 4 bytes (gT_uint) | Secondary hash   |
+-------------------+------------------+
| 64 bytes           | Whirlpool digest |
+-------------------+------------------+
```

### RSA Verification

1. Read 64 bytes of RSA-encrypted data from the container
2. Decrypt using `BigInteger::ModPow` with the RSA public key
3. Compute Whirlpool hash of the entire container data (via <in Ghidra DB> / <in Ghidra DB>)
4. Compare the 64-byte decrypted RSA signature against the computed Whirlpool hash
5. If mismatch, reject the master index

## Archive Index Response (Type 0x14)

**`jag::Js5WorkerThread::IndexDownloaded`**

Processing flow:
1. Read 4-byte CRC from packet (via <in Ghidra DB>)
2. Compute CRC32 over raw data using table at `<in Ghidra DB>`
3. If CRC mismatch: call `FailGetIndexResponse(this, archiveId, 1)`
4. Accumulate byte count at `this+0x254`
5. Read 1-byte RSA flag from data
6. If RSA flag == 1:
   a. Compute Whirlpool hash of data
   b. Read 64-byte RSA signature from data
   c. Compare hashes; if mismatch: `FailGetIndexResponse(this, archiveId, 2)`
7. Call `Js5Compression::Decompress` on the container data
8. If decompress fails: `FailGetIndexResponse(this, archiveId, 3)`
9. Package decompressed data into message with type 0x14, post to main thread

### Index Data Format

The decompressed index data contains metadata for all groups within an archive:
- Format byte (protocol version)
- Version number (if format >= certain threshold)
- Flags byte (bit 0: has names)
- Group count and group IDs (as smart-encoded deltas)
- Per-group: CRC32, version, file count, file IDs
- Optional: name hashes for groups and files

## Group Response (Type 0x1E)

**`jag::Js5WorkerThread::GroupDownloaded`**

Processing flow:
1. Read 4-byte CRC from packet
2. Compute CRC32 over raw data
3. If CRC mismatch: call `FailGetGroupResponse(this, archiveId, groupId, encrypted, 1)`
4. Read flags byte from data:
   - Bit 1 (& 2): RSA signature present
   - Other bits: encryption/compression info
5. If RSA flagged:
   a. Compute Whirlpool hash
   b. Read 64-byte RSA signature
   c. Compare; if mismatch: `FailGetGroupResponse(this, archiveId, groupId, encrypted, 2)`
6. Call `Js5Compression::Decompress`
7. If decompress fails: `FailGetGroupResponse(this, archiveId, groupId, encrypted, 3)`
8. If second decompress needed (double-compressed): decompress again
9. Package decompressed data into message with type 0x1E, post to main thread

### OnResponse Group Fields (Case 0x1E)

```
1 byte:  Archive ID
2 bytes: Group ID (via <in Ghidra DB> = gT_ushort or similar)
4 bytes: Version
4 bytes: CRC32
1 byte:  Flags (encryption + compression info)
N bytes: Container data
```

## File Retrieval

**`jag::Js5ResourceProvider::GetFile`**

Retrieves a decompressed file from the cache. Flow:

1. Look up the archive's index data
2. Find the group entry at `index[0x48] + groupId * 0x20`
3. If group data not loaded, allocate and return pending
4. Call `Js5Compression::Decompress` on the cached container
5. Check file mode flag at `*index + 0xe`:
   - Mode 1: Return raw decompressed data (deflate-only, single file)
   - Mode 2 or 4: Call `Js5Compression::SplitMultiVersion` to extract specific file version
   - Mode 3: Call XTEA decryption (<in Ghidra DB>) before returning
6. If multi-version: Split using `SplitMultiVersion` based on version count and file count
7. Wrap result in reference-counted buffer object

### Multi-Version Splitting

**`jag::Js5Compression::SplitMultiVersion`**

When a group contains multiple files (versions), this function splits the decompressed data:
1. Read version count byte from the last byte of data
2. Read per-file size deltas (4 bytes each, big/little endian based on platform)
3. Accumulate deltas to get absolute file offsets
4. Copy each file's data segment into the output packet

## CRC32 Verification

All downloaded data is verified using CRC32 before processing.

**CRC32 Table**: `<in Ghidra DB>` (256 x 4-byte entries)

**Algorithm** (standard CRC32 with initial value 0xFFFFFFFF):
```
crc = 0xFFFFFFFF
for each byte b in data:
    crc = (crc >> 8) ^ table[(b ^ crc) & 0xFF]
crc = ~crc
```

## Disk Cache

**`jag::Js5DiskCache::PerformWrite`**

Cache files are stored as SQLite databases named `%sjs5-%d.jcache` where `%d` is the archive ID.

- Uses `INSERT OR REPLACE` into `cache` and `cache_index` tables
- Data is compressed using zlib (`compress`) when compression type == 1 before writing
- Thread runner at `<addr in DB>` processes disk I/O operations in a background thread

**`jag::Js5Compression::DecompressGroup`**

Reads cached data from disk and decompresses:
1. Check if data starts with compression magic (`<in Ghidra DB>`)
2. If magic matches: decompress using `uncompress` (zlib)
3. Otherwise if type == 2: use streaming decompress (`Js5Compression::Decompress`)

## Network Queue

**`jag::Js5NetQueue::Js5NetQueue`**

Constructor allocates 0x310 bytes for the queue structure. Key fields:
- Offset 0x5C: `GroupDownloadedCallback` function pointer

**`jag::Js5NetQueue::GroupDownloadedCallback`**

Wrapper that validates packet size >= 3 bytes before forwarding to `GroupDownloaded`.

## Error Handling

### Index Failure

**`jag::Js5WorkerThread::FailGetIndexResponse`**

Sends failure notification with message type 0x14:
```
1 byte: 0x14 (message type)
1 byte: Archive ID
1 byte: Error code (1=CRC fail, 2=RSA fail, 3=decompress fail)
```

### Group Failure

**`jag::Js5WorkerThread::FailGetGroupResponse`**

Sends failure notification with message type 0x1E:
```
1 byte:  0x1E (message type)
1 byte:  Archive ID
4 bytes: Group ID (int, via <in Ghidra DB>)
1 byte:  Encrypted flag
1 byte:  Error code
```

## Key Data Addresses

| Address | Name | Description |
|---------|------|-------------|
| `<addr in DB>` | `<in Ghidra DB>` | Compression magic marker (zlib header check) |
| `<addr in DB>` | `<in Ghidra DB>` | CRC32 lookup table (256 entries) |
| `<addr in DB>` | `<in Ghidra DB>` | Endianness check (compared against `<in Ghidra DB>`) |
| `<addr in DB>` | `<in Ghidra DB>` | Encryption settings array (0x18 bytes per entry) |
| `<addr in DB>` | `<in Ghidra DB>` | Default/null index reference |
| `<addr in DB>` | `<in Ghidra DB>` | Default/null index reference (alternate) |

## All Identified Functions

| Address | Full Name | Description |
|---------|-----------|-------------|
| `<addr in DB>` | `jag::Js5Compression::Decompress` | Main container decompression (types 0-3) |
| `<addr in DB>` | `jag::Js5Compression::DecompressGroup` | Disk cache decompression |
| `<addr in DB>` | `jag::Js5Compression::SplitMultiVersion` | Multi-version file splitter |
| `<addr in DB>` | `jag::Js5MasterIndex::Js5MasterIndex` | Master index constructor with RSA/Whirlpool verification |
| `<addr in DB>` | `jag::Js5WorkerThread::OnResponse` | Main response dispatcher (6 message types) |
| `<addr in DB>` | `jag::Js5WorkerThread::GroupDownloaded` | Group download handler with CRC32/RSA/decompress |
| `<addr in DB>` | `jag::Js5WorkerThread::IndexDownloaded` | Index download handler with CRC32/RSA/decompress |
| `<addr in DB>` | `jag::Js5WorkerThread::FailGetGroupResponse` | Group failure notification (type 0x1E) |
| `<addr in DB>` | `jag::Js5WorkerThread::FailGetIndexResponse` | Index failure notification (type 0x14) |
| `<addr in DB>` | `jag::Js5WorkerThread::Js5WorkerThread` | Worker thread constructor |
| `<addr in DB>` | `jag::Js5WorkerThread::SetURLs` | Sets content delivery URLs |
| `<addr in DB>` | `jag::Js5ResourceProvider::GetFile` | Retrieves and decompresses file from cache |
| `<addr in DB>` | `jag::Js5NetQueue::Js5NetQueue` | Network queue constructor |
| `<addr in DB>` | `jag::Js5NetQueue::GroupDownloadedCallback` | Download completion callback wrapper |
| `<addr in DB>` | `jag::Js5DiskCache::PerformWrite` | SQLite disk cache writer |
| `<addr in DB>` | `jag::Js5DiskCache::ThreadRunner` | Disk cache background thread |

### Helper Functions (Not Renamed)

| Address | Purpose |
|---------|---------|
| `<addr in DB>` | Read 4-byte big-endian int from raw buffer (endian-aware) |
| `<addr in DB>` | Allocate/resize Packet buffer |
| `<addr in DB>` | Post message to inter-thread queue |
| `<addr in DB>` | Create message buffer |
| `<addr in DB>` | Write 4-byte big-endian int to Packet |
| `<addr in DB>` | Compute Whirlpool hash |
| `<addr in DB>` | Finalize Whirlpool hash |
| `<addr in DB>` | LZMA decompression |
| `<addr in DB>` | Large disk cache processing loop |

## Functions Not Yet Found

The following functions from `parsed_functions.txt` symbols have not been located in this binary build:

| Symbol Name | Description |
|-------------|-------------|
| `Js5Index::LoadIndex` | Parses archive index format (group IDs, CRCs, versions, file IDs) |
| `Js5NetQueue::RequestData` | Builds and submits network download requests |
| `Js5ResourceProvider::WorkerOnMessage` | Main-thread handler for worker thread messages |
| `Js5HTTPQueue::RequestData` | HTTP-specific download request builder |
| `Js5Preloader` methods | Pre-loading/priority management for cache assets |

## String References

| Address | String | Context |
|---------|--------|---------|
| In binary | `"Js5WorkerThread"` | Thread name, referenced in constructor |
| In binary | `"js5connect"` | Connection handshake identifier |
| In binary | `"js5connect_outofdate"` | Version mismatch error |
| In binary | `"js5connect_full"` | Server capacity error |
| In binary | `"Js5DiskCache has been deleted"` | Cache corruption message |
| In binary | `"%sjs5-%d.jcache"` | SQLite cache file naming pattern |
| In binary | `"Js5Cache-Move"` | Cache migration thread name |
