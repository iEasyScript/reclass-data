# JS5 HTTP Group Download: Response Format & Processing

Reverse-engineered from the NXT client binary (`rs2client` rev 946) via Ghidra MCP.

**Binary:** rs2client (port 8080) -- authoritative for rev 946

**Key Functions Analyzed:**
- `jag::Js5WorkerThread::GroupDownloaded` -- CRC validation + response packaging
- `jag::Js5WorkerThread::OnMessage` -- Worker thread message handler (case 0x1e dispatches to HTTPQueue or NetQueue)
- `jag::Js5ResourceProvider::WorkerOnMessage` -- Main thread handler (case 0x1e receives group data)
- `jag::Js5HTTPQueue::RequestData` -- Enqueues HTTP download request
- `jag::Js5WorkerThread::CreateQueues` -- Creates NetQueue + HTTPQueue
- `jag::Js5NetQueue::GroupDownloadedCallback` -- Callback wrapper (used by BOTH TCP and HTTP)
- `jag::Js5ResourceProvider::GetFile` -- httpMode path: decompress + provide to MemoryCache
- `jag::Js5ResourceProvider::GetFile_ArchiveGroup` -- Dispatcher: httpMode vs diskCache
- `jag::Js5ResourceProvider::RequestGroupFromServer` -- Request scheduling (also checks httpMode)
- `jag::Js5MemoryCache::ProvideGroup` -- Stores data in LRU memory cache
- `jag::Js5MemoryCache::LookupGroup` -- Hash table lookup (crash site)

---

## 1. Executive Summary: The Bug

**Root cause: The HTTP response body must include a 2-byte version suffix after the container data.**

The client's `GroupDownloaded` function computes CRC32 over the response body **minus the last 2 bytes**. Those last 2 bytes are a **little-endian version suffix** that Jagex's HTTP server appends. Our server sends raw container bytes without this suffix, causing:

1. CRC computation reads past the actual data (or computes over wrong range)
2. CRC mismatch -> `FailGetGroupResponse` is called
3. The group download is marked as failed
4. On retry with certain conditions, corrupt data may reach `MemoryCache::ProvideGroup`
5. Corrupted hash table entries in MemoryCache lead to SIGSEGV in `LookupGroup`

**Fix: Append a 2-byte version suffix to each HTTP response body.**

---

## 2. HTTP Response Body Format (What The Client Expects)

The HTTP URL is: `http://{host}:{port}/ms?m=0&a={archive}&g={group}&c={crc}&v={version}`

The expected response body is:

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     compression        Compression type (0=none, 1=bzip2, 2=gzip, 3=lzma)
1       4     compressedSize     Compressed payload size (big-endian)
5       4     decompressedSize   Only present if compression != 0
5/9     N     compressedPayload  The compressed (or raw) data
5+N/9+N 2     version            Version suffix (big-endian uint16)
```

**Total response size = container_data_bytes + 2**

The version suffix is the **group version** from the archive index, truncated to 16 bits (unsigned short). This is the same version that appears in the `v=` query parameter.

### How CRC Is Computed

From `GroupDownloaded`:

```c
// data[1] = total HTTP response body length
// data[2] = pointer to response body bytes
uVar10 = (int)data[1] - 2;        // <-- SUBTRACT 2 for the version suffix
lVar9 = (long)(int)uVar10;

if (lVar9 == 0) {
    uVar6 = 0;
} else {
    // Standard CRC32 over (responseBody[0..length-3])
    // i.e., everything EXCEPT the last 2 bytes
    uVar6 = CRC32(data[2], uVar10);  // init=0xFFFFFFFF, final=~crc
}

// Compare against expected CRC from the request metadata
if (uVar5 != uVar6) {
    FailGetGroupResponse(this, archive, group);
    return;
}
```

**The CRC is computed over the container bytes WITHOUT the 2-byte version suffix.** This matches how CRCs are stored in the archive index -- they cover `compression(1) + compressedSize(4) + [decompressedSize(4)] + compressedPayload(N)`.

### CRC32 Algorithm

- **Polynomial:** `<in Ghidra DB>` (reflected, standard CRC-32)
- **Init value:** 0xFFFFFFFF
- **Final XOR:** `~crc` (bitwise NOT)
- **Lookup table:** At address `<addr in DB>` (256 entries)
- **Equivalent Java:** `java.util.zip.CRC32` -- `update(bytes, 0, length-2)` then `(int)getValue`

---

## 3. GroupDownloaded Processing After CRC Check

After CRC validation passes, `GroupDownloaded` reads a flags byte from the request metadata:

```c
bVar2 = readByte(requestMetadata);  // flags
bVar12 = bVar2 & 1;                // bit 0: has decompressed data
// bit 1: has whirlpool/encryption
```

### Path A: Plain Group (flags & 2 == 0, flags & 1 == 0)

This is the typical HTTP download path for groups without encryption:

```c
// Build response message to main thread
responseSize = data[1] + 0xC;   // HTTP response body + 12 bytes overhead
allocatePacket(&response, responseSize);

Packet::pT_uchar(response, 0x1E);          // opcode: group downloaded
Packet::pT_uchar(response, archive);       // archive ID
Packet::pT_int(response, group);           // group ID
Packet::pT_uchar(response, 0);            // flag1 = 0 (no decompressed data inline)
Packet::pT_uchar(response, 0);            // flag2 = 0 (success)
Packet::pT_int(response, data[1]);         // full response body size (INCLUDING version suffix)
Packet::pArrayBuffer(response, data[2], data[1]);  // full response body bytes
Task::Response(this, response);
```

**Key insight:** The FULL response body (including the 2-byte version suffix) is passed to the main thread. The main thread later strips or ignores the version suffix when storing to DiskCache/MemoryCache.

### Path B: Encrypted Group (flags & 2 != 0)

For encrypted groups, additional whirlpool validation is performed against a 64-byte hash in the request metadata. This path is more complex but follows the same basic structure.

---

## 4. Main Thread: WorkerOnMessage Case 0x1E

When the main thread receives the group downloaded message:

```c
case 0x1E:
    archiveId = readByte(packet);
    groupId = readUint(packet);
    flag1 = readByte(packet);      // cVar2: 0=raw container, 1=has decompressed data, 2=encrypted
    flag2 = readByte(packet);      // cVar3: 0=success, non-zero=failure

    if (flag2 == 0):  // success
        dataSize = readUint(packet);
        AllocFromPool(&containerPacket, &dataSize);
        readArrayBuffer(packet, containerPacket, dataSize);

        // Look up CRC and version from the loaded archive index
        crc = archiveIndex[archiveId].crcs[groupId];
        version = archiveIndex[archiveId].versions[groupId];

        // Write to DiskCache (if enabled)
        if (diskCacheEnabled && diskCache != NULL):
            Js5DiskCache::ProvideGroup(diskCache, archiveId, groupId,
                &containerPacket, crc, version, writeMode);

        // If flag1 == 1: decompressed data follows inline
        if (flag1 == 1):
            decompressedSize = readUint(packet);
            AllocFromPool(&decompressedPacket, &decompressedSize);
            readArrayBuffer(packet, decompressedPacket, decompressedSize);
            MemoryCache::ProvideGroup(memoryCache, archiveId, groupId,
                version, crc, &decompressedPacket);
```

**DiskCache receives the raw container data (with version suffix).** MemoryCache receives decompressed data (if flag1==1) or nothing (flag1==0, in which case it's loaded from disk on demand).

---

## 5. The httpMode Flag (offset 0x70, this[0x0E])

### What It Does

When `httpMode` is true (non-zero), the `GetFile_ArchiveGroup` function takes a completely different path:

```c
GetFile_ArchiveGroup(this, archiveId, groupId, priority):
    if (this->httpMode):           // this[0x0E], offset 0x70
        GetFile(this, archiveId, groupId, priority);
        return 0;

    if (this->diskCacheEnabled):   // this[0x1EC5], offset 0xF628
        return RequestGroupFromDisk(this, archiveSettings, groupId, priority, urgent);

    return 0;  // dead end
```

In httpMode, `GetFile` directly:
1. Reads from the loaded archive index to find the group entry
2. Calls `Js5Compression::Decompress` on the cached container data
3. Handles multi-version splits if needed
4. Creates a decompressed data packet
5. Calls `MemoryCache::ProvideGroup` directly with the decompressed data

**httpMode is a fast path** where container data is already available (downloaded via HTTP and stored in DiskCache), and `GetFile` decompresses it in-place and provides it to the MemoryCache.

### How It Is Set

`httpMode` is set based on the `ModeWhere` parameter (`param=25` in jav_config.ws) and the `iVar27` check in `WorkerOnMessage` case 10. In the case 10 handler:

```c
if ((iVar27 != 0) || (*(char *)(this + 0x70) != '\0')) {
    // Set disk cache flags to enable HTTP-aware mode
    *(puVar19 + 0x2209) = 1;     // disk cache HTTP mode
    *(puVar19 + 0x2207) = 0;     // disable auto-write
    *((long)puVar19 + `<in Ghidra DB>`) = 0;
}
```

The `this + 0x70` byte is read but not written here. It must be set by the Js5ResourceProvider constructor based on configuration parameters.

### RequestGroupFromServer Also Checks httpMode

```c
RequestGroupFromServer(this, archiveSettings, groupId, priority, urgent):
    if (this->httpMode):
        GetFile(this, archiveId, groupId, priority);
        return;
    // ... normal TCP request path ...
```

When httpMode is true, `RequestGroupFromServer` short-circuits to `GetFile` instead of queueing a TCP request.

---

## 6. The Two Group Download Paths

### Path 1: TCP (NetQueue) -- Archive Indices + Groups via JS5 protocol

- Requests go through `Js5NetQueue::RequestData` on the worker thread
- Response arrives as framed JS5 TCP data (512-byte blocks with 0xFF separators)
- Worker thread strips framing, calls `GroupDownloadedCallback`
- `GroupDownloaded` validates CRC, builds response message, posts to main thread

### Path 2: HTTP (HTTPQueue) -- Groups via HTTP GET

- Requests go through `Js5HTTPQueue::RequestData` on the worker thread
- HTTP GET to `http://{host}:{port}/ms?m=0&a={archive}&g={group}&c={crc}&v={version}`
- Response body is the raw container + 2-byte version suffix
- Same `GroupDownloadedCallback` is called with the HTTP response body
- Same `GroupDownloaded` validation + packaging to main thread

**Both paths converge at `GroupDownloadedCallback` -> `GroupDownloaded`**, which is why the CRC validation and version suffix handling is identical.

### How The Client Decides TCP vs HTTP

In `Js5WorkerThread::OnMessage` case 0x1E (group request from main thread):

```c
if (flag_useHTTP == 0):
    // Use TCP (NetQueue)
    Js5NetQueue::RequestData(netQueue, archiveId, groupId, ...)
else:
    // Use HTTP (HTTPQueue)
    // But only if HTTPQueue has capacity (< 20 concurrent requests)
    if (activeHTTPRequests + pendingHTTPRequests < 20):
        Js5HTTPQueue::RequestData(httpQueue, archiveId, groupId, version, crc, ...)
```

The `flag_useHTTP` comes from the request metadata and determines per-group whether TCP or HTTP is used.

---

## 7. Js5MemoryCache::LookupGroup -- The Crash Site

The crash at `LookupGroup` occurs because:

```c
LookupGroup(this, archiveId, groupId):
    key = groupId << 8 | archiveId;
    bucketIndex = key % (this->bucketCount & 0xFFFFFFFF);

    for (entry = hashTable[bucketIndex]; entry != NULL; entry = entry[8]):
        if (key == entry[0]):
            // Found! Update LRU chain...
            // CRASH: entry[6] or entry[7] contains garbage pointer
            uVar2 = entry[6];          // LRU prev
            uVar3 = *(this + `<in Ghidra DB>`); // LRU sentinel
            *(uVar2 + 0x30) = entry[7];  // SIGSEGV here if uVar2 is garbage
```

The hash table entry at `entry[6]` (LRU prev pointer) contains an invalid address. This happens when `ProvideGroup` inserted an entry with corrupt pointers, which traces back to corrupt data reaching the MemoryCache due to CRC validation failures on improperly formatted HTTP responses.

---

## 8. Required Server Fix

### Current (BROKEN) HTTP Response

```
[compression(1)] [compressedSize(4)] [payload(N)]
```

Total: 5 + N bytes (raw container only)

### Correct HTTP Response

```
[compression(1)] [compressedSize(4)] [payload(N)] [version(2)]
```

Total: 5 + N + 2 bytes = container + 2-byte version suffix

### Version Suffix Details

- **Size:** 2 bytes
- **Encoding:** Big-endian unsigned short (matching `Packet::gT_ushort`)
- **Value:** The group version from the archive index, masked to 16 bits (`version & 0xFFFF`)
- **Source:** The `v=` parameter in the HTTP URL contains this value; it should match

### CRC Validation

The CRC in the `c=` query parameter and in the archive index covers the container data **without** the version suffix:
- CRC32 of `compression(1) + compressedSize(4) + [decompressedSize(4) if compressed] + compressedPayload(N)`
- This is the standard container CRC that Jagex stores in the archive index

The server must:
1. Read raw container from cache: `compression(1) + compressedSize(4) + payload(N)`
2. Append 2-byte version suffix: `(version >> 8) & 0xFF, version & 0xFF`
3. Serve the combined bytes as the HTTP response body

---

## 9. Implementation Checklist

-  Modify `ConfigServer.serveJs5Http` to append 2-byte version suffix to HTTP responses
-  Get the group version from the archive index (need `FileProvider` to expose version data)
-  Alternatively, use the `v=` query parameter value from the client's request URL
-  Verify CRC matches: `CRC32(containerBytes) == c_parameter`
-  Total response = `containerBytes + [version >> 8, version & 0xFF]`

### Using the `v=` Parameter as Version Source

The simplest fix: the client passes `v={version}` in the HTTP URL. The server can read this and append it:

```kotlin
val version = call.request.queryParameters["v"]?.toIntOrNull ?: 0
val versionSuffix = byteArrayOf(
    ((version shr 8) and 0xFF).toByte,
    (version and 0xFF).toByte
)
call.respondBytes(data + versionSuffix, ContentType.Application.OctetStream)
```

---

## 10. TCP vs HTTP: Key Differences in Data Format

| Aspect | TCP (JS5 Protocol) | HTTP (/ms endpoint) |
|--------|-------------------|---------------------|
| Framing | 10-byte header + 102KB blocks + continuation headers | None (raw HTTP body) |
| Version suffix | 2-byte version appended by Jagex server | 2-byte version appended by Jagex server |
| CRC scope | Container bytes only (excl. version suffix) | Container bytes only (excl. version suffix) |
| Processing | `GroupDownloaded` strips framing first | `GroupDownloaded` receives raw HTTP body |
| Callback | `GroupDownloadedCallback` | `GroupDownloadedCallback` (same!) |

Both paths expect the version suffix. The TCP path gets it from the JS5 server's response framing. The HTTP path gets it directly in the response body.
