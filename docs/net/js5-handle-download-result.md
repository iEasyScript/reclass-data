# JS5 HandleDownloadResult & Index Processing: Case 0x14 Deep Dive

Reverse-engineered from the NXT client binary (`rs2client`) via Ghidra MCP.

**Key Functions Analyzed:**
- `jag::Js5ResourceProvider::HandleDownloadResult` -- Direct download result handler
- `jag::Js5ResourceProvider::ProcessDownloadResults` -- Queue-draining wrapper
- `jag::Js5ResourceProvider::WorkerOnMessage` -- Main-thread message handler (case 0x14)
- `jag::Js5WorkerThread::IndexDownloaded` -- Worker-thread CRC/whirlpool validation
- `jag::Js5WorkerThread::FailGetIndexResponse` -- Response builder (success AND failure)
- `jag::Js5Index::LoadIndex` -- Index binary parser
- `jag::Js5ResourceProvider::GetIndex` -- Index request sender
- `jag::Js5ResourceProvider::FileReady` -- Group request trigger
- `jag::Js5ResourceProvider::FileReady_CheckIndex` -- IndexReady + FileReady wrapper
- `jag::Js5ResourceProvider::GetFile_ArchiveGroup` -- Disk cache / HTTP dispatch
- `jag::Js5ResourceProvider::RequestGroupFromServer` -- Server request enqueue
- `jag::Js5ResourceProvider::RequestGroupFromDisk` -- Disk cache request
- `jag::Js5DiskCache::ProvideGroup` -- Disk cache write

---

## 1. Overview: The Two Index Response Paths

When an index response (archive=255, group=X where X != 255) arrives, it can take two paths to the main thread:

### Path A: Worker Thread Direct Response (message type 0x14)

This is the path for indexes downloaded from TCP. The worker thread validates CRC + whirlpool, decompresses, and posts a 3-byte message (opcode 0x14 + archiveId + status) to the main thread. The decompressed data travels alongside as the packet payload.

### Path B: ProcessDownloadResults Queue (type 0 entries)

This is the path for indexes loaded from the disk cache. `ProcessDownloadResults` drains a mutex-protected queue on the main thread. When it encounters a type-0 entry with `groupId == 0xFFFFFFFF` (index), it handles the result inline.

Both paths converge on the same logic: decompress, validate, call `LoadIndex`, install via `MoveAssign`, set state to 3.

---

## 2. Worker Thread: IndexDownloaded

### Entry Point

Called when a JS5 TCP response for `archive=255, group=X` completes download. The raw container bytes (with JS5 framing stripped) are in the `data` parameter.

### Step-by-step Flow

```
IndexDownloaded(this, archiveId, data):
    extraDataPacket = in_RCX    // extra data from the request (CRC + whirlpool hash)

    // 1. Read expected CRC from the extra-data packet
    extraDataPacket.position = 0
    expectedCRC = Packet::gT_uint(extraDataPacket)    // 4 bytes, big-endian

    // 2. Compute CRC32 over the ENTIRE raw container
    //    Input: data[2] (byte pointer), data[1] (byte count) bytes
    //    Container = compression(1) + compressedSize(4) + payload(N)
    computedCRC = CRC32(data[2], data[1])              // standard CRC32, init=0xFFFFFFFF, final=~crc

    // 3. Compare
    if (expectedCRC != computedCRC):
        FailGetIndexResponse(this, archiveId)           // DL register = non-zero (failure)
        return                                          // <-- SILENT FAILURE, no group requests

    // 4. Read whirlpool flag from extra-data
    hasWhirlpool = extraDataPacket.readByte           // 1 byte

    if (hasWhirlpool == 0x01):
        // 5a. Compute Whirlpool over the SAME raw container bytes
        computedWhirlpool = NESSIE(data[2], data[1] * 8)    // bit count

        // 5b. Read expected whirlpool from extra-data (64 bytes)
        expectedWhirlpool = extraDataPacket.readBytes(64)

        // 5c. Compare byte-by-byte (unrolled 8-way comparison)
        if (computedWhirlpool != expectedWhirlpool):
            FailGetIndexResponse(this, archiveId)       // DL register = non-zero (failure)
            return

    // 6. All checks passed - decompress
    decompressedData = Js5Compression::Decompress(data)

    // 7. Send success response to main thread
    FailGetIndexResponse(this, archiveId)               // DL register = 0x00 (success)
```

### CRC32 Algorithm Details

- **Polynomial:** `<in Ghidra DB>` (reflected form, standard CRC-32)
- **Init value:** 0xFFFFFFFF
- **Final XOR:** ~crc (bitwise NOT)
- **Lookup table:** 256-entry table at address `<addr in DB>`
- **Input scope:** ALL bytes of the raw container -- `compression(1) + compressedSize(4) + payload(N)`
- **Equivalent:** `java.util.zip.CRC32.update(rawContainerBytes)` then `(int) getValue`

### Where the Expected CRC Comes From

1. `GetIndex` (main thread) reads `masterIndex.entries[archiveId].crc` from the master index
2. Writes it into a request packet: `pT_uchar(0x14) + pT_uchar(archiveId) + pT_int(crc) + pArrayBuffer(entryData)`
3. Sent as message type 0x14 to the worker thread
4. Worker stores the CRC + whirlpool in the extra-data packet associated with the TCP request
5. When the response arrives, `IndexDownloaded` reads the expected CRC from this extra-data

---

## 3. FailGetIndexResponse: The Response Packet

Despite its name, this function is called for BOTH success and failure. The status byte comes from the `DL` register (low byte of RDX), inherited from the calling code path.

### Packet Format

```
Offset  Size  Type   Field      Description
------  ----  ----   -----      -----------
0       1     byte   opcode     0x14 (message type: index downloaded)
1       1     byte   archiveId  Archive ID (0-66)
2       1     byte   status     0x00 = success, non-zero = failure
```

### How Status is Determined

- **Success path:** After `Js5Compression::Decompress`, DL = 0x00 (decompress sets RDX to the result pointer; the low byte naturally becomes 0 for valid heap addresses)
- **CRC failure:** DL inherits a non-zero value from the comparison path
- **Whirlpool failure:** DL inherits a non-zero value from the comparison path

---

## 4. Main Thread: WorkerOnMessage Case 0x14

This handles the message posted by `IndexDownloaded` (or by `ProcessDownloadResults` for disk-cache loaded indexes).

### Full Control Flow

```c
case 0x14:
    // Read archive ID
    archiveId = readByte(packet)                    // 1 byte

    // Read status byte
    statusByte = readByte(packet)                   // 1 byte

    if (statusByte != 0x00):
        // FAILURE: Reset index download state to "not requested"
        indexDownloadState[archiveId] = 0           // at this + 0x25D0 + archiveId*4
        return
        // This allows the index to be re-requested on the next demand

    // SUCCESS PATH:
    // Read expected CRC (from the decompressed response packet)
    expectedCRC = Packet::gT_uint(packet)           // 4 bytes

    // Check master index exists
    masterIndex = *(this + DWORD_ARRAY_000022e0 + 0x2D8)
    if (masterIndex == NULL):
        indexDownloadState[archiveId] = 0
        return

    // Bounds check against master index
    if (masterIndex.archiveCount <= archiveId):
        ABORT  // invalid instruction exception

    // Get master index entry for this archive
    entry = masterIndex.entries[archiveId]

    // Build response packet with decompressed data
    CreateResponsePacket(&responsePacket, &packetSize)
    Packet::pArrayBuffer(responsePacket, remainingPacketData, decompressedSize)

    // Initialize a new Js5Index on the stack (all fields zeroed)
    Js5Index tempIndex = {}
    tempIndex.crc = entry.crc                       // Copy CRC from master index entry
    // Copy name hash if applicable (entry + 2 != local_140 check for name hash source)

    // Set format version flag
    tempIndex.formatVersion = 1                     // local_150 = 1

    // >>> CRITICAL CHECK: Format version 7 <<<
    if (*(decompressedData.pointer) == 0x07):       // First byte of decompressed index data
        version = Packet::gT_uint(decompressedData) // Read 4-byte version (skipping format byte)
        tempIndex.version = version
        Js5Index::LoadIndex(&tempIndex, decompressedData)   // Parse the index
    // If first byte != 0x07, LoadIndex is NEVER CALLED
    // The index object remains empty (groupCount=0)

    // Install the index into the provider's per-archive array
    Js5Index::MoveAssign(this + 0x26E0 + archiveId * 0x108, &tempIndex)
    Js5Index::Destroy(&tempIndex)

    // If disk cache is enabled AND exists, persist the index container
    if (diskCacheEnabled && diskCache != NULL):     // this+0x5304 flag, this+0x90 pointer
        Js5DiskCache::ProvideGroup(diskCache, archiveId, -1, responsePacket, entry.crc, entry.version, writeFlag=1)
        // Also mark the disk cache archive as having an index loaded
        diskCacheArchive = diskCache + archiveId * 0x1D8
        if (diskCacheArchive.groupCount != 0):      // offset 0x24
            diskCacheArchive.indexLoaded = 1         // offset 0x15

    // SET INDEX STATE TO 3 (LOADED)
    indexDownloadState[archiveId] = 3               // at this + 0x25D0 + archiveId*4
```

### Index Download State Machine

The `indexDownloadState` array at `this + 0x25D0` (one uint32 per archive, up to 67 entries) tracks:

| Value | Meaning | Transition From | Transition To |
|-------|---------|----------------|---------------|
| 0 | Not requested / failed / needs retry | Initial, or failure in case 0x14 | 2 (via GetIndex/IndexReady) |
| 1 | Requested from disk cache | RequestGroupFromDisk (for index, groupId=-1) | 3 (on disk cache success) or 0 (on failure) |
| 2 | Request sent to worker thread (TCP) | GetIndex or IndexReady | 3 (on success) or 0 (on failure) |
| 3 | Index loaded and ready | Success in case 0x14 | Stays at 3 unless master index changes |

**State 3 is the gate for group requests.** Only when `indexDownloadState[archive] == 3` will `IndexReady` return READY, allowing `FileReady` to proceed to group requests.

---

## 5. The Format Version 7 Gate

This is a critical validation that can silently prevent all group requests for an archive:

```c
if (*(char *)decompressedData.pointer == '\x07'):
    version = Packet::gT_uint(decompressedData)
    Js5Index::LoadIndex(&tempIndex, decompressedData)
```

If the decompressed index data does NOT start with byte `0x07`, `LoadIndex` is never called. The `Js5Index` object remains empty (groupCount=0). The index state is still set to 3 (loaded), but `Js5Index::DoesFileExist` will return false for ALL groups, and no group requests will ever be generated for that archive.

**Modern RS3 (rev 946) indices use format version 7.** Older cache format indices would fail this check silently.

### What Format Version 7 Means

The first byte of the decompressed index is a protocol version:
- `0x05` or `0x06`: Older formats (RS2 era) -- NOT supported by NXT
- `0x07`: Modern NXT format -- uses "smart" variable-length encoding for group IDs and file counts

---

## 6. Js5Index::LoadIndex -- The Index Parser

This function parses the decompressed binary index data into usable group/file lookup tables.

### Input State

- `this`: A Js5Index object (partially initialized -- CRC already set)
- `packet`: A Packet containing the decompressed index data, positioned AFTER the format version byte and the 4-byte version int (i.e., at offset 5 of the decompressed data)

### Parse Flow

```
LoadIndex(this, packet):
    // 1. Read flags byte
    position = packet.position
    packet.position++
    flags = packet.data[position]
    hasNames = flags & 0x01
    hasDigests = flags & 0x02    // 64-byte SHA-512 per group
    hasUnknown8 = flags & 0x08
    hasVersions = flags & 0x04

    // 2. Read group count (smart: short or int)
    if (packet.peekByte < 0):      // high bit set
        groupCount = Packet::gT_uint(packet) & 0x7FFFFFFF
    else:
        groupCount = Packet::gT_ushort(packet)
    this.groupCount = groupCount      // at this + 0x28

    // 3. Allocate group ID array
    <in Ghidra DB>(this + 0x30, groupCount)    // resize/alloc

    // 4. Read group IDs (delta-encoded, smart short/int)
    accum = 0
    maxGroupId = -1
    for i in 0..groupCount-1:
        if (packet.peekByte < 0):
            delta = Packet::gT_uint(packet) & 0x7FFFFFFF
        else:
            delta = Packet::gT_ushort(packet)
        accum += delta
        groupIds[i] = accum           // at *(this + 0x40) + i*4
        if accum > maxGroupId:
            maxGroupId = accum
    // this.maxGroupId = maxGroupId   // at this + 0x84

    // 5. Allocate arrays sized to (maxGroupId + 1)
    arraySize = maxGroupId + 1
    allocate CRC array:       ReadAdditionalData(this + 0x90, arraySize)
    if hasDigests:
        allocate digest array: <in Ghidra DB>(this + 0xA8, arraySize)
    allocate version array:   ReadAdditionalData(this + 0xC0, arraySize)
    allocate unknown array:   ReadOpcodeArray(this + 0xD8, arraySize)

    // 6. Read name hashes (if hasNames flag set)
    if hasNames:
        allocate nameHash array: ReadAdditionalData(this + 0x48, arraySize)
        for i in 0..groupCount-1:
            nameHash = Packet::gT_uint(packet)
            nameHashArray[groupIds[i]] = nameHash
            // Special check: if nameHash == <in Ghidra DB>, record this group as "special"
            //   this.specialGroupId = groupIds[i]    // at this + 0x80

    // 7. Read CRCs (4 bytes each)
    for i in 0..groupCount-1:
        crc = Packet::gT_uint(packet)
        crcArray[groupIds[i]] = crc   // at *(this + 0xA0) + groupIds[i]*4

    // 8. Read unknown8 values (if flag set, 4 bytes each, discarded)
    if hasUnknown8:
        for i in 0..groupCount-1:
            Packet::gT_uint(packet)   // read and discard

    // 9. Read digests (if hasDigests flag, 64 bytes each)
    if hasDigests:
        for i in 0..groupCount-1:
            memcpy(digestArray[groupIds[i]], packet.data + packet.position, 0x40)
            packet.position += 0x40

    // 10. Read version/size info (if hasVersions flag)
    this.totalUncompressedSize = 0
    if hasVersions:
        for i in 0..groupCount-1:
            compressedSize = Packet::gT_uint(packet)
            this.totalUncompressedSize += compressedSize
            uncompressedSize = Packet::gT_uint(packet)   // read and used elsewhere

    // 11. Read per-group versions (4 bytes each)
    // Stored at *(this + 0xD0) indexed by groupIds[i]
    memset(versionArray, 0xFF, arraySize * 4)     // init to -1
    for i in 0..groupCount-1:
        version = Packet::gT_uint(packet)
        versionArray[groupIds[i]] = version

    // 12. Read per-group file counts (smart short/int)
    for i in 0..groupCount-1:
        if (packet.peekByte < 0):
            fileCount = Packet::gT_uint(packet) & 0x7FFFFFFF
        else:
            fileCount = Packet::gT_ushort(packet)
        fileCountArray[groupIds[i]] = fileCount   // ushort at *(this + 0xE8) + groupIds[i]*2

    // 13. Read per-group file ID tables (delta-encoded, smart short/int)
    for i in 0..groupCount-1:
        groupId = groupIds[i]
        fileCount = fileCountArray[groupId]
        if fileCount == 0: continue

        // Read file IDs (delta-encoded)
        maxFileId = -1
        accumFileId = 0
        for j in 0..fileCount-1:
            if (packet.peekByte < 0):
                delta = Packet::gT_uint(packet) & 0x7FFFFFFF
            else:
                delta = Packet::gT_ushort(packet)
            accumFileId += delta
            if accumFileId > maxFileId:
                maxFileId = accumFileId

        // If files are NOT contiguous (fileCount != maxFileId + 1):
        //   Allocate a fileIdMap for this group and re-read the file IDs
        //   The fileIdMap is stored in a per-group array at this + 0xF8 / this + 0x100
        if fileCount != maxFileId + 1:
            // Allocate/resize fileIdMap array
            // Re-parse file IDs into the map
            // This allows sparse file ID spaces within a group
```

### Smart Encoding (Variable-Length Group/File IDs)

The NXT format uses "smart" encoding for IDs and counts:
- If the next byte's high bit (bit 7) is SET: read a 4-byte int, mask off the high bit (`& 0x7FFFFFFF`)
- If the next byte's high bit is CLEAR: read a 2-byte unsigned short
- This allows values 0-32767 in 2 bytes, and 0-2147483647 in 4 bytes

### Endianness Note

The parser checks `<in Ghidra DB> == `<in Ghidra DB>` to determine if the system is little-endian. For little-endian systems (x86/x64), the byte-swap logic is applied to the raw memory reads. The packet read functions (`gT_uint`, `gT_ushort`) handle endianness internally.

---

## 7. HandleDownloadResult -- Direct Download Path

This is the handler used by `ProcessDownloadResults` when type-0 results are processed on the main thread. It handles both index responses (groupId==-1) and group responses.

### Index Response Path (groupId == 0xFFFFFFFF, isMasterIndex == false)

```c
HandleDownloadResult(this, archiveId, groupId=-1, packetData, crc, version, priority,
                     isIndexRequest, isRetry, isMasterIndex=false):

    // Check if index is already loaded (state 3)
    if (indexDownloadState[archiveId] == 3):
        goto cleanup  // Skip, already loaded

    // Get the master index entry for this archive
    masterIndexEntry = masterIndex.entries[archiveId]

    // Copy the packet data
    <in Ghidra DB>(&local_168, packetData)

    // Initialize a new Js5Index on the stack
    local_148.crc = masterIndexEntry.crc
    local_148.version = masterIndexEntry.version
    local_148.nameHash = copy from masterIndexEntry  // if applicable
    // ... zero all other fields ...
    local_150 = 1  // format version flag

    // CHECK FORMAT VERSION 7
    if (*decompressedData.pointer == 0x07):
        readVersion = Packet::gT_uint(&local_168)
        if (readVersion == local_128):   // CRC match check
            Js5Index::LoadIndex(&local_148, &local_168)
    // NOTE: In HandleDownloadResult, there is an ADDITIONAL CRC check:
    //   The version read from the decompressed data is compared against
    //   the version from the master index entry. LoadIndex is ONLY called
    //   if they match. This is different from WorkerOnMessage case 0x14
    //   which does NOT do this additional check.

    // Install the index
    Js5Index::MoveAssign(this + 0x26E0 + archiveId * 0x108, &local_148)
    Js5Index::Destroy(&local_148)

    // Set state to 3 (loaded)
    indexDownloadState[archiveId] = 3

    // If disk cache exists, mark archive as having index loaded
    if (this->diskCache != NULL):
        diskCacheArchive = diskCache + archiveId * 0x1D8
        if (diskCacheArchive.groupCount != 0):
            diskCacheArchive.indexLoaded = true    // offset 0x15
```

### Key Difference from WorkerOnMessage Case 0x14

In `HandleDownloadResult`, the format version 7 check has an **additional gate**:
```c
if (*local_158 == '\x07'):
    uVar8 = Packet::gT_uint(&local_168)
    if (uVar8 == local_128):           // Version from data == version from master index
        Js5Index::LoadIndex(...)
```

The version read from the decompressed data must match the version from the master index entry. This additional check does NOT exist in `WorkerOnMessage` case 0x14 (which always calls `LoadIndex` if the format byte is 0x07).

### Master Index Response Path (isMasterIndex == true)

When `isMasterIndex` is true (the 255/255 response), a different code path is taken:
- The index is installed at offset `this + 0x6BF8 + archiveId * 0x108` instead of `0x26E0`
- The `local_c8` (version) field is initialized differently (`0xFFFFFFFF` for each 4-byte half)
- LoadIndex is called without the version comparison check

---

## 8. ProcessDownloadResults -- Queue Drainer

This runs on the main thread and drains the download result queue.

### Entry Point and Queue

```c
ProcessDownloadResults(this):
    // Lock the result queue mutex
    mutex = this + DWORD_ARRAY_0000a324 + 0x6D2C
    lock(mutex)

    // Swap the queue: take all pending results, clear the queue
    resultQueue = this->resultQueue         // at this + 0x6D54
    resultQueueEnd = this->resultQueueEnd   // at this + 0x6D5C
    this->resultQueue = NULL
    this->resultQueueEnd = NULL
    this->resultQueueSize = NULL            // at this + 0x6D64

    unlock(mutex)
```

### Processing Each Result

Each result entry is 0x38 bytes (14 ints). Two types:

#### Type 0: Direct Download Result
```c
if (result.type == 0):
    priority = result[5] as byte
    groupId = result[2]
    archiveId = result[1]
    resourceProvider = *(this + DWORD_ARRAY_0000a324 + 0x6724)

    if (result[7] == 1):
        // Result includes decompressed data -- call HandleDownloadResult
        HandleDownloadResult(resourceProvider, archiveId, groupId,
                            result+8, result[4], result[3], priority,
                            result.isIndexRequest, result.isRetry, result.isMasterIndex)
    else:
        // Type 0 with result[7] != 1:
        // This is a FAILED download -- need to re-request

        if (groupId == 0xFFFFFFFF):
            // Failed INDEX download: send retry via worker thread
            // Build packet: pT_uchar(0x14) + pT_uchar(archiveId)
            //              + pT_int(masterIndex.entries[archiveId].crc)
            //              + pArrayBuffer(masterIndex.entries[archiveId].data)
            // Post to worker thread
            // Set indexDownloadState[archiveId] = 2 (re-requested)
        else if (result.isIndexRequest):
            // Failed GROUP download: call RequestGroupFromServer to retry
            RequestGroupFromServer(resourceProvider, archiveSettings, groupId, priority, urgent=1)

        // Decrement priority counter
        priorityCounter[priority]--
        // Remove from per-archive request tree
```

### Key Insight: Failed Index Downloads Trigger Retry

When `ProcessDownloadResults` encounters a failed index download (type 0, result[7] != 1, groupId == -1), it does NOT call `HandleDownloadResult`. Instead, it:

1. Builds a new request packet (message type 0x14)
2. Includes the CRC and whirlpool data from the master index
3. Posts it to the worker thread
4. Sets `indexDownloadState[archiveId] = 2` (re-requested)

This creates a **retry loop** for failed index downloads that continues until the download succeeds or the connection times out.

---

## 9. What Happens After ALL Indices Are Loaded

There is NO explicit "all indices loaded" event or callback. The system is entirely demand-driven:

### The Demand-Driven Pipeline

```
Game system needs file from archive X
    |
    v
FileReady_CheckIndex(archive=X, groupId, fileId)
    |
    | 1. Call IndexReady via vtable (offset +0x10)
    |    Checks:
    |    a. masterIndex != NULL          (gate #1, CORRECTED from diskCache)
    |    b. indexDownloadState[X] == 3  (gate #2: index loaded)
    |    If either fails: return NOT_READY
    |    If both pass: return READY
    |
    v
FileReady(archive=X, groupId, fileId)
    |
    | 2. Js5Index::DoesFileExist(index, groupId, fileId)
    |    If false: return NOT_FOUND
    |
    | 3. Js5MemoryCache::GetFileInternal(archiveId, groupId, fileId)
    |    If cached: return data (READY)
    |
    | 4. GetFile_ArchiveGroup(archiveId, groupId, priority)
    |    Dispatches to disk cache or returns 0
    |    |
    |    v
    |    GetFile_ArchiveGroup:
    |        if httpMode (this[0x0E]): GetFile and return 0
    |        if diskCacheEnabled (this[0x1EC5]):
    |            return RequestGroupFromDisk(...)
    |        return 0  // DEAD END if neither enabled
    |
    | 5. If disk cache had it, enters a spin loop:
    |    ProcessDownloadResults repeatedly
    |    Until the group appears in memory cache
    |    (Capped by checking disk cache status != 0x02)
    |
    | 6. If not cached anywhere:
    |    RequestGroupFromServer(archiveId, groupId, priority, urgent)
    |    return NOT_READY
    |
    v
Worker thread processes the group request
    |
    v
TCP request: flags(1) + archive(1) + group(4) + padding(4)
```

### Request Limits

- **Per-urgent counter:** Max 1500 (0x5DC) concurrent urgent requests
- **Per-prefetch counter:** Max 1500 concurrent prefetch requests
- **Disk cache total:** Max 9998 (0x270E) pending disk I/O requests across all priorities
- **Per-priority counters:** Tracked at `this + 0xD28` (4 uint32s for priorities 0-3)

---

## 10. The DiskCache Gate: Critical Path Analysis

The entire group request pipeline depends on two flags:

### Gate 1: masterIndex Pointer (this + 0x120 in librs2client, this + 0x90 in rs2client)

**CORRECTED (2026-03-10):** The primary IndexReady gate is the **masterIndex** pointer, NOT the diskCache pointer. Set during `WorkerOnMessage` case 10 after RSA verification passes:
```c
Js5MasterIndex* mi = new Js5MasterIndex(exponent, modulus, packet);
this->masterIndex = mi     // this + 0x120 (librs2client)
```

**If NULL or invalid (RSA failed):** `IndexReady` returns NOT_READY immediately. No index requests are sent. No group requests are sent.

### Gate 1b: diskCache Pointer (this + 0x90 in librs2client)

Set during `WorkerOnMessage` case 10 if `diskCacheEnabled` is true:
```c
if (diskCacheEnabled):
    Js5DiskCache* cache = new Js5DiskCache(`<in Ghidra DB>` bytes)
    Js5DiskCache::Js5DiskCache(cache, ...)
    this->diskCache = cache     // this + 0x90
```

This is checked by `GetFile_ArchiveGroup` for disk cache access but is NOT the IndexReady gate.

### Gate 2: diskCacheEnabled Flag (this + 0xF628, i.e., this[0x1EC5])

This is the 8th parameter (bool) of the `Js5ResourceProvider` constructor. It determines:
1. Whether `Js5DiskCache` is created (Gate 1)
2. Whether `GetFile_ArchiveGroup` routes to `RequestGroupFromDisk`

**If false AND httpMode is also false:** `GetFile_ArchiveGroup` returns 0 without doing anything. `FileReady` then calls `RequestGroupFromServer` directly, which ALSO checks `httpMode` first. If httpMode is false, it proceeds to the normal TCP request path.

### Important: masterIndex vs diskCacheEnabled vs diskCache

**CORRECTED:** The critical dependency for `IndexReady` is the **masterIndex** pointer being non-NULL and valid (populated with entries), NOT the diskCache. Even if `diskCacheEnabled` is false, `RequestGroupFromServer` can still function (it only checks `httpMode` first, then proceeds to the normal request path).

---

## 11. Disk Cache State Tracking

### Per-Archive Group Status Array

Located at `diskCache + `<in Ghidra DB>` + archiveId * 0x20`, this is a byte array with one entry per group (indexed by `groupId + 1`; slot 0 may be reserved for the index itself).

| Value | Meaning |
|-------|---------|
| 0 | Unknown / not checked |
| 1 | Cached on disk (valid) |
| 2 | Failed / not available on disk |
| 3 | Pending write (just written by ProvideGroup) |

### RequestGroupFromDisk State Checks

```c
char status = *(diskCache + `<in Ghidra DB>` + archiveId*0x20)[groupId + 1]

if (status == 0x02):   // Failed
    return false        // Triggers server request as fallback

if (status == 0x03):   // Pending
    return true         // Already being written, wait
```

### Js5DiskCache::ProvideGroup Sets State to 3

When `ProvideGroup` is called (from either WorkerOnMessage case 0x14 for indexes or case 0x1E for groups), it:
1. Locks the per-archive mutex
2. Sets `statusArray[groupId + 1] = 3` (pending)
3. Unlocks
4. Enqueues the write to the disk cache worker thread

---

## 12. Js5ResourceProvider Field Map (rs2client)

| Offset | Qword Index | Type | Field |
|--------|-------------|------|-------|
| 0x70 | this[0x0E] | bool | httpMode |
| 0x88 | this[0x11] | Js5MemoryCache* | memoryCache |
| 0x90 | this[0x12] | Js5DiskCache* | diskCache |
| 0x98 + archiveId*0x30 | | rbtree | perArchiveRequestTree |
| 0xB8 + archiveId*0x30 | | long | perArchivePendingCount |
| 0xD28 + priority*4 | | uint32[4] | priorityCounters |
| 0x25D0 + archiveId*4 | | uint32 | indexDownloadState |
| 0x26E0 + archiveId*0x108 | | Js5Index | perArchiveIndex (primary) |
| 0x6BF8 + archiveId*0x108 | | Js5Index | perArchiveIndex (secondary/master) |
| 0xF628 | this[0x1EC5] | bool | diskCacheEnabled |

### Js5Index Object Layout (0x108 bytes per archive)

| Offset | Type | Field |
|--------|------|-------|
| 0x00 | uint32 | crc |
| 0x08 | uint32 | version |
| 0x09 | bool | isComplete |
| 0x28 | uint32 | groupCount |
| 0x30 | -- | groupIds allocation info |
| 0x40 | int32* | groupIds array pointer |
| 0x48 | -- | nameHash allocation info |
| 0x58 | int32* | nameHash array pointer |
| 0x80 | uint32 | specialGroupId |
| 0x84 | int32 | maxGroupId |
| 0x88 | long | totalUncompressedSize |
| 0x90 | -- | CRC array allocation info |
| 0xA0 | int32* | CRC array pointer |
| 0xA8 | -- | digest allocation info |
| 0xB8 | byte* | digest array pointer |
| 0xC0 | -- | version array allocation info |
| 0xD0 | int32* | version array pointer |
| 0xD8 | -- | unknown array allocation info |
| 0xE8 | ushort* | fileCount array pointer |
| 0xF8 | ulong | fileIdMap array size |
| 0x100 | void** | fileIdMap array pointer |

---

## 13. Summary: Why the Client Might Not Send Group Requests After Index Downloads

Based on the complete decompilation, here are the failure modes ranked by likelihood:

### 1. Format Version Not 0x07 (Silent LoadIndex Skip)

If the decompressed index data's first byte is not `0x07`, `LoadIndex` is never called. The index object is installed but empty (groupCount=0). `DoesFileExist` returns false for everything. No group requests are generated. The state is set to 3, so no retry occurs.

### 2. CRC Mismatch in IndexDownloaded

If the CRC32 of the raw container bytes doesn't match the CRC in the master index, the worker thread sends a failure response. The main thread resets `indexDownloadState[archiveId] = 0`. The index will be re-requested on the next demand cycle, creating a silent retry loop until timeout.

### 3. Decompression Failure

If `Js5Compression::Decompress` fails, the decompressed data may be empty or malformed. The format version check would fail, and `LoadIndex` would be skipped.

### 4. No Game System Requesting Files

Group requests are demand-driven. If no game system (renderer, config loader, interface system) calls `FileReady_CheckIndex`, no group requests are generated. This can happen if the client is blocked in a prior initialization stage (e.g., waiting for configURI response, login connection, etc.).

### 5. masterIndex is NULL or Empty (CORRECTED)

If the master index RSA verification failed, the masterIndex object exists but has no archive entries. `IndexReady` checks `this->masterIndex != NULL` first. If the masterIndex was never created (download failed with size==0), IndexReady returns NOT_READY. If it was created but RSA failed, the entry loop in the constructor was skipped, so archive entries are empty.

### 6. Connection Dropped

If the JS5 TCP connection drops between index and group requests, the worker thread exits its polling state. Group requests would fail to transmit. The client would attempt to reconnect.
