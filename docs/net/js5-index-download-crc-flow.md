# JS5 Index Download: CRC Computation, Acceptance Flow, and Group Request Triggering

Reverse-engineered from the NXT client binary (`rs2client`) via Ghidra MCP to diagnose why the client goes silent after downloading 27 archive indices (255/X responses) but never requests actual group data.

**Key Functions Analyzed:**
- `jag::Js5WorkerThread::IndexDownloaded` -- CRC validation + whirlpool check + decompress
- `jag::Js5WorkerThread::FailGetIndexResponse` -- Response packet builder (success AND failure)
- `jag::Js5ResourceProvider::WorkerOnMessage` -- Main-thread handler, case 0x14 (index downloaded)
- `jag::Js5Index::LoadIndex` -- Index parser
- `jag::Js5ResourceProvider::FileReady` -- File availability check, triggers group requests
- `jag::Js5ResourceProvider::FileReady_CheckIndex` -- Wrapper that calls IndexReady first
- `jag::Js5ResourceProvider::GetFile` -- Decompresses cached group, feeds to MemoryCache
- `jag::Js5ResourceProvider::GetFile_ArchiveGroup` -- Dispatches to GetFile or disk cache
- `jag::Js5ResourceProvider::GetIndex` -- Sends index request (message type 0x14) to worker
- `jag::Js5ResourceProvider::RequestGroupFromServer` -- Enqueues group requests
- `jag::Js5WorkerThread::OnMessage` -- Worker thread message handler (request dispatch)
- `jag::Js5NetQueue::RequestData` -- TCP request queue insertion

---

## 1. CRC32 Computation in IndexDownloaded (EXACT BYTE-LEVEL)

### Function: `jag::Js5WorkerThread::IndexDownloaded`

When an index response (archive=255, group=N) is fully received from TCP, the worker thread's download callback invokes `IndexDownloaded(this, archiveId, data)`.

### Parameters

- `this`: Js5WorkerThread pointer
- `archiveId` (int): Which archive index was downloaded (0-66)
- `data` (Packet*): The raw container bytes received from the JS5 TCP stream
  - `data[1]` = byte count (ulong) -- total size of the container data
  - `data[2]` = byte pointer -- pointer to the container bytes

### What `data` Contains

The `data` Packet holds the **complete raw container** as received from the JS5 response, with JS5 framing (10-byte header, 5-byte continuation headers) already stripped. The bytes are:

```
[compression(1)] [compressedSize(4 BE)] [payload(N)]
```

Where `payload` is:
- For compression != 0: `[decompressedSize(4 BE)] [compressedData(compressedSize)]`
- For compression == 0: `[rawData(compressedSize)]`

### CRC32 Algorithm

The CRC is a **standard CRC32** (same polynomial as zlib/gzip, lookup table at `<addr in DB>`):

```
Input:  ALL bytes from data[2], for data[1] bytes
Init:   crc = 0xFFFFFFFF
Loop:   for each byte b in input:
            crc = (crc >> 8) ^ table[(b ^ crc) & 0xFF]
Final:  crc = ~crc
```

**CRITICAL: The CRC is computed over the ENTIRE raw container data.** This includes:
- The compression type byte (offset 0)
- The compressedSize field (offsets 1-4)
- The full payload (everything after offset 4)

**No bytes are excluded.** The entire `data[1]` bytes starting at `data[2]` are fed into the CRC32. There is no "skip last 2 bytes" or any other truncation.

### CRC Verification

```c
// Step 1: Read expected CRC from the extra-data packet (in_RCX)
in_RCX[3] = 0;  // Reset packet position
uVar6 = Packet::gT_uint(in_RCX);  // Read expected CRC (4 bytes, BE)

// Step 2: Compute CRC32 over the complete container data
uVar3 = data[1];       // byte count
pbVar8 = data[2];      // byte pointer
// ... standard CRC32 loop (unrolled 8x for performance) ...
uVar11 = ~uVar11;      // final XOR

// Step 3: Compare
if (uVar6 != uVar11) {
    FailGetIndexResponse(this, archive);  // CRC MISMATCH -> fail
    return;
}
```

### Where the Expected CRC Comes From

The expected CRC is stored in the **master index** and was embedded in the index request. The flow is:

1. `GetIndex` (main thread) reads `masterIndex.entries[archiveId].crc` and writes it into the request packet:
   ```c
   Packet::pT_int(local_60, **(int **)(masterIndexEntries + archiveId * 8));  // CRC
   ```
2. This packet is sent as message type 0x14 to the worker thread
3. `OnMessage` case 0x14 reads the CRC and 64-byte whirlpool digest, then passes them alongside the TCP request
4. When the response arrives, `IndexDownloaded` reads the expected CRC from this extra-data packet

**In summary:** The expected CRC = the CRC field from the master index entry for that archive.

### After CRC Passes: Whirlpool Check

```c
// Read hasWhirlpool flag from the extra-data packet
lVar7 = in_RCX[3];
in_RCX[3] = lVar7 + 1;
if (*(char *)(in_RCX[2] + lVar7) == '\x01') {  // hasWhirlpool flag
    // Compute Whirlpool hash over the raw container data
    <in Ghidra DB>(data[2], data[1] << 3, whirlpoolState);  // NESSIEadd (bit count)
    <in Ghidra DB>(whirlpoolState, computedHash);            // NESSIEfinalize -> 64 bytes

    // Read expected hash from extra-data packet (64 bytes)
    memcpy(expectedHash, in_RCX[2] + in_RCX[3], 64);
    in_RCX[3] += 64;

    // Compare byte-by-byte
    if (computedHash != expectedHash) {
        FailGetIndexResponse(this, archive);  // WHIRLPOOL MISMATCH -> fail
        return;
    }
}
```

**Whirlpool input is also the ENTIRE raw container data** (`data[1]` bytes at `data[2]`), same scope as the CRC.

### After All Checks Pass: Decompress and Respond

```c
// Decompress the container
Js5Compression::Decompress(decompressedBuffer, data);

// Send success response to main thread
FailGetIndexResponse(this, archive);  // Despite the name, this IS the success path too
```

**IMPORTANT:** `FailGetIndexResponse` is a misleadingly named function. It is called for BOTH success and failure. The key differentiator is the `DL` register value:
- **Success:** DL = 0x00 (from the successful decompress path)
- **Failure:** DL = non-zero (from the CRC/whirlpool mismatch paths)

---

## 2. FailGetIndexResponse: The Response Packet

### Function: `jag::Js5WorkerThread::FailGetIndexResponse`

```c
void FailGetIndexResponse(long *this, int archive) {
    // Create a 3-byte response packet
    local_3c = 3;
    CreateResponsePacket(&local_38, &local_3c);

    // Write opcode 0x14 (index downloaded)
    packet.writeByte(0x14);

    // Write archive ID
    packet.writeByte((byte)archive);

    // Write status byte (from DL register - inherited from caller)
    packet.writeByte(in_DL);  // 0x00 = success, non-zero = failure

    // Post to main thread
    Task::Response(this, &local_38);
}
```

### Response Packet Format

```
Offset  Size  Type   Field      Description
------  ----  ----   -----      -----------
0       1     byte   opcode     0x14 (message type: index downloaded)
1       1     byte   archive    Archive ID (0-66)
2       1     byte   status     0x00 = success, non-zero = failure
```

---

## 3. Main Thread Handler: WorkerOnMessage Case 0x14

### Function: `jag::Js5ResourceProvider::WorkerOnMessage`, case 0x14

```c
case 0x14:
    // Read archive ID (byte)
    bVar35 = readByte(packet);

    // Read status byte
    statusByte = readByte(packet);

    if (statusByte != '\0') {
        // FAILURE: Reset index download state to 0 (not requested)
        this->indexDownloadState[archive] = 0;
        return;
    }

    // SUCCESS PATH:
    // Read expected CRC from extra data
    uVar22 = Packet::gT_uint(packet);

    // Verify master index is loaded
    masterIndex = this->masterIndex;  // at this + DWORD_ARRAY_000022e0 + 0x2d8
    if (masterIndex == NULL) {
        this->indexDownloadState[archive] = 0;
        return;
    }

    // Verify archive ID is within master index range
    if (masterIndex->archiveCount <= archive) {
        // OUT OF BOUNDS -> triggers an error (invalid instruction exception)
        abort;
    }

    // Get the master index entry for this archive
    puVar16 = masterIndex->entries[archive];

    // Create a decompressed data packet from the remaining bytes
    CreateResponsePacket(&local_188, &local_190);
    Packet::pArrayBuffer(local_180, packet_remaining_data, decompressed_size);

    // Initialize a new Js5Index object on the stack
    // (zeroed out, all fields initialized)

    // Copy CRC from master index entry
    local_168[0] = *puVar16;  // CRC from master index

    // Check if decompressed data starts with 0x07 (format version 7)
    if (*(char *)local_180[2] == '\x07') {
        // Read version from decompressed data
        uVar22 = Packet::gT_uint(local_180);
        // Parse index data
        Js5Index::LoadIndex(local_168, local_180);
    }

    // Move the parsed index into the provider's index array
    Js5Index::MoveAssign(this->indices[archive], local_168);
    Js5Index::Destroy(local_168);

    // If disk cache is enabled, store the index container on disk
    if (this->diskCacheEnabled && this->diskCache != NULL) {
        Js5DiskCache::ProvideGroup(this->diskCache, archive, -1, ...);
        // Mark archive in disk cache as having index loaded
        if (diskCacheArchive->groupCount != 0) {
            diskCacheArchive->indexLoaded = true;
        }
    }

    // SET INDEX STATE TO 3 (LOADED)
    this->indexDownloadState[archive] = 3;
```

### Index Download State Machine

The `indexDownloadState` array (at `this + 0x25d0`, one uint32 per archive) tracks:

| Value | Meaning |
|-------|---------|
| 0 | Not requested / failed |
| 2 | Request sent, waiting for response |
| 3 | Index loaded and ready |

**The transition to state 3 is what enables group requests for that archive.**

---

## 4. What Triggers Group Data Requests

### The Demand-Driven Chain

Group requests are NOT automatic. They are triggered by game systems calling into the JS5 provider. The chain is:

```
Game system (renderer, login screen, config loader, etc.)
    |
    v
FileReady_CheckIndex(archive, groupId, fileId, ...)
    |
    | Step 1: Call IndexReady via vtable (checks indexDownloadState)
    | If state != 3 (loaded): return NOT_READY (no group request)
    | If state == 3: proceed
    |
    v
FileReady(archive, groupId, fileId, ...)
    |
    | Step 2: Call Js5Index::DoesFileExist on the loaded index
    | If file doesn't exist: return immediately
    |
    | Step 3: Check Js5MemoryCache::GetFileInternal
    | If cached in memory: return the data
    |
    | Step 4: Call GetFile_ArchiveGroup -> tries disk cache
    | If found on disk: return
    |
    | Step 5: Call RequestGroupFromServer(archive, groupId, priority, urgent)
    |   -> Creates Js5WorkerRequestMessage
    |   -> Inserts into per-archive request tree
    |   -> Inserts into per-priority request tree
    |
    v
Worker thread OnInterval polls request trees
    |
    v
Js5NetQueue::RequestData(archive, groupId, ...)
    |
    v
TCP request sent: flags(1) + archive(1) + group(4) + padding(4)
```

### The Critical Gate: IndexReady

`FileReady_CheckIndex` calls `IndexReady` via vtable (`*this + 0x10`). The IndexReady function (documented in `js5-post-master-index-flow.md`) checks:

1. **`this->masterIndex != NULL`** -- If master index wasn't parsed/accepted (RSA failed), returns NOT_READY (CORRECTED: was documented as diskCache check)
2. **`this->indexDownloadState[archiveId] == 3`** -- If index not loaded, returns NOT_READY or triggers download
3. **Index object is non-null** -- The actual Js5Index must be populated

**Only when `indexDownloadState[archive] == 3` can group requests proceed.**

### What Game Systems Trigger First Requests

For a fresh client with no disk cache, the typical sequence after master index acceptance:

1. Game client main loop resumes after WorkerOnMessage case 10 returns
2. Login screen rendering needs config data -> calls `FileReady_CheckIndex(archive=2, ...)`
3. `IndexReady` finds archive 2's index not loaded -> sends message 0x14 to worker
4. Worker requests index 255/2 via TCP
5. Server responds, index loaded, state set to 3
6. On the NEXT tick, the login screen renderer calls `FileReady_CheckIndex(archive=2, ...)` again
7. This time `IndexReady` returns READY (state == 3)
8. `FileReady` checks if the group is cached, finds it's not
9. `RequestGroupFromServer` enqueues the group request
10. Worker sends TCP request for `archive=2, group=N`

---

## 5. ROOT CAUSE ANALYSIS: Why Client Goes Silent After 27 Index Downloads

### The Symptom

- Master index accepted (RSA passes)
- Client requests all 27+ archive indices (255/0 through 255/66)
- Server serves all of them
- 30 seconds of silence
- Connection timeout, reconnect, repeat

### The Diagnosis

The fact that indices ARE being requested and served means the master index is accepted and `Js5DiskCache` was created. The fact that NO group requests follow means one of:

#### Hypothesis A: CRC Mismatch on Index Data

If our server's raw container data for an index has a different CRC than what's recorded in the master index, `IndexDownloaded` will fail the CRC check and send a failure response (status byte != 0). The main thread will reset `indexDownloadState[archive] = 0`, meaning the index appears "not requested" again.

**Key check:** The CRC in the master index must be the CRC32 of the **exact raw container bytes** we serve for that index. This means:

```
CRC32 input = compression(1) + compressedSize(4) + payload(N)
```

This is the SAME data as `cache.sector(255, archiveId)` -- the raw sector data from the SQLite cache. The master index CRC must match this exactly.

**If the master index is being built by our server** (rather than served from the real cache), the CRCs must be computed over the exact bytes that `FileProvider.data(255, archiveId)` returns.

#### Hypothesis B: Decompression Failure

If the container data passes CRC but `Js5Compression::Decompress` fails, the response sent to the main thread may have an empty or malformed decompressed payload. When `WorkerOnMessage` case 0x14 tries to parse it and finds the first byte is NOT `0x07` (format version), it skips `LoadIndex` entirely. The `Js5Index` remains empty, and while `indexDownloadState` is set to 3, the index has no groups listed, so `DoesFileExist` always returns false.

#### Hypothesis C: Format Version Check

The main thread handler checks:
```c
if (*(char *)local_180[2] == '\x07') {
    Js5Index::LoadIndex(local_168, local_180);
}
```

If the decompressed index data does NOT start with byte `0x07`, `LoadIndex` is never called. The index object remains empty. `DoesFileExist` returns false for all groups. No group requests are made.

**Modern RS3 indices use format version 7.** If the cache contains older format indices, this check would fail silently.

#### Hypothesis D: Index Loaded But No Groups Listed

If `LoadIndex` parses successfully but the index has `groupCount == 0`, then `DoesFileExist` returns false for everything, and no group requests are generated.

### Most Likely Cause

**Hypothesis A (CRC mismatch) is the most likely cause** given the symptoms:

1. The client requests all indices -- this means the master index IS accepted
2. The server serves all indices -- the TCP protocol and framing are correct
3. No group requests follow -- the indices were NOT accepted

When `IndexDownloaded` fails the CRC check, it:
- Calls `FailGetIndexResponse` with a non-zero status byte
- Main thread resets `indexDownloadState[archive] = 0`
- `IndexReady` sees state 0, tries to request the index again
- But `GetIndex` checks `indexDownloadState[archive] < 2` before sending
- State 0 qualifies, so it sends another request
- This creates a silent retry loop until the 30-second timeout

**The fix:** Ensure the CRC32 values in the master index (version table) match the CRC32 of the exact raw container bytes served for each index. If the master index is the real Jagex one but the index containers were re-compressed or modified, the CRCs will mismatch.

---

## 6. How to Verify: Server-Side CRC Check

Add CRC32 verification on the server side:

```kotlin
// For each index we serve:
val indexData = cache.sector(255, archiveId)  // raw container bytes
val computedCrc = CRC32
computedCrc.update(indexData)
val crc = computedCrc.value.toInt

// Compare against the CRC in our master index:
val expectedCrc = masterIndex.entries[archiveId].crc
if (crc != expectedCrc) {
    log.error("CRC MISMATCH for index $archiveId: computed=$crc, masterIndex=$expectedCrc")
}
```

If mismatches are found, the master index needs to be regenerated from the actual cache data, or the cache data needs to be served unmodified.

---

## 7. Complete Data Flow Diagram

```
                                    SERVER                              CLIENT
                                    ------                              ------

1. Master Index                     serve(255/255)  --------TCP-------> WorkerThread receives
   (version table)                  raw container                       Posts message type 10
                                                                        to main thread
                                                                        |
                                                                        v
                                                                   WorkerOnMessage case 10:
                                                                   - Parse master index
                                                                   - Create Js5DiskCache
                                                                   - Create Js5MemoryCache
                                                                   - For each archive:
                                                                     store CRC + version
                                                                   - indexDownloadState = 0 (all)

2. Game systems request files                                      FileReady_CheckIndex:
                                                                   - IndexReady checks state
                                                                   - state == 0 -> GetIndex
                                                                     |
                                                                     v
                                                                   GetIndex:
                                                                   - Build packet: 0x14 + archiveId
                                                                     + CRC(4B) + whirlpool(64B)
                                                                   - Send to worker thread
                                                                   - indexDownloadState[arch] = 2

3. Worker sends TCP request                                        OnMessage case 0x14:
                                    <--------TCP request-----------  Js5NetQueue::RequestData(255, archiveId)
                                    index=255 group=archiveId

4. Server responds                  serve(255/archiveId) ---TCP---> WorkerThread receives raw container
                                    raw container bytes             Callback: IndexDownloaded
                                                                    |
                                                                    v
                                                                   IndexDownloaded:
                                                                   A. Read expected CRC from extra-data packet
                                                                   B. CRC32 over ALL raw container bytes
                                                                   C. Compare CRC
                                                                      MISMATCH -> FailGetIndexResponse(fail)
                                                                                  -> main thread: state = 0
                                                                                  -> retry loop (SILENT!)
                                                                      MATCH -> continue
                                                                   D. Check whirlpool flag
                                                                      If set: verify 64B hash
                                                                      MISMATCH -> fail (same as above)
                                                                   E. Js5Compression::Decompress
                                                                   F. FailGetIndexResponse(success, DL=0)
                                                                      -> main thread: case 0x14

5. Main thread loads index                                         WorkerOnMessage case 0x14:
                                                                   - Read status byte (0 = success)
                                                                   - Read decompressed data
                                                                   - Check first byte == 0x07
                                                                   - Js5Index::LoadIndex -> parse groups
                                                                   - Store index in provider
                                                                   - Js5DiskCache::ProvideGroup (cache it)
                                                                   - indexDownloadState[arch] = 3

6. Group requests begin                                            FileReady_CheckIndex:
                                                                   - IndexReady -> state == 3 -> READY
                                                                   - FileReady -> DoesFileExist -> yes
                                                                   - Not in memory cache
                                                                   - Not in disk cache
                                                                   - RequestGroupFromServer
                                                                     |
                                                                     v
                                    <--------TCP request-----------  OnMessage case 0x1E:
                                    index=N group=M                  Js5NetQueue::RequestData(N, M)
```

---

## 8. CRC32 Reference Implementation (Standard CRC32)

The NXT client uses the standard CRC32 algorithm (same as `java.util.zip.CRC32`):

- Polynomial: `<in Ghidra DB>` (reflected form of 0x04C11DB7)
- Init: 0xFFFFFFFF
- Final XOR: 0xFFFFFFFF (i.e., bitwise NOT)
- Process: byte-at-a-time with 256-entry lookup table

```
Equivalent Java:
    java.util.zip.CRC32 crc = new CRC32;
    crc.update(rawContainerBytes);
    int result = (int) crc.getValue;
```

The CRC is computed over the **complete raw container**: `compression(1) + compressedSize(4) + payload(N)`. This is exactly the byte array returned by `cache.sector(255, archiveId)` -- no transformation, no header stripping.

---

## 9. Server Code Analysis: CRC Consistency Verification

### VersionTableBuilder CRC Source

In `SQLiteCache.parseRefTable` (line 255):
```kotlin
val rawTable = indexFiles[indexId]?.getRawTable
versionTable?.sector(indexId, rawTable, whirlpool)
```

`VersionTableBuilder.sector` calls `CRC.calculate(sectorData)` on the raw table bytes. This is `CRC32` with polynomial `<in Ghidra DB>` -- the standard CRC32, matching the client.

### FileProvider Data Source

`CacheFileProvider.data(255, archiveId)` calls `cache.sector(255, archiveId)` which calls `indexFiles[archiveId]?.getRawTable` -- the **same function** used to compute the CRC.

**Conclusion: The CRC values in the master index ARE consistent with the data served for index requests.** The raw bytes are identical -- same SQLite query, same column, same row. There is no transformation between CRC computation and serving.

### Server-Side Serving: What the Client Actually Receives

`FileProvider.serve` does:
1. Strips the 5-byte container header (`compression(1) + compressedSize(4)`)
2. Re-writes them into the JS5 response header as separate fields
3. Sends the remaining payload bytes with block framing

The client reassembles: `compression(1) + compressedSize(4) + payload(N)` -- which is exactly the original raw container bytes. **The CRC should match.**

### Revised Root Cause Assessment

Since the CRC computation is provably consistent between the master index and the served data, the root cause is likely NOT a CRC mismatch. The more likely causes are:

#### 1. The `FailGetIndexResponse` DL Register Problem

The decompiled `IndexDownloaded` function shows that after CRC passes and `Js5Compression::Decompress` runs, it calls `FailGetIndexResponse(this, archive)`. The status byte written is `in_DL` -- the value of the DL register inherited from the calling context. If `Decompress` leaves a non-zero value in RDX (and thus DL), the main thread would interpret the response as a failure.

However, this code path works correctly with Jagex's live servers, so `Decompress` presumably sets DL=0 on success. This is not our bug.

#### 2. The `indexDownloadState` is Set to 3 But No Game System Requests Files

After indices are loaded (state=3), group requests only happen when game systems call `FileReady_CheckIndex`. If the game client is stuck in an initialization phase before it starts requesting files (e.g., waiting for a login connection, config server response, or other initialization), no group requests will be generated.

**This is the most likely root cause.** The JS5 connection handles index downloads, but actual group downloads require the game client to progress to a state where it needs specific files (login screen rendering, config loading, etc.). If the client is blocked on something else (e.g., a login server connection attempt that's failing, or a configURI that's not responding properly), it will never reach the code that calls `FileReady_CheckIndex`.

#### 3. The `this[0x1ec5]` Disk-Cache-Enabled Flag in GetFile_ArchiveGroup

The `GetFile_ArchiveGroup` function (called by `FileReady` to check disk cache) has:
```c
if ((char)this[0x1ec5] != '\0') {
    cVar1 = RequestGroupFromDisk(this, archiveSettings, groupId, priority, in_R8B);
    return cVar1;
}
return 0;
```

If `this[0x1ec5]` is `'\0'` (disk caching disabled) AND `this[0xe]` is also `'\0'` (not in immediate mode), the function returns 0 without doing anything. This means `FileReady` would see `lVar3 == 0` and skip the disk-cache retry loop, proceeding directly to `RequestGroupFromServer`.

But `RequestGroupFromServer` also checks `this[0xe]`:
```c
if ((char)this[0xe] != '\0') {
    GetFile(this, archiveSettings, groupId, priority);
    return;
}
```

If `this[0xe] == '\0'` (not in immediate mode), it proceeds to the normal request flow. So this should work either way.

#### 4. Worker Thread Connection State Check

In `Js5WorkerThread::OnMessage` case 0x1E (group request from main thread):
```c
if ((*(int *)((long)this + 0x2a4) == 3) &&
    ((int *)this[0x35] != NULL) &&
    (*(int *)this[0x35] == 2))
```

The worker thread checks connection state == 3 AND that the mode object exists AND mode == 2. If the JS5 TCP connection dropped between index downloads and group requests, `connectionState` might not be 3, causing all group requests to fail silently.

**Check:** Is the JS5 server keeping the TCP connection alive? If the server closes the connection after serving all index responses, the worker thread would detect the disconnection and transition out of state 3.
