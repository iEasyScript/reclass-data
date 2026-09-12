# JS5 Post-Master-Index Flow: How Index Requests Are Triggered

Reverse-engineered from the NXT client binary via Ghidra MCP to diagnose the "client goes silent after master index" bug.

**Key Functions Analyzed:**
- `jag::Js5ResourceProvider::WorkerOnMessage` (rs2client) -- Main-thread message handler, case 10
- `jag::Js5ResourceProvider::IndexReady` (librs2client.so) -- Triggers index downloads (vtable slot 2, offset +0x10)
- `jag::Js5ResourceProvider::GetIndex` (rs2client) -- Higher-level index request API
- `jag::Js5ResourceProvider::FileReady` (rs2client) -- File availability check, triggers index if needed
- `jag::Js5ResourceProvider::FileReady_CheckIndex` (rs2client) -- Wrapper: calls IndexReady then FileReady
- `jag::Js5ResourceProvider::FileReady_WithCheck` (rs2client) -- Wrapper: calls IndexReady then memory cache check
- `jag::Js5ResourceProvider::GetFile_ArchiveGroup` (rs2client) -- Dispatches to HTTP, disk, or returns silently
- `jag::Js5ResourceProvider::RequestGroupFromDisk` (rs2client) -- Disk cache group request
- `jag::Js5ResourceProvider::RequestGroupFromServer` (rs2client) -- Server request scheduling
- `jag::Js5DiskCache::Startup` (rs2client) -- Disk cache initialization
- `jag::Js5DiskCache::GetDatabaseFilename` (rs2client) -- Cache path construction
- `jag::Js5DiskCache::OpenDatabase` (rs2client) -- SQLite database open
- `Js5WorkerThread::OnInterval` (librs2client.so) -- Worker thread polling loop
- `Js5WorkerThread::OnMessage` (librs2client.so) -- Worker thread message handler
- `jag::Js5WorkerThread::CreateQueues` (rs2client) -- Queue/connection setup
- `jag::Js5HTTPQueue::RequestData` (rs2client) -- HTTP download request
- `jag::Js5HTTPQueueRequest::Send` (librs2client.so) -- HTTP request execution

---

## Critical Finding: The MasterIndex Gate (CORRECTED)

**CORRECTION (verified 2026-03-10 against librs2client.so):** The primary gate in `IndexReady` is the **masterIndex** pointer at `this+0x120` (librs2client), NOT the diskCache pointer. If the master index RSA verification fails, the masterIndex object is left in an invalid/empty state and IndexReady returns NOT_READY immediately. The diskCache is a secondary gate that affects whether groups can be fetched from disk, but the masterIndex is the first check.

### The Three Request Paths

`GetFile_ArchiveGroup` (rs2client has three code paths:

```
GetFile_ArchiveGroup(this, archiveId, groupId, priority):
    // Path 1: HTTP mode
    if this->httpMode (offset 0x70, this[0xe]):
        GetFile(this, archiveId, groupId, priority)  // HTTP download
        return 0

    // Path 2: Disk cache path (TCP)
    if this->diskCacheEnabled (offset 0xF628, this[0x1ec5]):
        return RequestGroupFromDisk(this, archiveSettings, groupId, priority, urgent)

    // Path 3: DEAD END -- neither HTTP nor disk cache
    return 0   // <-- SILENTLY DROPS THE REQUEST
```

The `httpMode` flag at offset 0x70 is for the HTTP download path. The `diskCacheEnabled` flag at offset 0xF628 controls whether the TCP/disk cache path is available. **If both are false, the function returns 0 without doing anything.**

### The IndexReady Gate (librs2client.so

`IndexReady` is called via vtable (slot at vtable+0x10) from `FileReady_CheckIndex`, `FileReady_WithCheck`, and `GetIndex`. Its decompiled logic:

```
IndexReady(this, archiveSettings):
    // GATE: masterIndex pointer must be non-NULL
    if this->masterIndex == NULL:     // librs2client: this+0x120, rs2client: this+0x90
        return NOT_READY              // returns `<in Ghidra DB>` -- silently fails, no request sent

    archiveId = archiveSettings->archiveId
    if archiveSettings != this->archiveSettingsVector[archiveId]:
        return DataStatus::enumArray  // wrong archive reference

    if this->indexPointers[archiveId] != 0:
        return READY                  // index already loaded (`<in Ghidra DB>`)

    if this->indexDownloadState[archiveId] >= 2:
        return NOT_READY              // already requested, waiting

    // Try disk cache first
    result = RequestGroupFromDisk(this, archiveSettings, groupId=-1, ...)
    if result == false:   // disk cache didn't have it
        // Send request to worker thread over TCP
        packet = new Packet(0x46)
        packet.writeByte(0x14)                                  // message type: request index
        packet.writeByte(archiveId)                             // which archive
        packet.writeInt(masterIndex.entries[archiveId].crc)     // CRC for verification
        packet.writeBytes(masterIndex.entries[archiveId].data)  // whirlpool hash + metadata
        Task::Message(this->workerThread, packet)
        this->indexDownloadState[archiveId] = 2                 // mark as "requested"

    return NOT_READY  // loading
```

**CORRECTED (verified librs2client.so:** The very first check is `this->masterIndex != NULL` (at `this+0x120` in librs2client). This was previously documented as "diskCache != NULL" which is WRONG. The masterIndex pointer (same offset in both binaries: `this+0x120` in librs2client, `this+0x90` in rs2client) is the gate. If the master index was never parsed/accepted (RSA failure, etc.), `IndexReady` returns NOT_READY immediately without ever sending a request to the worker thread.

### DataStatus Return Values

The functions return pointers to static sentinel values:

| Address (librs2client) | Address (rs2client) | Meaning |
|------------------------|---------------------|---------|
| `<in Ghidra DB>` | `<addr in DB>` | NOT_FOUND / error |
| `<in Ghidra DB>` | `<addr in DB>` | NOT_READY / loading |
| `<in Ghidra DB>` | `<addr in DB>` | READY |

---

## Critical Finding: Index Requests Are DEMAND-DRIVEN, Not Automatic

**The NXT client does NOT automatically request all archive indices after accepting the master index.** There is no "request all indices" loop. Instead, index requests are triggered **on demand** by the game systems that need specific archives.

### How It Works

1. The client receives the master index (message type 10 / `WorkerOnMessage` case 10)
2. The master index is parsed; `Js5DiskCache` and `Js5MemoryCache` are created
3. The client does NOT immediately request any archive indices
4. Later, when a game system (renderer, login screen, etc.) needs data from a specific archive, it calls `GetFile` or `GroupPreloaded` or `FileReady`
5. Those functions call `IndexReady` (via vtable) to check if the archive's index is loaded
6. If the index is NOT loaded, `IndexReady` sends a message (type 0x14) to the worker thread requesting the index
7. The worker thread issues the TCP request (`jag::Js5NetQueue::RequestData` with archive=255, group=archiveId)

### The Client Does NOT Need a Login/Lobby Connection First

The JS5 subsystem operates independently of the login/lobby system. After the JS5 TCP handshake and master index acceptance, the client's game systems (login screen renderer, config loader, interface loader) begin requesting files through the JS5 pipeline. There is no dependency on a successful login or lobby connection before JS5 group data is requested.

The first file requests typically come from the login screen renderer needing textures, interfaces, and config data.

---

## WorkerOnMessage Case 10: Full Master Index Acceptance Flow

After the master index is received and RSA/Whirlpool verification passes, `WorkerOnMessage` case 10 does the following:

```
1. Read data size (ushort) -- if 0, master index failed, set error flag and return
2. Read raw container data (dataSize bytes)
3. Create new Js5MasterIndex object (parses the archive entries)
4. If memoryCache already exists (this->0x88 != NULL):
   a. For each archive, compare old master index entries with new ones
   b. If CRC or version changed, reset the archive's Js5Index
   c. This handles live-server index updates
   d. Jump to step 8

5. If memoryCache does NOT exist (first-time init):
   a. Zero out indexDownloadState array (0x43 = 67 entries)
   b. Zero out pending request counters (4 entries)
   c. Create Js5MemoryCache (`<in Ghidra DB>` bytes)
   d. Store at this+0x88

   e. Check diskCacheEnabled flag (this+0xF628 in rs2client)
      - This flag was set during Js5ResourceProvider construction from the `bool` parameter
      - The constructor signature: Js5ResourceProvider(url1, url2, url3, SystemSettings*,
        configPacket, version, archiveSettings, bool diskCacheEnabled, rsaModulus, rsaExponent)

   f. If diskCacheEnabled:
      - Allocate Js5DiskCache (`<in Ghidra DB>` bytes)
      - Set vtable to PTR_OnCacheFolderChanged_014a8d18
      - Initialize per-archive Database objects, request queues, thread sync
      - Construct cache folder path from SystemSettings
      - Call Js5DiskCache::Startup (opens/creates SQLite .jcache files)
      - Store DiskCache pointer at this+0x90
   g. If NOT diskCacheEnabled:
      - Skip DiskCache creation entirely
      - this+0x90 remains NULL
      - Jump to step 6 (which reads from this+0x90, getting NULL)

6. For each archive in the archive settings vector:
   a. If archive settings is non-null:
      - Compute group count from master index (archiveEntry.fileCount + 1)
      - Resize the disk cache's per-archive group tracking array
      (This allocates storage for tracking which groups are cached on disk)

7. Clean up any stale verification data

8. RETURN -- no index requests are sent here
```

**Key observation:** Step 5f calls `Js5DiskCache::Startup` which initializes SQLite databases. This is synchronous and happens on the main thread. After this returns, the disk cache is ready to serve cached data.

### The diskCacheEnabled Flag Origin

The `diskCacheEnabled` flag is the 8th parameter (`bool`) passed to the `Js5ResourceProvider` constructor. The full constructor signature (from librs2client.so symbols):

```cpp
jag::Js5ResourceProvider::Js5ResourceProvider(
    eastl::basic_string<char> const& url1,
    eastl::basic_string<char> const& url2,
    eastl::basic_string<char> const& url3,
    jag::SystemSettings* settings,
    jag::Packet const& configPacket,
    unsigned int version,
    jag::Js5ArchiveSetSettings& archiveSettings,
    bool diskCacheEnabled,          // <-- THIS CONTROLS EVERYTHING
    jag::math::BigInteger* rsaExponent,   // stored at this+0x78 (librs2client)
    jag::math::BigInteger* rsaModulus     // stored at this+0x80 (librs2client)
);
```

**VERIFIED (librs2client.so:** In WorkerOnMessage case 10, the constructor call is:
```c
pBVar10 = *(BigInteger **)(this + 0x78);  // 9th param = exponent
pBVar11 = *(BigInteger **)(this + 0x80);  // 10th param = modulus
Js5MasterIndex::Js5MasterIndex(pJVar21, pBVar10, pBVar11, local_1c8);
```
And in the Js5MasterIndex constructor:
```c
mp_exptmod(ciphertext, *(param_1), *(param_2), result);
// libtommath: mp_exptmod(G, X, P, Y) => Y = G^X mod P
// param_1 = X = exponent, param_2 = P = modulus
```

This bool is likely derived from `SystemSettings` or `preferences.cfg`. If the client cannot determine a valid cache folder path (e.g., `cache_folder` not set in preferences.cfg, or the path doesn't exist/isn't writable), this flag may be false.

---

## Js5DiskCache Initialization Details

### Startup Flow (rs2client

`Js5DiskCache::Startup` iterates through all known archives from the archive settings and:

1. For each archive:
   a. Resizes the per-archive group status tracking array (used for "is this group cached on disk?")
   b. Sets archive metadata (archive ID, back-pointer to disk cache)
   c. Checks if the archive is a "core" archive (affects filename)
   d. Calls `GetDatabaseFilename` to construct the path (e.g., `{cacheFolder}/js5-5.jcache` or `{cacheFolder}/core-js5-5.jcache`)
   e. Checks if the file already exists on disk
   f. If it exists, checks for a `_dummy` suffixed copy, potentially recovers from interrupted moves
   g. Opens the SQLite database via `Database::Open`
   h. Sets the per-archive status to "open" (state=2) and marks the archive as having a disk cache entry

2. After all archives are processed:
   a. Cleans up any orphaned `.jcache` files for archives that no longer exist
   b. Starts the background worker thread (`Js5DiskCache::ThreadRunner` -> `ThreadWorkLoop`)
   c. The worker thread handles async disk I/O (reads, writes, deletes)

### Database Filename Construction (`GetDatabaseFilename`)

```
path = "{cacheFolder}/{prefix}js5-{archiveId}.jcache"
```

Where:
- `cacheFolder` comes from SystemSettings (ultimately from `preferences.cfg` `cache_folder=`)
- `prefix` is `"core-"` for core databases or `""` for regular ones
- Translation-aware archives may have a language suffix appended

### What Can Go Wrong

1. **Cache folder doesn't exist:** If `~/.projectx` (or whatever `cache_folder` is set to) doesn't exist, `GetDatabaseFilename` may construct a path to a non-existent directory, and `Database::Open` will fail.

2. **Not writable:** If the cache folder exists but isn't writable, database creation fails.

3. **Missing preferences.cfg:** If the client can't find or parse preferences.cfg, it may not have a cache folder path at all, potentially causing `diskCacheEnabled` to be false.

4. **OpenDatabase retry loop:** `OpenDatabase` has a retry loop -- if the database open fails, it loops back and retries. But it checks the stop flag first, so if the disk cache is being torn down, it exits. If the open consistently fails (bad path), this could hang or repeatedly fail.

---

## Multiple JS5 Connections

### TCP: Single Connection

The `Js5WorkerThread` maintains exactly **one** `Js5NetQueue` at `this+0x138` (offset 0x36 in qwords). The `CreateQueues` function creates one `Js5NetQueue` (0xD0 bytes) and one `Js5HTTPQueue` (0x80 bytes).

The `OnInterval` function manages a single `ClientStream` at `this+0x130`. There is no mechanism for parallel TCP connections.

### HTTP: Separate Parallel Path

The client also has a `Js5HTTPQueue` at `this+0x140` for HTTP-based file downloads. The `OnMessage` handler for group requests (case 0x1E) checks a flag:

```
if (bVar19 == 0):
    // TCP path: Js5NetQueue::RequestData
else:
    // HTTP path: Js5HTTPQueue::RequestData
```

The HTTP path constructs URLs like:
```
{baseURL}/ms?m=0&a={archive}&g={group}&c={crc}&v={version}
```

The `OnInterval` function processes HTTP responses by polling `Js5HTTPQueueRequest` objects and checking for completion. HTTP requests run asynchronously via the system's HTTP client.

**Important:** The master index can also be requested over HTTP (message type 0x28 in `OnMessage`), with a fallback mechanism (`MasterIndexNotDownloadedOverHTTP`).

### Connection Count Summary

| Transport | Count | Queue Object | Purpose |
|-----------|-------|-------------|---------|
| TCP | 1 | `Js5NetQueue` at `this+0x138` | Primary for all requests |
| HTTP | 1+ | `Js5HTTPQueue` at `this+0x140` | Parallel downloads, supports multiple concurrent HTTP requests |

---

## Request Scheduling Details

### How Group Requests Enter the Pipeline

There are two paths for group requests:

#### Path 1: Through RequestGroupFromDisk (disk cache path)

1. `FileReady`/`FileReady_WithCheck` calls `GetFile_ArchiveGroup`
2. `GetFile_ArchiveGroup` checks `this->diskCacheEnabled` (offset 0xF628)
3. If enabled, calls `RequestGroupFromDisk`
4. `RequestGroupFromDisk` checks `this->diskCache` (offset 0x90) -- if NULL, returns TRUE immediately (pretends success but does nothing meaningful)
5. If disk cache exists, checks the per-archive group status array at `diskCache + `<in Ghidra DB>` + archiveId*0x20`
6. Status values: 0=unknown, 1=cached, 2=failed, 3=pending
7. If status is 2 (failed), returns FALSE (triggers server request as fallback)
8. If status is 3 (pending), returns TRUE (already being loaded)
9. Otherwise, creates a request node in the per-archive request tree and calls `Js5DiskCache::EnqueueRequest`
10. The disk cache worker thread processes the request asynchronously

#### Path 2: Through RequestGroupFromServer (network path)

1. When disk cache doesn't have the group (RequestGroupFromDisk returned FALSE), or when called directly
2. `RequestGroupFromServer` creates a `Js5WorkerRequestMessage` from the shared pool
3. Inserts into per-archive request tree (sorted by groupId) and per-priority request tree
4. The worker thread's `OnInterval` iterates the request trees and calls `Js5NetQueue::RequestData`
5. The TCP request is sent on the next polling iteration

### Request Limits

- **Server request limit:** 1500 total (0x5DC) checked per urgent/non-urgent counter
- **Disk cache request limit:** 9998 (0x270E) total across all priority levels
- If limits are reached, requests are silently dropped

### What Triggers Requests for a Fresh Client

For a fresh client with no disk cache contents, the typical sequence is:

1. Master index accepted (message 10)
2. `Js5DiskCache::Startup` runs -- creates empty SQLite databases
3. Game client main loop resumes
4. Login screen renderer needs textures/interfaces --> calls `FileReady(archive=X, group=Y, file=Z)`
5. `FileReady_CheckIndex` calls `IndexReady(archive=X)` via vtable
6. `IndexReady` sees diskCache is non-NULL, index not loaded, sends message 0x14 to worker
7. Worker receives message 0x14, sends TCP request for `255/X` (index for archive X)
8. Server responds with index data
9. Main thread processes response in `WorkerOnMessage` case 0x14: calls `Js5Index::LoadIndex`
10. On next game tick, `FileReady_CheckIndex` calls `IndexReady` again -- now returns READY
11. `FileReady` proceeds to call `GetFile_ArchiveGroup` for the actual group data
12. `GetFile_ArchiveGroup` -> `RequestGroupFromDisk` -> `EnqueueRequest` (disk cache miss) -> eventually `RequestGroupFromServer`

---

## Diagnosing "Client Goes Silent After Master Index"

### Root Cause Analysis (CORRECTED 2026-03-10)

Based on verified analysis of librs2client.so with full symbols, the most likely causes (in order):

**1. RSA verification failure in Js5MasterIndex constructor** -- If any of these checks fail:
   - Decrypted result size != 65 bytes (0x41)
   - Decrypted byte[0] != 0x01
   - Whirlpool hash mismatch
   The masterIndex object is left with empty archive entries array. WorkerOnMessage case 10 stores it at `this+0x120` but with no entries, so IndexReady returns NOT_READY or finds no valid entries.

**2. diskCacheEnabled is FALSE** -- If this flag (at `this+0x168` in librs2client) is false:
   - `WorkerOnMessage` case 10 skips `Js5DiskCache` creation -- `this+0x90` stays NULL
   - `GetFile_ArchiveGroup` returns 0 silently (neither HTTP mode nor disk cache enabled)
   - However, `IndexReady` STILL works if masterIndex is valid (its gate is masterIndex, not diskCache)

### Why diskCacheEnabled Might Be False

The `diskCacheEnabled` bool is the 8th parameter to the `Js5ResourceProvider` constructor, derived from `SystemSettings`. Possible causes:

1. **preferences.cfg not found or malformed:** If the client can't read `cache_folder` from preferences.cfg, it may disable disk caching
2. **Cache folder path invalid:** If `cache_folder` points to a non-existent or non-writable path, the client may proactively disable disk caching
3. **Missing cache_folder directory:** The directory `~/.projectx` must exist before the client starts -- the client may not create it automatically
4. **Client build configuration:** Some client configurations may disable disk caching by default (debug builds, web builds)

### Other Possible Causes

1. **Master index entry count mismatch:** If our master index reports a different number of archives than the client expects, the archive settings vector might not match, causing `IndexReady`'s archive pointer comparison `archiveSettings != this->archiveSettingsVector[archiveId]` to fail and return early.

2. **Index download state stuck:** If `indexDownloadState[archiveId] >= 2` for archives (perhaps from stale disk cache data), `IndexReady` would think the index is already being downloaded.

3. **Worker thread not running:** If the `Js5WorkerThread` isn't processing messages, the 0x14 messages from `IndexReady` would queue up but never be dispatched as TCP requests.

4. **Disk cache Startup failure:** Even if `diskCacheEnabled` is true, if `Js5DiskCache::Startup` fails (can't create SQLite databases), the per-archive database status might be wrong, preventing `RequestGroupFromDisk` from functioning.

### Debugging Recommendations

1. **Check for .jcache files:** After the client connects and receives the master index, check if SQLite `.jcache` files are being created in the cache folder (e.g., `~/.projectx/js5-0.jcache`). If they exist, the disk cache was created successfully.

2. **Ensure cache folder exists and is writable:** `mkdir -p ~/.projectx && chmod 755 ~/.projectx` before launching the client.

3. **Verify preferences.cfg:** The client must have a valid `cache_folder=` entry in preferences.cfg pointing to an existing, writable directory.

4. **Check the client's stderr:** The patcher and client may print diagnostic messages about cache folder issues.

5. **Verify master index archive count:** Ensure our master index entry count matches the `Js5ArchiveSetSettings` the client was built with. The client cross-references each archive settings entry against master index entries.

6. **Monitor the TCP connection:** After the master index is served, the next client request should be for an index (archive 255, group = some archive ID). If nothing comes, the gate is the disk cache.

---

## Appendix: Key Js5ResourceProvider Field Map

| Offset (rs2client) | Offset (librs2client) | Type | Field |
|--------------------|-----------------------|------|-------|
| 0x70 (this[0xe]) | -- | bool | httpMode |
| -- | 0x78 | BigInteger* | rsaExponent (9th ctor param) |
| -- | 0x80 | BigInteger* | rsaModulus (10th ctor param) |
| 0x88 (this[0x11]) | 0x88 | Js5MemoryCache* | memoryCache |
| 0x90 (this[0x12]) | 0x90 | Js5DiskCache* | diskCache |
| -- | 0x120 | Js5MasterIndex* | masterIndex (gate for IndexReady) |
| 0x25D0 + archiveId*4 | 0x140 + archiveId*4 | uint | indexDownloadState |
| 0x26E0 + archiveId*0x108 | 0x150 + archiveId*8 (ptr array) | Js5Index | perArchiveIndex |
| -- | 0x168 | bool | diskCacheEnabled |
| 0xF628 (this[0x1ec5]) | -- | bool | diskCacheEnabled (rs2client) |

## Appendix: Message Type Summary (Worker <-> Main Thread)

| Type | Direction | Description |
|------|-----------|-------------|
| 0x01 | Main->Worker | URL update |
| 0x02 | Main->Worker | Initialize (URLs, mode, packet, keyCount) |
| 0x06 | Worker->Main | Set CRC/version |
| 0x07 | Main->Worker | Change URLs |
| 0x0A (10) | Worker->Main | Master index received |
| 0x14 (20) | Main->Worker + Worker->Main | Request index / Index downloaded |
| 0x1E (30) | Main->Worker + Worker->Main | Request group / Group downloaded |
| 0x28 (40) | Main->Worker + Worker->Main | Request master index verify / Verified master index |
