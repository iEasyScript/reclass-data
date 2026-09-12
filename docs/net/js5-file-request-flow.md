# JS5 File Request Flow — RequestGroupFromDisk and Disk Cache Miss Handling

## RE Source
- Binary: `rs2client` (NXT Linux client)
- Functions analyzed:
  - `jag::Js5ResourceProvider::FileReady_CheckIndex`
  - `jag::Js5ResourceProvider::FileReady`
  - `jag::Js5ResourceProvider::GetFile_ArchiveGroup`
  - `jag::Js5ResourceProvider::RequestGroupFromDisk`
  - `jag::Js5ResourceProvider::RequestGroupFromServer`
  - `jag::Js5ResourceProvider::GetIndex`
  - `jag::Js5DiskCache::EnqueueRequest`
  - `jag::Js5DiskCache::ProvideGroup`
  - `jag::Js5DiskCache::ThreadWorkLoop`
  - `jag::Js5DiskCache::Startup`
  - `jag::Js5ResourceProvider::ProcessDownloadResults`

---

## Overview: The File Request Pipeline

When the NXT client needs a cache file (group), the flow is:

```
Game system needs file
    │
    ▼
FileReady_CheckIndex(archive, groupId, fileId)
    │
    ├─ calls IndexReady(archive) via vtable[0x10]
    │   └─ if NOT ready (status != READY) → returns immediately, no FileReady call
    │
    ▼ (only if index is READY)
FileReady(archive, groupId, fileId, priority, urgent)
    │
    ├─ DoesFileExist(groupId, fileId) → if false: returns NOT_FOUND sentinel
    │
    ├─ GetFileInternal (memory cache check) → if hit: returns data
    │
    ├─ GetFile_ArchiveGroup(archive, groupId, priority)
    │   │
    │   ├─ if diskCacheEnabled (this+0x1ec5):
    │   │   └─ RequestGroupFromDisk(...) → returns char (0=FAILED, 1=success/pending)
    │   │
    │   └─ if NOT diskCacheEnabled:
    │       └─ GetFile(...) → direct HTTP/other path
    │
    ├─ if GetFile_ArchiveGroup returns TRUE (1):
    │   │
    │   ├─ if param_9 == 0: return LOADING sentinel
    │   │
    │   └─ SPIN LOOP:
    │       ├─ ProcessDownloadResults
    │       ├─ GetFileInternal (retry memory cache)
    │       ├─ Check disk status == 0x02 (FAILED) → break
    │       └─ Loop until data appears or failure
    │
    └─ if GetFile_ArchiveGroup returns FALSE (0):
        └─ RequestGroupFromServer(archive, groupId, priority, urgent)
            └─ Creates Js5WorkerRequestMessage → enqueued for JS5 TCP transmission
```

---

## Critical Finding: Disk Cache Status Array

The disk cache maintains a **per-group status byte array** at:
```
diskCache + `<in Ghidra DB>` + (archiveId * 0x20)  →  pointer to status array
status_array[groupId + 1]  →  status byte for that group
```

### Status Values

| Value | Meaning | Set by |
|-------|---------|--------|
| `0x00` | NOT_REQUESTED / IDLE | Default / initial state |
| `0x01` | ??? (seen in joined_r<addr in DB>: `*(piVar34+1) = 1`) | Cache hit with valid data |
| `0x02` | FAILED | Cache miss (CRC mismatch, data not found, or key out of range) |
| `0x03` | PENDING | EnqueueRequest sets this before enqueuing |

### The Gate in RequestGroupFromDisk (<addr in DB>)

```c
// At <in Ghidra DB> in RequestGroupFromDisk:
char status = *(status_array + (groupId + 1));

if (status == 0x02) {    // FAILED
    return '\0';          // return FALSE → caller falls through to RequestGroupFromServer
}
if (status == 0x03) {    // PENDING (already enqueued)
    return '\x01';        // return TRUE → duplicate request suppressed
}
// Otherwise (status == 0x00): proceed to enqueue disk read
```

**This is the KEY mechanism.** When `RequestGroupFromDisk` returns `'\0'` (FALSE), `GetFile_ArchiveGroup` returns `0`, and `FileReady` falls through to `RequestGroupFromServer` — which creates a JS5 TCP request.

---

## What Happens When a Group Is NOT in the SQLite Cache

### ThreadWorkLoop — Batch Processing Model (IMPORTANT)

The disk cache worker thread (`ThreadWorkLoop` does **NOT** process individual enqueued requests one at a time. Instead, it works in a **batch/full-scan** model per archive:

#### Phase 1: Archive Selection and Pre-marking

The loop iterates over archives (`lVar21 = 0` to N):
```c
// Line 500: Check if archive's database state is 1 or 2
if (*(int *)(diskCache + `<in Ghidra DB>` + lVar21 * 4) - 1U < 2) {
```

For each active archive, it:
1. Calls `IndexReady` (vtable) to confirm the index is loaded
2. **Iterates ALL group IDs from the Js5Index** (not just enqueued ones)
3. **Pre-marks every group with status = 2 (FAILED)** in a sorted array:
   ```c
   // Line 586: For each groupId in the index
   *(undefined1 *)(piVar23 + 1) = 2;  // Pre-set to FAILED
   ```

This means: before the SQL query even runs, every group starts as "FAILED".

#### Phase 2: SQLite Full Table Scan

4. **Opens database**: `OpenDatabase(diskCache, dbHandle)`
5. **Queries entire table**: `"SELECT DATA,VERSION,CRC,KEY FROM cache"` (no WHERE clause!)
6. **Steps through ALL rows**: `sqlite3_step(statement)` — SQLITE_ROW (100) or SQLITE_DONE (101)

#### Phase 3: For Each Row (SQLITE_ROW)

7. Reads columns: DATA (blob), VERSION (int), CRC (int), KEY (int)
8. **Validates CRC/version** against the Js5Index:
   ```c
   // Line 960:
   if ((diskCacheEnabled + expectedCRC == actualCRC) && (actualVersion == expectedVersion)) {
       // CRC+version match → cache HIT
       goto joined_r<addr in DB>;  // sets status = 1 (HIT), packages data
   }
   ```
9. **If CRC/version mismatch**:
   - If KEY > maxKey in index: `goto <in Ghidra DB>` (skip, re-step to next row)
   - If CRC is valid (1 <= CRC-1 < `<in Ghidra DB>`): `goto joined_r<addr in DB>` → **confirms status = 2 (FAILED)**
   - Otherwise (CRC == 0 or -1): enqueues a re-request with `type=2, priority=2, urgent=true`

#### Phase 4: After All Rows (SQLITE_DONE or no rows)

10. Falls out of the `do...while(iVar16 == 100)` loop
11. **Closes database**: `Database::Close(dbHandle)`
12. **Pushes batch results** to the result queue (mutex at `diskCache + 0x6d2c`)
    - Results include ALL groups that were pre-marked — both hits (status=1) and misses (status=2)
    - For an empty database: ALL groups remain at status=2 (FAILED)
13. Results are consumed by `ProcessDownloadResults` on the main thread

### ProcessDownloadResults — The Dispatch

When `ProcessDownloadResults` drains the result queue:

- **`result_type == 0` (disk read result)**:
  - **`piVar7[7] == 1`** (has data): calls `HandleDownloadResult` → stores in memory cache
  - **`piVar7[7] != 1`** (no data / failed):
    - If `groupId == -1` (index request): sends CRC packet to server, sets `indexDownloadState = 2`
    - If `piVar7[0x15] != 0` (retry flag): **calls `RequestGroupFromServer`** → JS5 TCP request!
    - Decrements priority counter, removes from request tree

### The `joined_r<addr in DB>` Path (Status = 2 / FAILED)

```c
// At joined_r<addr in DB>:
// Binary search in sorted array for groupId...
// Then:
*(piVar34 + 1) = 2;     // Set status to FAILED
goto <in Ghidra DB>;       // Continue processing next row
```

When this status is set to `2`, the NEXT time `RequestGroupFromDisk` is called for that same group, it will see `status == 0x02` and immediately return FALSE, causing the fallthrough to `RequestGroupFromServer`.

---

## Complete Flow for a Cache Miss (Empty Database)

Given: Client has an empty disk cache (0 rows in SQLite). Game system requests archive 7, group 42.

### Step 1: RequestGroupFromDisk Enqueues

1. `FileReady_CheckIndex` → `IndexReady` returns READY (index loaded, state=3)
2. `FileReady` → `DoesFileExist` returns true (group exists in index)
3. `GetFileInternal` → cache miss (not in memory)
4. `GetFile_ArchiveGroup` → `diskCacheEnabled == true` → `RequestGroupFromDisk`
5. `RequestGroupFromDisk` checks status array: **status = 0x00 (IDLE)**
6. Does NOT return early — proceeds to enqueue
7. `Js5DiskCache::EnqueueRequest`:
   - Sets `status_array[groupId+1] = 3` (PENDING)
   - Pushes request struct into insertion queue
   - Signals condition variable (`notify_all`)
8. `RequestGroupFromDisk` returns `'\x01'` (TRUE)

### Step 2: GetFile_ArchiveGroup Returns TRUE

9. `GetFile_ArchiveGroup` returns `1` (non-zero = true)
10. Back in `FileReady`:
    - If `param_9 == 0`: returns LOADING sentinel immediately (non-blocking path)
    - If `param_9 != 0`: enters **spin loop**

### Step 3: Disk Cache Thread Batch Processes Archive

11. `ThreadWorkLoop` wakes up, calls `MoveFromInsertionQueue`
12. Iterates archives — finds archive 7 has pending requests (database state 1 or 2)
13. **Pre-marks ALL groups in archive 7's index with status = 2 (FAILED)**
14. Opens SQLite database for archive 7
15. `SELECT DATA,VERSION,CRC,KEY FROM cache` (full table scan)
16. `sqlite3_step` returns **SQLITE_DONE** (101) — no rows in empty database
17. Falls out of the row-processing loop — all groups remain at status=2
18. `Database::Close`
19. Pushes batch results to result queue — every group marked as status=2

### Step 4: Main Thread Processes Results

20. `ProcessDownloadResults` drains result queue
21. For each result with `result_type == 0` (disk read):
    - If `piVar7[7] == 1` (has data): calls `HandleDownloadResult` (cache hit path)
    - If `piVar7[7] != 1` (no data — our case for empty DB):
      - If `piVar7[0x15] != 0` (retry/redownload flag): **calls `RequestGroupFromServer`**
      - Decrements priority counter, removes from request tree

### Step 5: JS5 TCP Request Sent

21. `RequestGroupFromServer` creates a `Js5WorkerRequestMessage`
22. Message is enqueued into the per-archive and per-priority request trees
23. The JS5 worker thread picks it up and sends the TCP request to the server

---

## Answer to the Critical Question

**When `RequestGroupFromDisk` is called for a group that does NOT exist on disk, what happens?**

**Answer: (a) with a twist.** It does NOT immediately return false. Instead:

1. `RequestGroupFromDisk` sets status=3 (PENDING), enqueues to disk thread, returns TRUE
2. The disk cache thread performs the SQLite query, finds no data, and pushes a "failed" result
3. `ProcessDownloadResults` on the main thread receives the result and calls `RequestGroupFromServer`
4. The JS5 TCP request is finally sent

The flow is **asynchronous** — the disk cache is always consulted first, even for an empty cache. The fallthrough to `RequestGroupFromServer` happens via the result queue, not via a synchronous return value.

**If the same group is requested AGAIN later** and the disk thread already set status=2 (FAILED), then `RequestGroupFromDisk` returns FALSE immediately, and `GetFile_ArchiveGroup` returns 0, causing an immediate `RequestGroupFromServer` call.

---

## Key Data Structures

### Per-Archive Database State (`diskCache + `<in Ghidra DB>`)

```c
int archiveDatabaseState[N];  // at diskCache + `<in Ghidra DB>` + archiveId * 4
```

ThreadWorkLoop only processes archives where `state - 1 < 2` (i.e., state is 1 or 2):
- State 0: not initialized
- State 1: database exists, ready to scan
- State 2: database opened/active
- Other: skip

Set by `Js5DiskCache::Startup` during initialization when it discovers database files on disk.

### Per-Archive Group Status Array (`diskCache + `<in Ghidra DB>`)

```c
// diskCache + `<in Ghidra DB>` + archiveId * 0x20 → pointer to byte array
// byte_array[groupId + 1] → status for that group
// byte_array[0] → status for index (groupId == -1, so -1+1 == 0)
```

### Result Queue Struct Layout

Each result in the queue (stride = 0x38 bytes / 7 qwords):
```
offset 0x00: result_type (0 = disk read, 1 = ?)
offset 0x04: archiveId (uint)
offset 0x08: groupId (uint)
offset 0x0C: version (uint)
offset 0x10: crc/data
offset 0x14: priority (byte)
offset 0x15: retry_flag (char) — CRITICAL: controls fallthrough to RequestGroupFromServer
offset 0x16: ? (char)
offset 0x17: ? (char)
offset 0x1C: has_data_flag (int, == 1 means data present)
offset 0x20+: packet data (if present)
```

---

## Why the Client Might Not Send Group Requests

If the server sees index downloads complete but no group requests follow, possible causes:

### Most Likely: Index Processing Failure (Cause #3)

1. **`indexDownloadState` never reaches 3 (READY)**: The vtable call `IndexReady` (vtable+0x10) must return the READY sentinel (`&<in Ghidra DB>`). If index processing fails after download, `FileReady_CheckIndex` returns before ever calling `FileReady`. This is the most likely cause — the server sends index data, the client downloads it, but the index parsing/validation fails silently.

### Other Possible Causes

2. **Index data is malformed**: If the index data the server sends is corrupt or has wrong format, the Js5Index may fail to parse, preventing `DoesFileExist` from returning true. Or the index loads but with wrong group counts, so no groups appear valid.

3. **Js5Index CRC/version mismatch**: In `RequestGroupFromDisk` for index requests (groupId=-1), there's extensive CRC/version validation against the master index. If this fails, the index may not be properly loaded, or the index download state may be set to 2 (failed) rather than 3 (ready).

4. **No game systems requesting files**: The entire flow is demand-driven. If no game system calls `FileReady_CheckIndex`, no requests are generated. The client only requests files when it needs them (e.g., entering lobby needs interface definitions, login needs certain configs). However, after a successful login, the client should immediately request interface, config, and other essential data — so this is unlikely if login progresses.

5. **Disk cache thread stuck or not started**: If `Js5DiskCache::Startup` wasn't called or the worker thread isn't running, enqueued requests are never processed, results never come back, and the flow stalls. The non-blocking path returns "LOADING" but never transitions.

6. **The retry flag is not set**: In `ProcessDownloadResults`, the fallthrough to `RequestGroupFromServer` only happens if `piVar7[0x15] != 0`. If the disk cache result struct doesn't have this flag set, the request is simply dropped — no TCP request is ever sent.

7. **`archiveDatabaseState` not initialized**: If `Js5DiskCache::Startup` didn't set the database state for an archive (e.g., no database file exists and none was created), `ThreadWorkLoop` skips that archive entirely. Requests are enqueued but never processed.
