# Js5MemoryCache Write Path — RE Documentation

**Binary**: rs2client (rev 946, stripped)
**Verified against**: rs2client via Ghidra MCP (port 8080)
**Date**: 2026-03-11

## Overview

This document traces the complete JS5 data path from download completion to MemoryCache storage, with focus on the hash table implementation that causes SIGSEGV crashes due to corrupted bucket pointers.

---

## 1. Crash Stack Trace Analysis

The crash stack trace (bottom to top):

| Address | Function | Role |
|---------|----------|------|
| `<in Ghidra DB>` | `_start` | CRT entry, calls `__libc_start_main(<in Ghidra DB>, ...)` |
| `<in Ghidra DB>` | N/A (no function found) | Likely inside libc `__libc_start_main` |
| `<in Ghidra DB>` | N/A (no function found) | Likely inside libc `__libc_start_main` |
| `<in Ghidra DB>` | `<in Ghidra DB>` (main) | SDL main loop — calls `jag::Client::MainLogic` via vtable `*this + 0xf8` |
| `<in Ghidra DB>` | `<in Ghidra DB>` (game tick loop) | Frame tick dispatcher — calls `(*vtable+0xf8)(this, isLastTick)` repeatedly |
| `<in Ghidra DB>` | `jag::Client::MainLogic` | Client main logic — calls `Js5WorkerThread::Js5WorkerThread`, then game systems |
| `<in Ghidra DB>` | `jag::ConnectionManager::LoginProtocolHandler` | Login protocol state machine — very large function |
| `<in Ghidra DB>` | `<in Ghidra DB>` | Scene/resource loading — calls `FileReady`, `FileReady_CheckIndex`, `EvictEntry` |
| `<in Ghidra DB>` | `<in Ghidra DB>` | Resource loader — calls `FileReady_CheckIndex`, `GetFileInternal` via vtable, `EvictEntry` |

### Crash Path Summary

```
_start
  → main (<in Ghidra DB>) — SDL_Init, creates Client object, enters event loop
    → game tick (<in Ghidra DB>) — frame timing, calls MainLogic via vtable
      → Client::MainLogic (`<in Ghidra DB>`) — initializes Js5WorkerThread, runs game systems
        → LoginProtocolHandler (`<in Ghidra DB>`) — login state machine
          → <in Ghidra DB> (`<in Ghidra DB>`) — scene/resource loading
            → <in Ghidra DB> (`<in Ghidra DB>`) — individual resource file loading
              → FileReady_CheckIndex → LookupGroup → SIGSEGV
```

---

## 2. Js5MemoryCache Constructor (`<in Ghidra DB>`)

```
void Js5MemoryCache_ctor(long this, ulong initialCapacity)
```

### Layout (confirmed from decompile)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `+0x08` | 8 | `bucketArray` | Pointer to hash bucket array (each bucket is 8 bytes — a pointer to first entry) |
| `+0x10` | 8 | `bucketCount` | Number of hash buckets (initially computed from capacity) |
| `+0x18` | 8 | `(unused/zero)` | Zeroed on init |
| `+0x20` | 8 | `loadFactor + bucketCount` | Packed: `<in Ghidra DB>`3f800000 → load factor (float 1.0 at low 32 bits) + bucket count (u32 at high 32 bits) |
| `+0x28` | 4 | `entryCount` | Number of entries in the hash table |
| `+0x30..+0x48` | 24 | Pool allocator fields | Slab/pool allocator for hash entries |

### Initialization Logic

```c
if (initialCapacity > 1) {
    bucketCount = <in Ghidra DB>(this + 0x20);  // compute prime bucket count
    allocSize = bucketCount * 8;
    if (allocSize + 8 < 0x8011) {
        bucketArray = *(this + 0x60);   // use pool allocator
    } else {
        bucketArray = HeapInterface::Alloc8(allocSize + 8);
    }
    memset(bucketArray, 0, allocSize);           // ZERO all buckets
    *(bucketArray + allocSize) = 0xFFFFFFFFFFFFFFFF;  // sentinel at end
    this->bucketArray = bucketArray;
} else {
    this->bucketCount = 1;
    this->bucketArray = &<in Ghidra DB>;  // static single-bucket
}
```

**Key finding**: The constructor properly zeroes the bucket array via `memset`. The sentinel value `0xFFFFFFFFFFFFFFFF` is placed at `bucketArray[bucketCount]` (one past the last bucket). This sentinel is used by `EvictEntry` to find the next non-null bucket.

---

## 3. Hash Table Entry Layout

Each entry in the hash table is 9 quadwords (72 bytes):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `+0x00` | 8 | `key` | Hash key = `(groupId << 8) \| archiveId` |
| `+0x08` | 8 | `sharedPtr_controlBlock` | shared_ptr control block (ref-counted) |
| `+0x10` | 8 | `sharedPtr_dataPtr` | shared_ptr data pointer (Packet with decompressed data) |
| `+0x18` | 8 | `originalKey` | Copy of key (used in LRU tracking) |
| `+0x20` | 4 | `dataSize` | Size of the cached data |
| `+0x28` | 8 | `lruEpoch` | LRU epoch/generation counter |
| `+0x30` | 8 | `lruPrev` | LRU doubly-linked list — pointer to previous node (+0x08 of prev entry) |
| `+0x38` | 8 | `lruNext` | LRU doubly-linked list — pointer to next node (+0x08 of next entry) |
| `+0x40` | 8 | `nextInBucket` | Singly-linked list — next entry in same hash bucket |

### Hash Function

```
key = (groupId << 8) | archiveId
bucketIndex = key % bucketCount
```

The bucket array is an array of pointers. `bucketArray[bucketIndex]` points to the first entry in that bucket's chain. Entries are chained via `entry[8]` (offset +0x40, the `nextInBucket` field).

---

## 4. Js5MemoryCache::LookupGroup (`<in Ghidra DB>`)

```
long LookupGroup(Js5MemoryCache* this, ulong archiveId, uint groupId, uint js5Index)
```

### Algorithm

1. Compute `key = groupId << 8 | archiveId`
2. Compute `bucketIndex = key % (*(this + 0x20) & 0xFFFFFFFF)`
3. Walk the bucket chain: `entry = *(bucketArray + bucketIndex * 8)`
4. For each entry, compare `entry[0]` (the key) to `key`
5. On match: promote entry in LRU list (move to head), then validate CRC/version against `js5Index`
6. On no match: return pointer to static "not found" object at `<in Ghidra DB>`

### Critical Pointer Dereference (CRASH SITE)

```c
puVar1 = *(ulong **)(*(long *)(this + 0x18) + (key % (*(ulong *)(this + 0x20) & 0xffffffff)) * 8);
```

This loads `bucketArray[bucketIndex]`. If the bucket contains a non-null garbage pointer (not properly zeroed), the next line dereferences it:

```c
if (key == *puVar1)  // SIGSEGV here if puVar1 is garbage
```

### LRU Promotion on Hit

When a cache hit is found, the entry is moved to the head of the LRU list:
```c
// Unlink from current position
entry[6] → +0x30 = entry[7]   // prev.next = next
entry[7] → +0x28 = entry[6]   // next.prev = prev

// Insert at head
entry[5] = *(this + `<in Ghidra DB>`)   // epoch
entry[7] = *(uVar2 + 0x30)     // next = head.next
*(head.next + 0x28) = &entry[1] // head.next.prev = us
*(uVar2 + 0x30) = &entry[1]    // head.next = us
entry[6] = uVar2                // prev = head
```

### CRC/Version Validation

After finding a cached entry, LookupGroup validates the stored CRC and version against the current Js5Index. If they don't match (index was updated), it calls `EvictEntry` to remove the stale data.

---

## 5. Js5MemoryCache::ProvideGroup (`<in Ghidra DB>`)

```
long* ProvideGroup(long memoryCache, uint archiveId, ulong groupId, uint version, uint crc, long* packet)
```

This is the **write path** — called when downloaded data needs to be stored in the memory cache.

### Algorithm

1. **Allocate wrapper**: `<in Ghidra DB>(local_68, 0x38, 0)` — allocates a 0x38-byte object for the cache entry wrapper. Stores `version` at `+0x24`, `crc` at `+0x20`, and the Packet shared_ptr data.

2. **Compute key**: `key = (groupId << 8) | archiveId`

3. **Evict existing**: `EvictEntry(memoryCache + 8, key)` — remove any existing entry with same key.

4. **Update size counter**: `memoryCache[0x0c] -= dataSize` — decrement remaining capacity.

5. **Evict LRU if over capacity**: While `memoryCache[0x0c] < 0` (capacity exceeded):
   - Remove the LRU tail entry from the hash table
   - Add its data size back to the capacity counter
   - Walk the bucket chain to unlink it

6. **Insert new entry**:
   - Check if key already exists in the bucket chain
   - If not found, may **rehash** (grow the bucket array):
     ```c
     newBucketCount = <in Ghidra DB>(memoryCache + 0x30, oldBucketCount, entryCount, 1);
     newBuckets = HeapInterface::Alloc8(newBucketCount * 8 + 8);
     memset(newBuckets, 0, newBucketCount * 8);
     // Rehash all existing entries into new buckets
     for each old bucket:
         for each entry in bucket chain:
             newBucket = entry.key % newBucketCount
             entry.nextInBucket = newBuckets[newBucket]
             newBuckets[newBucket] = entry
     ```
   - Allocate new entry node via `<in Ghidra DB>` (72 bytes)
   - Zero all fields
   - Insert at head of bucket chain:
     ```c
     entry->nextInBucket = bucketArray[bucketIndex]
     bucketArray[bucketIndex] = entry
     entryCount++
     ```

7. **Store data in entry**:
   - `entry[1] = sharedPtr_controlBlock`
   - `entry[2] = sharedPtr_dataPtr`
   - `entry[3] = key`
   - `entry[4] = dataSize` (as int)
   - `entry[5] = epoch`
   - Insert into LRU linked list at head

### Potential Corruption Vectors

**A. Rehash race condition**: The rehash loop iterates all old buckets and re-inserts entries into new buckets. If another thread accesses the hash table during rehash, it will see partially-migrated state. However, ProvideGroup is called from the **main thread** (via ProcessDownloadResults), so this should be single-threaded.

**B. Double-insert on key collision**: If `EvictEntry` fails to remove an existing entry (e.g., due to the sentinel check — see EvictEntry analysis), then ProvideGroup will find the old entry at `<in Ghidra DB>` and overwrite its data fields. This path looks safe.

**C. Stale bucket pointers after rehash**: After rehash, `memoryCache + 0x18` (bucket array pointer) and `memoryCache + 0x20` (bucket count) are updated. Any cached local copies of these values would be stale. In ProvideGroup itself this is handled (it re-reads after rehash), but concurrent readers would see partial state.

---

## 6. Js5MemoryCache::EvictEntry (`<in Ghidra DB>`)

```
ulong EvictEntry(int* cacheObj, ulong key)
```

### Algorithm

1. Compute `bucketIndex = key % (cacheObj[6] & 0xFFFFFFFF)`
2. Load `firstEntry = *(cacheObj[4] + bucketIndex * 8)` — first entry in bucket
3. Walk the chain looking for `entry.key == key`
4. **Sentinel check**: If the matching entry equals `*(cacheObj[4] + cacheObj[6] * 8)` (the sentinel slot), **return without evicting**. This prevents removing the sentinel.
5. Update capacity: `cacheObj[1] += entry[4]` (add data size back)
6. Unlink from LRU: `entry[6]→+0x30 = entry[7]; entry[7]→+0x28 = entry[6]`
7. Unlink from bucket chain (singly-linked — find predecessor)
8. DecRef the shared_ptr if present
9. Free or recycle the entry node
10. Decrement `cacheObj[8]` (entry count)

### Layout of cacheObj (EvictEntry's `this`)

Note: EvictEntry takes `int*` — the `cacheObj` is at `memoryCache + 8` (the hash table sub-object). So offsets here are relative to `memoryCache + 8`:

| Offset (int*) | Byte offset from memoryCache | Field |
|----------------|------------------------------|-------|
| `cacheObj[0]` | `+0x08` | flags/mode (0 = disabled, nonzero = enabled) |
| `cacheObj[1]` | `+0x0C` | remainingCapacity (int) |
| `cacheObj[4]` (long) | `+0x18` | bucketArray pointer |
| `cacheObj[6]` (long) | `+0x20` | bucketCount |
| `cacheObj[8]` (long) | `+0x28` | entryCount |
| `cacheObj[0x0e]` | `+0x38..` | Pool/slab allocator |
| `cacheObj[0x1a]` | `+0x68..` | Pool range start |

---

## 7. Js5ResourceProvider::ProcessDownloadResults (`<in Ghidra DB>`)

```
void ProcessDownloadResults(long this)
```

Called from the **main thread** to drain the download result queue.

### Algorithm

1. **Lock mutex** at `this + 0x6d2c`
2. **Swap out** the result queue: take the list pointers (`this + 0x6d54`, `this + 0x6d5c`) and zero them
3. **Unlock mutex**
4. **Iterate** each result entry (stride = 0x0e int-sized fields = 56 bytes per entry):
   - `result[0]` = type (0 = success, other = failure)
   - `result[1]` = archiveId
   - `result[2]` = groupId
   - `result[3]` = version
   - `result[4]` = crc
   - `result[5]` = priority (byte at offset 0x14)
   - `result[7]` = sub-type (1 = call HandleDownloadResult, else = re-request)
   - `result[8..13]` = packet data
5. For type 0 (success):
   - If sub-type == 1: call `HandleDownloadResult(this[0x6724], archiveId, groupId, packetData, crc, version, priority, ...)`
   - Else: re-request via `RequestGroupFromServer`
   - Decrement priority counter at `this + 0xd28 + priority * 4`
   - Remove from pending request tree
6. Free heap allocations in result entries

### Thread Safety

The mutex protects only the queue swap. The actual processing (including HandleDownloadResult which calls ProvideGroup) happens **outside** the lock, on the main thread. This is safe as long as only the main thread calls LookupGroup/ProvideGroup.

---

## 8. Js5ResourceProvider::HandleDownloadResult (`<in Ghidra DB>`)

```
void HandleDownloadResult(long this, uint archiveId, uint groupId,
    undefined8 packetData, uint crc, uint version, byte priority,
    char isIndexRequest, char isRetry, char isMasterIndex)
```

### Two paths:

**A. Index download (groupId == 0xFFFFFFFF)**:
- Decompresses the index data
- Validates CRC against stored expected CRC
- Calls `Js5Index::LoadIndex` to parse the index
- Calls `Js5Index::MoveAssign` to install the new index
- Sets archive state to 3 (ready)

**B. Group download (isIndexRequest != 0)**:
- Wraps the packet data in a shared_ptr cache entry
- Calls **`Js5MemoryCache::ProvideGroup(this[0x88/8], archiveId, groupId, version, crc, packet)`**
- This is the actual write to the memory cache

Note: `this[0x88/8]` = `this + 0x88` is the offset to the `Js5MemoryCache*` within the Js5ResourceProvider. Cross-referencing with FileReady which uses `this[0x11]` (= `this + 0x88`), this is consistent.

---

## 9. Js5ResourceProvider::FileReady (`<in Ghidra DB>`)

```
undefined* FileReady(long* this, long* outPacket, uint* archiveSettings,
    uint groupId, uint fileId, byte priority, char urgent, char param_8, char param_9)
```

### Flow

1. Check `Js5Index::DoesFileExist` for the archive
2. Try `Js5MemoryCache::GetFileInternal(this[0x11], ...)` — if cached, return immediately
3. If not cached, try `GetFile_ArchiveGroup` (disk cache)
4. If not on disk either, enter a **spin loop**:
   ```c
   do {
       ProcessDownloadResults(this[0x12]);   // drain download queue
       result = GetFileInternal(this[0x11], ...);  // check cache again
   } while (result != READY && download_still_pending);
   ```
5. If still not available, call `RequestGroupFromServer`

**Key insight**: `this[0x11]` = Js5MemoryCache pointer, `this[0x12]` = Js5Net/downloader object.

---

## 10. Js5MemoryCache::GetFileInternal (`<in Ghidra DB>`)

```
undefined* GetFileInternal(long memoryCache, long* outPacket, uint archiveId,
    uint groupId, uint fileId, long js5Index, char markAccessed)
```

1. Calls `LookupGroup(memoryCache, archiveId, groupId, js5Index)` — **this is the crash site**
2. If `*(result + 8) == 0` (not found), return LOADING status
3. If found and single-file group: return the cached Packet directly
4. If multi-file group: use `Js5Index::RemapFileId` to find file offset, extract sub-range

---

## 11. Crash-Path Functions in Detail

### <in Ghidra DB> (`<in Ghidra DB>`) — Resource File Loader

This function loads individual resource files (textures, models, etc.). It:

1. Calls `(*vtable + 0x20)(resourceProvider, outPacket, ...)` — which resolves to `FileReady` or `FileReady_CheckIndex`
2. On success, processes the loaded data (sets flags, copies to render targets)
3. Calls `EvictEntry` to release memory cache entries after consumption
4. Contains the call at `<in Ghidra DB>` that leads to the crash

### <in Ghidra DB> (`<in Ghidra DB>`) — Scene/Resource Batch Loader

Very large function (~61K chars decompiled). Handles batch loading of scene resources. Calls into the resource file loader (<in Ghidra DB>) and manages resource state tracking.

### Js5ResourceProvider::FileReady_WithCheck (`<in Ghidra DB>`)

A simpler variant of FileReady:
1. Check index readiness via `(*vtable + 0x10)`
2. Check `DoesFileExist`
3. Call `LookupGroup` directly (not GetFileInternal)
4. If not cached, request from server

This also calls `LookupGroup` and can trigger the crash.

---

## 12. The Corruption Theory

### What we know:

1. The constructor at `<in Ghidra DB>` **properly zeroes** the bucket array
2. The crash happens in `LookupGroup` when dereferencing a bucket entry pointer
3. The crash occurs during gameplay resource loading (scene loading, not during initial JS5 bootstrap)

### Most likely corruption scenarios:

**Scenario A: Uninitialized memory from pool allocator**

In `ProvideGroup`, new entries are allocated via `<in Ghidra DB>`. After allocation, all 9 quadwords are explicitly zeroed. However, during **rehash**, entries are moved between buckets without zeroing. If the pool allocator returns memory from a previously-freed entry that was only partially zeroed, the `nextInBucket` field (`entry[8]`) could contain a stale pointer.

**Scenario B: LRU list corruption leading to bucket corruption**

The LRU linked list uses offsets `entry + 0x08` (entry[1]) as the list node address, with prev/next at `entry[6]` (+0x30) and `entry[7]` (+0x38). If a `DecRef` frees an entry's shared_ptr control block at `entry[1]` while the entry is still in the LRU list, subsequent LRU operations could corrupt memory that overlaps with bucket array storage.

**Scenario C: Concurrent access from worker thread**

`Js5WorkerThread::GroupDownloaded` (`<in Ghidra DB>`) processes downloaded data on the **worker thread**. It computes CRC, validates integrity, then sends a response to the main thread. However, if any code path in the worker thread directly touches the MemoryCache (unlikely based on current analysis — the worker thread uses a mutex-protected queue), corruption could occur.

**Scenario D: Our server sending malformed data that triggers edge cases**

If the server sends:
- Wrong CRC values → `LookupGroup` validation fails → `EvictEntry` called → safe
- Wrong version → same as above
- Corrupt container data → decompression fails → `FailGetGroupResponse` called → safe
- **Empty or zero-length containers** → could cause issues in `ProvideGroup` if `dataSize` is 0, leading to capacity calculations going wrong
- **Very large dataSize values** → could cause `remainingCapacity` to go extremely negative, triggering excessive LRU eviction that could race with ongoing lookups

### Recommendation

The patcher's LookupGroup trampoline (validating RDX pointer range before dereference) is a correct mitigation. To find the root cause, instrument `ProvideGroup` to log every write to the bucket array, tracking when a non-zero value first appears in a bucket that should be zero.

---

## 13. Key Function Address Summary

| Address | Name | Thread | Touches MemoryCache? |
|---------|------|--------|---------------------|
| `<in Ghidra DB>` | Js5MemoryCache constructor | Main | Yes — initializes |
| `<in Ghidra DB>` | Js5MemoryCache::LookupGroup | Main | Yes — reads buckets (CRASH SITE) |
| `<in Ghidra DB>` | Js5MemoryCache::GetFileInternal | Main | Yes — calls LookupGroup |
| `<in Ghidra DB>` | Js5MemoryCache::ProvideGroup | Main | Yes — writes buckets, rehashes |
| `<in Ghidra DB>` | Js5MemoryCache::EvictEntry | Main | Yes — removes from buckets |
| `<in Ghidra DB>` | ProcessDownloadResults | Main | No — calls HandleDownloadResult |
| `<in Ghidra DB>` | HandleDownloadResult | Main | Yes — calls ProvideGroup |
| `<in Ghidra DB>` | FileReady | Main | Yes — calls GetFileInternal, ProcessDownloadResults |
| `<in Ghidra DB>` | FileReady_WithCheck | Main | Yes — calls LookupGroup directly |
| `<in Ghidra DB>` | Js5WorkerThread::GroupDownloaded | Worker | No — CRC check, queues result |
| `<in Ghidra DB>` | Js5WorkerThread::IndexDownloaded | Worker | No — CRC check, queues result |
| `<in Ghidra DB>` | Resource file loader | Main | Yes — calls FileReady, EvictEntry |
| `<in Ghidra DB>` | Scene resource batch loader | Main | Indirectly — calls resource loader |
| `<in Ghidra DB>` | Game tick loop | Main | No — calls MainLogic |
| `<in Ghidra DB>` | Client::MainLogic | Main | Indirectly — runs game systems |
| `<in Ghidra DB>` | LoginProtocolHandler | Main | Indirectly — triggers resource loads |
| `<in Ghidra DB>` | main (SDL) | Main | No — event loop |

---

## 14. MemoryCache Sub-Object Layout (Full)

The MemoryCache is accessed at different offsets depending on context:

- From `Js5ResourceProvider`: `this[0x11]` = `*(this + 0x88)` = pointer to MemoryCache
- `EvictEntry` takes `memoryCache + 0x08` as its `this` pointer (the hash table sub-object)
- `ProvideGroup` takes the full `memoryCache` base address

### Full layout from constructor + ProvideGroup + EvictEntry:

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| `+0x00` | int | mode/flags | 0 = cache disabled |
| `+0x04` | (pad) | | |
| `+0x08` | long* | bucketArray | Pointer to array of bucket head pointers |
| `+0x0C` | int | remainingCapacity | Starts at max, decremented on insert |
| `+0x10` | long | (internal) | |
| `+0x18` | long* | bucketArray (EvictEntry view) | Same as +0x08, different offset due to sub-object |
| `+0x20` | ulong | bucketCount (packed) | Low 32 bits = count, high 32 bits = load factor |
| `+0x28` | long | entryCount | Number of entries in hash table |
| `+0x30..+0x60` | | Pool allocator | Slab allocator for entry nodes |
| `+0x68` | long* | poolRangeStart | For determining if entry is in pool |
| `+0x70` | long* | poolSentinel/freeList | Pool free list head or sentinel entry |

**IMPORTANT NOTE ON OFFSET CONFUSION**: The code uses two different "views" of the MemoryCache:
- `ProvideGroup` receives `memoryCache` (the full object base)
- `EvictEntry` receives `memoryCache + 8` (casted to `int*`)
- So `cacheObj[4]` in EvictEntry (= `(int*)(memoryCache+8) + 4` = `memoryCache + 0x18`) corresponds to `*(memoryCache + 0x18)` = bucketArray
- And `cacheObj[6]` (= `memoryCache + 0x20`) = bucketCount

This dual-view is consistent: ProvideGroup accesses `*(memoryCache + 0x18)` for bucketArray and `*(memoryCache + 0x20)` for bucketCount, matching EvictEntry's `cacheObj[4]` and `cacheObj[6]`.
