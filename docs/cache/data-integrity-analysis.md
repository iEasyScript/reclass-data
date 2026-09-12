# Cache Data Integrity Analysis

Date: 2026-03-11
Tool: `CacheIntegrityCheck.kt`
Cache path: `./data/cache/`

## Summary

**ALL 539,779 containers passed integrity validation.** No corrupted, truncated, or mismatched data was found across all 45 indices.

## Validation Results

### Overall Statistics

| Metric | Count |
|--------|-------|
| Total containers checked | 539,779 |
| OK | 539,779 |
| Truncated | 0 |
| Oversized (extra bytes) | 0 |
| Bad compression type | 0 |
| Decompression failed | 0 |
| CRC mismatch (vs ref table) | 0 |
| Too small (< 5 bytes) | 0 |

### Per-Index Breakdown

All indices passed with zero errors:

| Index | Groups | Status |
|-------|--------|--------|
| 1 (underlays) | 5,301 | ALL OK |
| 2 (configs) | 39 | ALL OK |
| 3 (interfaces) | 1,874 | ALL OK |
| 5 (maps) | 8,315 | ALL OK |
| 8 (graphics) | 35,530 | ALL OK |
| 10 (huffman) | 1 | ALL OK |
| 12 (clientscript) | 20,664 | ALL OK |
| 13 (fontmetrics) | 60 | ALL OK |
| 14 (vorbis) | 59,133 | ALL OK |
| 16 (worldmapdata) | 531 | ALL OK |
| 17 (dbindex) | 69 | ALL OK |
| 18 (dbrows) | 255 | ALL OK |
| 19 | 236 | ALL OK |
| 20 | 295 | ALL OK |
| 21 | 36 | ALL OK |
| 22 | 1,651 | ALL OK |
| 23 | 5 | ALL OK |
| 24 | 2 | ALL OK |
| 26 | 1 | ALL OK |
| 27 | 2 | ALL OK |
| 28 (quickchat) | 11 | ALL OK |
| 29 | 1 | ALL OK |
| 32 | 11 | ALL OK |
| 33 | 3 | ALL OK |
| 34 | 11 | ALL OK |
| 35 | 54 | ALL OK |
| 40 (music) | 85,059 | ALL OK |
| 41 | 764 | ALL OK |
| 42 | 136 | ALL OK |
| 47 (models) | 139,406 | ALL OK |
| 48 (frames) | 33,439 | ALL OK |
| 49 | 237 | ALL OK |
| 52 (textures-dds) | 35,550 | ALL OK |
| 53 (textures-png) | 35,550 | ALL OK |
| 54 (textures-bmp) | 35,499 | ALL OK |
| 55 (textures-ktx) | 35,550 | ALL OK |
| 56 (skeletalAnims) | 2,743 | ALL OK |
| 57 (achievements) | 39 | ALL OK |
| 58 | 225 | ALL OK |
| 59 | 5 | ALL OK |
| 60 | 319 | ALL OK |
| 61 | 1,106 | ALL OK |
| 62 | 7 | ALL OK |
| 65 | 2 | ALL OK |
| 66 | 8 | ALL OK |

### Archive Indices (255/N)

All 45 archive reference tables (stored in `js5-255.jcache`) also validated successfully. Headers are consistent, compression types valid (BZIP2, GZIP, LZMA used across indices), and all decompress without error.

### Priority Archives (28, 59, 62)

These are the first archives the NXT client requests after receiving the master index:

- **Index 28** (quickchat): 11 groups, mix of uncompressed (comp=0) and GZIP (comp=2). All OK.
- **Index 59**: 5 groups, GZIP and BZIP2. Largest is 213,911 bytes. All OK.
- **Index 62**: 7 groups, all BZIP2 compressed. All OK.

## Version Suffix Analysis

**Finding: The cache downloader does NOT store a 2-byte version suffix.**

| Category | Count |
|----------|-------|
| Containers with 0 extra bytes | 539,779 |
| Containers with 2 extra bytes (version suffix) | 0 |
| Containers with other extra bytes | 0 |

### Data Flow Details

The version suffix question is critical for understanding CRC behavior. Here is the complete data flow:

#### 1. Wire Format (Jagex JS5 Response)

The NXT JS5 protocol sends:
```
[index(1)][hash(4)][compression(1)][compressedSize(4BE)]  -- 10-byte response header
[payload: decompSize(4, if compressed) + compressed_data]
```
This is framed in 102,400-byte blocks with 5-byte continuation headers.

In old RS2/OSRS, the wire format appended a 2-byte version suffix AFTER the container payload. The NXT protocol does NOT include this suffix on the wire.

#### 2. Cache Downloader Storage

The downloader (`JS5Connection.receiver` and `JS5Protocol.readResponse`) reconstructs the container as:
```
container = [compression(1)][compressedSize(4BE)][payload]
```
Where payload = `decompressedSize(4, if compressed) + compressed_data`.

The container is stored in SQLite via `IndexFile.putRaw` exactly as reconstructed -- no version suffix added.

#### 3. Server FileProvider

`FileProvider.data(index, archive)` returns the raw SQLite blob via `cache.sector` -> `IndexFile.getRaw`.

`FileProvider.serve` builds the JS5 response by:
- Extracting compression and compressedSize from the first 5 bytes of stored data
- Writing a 10-byte response header (index + hash + compression + compressedSize)
- Copying the payload (bytes 5+) from stored data
- NO version suffix is appended

#### 4. CRC Computation

- **Master index CRCs** (for archive indices): Computed by `VersionTableBuilder.sector` over the ENTIRE raw ref table blob (`IndexFile.getRawTable`). This matches what `sector(255, indexId)` returns.
- **Ref table CRCs** (for group data): Stored in the decompressed ref table. These are the CRCs Jagex computed, presumably over `container_data - 2_bytes` in older protocols. Since NXT does not include a version suffix, and our downloader stores no suffix, `CRC.calculate(stored_data)` matches the ref table CRC directly.

### Conclusion on Version Suffix

The NXT JS5 protocol (rev 946) does not use a 2-byte version suffix. The CRC stored in the archive ref table is computed over the full container (header + payload), which is exactly what we store. This is confirmed by the 100% CRC match rate across all 539,779 containers.

## Implications for Serving

Since all containers are valid and CRC-consistent:
1. The `FileProvider` can serve stored data as-is without modification
2. No version suffix stripping or addition is needed
3. The master index CRCs (computed at server startup by `VersionTableBuilder`) will match what the client computes when it downloads archive indices
4. Group CRCs from the ref table will match what the client computes when it downloads individual groups

## Tool Usage

```bash
./gradlew :tools:run -PmainClass=org.projectx.tools.CacheIntegrityCheckKt
```

Runtime: ~12 minutes (processes 539K containers across 46 SQLite databases).
