# JS5 HTTP Transport — Music & Bulk Data Downloads

## Overview

The NXT client uses **two parallel transport mechanisms** for JS5 cache data:

1. **TCP (Js5NetQueue)** — The standard JS5 TCP connection used for most archives. Requests flow through the persistent JS5 socket with 5-byte headers and 512-byte chunked responses.
2. **HTTP (Js5HTTPQueue)** — An HTTP-based fallback/alternative transport used for specific archives. Requests are standard HTTP GET requests to a content server.

Both transports are managed by `jag::Js5WorkerThread`, which maintains a `Js5NetQueue` at `this+0x1b0` (offset 0x36 in longs) and a `Js5HTTPQueue` at `this+0x1b8` (offset 0x37). The choice between them is made **per-request** based on a flag in the archive settings.

## Which Archives Use HTTP?

The routing decision happens in `jag::Js5WorkerThread::OnMessage` (case 0x1e — group request). The request message includes a byte field (`local_409` / offset 0x31 in the request struct) that acts as a boolean:

- **`local_409 == 0`** → Route to `Js5NetQueue::RequestData` (TCP)
- **`local_409 != 0`** → Route to `Js5HTTPQueue::RequestData` (HTTP)

This flag comes from the archive settings at offset `0x0e` of the per-archive config struct (the `archiveSettings` parameter in `RequestGroupFromServer`, stored as `*(byte *)(archiveSettings + 0xe)`). The flag is set when the archive is registered in the `Js5ResourceProvider`.

Based on observed behavior with the live Jagex servers:

- **Index 40 (music/audio)** — HTTP transport. This index is NOT served over the JS5 TCP connection (confirmed by the cache downloader failing to get it via TCP).
- **All other standard indices** — TCP transport.

The master index (archive=0xFF, group=0xFF) can also be requested over HTTP. `Js5WorkerThread::OnMessage` case 0x28 handles `RequestMasterIndexOverHTTP`, calling `Js5HTTPQueue::RequestData(archive=0xFF, group=0xFF, version=0, checksum=0, requestType=0, priority=1, ...)`.

## HTTP URL Format

### URL Pattern

The URL is constructed in `<in Ghidra DB>` (the HTTP request builder, called from `ConnectionManager::MainLogic`):

```
%s/ms?m=0&a=%u&k=%d&g=%u&c=%d&v=%d
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `%s` (base) | string | The JS5 content server base URL (from `ChangeURLs` fallback URL) |
| `m` | int | Always `0` — likely a "mode" or "method" identifier |
| `a` | uint | **Archive ID** (index number, e.g., 40 for music) |
| `k` | int | **Key/priority** — from request field at offset `0x30` (the `requestType` parameter from `Js5HTTPQueue::RequestData`) |
| `g` | uint | **Group ID** (file within the archive) |
| `c` | int | **Checksum** (CRC32 of the expected data) |
| `v` | int | **Version** of the group |

### Example URLs

For music archive (index 40), group 1234, with checksum `<in Ghidra DB>` and version 5:
```
http://content.runescape.com/ms?m=0&a=40&k=0&g=1234&c=-1412567295&v=5
```

For master index over HTTP:
```
http://content.runescape.com/ms?m=0&a=255&k=0&g=255&c=0&v=0
```

Note: The `c` parameter is a **signed int** (`%d`), so CRC values above 0x7FFFFFFF will appear as negative numbers.

### Base URL Source

The base URL (`%s`) comes from the fallback URL stored in the `Js5WorkerThread`. In `ChangeURLs(primaryURL, fallbackURL)`:

- `primaryURL` → stored at `this+0x1f0` (offset 0x3e) — used for TCP connections
- `fallbackURL` → stored at `this+0x1d8` (offset 0x3b) — used as the HTTP base URL for `Js5HTTPQueue`

The `CreateQueues` function passes the fallback URL to the `Js5HTTPQueue` constructor. The fallback URL is the second string read from the initialization message (case 2 in `OnMessage`), which originates from `jav_config.ws`.

From `jav_config.ws`, the relevant parameter is typically:
```
param=33=http://content.runescape.com
```
or similar content server URL.

## HTTP Request Construction

### Request Object (`Js5HTTPQueue::RequestData`)

The function signature (from Ghidra):
```c
int Js5HTTPQueue::RequestData(
    long this,
    uint archiveId,       // Archive/index number
    uint groupId,         // Group/file within the archive
    uint version,         // Expected version
    uint checksum,        // Expected CRC32
    uint requestType,     // Request type (used as 'k' param)
    int priority,         // Internal priority value
    long callback,        // Success callback (std::function)
    long netCallback,     // Network callback (std::function)
    long packet,          // Pre-built packet data (moved into request)
    uint timeout,         // Request timeout value
    byte priorityEnum     // Priority enum (urgent=2, prefetch=0)
)
```

The request is enqueued into a sorted list at `this+0x18`. The sort key is `(groupId << 8) | archiveId`, ensuring requests are processed in a deterministic order.

### Capacity Limit

The HTTP queue has a maximum of **20 concurrent requests** (`0x14`). Before enqueuing, the code checks:
```
active_slots + pending_requests < 0x14
```
where `active_slots` counts non-null entries in the slot array at `this+0x48`, and `pending_requests` counts entries in the sorted list at `this+0x18`. If the queue is full, `RequestData` returns 0 (failure), and the caller retries later.

### HTTP Execution

The URL is built by `<in Ghidra DB>` which calls `<in Ghidra DB>` to initiate the HTTP request. This function:
1. Sets the request state to `3` (in-progress)
2. Copies the URL string into the request object at offset `+0x8`
3. Copies a "Content-Type" hint string (typically empty `""` for GET requests) at offset `+0x268`
4. Submits the request to a thread pool singleton (`<in Ghidra DB>`, a `TPSingleton` with `min(hardware_concurrency, 16)` threads)

The actual HTTP request uses **libcurl** (statically linked into the binary). Evidence:
- `User-Agent` and `Host:` format strings are present
- Cookie file format string: `"# Netscape HTTP Cookie File"`
- Standard libcurl multi-part form handling code

### Response Handling

In `ConnectionManager::MainLogic`, completed HTTP responses are polled from the slot array. For each completed request:

1. The `Content-Type` header is checked against `"application/octet-stream"` using `<in Ghidra DB>` (string comparison)
2. If the content type matches, the response body is treated as raw JS5 container data
3. The success callback is invoked with the archive ID, group ID, and response data
4. If the content type does NOT match (or the request failed with HTTP error), the failure callback is invoked

## Response Data Format

The HTTP response body is a **standard JS5 container** — the same format used for TCP responses, but **without the TCP framing** (no 512-byte chunks, no 0xFF separators, no prefetch/urgent marker bytes).

### CRC Verification

In `Js5WorkerThread::GroupDownloaded`, the response data undergoes CRC32 verification:

1. The first 5 bytes are skipped (read position advanced by 5 — the compression header: 1 byte type + 4 bytes compressed size)
2. A 4-byte CRC32 is read from the response
3. The CRC32 of the remaining data (after the initial 2-byte skip, length = `dataLength - 2`) is computed
4. If the computed CRC does not match the expected CRC, `FailGetGroupResponse` is called

### Encryption Flag

A flags byte is read after the CRC:
- **Bit 0** — If set, the data contains XTEA-encrypted content (requires key exchange)
- **Bit 1** — If set, use "type 2" processing (the response is forwarded with additional key data)

For XTEA-encrypted responses (flags & 2), an additional 64-byte XTEA key block is read from the response stream.

### Data Flow After Download

After successful CRC verification:
1. For unencrypted data (flags == 0): The raw container is decompressed via `Js5Compression::Decompress`
2. For encrypted data: A response packet is built with opcode `0x1e`, containing the archive ID, group ID, and raw data, and sent back to the main thread
3. The main thread (`WorkerOnMessage` case 0x1e) stores the data via `Js5DiskCache::ProvideGroup` and `Js5MemoryCache::ProvideGroup`

## Audio Packet Handlers

The server instructs the client to play/preload music via server-to-client packets:

### VORBIS_SONG (address: <addr in DB>)

Plays a Vorbis audio track. Reads:
1. `ushort` — Song/track ID
2. `ushort` — Crossfade parameter
3. `ushort` — Volume/delay parameter (converted to float via multiplication)

The track ID is used to look up the audio data from the JS5 resource provider (index 40). The audio system (`<in Ghidra DB>`) manages a queue of active audio tracks and handles crossfading between songs.

### VORBIS_PRELOAD (address: <addr in DB>)

Pre-loads a Vorbis audio track into cache. Reads:
1. `int` (via `g4s_alt3`) — Track ID to preload

This triggers a `GetFile` request against the JS5 resource provider for the given track, which (for index 40) routes through `Js5HTTPQueue` to download the data over HTTP before it's needed for playback.

### MIDI_SWAP (address: <addr in DB>)

Swaps/plays a MIDI track. Reads:
1. `byte` — Crossfade speed/flags
2. `int` (via `g4s_alt3`) — MIDI track ID

MIDI tracks use a different index than Vorbis (likely index 6 — "music" in the older nomenclature), and may use TCP transport.

## Summary of Key Findings

| Question | Answer |
|----------|--------|
| URL pattern | `{baseURL}/ms?m=0&a={archive}&k={key}&g={group}&c={crc}&v={version}` |
| Music data format | Standard JS5 container (compression byte + sizes + compressed data). The actual audio inside is Vorbis (OGG). |
| HTTP request method | GET (URL with query parameters, no request body) |
| Content-Type check | `application/octet-stream` — response must have this content type |
| Is index 40 the only HTTP index? | It is the primary one. The master index (0xFF) can also be fetched via HTTP as a fallback. The routing is per-archive based on a flag in archive settings. |
| Response format | Raw JS5 container bytes (same as TCP but without TCP framing/chunking) |
| Concurrent request limit | 20 simultaneous HTTP requests |
| Base URL source | Fallback URL from `jav_config.ws` (typically `http://content.runescape.com`) |

## Implementation Notes for the Server

To serve index 40 (music) and support the HTTP JS5 transport:

1. **Endpoint**: Listen for HTTP GET requests matching `/ms` with query parameters `m`, `a`, `k`, `g`, `c`, `v`
2. **Response**: Return the raw JS5 container blob (compression byte + compressed/uncompressed size + data) with `Content-Type: application/octet-stream`
3. **No TCP framing**: Unlike the TCP JS5 protocol, do NOT add 512-byte chunk framing or 0xFF separators
4. **CRC validation**: The client will verify the CRC32 of the response data against the `c` parameter
5. **Version validation**: The client checks the version against the `v` parameter
6. **The `k` parameter** can likely be ignored server-side (it appears to be a client-side priority/type hint)
7. **The `m=0` parameter** appears to be a fixed mode identifier; its meaning is unclear but it is always 0

The JS5 HTTP server can be implemented as a simple HTTP endpoint (e.g., Ktor route) that reads from the same SQLite cache backend used for TCP JS5 serving.
