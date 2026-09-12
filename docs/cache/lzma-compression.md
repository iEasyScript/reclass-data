# LZMA Compression in JS5 Containers (Compression Type 3)

**Source:** Reverse engineering of `jag::Js5Compression::Decompress` at `<addr in DB>` and the LZMA decompression function `<in Ghidra DB>` at `<addr in DB>` in the NXT client binary (`rs2client`).

---

## Container Header Format

All JS5 compressed containers share the same header format:

```
Offset  Size  Type         Field
------  ----  ----         -----
0       1     uint8        compressionType (0=none, 1=bzip2, 2=gzip, 3=lzma)
1       4     big-endian   compressedSize
```

- `compressionType` is read as a raw byte at offset 0.
- `compressedSize` is read via `jag::Packet::gT_uint` (big-endian 32-bit unsigned int) at offset 1.

If `compressionType != 0`, an additional field follows:

```
Offset  Size  Type         Field
------  ----  ----         -----
5       4     big-endian   decompressedSize
```

- `decompressedSize` is read via `jag::Packet::gT_uint` at offset 5.

Both sizes are **full 32-bit integers** -- there is NO 24-bit masking.

### What `compressedSize` measures

`compressedSize` equals the total number of bytes of compressed payload starting at offset 9 (i.e., everything after the 9-byte header). This was verified by validation checks in both the GZIP and BZIP2 code paths:

- **BZIP2 (type 1):** Validates `bytes_consumed_from_offset_9 == compressedSize`
- **GZIP (type 2):** Validates `bytes_consumed_from_offset_9 == compressedSize - 8` (the -8 accounts for the 8-byte gzip trailer that raw inflate does not consume, while the 10-byte gzip header is consumed)
- **LZMA (type 3):** Uses `compressedSize` as a generous budget for the decoder; decompression terminates naturally when `decompressedSize` bytes are produced.

**Total container size** = 1 (type) + 4 (compressedSize field) + 4 (decompressedSize field) + compressedSize = **compressedSize + 9**.

For uncompressed containers (type 0), there is no decompressedSize field: total = 1 + 4 + compressedSize = **compressedSize + 5**.

---

## LZMA Container Layout (Type 3)

```
Offset  Size  Type              Field
------  ----  ----              -----
0       1     uint8             compressionType = 0x03
1       4     big-endian u32    compressedSize
5       4     big-endian u32    decompressedSize
9       1     uint8             lzmaPropertyByte (encodes lc, lp, pb)
10      4     little-endian u32 lzmaDictionarySize
14      N     raw bytes         lzmaCompressedStream
```

Where `N = compressedSize - 5` (total payload minus the 5-byte LZMA properties header).

Total container size = **compressedSize + 9** bytes.

---

## LZMA Properties (5 bytes at offset 9)

The 5-byte LZMA properties follow the **standard LZMA SDK format**:

### Byte 0: Property byte (offset 9)

Encodes `lc`, `lp`, and `pb` as a single byte:

```
propertyByte = lc + 9 * (lp + 5 * pb)
```

Decoding:
```
lc = propertyByte % 9           // literal context bits (0-8)
lp = (propertyByte / 9) % 5     // literal position bits (0-4)
pb = propertyByte / 45           // position bits (0-4)
```

The client validates `propertyByte < 0xE1` (225 = 9 * 5 * 5), which is the standard maximum.

### Bytes 1-4: Dictionary size (offset 10-13)

A **little-endian** 32-bit unsigned integer specifying the LZMA dictionary size in bytes. This is read in native (little-endian) byte order from the raw data, NOT via `jag::Packet::gT_uint`.

The client enforces a minimum dictionary size of `0x1000` (4096 bytes).

---

## LZMA Compressed Stream (offset 14+)

The compressed stream at offset 14 is a **raw LZMA1 stream** -- the same format produced by the LZMA SDK's `LzmaDec` / `LzmaEnc` without any additional framing or headers.

There is **NO 8-byte uncompressed size field** in the LZMA data. The decompressed size is already known from the container header field at offset 5-8. This differs from the standard `.lzma` file format which includes a 13-byte header (5 props + 8 byte uncompressed size).

### Decoder implementation

The client uses an inlined LZMA1 range decoder. Key functions:
- `<in Ghidra DB>` at `<addr in DB>` -- LZMA decompression entry point (called for type 3)
- `<in Ghidra DB>` at `<addr in DB>` -- LZMA range decoder (processes compressed input)
- `<in Ghidra DB>` at `<addr in DB>` -- LZMA match/literal decoder

The probability model table size is computed as:
```
probTableSize = (0x300 << ((lp + lc) & 0x1F)) + 0x7C0
```

Each probability entry is a 16-bit value initialized to `0x400` (1024), matching the standard LZMA SDK initialization.

---

## Decompression Termination

The LZMA decompression loop terminates when **either**:
1. `decompressedSize` bytes have been produced (normal completion), or
2. All compressed input bytes have been consumed.

On successful decompression, the output buffer contains exactly `decompressedSize` bytes.

---

## Summary: All Compression Types

| Type | Name       | Data at offset 9                                      |
|------|------------|-------------------------------------------------------|
| 0    | None       | Raw uncompressed data (no decompressedSize field)     |
| 1    | BZIP2      | Raw BZIP2 stream (starts with `BZ` magic)             |
| 2    | GZIP       | Standard GZIP stream (starts with `1F 8B` magic)      |
| 3    | LZMA       | 5-byte LZMA properties + raw LZMA1 compressed stream  |

---

## Code References

| Symbol | Address | Role |
|--------|---------|------|
| `jag::Js5Compression::Decompress` | `<addr in DB>` | Main decompression dispatcher (7500+ lines decompiled) |
| `jag::Js5Compression::DecompressGroup` | `<addr in DB>` | Simpler variant using magic-number detection |
| `<in Ghidra DB>` | `<addr in DB>` | LZMA decompression (type 3 handler) |
| `<in Ghidra DB>` | `<addr in DB>` | LZMA range decoder |
| `<in Ghidra DB>` | `<addr in DB>` | LZMA match/literal decoder |
| `jag::Packet::gT_uint` | `<addr in DB>` | Big-endian 32-bit integer read |
