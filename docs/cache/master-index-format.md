# NXT Master Index (Version Table) Format

Reverse-engineered from the NXT client binary (`rs2client` and `librs2client.so`) via Ghidra MCP.

**Key Functions Analyzed:**
- `jag::Js5MasterIndex::Js5MasterIndex` (rs2client) / `<addr in DB>` (librs2client.so) -- Master index parser/constructor
- `jag::Js5ResourceProvider::WorkerOnMessage` (rs2client) -- case 10: master index dispatch, case 0x28: verify master index
- `<in Ghidra DB>` (rs2client) -- Master index download callback
- `<in Ghidra DB>` (rs2client) -- uint32 BE reader (container header field reader)
- `jag::Packet::gT_uint` (rs2client) -- uint32 BE reader (per-archive field reader)
- `<in Ghidra DB>` (rs2client) -- Whirlpool hash update (NESSIEadd)
- `<in Ghidra DB>` (rs2client) -- Whirlpool hash finalize (NESSIEfinalize)
- `jag::math::BigInteger::ModPow` (rs2client) -- RSA modular exponentiation
- `jag::math::BigInteger::FromBytes` (rs2client) -- BigInteger from byte array

---

## Overview

The master index (a.k.a. "version table") is the JS5 response for archive=255, group=255. It describes all cache indices: their CRCs, versions, whirlpool hashes, file counts, and uncompressed sizes. The NXT client uses it to determine which indices need downloading/updating.

The master index is served as a **standard JS5 container** (compression byte + compressedSize + payload). The client receives the raw container bytes via the JS5 TCP protocol, then the `Js5MasterIndex` constructor parses the container in-place, performing RSA signature verification.

---

## Data Flow: Server to Js5MasterIndex Constructor

### Step 1: JS5 TCP Response

The server sends the master index as a normal JS5 file response:

```
[archive=0xFF(1B)] [group=<addr in DB>(4B)] [containerData...]
```

With standard 102,400-byte block framing (see js5-response-format.md).

### Step 2: Download Callback (<in Ghidra DB>)

The JS5 worker thread receives the complete container data and posts it to the main thread:

```
Message: [opcode=0x0A(1B)] [dataSize(2B, ushort BE)] [rawContainerData(dataSize bytes)]
```

The raw container data is the **entire container** as received from the JS5 response (starting with the compression byte).

### Step 3: WorkerOnMessage Case 10 (VERIFIED librs2client.so

The main thread handler:
1. Reads `dataSize` as ushort (2 bytes, BE)
2. If `dataSize == 0`, master index download failed -- set error flag and return
3. Copies `dataSize` bytes of raw container data into a Packet buffer
4. Retrieves RSA key pointers: exponent from `this + 0x78`, modulus from `this + 0x80`
5. Calls `Js5MasterIndex::Js5MasterIndex(masterIndexObj, exponent, modulus, packet)`

**Critical: NO decompression occurs before passing to the constructor.** The constructor receives and parses the raw container bytes directly.

### Step 4: Js5MasterIndex Constructor

The constructor treats the buffer as a Packet (position-tracked byte array). It parses the container header fields and payload in-place.

---

## Container Wire Format (What the Server Must Send)

The master index container uses **compression = 0** (no compression). The complete byte layout:

```
Offset  Size  Type        Field              Description
------  ----  ----        -----              -----------
0       1     uint8       compression        MUST be 0 (no compression)
1       4     uint32 BE   compressedSize     Total size of everything after this field
                                              = 1 + archiveCount*80 + rsaSignatureSize
5       1     uint8       archiveCount       Number of archive index entries (N)

Per archive entry (N entries, 80 bytes each, starting at offset 6):
+0      4     uint32 BE   crc                CRC32 of the archive's raw index container
+4      4     uint32 BE   version            Archive revision/version number
+8      4     uint32 BE   fileCount          Number of files/groups in the archive
+12     4     uint32 BE   uncompressedSize   Total uncompressed size of the archive
+16     64    bytes       whirlpool          Whirlpool hash of the archive's raw index container

RSA signature block (starts at offset 6 + N*80):
...     var   bytes       rsaSignature       RSA-encrypted signature (see below)
```

### Field Details

**compression (offset 0):** The constructor sets position to 1, effectively skipping this byte. It does NOT read or validate the compression type. However, the JS5 response framing reads it as part of the 10-byte response header. It should be `0`.

**compressedSize (offset 1-4):** Read by the constructor as uint32 BE via `<in Ghidra DB>`. This value is used to calculate the RSA signature block size:

```
rsaSignatureSize = compressedSize - 1 - archiveCount * 80
```

(Where `compressedSize` is the value from container offset 1-4.)

**archiveCount (offset 5):** Read as a single unsigned byte. This is the **first byte of the payload** (at container offset 5). The constructor stores `archiveCount - 1` at object offset 0x00 (used internally), and `archiveCount + 1` at object offset 0x08 (used as array capacity). The per-entry loop iterates exactly `archiveCount` times. Maximum 255 archives.

**Per-archive entries (offset 6+):** Each entry is exactly **80 bytes**. Read order confirmed from the constructor's entry loop:

```c
// Loop starts at byte offset 6, increments by 0x50 (80) per iteration
iVar13 = Packet::gT_uint(packet);    // CRC (4B)
iVar12 = Packet::gT_uint(packet);    // version (4B)
uVar14 = <in Ghidra DB>(packet);       // fileCount (4B)
uVar15 = <in Ghidra DB>(packet);       // uncompressedSize (4B)
// memcpy 0x40 (64) bytes                whirlpool (64B)
```

Wire order within each 80-byte entry:

```
+0:  CRC (4B)
+4:  version (4B)
+8:  fileCount (4B)
+12: uncompressedSize (4B)
+16: whirlpool (64B)
```

The constructor stores them into the entry object (0x20 = 32 bytes, from `operator_new(0x20)`) as:
```c
// Verified from librs2client.so:
*puVar10 = uVar29;       // offset 0x00: CRC (uint32)
puVar10[1] = uVar3;      // offset 0x04: version (uint32)
// offset 0x08: Array<uint8> for whirlpool (64 bytes, heap-allocated)
puVar10[6] = uVar4;      // offset 0x18: fileCount (uint32)
puVar10[7] = local_1fc;  // offset 0x1C: uncompressedSize (uint32)
```

---

## RSA Signature — DETAILED ANALYSIS

> **CORRECTION (verified against the live Jagex 949 signature + the 949-1 ctor @ `<in Ghidra DB>`):**
> - **The client does NOT check the decrypted plaintext's leading byte against any value.** The `0x01`
>   mentioned throughout the older notes below is wrong. The two real acceptance gates are: (1) the
>   RSA-decrypted plaintext length is **exactly 65 bytes** (`<in Ghidra DB>`: CMP len, 0x41; JZ`), and (2) the
>   trailing 64 bytes equal the Whirlpool of `container[5 .. 6+N*80)`.
> - **The actual leading byte is `0x0a` (10), not `0x01`** — both our `VersionTableBuilder` and live
>   Jagex 949 sign `[0x0a][64-byte whirlpool]`. Since the byte is unchecked, its value is irrelevant to
>   acceptance, but `0x0a` is what is on the wire.
> - **A wrong verification modulus is the dominant real-world failure:** `signature^e mod modulus`
>   yields a ~modulus-sized number → decrypted length ≠ 65 → silent reject → `Js5MasterIndex.archive_count`
>   left 0 → the first cache-index request traps at `RequestGroupFromDisk `<in Ghidra DB>`
>   (`CMP [masterIndex+0x10]=0, archiveId; JBE`). This is a **crash** on 949, not the historical idle timeout.
> - **949 rotated both rs2client RSA moduli.** JS5 (4096-bit) modulus hex now starts
>   `a4ba332072d8ccdcff327ef42dc5be75`; login (1024-bit) starts `83fec000fd2e3d6f1555e4f1a3875dd9`. The
>   LD_PRELOAD patcher must search for these new prefixes; the 948 prefixes (`a6400fbc…` / `aad4a780…`)
>   are absent from the 949 binary, so a patcher still using them silently fails to swap the key.

### Signature Block Location

The RSA signature block starts immediately after the per-archive entries:

```
rsaBlockOffset = 6 + archiveCount * 80
rsaBlockSize   = compressedSize - 1 - archiveCount * 80
```

(Where `compressedSize` is the value from container offset 1-4.)

### How the Constructor Extracts the RSA Block

In the `rs2client` decompilation at `<addr in DB>`:

```c
// Position is set to 1 (skip compression byte)
uVar10 = <in Ghidra DB>;           // Read compressedSize (4 bytes BE) from offset 1
lVar25 = *(long *)(in_RCX + 0x18); // Current position in packet = 5
lVar32 = lVar25 + 1;               // Skip archiveCount byte -> position = 6
bVar4 = *(byte *)(data + lVar25);  // Read archiveCount byte from offset 5
lVar32 = (bVar4 * 80) + lVar32;    // Skip all archive entries -> position = 6 + N*80
lVar32 = 5 - lVar32;               // Calculate: -(1 + N*80)  (this is -hashLen)
uVar35 = uVar10 + lVar32;          // rsaBlockSize = compressedSize - 1 - N*80
```

The RSA block bytes are then copied from `packet[6 + N*80]` for `rsaBlockSize` bytes.

### RSA Decryption — CRITICAL DETAILS

**In `librs2client.so` (clearer symbol info):**

```c
// pvVar9 = new BigInteger  (for the ciphertext)
mp_init(pvVar9);
mp_read_unsigned_bin(pvVar9, lVar20, sVar25 & 0xffffffff);  // Load RSA block as UNSIGNED BigInt

// puVar10 = new BigInteger  (for the result)
mp_init(puVar10);

// result = ciphertext^exponent mod modulus
iVar7 = mp_exptmod(pvVar9,
                    *(undefined8 *)param_1,    // exponent (from BigInteger* param_1)
                    *(undefined8 *)param_2,    // modulus (from BigInteger* param_2)
                    puVar10);                  // result
```

**Key observation:** The NXT client uses **libtommath** (`mp_read_unsigned_bin`, `mp_exptmod`, `mp_init`, `mp_clear`). The function `mp_read_unsigned_bin` reads a byte array as an **unsigned** big integer. This is different from Java's `BigInteger(byte)` constructor, which interprets the byte array as **signed** (two's complement).

**In `rs2client`:**

```c
math::BigInteger::BigInteger(this_00, iVar13);
math::BigInteger::FromBytes(this_00, data_00, (int)uVar35);  // Load RSA block
math::BigInteger::ModPow(this_00, plVar17, (long *)*in_RDX, this_01);  // ModPow
```

`FromBytes` is the equivalent of `mp_read_unsigned_bin` -- it reads bytes as an unsigned integer.

### Result Size Check

After RSA decryption, the result BigInteger is converted back to a byte array. The constructor checks the result's byte length:

**In `rs2client`:**
```c
if (local_120 != 0x41)  // 0x41 = 65 decimal
    goto joined_r<addr in DB>;  // REJECT: skip Whirlpool verification, skip entry parsing
```

**In `librs2client.so`:**
```c
if ((local_140 != (ref_counter_base *)0x0) && (*(long *)local_140 == 0x41))
    // proceed with Whirlpool verification
```

**The decrypted RSA result MUST be exactly 65 bytes.** If it is any other size, the entire master index is rejected silently.

### Decrypted Signature Format

```
Offset  Size  Type    Field       Description
------  ----  ----    -----       -----------
0       1     uint8   magic       0x0a on the wire; NOT validated by the client (any value accepted)
1       64    bytes   whirlpool   Whirlpool hash digest
```

Total: 65 bytes (0x41).

### Whirlpool Hash Computation

**In `librs2client.so` (clear symbol names):**

```c
// Hash is computed over the raw container bytes starting at offset 5
// (the archiveCount byte) for (1 + archiveCount * 80) bytes
lVar20 = *(long *)(param_3 + 8);  // Packet buffer pointer
if (lVar20 == 0) {
    puVar26 = (uchar *)0x5;
} else {
    puVar26 = (uchar *)(*(long *)(lVar20 + 8) + 5);  // buffer + 5
}

// lVar12 was computed earlier as: 5 - (6 + N*80) = -(1 + N*80)
// So lVar12 * -8 = (1 + N*80) * 8 = bit length of hash input
Whirlpool::NESSIEadd(&whirlpoolState, puVar26, lVar12 * -8, &whirlpoolState);

// Finalize into a 64-byte output buffer
Packet::Packet(&resultPacket, 0x40);  // Allocate 64-byte buffer
Whirlpool::NESSIEfinalize(&whirlpoolState, &whirlpoolState, resultBuffer);
```

**Hash range:**
```
Start:  container offset 5 (the archiveCount byte)
Length: 1 + archiveCount * 80  (in bytes)
End:    container offset 6 + archiveCount * 80
```

This covers the **archiveCount byte plus all per-archive entries**. It does NOT include:
- The container header (compression byte + compressedSize) -- offsets 0-4
- The RSA signature block itself

### Whirlpool Comparison

**In `librs2client.so`:**

```c
// Compare computed hash (from NESSIEfinalize) against decrypted RSA result bytes [1..64]
lVar12 = 0;
do {
    if (*(char *)(computedHash + lVar12) != *(char *)(decryptedRsa + 1 + lVar12))
        goto <in Ghidra DB>;  // MISMATCH: reject
    lVar12 = lVar12 + 1;
} while (lVar12 != 0x40);  // Compare all 64 bytes
```

**In `rs2client`:**

```c
// Same comparison, byte by byte, 64 bytes total
// Compares local_f8 (computed Whirlpool) against local_118 + 1 (decrypted RSA, skip byte 0)
if ((char)*local_f8 != *(char *)((long)local_118 + 1)) goto <in Ghidra DB>;  // REJECT
lVar32 = 1;
do {
    // Unrolled comparison, 9 bytes per iteration
    if (*(char *)((long)local_f8 + lVar32) != *(char *)((long)local_118 + lVar32 + 1))
        goto <in Ghidra DB>;  // REJECT
    // ... (7 more byte comparisons per iteration)
    lVar32 = lVar32 + 9;
} while (lVar32 != 0x40);
```

### What Happens on Verification Failure

When any verification check fails:

1. **Decrypted size != 65:** The code jumps directly to `joined_r<addr in DB>` (rs2client) or falls through to skip entry parsing. The `Js5MasterIndex` object is left in an uninitialized state (no archive entries populated).

2. **Byte[0] != 0x01 or Whirlpool mismatch:** The code jumps to `<in Ghidra DB>` / `<in Ghidra DB>`, which skips the entry parsing loop entirely.

3. **No error is logged.** The failure is completely silent. The client simply has an empty/invalid master index, which means it never knows what archives exist, so it never requests any further files. This manifests as a **30-second timeout** (State 3 timeout) because the client sits idle waiting for something that will never happen.

4. **No RSA keys (both null):** If `param_1` and `param_2` (or `data` in rs2client) are both null, the constructor skips RSA entirely and treats the raw bytes after the entries as the "decrypted" result. This is the "unsigned" / "no RSA" path.

---

## CRITICAL BUG: Java BigInteger Signedness

### The Problem

The NXT client uses `mp_read_unsigned_bin` (libtommath) which reads byte arrays as **unsigned** integers. Java's `BigInteger(byte)` constructor interprets byte arrays as **signed** (two's complement).

When our server does:
```kotlin
val rsa = BigInteger(output).modPow(exponent, modulus).toByteArray
```

If `output[0]` has the high bit set (value >= 0x80), Java interprets it as a negative number. The resulting `modPow` produces a completely different (wrong) ciphertext. The client then decrypts to garbage and silently rejects the master index.

**However**, for our specific case, `output[0] = 0x01`, so the plaintext is always positive. The issue is more subtle:

### The Real Issue: `BigInteger.toByteArray` Padding

Java's `BigInteger.toByteArray` returns a **signed** two's complement representation. If the result of `modPow` has its highest bit set, `toByteArray` prepends a `0x00` byte to keep the number positive. This means:

- For a 1024-bit modulus, the RSA ciphertext should be exactly 128 bytes
- But `toByteArray` might return 129 bytes (with a leading `0x00`)
- Or it might return fewer bytes if the result has leading zero bits

The client's `mp_read_unsigned_bin` reads exactly `rsaBlockSize` bytes from the container. Our `compressedSize` field tells the client where the RSA block ends and how big it is. So if we write 129 bytes but the client reads all 129, it would do `mp_read_unsigned_bin(data, 129)` and get the right unsigned value (leading `0x00` is harmless for unsigned reads).

**The real question is:** Does the server's `RSA.crypt` output match what the client expects to RSA-decrypt back to 65 bytes?

### Server-Side RSA Signing

Our server does:
```kotlin
// output = [0x01][64B whirlpool] = 65 bytes
val rsa = BigInteger(output).modPow(exponent, modulus).toByteArray
```

This signs using the **private** exponent. The client then decrypts using the **public** exponent (65537).

### Client-Side RSA Decryption

```c
mp_read_unsigned_bin(ciphertext_bigint, rsaBlockBytes, rsaBlockSize);
mp_exptmod(ciphertext_bigint, publicExponent, modulus, result_bigint);
// Convert result_bigint back to bytes, check length == 65
```

The conversion back to bytes (BigInteger-to-bytes in the rs2client constructor) uses the `DivMod` loop pattern, extracting bytes via repeated division by 256, then reversing the array. The resulting byte count is the number of significant bytes in the BigInteger -- no padding. So if the mathematical result is `0x01` followed by 64 bytes, it produces exactly 65 bytes.

### Potential Issues to Check

1. **Leading zero from `toByteArray`:** If `BigInteger(output)` produces a leading `0x00` when converting to bytes for the RSA block, the block size in the container changes. The client reads `rsaBlockSize = compressedSize - 1 - N*80`, so as long as `compressedSize` is consistent with the actual RSA block written, this is fine.

2. **RSA block smaller than modulus:** After `modPow`, if the result has leading zero bytes, `toByteArray` returns fewer bytes. For a 4096-bit (512-byte) modulus, the RSA output could be anywhere from 1 to 513 bytes (with sign byte). We write however many bytes `toByteArray` returns, and set `compressedSize` accordingly.

3. **Key size mismatch:** The server uses a 4096-bit RSA key. The patcher must replace the **same size** modulus in the client binary. If the client's original modulus storage is smaller than 4096 bits, the patcher might not have enough space. More importantly, the RSA ciphertext size depends on the modulus size. The client expects `rsaBlockSize` to match what was signed with a specific key size.

### Recommendation

Use `BigInteger(1, output)` (positive signum constructor) for the plaintext to ensure unsigned interpretation:
```kotlin
val rsa = BigInteger(1, output).modPow(exponent, modulus).toByteArray
```

And strip any leading `0x00` byte from `toByteArray` if present:
```kotlin
val rsaBytes = if (rsa[0] == 0.toByte && rsa.size > 1) rsa.copyOfRange(1, rsa.size) else rsa
```

This ensures the RSA block written to the container has no unexpected padding.

---

## RSA Key Location in the Binary

The RSA keys for JS5 master index verification are stored directly on the `Js5ResourceProvider` object (NOT via a pointer to a struct):

```
Js5ResourceProvider offsets (librs2client.so):
    this + 0x78:  BigInteger* exponent   // public exponent (65537 = 0x10001)
    this + 0x80:  BigInteger* modulus    // RSA modulus
```

These are the 9th and 10th constructor parameters: `..., bool diskCacheEnabled, BigInteger* exponent, BigInteger* modulus`.

**In WorkerOnMessage (librs2client.so:**
```c
pBVar10 = *(BigInteger **)(this + 0x78);  // exponent
pBVar11 = *(BigInteger **)(this + 0x80);  // modulus
Js5MasterIndex::Js5MasterIndex(pJVar21, pBVar10, pBVar11, local_1c8);
```

**In the Js5MasterIndex constructor (librs2client.so:**
```c
// Signature: Js5MasterIndex(this, BigInteger* param_1, BigInteger* param_2, Packet* param_3)
// param_1 = exponent, param_2 = modulus
mp_exptmod(ciphertext,
           *(undefined8 *)param_1,  // X = exponent (mp_int data pointer)
           *(undefined8 *)param_2,  // P = modulus (mp_int data pointer)
           result);                 // Y = result
// libtommath: mp_exptmod(G, X, P, Y) computes Y = G^X mod P
```

**CRITICAL:** The parameter order is `(exponent, modulus)`, NOT `(modulus, exponent)`. This was previously documented incorrectly in `js5-post-master-index-flow.md`.

### How the Patcher Works

The RSA keys are initialized in `<in Ghidra DB>` (`.init_array` constructor):

```c
// At <addr in DB> in rs2client:
<in Ghidra DB>(&<in Ghidra DB>, "10001", 0x10);       // Login exponent = 65537
<in Ghidra DB>(&<in Ghidra DB>, "9cbc5f91...", 0x10);  // Login modulus (1024-bit, 256 hex chars
<in Ghidra DB>(&<in Ghidra DB>, "10001", 0x10);        // JS5 exponent = 65537
<in Ghidra DB>(&<in Ghidra DB>, &<in Ghidra DB>, 0x10);  // JS5 modulus (4096-bit, 1024 hex chars
<in Ghidra DB>(&<in Ghidra DB>, "10001", 0x10);        // Unknown exponent = 65537
<in Ghidra DB>(&<in Ghidra DB>, "ccd229d9...", 0x10);  // Unknown modulus (512-bit, 128 hex chars
```

`<in Ghidra DB>` parses a hex string (base 16) into a `jag::math::BigInteger` stored at the given global address. The hex strings are in `.rodata`.

**Key addresses:**
- `<addr in DB>`: Login RSA modulus hex string (256 chars, prefix `9cbc5f91...`)
- `<addr in DB>`: JS5 RSA modulus hex string (1024 chars, prefix `e9b6a139afb361a6438c46cdade9e7ae`)
- `<addr in DB>`: Unknown RSA modulus hex string (128 chars, prefix `ccd229d9...`)

The LD_PRELOAD patcher (`libprojectx_patcher.so`) pattern-matches these hex strings in the process's memory and overwrites them with custom values BEFORE the `.init_array` constructor runs. Since LD_PRELOAD constructors execute before the main binary's constructors, the patched hex strings are what `<in Ghidra DB>` actually parses.

**Critical requirement:** The patcher reads `PROJECTX_JS5_RSA_MODULUS` from the **process environment**. This env var must be `export`-ed in the shell, not just set as a shell variable. Using `source .env` without `set -a` or explicit `export` will NOT make the variables visible to child processes.

The `Js5ResourceProvider` object stores the key pointers directly (librs2client.so):
- `this + 0x78` -> BigInteger* for JS5 exponent (global at `<in Ghidra DB>`)
- `this + 0x80` -> BigInteger* for JS5 modulus (global at `<in Ghidra DB>`)

**Static init order (librs2client.so:**
```
BigInteger("10001", 16) -> global `<in Ghidra DB>`  (Login exponent)
BigInteger(loginModHex, 16) -> global `<in Ghidra DB>`  (Login modulus, hex at `<in Ghidra DB>`)
BigInteger("10001", 16) -> global `<in Ghidra DB>`  (JS5 exponent)
BigInteger(js5ModHex, 16) -> global `<in Ghidra DB>`  (JS5 modulus, hex at `<in Ghidra DB>`)
BigInteger("10001", 16) -> global `<in Ghidra DB>`  (Unknown exponent)
BigInteger(unknownModHex, 16) -> global `<in Ghidra DB>`  (Unknown modulus, hex at `<in Ghidra DB>`)
BigInteger(exp4Hex, 16) -> global `<in Ghidra DB>`  (4th key exponent, hex at `<in Ghidra DB>`)
BigInteger(mod4Hex, 16) -> global `<in Ghidra DB>`  (4th key modulus, hex at `<in Ghidra DB>`)
```

The patcher replaces the hex strings at their `.rodata` addresses BEFORE the static initialization constructors run.

---

## Verification Procedure Summary

```
1. Extract RSA block: bytes from offset (6 + N*80) to end of compressedSize data
   - rsaBlockSize = compressedSize - 1 - N*80
2. RSA decrypt: result = rsaBlock^publicExponent mod modulus
   - Uses UNSIGNED big integer interpretation (mp_read_unsigned_bin / libtommath)
3. Check decrypted byte length == 65 (0x41)   <-- the real gate; a wrong modulus fails here
4. (decrypted[0] is NOT checked by the client — it is 0x0a on the wire but any value is accepted)
5. Compute Whirlpool hash over container bytes [5 .. 5 + 1 + N*80)
   - Input: archiveCount byte + all 80-byte entries
   - NESSIEadd bit count = (1 + N*80) * 8
6. Compare decrypted[1..64] against computed 64-byte Whirlpool hash
   - Byte-by-byte comparison, all 64 bytes must match
7. If ANY check fails: master index is silently rejected
   - No error log, no disconnect signal
   - Client simply has no valid master index
   - Result: client sits idle, 30-second State 3 timeout
```

---

## Correct VersionTableBuilder Layout

```
Byte 0:     compression = 0x00
Bytes 1-4:  compressedSize = 1 + archiveCount * 80 + rsaBlockSize  (uint32 BE)
Byte 5:     archiveCount (uint8)

For each archive (i = 0 to archiveCount-1):
  Bytes 6+i*80+0  .. 6+i*80+3:   CRC32 of raw index container (uint32 BE)
  Bytes 6+i*80+4  .. 6+i*80+7:   version/revision (uint32 BE)
  Bytes 6+i*80+8  .. 6+i*80+11:  fileCount (uint32 BE)
  Bytes 6+i*80+12 .. 6+i*80+15:  uncompressedSize (uint32 BE)
  Bytes 6+i*80+16 .. 6+i*80+79:  Whirlpool hash (64 bytes)

After all entries:
  RSA signature block (variable size, depends on modulus size)
  - For 1024-bit key: typically 128 bytes
  - For 4096-bit key: typically 512 bytes

Whirlpool hash for RSA covers bytes [5 .. 6 + archiveCount * 80)
RSA plaintext = [0x01] [64-byte Whirlpool hash] = 65 bytes total
RSA ciphertext = plaintext^privateExponent mod modulus
```

---

## Summary of Key Differences from OSRS Format

| Aspect | OSRS Format | NXT RS3 Format |
|--------|-------------|----------------|
| Entry size | 72 bytes | **80 bytes** |
| Fields per entry | CRC + revision + whirlpool | CRC + version + **fileCount** + **uncompressedSize** + whirlpool |
| Field order | CRC, revision, whirlpool | CRC, version, **fileCount, uncompressedSize**, whirlpool |
| Format version byte | Present before entries | **Not present** (no formatVersion field) |
| Checksum field | Present (4 bytes) | **Not present** (container compressedSize serves a different purpose) |
| archiveCount position | After format headers | **Byte 5** (first payload byte, immediately after container header) |
| Whirlpool hash range | Over format + entries | Over archiveCount byte + all entries (bytes 5 to 6+N*80) |
| RSA plaintext | [0x01][64B hash] = 65 bytes | [0x01][64B hash] = 65 bytes (same) |
| BigInteger interpretation | Signed (Java) | **Unsigned** (libtommath `mp_read_unsigned_bin`) |
| RSA library | Java BigInteger | **libtommath** (`mp_exptmod`) |
