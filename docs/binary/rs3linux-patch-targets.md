# rs3linux Patch Targets for LD_PRELOAD

This document describes the two patch targets in `rs3linux` (the Linux NXT launcher)
required to redirect download verification to our own RSA key and bypass the
codebase URL whitelist.

Produced by: ghidra-reverse-engineer agent
Binary: `client/rs3linux` (ELF64, PIE/ET_DYN, image base <addr in DB> in Ghidra)

> **Per-OS data layout (2026-06-24).** The client/launcher binaries now live
> under a per-OS tree at `data/client/<os>/`:
> | OS | game client | Jagex launcher | patcher artifact |
> |----|-------------|----------------|------------------|
> | linux   | `data/client/linux/rs2client`     | `data/client/linux/rs3linux`       | `libprojectx_patcher.so` |
> | windows | `data/client/windows/rs2client.exe` | `data/client/windows/rs3windows.exe` | `projectx_patcher.dll` + `projectx_injector.exe` |
> | macos   | `data/client/macos/rs2client`     | `data/client/macos/rs3mac`         | `libprojectx_patcher.dylib` |
>
> The launcher auto-detects the host via `cfg!(target_os = ...)` and resolves
> the launcher binary name (`launcher_binary_name`), the patcher lib name
> (`patcher_lib_name`) and the per-OS folder (`host_os_dir`) in
> `client/launcher/src/game/process.rs`. The `rs3linux` patches below are
> **Linux-launcher-only** (the codebase regex does not exist in the
> Windows/macOS launcher binaries, and are verified absent from the Mach-O
> rs2client). The macOS rs2client runtime patches (login + JS5 RSA moduli, HTTP
> port) are documented in `patch-targets-macos.md` and implemented by the
> `client/launcher/patcher-mac` crate (`libprojectx_patcher.dylib`,
> `DYLD_INSERT_LIBRARIES`).

## LZMA decompression flag — REMOVED

The launcher expects an LZMA-alone download and `download_crc_0` is the CRC of the *decompressed*
binary. ConfigServer used to serve the client raw, so the Linux patcher disabled the launcher's
decompression to stop it unpacking an already-unpacked file.

The server now serves a proper LZMA-alone stream (`LzmaAlone.compress`, cached beside the binary)
and reports the compressed byte count in `download`, matching live Jagex. That removes the reason
the flag patch existed, so it is gone from the patcher and was never added for Windows or macOS —
one patch target fewer on every platform.

Note the claim that the Windows launcher has no LZMA support was wrong: `rs3windows.exe` does
contain LZMA/XZ code. It simply no longer needs patching.

---

## 1. RSA Modulus (download_hash verification)

### Location

| Property | Value |
|----------|-------|
| Ghidra address | `<addr in DB>` |
| File offset | `<addr in DB>` (Ghidra addr - `<in Ghidra DB>` image base) |
| Section | `.rodata` |
| Format | Null-terminated lowercase hex ASCII string |
| Length | 1024 hex characters + 1 null byte = 1025 bytes |
| RSA key size | 4096 bits (512 bytes) |
| Public exponent | `0x10001` (65537), stored as ASCII string `"10001"` |

### Full Modulus (hex)

```
a49962fc0737fddcd94c0daf84e5d214a130b4eda82167e0e9507e1ca421b500175bf6b09c9ea9a4
f3cdba0c8da28c696877e13244aa3baa53e522865db2b2148e1a69d7e95567dcb88cbce828658ea0
487cbd85d348aa48457f3f968d101ba25254a43e1b2b5051e9f5a3184a2dec6c59eb5b2ace3719d4
6feec4a82801b0f71b79c36e6547cf0e22093a519703c9becdc829c749610b3fac188ac9811eba02
9fbaf13aec78513957f7d4d3fd57c90bfcce0922cdce549e6dec3de0ce7c6b3b40fefd54f6ebd844
c852100174f0e4b43386e49d8f1283b74940a9a7915681ffdc7853d37be466926aa1aa3a4940aed3
9b5a9b767b85035c28802dc82b391b3797240bb2c57522498f4ef0801e6a28147f4c6d47b506417
926e07e53bf9ef5a97a517cc7cf2b00cceb1dc4842175a86710cd5dae9b89114bbc41842d92a8c7d
c20d3994511fe60f03c8137f2b9c25082f3ceaf80307187c785ec1d3f1750b29082f42ce4d999279
cbb9f196436c61913d46c4242f939dc52d1f31e1ed5a1058cad63ebd6f33114eb48b343ef6ed3a2d
cd2d2e02ab1c94ee2f504a14c612f415181d8e5958197da90223bd577cebf948a5adc79a642c1c43
7365d49f4ac170526ca36d9c2057e02aa96a3ade6bc8d1d0dce8f5d9205e361094009adcd1478393
274d0c6b71453aa0b27f5ed187c01b9f5d9573d1253f2b90099ddda628838fee9
```

### How it is loaded

In `<in Ghidra DB>` (global init, `.init_array`):

```
// Exponent: "10001" -> bignum at <in Ghidra DB>
<in Ghidra DB> = new BigNum;
<in Ghidra DB>(<in Ghidra DB>, "10001");

// Modulus: hex string at <in Ghidra DB> -> bignum at <in Ghidra DB>
<in Ghidra DB> = new BigNum;
<in Ghidra DB>(<in Ghidra DB>, &<in Ghidra DB>);
```

`<in Ghidra DB>` is a hex-string-to-BigNum parser. It iterates each character,
looks it up in `"0123456789ABCDEF..."`, rejects chars with index > 15 (hex only),
and builds the BigNum via multiply-by-16-and-add.

### Verification flow (<in Ghidra DB>)

1. Read `download_hash_%u` from jav_config parameters (base64-encoded RSA signature)
2. Base64 decode the signature into raw bytes
3. Load raw bytes into a BigNum
4. RSA decrypt: `result = signature ^ 0x10001 mod modulus` via `<in Ghidra DB>`
5. Extract bytes from the BigNum result
6. Check that the result is exactly **0x41 (65) bytes** long
7. The 65 bytes = **1 byte prefix + 64 bytes Whirlpool hash**
8. Compute Whirlpool hash of the downloaded file data
9. Compare the 64-byte hash from RSA decryption against the computed Whirlpool hash
   (byte-by-byte comparison at `<in Ghidra DB>`, 9 bytes per iteration, up to 0x40 = 64 bytes)
10. If match: proceed to codebase URL check
11. If no match or wrong length: set error code 0x11 with message `"err_save_file"`

### Hash algorithm: Whirlpool

The hash is computed by a statically-linked **Whirlpool** implementation:
- `<in Ghidra DB>`: Whirlpool update (feeds data into hash context, 512-bit blocks)
- `<in Ghidra DB>`: Whirlpool finalize (padding, final transform, outputs 64 bytes)
- `<in Ghidra DB>`: Whirlpool compression function (8x8 matrix of 64-bit words,
  8 S-box tables at `<in Ghidra DB>`..`<in Ghidra DB>`, round constants at `<in Ghidra DB>`,
  Miyaguchi-Preneel construction)

The `.dpb` file extension is special-cased: if the download filename ends in `.dpb`,
the Whirlpool hash verification is applied differently (separate code path).

### Signature format

After RSA decryption (`signature ^ e mod n`), the expected plaintext is:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Prefix byte (unknown value, skipped in comparison) |
| 1 | 64 | Whirlpool hash of the downloaded file |

Total: 65 bytes (0x41). This is NOT PKCS#1 v1.5 padding. It is a raw/unpadded
RSA signature with a simple 1-byte prefix followed by the hash.

---

## 2. Codebase URL Regex

### Location

| Property | Value |
|----------|-------|
| Ghidra address | `<addr in DB>` |
| File offset | `<addr in DB>` |
| Section | `.rodata` |
| Format | Null-terminated ASCII string |
| Length | 48 bytes + 1 null byte = 49 bytes |

### Regex string

```
^https?://[a-z0-9\-]*\.?runescape.com(:[0-9]+)?/
```

### How it is checked (<in Ghidra DB> at ~<addr in DB>)

```c
// Get "codebase" parameter from jav_config
<in Ghidra DB>(piVar22, lVar2 + 0x480, "codebase");

// Compile the regex
wxRegEx::Init(local_358);
<in Ghidra DB>(local_3d8, "^https?://[a-z0-9\\-]*\\.?runescape.com(:[0-9]+)?/");
wxRegEx::Compile(local_358, local_3d8, 0);   // flags = 0 (default/extended)

// Test the codebase URL against the regex
cVar7 = wxRegEx::Matches(local_358, local_3d8, 0);

// If no match: error
if (cVar7 == '\0') {
    *(lVar15 + 0x33c) = 0x11;          // error code
    <in Ghidra DB>(lVar15, "err_save_file", 0xd, 0);  // error sub-code 0xd
    wxRegEx::~wxRegEx(local_358);
    goto <in Ghidra DB>;                  // abort
}
// If match: construct download URL and proceed
```

### Regex implementation

Uses **wxRegEx** (wxWidgets regex wrapper), NOT POSIX `regcomp`/`regexec`.
- `wxRegEx::Compile` at `<addr in DB>`
- `wxRegEx::Matches` at `<addr in DB>`
- Internally calls `wx_re_exec` (wxWidgets' own regex engine)
- No `regexec` or `regcomp` in the import table

---

## 3. Other RSA Keys

No other large hex strings were found in `.rodata` besides the one at `<addr in DB>`.
The game client RSA key (for rs2client login) is in the `rs2client` binary, not in
`rs3linux`. The launcher only uses this single 4096-bit key for download verification.

---

## Recommended LD_PRELOAD Patching Strategy

### Option A: String patching in memory (Recommended)

**RSA Modulus:**
1. Generate your own 4096-bit RSA keypair
2. In the LD_PRELOAD `.so`, hook a function that runs early (e.g., `__attribute__((constructor))`)
3. Scan the process memory for the hex string `"a49962fc0737fddc..."` (first 16+ chars are unique enough)
4. Replace the 1024 hex characters in-place with your own modulus hex string
5. The BigNum parser (`<in Ghidra DB>`) will then load your modulus instead
6. Sign `download_hash_0` values with: `signature = (prefix_byte || whirlpool_hash) ^ d mod n`
   where `d` is your private key and `n` is your modulus

**Codebase URL regex:**
1. Find the regex string `"^https?://[a-z0-9\\-]*\\.?runescape.com(:[0-9]+)?/"` in memory
2. Replace it with a permissive regex like `"^https?://.*/"` (pad remaining bytes with nulls)
3. Since the replacement is shorter (14 bytes vs 48 bytes), just null-terminate after the new pattern
4. Alternative: replace with `"^.*$"` to match anything

### Option B: Function hooking

**RSA bypass (hook `<in Ghidra DB>` - the modexp function):**
- Intercept the RSA modexp call
- Return a known plaintext (prefix byte + correct Whirlpool hash)
- Harder because you'd need to compute the Whirlpool hash yourself

**Regex bypass (hook `wxRegEx::Matches`):**
- Hook `wxRegEx::Matches` at `<addr in DB>`
- Always return 1 (match) for any input
- Risk: this hooks ALL regex matches in the process, not just the URL check

### Option C: Hybrid (Recommended for robustness)

- **RSA**: Use string patching (Option A) - most reliable, survives any code path
- **Regex**: Use string patching (Option A) - simple, targeted, no side effects
- Both can be done in a single `__attribute__((constructor))` function:
  1. Open `/proc/self/maps` to find the `.rodata` segment
  2. `mprotect` the page to `PROT_READ | PROT_WRITE`
  3. `memmem` to find both strings
  4. Overwrite in-place
  5. `mprotect` back to `PROT_READ`

### Signing downloads with your key

To produce valid `download_hash_N` values:

```python
import hashlib
# 1. Compute Whirlpool hash of the file
# (Python doesn't have built-in Whirlpool; use hashlib with OpenSSL or whirlpool library)
import whirlpool
file_hash = whirlpool.new(file_data).digest  # 64 bytes

# 2. Construct the 65-byte plaintext
prefix = b'\x00'  # or whatever prefix byte the original uses - needs testing
plaintext = prefix + file_hash

# 3. Convert to integer and sign with RSA private key
m = int.from_bytes(plaintext, 'big')
signature = pow(m, d, n)  # d = private exponent, n = your modulus

# 4. Base64 encode the signature
sig_bytes = signature.to_bytes(512, 'big')  # 4096-bit key = 512 bytes
download_hash = base64.b64encode(sig_bytes).decode
```

### PIE/ASLR note

`rs3linux` is ET_DYN (PIE), so addresses are randomized at runtime.
The LD_PRELOAD patcher must:
- Use `/proc/self/maps` to find the base address
- Or use `memmem` pattern scanning (preferred - address-independent)
- The hex modulus string and regex pattern are unique enough for reliable pattern matching
