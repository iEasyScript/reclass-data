# rs2client RSA Key Locations

Produced by: ghidra-reverse-engineer agent
Binary: `data/client/rs2client` (ELF64, non-PIE, image base <addr in DB> in Ghidra)
Init function: `<in Ghidra DB>` (`.init_array` constructor, initializes all BigInteger globals)

---

## Key Summary

| # | Global (modulus) | Global (exponent) | Size | Base | Usage |
|---|------------------|--------------------|------|------|-------|
| 1 | `<in Ghidra DB>` | `<in Ghidra DB>` | 1024-bit | hex | Login RSA (CreateLoginRSAPacket, StartRSAPacket) |
| 2 | `<in Ghidra DB>` | `<in Ghidra DB>` | 4096-bit | hex | **JS5 Master Index / Version Table verification** |
| 3 | `<in Ghidra DB>` | `<in Ghidra DB>` | 512-bit | hex | Unknown (not xref'd outside init) |
| 4 | `<in Ghidra DB>` | `<in Ghidra DB>` | ~512-bit | decimal | Unknown (used in <in Ghidra DB>) |

---

## 1. Login RSA Key (1024-bit)

### Location

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Modulus string file offset | `<addr in DB>` |
| Modulus string VA | `<addr in DB>` (in `.rodata`, VA == file offset) |
| Format | Null-terminated lowercase hex ASCII string |
| Length | 256 hex characters (1024 bits) |
| Exponent | `10001` (hex) = 65537 |

### Modulus (hex)

```
9cbc5f910c473c629a26baf5f9a1d01d4b8aadc6480518d3fe8659e4b09cbe90
e104147c47e7df58da3891358777ff6d3a4dbb8940b1d844592b40f45a975590
028c0b480f82ac6a52b47ce63b8154e56aa8164a81063a95df25f07882ffdfeb
1eb91c4a0d03dd0537c933065080b90436c1376cfa8c3fdebf2e747142579069
```

### Usage

Referenced by:
- `jag::LoginManager::StartRSAPacket` at `<addr in DB>`
- `jag::LoginManager::CreateLoginRSAPacket` at `<addr in DB>`
- `jag::LoginManager::LoginStepWaitingSocialNetworkToken` at `<addr in DB>`

Used for RSA encryption of the login block (ISAAC seeds, credentials, etc.)

---

## 2. JS5 Master Index RSA Key (4096-bit) -- PATCH TARGET

### Location

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Modulus string file offset | **`<addr in DB>`** |
| Modulus string VA | `<addr in DB>` (in `.rodata`, VA == file offset) |
| Format | Null-terminated lowercase hex ASCII string |
| Length | 1024 hex characters (4096 bits) |
| Exponent | `10001` (hex) = 65537 |

### Modulus (hex)

```
e9b6a139afb361a6438c46cdade9e7ae160dcda18e2a3c6eb549b870dceaf74c
39bbedfcbd6cbb1432f611c296d7fe53d4ab2eb8a73ca6ce6a58e4b003b1ec3e
1eabd2880ee7efed98f6a064bd48cf7b24de32418df839f09de4c80072af7f8b
cc0ad00e61e48b69ae53491c3103d86ee2ffca1256628df84c07aee33e6f8a76
ca12e8ff15111b6a6fb521e0e81f38faa9d2a49543189b0c46d767cbb3a83bf3
0c8e00cb4cf9f26691898f75af62b97783e34c9ac15750ab4b5eccf18b324c11
cdbfca3fe6719176452b25bedb1677f4db6b4b57b3b9d889b1ea2f3953290ab6
ae3be47b03ddbcc4f79bfbcbf35c7e3c995ad05bbbc39938515a2e2b1723871a
60179218af51c8d48a7ec6652363d54724cd685680f805596ca39bd620e3c1b6
f51819ba2fa4238429e914a0c3cb3414769ae20bf1d2bf17d43031d79ab0a2d4
094476f0f925b78d692c4be3b60bdc95dd836c18da12043380fdaa715cb0c1c4
b259365985243c61ceebf7a0747c1b8eab5b0687280173752d2447c51c33a76a
139555f552bb6a61ccbd6addbb39a7dd60c2abdd7bac061581d3b2697b06d969
3bf002d1a41dac815b5be745b75f56b514b8edd6b140bfe2f178b114feb49f53
9e0bdb9af65ef6ecc19a49f5b90faed0d9b76c247c02747236ad70ebd39257fa
eea76ad6a4d381a9d631149dd34a04814367adfc1e6d2e7c572d3feb5237d74b
```

### Usage

Referenced by:
- `jag::Js5WorkerThread::Js5WorkerThread` at `<addr in DB>` and `<addr in DB>`

The Js5WorkerThread constructor stores pointers to these globals in the
Js5ResourceProvider object:
```
resourceProvider[0x10] = &<in Ghidra DB>;  // exponent (byte offset 0x80)
resourceProvider[0x11] = &<in Ghidra DB>;  // modulus  (byte offset 0x88)
```

### Verification flow (jag::Js5MasterIndex::Js5MasterIndex at <addr in DB>)

When the master index (index 255, archive 255) is received, `WorkerOnMessage`
(opcode 10 and opcode 0x28) calls `Js5MasterIndex::Js5MasterIndex(this, exponent_ptr, modulus_ptr)`.

The constructor:

1. Reads the version table data from the response packet
2. Extracts the trailing RSA-encrypted block (the whirlpool hash signature)
3. Loads the encrypted block into a BigInteger (`this_00`)
4. Performs RSA decryption: `result = data ^ exponent mod modulus` via `math::BigInteger::ModPow`
5. Converts the BigInteger result back to bytes
6. Expects exactly **0x41 (65) bytes**: 1 prefix byte + 64 bytes Whirlpool hash
7. Computes Whirlpool hash of the version table entries (CRC + version per index, 5 bytes each)
   using `<in Ghidra DB>` (Whirlpool init/update/finalize)
8. Compares the 64-byte Whirlpool hash from RSA decryption against the computed hash
   (byte-by-byte, 9 bytes per iteration, 0x40 total)
9. If match: proceeds to parse per-index entries (CRC, version, digest, sizes)
10. If mismatch: the master index is rejected

### Signature format

After RSA decryption (`encrypted_block ^ e mod n`), the expected plaintext is:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Prefix byte (value checked implicitly via length) |
| 1 | 64 | Whirlpool hash of the version table body |

Total: 65 bytes (0x41). Same raw format as the rs3linux download verification.

---

## 3. 512-bit Key (Unknown purpose)

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Exponent | `10001` (hex) |

### Modulus (hex)

```
ccd229d98f18b41132806b86674a4149a0fd48f534b2cf421587603087f72643
c393cd54e3e55994bb6828e2693e5af6b95a56b9e5cf92fc7520ef28baa6b6b7
```

Not referenced outside the init function. May be a legacy/unused key.

---

## 4. Decimal-format Key (Unknown purpose)

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Base | 10 (decimal, not hex) |

### Values (decimal)

- Exponent: `80782894952180643741752986186714059433953886149239752893425047584684715842049`
- Modulus: `7237300117305667488707183861728052766358166655052137727439795191253340127955075499635575104901523446809299097934591732635674173519120047404024393881551683`

Referenced by `<in Ghidra DB>` — purpose unknown. The decimal format and non-standard
exponent suggest this may be used for a different cryptographic purpose (not standard
RSA with e=65537).

---

## Patching Strategy for rs2client

The patcher must replace **two** RSA modulus strings in memory:

### Patch 1: Login RSA (1024-bit)
- Pattern: first 16+ chars of `9cbc5f910c473c62...`
- File offset: `<addr in DB>`
- Replace 256 hex chars with your 1024-bit modulus (must be exactly 256 hex chars / 128 bytes)

### Patch 2: JS5 Master Index RSA (4096-bit)
- Pattern: first 16+ chars of `e9b6a139afb361a6...`
- File offset: `<addr in DB>`
- Replace 1024 hex chars with your 4096-bit modulus (must be exactly 1024 hex chars / 512 bytes)

Both strings are in `.rodata`. Since rs2client is **not PIE** (ET_EXEC), the addresses are
fixed and the patcher can use either pattern matching or direct address patching.

The patcher needs to `mprotect` the `.rodata` page(s) to `PROT_READ|PROT_WRITE` before
modifying the strings, then restore to `PROT_READ`.

### Key generation

You need **two separate** RSA keypairs:
1. A **1024-bit** keypair for login RSA
2. A **4096-bit** keypair for JS5 master index verification

Both use public exponent `e = 0x10001` (65537).

For the JS5 master index, the server must sign the version table with:
```
signature = (0x00 || whirlpool_hash) ^ d mod n
```
where `d` is the 4096-bit private exponent, `n` is the 4096-bit modulus, and
`whirlpool_hash` is the 64-byte Whirlpool digest of the version table body.
