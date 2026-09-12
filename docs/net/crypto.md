# Network Cryptographic Primitives

The NXT client uses three cryptographic primitives for its network protocol:
**ISAAC** (stream cipher), **XTEA** (block cipher, called "tinyKey"), and
**RSA** (asymmetric encryption). This document describes each algorithm's
implementation, data structures, and role in the login/communication flow.

---

## ISAAC Stream Cipher

ISAAC (Indirection, Shift, Accumulate, Add, and Count) is a fast
cryptographically secure PRNG used for **opcode encryption** in the
client-server protocol.

### Purpose

After login, both client and server maintain synchronized ISAAC instances.
Each outgoing opcode byte is encrypted by adding the next ISAAC value:

```
encrypted_opcode = raw_opcode + Isaac::TakeNextValue
```

The server decrypts by subtracting. A separate ISAAC instance (seeded with
a modified key) decrypts incoming server opcodes.

### State Structure

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0x000 | 4 | uint | randcnt | Remaining values before next Generate |
| 0x004 | 1024 | uint[256] | randrsl | Result array returned by TakeNextValue |
| 0x404 | 1024 | uint[256] | randmem | Internal state array |
| 0x804 | 4 | uint | randa | Accumulator (mixed via shifts) |
| 0x808 | 4 | uint | randb | Running sum |
| 0x80C | 4 | uint | randc | Generation counter |

**Total size: 0x810 (2064) bytes** -- confirmed by `operator_new(0x810)` in
the login builder.

**Ghidra struct:** `Isaac` in category `/jag`

### Functions

| Address | Name | Prototype |
|---------|------|-----------|
| <addr in DB> | `jag::Isaac::Init` | `void Init(Isaac *this, int *seed)` |
| <addr in DB> | `jag::Isaac::Generate` | `void Generate(Isaac *this)` |
| <addr in DB> | `jag::Isaac::TakeNextValue` | `uint TakeNextValue(Isaac *this)` |

### Init Algorithm

1. Zero all fields: `randcnt = 0`, `randa = randb = randc = 0`,
   `randrsl[0..255] = 0`, `randmem[0..255] = 0`
2. Copy first 4 seed values into `randrsl[0..3]`
3. Initialize 8 mixing variables from the golden ratio `0x9E3779B9`,
   pre-mixed through 4 rounds (values: `<in Ghidra DB>`, `<in Ghidra DB>`,
   `<in Ghidra DB>`, `<in Ghidra DB>`, `<in Ghidra DB>`, `<in Ghidra DB>`, `<in Ghidra DB>`,
   `<in Ghidra DB>`)
4. **Pass 1:** Mix seed values (from `randrsl`) into `randmem`, 8 elements
   at a time, using the standard ISAAC mixing function with alternating
   shifts (`<<13`, `>>6`, `<<2`, `>>16`, `<<8`, `>>9`)
5. **Pass 2:** Mix `randmem` values into itself using the same mixing
   function
6. Call `Generate` to fill `randrsl` with initial pseudo-random values
7. Set `randcnt = 256` so the first `TakeNextValue` returns immediately

### Generate Algorithm

1. Increment `randc` by 1
2. Add `randc` to `randb` (running sum)
3. For each index `i` in `0..255`:
   - Mix `randa` using the shift pattern based on `i % 4`:
     - `i % 4 == 0`: `randa ^= randa << 13`
     - `i % 4 == 1`: `randa ^= randa >> 6`
     - `i % 4 == 2`: `randa ^= randa << 2`
     - `i % 4 == 3`: `randa ^= randa >> 16`
   - `randa += randmem[(i + 128) & 0xFF]`
   - `x = randmem[i]`
   - `randmem[i] = randa + randb + randmem[(x >> 2) & 0xFF]`
   - `randb = x + randmem[(randmem[i] >> 10) & 0xFF]`
   - `randrsl[i] = randb`

### TakeNextValue

1. If `randcnt > 0`: decrement `randcnt`, return `randrsl[randcnt]`
2. If `randcnt == 0`: call `Generate` inline, set `randcnt = 255`,
   return `randrsl[255]`

### Login Seeding

During login (in `jag::LoginManager::SendLoginPacketInner` at `<addr in DB>`):

1. Generate 4 random seed ints (from `/dev/urandom` or `std::random_device`)
2. Create client-to-server Isaac: `Init(isaac_out, seed[0..3])`
3. Create server-to-client Isaac with modified seed:
   `seed[i] += delta[i]` where deltas are at `<addr in DB>`
   (a fixed 4-int delta added to derive the server's key from the client's)
4. Store `isaac_out` at connection+0x40, `isaac_in` at connection+0x2B8

### ISAAC Delta Constants (VERIFIED — rs2client rev 946)

Address: `<addr in DB>` in `.rodata` (4 consecutive int32 values, little-endian)
Xref: READ from `SendLoginPacketInner` at `<addr in DB>`

| Index | Decimal | Hex |
|-------|---------|-----|
| delta[0] | 50 | <addr in DB> |
| delta[1] | 50 | <addr in DB> |
| delta[2] | 50 | <addr in DB> |
| delta[3] | 50 | <addr in DB> |

All four deltas are the same value: **50**. This is the classic RuneScape ISAAC delta.

The Ghidra decompilation shows the seeding as:
```c
// First ISAAC: client-to-server (raw XTEA key as seed)
Isaac::Init(isaac_out, &this->field_0x48);

// Second ISAAC: server-to-client (XTEA key + deltas)
modified_seed[0] = this->field_0x48 + _DAT_00dc8090;   // + 50
modified_seed[1] = this->field_0x4c + _UNK_00dc8094;   // + 50
modified_seed[2] = this->field_0x50 + _UNK_00dc8098;   // + 50
modified_seed[3] = this->field_0x54 + _UNK_00dc809c;   // + 50
Isaac::Init(isaac_in, modified_seed);
```

**Server implementation note:** The server receives the 4 XTEA key ints from
the RSA-decrypted login block. To create matching ISAAC ciphers:
- Server recv cipher (decrypts client->server): `Init(seed[0..3])` (raw key)
- Server send cipher (encrypts server->client): `Init(seed[i] + 50)` (key + delta)

---

## XTEA Block Cipher ("tinyKey")

XTEA (eXtended Tiny Encryption Algorithm) is used for **encrypting
credential blocks** in login packets. The codebase calls it "tinyKey".

### Purpose

The login packet contains sensitive data (XTEA key material, credentials)
that is encrypted with XTEA before being wrapped in the RSA block. The
4-int XTEA key is generated from the Isaac PRNG and shared with the server
inside the RSA-encrypted portion.

### Algorithm Parameters

| Parameter | Value |
|-----------|-------|
| Block size | 64 bits (two 32-bit halves) |
| Key size | 128 bits (4 x 32-bit ints) |
| Rounds | 32 (Feistel rounds) |
| Delta | `0x9E3779B9` (derived from golden ratio) |
| Sum range | `<addr in DB>` to `<in Ghidra DB>` (`32 * delta`) |

### Functions

| Address | Name | Prototype |
|---------|------|-----------|
| <addr in DB> | `jag::Packet::tinyKeyEncrypt` | `void tinyKeyEncrypt(long packet, int *key, long startOffset, long endOffset)` |

**Note:** No standalone `tinyKeyDecrypt` function was found in the client
binary. The client only encrypts; the server handles decryption. The
ground-truth symbols indicate a decrypt clone exists in the debug build at
a different address, but it may be compiled out or inlined in the release
build.

### Encrypt Implementation

The function operates on the Packet buffer between `startOffset` and
`endOffset`, processing 8-byte blocks:

1. For each 8-byte block:
   - Read two 32-bit values (`v0`, `v1`)
   - If little-endian: byte-swap both values to big-endian
   - Initialize `sum = 0`
   - Execute 32 Feistel rounds (unrolled 4x, 8 loop iterations):
     ```
     sum += delta
     v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (key[sum & 3] + sum)
     v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (key[(sum >> 11) & 3] + sum)
     ```
   - If little-endian: byte-swap results back
   - Write encrypted values back to buffer

### Endianness

The endianness marker at `<in Ghidra DB>` is checked: if `<in Ghidra DB>`
(little-endian), values are byte-swapped before and after encryption to
ensure the XTEA operates on big-endian data regardless of platform.

### Usage Sites

| Address | Function | Context |
|---------|----------|---------|
| <addr in DB> | SendLoginPacketInner (lobby) | Encrypts login credentials |
| <addr in DB> | Login builder (game world) | Encrypts login credentials |
| <addr in DB> | Direct login builder | Encrypts auth data |
| <addr in DB> | CS2 opcode handler | Encrypts chat/command messages |
| <addr in DB> | CS2 opcode handler | Encrypts messages |
| <addr in DB> | CS2 opcode handler | Encrypts messages with length prefix |

---

## RSA Encryption

RSA is used to **securely transmit the XTEA key** to the server during
login. The client encrypts the XTEA key block with the server's public RSA
key, ensuring only the server can read the key material.

### Purpose

The login handshake works as follows:
1. Client generates 4 random XTEA key ints
2. Client writes the XTEA key (and other sensitive data) into a block
3. Client RSA-encrypts this block with the server's public key
4. Client XTEA-encrypts the remaining login data with the generated key
5. Client sends the packet: RSA block first, then XTEA block

The server RSA-decrypts to recover the XTEA key, then XTEA-decrypts the
remainder.

### BigInteger Implementation

The client uses a custom BigInteger library (not OpenSSL) for RSA math.
Each BigInteger is **0x18 (24) bytes** and is heap-allocated.

| Address | Name | Purpose |
|---------|------|---------|
| <addr in DB> | `jag::math::BigInteger::BigInteger` | Default constructor |
| <addr in DB> | `jag::math::BigInteger::~BigInteger` | Destructor |
| <addr in DB> | `jag::math::BigInteger::FromBytes` | Convert byte array to BigInteger |
| <addr in DB> | `jag::math::BigInteger::ModPow` | `result = base^exp mod mod` |
| <addr in DB> | `jag::math::BigInteger::BitLength` | Number of significant bits |
| <addr in DB> | `jag::math::BigInteger::DivMod` | Division with remainder |

### Functions

| Address | Name | Prototype |
|---------|------|-----------|
| <addr in DB> | `jag::Packet::rsaEncrypt` | `void rsaEncrypt(long packet, long *modulus, long *exponent)` |

### rsaEncrypt Flow

1. Create BigInteger from packet data bytes (`FromBytes`)
2. Allocate result BigInteger
3. Perform modular exponentiation: `result = data^exponent mod modulus`
   (`ModPow`)
4. If ModPow fails (returns non-zero), create empty result
5. Calculate output byte length from `BitLength`
6. Extract individual bytes via repeated `DivMod` by 256
7. Reverse byte array (BigInteger extracts LSB-first, output needs
   MSB-first)
8. Write to packet: `pT_ushort(length + 1)`, `byte(0)`, `bytes[...]`
9. Clean up all BigInteger temporaries

### RSA Key Storage

The RSA public key (modulus and exponent) are stored as global BigInteger
pointers:
- Modulus pointer: `<in Ghidra DB>`
- Exponent pointer: `<in Ghidra DB>`

These are passed to `rsaEncrypt` during login at `<addr in DB>`:
```c
rsaEncrypt(packet, &<in Ghidra DB>, &<in Ghidra DB>);
```

---

## Login Crypto Flow Summary

```
1. Generate 4 random ints as XTEA seed
2. Write XTEA seed into RSA block
3. RSA-encrypt the block:    rsaEncrypt(packet, rsa_mod, rsa_exp)
4. XTEA-encrypt credentials: tinyKeyEncrypt(packet, xtea_key, start, end)
5. Send login packet
6. On success:
   a. Create client Isaac:  Init(isaac_out, seed)
   b. Modify seed:          seed[i] += delta[i]
   c. Create server Isaac:  Init(isaac_in, modified_seed)
   d. Store at connection+0x40 (out) and connection+0x2B8 (in)
7. All subsequent opcodes encrypted with Isaac
```

---

## Ghidra Documentation Status

All functions listed above have been:
- Renamed with full namespace paths in Ghidra
- Prototyped with correct parameter types
- Commented at entry points with algorithm descriptions
- Organized in proper namespace hierarchies:
  - `jag::Isaac::` -- ISAAC cipher
  - `jag::Packet::` -- XTEA and RSA packet operations
  - `jag::math::BigInteger::` -- Arbitrary precision arithmetic
  - `jag::ConnectionManager::` -- Isaac-based opcode encryption helpers

The `Isaac` struct (2064 bytes) has been created in Ghidra under `/jag`
with all 6 fields documented.
