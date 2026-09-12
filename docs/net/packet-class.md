# jag::Packet Class

The `jag::Packet` class is the fundamental network I/O primitive used throughout the NXT client for reading and writing binary protocol data. It wraps a byte buffer with a position cursor, providing methods for reading/writing integers, strings, and raw byte arrays in various byte orderings.

## Struct Layout (32 bytes)

| Offset | Size | Type     | Name               | Description |
|--------|------|----------|--------------------|-------------|
| 0x00   | 8    | long     | refCountOrSharedPtr | Shared pointer or reference count for the backing Array |
| 0x08   | 8    | long     | arrayObj           | Pointer to the backing Array object (also used for capacity/bounds checking) |
| 0x10   | 8    | uchar *  | data               | Pointer to the raw byte data buffer |
| 0x18   | 8    | ulong    | pos                | Current read/write position in the data buffer |

Defined in Ghidra as struct `Packet` (32 bytes) in category `/jag`.

## PacketBit Sub-Structure (16 bytes)

Used for bit-level reading of packed data. Wraps a Packet with a separate bit position.

| Offset | Size | Type     | Name    | Description |
|--------|------|----------|---------|-------------|
| 0x00   | 8    | Packet * | packet  | Pointer to the parent Packet |
| 0x08   | 4    | uint     | bitPos  | Current bit position |

Defined in Ghidra as struct `PacketBit` (16 bytes) in category `/jag`.

## Naming Conventions

The method naming follows a consistent scheme:

- **`g`** = get (read from packet)
- **`p`** = put (write to packet)
- **Number** = byte count (e.g., `g3` = read 3 bytes, `p1` = write 1 byte)
- **`T`** = templated (generic read/write for a given type)
- **`s`** = signed return type
- **`Smart`** = variable-length encoding (1-or-2 or 2-or-4 bytes)
- **`alt`** + number = alternative byte ordering (obfuscation)
- **`LE`** = little-endian
- **`CP1252`** = Windows-1252 character encoding
- **`UTF8`** = UTF-8 character encoding

## Endianness Handling

All multi-byte reads/writes check the endianness flag at `<in Ghidra DB>`:
- If `<in Ghidra DB> == `<in Ghidra DB>` (little-endian system), byte-swap before reading/after writing
- The protocol uses big-endian (network byte order) by default

## Identified Methods

### Read Methods (Get)

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `gT_ushort`                     | `ushort gT_ushort(Packet *this)` | Reads 2-byte big-endian unsigned short, advances pos by 2 |
| <addr in DB> | `gT_uint`                       | `uint gT_uint(Packet *this)` | Reads 4-byte big-endian unsigned int, advances pos by 4 |
| <addr in DB> | `gT_ulong`                      | `ulong gT_ulong(Packet *this)` | Reads 8-byte big-endian unsigned long, advances pos by 8 |
| <addr in DB> | `g4_alt1`                       | `uint g4_alt1(Packet *this)` | Reads 4 bytes: b[0]<<8 + b[1] + b[2]<<24 + b[3]<<16 |
| <addr in DB> | `g4s_alt2`                      | `int g4s_alt2(Packet *this)` | Reads 4 bytes in LE order: b[0] + b[1]<<8 + b[2]<<16 + b[3]<<24 (signed) |
| <addr in DB> | `g4s_alt3`                      | `int g4s_alt3(Packet *this)` | Reads 4 bytes: b[0]<<16 + b[1]<<24 + b[2] + b[3]<<8 (signed) |

### Smart (Variable-Length) Methods

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `gSmart1or2`                    | `uint gSmart1or2(Packet *this)` | If high bit clear: 1 byte (0-127). Else: 2 bytes (ushort + 0x8000) |
| <addr in DB> | `gSmart2or4s`                   | `int gSmart2or4s(Packet *this)` | If high bit set: 4 bytes (& 0x7FFFFFFF). Else: 2 bytes. Returns -1 if 0x7FFF |
| <addr in DB> | `gSmart1or2s`                   | `int gSmart1or2s(Packet *this)` | If high bit clear: 1 byte minus 0x40 (signed). Else: 2 bytes + 0x4000 |

### String Methods

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `gStringCP1252ToUTF8`           | `void gStringCP1252ToUTF8(Packet *this, void *outString)` | Reads null-terminated CP1252 string, converts to UTF-8 |
| <addr in DB> | `gStringCP1252ToUTF8_basic_string` | `ulong gStringCP1252ToUTF8_basic_string(Packet *this, void *outString)` | Template variant for eastl::basic_string output. Returns string length |
| <addr in DB> | `pStringNoConversion`           | `void pStringNoConversion(Packet *this, void *eastlString)` | Writes EASTL string with null terminator, no charset conversion |

### Write Methods (Put)

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `p1`                            | `void p1(Packet *this, uchar value)` | Writes 1 byte, advances pos by 1 |
| <addr in DB> | `pT_ushort`                     | `void pT_ushort(Packet *this, ushort value)` | Writes 2-byte big-endian unsigned short |
| <addr in DB> | `p4_alt1`                       | `void p4_alt1(Packet *this, uint value)` | Writes 4 bytes: [b>>8, b&0xFF, b>>24, b>>16] |
| <addr in DB> | `pT_int`                        | `void pT_int(Packet *this, int value)` | Writes 4-byte big-endian int, byte-swaps on LE |
| <addr in DB> | `pT_long`                       | `void pT_long(Packet *this, long value)` | Writes 8-byte big-endian long, full byte-swap on LE |
| <addr in DB> | `pArrayBuffer`                  | `void pArrayBuffer(Packet *this, void *src, ulong length)` | Copies buffer to packet at pos; bounds-checks against arrayObj |
| <addr in DB> | `pSizeMarker`                   | `void pSizeMarker(Packet *this)` | Writes 2-byte zero placeholder (for later size fill-in) |
| <addr in DB> | `p4SizeMarker`                  | `void p4SizeMarker(Packet *this)` | Writes 4-byte zero placeholder (for later size fill-in). Not in parsed_functions.txt |

### Bit-Level Methods

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `Bit::gBit`                     | `uint gBit(PacketBit *this, uint numBits)` | Reads N bits from packet at current bit position |

### Crypto Methods

| Address    | Name                            | Prototype | Description |
|------------|----------------------------------|-----------|-------------|
| <addr in DB> | `tinyKeyEncrypt`                | `void tinyKeyEncrypt(Packet *this, int *key, long start, long end)` | XTEA block cipher encryption (32 Feistel rounds, delta 0x9E3779B9) |
| <addr in DB> | `rsaEncrypt`                    | `void rsaEncrypt(Packet *this, long *modulus, long *exponent)` | RSA encryption using BigInteger modular exponentiation |

## Inlined or Undiscovered Methods

The following methods from `parsed_functions.txt` were not found as standalone callable functions in this binary build.

### Confirmed Inlined (marked `[clone]` in parsed_functions.txt)

These are compiler-generated clones that were fully inlined at their call sites:

- `g3` - 3-byte read (seen inlined as: `b[0] + b[1]*0x100 + b[2]*`<in Ghidra DB>`)
- `gT<short>` - Signed 2-byte read (likely shares implementation with gT_ushort)
- `gT<int>` - Signed 4-byte read (likely shares implementation with gT_uint)
- `gT<float>` - Float read (4-byte BE read + reinterpret)
- `gTLE<ushort>` - Little-endian 2-byte read
- `g4s_alt1` - Signed alt byte order read (alt1 pattern)
- `pT<short>` - Signed 2-byte write (same implementation as pT_ushort)
- `pStringUTF8ToCP1252` - UTF-8 to CP1252 string write
- `tinyKeyDecrypt` - XTEA decryption
- `operator=` - Copy assignment
- Constructors (`Packet(void)`, `Packet(ulong)`, `Packet(Packet const&)`, etc.)
- Destructor (`~Packet`)

### Not Found Despite Not Being Clones

These methods are NOT marked `[clone]` in `parsed_functions.txt`, suggesting they should exist as standalone functions, but they could not be located through behavioral analysis, caller tracing, or address-range scanning. They may exist at addresses not yet explored, or may have been optimized/merged by the linker.

- `g2sArrLE(short*, ulong)` - Reads an array of little-endian signed shorts into a buffer
- `gArrayBuffer(jag::Packet&, ulong)` - Copies data from this packet into a destination Packet
- `Packet(jag::shared_ptr<jag::Array<uchar>> const&)` - Constructor from shared_ptr to Array
- `Packet(void)` - Default constructor

## Alternative Byte Orderings

The protocol uses several byte ordering schemes for obfuscation. The "alt" variants rearrange bytes compared to standard big-endian:

| Name    | Byte Order                                    | Standard BE Equivalent |
|---------|----------------------------------------------|----------------------|
| (none)  | b[0]<<24 + b[1]<<16 + b[2]<<8 + b[3]       | Big-endian (standard) |
| alt1    | b[0]<<8 + b[1] + b[2]<<24 + b[3]<<16       | Swap within each 16-bit half |
| alt2    | b[0] + b[1]<<8 + b[2]<<16 + b[3]<<24       | Little-endian |
| alt3    | b[0]<<16 + b[1]<<24 + b[2] + b[3]<<8       | Swap halves, swap within halves |

## Usage Pattern

```c
// Reading from a ServerProt packet:
uint itemId = jag::Packet::gT_uint(packet);
ushort slot = jag::Packet::gT_ushort(packet);
int amount = jag::Packet::gSmart2or4s(packet);
jag::Packet::gStringCP1252ToUTF8(packet, &nameString);

// Writing to a ClientProt packet:
jag::Packet::p1(packet, opcode);
jag::Packet::pT_ushort(packet, interfaceId);
jag::Packet::pT_int(packet, targetIndex);
jag::Packet::pStringNoConversion(packet, &playerName);
jag::Packet::pArrayBuffer(packet, buffer, bufferLen);

// Crypto (login flow):
jag::Packet::rsaEncrypt(packet, &modulus, &exponent);
jag::Packet::tinyKeyEncrypt(packet, xteaKey, startPos, endPos);
```

## Cross-References

- **Engine Offsets**: Not directly in `Offsets.kt` (Packet is used through function hooking, not field access)
- **Key Callers**: `jag::ConnectionManager::TcpIn` (server message dispatch), all ServerProt decoders, ClientProt message builders
- **Bit-level Usage**: `jag::PlayerList::GetHighResolutionPlayerPosition`, `jag::PlayerList::GetLowResolutionPlayerPosition`
- **Crypto Usage**: Login packet building (XTEA + RSA encryption)
