# Buffer Transform ↔ Disassembly Pattern Table (NXT packet RE)

**Purpose.** When reverse-engineering a packet handler in `rs2client`, the decompiled body shows how the
client READS each field off its `Packet`. To implement the server side correctly you must map each
decompiled read to the exact `world.gregs.voidps.buffer` write function (`JagExtensions` / `BufferWriter`).
This table is the canonical mapping. Use it for **100% accuracy** — guessing a transform from a raw wire
byte is how the REBUILD map-size byte got mislabelled a magic `0x85` constant when it is `writeByteAdd(5)`,
and how OBJ_ADD's `objId` low byte was missed.

> Server `write*` and client `read*` are inverses: a field the server emits with `writeX(v)` must be the
> field the client recovers with the matching `readX`. The rows below pair them and give the decompiled
> C / asm shapes Ghidra produces for the client read.

---

## 0. THE mod-256 PRINCIPLE (read this first)

`+0x80` and `−0x80` are the **same operation mod 256** (`x + 0x80 ≡ x − 0x80`). So the decompiler renders
the "add 128" transform sometimes as `byte + 0x80` and sometimes as `byte - 0x80` — they are identical.
**Never** infer the transform from the *sign* of the 0x80. Infer it from the SHAPE:

| Decompiled shape (let `b` = the freshly-read byte) | Transform | Server write |
|---|---|---|
| `b` used raw (`(char)b`, `b & 0xff`) | none | `writeByte` |
| `b ± 0x80`  — *b is positive, 0x80 added/subtracted* | ADD | `writeByteAdd` |
| `±0x80 − b`  — *b is subtracted FROM ±0x80* (`0x80 - b`, `-0x80 - b`) | SUBTRACT | `writeByteSubtract` |
| `−b`  — *b negated, no 0x80* (`-b`, `0 - b`, `(char)(0x100 - b)`) | INVERSE | `writeByteInverse` |

Decision: is the byte **negated**? No, but combined with 0x80 → **Add**. Yes, with 0x80 → **Subtract**.
Yes, without 0x80 → **Inverse**. Neither → **raw**.

Recover the server-side `v` you must pass: `writeByteAdd` wire `w` ⇒ `v = (w − 0x80) & 0xff`;
`writeByteSubtract` ⇒ `v = (0x80 − w) & 0xff`; `writeByteInverse` ⇒ `v = (−w) & 0xff`. (REBUILD: wire
`0x85` under the Add shape ⇒ `v = 0x85 − 0x80 = 5` = map-size index 5.)

---

## 1. Single byte

| Server write (value `v`) | Wire byte | Client read fn | Decompiled / asm read shapes |
|---|---|---|---|
| `writeByte(v)` | `v` | `readByte` (signed) / `readUnsignedByte` | `(char)b` ; `b & 0xff` ; `MOVSX`/`MOVZX r, byte ptr` |
| `writeByteAdd(v)` | `(v+0x80)&0xff` | `readByteAdd` | `(char)(b - 0x80)` ; `b + 0x80` ; `MOVZX; ADD/SUB 0x80` |
| `writeByteSubtract(v)` | `(0x80−v)&0xff` | `readByteSubtract` | `(char)(0x80 - b)` ; `(char)(-0x80 - b)` ; `NEG; ADD 0x80` |
| `writeByteInverse(v)` | `(−v)&0xff` | `readByteInverse` | `-(char)b` ; `0 - b` ; `NEG r` (no 0x80) |

## 2. Short (2 bytes) — endianness × which byte carries the ±0x80

Read as two bytes `b0` (first on wire) then `b1`. BE = `(b0<<8)|b1`. LE = `b0|(b1<<8)`.

| Server write | Wire `[first,second]` | Client read fn | Decompiled shape |
|---|---|---|---|
| `writeShort(v)` (BE) | `[v>>8, v]` | `readShort` / `readUnsignedShort` | `(b0<<8)|(b1&0xff)` ; 16-bit load + `BSWAP`/`ROL 8` |
| `writeShortLittle(v)` (LE) | `[v, v>>8]` | `readShortLittle` | `b0|(b1<<8)` ; bare 16-bit load (no BSWAP) |
| `writeShortAdd(v)` (BE, lo+0x80) | `[v>>8, (v+0x80)&0xff]` | `readShortAdd` | `(b0<<8)|((b1-0x80)&0xff)` — **high byte raw, low byte has the Add shape** |
| `writeShortAddLittle(v)` (LE, lo+0x80) | `[(v+0x80)&0xff, v>>8]` | `readShortAddLittle` | `((b0-0x80)&0xff)|(b1<<8)` — **first byte Add, second raw high** |

> Tell BE vs LE by the shift on the FIRST read byte: first byte `<<8` ⇒ big-endian; first byte un-shifted
> (the `|` term with no shift) ⇒ little-endian. The `±0x80` on exactly one byte ⇒ the `*Add` variant.

## 3. Medium (3) & Int (4 bytes)

| Server write | Wire byte order (B3=MSB…B0=LSB) | Client read fn | Decompiled shape |
|---|---|---|---|
| `writeMedium(v)` | `[B2,B1,B0]` | `readMedium`/`readUnsignedMedium` | `(b0<<16)|(b1<<8)|b2` |
| `writeInt(v)` (BE) | `[B3,B2,B1,B0]` | `readInt` | `(b0<<24)|(b1<<16)|(b2<<8)|b3` ; 32-bit load + `BSWAP` |
| `writeIntLittle(v)` (LE) | `[B0,B1,B2,B3]` | `readIntLittle` | `b0|(b1<<8)|(b2<<16)|(b3<<24)` ; bare 32-bit load |
| `writeIntMiddle(v)` | `[B1,B0,B3,B2]` | `readUnsignedIntMiddle` | `(b0<<8)|b1|(b2<<24)|(b3<<16)` |
| `writeIntInverseMiddle(v)` | `[B2,B3,B0,B1]` | `readIntInverseMiddle` | `(b0<<16)|(b1<<24)|b2|(b3<<8)` |
| `writeIntInverse(v)` | `[B1,B3,B2, (−B0)&0xff]` | (custom) | `(b0<<8)|(b1<<24)|(b2<<16)|(-b3)` — last byte has the **Inverse** shape |
| `writeIntInverseLittle(v)` | `[(−B0)&0xff,B1,B2,B3]` | (custom) | first byte Inverse, then `(b1<<8)|(b2<<16)|(b3<<24)` |

> `writeIntMiddle`/`writeIntInverseMiddle` are the RS "alt3"/middle-endian ints (used by VARP_LARGE,
> CLIENT_SETVARC_LARGE, OBJ-family). Identify by the scrambled `<<8/<<16/<<24` order, NOT a clean BSWAP.

## 4. Smart / BigSmart (variable length)

| Client read fn | Decompiled shape (peek = first byte) | Meaning |
|---|---|---|
| `readSmart` | `if ((char)peek < 0) { (peek<<8|b1) - 0x8000 } else peek` (peek compared to 0x80 / sign) | 1 byte if <128 else 2 bytes − 0x8000 |
| `readBigSmart` | `if ((char)peek < 0) { (4-byte) & 0x7fffffff } else { (peek<<8|b1); 0x7fff⇒-1 }` | 2 or 4 bytes; high bit of first byte selects width |
| `readLargeSmart` | loop of `readSmart` accumulating while `==0x7fff` | sum of smarts |

The signature is a **branch on the sign / `< 0x80` of the first byte** before deciding to read more.

## 5. String, bits, bytes

| Client read fn | Decompiled shape |
|---|---|
| `readString` (CP1252) | loop reading bytes until `== 0` (null terminator), then CP1252 decode (`<in Ghidra DB>`) |
| jstr2 / "+128" string | same as above but each char is `b - 0x80` (Add shape per char) before the terminator |
| `readBits(n)` (gBit) | bit cursor arithmetic: `bitPos>>3`, `8 - (bitPos & 7)`, mask `(1<<n)-1`, shift+OR loop |
| `readBytes` | `memcpy` / bulk copy of N raw bytes |

> Bit-domain (`startBitAccess`/`readBits`) and byte-domain reads do not mix mid-field: a handler
> `byte-aligns` (`position = (bitPos+7)>>3`) before switching to byte reads (see PLAYER_INFO/NPC_INFO).

---

## 6. Worked examples (from this project's RE)

* **REBUILD_NORMAL map-size** — handler: `DAT = b + 0x80`. Add shape ⇒ `writeByteAdd`. Wire `0x85` ⇒
  `v = 0x85 − 0x80 = 5` (map-size index 5). NOT a magic `0x85` constant.
* **OBJ_ADD (op46)** — handler reads `[g1 packedCoord][g2 count][objIdHi raw][objIdLo: b - 0x80]`. The
  objId low byte's `b - 0x80` is the Add shape ⇒ `writeShortAdd(objId)` (hi raw, lo `writeByteAdd`).
* **op78 UPDATE_ZONE** — level `(b + 0x80)` = Add ⇒ `writeByteAdd`; zoneY `(char)(-0x80 - b)` = Subtract
  ⇒ `writeByteSubtract`; zoneX raw ⇒ `writeByte`. (X and Y differ — confirm each axis separately.)
* **UPDATE_STAT (op44)** — xp `b0|b1<<8|b2<<16|b3<<24` = LE ⇒ `writeIntLittle`; skillId `-b` = Inverse ⇒
  `writeByteInverse`.

## 7. Workflow

1. Decompile the client handler; for each `Packet` read, note the byte(s) consumed and the arithmetic.
2. Match the SHAPE against §0–§5 (negated? combined with 0x80? endianness? scrambled order?).
3. Pick the inverse `write*`; recover the server `v` with the formula in §0 if a constant is involved.
4. Cross-check against a live capture byte when one exists — the wire byte must equal `write*(v)`.
