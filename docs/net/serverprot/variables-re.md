# Variable Setter Packet Formats (RE-verified, rev 946)

All byte transforms verified from rs2client binary via Ghidra decompilation.

## Byte Transform Reference

| Transform | Wire bytes → Value | Server Write |
|-----------|-------------------|--------------|
| g1 | `b[0]` | `p1(v)` |
| g1(-128) | `b[0] - 128` (sign-extend) | `p1(v + 128)` |
| g1(0x80-raw) | `128 - b[0]` (sign-extend) | `p1(128 - v)` |
| g1(negate) | `-b[0]` (sign-extend) | `p1(-v)` |
| g2BE | `b[0]<<8 \| b[1]` | `p2(v)` |
| g2LE | `b[1]<<8 \| b[0]` | `p2LE(v)` |
| g2(lo-128) | `b[0]<<8 \| ((b[1]-128)&0xFF)` | `p1(v>>8); p1((v&0xFF)+128)` |
| g4BE | `b[0]<<24 \| b[1]<<16 \| b[2]<<8 \| b[3]` | `p4(v)` |
| g4_alt1 | `b[0]<<8 \| b[1] \| b[2]<<24 \| b[3]<<16` | `p1(v>>8); p1(v); p1(v>>24); p1(v>>16)` |
| g4_alt2 | `b[0] \| b[1]<<8 \| b[2]<<16 \| b[3]<<24` (LE) | `p4LE(v)` |
| g4_alt3 | `b[1]<<24 \| b[0]<<16 \| b[3]<<8 \| b[2]` | `p1(v>>16); p1(v>>24); p1(v); p1(v>>8)` |
| g8BE | standard big-endian 64-bit | `p8(v)` |

## Opcode 14 — SET_VARP_SMALL (3 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-1 | g2(lo-128) | varpId |
| 2 | g1(-128) | value (signed byte) |

## Opcode 124 — SET_VARP_INT (6 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-1 | g2LE | varpId |
| 2-5 | g4_alt1 | value (int32) |

## Opcode 138 — SET_VARP_LONG (10 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-7 | g8BE | value (int64) — **value comes FIRST** |
| 8-9 | g2(lo-128) | varpId |

## Opcode 12 — SET_VARC_INT (6 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-1 | g2BE | varcId |
| 2-5 | g4_alt2 (LE) | value (int32) |

## Opcode 19 — SET_VARC_SMALL (3 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0 | g1(0x80-raw) | value (signed byte) — **value comes FIRST** |
| 1-2 | g2BE | varcId |

## Opcode 114 — UPDATE_STAT (6 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-3 | g4_alt1 | xp (unsigned, capped at 200M / 2B for elite) |
| 4 | g1(-128) | boostedLevel |
| 5 | g1(negate) | statId |

## Opcode 115 — RESET_VARC_INT (6 bytes)

| Offset | Read | Field |
|--------|------|-------|
| 0-1 | g2BE | varcId |
| 2-5 | g4_alt3 | value (int32) |

## Opcode 60 — RESET_VARC_SMALL (var_byte)

| Offset | Read | Field |
|--------|------|-------|
| 0 | g1(negate) | value (signed byte) — **value comes FIRST** |
| 1-2 | g2BE | varcId |

## Opcode 112 — RESET_ALL_VARPS (0 bytes)

No payload. Clears all player varps and client varcs.
