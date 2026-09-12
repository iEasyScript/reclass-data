# Cross-Architecture Porting: Desktop (x86-64) → Mobile (AArch64)

**Read this before using any desktop finding.** The Project X project represents a large investment in
reverse engineering the desktop `rs2client`. Most of that knowledge is reusable here. Some of it is
actively dangerous here. This document draws the line.

## The core fact

The mobile client is the **same NXT engine as desktop**, recompiled for AArch64 by NDK r28c Clang.
Same source, different machine code. `[VERIFIED — artifact]`

Everything below follows from that.

## What ports

| Category | Confidence | Why |
|---|---|---|
| Wire protocol — opcodes, packet names, field order, sizes, transforms, endianness | High | Defined by source, not ISA |
| ISAAC / RSA / XTEA usage | High | Same |
| Cache and JS5 formats | High | Same |
| Class/namespace organization (`jag::*`), method names, call-graph shape | High | Same |
| `.rodata` algorithm constants — RSA moduli, ISAAC constants, CRC tables, magic bytes | High | Data, not code. **ISA-independent.** |
| String literals | High | Identical. **The strongest anchor available.** |

## What does NOT port

| Category | Why |
|---|---|
| **Byte-pattern signatures** | An x86-64 sig is meaningless in AArch64. Never run a desktop sig against this target. |
| **Addresses** | Different image, different layout. |
| **Function sizes, prologue/epilogue shape, register allocation** | Different compiler, different ISA. |
| **Inlining decisions** | A helper inlined on desktop may be a real call on mobile, and vice versa. |
| **Calling conventions** | `__thiscall`/`__cdecl`/`__fastcall` are x86 concepts and do not exist on AArch64. Use `default`. |

## The subtle one: struct field offsets

**Probably port. Must be verified per-struct. Never assume.**

Both targets are **LP64** — 64-bit pointers, same integer widths, broadly the same alignment rules. A struct
laid out from the same source will *usually* have identical offsets on both.

This makes desktop offsets an **excellent hypothesis generator and a terrible source of truth.**

Divergence is possible via:
- arch-specific `#ifdef`s in the source
- differing vtable layout or base-class padding
- ABI edge cases — bitfields, `long double`, over-aligned types, empty base optimization

**Procedure:** use the desktop offset to *predict* where a field sits, then **confirm against the mobile
target's own field-access patterns** before committing anything to Ghidra. Cite both halves:

```
[Predicted from desktop OClient.PLAYER_MANAGER=`<in Ghidra DB>`; CONFIRMED in mobile
```

The prediction alone is never sufficient. A desktop offset with no mobile confirmation is tagged
`[PREDICTED FROM DESKTOP — UNVERIFIED ON MOBILE]` and is **not a fact**.

## How to locate a known-from-desktop function in the mobile target

Byte sigs don't cross the ISA boundary, so use these instead, in priority order:

1. **String xrefs — BEST.** String literals are identical across builds.
   `list_strings(filter="…")` → `get_xrefs_to(string_addr)` → you are inside the function. This is why the
   log format strings in `binary/target-binary.md` are so valuable.
2. **ISA-independent constant sigs.** RSA moduli, ISAAC constants, CRC tables, magic bytes live in `.rodata`
   and are byte-identical across arch. `search_memory_pattern(executable_only=False)` then xref to code.
   **This is the one place a desktop-derived byte pattern legitimately ports.**
3. **Import/PLT anchoring.** Both builds call `memcpy`, `malloc`, curl, BoringSSL. Find the import, xref it,
   narrow by surrounding structure.
4. **Call-graph shape.** With two or three anchors established, the functions between them are constrained
   by who-calls-whom.
5. **Behavioral/structural equivalence.** Same switch arity, same field-access pattern, same constant set,
   same control-flow shape.

**Anti-pattern:** taking a working x86-64 signature from the Project X project and running
`search_memory_pattern` with it here. It returns nothing, or worse, a coincidental match.

## AArch64 specifics

### AAPCS64 calling convention

- Integer/pointer args in `X0`–`X7`; further args on the stack. `W0`–`W7` are 32-bit views.
- Return in `X0` (`X1` too for 128-bit).
- **`X8` is the indirect result register** — a function returning a large struct by value takes a hidden
  pointer in `X8`, *not* `X0`. If a "void" function writes through `X8`, it returns a struct by value.
- **`this` is `X0`** on C++ member functions; other args shift to `X1`+.
- FP/SIMD args/returns in `V0`–`V7`; `V8`–`V15` callee-saved (low 64 bits only).
- Callee-saved `X19`–`X28`; frame pointer `X29`; link register `X30`; `SP` 16-byte aligned.
- **No `__thiscall`.** Set Ghidra's calling convention to `"default"`.

### Instruction encoding and sig-scanning

AArch64 instructions are **fixed 4 bytes, little-endian encoded**. Therefore:

1. **Patterns must be 4-byte aligned and a multiple of 4 bytes.**
2. **Specificity per byte is lower than x86.** 16 bytes is only 4 instructions. Use **24–48 bytes (6–12
   instructions)**.
3. **Wildcard at instruction granularity** — wildcard the whole 4-byte instruction (`?? ?? ?? ??`) when it
   contains any address or large immediate, rather than trying to mask a field inside it.

**Wildcard these entirely:**

| Instruction | Encoding note | Why |
|---|---|---|
| `BL <label>` | bits 31–26 = `100101`; top byte `0x94`–`0x97` | 26-bit relative target varies |
| `B <label>` | bits 31–26 = `000101`; top byte `0x14`–`0x17` | same |
| `B.cond` / `CBZ` / `CBNZ` / `TBZ` / `TBNZ` | — | relative targets vary |
| `ADRP Xd, <page>` | bit 31=1, bits 28–24=`10000`; top byte `0x90`/`0xB0`/`0xD0`/`0xF0` | 21-bit page offset varies |
| `ADD Xd, Xn, #imm` completing an ADRP pair | — | `#imm` is the low 12 bits of an address |
| `LDR Xd, [Xn, #imm]` completing an ADRP+LDR GOT access | — | same |
| `MOVZ`/`MOVK` sequences building an absolute | — | varies when it's an address |

**ADRP+ADD / ADRP+LDR is the AArch64 equivalent of x86 RIP-relative addressing.** Where the desktop
guidance says "wildcard the 4 bytes after `48 8B 05`", here it's "wildcard both instructions of the ADRP
pair." To resolve what a pair points at, use `get_xrefs_from` on the ADRP address — Ghidra resolves it for
you — rather than decoding the immediate by hand.

**Keep these — they give a pattern its identity:**
- Register-to-register arithmetic/logic with fixed registers (`ADD X0, X1, X2`, `EOR W3, W3, W4`)
- Small literal immediates that are algorithm constants (`CMP W0, #0x80`, `AND W1, W1, #0x7F`)
- `REV`/`REV16`/`REV32` byte-swaps — very characteristic of packet code
- Shifts/bitfield ops (`LSL`, `LSR`, `UBFX`, `SBFX`, `BFI`)
- Load/store with small fixed offsets (`LDRB W0, [X1, #4]`) — struct field access

**BTI note:** NDK r28c may emit `BTI c` (`hint #34`, encoded `5f 24 03 d5`) at indirect-branch targets,
making prologues even less distinctive than usual. **Take signatures from the middle of a function body,
never the prologue.**

### Reading inlined `jag::Packet` helpers

The **semantics are identical** to desktop; the **assembly shapes are not**.

| Operation | AArch64 shape |
|---|---|
| `g1` (read u8) | `LDRB Wd, [Xbuf, Xpos]`, position `+1` |
| `g2` (read u16 BE) | `LDRH Wd, [...]` then **`REV16 Wd, Wd`**, position `+2` |
| `g4` (read u32 BE) | `LDR Wd, [...]` then **`REV Wd, Wd`**, position `+4` |
| `g8` (read u64 BE) | `LDR Xd, [...]` then **`REV Xd, Xd`**, position `+8` |
| LE reads (`gTLE`, `g4_alt1`) | **no REV** — LE is native on AArch64, same as x86 |
| `gSmart1or2` | `LDRB` + `TBNZ`/`CMP #0x80` branch on the high bit |
| byte transforms | `SUB`/`ADD Wd, Wd, #0x80`, or `NEG Wd, Wd` |

**`REV` is the single best signal that a big-endian multi-byte network field is being read or written.** Its
presence or absence distinguishes BE from LE fields directly.

### The mod-256 trap (unchanged from desktop — still applies)

`+0x80` and `-0x80` are **identical mod 256**, so the decompiler renders the same ADD transform as either.
**Never infer the transform from the sign of the 0x80** — infer it from the shape (`b` = the freshly-read
byte):

| Decompiled shape | Transform |
|---|---|
| `b` used raw | none |
| `b ± 0x80` — b positive, 0x80 added/subtracted | **ADD** (`readByteAdd` / `writeByteAdd`) |
| `±0x80 - b` — b subtracted FROM 0x80 | **SUBTRACT** |
| `-b` — b negated, no 0x80 | **INVERSE** |

Recovering a constant `v` from wire byte `w`: Add ⇒ `v=(w-0x80)&0xff` · Subtract ⇒ `v=(0x80-w)&0xff` ·
Inverse ⇒ `v=(-w)&0xff`.

The full transform table with worked examples is in the Project X repo at
`re-resources/docs/net/buffer-transform-patterns.md` (read-only). Consult it for the concept; document what
the **mobile** binary actually does here.

## Build-version caveat — same MAJOR, different sub-revision

`[VERIFIED — artifact]` The two targets are no longer the same build:

| Instance | Build | Ghidra name | Language |
|---|---|---|---|
| Mobile (writable target) | **949-3** | `liblibs.hal.system.rs2client.so.949-3` | `AARCH64:LE:64:v8A` |
| Desktop (read-only reference) | **949-4** | `rs2client.949-4` | `x86:LE:64` |

Mobile's build is authoritative in `data/client/android/build-info.json` (`engineVersion`); desktop's
is the `RS2Engine-949-NXT-<S>` string in the binary. Mobile was imported 2026-07-16 at 949-3 and has
**not** been re-pulled since; desktop moved to 949-4 on 2026-07-27.

**Both are major 949, so the shared-source guarantees still hold:** wire protocol, opcodes, packet
layouts, cache/JS5 formats, class/namespace names and `.rodata` algorithm constants are common. A
structural match between the two remains same-source evidence.

**But architecture is no longer the ONLY axis of difference** — the sub-revision differs too. Treat a
desktop finding as a behavioural blueprint, never as an address or a layout to copy. That was already
the rule for addresses because of the architecture gap; it now also applies to anything a sub-revision
could touch. Re-pull the APK if you need a like-for-like comparison.

Confirmed in practice — the config-URI builders (`<in Ghidra DB>` mobile / `<in Ghidra DB>` desktop) match
string-for-string and field-offset-for-field-offset, differing only in the `binaryType` constant
(`7` vs `4`) and in whether the launch-URL object is a member or a parameter. See
[../net/jav-config.md](../net/jav-config.md#desktop-cross-check--the-strongest-confirmation-available).

Re-verify at session start anyway (`list_binaries`) — the desktop instance could be swapped for another
build later.

## The absence of a string is NOT evidence of absence

**This trap cost real time; internalise it.**

Short string literals compared as `eastl::string`/`std::string` are frequently **materialised as
instruction immediates** and never appear in `.rodata` at all. A `grep` — even a raw byte grep over the
whole file — will not find them.

Worked example from this project. The premise "no `configURI` string exists in the `.so`, therefore
native must compare against some other literal" was **doubly wrong**:

1. `[VERIFIED — artifact]` A raw byte grep for `configURI` returns **zero** hits in the mobile `.so`
   **and zero in the desktop `rs2client`** — yet Project X demonstrably launches desktop with
   `--configURI`. Absence proved nothing.
2. The actual explanation was found in Project X's own notes: `--configURI` is a **launcher** flag
   (`rs3windows.exe`), never an rs2client flag. rs2client takes a positional `rs-launch://` URL. The
   string is absent because **the feature does not live in that binary.**

Observe how strings get hidden. In mobile `jag::android::android_main`, the literal
`"android"` is built as:

```c
*(undefined4 *)plVar32          = `<in Ghidra DB>`;   // "andr"
*(undefined4 *)((long)plVar32+3)= `<in Ghidra DB>`;   // "roid"
*(undefined1 *)((long)plVar32+7)= 0;            // NUL
```

Nine bytes of `com/jagex/bootstrap/StartupArguments` method names are assembled the same way. On x86-64
a `mov r64, imm64` embeds 8 **contiguous** ASCII bytes, so an 8-byte grep can sometimes find them
(`grep configUR`, not `grep configURI`). **On AArch64 `MOVZ`/`MOVK` carry only 2 payload bytes per
4-byte instruction, so the ASCII is scattered and NO grep of any length will find it.**

### Rules that follow

- **Never conclude "the client does not support X" from a missing string.** Conclude only "no `.rodata`
  literal exists."
- To prove a negative, use the **reference graph** (`get_xrefs_to`), not string search — and corroborate
  with a second method. For `g_StartupArgumentsArgv` the negative was established by *both* Ghidra's
  xref graph *and* a raw decode of all 52,250 `ADRP` instructions in `.text`. That is the standard.
- When grepping for a short literal on **x86-64**, try 8-byte substrings (`configUR`, `onfigURI`) to
  catch `mov imm64` materialisation.
- On **AArch64**, do not attempt this at all — anchor on the reference graph or on a longer `.rodata`
  string that *is* present.
