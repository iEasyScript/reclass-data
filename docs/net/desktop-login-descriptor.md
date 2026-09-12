# Desktop `rs2client` Login Descriptor — Byte-Exact XTEA Tail (op19 lobby / op16 world)

Source of truth: **desktop `rs2client.949-1`** (x86-64, Ghidra port 8081). The mobile AArch64 `.so`
is used only for cross-reference. This document is the desktop counterpart to
`docs/mobile/net/machine-info.md` and supersedes the assumption that "one decoder handles both
platforms unchanged."

## TL;DR — the desktop tail is the SAME wire skeleton as mobile

After decompiling the desktop top-level builder and both sub-encoders, the desktop XTEA-enciphered
login tail is **byte-structurally identical** to the mobile tail: same field order, same
length-prefixed 58-byte machine-info block (marker `0x26`), same device block (marker `0x09` + 8
NUL-terminated strings + CPU fields), same trailing 46×u32 settings block. **Nothing branches on
platform except lobby-vs-world.**

What actually differs (and causes a mobile-tuned decoder to misalign) is **values and string
content/length**, not structure:

| Signal | Mobile (Android) | Desktop (Linux) |
|--------|------------------|-----------------|
| `binaryType` byte | `0x07` | **`0x0A` (10)** — compile-time constant, `Client+`<in Ghidra DB>` |
| `platformType` byte (`GetPlatformType`) | `0x02` | **`0x00` or `0x05`** (runtime; see §6) |
| device `clientName` string | `"NXT-Android"` | **`"NXT-Linux"`** (`<addr in DB>`) |
| device GL/CPU/OS strings | Mali-G78 / ARM64 / "google / Pixel 6 …" | Mesa/Intel/AMD-NVIDIA / x86_64 / Linux host descriptor |
| which device strings are empty | strA(gpuVendor) & strC empty | platform-dependent — **never assume** |

A decoder MUST walk the device strings by NUL terminator and honor `machineInfoLen`; it must not
hardcode any mobile string length or empty-slot pattern. Do that and one decode path handles both.

## Encoder functions (renamed in the desktop Ghidra DB)

| Address | Name | Role |
|---------|------|------|
| `<addr in DB>` | `jag::LoginManager::SendLoginPacket` | top-level login builder (lobby op19 / world op16) |
| `<addr in DB>` | `jag::WriteMachineInfoBlock` | fixed 58-byte machine-info block (marker `0x26`) |
| `<addr in DB>` | `jag::WriteDeviceInfoBlock` | device block (marker `0x09`, 8 strings, CPU fields) |
| `<addr in DB>` | `jag::LoginManager::WriteLoginClientSettingsBlock` | 46×u32 BE settings block |
| `<addr in DB>` | `jag::Packet::pFramedStringUTF8` | device string: `[0x00 framing][CP1252→UTF8 content][0x00 NUL]` |
| `<addr in DB>` | `jag::GetPlatformType` | maps `binaryType` → `platformType` byte |

All multi-byte ints are **big-endian**. `RSString` (`pStringNoConversion`) = raw CP1252 bytes + a
`0x00` terminator, no version byte (empty string = single `0x00`).

## XTEA boundary

The packet is built as `[opcode][u16 sizeMarker][clientVersion u32=0x3b5][subVersion u32=1]
[+ world only: totp u8][RSA block]` then the **XTEA-enciphered tail**. `tinyKeyEncrypt`
(`Packet+0x48` = 4 XTEA ints) covers from **immediately after the RSA block** — i.e. from
`hasSessionTokenFlag` (offset 0 below) to the end of the settings block. Decode = XTEA-decrypt the
tail, then walk the tables below from offset 0.

---

## 1. LOBBY tail (op19, `loginMode != 2`) — sequential walk

Offsets are exact up to the first RSString; after any variable field, keep walking sequentially.

| # | Off | Size | Type | Field | Notes |
|---|-----|------|------|-------|-------|
| 1 | 0 | 1 | u8 | `hasSessionTokenFlag` | `(loginToken@LoginMgr+0x120 == -1)`. `1` ⇒ `username` RSString next; `0` ⇒ `u64 loginToken` |
| 2 | 1 | var | RSString / u64 | `username` **or** `loginToken` | RSString if flag==1, else 8-byte BE token |
| 3 | — | 1 | u8 | `configByteA` | **lobby-only**; `*(u8*)*(Client+RELA[0xd0a])` |
| 4 | — | 1 | u8 | `configByteB` | **lobby-only**; `*(u8*)*(Client+RELA[0xd0f])` |
| 5 | — | 1 | u8 | `loginType` | `2`=WebSocket, `3`=direct TCP |
| 6 | — | 2 | u16 | `screenWidth` | `Client machine +0x68` |
| 7 | — | 2 | u16 | `screenHeight` | `+0x6c` |
| 8 | — | 1 | u8 | `displayMode` | `Client+`<in Ghidra DB>`-source +0x140` |
| 9 | — | 24 | byte[24] | `machineUid` | opaque; `0xFF×24` at lobby (unset), per-session at world. Copy/ignore |
| 10 | — | var | RSString | `clientInfo` | install/session token string (`Client+`<in Ghidra DB>`) |
| 11 | — | 1 | u8 | `machineInfoLen` | **= 58 (`0x3a`)** |
| 12 | — | 58 | block | `machineInfoBlock` | §4 (marker `0x26`, fixed 58B) |
| 13 | — | var | block | `deviceInfoBlock` | §5 (marker `0x09`; NO length prefix — walk it) |
| 14 | — | 4 | u32 | `configInt0` | `*(Client+RELA[0xcf7] +0x10)` |
| 15 | — | 1 | u8 | `js5ArchiveCount` | `N` |
| 16 | — | 4·N | u32[N] | `js5ArchiveCrcs` | one CRC per archive (usually 0 in captures) |
| 17 | — | var | RSString | `clientToken` | `Client+`<in Ghidra DB>` (empty in OAuth captures) |
| 18 | — | 4 | u32 | `configInt1` | `*(Client+RELA[0xd10] +4)` — **lobby writes it here** |
| 19 | — | 4 | u32 | `configInt2` | client build/config hash (build-specific constant) |
| 20 | — | var | RSString | `sessionToken` | `Client+`<in Ghidra DB>` |
| **21** | — | **1** | **u8** | **`binaryType`** | **★ `Client+`<in Ghidra DB>` = `0x0A` on Linux** |
| **22** | — | **1** | **u8** | **`platformType`** | **★ `GetPlatformType` = 0 or 5 on desktop** |
| 23 | — | 1 | u8(bool) | `hasSocialAuth` | trailing social-auth flag |
| 24 | — | 184 | u32[46] | `clientSettingsBlock` | §6 (last field) |

## 2. WORLD tail (op16, `loginMode == 2`) — sequential walk

Deltas from lobby: no `configByteA/B`; `configInt1` moves up (right after `clientInfo`); two u64
world fields; an extra `hasExtraString`/`extraString`; two extra world bytes; and a trailing
`selfIndex` u16.

| # | Size | Type | Field | Notes |
|---|------|------|-------|-------|
| 1 | 1 | u8 | `hasSessionTokenFlag` | as lobby |
| 2 | var | RSString / u64 | `username` / `loginToken` | as lobby |
| 3 | 1 | u8 | `loginType` | (no configByteA/B in world) |
| 4 | 2 | u16 | `screenWidth` | |
| 5 | 2 | u16 | `screenHeight` | |
| 6 | 1 | u8 | `displayMode` | |
| 7 | 24 | byte[24] | `machineUid` | **populated** per-session in world |
| 8 | var | RSString | `clientInfo` | |
| 9 | 4 | u32 | `configInt1` | `*(Client+RELA[0xd10] +4)` — **world writes it here** |
| 10 | 1 | u8 | `machineInfoLen` | = 58 |
| 11 | 58 | block | `machineInfoBlock` | §4 |
| 12 | var | block | `deviceInfoBlock` | §5 |
| 13 | 4 | u32 | `configInt0` | `*(Client+RELA[0xcf7] +0x10)` |
| 14 | 8 | u64 | `worldField0` | `Client+RELA[0xd17]` (BE long) |
| 15 | 8 | u64 | `worldField1` | `Client+RELA[0xca1]` (BE long) |
| 16 | 1 | u8 | `js5ArchiveCount` | `N` |
| 17 | 4·N | u32[N] | `js5ArchiveCrcs` | |
| 18 | var | RSString | `clientToken` | `Client+`<in Ghidra DB>` |
| 19 | 1 | u8(bool) | `hasExtraString` | `Client+`<in Ghidra DB>` SSO string len != 0 |
| 20 | var | RSString | `extraString` | present only if #19 == 1 |
| 21 | 1 | u8 | `worldConst1` | const `0x01` |
| 22 | 1 | u8 | `worldByte` | `*(u8*)(Client+RELA[0xd1c].r_info +4)` |
| **23** | **1** | **u8** | **`binaryType`** | **★ `0x0A` on Linux** |
| **24** | **1** | **u8** | **`platformType`** | **★ `GetPlatformType` = 0 or 5** |
| 25 | 4 | u32 | `configInt2` | build/config hash |
| 26 | var | RSString | `sessionToken` | `Client+`<in Ghidra DB>` |
| 27 | 1 | u8(bool) | `hasSocialAuth` | |
| 28 | 2 | u16 | `selfIndex` | world self player index (`-1` = `0xFFFF` if unset) |
| 29 | 184 | u32[46] | `clientSettingsBlock` | §6 (last field) |

---

## 3. Platform indicator (task 2) — exact positions

- **`binaryType`** is read raw from **`Client + `<in Ghidra DB>`** (a 4-byte int; low byte emitted). It is a
  **compile-time constant baked per binary** — written exactly once, at `<addr in DB>`
  (`MOV dword [R14+`<in Ghidra DB>`], 0xA`). **Linux desktop value = `0x0A` (10).** (Not 0 and not 4.)
  Mobile-Android = 7, iOS = 8. Windows/Mac desktop builds will carry their own constant (re-derive
  per binary; only the Linux binary was analyzed here).
- **`platformType`** is `GetPlatformType(client)` (`<addr in DB>`): `binaryType==7 → 2` (android),
  `==8 → 3` (iOS), else desktop → `5` if `*(u8*)(*(Client+`<in Ghidra DB>`) + 0x169) != 0` else `0`. So on
  desktop it is **0 or 5** (a runtime GL/display flag), NOT a stable OS id. **Do not** use
  `platformType` to detect desktop; use `binaryType` and/or `clientName`.
- **`clientName`** = device-block string slot **G** (`strG`, §5). On Linux it is **`"NXT-Linux"`**
  (`.rodata <addr in DB>`); Windows/Mac builds emit `"NXT-Windows"`/`"NXT-Mac"`. This is the most
  robust cross-platform OS signal (mobile emits `"NXT-Android"`).

**Deterministic reach to `binaryType`:** lobby = walk fields 1→20 then read u8 (#21); world = walk
fields 1→22 then read u8 (#23). Both are one byte before `platformType`.

---

## 4. `machineInfoBlock` — fixed 58 bytes (`WriteMachineInfoBlock`

Answer to task 3: this is a **fixed 58-byte GL/render-capability descriptor**, NOT the classic RS
`ClientMachine` (there is no osType/os64bit/osVersion/java-vendor/java-version/maxMemory block — NXT
does not run on the JVM). The OS/GL/CPU *strings* live in the device block (§5); this block is
purely numeric capability flags and limits. It is preceded by `machineInfoLen` (= `0x3a`), so a
decoder may treat it as opaque: **read `machineInfoLen` (=58), read that many bytes.**

Internal layout (relative offset, for completeness — identical skeleton to mobile §2):

- `+0`: marker `0x26`
- `+1..+2`: const `01 00`
- `+3..+35`: interleaved single-byte GL capability flags (values from the machine-info source
  struct) and hard-coded structural constants (`5, 1, 2, 1, 2, 3, 0, 2, …`)
- `+36..+43`: four u16 BE limit counts
- `+44..+51`: trailing capability/const bytes
- `+52..+56`: five `0x7f` max-cap bytes
- `+57`: terminator `0x01`

Byte positions/types are fixed; only the capability values vary by GPU. Total always 58.

---

## 5. `deviceInfoBlock` — variable (`WriteDeviceInfoBlock`

**No length prefix in the packet** — walk it exactly. `pFramedStringUTF8` writes each string as
`[0x00 framing][content bytes][0x00 NUL]`. Relative offsets:

| Off | Size | Type | Field | Notes |
|-----|------|------|-------|-------|
| 0 | 1 | u8 | `marker` | `0x09` |
| 1 | 1 | u8 | `flagA` | `clientMachine[0]` |
| 2 | 1 | u8(bool) | `flagB` | `clientMachine[4] != 0` |
| 3 | 2 | u16 BE | `fieldC` | `clientMachine[8]` |
| 5 | 5 | u8×5 | const `00 00 00 00 00` | |
| 10 | 2 | u16 | const `00 00` | |
| 12 | 1 | u8 | const `01` | |
| 13 | 3 | u24 BE | `medium` | `clientMachine[0xa8]` |
| 16 | 2 | u16 | const `00 00` | |
| 18 | var | framed str | `strA` (GL vendor) | `[00][content][00]` |
| — | var | framed str | `strB` (GL renderer) | |
| — | var | framed str | `strC` (GL / driver) | |
| — | var | framed str | `strD` (GL version) | |
| — | 1 | u8 | `devByte` | `clientMachine[0xd8]` |
| — | 2 | u16 BE | `devShort` | `clientMachine[0xdc]` |
| — | var | framed str | `strE` (CPU arch) | |
| — | var | framed str | `strF` (CPU model) | |
| — | 1 | u8 | `cpuCount` | `clientMachine[0xa0]` |
| — | 1 | u8 | `cpuField1` | `clientMachine[0xa4]` |
| — | 4 | u32 BE | `cpuField2` | `clientMachine[0xac]` |
| — | 4 | u32 BE | `cpuField3` | `clientMachine[0xb0]` |
| — | 4 | u32 BE | `cpuField4` | `clientMachine[0xb4]` |
| — | 4 | u32 BE | `cpuField5` | `clientMachine[0xb8]` |
| — | var | framed str | **`strG` = `clientName`** | **`"NXT-Linux"` ← OS indicator** |
| — | var | framed str | `strH` (device/host descriptor) | |

Fixed (non-string) overhead = 55 bytes (`0x37`); total = 55 + Σ(string content lengths). Any of the
8 strings may be empty (`[00][00]`) depending on platform/driver — **walk by NUL, never assume.**

---

## 6. `clientSettingsBlock` — 46×u32 BE (`WriteLoginClientSettingsBlock`

Fixed **46 big-endian u32 = 184 bytes**, the final region of the tail: 36 values from
`ConfigProvider::getInt(hashKey)` + 10 zero placeholders (`p4SizeMarker`), in a fixed order. Not a
signature/attestation. Decode = read 46 BE u32 (`settings0..45`). Values are client-config/telemetry
constants; none is an OS field.

---

## 7. DIFF vs the mobile contract (task 4)

**Structure: no difference.** Field order, sub-block skeletons, `machineInfoLen`-prefixed 58-byte
block, device-block framing (8 NUL strings + CPU fields), and 46×u32 settings block are identical
between desktop and mobile, for both lobby and world. The lobby-vs-world fork is the only structural
branch, and it is the same on both platforms.

**Value/content differences (the misalignment source):**

1. `binaryType`: **`0x0A` desktop-Linux** vs `0x07` mobile-Android. One byte before `platformType`.
2. `platformType`: **`0`/`5` desktop** vs `2` android — runtime GL flag on desktop, not an OS id.
3. `clientName` (device strG): **`"NXT-Linux"`** vs `"NXT-Android"` (different length ⇒ shifts the
   tail end).
4. Other device strings: desktop emits **Mesa/Intel/AMD/NVIDIA GL vendor+renderer+version, x86_64
   CPU arch/model, and a Linux host descriptor** — different values and lengths; different
   empty/non-empty slots than mobile's (gpuVendor & strC empty on the Pixel-6 capture).
5. Machine-info block values and device numeric framing come from a different (desktop GL/OS)
   collector — same byte positions, different values.

**Why a mobile-built decoder misaligns on desktop:** if it hardcoded mobile string lengths, assumed
specific empty slots, or skipped the device block by a fixed byte count, the different desktop
strings shift everything after the device block. Fix = walk the device strings by NUL terminator and
honor `machineInfoLen`; then the same decoder is byte-correct on both.

---

## 8. Unified decoder sketch (both branches, both platforms)

```kotlin
// XTEA-decrypt the tail, then walk. u16/u24/u32/u64 big-endian; RSString = CP1252 until 0x00.
hasSessionTokenFlag : u8
if (hasSessionTokenFlag == 1) username : RSString else loginToken : u64
if (lobby) { configByteA: u8; configByteB: u8 }
loginType   : u8
screenWidth : u16; screenHeight : u16
displayMode : u8
machineUid  : byte[24]
clientInfo  : RSString
if (world) { configInt1 : u32 }
machineInfoLen : u8            // == 58
machineInfoBlock : byte[machineInfoLen]
deviceInfoBlock  : walkDeviceBlock   // marker 0x09; 8 NUL strings; see §5
configInt0 : u32
if (world) { worldField0 : u64; worldField1 : u64 }
js5ArchiveCount : u8
js5ArchiveCrcs  : u32[js5ArchiveCount]
clientToken : RSString
if (lobby) { configInt1 : u32; configInt2 : u32 }
if (world) { hasExtraString : u8; if (it) extraString : RSString; worldConst1 : u8; worldByte : u8 }
if (world) { binaryType : u8; platformType : u8; configInt2 : u32; sessionToken : RSString
             hasSocialAuth : u8; selfIndex : u16 }
if (lobby) { configInt2 : u32; sessionToken : RSString; binaryType : u8; platformType : u8
             hasSocialAuth : u8 }
clientSettingsBlock : u32[46]

// Platform detection: isMobile = binaryType in 7..8  (android 7 / iOS 8);
//                     desktop  = else (Linux baked as 0x0A here). Also clientName startsWith "NXT-".
```

`walkDeviceBlock`: u8 marker(0x09), u8 flagA, u8 flagB, u16 fieldC, byte[5]=0, u16=0, u8=1,
u24 medium, u16=0, RSString strA..strD, u8 devByte, u16 devShort, RSString strE..strF, u8 cpuCount,
u8 cpuField1, u32 cpuField2..cpuField5, RSString strG(clientName), RSString strH. Device strings
carry a leading `0x00` framing byte before content — consume it, then read to the `0x00` NUL.

## Cross-references
- Mobile contract (identical skeleton, mobile values): `docs/mobile/net/machine-info.md`
- Older desktop pseudocode hint (build 946, superseded): `docs/net/login-protocol.md`
