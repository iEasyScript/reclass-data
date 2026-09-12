# op19/op16 Login Descriptor — Complete Per-Byte Decoder Contract (round-trip verified)

The **final, exhaustive, byte-exact** field map of the XTEA-enciphered login tail, for a server-side
`MachineInformation` decoder. **Every byte is a named, typed field — no reserved/skip reads.** Derived
from disassembly of the encoders (not just the decompiler, whose position-tracking is ambiguous here) and
**round-trip-verified against both ground-truth plaintexts**: the walk below consumes
`lobby_tail.bin` to **exactly 564** bytes and `world_tail.bin` to **exactly 583** bytes.

Encoders (mobile, renamed in Ghidra):
- top-level writer — `jag::LoginManager::SendLoginPacket` `<in Ghidra DB>`
- 58-byte platform block — `jag::WriteMachineInfoBlock` `<in Ghidra DB>`
- device-strings block — `jag::WriteDeviceInfoBlock` `<in Ghidra DB>`
- 46× u32 settings block — `jag::LoginManager::WriteLoginClientSettingsBlock` `<in Ghidra DB>`

All multi-byte ints are **big-endian**. `RSString` = raw CP1252 bytes + a `0x00` terminator, **no** version
byte (an empty string is a single `0x00`). Offsets are in the XTEA-decrypted tail (XTEA covers from off 0).

---

## 0. Platform-uniformity (task 5): ONE decoder for desktop AND mobile

` / rs2client <addr in DB>]` Mobile and desktop `SendLoginPacket` are the same
function calling the same three sub-encoders in the same order. **Block layout never branches on
platform — only values differ** (`binaryType` 7 vs 0–6, `NXT-Android` vs `NXT-Windows/Linux/Mac`, GL/CPU
strings). The only structural fork is lobby (§1) vs world (§5). **One `MachineInformation` decoder
handles both.**

---

## 1. LOBBY tail (op19, loginMode==1) — every byte named (→ exactly 564)

Capture = Pixel-6 OAuth/SSO session: `username`, `clientToken`, `configString` are empty; the JS5 CRC
list is empty. Offsets are exact for this capture; variable fields (RSStrings) shift everything after
them, so **walk sequentially**.

| # | Off | Size | Type | Field | Value | Source / note |
|---|-----|------|------|-------|-------|---------------|
| 1 | 0 | 1 | u8 | `hasSessionTokenFlag` | `01` | `(loginToken@+0x120 == -1)`; `1`⇒`username` RSString follows, `0`⇒`u64 loginToken` |
| 2 | 1 | var | RSString | `username` | `""`=`00` | empty on OAuth; account name on directlogin |
| 3 | 2 | 1 | u8 | `configByteA` | `00` | **lobby-only**; `*(u8*)*(Client+`<in Ghidra DB>`)` |
| 4 | 3 | 1 | u8 | `configByteB` | `00` | **lobby-only**; `*(u8*)*(Client+`<in Ghidra DB>`)` |
| 5 | 4 | 1 | u8 | `loginType` | `03` | `2`=WebSocket, `3`=direct TCP |
| 6 | 5 | 2 | u16 | `screenWidth` | `1333` | `Client+`<in Ghidra DB>` → +0x68` |
| 7 | 7 | 2 | u16 | `screenHeight` | `600` | `→ +0x6c` |
| 8 | 9 | 1 | u8 | `displayMode` | `00` | `Client+`<in Ghidra DB>` → +0x1b8` |
| 9 | 10 | 24 | byte[24] | `machineUid` | `FF×24` | `Client+`<in Ghidra DB>` → +0xc0`. **`0xFF` (unset) at lobby; per-session bytes at world.** Opaque; copy/ignore |
| 10 | 34 | var | RSString | `clientInfo` | `"wwGl…Ovk"` (43) | `Client+`<in Ghidra DB>`; session/install token |
| 11 | 78 | 1 | u8 | `machineInfoLen` | `0x3a`=58 | length of #12 |
| 12 | 79 | 58 | block | **`machineInfoBlock`** | §2 | `WriteMachineInfoBlock` |
| 13 | 137 | 193 | block | **`deviceInfoBlock`** | §3 | `WriteDeviceInfoBlock` (var length: 55 + Σ string lengths) |
| 14 | 330 | 4 | u32 | `configInt0` | `0` | `Client+`<in Ghidra DB>` → +0x10` |
| 15 | 334 | 1 | u8 | `js5ArchiveCount` | `0` | `(Client+`<in Ghidra DB>`[+0xae0] − [+0xad8])>>2` |
| 16 | — | 4×N | u32[N] | `js5ArchiveCrcs` | (none) | `N`=#15; absent here |
| 17 | 335 | var | RSString | `clientToken` | `""`=`00` | `Client+`<in Ghidra DB>`; **empty in capture** |
| 18 | 336 | 4 | u32 | `configInt1` | `0` | `Client+`<in Ghidra DB>` |
| 19 | 340 | 4 | u32 | `configInt2` | **`0x0FDA7A95`** | `Client+`<in Ghidra DB>` (task 3: a constant client build/config hash) |
| 20 | 344 | var | RSString | `sessionToken` | `"og55…qw"` (32) | `Client+`<in Ghidra DB>`; the **last string before the OS bytes** |
| **21** | **377** | **1** | **u8** | **`binaryType`** | **`07`** | **★ 7=android, 8=iOS, 0–6=desktop.** `Client+`<in Ghidra DB>` |
| **22** | **378** | **1** | **u8** | **`platformType`** | **`02`** | **★ `jag::GetPlatformType`: 2=android, 3=iOS, 0/5=desktop** |
| 23 | 379 | 1 | u8(bool) | `hasSocialAuth` | `00` | trailing social-auth flag |
| 24 | 380 | 184 | u32[46] | **`clientSettingsBlock`** | §4 | `WriteLoginClientSettingsBlock`; ends at 563 |

Sum: `1+1+2+1+4+1+24+44+1+58+193+4+1+1+4+4+33+1+1+1+184 = 564` ✓ (matches `lobby_tail.bin`).

---

## 2. `machineInfoBlock` (58 B) — `WriteMachineInfoBlock` / `<in Ghidra DB>`

` + artifact]` Fixed 58-byte block. Marker `0x26`; a fixed sequence of GL/platform
capability values (`v#` = read from the machine-info source `Client+`<in Ghidra DB>`), four u16 limit-counts, five
`0x7f` max-caps, and hard-coded structural constants (`c#`). Blk-offset (col 1) + tail-offset (col 2).

| Blk | Off | Type | Field | Src | Capture |
|-----|-----|------|-------|-----|---------|
| 0 | 79 | u8 | `mi_marker` | const | `0x26` |
| 1–2 | 80 | u8×2 | `mi_c0,mi_c1` | const | `01 00` |
| 3 | 82 | u8 | `mi_v_298` | `+0x298` | `01` |
| 4 | 83 | u8 | `mi_v_378` | `+0x378` | `01` |
| 5 | 84 | u8 | `mi_v_448` | `+0x448` | `02` |
| 6 | 85 | u8 | `mi_c2` | const | `05` |
| 7 | 86 | u8 | `mi_v_5f8` | `+0x5f8` | `01` |
| 8 | 87 | u8 | `mi_v_6c8` | `+0x6c8` | `01` |
| 9 | 88 | u8 | `mi_c3` | const | `01` |
| 10 | 89 | u8 | `mi_v_798` | `+0x798` | `01` |
| 11 | 90 | u8 | `mi_v_8a8` | `+0x8a8` | `01` |
| 12–14 | 91 | u8×3 | `mi_c4..6` | const | `02 01 02` |
| 15 | 94 | u8 | `mi_v_b28` | `+0xb28` | `01` |
| 16–18 | 95 | u8×3 | `mi_c7..9` | const | `03 00 02` |
| 19 | 98 | u8 | `mi_v_x1` | `+0x3f0` | `02` |
| 20–22 | 99 | u8×3 | `mi_c10..12` | const | `01 01 00` |
| 23 | 102 | u8 | `mi_v_cc8` | `+0xcc8` | `01` |
| 24–26 | 103 | u8×3 | `mi_c13..15` | const | `01 00 01` |
| 27 | 106 | u8 | `mi_v_x2` | `+0x230` | `02` |
| 28 | 107 | u8 | `mi_v_a48` | `+0xa48` | `01` |
| 29 | 108 | u8 | `mi_v_978` | `+0x978` | `01` |
| 30 | 109 | u8 | `mi_v_1b8` | `+0x1b8` | `00` |
| 31 | 110 | u8 | `mi_v_bf8` | `+0xbf8` | `00` |
| 32 | 111 | u8 | `mi_v_da8` | `+0xda8` | `01` |
| 33 | 112 | u8 | `mi_v_e78` | `+0xe78` | `01` |
| 34 | 113 | u8 | `mi_v_e8` | `+0xe8` | `00` |
| 35 | 114 | u8 | `mi_v_f48` | `+0xf48` | `00` |
| 36 | 115 | u16 | `mi_u16_0` | `+0x254` | `0x0023`=35 |
| 37 | 117 | u16 | `mi_u16_1` | `+0x278` | `0x000f`=15 |
| 38 | 119 | u16 | `mi_u16_2` | `+0x2a0` | `0x0064`=100 |
| 39 | 121 | u16 | `mi_u16_3` | `+0x2bc` | `0x0064`=100 |
| 40 | 123 | u8 | `mi_v_x3` | `+0x3ac` | `00` |
| 41 | 124 | u8 | `mi_v_18` | `+0x18` | `00` |
| 42 | 125 | u8 | `mi_c16` | const | `04` |
| 43–46 | 126 | u8×4 | `mi_c17..20` | const | `00 00 00 00` |
| 47 | 130 | u8 | `mi_c21` | const | `01` |
| 48–52 | 131 | u8×5 | `mi_cap0..4` | `+0x4e4,0x508,0x528,0x54c,0x570` | `7f×5`=127 |
| 53 | 136 | u8 | `mi_terminator` | const | `01` |

`[VERIFIED — every byte's position/type/source]`; `[UNCONFIRMED — the GL-capability *meaning* of each `mi_v*`
byte]`. Note: this block carries **no OS field**; the platform is `binaryType`/`platformType`/`NXT-Android`.

---

## 3. `deviceInfoBlock` (193 B) — `WriteDeviceInfoBlock` / `<in Ghidra DB>`

` disasm + artifact]` Marker `0x09`, numeric framing, a 24-bit medium, then **8
NUL-terminated device strings** with inter-string framing. Every byte named; blk-offset + tail-offset.

| Blk | Off | Type | Field | Value | Note |
|-----|-----|------|-------|-------|------|
| 0 | 137 | u8 | `dev_marker` | `0x09` | |
| 1 | 138 | u8 | `dev_flagA` | `05` | `src int@0` |
| 2 | 139 | u8(bool) | `dev_flagB` | `01` | `src int@4 != 0` |
| 3–4 | 140 | u16 | `dev_fieldC` | `0x2734` | `src int@8` |
| 5–9 | 142 | u8×5 | `dev_c0..4` | `00×5` | const 0 |
| 10–11 | 147 | u16 | `dev_c5` | `0000` | const 0 |
| 12 | 149 | u8 | `dev_c6` | `01` | const 1 |
| 13–15 | 150 | u24 | `dev_medium` | `<in Ghidra DB>` | `src int@0xa8` (BE 3-byte) |
| 16–17 | 153 | u16 | `dev_c7` | `0000` | const 0 |
| 18 | 155 | u8 | `dev_c8` | `00` | str1 framing |
| 19 | 156 | RSString | `gpuVendor` **(EMPTY)** | `00` | str1 `src+0x10` — empty here |
| 20 | 157 | u8 | `dev_f1` | `00` | str2 framing |
| 21 | 158 | RSString | `glRenderer` | `"Mali-G78"` | str2 `src+0x28` |
| — | 167 | u8 | `dev_f2` | `00` | str3 framing |
| — | 168 | RSString | `dev_str3` **(EMPTY)** | `00` | str3 `src+0x40` — empty here |
| — | 169 | u8 | `dev_f3` | `00` | str4 framing |
| — | 170 | RSString | `glVersion` | `"OpenGL ES 3.2 v1.r54p1-…c5"` (62) | str4 `src+0x58` |
| — | 233 | u8 | `dev_g0` | `00` | `src int@0xd8` |
| — | 234 | u16 | `dev_g1` | `0000` | `src int@0xdc` |
| — | 236 | u8 | `dev_f4` | `00` | str5 framing |
| — | 237 | RSString | `cpuArch` | `"ARM64"` | str5 `src+0x70` |
| — | 243 | u8 | `dev_f5` | `00` | str6 framing |
| — | 244 | RSString | `cpuModel` | `"ARM64"` | str6 `src+0x88` |
| — | 250 | u8 | `cpuCount` | `08` | `src int@0xa0` (Pixel-6 = 8 cores) |
| — | 251 | u8 | `cpuField1` | `08` | `src int@0xa4` |
| — | 252 | u32 | `cpuField2` | `0` | `src int@0xac` BE |
| — | 256 | u32 | `cpuField3` | `0` | `src int@0xb0` BE |
| — | 260 | u32 | `cpuField4` | `0` | `src int@0xb4` BE |
| — | 264 | u32 | `cpuField5` | `0` | `src int@0xb8` BE |
| — | 268 | u8 | `dev_f6` | `00` | str7 framing |
| — | 269 | RSString | **`clientName`** | **`"NXT-Android"`** | str7 `src+0xc0` — ★ OS indicator (desktop: `NXT-Windows/Linux/Mac`) |
| — | 281 | u8 | `dev_f7` | `00` | str8 framing |
| — | 282 | RSString | `deviceString` | `"google / Pixel 6 (oriole / oriole) (Android 16)"` (47) | str8 `src+0xe0`; ends @329 |

The **8 device strings** in order: `gpuVendor`(EMPTY), `glRenderer`, `dev_str3`(EMPTY), `glVersion`,
`cpuArch`, `cpuModel`, `clientName`, `deviceString`. **The two empty ones are str1 (gpuVendor) and str3.**
Each is `RSString` (CP1252 + `NUL`), preceded by one framing byte; the special framing (`dev_g0/g1`,
`cpuCount`/`cpuField1..5`) sits between str4↔str5 and str6↔str7. `[VERIFIED — all strings, order, framing,
empties]`; `[UNCONFIRMED — semantic of the numeric framing values dev_flagA..dev_g1]`.

---

## 4. `clientSettingsBlock` (184 B) — `WriteLoginClientSettingsBlock` / `<in Ghidra DB>` (task 4)

` + artifact]` The trailing region is **NOT** a signature/attestation. It is a
**fixed sequence of 46 big-endian `u32` fields**: 36 client-config/telemetry values fetched by
`ConfigProvider::getInt(hashKey)` + 10 hard-coded `0` u32s, in a fixed order. `46×4 = 184` bytes, filling
the tail to off 563 (last field `settings45` = `5b 15 7b e0`). Decoder: read 46 BE u32s (`settings0..45`).
`[VERIFIED — count 46, type u32 BE]`; `[UNCONFIRMED — per-field config-key meaning]`. None is an OS field.

---

## 5. WORLD tail (op16, loginMode==2) — every byte named (→ exactly 583)

` disasm + artifact]` Same three encoder blocks; different top-level framing. Deltas
from lobby:

| # | Off | Size | Type | Field | Note |
|---|-----|------|------|-------|------|
| 1 | 0 | 1 | u8 | `hasSessionTokenFlag` | `01` |
| 2 | 1 | var | RSString | `username` | empty |
| — | | | | **(no `configByteA/B`)** | world omits them |
| 3 | 2 | 1 | u8 | `loginType` | `03` |
| 4 | 3 | 2 | u16 | `screenWidth` | |
| 5 | 5 | 2 | u16 | `screenHeight` | |
| 6 | 7 | 1 | u8 | `displayMode` | |
| 7 | 8 | 24 | byte[24] | `machineUid` | **populated** (per-session) in world |
| 8 | 32 | var | RSString | `clientInfo` | 43-byte token |
| 9 | 76 | 4 | u32 | `configInt1` | `Client+`<in Ghidra DB>` — world writes it **here** |
| 10 | 80 | 1 | u8 | `machineInfoLen` | 58 |
| 11 | 81 | 58 | block | `machineInfoBlock` | §2 |
| 12 | 139 | 193 | block | `deviceInfoBlock` | §3 |
| 13 | 332 | 4 | u32 | `configInt0` | `Client+`<in Ghidra DB>`+0x10` |
| 14 | 336 | 8 | u64 | `worldField0` | `Client+`<in Ghidra DB>`/+`<in Ghidra DB>` |
| 15 | 344 | 8 | u64 | `worldField1` | `Client+`<in Ghidra DB>`/+`<in Ghidra DB>` |
| 16 | 352 | 1 | u8 | `js5ArchiveCount` | `0` |
| 17 | — | 4×N | u32[N] | `js5ArchiveCrcs` | none |
| 18 | 353 | var | RSString | `clientToken` | empty (`00`) |
| 19 | 354 | 1 | u8(bool) | `hasExtraString` | `Client+`<in Ghidra DB>` len!=0` |
| 20 | — | var | RSString | `extraString` | only if #19; empty here |
| 21 | 355 | 1 | u8 | `worldConst1` | const `01` |
| 22 | 356 | 1 | u8 | `worldByte` | `Client+`<in Ghidra DB>` |
| **23** | **357** | **1** | **u8** | **`binaryType`** | **`07`** |
| **24** | **358** | **1** | **u8** | **`platformType`** | **`02`** |
| 25 | 359 | 4 | u32 | `configInt2` | **`0x0FDA7A95`** |
| 26 | 363 | var | RSString | `sessionToken` | `"og55…qw"` (32) |
| 27 | 396 | 1 | u8(bool) | `hasSocialAuth` | |
| 28 | 397 | 2 | u16 | `selfIndex` | world self player index |
| 29 | 399 | 184 | u32[46] | `clientSettingsBlock` | §4; ends 583 |

Sum: `1+1+1+2+2+1+24+44+4+1+58+193+4+8+8+1+1+1+1+1+1+1+4+33+1+2+184 = 583` ✓ (matches `world_tail.bin`).

`"NXT-Android"` sits at **off 271** in world (device block starts @139), ≈ the lobby off-269 — the reason
it is the recommended uniform OS signal.

---

## 6. Kotlin `MachineInformation` decoder (ordered, both branches)

```kotlin
// XTEA-decrypt the tail first, then walk. u16/u24/u32 big-endian; RSString = CP1252 until 0x00.
hasSessionTokenFlag : u8            // 1 => username RSString ; 0 => u64 loginToken
username            : RSString      // (or loginToken u64)
if (lobby) { configByteA: u8; configByteB: u8 }
loginType           : u8            // 2=WebSocket, 3=direct socket
screenWidth         : u16
screenHeight        : u16
displayMode         : u8
machineUid          : byte[24]      // 0xFF at lobby; per-session at world
clientInfo          : RSString
if (world) { configInt1: u32 }
machineInfoLen      : u8            // 58
machineInfoBlock    : byte[58]      // §2 (marker 0x26 + capability descriptor)
deviceInfoBlock     : {             // §3
    marker=0x09; flagA:u8; flagB:u8; fieldC:u16; 5×u8=0; u16=0; u8=1; medium:u24; u16=0;
    f:u8; gpuVendor:RSString(empty); f:u8; glRenderer:RSString; f:u8; str3:RSString(empty);
    f:u8; glVersion:RSString; g0:u8; g1:u16; f:u8; cpuArch:RSString; f:u8; cpuModel:RSString;
    cpuCount:u8; cpuField1:u8; cpuField2..5:u32×4; f:u8; clientName:RSString /*NXT-Android*/;
    f:u8; deviceString:RSString
}
configInt0          : u32
if (world) { worldField0:u64; worldField1:u64 }
js5ArchiveCount     : u8
js5ArchiveCrcs      : u32[js5ArchiveCount]
clientToken         : RSString      // empty in captures
if (world) { hasExtraString:u8; if (it) extraString:RSString; worldConst1:u8=1; worldByte:u8 }
if (lobby) { configInt1:u32; configInt2:u32 }        // 0x0FDA7A95
if (world) { binaryType:u8; platformType:u8; configInt2:u32; sessionToken:RSString;
             hasSocialAuth:u8; selfIndex:u16 }
if (lobby) { configInt2:u32; sessionToken:RSString; binaryType:u8; platformType:u8; hasSocialAuth:u8 }
clientSettingsBlock : u32[46]
```

> Field ordering differs between branches around `sessionToken`/`binaryType` — the table above is the
> authority (lobby §1, world §5). Detection: `isMobile = binaryType in 7..8` (equivalently
> `clientName == "NXT-Android"` or `platformType in 2..3`).

## Cross-references
- Mobile-detection summary & response-side verdict: [login-handshake.md §6](login-handshake.md)
- Ground truth: `captures/mobile-official-lobby-world-login/` (`lobby_tail.bin` 564 B, `world_tail.bin` 583 B)
