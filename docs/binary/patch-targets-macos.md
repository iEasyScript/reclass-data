# macOS rs2client Patch Targets (Mach-O)

Patch targets for the **macOS** NXT game client, consumed by the
`client/launcher/patcher-mac` crate (`libprojectx_patcher.dylib`, loaded via
`DYLD_INSERT_LIBRARIES` + `DYLD_FORCE_FLAT_NAMESPACE=1`).

- **Binary:** `data/client/macos/rs2client`
- **Format:** Mach-O 64-bit x86_64 executable (PIE, two-level namespace), clang
- **Revision:** 948-5 (`clients.manifest.json` → `macos.serverVersion=948`, crc 715619062)
- **Counterparts:** Linux ELF `data/client/linux/rs2client`
  (the patcher sources), Windows PE `data/client/windows/rs2client.exe`
  (same doc, P1–P3).

> **Source-of-truth note.** All three patches (P1/P2 RSA moduli and P3 HTTP
> port) and the "not applicable" findings are **byte-verified** via raw binary
> analysis of the Mach-O (Python pattern scans + RIP-relative LEA tracing +
> CALL-target scanning). P3 was previously UNRESOLVED; it is now fully
> documented by the ghidra-reverse-engineer agent. The Mach-O was not imported
> into Ghidra — analysis was done entirely through binary inspection.

---

## Per-OS data layout

| OS | game client | Jagex launcher | patcher artifact |
|----|-------------|----------------|------------------|
| linux   | `data/client/linux/rs2client`     | `data/client/linux/rs3linux`       | `libprojectx_patcher.so` |
| windows | `data/client/windows/rs2client.exe` | `data/client/windows/rs3windows.exe` | `projectx_patcher.dll` + `projectx_injector.exe` |
| macos   | `data/client/macos/rs2client`     | `data/client/macos/rs3mac`         | `libprojectx_patcher.dylib` |

The launcher auto-detects the host OS and resolves names via `host_os_dir` /
`launcher_binary_name` / `patcher_lib_name` in
`client/launcher/src/game/process.rs`. macOS launch uses `build_macos_command`
(`DYLD_INSERT_LIBRARIES` instead of `LD_PRELOAD`).

---

## P1 — Login RSA modulus (ASCII hex) — VERIFIED, pattern shared

| Property | Value |
|----------|-------|
| Search prefix | `aad4a7804c34bb788d52dbd5f70e5721` (first 32 hex chars) |
| Full length | 256 hex chars (1024-bit modulus) |
| Mach-O match count | **1** (byte-verified) |
| Section | `__TEXT,__const` (ASCII string in read-only data) |
| Patch | Overwrite in place with `PROJECTX_RSA_MODULUS`, left-padded to 256 chars |

The login modulus ASCII string is **byte-identical** to the Linux/Windows
builds — Jagex ships the same login RSA key across OS builds. The patcher reuses
the exact same `RS2CLIENT_MODULUS_PREFIX` constant. Only the in-memory address
differs (resolved at runtime by scanning the main image; no fixed offset baked).

## P2 — JS5 RSA modulus (ASCII hex) — VERIFIED, pattern shared

| Property | Value |
|----------|-------|
| Search prefix | `a6400fbcbd9dd09f48045caf3f543dd6` (first 32 hex chars) |
| Full length | 1024 hex chars (4096-bit modulus) |
| Mach-O match count | **1** (byte-verified) |
| Section | `__TEXT,__const` |
| Patch | Overwrite in place with `PROJECTX_JS5_RSA_MODULUS`, left-padded to 1024 chars |

Also byte-identical across OS builds. Skipped in proxy mode (JS5 goes directly
to Jagex, whose key must remain).

## P3 — HTTP JS5 content port (hardcoded 80) — RESOLVED (RE verified, raw binary analysis)

**Binary verified against:** Mach-O 64-bit x86_64 (clang PIE), rev 948-5,
SHA1 `9fc52a4a2bab40d799ea07b111d143518080fff5`, size 15,649,624 bytes.

### False positive verdict on the two `b8 50 00 00 00 eb` candidates

Both previously-identified offsets (`<in Ghidra DB>` / `<in Ghidra DB>`) are **confirmed
false positives**. Raw disassembly shows they are jump-dispatch table arms (clang
`llvm.switch.table` lowering) returning struct field offsets or enum values in the
sequence `0x58, 0x60, 0x78, 0x50, 0x68, 0x70` — not port constants. They have no
`0x1b58` (7000) or `0xe02e` (12000) bytes in their vicinity, which any genuine
HTTP-URL builder must contain (the alternate port is worldId + 7000 or worldId +
12000). The surrounding context is byte-identical at both sites:

```
00 00 eb 23  b8 50 00 00 00  eb 05  b8 68 00 00 00  49 8b 0e 4c
```

`0x68` immediately follows `0x50` as the next table arm — a series of
`MOV EAX, N; JMP ...` arms, not a conditional branch between two distinct code
paths. This is **not** the URL-mode dispatch shape.

### Actual port-80 patch sites

clang on macOS generates port 80 as a **16-bit immediate** (operand-size prefix
`0x66`), not a 32-bit `MOV EAX`. The instruction sequence is:

```
66 be 50 00   ; MOV SI, 0x50  (port 80)
eb 06         ; JMP short +6  (skip the alternate port calc)
81 c6 58 1b 00 00  ; ADD ESI, 0x1b58  (alternate: worldId + 7000)
```

or (one variant, site 3):

```
66 b8 50 00   ; MOV AX, 0x50  (port 80)
eb 05         ; JMP short +5
05 58 1b 00 00  ; ADD EAX, 0x1b58  (alternate: worldId + 7000)
```

This is confirmed as the GetHTTPURL-equivalent URL-builder: all three sites
reference the `'%s%s:%u'` and `'https://'` format strings (packed at vmaddr
`<in Ghidra DB>`4`), all three have the 7000 (`0x1b58`) alternate port, and two of the
three also have the 12000 (`0x2ee0`) alternate port in the same function body.
None of the false-positive `b8 50 00 00 00 eb` sites have any of these markers.

### Three patch sites (all must be patched)

The URL-builder logic appears in three inlined or duplicated copies within the
Mach-O — clang inlined `GetHTTPURL` into its callers rather than emitting a
single outlined function. All three must be patched to redirect every HTTP JS5
request.

| Site | File offset | Vmaddr (PIE base `<in Ghidra DB>`0) | Pattern | Port offset in pattern |
|------|-------------|-------------------------------|---------|------------------------|
| 1 | `<addr in DB>` | `<in Ghidra DB>`001512d3` | `66 be 50 00 eb 06 81 c6 58 1b 00 00` | +2 (2-byte LE) |
| 2 | `<addr in DB>` | `<in Ghidra DB>`002155a6` | `66 be 50 00 eb 06 81 c6 58 1b 00 00` | +2 (2-byte LE) |
| 3 | `<addr in DB>` | `<in Ghidra DB>`00273834` | `66 b8 50 00 eb 05 05 58 1b 00 00` | +2 (2-byte LE) |

The port immediate is a **2-byte little-endian 16-bit value** at offset +2 within
the pattern (`50 00` for port 80). To redirect to port N, write `N & 0xffff` as
LE16 at that offset. Ports above 65535 are invalid and must be rejected.

### Unique search patterns

Both pattern variants are globally unique across the Mach-O:

| Pattern (hex) | Match count | Unique? |
|---------------|-------------|---------|
| `66 be 50 00 eb 06 81 c6 58 1b 00 00 44 0f b7 c6` (16 bytes) | **2** | Identifies both type-1 sites |
| `66 b8 50 00 eb 05 05 58 1b 00 00 44 0f b7 c0` (15 bytes) | **1** | Identifies the type-2 site |

The patcher should search for **both** patterns and patch every match. Total
expected matches: 2 + 1 = **3**. If any other count is found, abort and log (binary
may have changed).

### Patcher implementation note

The port immediate is 16-bit on macOS (2 bytes), versus 32-bit (4 bytes) on
Linux and Windows. The patcher `patch_port` helper must use `write_u16_le` for
macOS, not `write_u32_le`. High 2 bytes are implicitly zero (port fits in u16).

The pattern offset for the LE16 port value within each pattern is `+2` (after the
`66 be` or `66 b8` prefix byte and opcode byte).

### Ghidra import status

The Mach-O was **not imported into Ghidra** (the loaded instances are the Linux
ELF `rs2client.948-5` on port 8081 and `librs2client.so` on port 8080). All
findings in this section are from raw binary analysis (Python): RIP-relative LEA
tracing to string literals, CALL-target scanning to identify callers, surrounding
byte context at each candidate site. No Ghidra renaming was applied to the Mach-O
binary. If a Ghidra Mach-O project is created in future, the function containing
site 1 (`<in Ghidra DB>`0` entry → calls GetHTTPURL-inline at `<in Ghidra DB>`0`) should be
named `jag::WorldLobbyData::GetHTTPURL` (inline) or its inliner.

---

## Not applicable to the Mach-O rs2client (verified absent)

These are **rs3linux-launcher-only** patches and are byte-verified to NOT exist
in the macOS rs2client game client:

| Target | Mach-O match count |
|--------|--------------------|
| Codebase URL regex (`^https?://[a-z0-9\-]*\.?runescape.com...`) | 0 |
| LZMA decompression flag (`C6 80 81 01 00 00 00  C6 80 82 01 00 00 01 ...`) | 0 |

If/when a macOS Jagex launcher binary (`rs3mac`, extracted from `RuneScape.dmg`)
needs the launcher-side patches (download-hash RSA, codebase regex), the RE
agent should analyze `data/client/macos/rs3mac` separately and document those
targets here under a new "rs3mac launcher" section. The current `patcher-mac`
crate targets only the rs2client game client.
