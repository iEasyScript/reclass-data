# NXT Client Binary Download (per-OS)

How Jagex distributes the `rs2client` NXT game binary per operating system, and how the
`client-updater` tool (`tools/.../clientupdater/`) downloads and version-checks them.

> Everything here was verified **empirically against the live CDN** on 2026-06-24 (server_version
> 948), not inferred from Ghidra. The download URL scheme is also confirmed by the open-source
> `nxtlauncher`, which our Rust launcher mirrors.

## 1. Per-OS metadata: `jav_config.ws?binaryType=N`

The `binaryType` query param selects the platform. Each returns its own `codebase` host plus the
download descriptor for that OS:

| binaryType | OS              | `download_name_0` | binary format | notes                          |
|-----------:|-----------------|-------------------|---------------|--------------------------------|
| 1          | Windows 32-bit  | `rs2client.exe`   | PE/MZ         | legacy ~80 KB stub, not a real client |
| 2          | Windows 64-bit  | `rs2client.exe`   | PE32+ x86-64  | real client (~14 MB)           |
| 3          | macOS           | `rs2client`       | Mach-O x86-64 | real client (~15 MB)           |
| 4          | Linux           | `rs2client`       | ELF x86-64    | real client (~18 MB)           |

Fetch URL (the `www` host 302-redirects to a `world{N}` host that carries the config):

```
https://www.runescape.com/k=5/l=0/jav_config.ws?binaryType=N
```

Relevant keys in the response (all plain `key=value` "settings" lines):

| key               | meaning                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `codebase`        | base URL for the binary download, e.g. `https://world3.runescape.com/k=5/` |
| `download_name_0` | the binary's filename (`rs2client` / `rs2client.exe`)                    |
| `download_crc_0`  | **CRC32 of the _decompressed_ binary** (see §3)                         |
| `server_version`  | game revision major (e.g. `948`)                                        |

The `world{N}` host assigned to a `binaryType` is **load-balanced and varies between requests** —
any `world{N}` mirror serves any binary given the right `crc`. Always use the `codebase` returned by
the same `jav_config` fetch rather than hardcoding a host.

## 2. Download URL

```
{codebase}client?binaryType={N}&fileName={download_name_0}&crc={download_crc_0}
```

Example (Linux):
`https://world3.runescape.com/k=5/client?binaryType=4&fileName=rs2client&crc=636504554`

The naive `{codebase}{download_name_0}` (i.e. `.../k=5/rs2client`) returns **404** — the `client?…`
endpoint with the `crc` cache key is required. Our `ConfigServer` is lenient (`path.contains("rs2client")`)
so it accepts either form from a patched launcher, but Jagex requires the `client?…` form.

## 3. Wire format: LZMA-alone, CRC over the decompressed bytes

The body is a raw `.lzma` ("alone") stream — **not** an RS cache container:

```
[0]      1 byte   LZMA properties (lc/lp/pb)         always 0x5D
[1..4]   4 bytes  dictionary size, little-endian     <addr in DB> = 8 MiB
[5..12]  8 bytes  uncompressed size, little-endian
[13..]   N bytes  LZMA-compressed stream
```

This is the same `lzma.sdk.lzma.Decoder` used by `world.gregs.voidps.cache.compress.DecompressionContext`
for container type 3; only the header placement differs. See `tools/.../clientupdater/LzmaAlone.kt`.

**`download_crc_0` is the CRC32 of the _decompressed_ binary**, verified for binaryType 2 and 3:

```
download_crc_0 == crc32(lzma_decompress(body))          # TRUE
download_crc_0 == crc32(body)                            # FALSE (not the compressed bytes)
```

The Jagex launcher therefore downloads the compressed body, decompresses it, and verifies the result
against `download_crc_0`. The launcher's LZMA-decompress step is the one our patcher disables (so our
`ConfigServer` can serve the binary uncompressed) — see the patcher sources under `client/launcher/`.

Because our archived `./data/client` binaries are stored **decompressed**, `download_crc_0` is a
direct version identity for them: `crc32(local_file) == download_crc_0` ⟺ we have the latest build.

## 4. The `client-updater` tool

`tools/src/main/kotlin/org/projectx/tools/clientupdater/` — downloads the latest `rs2client` for every
major OS and checks each against `./data/client`.

```
./gradlew :tools:run -PmainClass=org.projectx.tools.clientupdater.MainKt --args="[flags]"
```

| flag          | effect                                                              |
|---------------|---------------------------------------------------------------------|
| `--dir PATH`  | client root to check/update (default `./data/client`)               |
| `--os a,b,c`  | subset of `{linux,windows,macos}` (default: all three)              |
| `--check`     | dry run: report status only, no downloads/writes                    |
| `--update`    | also replace OUTDATED existing binaries (MISSING are always filled) |
| `--force`     | re-download every selected target even if up to date                |

Per OS it fetches the `jav_config` metadata, compares `download_crc_0` against the CRC32 of the local
file, and (unless `--check`) downloads + LZMA-decompresses + CRC-verifies + validates the magic
(`ELF`/`PE`/`Mach-O`) before an atomic write. Default behaviour is **non-destructive**: it fills in
MISSING binaries but leaves OUTDATED ones in place (reporting them) until you pass `--update`.

### Per-OS layout under the client root

Each OS gets its own folder so the per-OS files never collide (Linux & macOS clients are both
`rs2client`). The **32-bit Windows build is dropped** — it is an ~80 KB i386 console stub, not a real
client; the working Windows client is 64-bit (binaryType 2). This tool downloads/verifies the **game
client**; the `rs3*` launcher and patcher lib in each folder are owned by the cross-platform Rust
launcher (it reports launcher presence only).

```
data/client/
  linux/    rs2client       rs3linux         libprojectx_patcher.so
  windows/  rs2client.exe   rs3windows.exe   projectx_patcher.dll + projectx_injector.exe
  macos/    rs2client       rs3mac           libprojectx_patcher.dylib
```

`ConfigServer` serves `EnvVars.clientBinaryPath` (default `./data/client/linux/rs2client`). A
`clients.manifest.json` is written at the client root recording per-OS `server_version`,
`download_crc_0`, `clientPath`/`launcherPath`, size, SHA-256, source URL and download timestamp.

> Scope: this tool handles the **game client** (`rs2client`), the version-bearing binary the server
> serves and that we reverse-engineer/patch. The Jagex **launcher** (`rs3linux`/`rs3windows.exe`/`rs3mac`)
> has a different per-OS distribution and is acquired by the cross-platform Rust launcher: Linux from the
> `content.runescape.com` Ubuntu apt repo (`.deb`), Windows from `downloads/windows/RuneScape-Setup.exe`
> (Inno Setup → `innoextract`), macOS from `downloads/osx/RuneScape.dmg` (HFS → `7z`). The macOS patcher
> dylib lives at `client/launcher/patcher-mac/`; mac patch targets are documented in
> `docs/binary/patch-targets-macos.md`.
