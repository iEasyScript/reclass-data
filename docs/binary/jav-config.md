# jav_config.ws Format Documentation

## Source
Fetched from `https://www.runescape.com/k=5/l=0/jav_config.ws?binaryType=4` (Linux NXT client, rev 946).

A live copy is saved at `docs/binary/jav_config_live.ws`.

## Format

Plain text, line-delimited (`\n`), three types of lines:

1. **`key=value`** — General config properties (e.g. `title=RuneScape`, `codebase=...`)
2. **`msg=key=value`** — Message strings (e.g. `msg=lang0=English`, `msg=ok=OK`)
3. **`param=N=value`** — Numbered parameters passed as CLI args to the NXT binary

The NXT binary's parser (`<in Ghidra DB>`) splits by `\r\n`, then categorizes each line:
- Lines starting with `msg=` → stored in message map (key after `msg=` is the message key)
- Lines starting with `param=` → stored in param map (number after `param=` is the key)
- Everything else → stored in general config map (key before first `=`)

## General Config Keys

| Key | Example Value | Description |
|-----|---------------|-------------|
| `title` | `RuneScape` | Window title |
| `codebase` | `https://world3.runescape.com/k=5/` | Base URL for client binary downloads |
| `binary_name` | `rs2client` | Name of the main executable |
| `download_name_N` | `rs2client` | Filename of Nth downloadable binary |
| `download_crc_N` | `960095066` | CRC32 of Nth binary |
| `download_hash_N` | `d9p94k...` | Hash of Nth binary |
| `binary_count` | `1` | Number of binaries to download |
| `launcher_version` | `224` | Expected launcher compatibility version |
| `server_version` | `946` | Game version (must match JS5 handshake) |
| `launcher_sub_version` | `1` | Sub version |
| `cache_variant_suffix` | (empty) | Cache variant suffix |
| `termsurl` | `https://legal.jagex.com/docs/terms` | Terms of service URL |
| `privacyurl` | `https://legal.jagex.com/docs/policies` | Privacy policy URL |
| `download` | `8789335` | Total download size in bytes |
| `window_preferredwidth` | `1024` | Default window width |
| `window_preferredheight` | `768` | Default window height |
| `applet_minwidth` | `765` | Minimum window width |
| `applet_minheight` | `540` | Minimum window height |
| `applet_maxwidth` | `3840` | Maximum window width |
| `applet_maxheight` | `2160` | Maximum window height |
| `advert_height` | `96` | Advert banner height |

## Param Keys (param=N=value)

Parameters are passed as numbered CLI arguments to the NXT binary.

| Param | Live Value | Description |
|-------|-----------|-------------|
| 1 | `0` | Unknown |
| 2 | `1101` | Unknown (build/revision related?) |
| 3 | `lobby2a.runescape.com` | **Lobby server host** |
| 4 | `0` | Unknown |
| 5 | `0` | Unknown |
| 6 | `0` | Unknown |
| 7 | `0` | Unknown |
| 8 | `false` | Unknown |
| 10 | `wwGlrZHF5gKN6D3mDdihco3oPeYN2KFybL9hUUFqOvk` | **Login server token** |
| 11 | `225` | Unknown |
| 13 | `false` | Unknown |
| 14 | `false` | Unknown |
| 15 | (empty) | Unknown |
| 16 | `.runescape.com` | **Cookie domain** |
| 17 | `false` | Unknown |
| 18 | `-1187320092` | Unknown (hash/seed?) |
| 19 | (empty) | Unknown |
| 20 | `false` | Unknown |
| 21 | `halign=true\|valign=true\|...` | Loading screen layout |
| 22 | (empty) | Unknown |
| 23 | `false` | Unknown |
| 24 | `true` | Unknown |
| 25 | `0` | Unknown |
| 26 | `false` | Unknown |
| 27 | `3` | Unknown |
| 28 | `265964763` | Unknown (hash/seed?) |
| 29 | `bLZjB2W-UpMoPT-k-QPJ7hmykSCAaj0n` | **JS5 server token** |
| 31 | `19435` | Unknown |
| 32 | (empty) | Unknown |
| 33 | (empty) | Unknown |
| 34 | `547933620` | Unknown (hash/seed?) |
| 35 | `https://world3.runescape.com/k=5` | **World server URL** |
| 36 | `https://secure.runescape.com/m=gamelogspecs/...` | Stats/telemetry URL |
| 37 | `content.runescape.com` | **Content server host** |
| 38 | `1200` | Unknown (timeout?) |
| 39 | `false` | Unknown |
| 40 | `https://world3.runescape.com/k=5` | **World server URL (alt)** |
| 41 | `43594` | **Game port 1** |
| 42 | `443` | **Game port 2 (SSL)** |
| 43 | `43594` | **Game port 3** |
| 44 | `443` | **Game port 4 (SSL)** |
| 45 | `43594` | **Game port 5** |
| 46 | `443` | **Game port 6 (SSL)** |
| 47 | `43594` | **Game port 7** |
| 48 | `443` | **Game port 8 (SSL)** |
| 49 | `content.runescape.com` | **Content server host** |
| 50 | `0` | Unknown |
| 51 | `0` | Unknown |
| 52 | `0` | Unknown |
| 53 | `https://auth.jagex.com/` | Auth URL |
| 54 | `https://payments.jagex.com/` | Payments URL |
| 55 | `196515767263-...` | Google OAuth client ID |
| 56 | `https://social.auth.jagex.com/` | Social auth URL |
| 57 | `6124` | Unknown |
| 58 | `https://account.jagex.com/` | Account URL |
| 59 | `https://auth.runescape.com/` | RuneScape auth URL |
| 60 | `0` | Unknown |

## Binary Types

The `binaryType` query parameter selects the platform:

| Value | Platform |
|-------|----------|
| 1 | Windows 32-bit |
| 2 | Windows 64-bit |
| 3 | macOS |
| 4 | Linux |
| 5 | Windows 32-bit + DLLs |
| 6 | Windows 64-bit + DLLs |

## How the Launcher Uses It

From `nxtlauncher` (syldrathecat/nxtlauncher):

1. Fetches `jav_config.ws` from the `--configURI` URL (default: `https://www.runescape.com/k=5/l=$(Language:0)/jav_config.ws?binaryType=4`)
2. Reads `codebase`, `binary_count`, `download_name_N`, `download_crc_N` to download/verify client binaries
3. Reads `title`, `binary_name`, `launcher_version` for launch configuration
4. Passes all `param=N` entries as CLI arguments to the NXT binary: `param_key param_value` pairs
5. Communicates with client via IPC FIFOs (`/tmp/RS2LauncherConnection_XXXX_{i,o}`)

## Config URL Used by Binary

The NXT binary itself references:
- `https://rs.config.runescape.com/l=%i/jav_config.ws?binaryType=%s`
- `http://%s/jav_config.ws?binaryType=%s` (custom server fallback)

The `server_version` key is read by `<in Ghidra DB>` and compared against the expected version for JS5 handshake validation.
