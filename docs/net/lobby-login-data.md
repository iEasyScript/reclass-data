# Lobby Login Data Format (rev 946)

**Source:** `jag::LoginManager::LoginStepHandleLoginData` in rs2client (Ghidra RE)
**Sent:** Server → Client after login response code 2 (SUCCESS)
**Wire format:** `[1B response_code=0x02] [1B data_length] [NB login_data]`

> **948-5 VERIFIED (handler.** The lobby field layout below is UNCHANGED from rev 946 —
> every field offset re-traced byte-for-byte in 948-5 (playerIndex g2 @ **offset 32-33 → +0x1C**,
> isMembersWorld @ **offset 47 → +0x18**, prefix 0-47 all match). See the CRITICAL note below.
>
> ⚠️ **CRITICAL — this handler decodes TWO DIFFERENT layouts keyed on `loginType` (`LoginManager+0x20`).**
> The table below is the **LOBBY** layout (`loginType != 2`, LOBBYLOGIN prot, ends `SetMainState(0x14)`).
> The **WORLD/GAME** login (`loginType == 2`, GAMELOGIN prot, ends `SetMainState(0x1e)` = LOGGED_IN)
> uses a **completely different, shorter block** — see [WORLD/GAME Login Data](#worldgame-login-data-logintype--2).
> **The in-world self player index the client/engine actually uses (`LoggedInPlayer+0x48`,
> `self = playerManager[+0x48]`) comes from the WORLD block at wire offset 7-8 — NOT the lobby's +0x1C.**

## Field Layout (LOBBY — loginType != 2)

| # | Offset | Read | Bytes | Field | Sample | Notes |
|---|--------|------|-------|-------|--------|-------|
| 1 | 0 | g1 | 1 | hasTotpUpdate | 0 | If 1: ISAAC re-seed (4 cipher bytes + g4 TOTP code) follows |
| 2 | 1 | g1 | 1 | playerRights | 0 | LoggedInPlayer+0x08. **Engine `OLoggedInPlayer.PLAYER_RIGHTS=0x8` + in-game dev-feature gate treat this as `playerRights`, NOT membershipType.** This is the field that gates shift-click teleport / dev world-click (`playerRights>0`). See `player-rights-dev-features.md`. |
| 3 | 2 | g1 | 1 | membershipDays | 0 | LoggedInPlayer+0x0C |
| 4 | 3 | g1 | 1 | emailValidated | 0 | Bool (`== 1`); +0x10 |
| 5 | 4-6 | g3s | 3 | recoveryDelay | -8388606 | Signed medium: if > `<in Ghidra DB>` then subtract `<in Ghidra DB>` |
| 6 | 7 | g1s | 1 | staffModLevel | 1 | Signed byte cast to int; +0x88 |
| 7 | 8 | g1 | 1 | unknownFlag1 | 0 | Bool; +0x19 |
| 8 | 9 | g1 | 1 | unknownFlag2 | 1 | Bool; +0x1A |
| 9 | 10-17 | g8 | 8 | membershipTimestamp | 1631993231463 | Unix millis; +0x30 |
| 10 | 18 | g1 | 1 | timeDaysByte | 223 | Used in: `(membershipTs - now) - timeMillisInt - (timeDaysByte << 32)` |
| 11 | 19-22 | g4 | 4 | timeMillisInt | 128664087 | See above |
| 12 | 23 | g1 | 1 | flagsByte | 0x00 | bit0 = quickChatOnly (+0x28), bit1 = unknown (+0x29) |
| 13 | 24-27 | g4 | 4 | lastLoginIP | 0 | +0x40 |
| 14 | 28-31 | g4 | 4 | lastLoginDays | 5000 | +0x44 |
| 15 | 32-33 | g2 | 2 | playerIndex | 0 | +0x1C |
| 16 | 34-35 | g2 | 2 | unknown3 | 0 | +0x20 |
| 17 | 36-37 | g2 | 2 | unknown4 | 8573 | +0x60 |
| 18 | 38-41 | g4 | 4 | unknown5 | `<in Ghidra DB>` | +0x64 |
| 19 | 42 | g1 | 1 | unknown6 | 3 | +0x24 |
| 20 | 43-44 | g2 | 2 | unknown7 | 53791 | +0x38 |
| 21 | 45-46 | g2 | 2 | unknown8 | 53791 | +0x3C |
| 22 | 47 | g1 | 1 | isMembersWorld | 0 | Bool; +0x18 |
| 23 | 48-56 | gjStr | 9 | displayName | "Mememom" | Versioned: [1B ver=0x00][string][NUL] |
| 24 | 57 | g1 | 1 | unknown9 | 2 | +0x84 |
| 25 | 58-61 | g4 | 4 | unknown10 | <addr in DB> | +0x80 |
| 26 | 62-63 | g2 | 2 | worldId | 3 | 0xFFFF = -1 |
| 27 | 64-85 | gjStr | 22 | serverHostname | "world3.runescape.com" | Versioned string |
| 28 | 86-87 | g2 | 2 | gamePort | 43594 | TCP game port |
| 29 | 88-89 | g2 | 2 | httpsPort | 443 | HTTPS port |
| 30 | 90-97 | g8 | 8 | sessionToken1 | `<in Ghidra DB>`13154028 | LoginManager session state |
| 31 | 98-105 | g8 | 8 | sessionToken2 | `<in Ghidra DB>`0E4004A4 | LoginManager session state |

**Total: 106 bytes** (sample data from live Jagex lobby login, March 2026)

## gjStr (Versioned String)

```
version = g1
if version != 0: return ""  // invalid version → empty string
return gStr               // null-terminated CP1252 string
```

## Notes

- The `hasTotpUpdate` field at offset 0 gates an ISAAC re-seed path. When 1, the client reads 4 ISAAC cipher values then a g4 TOTP code before proceeding.
- `recoveryDelay` uses signed 24-bit (medium) encoding. Value -8388606 likely means "recovery not set".
- `lastLoginDays` = 5000 appears to mean "never logged in before" or "very long ago".
- `unknown5` (`<in Ghidra DB>`) at +0x64 may be a CRC or hash.
- `unknown7` and `unknown8` are identical (53791 = 0xD21F) in sample — possibly related build/version numbers.

## WORLD/GAME Login Data (loginType == 2)

**948-5 verified** by disassembly of `jag::LoginManager::LoginStepHandleLoginData`, world
branch. This is the block the client parses after a **GAMELOGIN** (connecting to a game
world), distinct from the LOBBYLOGIN block above. The branch is selected by `loginType` (`LoginManager+0x20`):
`== 2` → this short world layout + `Client::SetMainState(0x1e)` (LOGGED_IN / 3D world); otherwise → the
full lobby layout above + `SetMainState(0x14)`.

The client decides `loginType` itself (GAMELOGIN vs LOBBYLOGIN) before it sends its login packet — the
server cannot change which layout the client uses to parse. **A world connection is always parsed with this
layout.**

| # | Offset | Read | Bytes | Field | Store | Notes |
|---|--------|------|-------|-------|-------|-------|
| 1 | 0 | g1 | 1 | hasTotpUpdate | — | If 1: ISAAC re-seed path runs first |
| 2 | 1 | g1 | 1 | playerRights | `+0x08` | Same field/offset as lobby. Gates shift-click teleport / dev world-click (`>0`) |
| 3 | 2 | g1 | 1 | membershipDays | `+0x0C` | |
| 4 | 3 | g1 | 1 | emailValidated | `+0x10` | bool `== 1` |
| 5 | 4 | g1 | 1 | unknownFlag1 | `+0x19` | bool |
| 6 | 5 | g1 | 1 | unknownFlag2 | `+0x1A` | bool |
| 7 | 6 | g1 | 1 | someFlag | (secondary struct `+0x08`) | bool; written to the 0x18-byte login sub-struct, not LoggedInPlayer |
| 8 | **7-8** | **g2** | **2** | **playerIndex (serverIndex)** | **`+0x48`** | **THE in-world self slot id. `self = playerManager[+0x48]`. Engine `OLoggedInPlayer.PLAYER_INDEX=0x48`.** |
| 9 | 9 | g1 | 1 | someBool | `+0x28` | bool |
| 10 | 10-12 | g3s | 3 | recoveryDelay | `+0x14` | signed medium (BE) |
| 11 | 13 | g1 | 1 | isMembersWorld | (membership state) | bool; drives the members-world state update |
| 12 | 14+ | (string) | var | displayName | `client+`<in Ghidra DB>` | read by a string helper (`<in Ghidra DB>`); exact framing not byte-traced here |
| 13 | … | g2 + g4 | 6 | membershipTimestamp | `+0x90` | `(g4 - now/1e6) + (g2 << 32)` |
| 14 | … | g8 | 8 | sessionToken1 | `LoginManager+0xF0` | reconnect/world-hop token |
| 15 | … | g8 | 8 | sessionToken2 | `LoginManager+0xF8` | reconnect/world-hop token |

### Key differences vs the LOBBY layout

- The layouts are identical only for offsets 0-3 (`hasTotpUpdate`, `playerRights`, `membershipDays`,
  `emailValidated`). They **diverge from offset 4 onward.**
- **playerIndex:** WORLD = g2 @ **offset 7-8 → +0x48**; LOBBY = g2 @ offset 32-33 → +0x1C. On a world login
  the lobby's `+0x1C` is never written (stays at init `-1`); on a lobby login `+0x48` stays `-1`.
- **isMembersWorld:** WORLD @ offset **13**; LOBBY @ offset **47**.
- **staffModLevel (`+0x88`):** only the LOBBY block writes it (offset 7, signed byte). The WORLD block never
  writes `+0x88`, so a world login leaves it at init `-1`.
- The WORLD block has no `lastLoginIP`/`lastLoginDays`/`worldId`/hostname/port fields — those are
  lobby-only. The world's own host/port were already known (the client dialed it).

### Implication for the server world login (WorldLoginHandler)

The value the client uses as its own slot id in-world is `LoggedInPlayer+0x48`, read from **world wire
offset 7-8** (g2, big-endian). A world-login response that places the server-allocated player index anywhere
other than offset 7-8 will leave the client's self index reading whatever bytes happen to sit at 7-8. Writing
the index at the lobby position (offset 32-33) has **no effect on the world client's self index** — that byte
range falls inside the misparsed display-name/timestamp region under this layout.
