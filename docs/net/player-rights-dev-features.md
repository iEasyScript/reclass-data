# Player Rights, Shift-Click Teleport & `::` Console Gating (rs2client.948-5)

**Target:** `rs2client.948-5` (Ghidra). All addresses are 948-5 target addresses.
**Question answered:** why an "admin" login does not enable shift-click teleport or the `::` developer console, and what the server must send to enable them.

---

## TL;DR (the one thing to change)

The client feature gate is **`playerRights`** = `LoggedInPlayer + 0x08` (engine `OLoggedInPlayer.PLAYER_RIGHTS = 0x8`), **NOT** `staffModLevel` (`+0x88`, lobby wire offset 7).

- The **world/game login** response (loginMode/loginType `== 2`) writes **`playerRights` from wire offset 1** (a plain unsigned byte → `LoggedInPlayer+0x08`).
- The **world login does NOT read `staffModLevel` at all**; it allocates a fresh `LoggedInPlayer` and leaves `+0x88 = -1`. So writing rights at the lobby's `staffModLevel` offset (7) is destroyed on world connect and is irrelevant to these features anyway.
- Shift-click teleport requires `playerRights > 0` **AND** client-side keyboard-modifier state — the server can only influence `playerRights`.

**Server action:** in the world/game login-success data block, put the rights/crown value (**must be `>= 1`**) at **wire offset 1** (unsigned byte, no transform). That lands in `playerRights`. Offset 7 (currently `00 01`) is `playerIndex` (g2 → `+0x48`), leave it.

---

## Key client structures / addresses (verified)

| Symbol | Location | Notes |
|---|---|---|
| `LoggedInPlayer` | `*(client + `<in Ghidra DB>`)` | engine `OClient.LOGGED_IN_PLAYER` |
| `LoggedInPlayer.playerRights` | `LoggedInPlayer + 0x08` (int) | engine `OLoggedInPlayer.PLAYER_RIGHTS`; **the gate field** |
| `LoggedInPlayer.playerIndex` | `LoggedInPlayer + 0x48` (u16→int) | engine `OLoggedInPlayer.PLAYER_INDEX` |
| `LoggedInPlayer.staffModLevel` | `LoggedInPlayer + 0x88` (signed int) | lobby-only; init `-1`; **NOT read by these features** |
| `MainLogicManager` | `*(client + `<in Ghidra DB>`)` | engine `OClient.MAINLOGIC_MANAGER` |
| `MainLogicManager` input flags | `MainLogicManager + 0x490` (bitfield) | client-side; bit0 & bit2 gate mouse teleport |
| `jag::game::SendDevTeleportCheat` | `<addr in DB>` | builds the `tele` string, runs it via console executor (was `<in Ghidra DB>`) |
| console executor | `<addr in DB>` | matches a registered `::` command, else falls through to CLIENT_CHEAT |
| `jag::ClientProt::SendClientCheat` | `<addr in DB>` | encodes ClientProt **CLIENT_CHEAT (op0, varByte)** |
| `jag::game::HandleDevTeleportKeybind` | `<addr in DB>` | Ctrl+Shift keybind dev-teleport (was `<in Ghidra DB>`) |
| `jag::LoginManager::LoginStepHandleLoginData` | `<addr in DB>` | parses BOTH lobby & world login-success data |
| `IsKeyDown(sdlKeycode)` | `<addr in DB>` | key-state RB-tree lookup (`<in Ghidra DB>`) |

---

## Shift-click teleport path

Shift-click on the 3D world / minimap / a scenery loc, when the gate passes, builds a console command string and sends it to the server as CLIENT_CHEAT. It is **not** a local teleport — the server must implement the `tele` command.

### `SendDevTeleportCheat(consoleCtx, plane, absTileX, absTileY)`

Builds (printf-style):

```
"tele %d,%d,%d,%d,%d"
        plane,
        absTileX >> 6,        // mapSquareX  (absolute tile X / 64)
        absTileY >> 6,        // mapSquareY  (absolute tile Y / 64)
        absTileX & 0x3f,      // localX      (0..63 within map square)
        absTileY & 0x3f       // localY      (0..63 within map square)
```

i.e. the wire text the server receives (inside CLIENT_CHEAT) is:

```
tele <level>,<mapSquareX>,<mapSquareY>,<localX>,<localY>
```

**5 comma-separated integers**, literal prefix `tele ` (a space after `tele`, commas with no spaces). The server's `::tele` command must parse exactly these 5 fields and reconstruct `absTileX = mapSquareX*64 + localX`, `absTileY = mapSquareY*64 + localY`, plane = field 1.

The string is executed via console executor `<addr in DB>`; an unrecognized command (which `tele` is, client-side) falls through to `jag::ClientProt::SendClientCheat` → **CLIENT_CHEAT (op0)**. See `re-resources/docs/net/clientprot-table.md` for op0's varByte wire format (`p1 count, p1 flagA, p1 flagB, then CP1252 string`).

### The gate (verified in 3 callers)

`jag::minimenuactions::ThreeDView::DoOpLoc` (`<addr in DB>`) and `jag::ClientProt::SendMoveMinimapClick` (`<addr in DB>`):

```c
loggedIn = *(client + `<in Ghidra DB>`);
if (playerEntity_exists) {
    flags = *(uint*)(*(client + `<in Ghidra DB>`) + 0x490);      // MainLogicManager+0x490
    if ( (int)loggedIn[0x08] > 0                          // playerRights > 0
         && (flags >> 2 & 1)                              // MLM+0x490 bit2
         && (flags & 1) ) {                               // MLM+0x490 bit0
        SendDevTeleportCheat(...);   // -> "tele ..." -> CLIENT_CHEAT
        return;
    }
    // else: normal walk / interact
}
```

Game-view raycast click (`<in Ghidra DB>`:

```c
if (*(byte*)(mlm + 0x490) & 4) {          // MLM+0x490 bit2
    loggedIn = *(client + `<in Ghidra DB>`);
    if (loggedIn != 0 && (int)loggedIn[0x08] > 0)   // playerRights > 0
        SendDevTeleportCheat(consoleCtx, plane, absTileX, absTileY);
}
```

**Two independent conditions** (so bit2 is NOT derived from rights):

1. `playerRights (LoggedInPlayer+0x08) > 0` — **server-controlled** (world login wire offset 1).
2. `MainLogicManager+0x490` bit2 (and bit0 for the minimap/loc paths) — **client-side input state** captured at click time (keyboard modifiers). The server cannot set this; the operator must hold the correct modifier key(s) while clicking.

### Ctrl+Shift keybind variant — `HandleDevTeleportKeybind`

```c
if (IsKeyDown(`<in Ghidra DB>` /*SDLK_LCTRL*/) && IsKeyDown(`<in Ghidra DB>` /*SDLK_LSHIFT*/)) {
    if (LoggedInPlayer_exists && playerEntity_exists) {
        GetPositionGrid(...);
        SendDevTeleportCheat(...);   // teleport self to hovered tile
    }
}
```

This path requires **Left-Ctrl + Left-Shift held**. It is the strongest hint for what `MainLogicManager+0x490` bits 0/2 represent on the mouse path (very likely the cached shift/ctrl modifier state). Confidence on the exact bit→key mapping is MEDIUM — the flag writer was not pinned; but it is unambiguously client-side input state, not a server value.

---

## `::` console

The console command executor (`<addr in DB>`) and CLIENT_CHEAT encoder (`<addr in DB>`) do **not** gate on `playerRights` themselves — they send unconditionally once a live game connection exists. The registered `::` commands (`getcamerapos`, `getclientvarp`, `debugcamera`, …) are registered in `<in Ghidra DB>` with `SendClientCheat` as the fallback for unknown commands. `jag::PacketHandlers::DoCheat` (`<in Ghidra DB>`..`) is a **server→client** packet that makes the client run a console command — unrelated to the input gate.

Whether the chat-box `::` prefix entry is separately gated on `playerRights` at the CS2/interface layer was not fully traced (MEDIUM confidence). But because the shift-click teleport (which routes through the SAME console→CLIENT_CHEAT machinery) is gated on `playerRights > 0`, the recommended fix (rights at world offset 1) is the correct lever for both symptoms. If the `::` box still does not send after rights are fixed, the remaining suspect is a client varc/interface-level enable — RE that separately.

---

## World login-success STATE MACHINE — full byte accounting (loginType == 2)

The world login-success response is consumed by the `LoginManager` step machine (step at `LoginManager+0x10`). Traced over the live server stream `[02][09 B5][<2485B varc>][02][2B][<43B loginData>]`:

| # | client step (`+0x10`) | fn | wire bytes consumed | effect |
|---|---|---|---|---|
| 1 | `0x5a` | `LoginStepWaitingDisallowResult` | **`[02]`** (1B) | responseCode → `+0x184` = 2 (SUCCESS); → step `0x60` |
| 2 | `0x60` | `LoginStepDealWithFirstResponse` | — | `+0x184==2` && loginType(`+0x20`)`==2` (world) → step **`0xFA`** (varc). (loginType`!=2` → `0x8c`, no varc) |
| 3 | `0xFA` | `…ServerClientVarLength` | **`[09 B5]`** (2B, g2 BE) | varc blockLen = 2485 → `+0x1c8`; → `0x104` |
| 4 | `0x104` | `…ServerClientVarConfigData` | **`[2485B]`** | copied into varc packet `+0x198`; → `0x10e` |
| 5 | `0x10e` | `…ServerClientVar` | — (parses the *separate* varc packet, not the connection) | block[0]=continuationFlag=1 → send LoginProt *continue*, → step **`0x82`** (flag 0 → loop to `0xFA`) |
| 6 | `0x82` | `LoginStepWaitingPlayersPacketReconnect` | **`[02]`** (1B) | → `+0x188` = 2; → step `0x88` |
| 7 | `0x88` | `LoginStepDealWithThirdResult` | — | requires `+0x188 == 2` (else disconnect) → step **`0x8c`** |
| 8 | `0x8c` | `LoginStepWaitingLoginCredentialsLength` | **`[2B]`** (1B, **g1**) | loginData length = 43 → `+0xd0`; → step `0x96` |
| 9 | `0x96` | `LoginStepHandleLoginData` | **`[43B loginData]`** | mode-2 parse; **`playerRights = loginData[1]`**; sets LOGGED_IN |

**Conclusion: the framing is CORRECT.** The order the client expects — **varc block BEFORE loginData** — is exactly what the server sends. The `[02]` between the varc block and the loginData length is the **required second response/success code** (step 0x82 reads it into `+0x188`; step 0x88 aborts the login unless it is `2`). The loginData length is **g1** (1 byte), matching the server's `writeByte(loginData.size)`. The client `MOVZX`es **loginData offset 1** (the `0x02` crown byte) into `LoggedInPlayer+0x08 = playerRights`. So **playerRights receives `2`** — the byte is placed correctly.

> Therefore the world-login framing is NOT the cause of a `playerRights==0` symptom. If an engine memory read of `*(client+`<in Ghidra DB>`)+0x08` in-world shows `2` (it should), the shift-click blocker is the client-side `MainLogicManager+0x490` modifier gate (hold **Ctrl+Shift**), not the login byte. If a staff account's capture shows `loginData[1]==0`, the account resolved to `Rights.PLAYER` (crown 0) — e.g. the `EnvVars.debug` no-lobby-grant + real-mongo path in `WorldLoginHandler` yields `PLAYER`.

## World / game login-success data (loginType == 2) — field map

`LoginStepHandleLoginData`. `loginType = *(LoginManager + 0x20)`. `== 2` is the **world/game** login (ends `SetMainState(0x1e)` = LOGGED_IN); other values are the lobby (`0x14`). Both branches allocate a **fresh** `LoggedInPlayer` at `client+`<in Ghidra DB>` (staffModLevel `+0x88` init = `-1`).

Compact world block, from the disassembly (offsets are into the data block; `wire[0]` is the first data byte after the `0x02`/length framing):

| wire off | read | dest field | notes |
|---|---|---|---|
| 0 | g1 | hasTotpUpdate | if `== 1`: ISAAC reseed path (`<in Ghidra DB>`) consumes extra bytes and shifts everything — keep this **0** |
| 1 | g1 | `+0x08` **playerRights** | **put crown/rights here, `>= 1`** |
| 2 | g1 | `+0x0C` | (membershipDays-like) |
| 3 | g1 (==1) | `+0x10` bool | |
| 4 | g1 (==1) | `+0x19` bool | |
| 5 | g1 (==1) | `+0x1A` bool | |
| 6 | g1 (==1) | (aux)`+0x08` bool | |
| 7..8 | g2 | `+0x48` **playerIndex** | your `00 01` currently lands here |
| 9 | g1 (==1) | `+0x28` bool | |
| 10..12 | g3s | `+0x14` recoveryDelay | signed medium |
| 13 | g1 (==1) | (quickchat bool) | |
| … | `<in Ghidra DB>(...)` | — | consumes additional bytes |
| … | g2 + g4 | `+0x90` | membership timestamp math |
| … | g8 | `LoginManager+0xf0` | session token 1 |
| … | g8 | `LoginManager+0xf8` | session token 2 |

**There is NO `staffModLevel` field in the world block.** The lobby block (see `lobby-login-data.md`) has `staffModLevel` at offset 7 → `+0x88`, but that is a different login step and a different field; it does not gate shift-click / dev world-click.

> ⚠️ Doc discrepancy to fix: `lobby-login-data.md` labels wire offset 1 → `+0x08` as **membershipType**. The verified engine offset (`OLoggedInPlayer.PLAYER_RIGHTS = 0x8`) and the in-binary dev-feature gate both treat `+0x08` as **playerRights**. Treat `+0x08` as `playerRights`.

---

## Current server state (as of this analysis)

`WorldLoginHandler.sendLoginResponse` (`world/.../server/login/WorldLoginHandler.kt`) **already** writes the correct thing:

```kotlin
writeByte(0)                     // wire[0] hasTotpUpdate = 0        ✓
writeByte(account.rights.crown)  // wire[1] -> +0x08 playerRights    ✓  (ADMIN.crown = 2)
...
writeShort(playerIndex)          // wire[7..8] -> +0x48 playerIndex  ✓
```

and `Rights`: `PLAYER(0), MOD(1), ADMIN(2), DEVELOPER(2), OWNER(2)`. So for an admin login the client receives `playerRights = 2`, which is `> 0`. **The server-controlled half of the gate is already satisfied.** `playerRights` is read at wire offset 1 which is parsed *before* any downstream string/field, so even if the tail of the block is misaligned, `playerRights` is set correctly.

Therefore, if shift-click teleport still does nothing for an admin, the cause is **not** the login byte. The two remaining suspects, in order:

1. **Client-side modifier keys not held.** The gate also needs `MainLogicManager+0x490` bit2 (+ bit0 for the minimap/loc paths). The parallel keybind path requires **Left-Ctrl + Left-Shift**. Try **Ctrl+Shift+left-click** on the 3D world, not Shift alone. The server cannot set this flag.
2. **The account isn't actually resolving to a staff tier** (`crown == 0`). Check the `WORLD login-data for … rights=… crown=…` log line — if `crown=0`, the account is `PLAYER` and `playerRights = 0` fails the `> 0` test. Ensure the account's `Rights` is `MOD`/`ADMIN`/`DEVELOPER`/`OWNER`.

## Recommendation for the networking-protocol-engineer

1. **Keep** writing rights/crown as a plain unsigned byte at **world wire offset 1** (already done). It lands in `LoggedInPlayer+0x08 = playerRights`. Do **not** move it to offset 7 (that's `playerIndex`, g2) and do **not** rely on lobby `staffModLevel` (+0x88) — the world login discards it.
2. Make sure the test account's `Rights.crown >= 1` (staff). `PLAYER.crown == 0` → feature disabled by design.
3. For the operator: shift-click teleport is really **Ctrl+Shift + click** (the client also gates on cached keyboard-modifier state that the server cannot control).
4. Server-side: implement the `tele` command to parse `tele <level>,<mapSquareX>,<mapSquareY>,<localX>,<localY>` (5 ints) arriving inside CLIENT_CHEAT (op0), reconstruct `absTile = mapSquare*64 + local`, and teleport the player. (This is the same command text the shift-click builds and sends.)

### Confidence

- **HIGH:** `tele` string format & 5-field coord scheme; the `playerRights (+0x08) > 0` gate; world login reads `+0x08` from wire offset 1 and does not read `+0x88`; `+0x88` reset to `-1` on world connect; struct offsets (engine-cross-verified).
- **MEDIUM:** exact meaning of `MainLogicManager+0x490` bit0/bit2 (client-side input modifiers, most likely shift/ctrl; writer not pinned); whether the chat-box `::` entry has an additional CS2/varc-level enable separate from `playerRights`.
