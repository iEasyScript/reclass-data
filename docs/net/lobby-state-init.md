# Lobby State Initialization (mainState 0x14) - rs2client rev 946

**Binary**: rs2client (Ghidra port 8080, STRIPPED)
**Verified**: 2026-03-12

---

## 1. How the Client Enters Lobby State

### Login Step Sequence (Lobby Login)

The login step machine in `LoginManager` processes these steps in order:

```
Step 0x0A (10)  -> LoginStepInit (start login)
Step 0x0D (13)  -> LoginStepWaitingSSOKey
Step 0x0E (14)  -> LoginStepWaitingConnectionOpened
Step 0x0F (15)  -> LoginStepWaitingSSOKeyResponse (sends connection type byte 14)
Step 0x1E (30)  -> LoginStepWaitingFirstResponse (reads 9 bytes: 1 response + 8 session key)
Step 0x28 (40)  -> LoginStepWaitingSecondResponse (reads 2-byte XTEA challenge length)
Step 0x32 (50)  -> LoginStepDealWithSecondResponse (reads XTEA challenge)
Step 0x3C (60)  -> LoginStepWaitingThirdResponse (reads 1-byte go-ahead)
Step 0x46 (70)  -> LoginStepDealWithThirdResponse (reads 16-byte XTEA login token)
Step 0x50 (80)  -> LoginStepSendLoginPacket (sends opcode 19 + login packet)
Step 0x5A (90)  -> LoginStepWaitingDisallowResult (reads 1-byte result)
Step 0x60 (96)  -> LoginStepDealWithFirstResponse (dispatches on result code)
                   Result 2 (SUCCESS) for lobby -> loginStep = 0x8C
Step 0x8C (140) -> LoginStepWaitingLoginCredentialsLength (reads 1-byte data length)
Step 0x96 (150) -> LoginStepHandleLoginData (reads lobby data, THE KEY STEP)
```

### LoginStepHandleLoginData (Step 150) - State Transition

**Function**: `jag::LoginManager::LoginStepHandleLoginData` at `<addr in DB>`

After reading the lobby data blob, this function:

1. Creates a new `LoginState` object (0xF0 bytes) and populates it with parsed fields
2. Stores LoginState in the Client object
3. Clears stat/inventory tables
4. If session tokens changed from previous: clears JS5 disk cache
5. Sets `loginStep = 0` (IDLE - login manager is done)
6. Sets `normalLoginResult = 2` (SUCCESS)
7. **Calls `Client::SetMainState(0x14)` (LOBBY)**

For game login (loginType == 2), it would set `SetMainState(0x1E)` instead.

### What SetMainState(0x14) Does

**Function**: `jag::Client::SetMainState` at `<addr in DB>`

`SetMainState` iterates a list of subsystem observer objects (`this+`<in Ghidra DB>`..`<in Ghidra DB>`) and calls each observer's vtable+0x10 method with `(oldState, newState)`. Then sets `this->mainState = newState` at offset `<in Ghidra DB>`.

The observers are subsystems that react to state transitions (e.g., resetting internal state, starting/stopping processing). The exact observers are not enumerated here but include the connection manager, interface manager, and other subsystems.

---

## 2. The LoginProtocolHandler Main Loop

**Function**: `jag::ConnectionManager::LoginProtocolHandler` at `<addr in DB>`

After login completes (loginStep = 0), the client continues executing the LoginProtocolHandler which acts as the main game loop. It checks `Client.mainState` to determine what to do each tick.

### State Dispatch Logic

```
mainState = Client->mainState  (at offset `<in Ghidra DB>`)

if (mainState == 0):
    // PRE-LOGIN: waiting for config provider, scene manager
    // Checks configProvider state == 4, sets up skill defaults
    // Transitions: SetMainState(1)

else if (mainState == 1):
    // TRANSITIONAL: checks if field_`<in Ghidra DB>` is ready
    // If field_`<in Ghidra DB>` is null or field_`<in Ghidra DB>`+0x4c is 0:
    //     SetMainState(10)  // transition to active state
    // goto <in Ghidra DB> (continue to packet processing)

else:  // mainState >= 2 (includes 0x14=LOBBY, 0x1E=WORLD)
    // ACTIVE GAME LOOP
    // Two sub-branches based on field_`<in Ghidra DB>`+0x1c:

    if (*(field_`<in Ghidra DB>` + 0x1c) == 0):
        // LOBBY BRANCH (no world loaded)
        <in Ghidra DB>(clientPtr+`<in Ghidra DB>`)  // Interface update (includes ExecuteOnLoad)
        ScriptRunner::ProcessScripts    // Process CS2 scripts
        ProcessConnections              // Read & dispatch server packets

    else:
        // WORLD BRANCH (world loaded, field_`<in Ghidra DB>`+0x1c != 0)
        <in Ghidra DB>                    // World update (entity ticking, etc.)
        ProcessConnections              // Read & dispatch server packets
        // Process var changes
        ClientProt::SendSceneGraphReport  // Send scene graph report
        // If mainState == 0x1E: SendAppletFocusEvents
        <in Ghidra DB>                    // LoginManager tick (keepalive, reconnect)
        <in Ghidra DB>                    // Interface update
```

**Key finding**: In lobby state (mainState 0x14), `field_`<in Ghidra DB>`+0x1c` is 0, so the LOBBY BRANCH executes. This branch:
1. Updates interfaces (<in Ghidra DB> which calls `ExecuteOnLoad` for newly opened interfaces)
2. Processes CS2 scripts
3. Processes incoming server connections/packets

---

## 3. Rendering Gate in MainLogic

**Function**: `jag::Client::MainLogic` at `<addr in DB>`

MainLogic runs every frame regardless of mainState. It contains a rendering gate that determines whether the client actually draws anything to screen.

### Bitmask Check

```c
if ((1 << mainState) & `<in Ghidra DB>`) != 0
```

Binary: `<in Ghidra DB>` = bits 10, 20, 24, 28 set.
- Bit 10 = mainState 0x0A (loading?)
- Bit 20 = mainState 0x14 (lobby) -- YES, lobby IS in the render mask
- Bit 24 = mainState 0x18 (world?)
- Bit 28 = mainState 0x1C (?)

**Lobby state passes this check.** The bitmask explicitly includes state 0x14.

### Field Gate Conditions

After the bitmask check, rendering is further gated on several fields:

| Field Offset (from Client) | Condition | Purpose (estimated) |
|---|---|---|
| `+`<in Ghidra DB>` | Must be != 0 | Possibly a "ready" flag or frame counter |
| `+`<in Ghidra DB>` | Must be non-null | Possibly a renderer or display object |
| `+`<in Ghidra DB>` | Must be non-null | Possibly a scene graph or UI root |
| `+`<in Ghidra DB>` | Must be non-null | Possibly a texture/resource manager |
| `+`<in Ghidra DB>` | Non-empty string | Possibly a session or config string |

Additionally, `<in Ghidra DB>` must return a truthy value (likely checks if the graphics subsystem is initialized).

These fields are likely initialized during client startup (graphics init, resource loading, etc.) rather than during the login protocol. If the client has been running long enough to show a login screen, these fields should already be set.

---

## 4. SCENE_GRAPH_REPORT (ClientProt Opcode 50)

**Function**: `jag::ClientProt::SendSceneGraphReport` at `<addr in DB>`

### When It Is Sent

SendSceneGraphReport is called ONLY from the WORLD BRANCH of the LoginProtocolHandler main loop (when `field_`<in Ghidra DB>`+0x1c != 0`). It is NOT sent in lobby state.

However, it has a guard condition:
```c
mainState = *(client + `<in Ghidra DB>` + baseOffset)
if (mainState < 0x1f && ((`<in Ghidra DB>` >> mainState) & 1) != 0 && client->field_0x14 != 0)
```

The bitmask `<in Ghidra DB>` enables sending for states where bits are set:
- Bit 20 (0x14 = LOBBY) is NOT set in `<in Ghidra DB>`
- Bit 24 (0x18) IS set
- Bit 28 (0x1C) IS set
- Bit 30 (0x1E = WORLD) IS set

So even in the world branch, SceneGraphReport is only sent for specific states (0x18, 0x1C, 0x1E).

### What the Payload Means

The 4-byte payload is `client->field_0x10`, which appears to be a frame/tick counter or scene graph generation number. The value `00 00 00 02` indicates the second frame/tick of the current session.

---

## 5. Interface System and IF_OPENTOP

### IF_OPENTOP Handler (ServerProt Opcode 207 / 0xCF, size 2)

**CORRECTION:** Previously documented as opcode 108 (which is actually IF_SETOBJECT_ALWAYSNUM).
Verified from RegisterAll: `InitEntry(&<in Ghidra DB>, 0xcf, 2)`.
The packet payload is just 2 bytes: ushort BE interface ID. No walkType.

The handler creates an InterfaceManager update entry of type 0xC, marks it dirty, and stores the
interface ID via `SetUpdateSlotValue(entry+0x20, &interfaceId)`. The dirty entry is processed by
<in Ghidra DB> on the next tick. When the interface loads, `ScriptRunner::ExecuteOnLoad` fires for all
components.

### Interface Update Pipeline

```
Server sends IF_OPENTOP (opcode 0xCF)
  -> ProcessConnections dispatches the packet handler
  -> IF_OPENTOP handler creates a dirty update entry of type 0xC
  -> On next tick, <in Ghidra DB> processes dirty entries
  -> Interface definition is loaded from cache (archive 3)
  -> Components are created and laid out
  -> ScriptRunner::ExecuteOnLoad fires OnLoad scripts for each component
  -> Components become visible and renderable
```

---

## 6. TcpIn: ISAAC Opcode Decoding

**Address:** `jag::ConnectionManager::TcpIn`

Reads raw bytes from the connection buffer and decodes ServerProt opcodes using the ISAAC cipher:

```
raw_byte = read_byte
decoded = (raw_byte - isaac_next) & 0xFF

if decoded < 128:
    opcode = decoded
else:
    second_byte = read_byte
    opcode = (decoded - 128) * 256 + second_byte
```

Then looks up the handler in `g_serverProtVector` (217 entries at `<addr in DB>`) and dispatches.

**ISAAC cipher setup (verified):**
- Client recv cipher: `Isaac(keys + delta)` where delta values are at `<addr in DB>`
- Client send cipher: `Isaac(raw_keys)` (no delta)
- Server must use: outCipher = `Isaac(keys + delta)`, inCipher = `Isaac(raw_keys)`

This has been verified to work -- ISAAC-encrypted packets are decoded correctly by the client.

### ProcessConnections in_SIL Parameter

There is a parameter (`in_SIL` in Ghidra decompilation) in ProcessConnections that gates whether TcpIn is called. If this parameter is `'\0'`, TcpIn is NOT called and no packets are processed. This appears to be a Ghidra artifact for the RSI register. At runtime the actual value needs to be non-zero for packet processing to occur. This is likely always true for the lobby connection but worth noting if packets appear to not be processed.

---

## 7. What the Server MUST Send for Lobby Rendering

### Verified Minimum Sequence (from projectx reference + RE analysis)

The projectx reference lobby server (targeting ~rev 880) sends this sequence after login success:

```
1. Login result: [1B] 2 (SUCCESS) + [1B] dataLength + [NB] lobbyData
   -- ISAAC ciphers initialized at this point --
2. Vars:
   - SET_VARP_INT(281, 1000)
   - SET_VARP_SMALL(2528, 1)
   - SET_VARP_SMALL(2567, 1)
   - SET_VARBIT_SMALL(10242, 1)
   - SET_VARBIT_SMALL(10243, 12)
   - SET_VARC_INT(1919, 1)
   - SET_VARBIT_SMALL(11162, 1)
3. (Social login/friends list initialization)
```

**CRITICAL NOTE**: The projectx reference (targeting ~rev 880 Java client) does NOT send `IF_OPENTOP`.
The old Java client auto-opens the lobby interface via `LoginManager.openLobby` which is called
from `setGameState` when transitioning to lobby state. It reads the interface ID from
`EntityDefaults.lobbyWindow` (cache index 28, file 3, opcode 6).

**The NXT client (rev 946) does NOT auto-open the lobby interface.** The entity defaults in the
rev 946 cache do not contain a `lobbyWindow` field (opcode 6 is absent). The server MUST send
IF_OPENTOP (opcode 207/0xCF) with the lobby interface ID.

### ROOT CAUSE FOUND (2026-03-12)

**The server was sending the wrong opcode for IF_OPENTOP.**

- Server was using opcode **108 (0x6C)** which is actually **IF_SETOBJECT_ALWAYSNUM** (size 6)
- Correct opcode is **207 (0xCF)** with size **2** (just ushort BE interface ID)
- This was verified from RegisterAll: `InitEntry(&<in Ghidra DB>, 0xcf, 2)`
- The incorrect documentation in `docs/net/serverprot/interfaces.md` and `if-opentop.md` was the source of the error

Additionally:
- The old packet format included a 4-byte g4s_alt2 walkType field. The correct rev 946 format is just 2 bytes.
- Interface 1477 DOES exist in the cache (78360 bytes decompressed) and is likely the correct lobby interface.
- The NXT client does NOT auto-open the lobby interface (unlike the old Java client). The server MUST send IF_OPENTOP.

**Fix applied:** Changed `IF_OPENTOP` constant from `0x6C` to `0xCF` and removed the 4-byte walkType from the packet payload.

---

## 8. Lobby ServerProt Handlers (Confirmed in rev 946)

From `g_serverProtVector` analysis, the following handlers are confirmed as lobby-relevant:

| Name | Opcode | Size | Description |
|---|---|---|---|
| NO_TIMEOUT | 0x92 (146) | 0 (fixed) | Keepalive -- trivial handler, returns immediately |
| CREATE_CHECK_EMAIL_REPLY | 0x85 (133) | 1 (fixed) | Account creation email check reply |
| CREATE_CHECK_NAME_REPLY | 0xCC (204) | 1 (fixed) | Account creation name check reply |
| CHANGE_LOBBY | 0x11 (17) | varShort | Reads CP1252 strings, builds vector (world list?) |

**Not found in rev 946** (present in older revisions):
- CREATE_ACCOUNT_REPLY
- CREATE_SUGGEST_NAME_ERROR
- CREATE_SUGGEST_NAME_REPLY
- LOBBY_APPEARANCE (may be handled through player info system)

The lobby shares the full `g_serverProtVector` table (217 entries) with the world -- there is no separate lobby-only handler table. Any ServerProt that works in-world also works in lobby (IF_OPENTOP, SET_VARC, VARP_SMALL, VARP_LARGE, etc.).

---

## 9. Login Step Map (Complete)

| Step (hex) | Step (dec) | Function | Direction |
|-----------|-----------|----------|-----------|
| 0x0A | 10 | LoginStepInit | - |
| 0x0C | 12 | LoginStepWaitingLoginCredentials | - |
| 0x0D | 13 | LoginStepWaitingSSOKey | - |
| 0x0E | 14 | LoginStepWaitingConnectionOpened | - |
| 0x0F | 15 | LoginStepWaitingSSOKeyResponse | C->S |
| 0x1E | 30 | LoginStepWaitingFirstResponse | S->C |
| 0x28 | 40 | LoginStepWaitingSecondResponse | S->C |
| 0x32 | 50 | LoginStepDealWithSecondResponse | S->C |
| 0x3C | 60 | LoginStepWaitingThirdResponse | S->C |
| 0x46 | 70 | LoginStepDealWithThirdResponse | S->C |
| 0x50 | 80 | LoginStepSendLoginPacket | C->S |
| 0x5A | 90 | LoginStepWaitingDisallowResult | S->C |
| 0x5C | 92 | LoginStepWaitingReasonLength | S->C |
| 0x60 | 96 | LoginStepDealWithFirstResponse | dispatch |
| 0x6E | 110 | LoginStepWaitingSendContinue | C->S |
| 0x78 | 120 | LoginStepWaitingInQueue | S->C |
| 0x82 | 130 | LoginStepWaitingPlayersPacketReconnect | S->C |
| 0x84 | 132 | LoginStepWaitingThirdReasonLength | S->C |
| 0x88 | 136 | LoginStepDealWithThirdResult | - |
| 0x8C | 140 | LoginStepWaitingLoginCredentialsLength | S->C |
| 0x96 | 150 | LoginStepHandleLoginData | S->C |
| 0xBE | 190 | LoginStepWaitingDisallowResult2 | S->C |
| 0xC8 | 200 | LoginStepWaitingTempBanned | S->C |
| 0xD2 | 210 | LoginStepWaitingForTOTPPassCode | - |
| 0xDC | 220 | LoginStepWaitingURLLength | S->C |
| 0xE6 | 230 | LoginStepWaitingURL | S->C |
| 0xF0 | 240 | LoginStepWaitingHopBlockTime | S->C |
| 0xFA | 250 | LoginStepWaitingServerClientVarLength | S->C |
| 0x104 | 260 | LoginStepWaitingServerClientVarConfigData | S->C |
| 0x10E | 270 | LoginStepWaitingServerClientVar | S->C |
| 0x118 | 280 | StartRSAPacket (legacy) | C->S |
| 0x122 | 290 | CheckLoaded | - |
| 0x12C | 300 | LoginStepWaitingReasonLength2 | S->C |
| 0x136 | 310 | LoginStepWaitingSocialNetworkTokenLength | S->C |

---

## 10. Open Questions

1. **What are the rendering gate fields?** Fields at Client+`<in Ghidra DB>`, +`<in Ghidra DB>`, +`<in Ghidra DB>`, +`<in Ghidra DB>` gate rendering in MainLogic. Are they initialized during client startup (pre-login) or do they require specific packets? Most likely pre-login (graphics subsystem init).

2. **ProcessConnections in_SIL parameter:** Is this always non-zero for the lobby connection at runtime? If it's zero, TcpIn never runs and no packets are processed.

3. **Login data blob format:** The exact format parsed by `LoginStepHandleLoginData` needs byte-level documentation. See `login-protocol.md` and `lobby-login-data.md`.

4. **Is CHANGE_LOBBY (opcode 0x11) the world list packet?** Its handler reads strings and builds a vector, which is consistent with world list data.

---

## 11. Recommendations for Black Screen Issues

1. **Verify IF_OPENTOP opcode is 0xCF** (207) with 2-byte payload (ushort BE interface ID)
2. **Send lobby vars** matching the reference (varp 281, 2528, 2567; varbits 10242, 10243, 11162; varc 1919)
3. **Verify login data blob format** -- RE `LoginStepHandleLoginData` at byte level to ensure the server's lobby data blob matches what rev 946 expects
4. **Send NO_TIMEOUT (0x92) periodically** as a keepalive
5. **Check if the client needs world list data** (CHANGE_LOBBY / opcode 0x11) before it renders

---

## 12. Function Address Reference

| Address | Function | Notes |
|---------|----------|-------|
| <addr in DB> | Client::SetMainState | Notifies observers, sets mainState |
| <addr in DB> | ConnectionManager::LoginProtocolHandler | Main game loop |
| <addr in DB> | Client::MainLogic | Rendering gate logic |
| <addr in DB> | ConnectionManager::ProcessConnections | Per-state connection processing |
| <addr in DB> | ConnectionManager::TcpIn | ISAAC opcode decoding, packet dispatch |
| <addr in DB> | ClientProt::SendSceneGraphReport | Sends scene graph state to server |
| <addr in DB> | packethandlers::Interfaces::IF_OPENTOP | Opens top-level interface |
| <addr in DB> | <in Ghidra DB> | Interface update tick (calls ExecuteOnLoad) |
| <addr in DB> | ScriptRunner::ProcessScripts | CS2 script processing |
| <addr in DB> | ScriptRunner::ExecuteOnLoad | Fires OnLoad hooks for interface |
| <addr in DB> | LoginStepHandleLoginData | Parses login data, sets mainState(0x14) |
| <addr in DB> | LoginStepDealWithFirstResponse | Dispatches on login result code |
| <addr in DB> | LoginManager::SendLoginPacketInner | Sends login packet, initializes ISAAC |
| <addr in DB> | LoginStepWaitingServerClientVarConfigData | Reads SCV config data |
| <addr in DB> | LoginStepWaitingServerClientVar | Processes server client vars |
| <addr in DB> | RESET_CLIENT_STATE handler | Creates new client state object |
| <addr in DB> | InterfaceManager::MarkUpdateEntryDirty | Marks interface entry for processing |
| <addr in DB> | InterfaceManager::CreateOrFindUpdateEntry | Gets/creates update entry |
| <addr in DB> | g_serverProtVector | 217 entries, shared lobby/world handler table |
| <addr in DB> | ISAAC delta values | Used for client recv cipher initialization |
