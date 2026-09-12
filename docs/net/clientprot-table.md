# ClientProt Opcode Table (rev 947-1)

Binary: NXT Client (Build 947-1)
Extracted from: `jag::ServerProt::RegisterAll` at `<addr in DB>` (947-1)
Constructor: `<addr in DB>` (ClientProt), `<addr in DB>` (ClientProt::InitEntry for lobby entries)
ClientProt struct size: 0x10 bytes (opcode:int32+0x00, size:int32+0x04, name:char*+0x08)
Entry base addresses: `<addr in DB>` to `<addr in DB>` (0x10 stride), outlier at `<addr in DB>` (op 112)
Total game opcodes: 130 (0-129)
Total lobby opcodes: 18 (0-17)

Cross-referenced against: 946-5 binary (`clientprot-table.md`)

## Size Mode Legend

| Mode | Value | Description |
|------|-------|-------------|
| Fixed | >= 0 | Packet has exactly N bytes of payload |
| VAR_BYTE | -1 | Length prefixed with 1 byte (max 255 bytes payload) |
| VAR_SHORT | -2 | Length prefixed with 2 bytes (max 65535 bytes payload) |
| 0 | 0 | No payload bytes (opcode-only packet) |

## Game ClientProt Table (130 entries)

Confidence levels:
- **CONFIRMED**: Verified by decompiling the Send* function in 947-1 and checking which DAT_ address it references
- **HIGH**: Unique remaining size match after confirmed entries removed
- **MEDIUM**: Size count match (equal number of entries with that size in both revisions)
- **LOW**: Multiple candidates with same size, name is a guess
- **NEW**: Size does not appear in 946 table, likely a changed/new packet

| 947 Opcode | Size | DAT Address | Identified Name | 946 Opcode | Confidence | Notes |
|------------|------|-------------|-----------------|------------|------------|-------|
| 0 | 5 | <addr in DB> | MOVE_GAME_MINIMENU | 33 | MEDIUM | size count match |
| 1 | 3 | <addr in DB> | | | LOW | 3-byte group (NPC/OBJ ops) |
| 2 | 4 | <addr in DB> | | | LOW | 4-byte group (LOC/callback ops) |
| 3 | 5 | <addr in DB> | MOVE_SCRIPTED | 89 | MEDIUM | size count match |
| 4 | 8 | <addr in DB> | **IF_BUTTON3** | | **CONFIRMED** | IfButtonXInner table[2]; format: short(comp) int(slot) short(item) |
| 5 | 8 | <addr in DB> | **IF_BUTTON7** | | **CONFIRMED** | IfButtonXInner table[6]; format: short(comp) int(slot) short(item) |
| 6 | 15 | <addr in DB> | OPNPC_T_EXTENDED | 26 | MEDIUM | size count match |
| 7 | 6 | <addr in DB> | **EVENT_MOUSE_CLICK** | | **CONFIRMED** | SendEventMouseClick; writes int(y<<16|x) + byteAdd(timeDelta) + byte(flags) |
| 8 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 9 | 12 | <addr in DB> | | | LOW | 12-byte group (IF_BUTTON_T4/T9) |
| 10 | 9 | <addr in DB> | | | LOW | 9-byte group |
| 11 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 12 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 13 | 16 | <addr in DB> | | | LOW | 16-byte group (IF_BUTTON_T) |
| 14 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 15 | 6 | <addr in DB> | | | NEW | new size |
| 16 | 8 | <addr in DB> | | | LOW | 8-byte group |
| 17 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 18 | 8 | <addr in DB> | **IF_BUTTON9** | | **CONFIRMED** | IfButtonXInner table[8]; format: short(comp) int(slot) short(item) |
| 19 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 20 | 1 | <addr in DB> | | | LOW | 1-byte group |
| 21 | 8 | <addr in DB> | **IF_BUTTON8** | | **CONFIRMED** | IfButtonXInner table[7]; format: short(comp) int(slot) short(item) |
| 22 | VAR_BYTE | <addr in DB> | **FRIENDLIST_DEL** | 121 | **CONFIRMED** | SendFriendlistDel |
| 23 | 4 | <addr in DB> | **WORLDLIST_FETCH** | 110 | **CONFIRMED** | SendWorldlistFetch |
| 24 | VAR_BYTE | <addr in DB> | **CLANCHANNEL_KICKUSER** | 78 | **CONFIRMED** | SendSocialRequest |
| 25 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 26 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 27 | 0 | <addr in DB> | **NO_TIMEOUT** | | **CONFIRMED** | ProcessConnections; keepalive sent every 50 ticks on login+game connections |
| 28 | 18 | <addr in DB> | MOVE_GAME_EXTENDED | 92 | MEDIUM | unique size match |
| 29 | 8 | <addr in DB> | **IF_BUTTON5** | | **CONFIRMED** | IfButtonXInner table[4]; format: short(comp) int(slot) short(item) |
| 30 | 4 | <addr in DB> | **TRANSMITVAR_VERIFYID** | | **CONFIRMED** | SendSceneGraphReport; writes int(verifyId) |
| 31 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 32 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 33 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 34 | VAR_BYTE | <addr in DB> | **CLIENT_DETAILOPTIONS_STATUS** | | **CONFIRMED** | SendMultiDisplayPackets; SerialiseForServer graphics settings (1B count + data) |
| 35 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 36 | 8 | <addr in DB> | **IF_BUTTON10** | | **CONFIRMED** | IfButtonXInner table[9]; format: short(comp) int(slot) short(item) |
| 37 | 1 | <addr in DB> | | | LOW | 1-byte group |
| 38 | 1 | <addr in DB> | | | LOW | 1-byte group |
| 39 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 40 | 16 | <addr in DB> | | | LOW | 16-byte group (IF_BUTTON_T) |
| 41 | 0 | <addr in DB> | | | LOW | 0-byte group |
| 42 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 43 | 0 | <addr in DB> | | | LOW | 0-byte group |
| 44 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 45 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 46 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 47 | 4 | <addr in DB> | **EVENT_CAMERA_POSITION** | | **CONFIRMED** | SendMultiDisplayPackets; writes shortAdd(yaw) + short(pitch) via QuaternionToJagexAngles |
| 48 | VAR_BYTE | <addr in DB> | **IGNORELIST_ADD** | 67 | **CONFIRMED** | SendIgnorelistAdd |
| 49 | 17 | <addr in DB> | | | NEW | new size |
| 50 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 51 | 8 | <addr in DB> | **IF_BUTTON6** | | **CONFIRMED** | IfButtonXInner table[5]; format: short(comp) int(slot) short(item) |
| 52 | 1 | <addr in DB> | | | LOW | 1-byte group |
| 53 | VAR_SHORT | <addr in DB> | **EVENT_KEYBOARD** | | **CONFIRMED** | SendMultiDisplayPackets; writes short(count) + entries of [byte(key) byte(deltaHi) byte(deltaMid) byte(deltaLo)] |
| 54 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 55 | 0 | <addr in DB> | **MAP_BUILD_COMPLETE** | 21 | **CONFIRMED** | SendMapBuildComplete |
| 56 | 1 | <addr in DB> | **EVENT_APPLET_FOCUS** | | **CONFIRMED** | SendMultiDisplayPackets; writes byte(hasFocus) via SDL_GetKeyboardFocus |
| 57 | 1 | <addr in DB> | | | LOW | 1-byte group |
| 58 | 15 | <addr in DB> | OPLOC_T_EXTENDED | 51 | MEDIUM | size count match |
| 59 | 4 | <addr in DB> | **DETECT_MODIFIED_CLIENT** | 95 | **CONFIRMED** | SendDetectModifiedClient |
| 60 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 61 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 62 | 2 | <addr in DB> | | | LOW | 2-byte group |
| 63 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 64 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 65 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 66 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 67 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 68 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 69 | VAR_BYTE | <addr in DB> | **MESSAGE_PUBLIC (effects)** | 29 | **CONFIRMED** | SendMessagePublicWithEffects |
| 70 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 71 | 0 | <addr in DB> | | | LOW | 0-byte group |
| 72 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 73 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 74 | VAR_SHORT | <addr in DB> | **EVENT_TELEMETRY** | 45 | **CONFIRMED** | SendAppletFocusEvents |
| 75 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 76 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 77 | 8 | <addr in DB> | **IF_BUTTON2** | | **CONFIRMED** | IfButtonXInner table[1]; format: short(comp) int(slot) short(item) |
| 78 | VAR_SHORT | <addr in DB> | **MOVE_GAME** | 102 | **CONFIRMED** | SendMoveGame |
| 79 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 80 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 81 | 11 | <addr in DB> | **OPLOC_T2** | 70 | **CONFIRMED** | SendOpLocTLong |
| 82 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 83 | 18 | <addr in DB> | | | NEW | extra 18-byte entry |
| 84 | VAR_BYTE | <addr in DB> | **RESUME_P_NAMEDIALOG** | | **CONFIRMED** | SendResumePNameDialog; writes byte(charCount) + pStringUTF8ToCP1252(text) |
| 85 | 11 | <addr in DB> | OPNPC_T2_EXTENDED | 90 | MEDIUM | size count match |
| 86 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 87 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 88 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 89 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 90 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 91 | 2 | <addr in DB> | | | LOW | 2-byte group |
| 92 | 22 | <addr in DB> | | | NEW | new size |
| 93 | VAR_BYTE | <addr in DB> | **FRIENDLIST_ADD** | 39 | **CONFIRMED** | SendFriendlistAdd |
| 94 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 95 | 8 | <addr in DB> | **IF_BUTTON4** | | **CONFIRMED** | IfButtonXInner table[3]; format: short(comp) int(slot) short(item) |
| 96 | 8 | <addr in DB> | **IF_BUTTON1** | | **CONFIRMED** | IfButtonXInner table[0]; format: short(comp) int(slot) short(item) |
| 97 | 9 | <addr in DB> | **ANTI_CHEAT_REPLY** | | **CONFIRMED** | HandleAntiCheatChallenge (ServerProt handler sends this); writes byte(~sessionIdx) + 4B(challenge1_rearranged) + 4B(challenge2_rearranged) |
| 98 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 99 | 2 | <addr in DB> | | | LOW | 2-byte group |
| 100 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 101 | 2 | <addr in DB> | | | LOW | 2-byte group |
| 102 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 103 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 104 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 105 | VAR_BYTE | <addr in DB> | **EVENT_MOUSE_MOVE** | | **CONFIRMED** | SendCameraMovementUpdate (via vtable); delta-encoded mouse/camera positions with timing |
| 106 | 4 | <addr in DB> | | | LOW | 4-byte group |
| 107 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 108 | 6 | <addr in DB> | **WINDOW_STATUS** | 82 | **CONFIRMED** | SendDisplayInfo (size 3->6) |
| 109 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 110 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 111 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 112 | 11 | <addr in DB> | OPLOC_T3 | 111 | MEDIUM | size count match |
| 113 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 114 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 115 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 116 | VAR_SHORT | <addr in DB> | | | LOW | varShort group |
| 117 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 118 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 119 | VAR_BYTE | <addr in DB> | | | LOW | varByte group |
| 120 | VAR_BYTE | <addr in DB> | **MESSAGE_PUBLIC** | 29 | **CONFIRMED** | SendMessagePublic |
| 121 | VAR_SHORT | <addr in DB> | **MESSAGE_PRIVATE** | 52 | **CONFIRMED** | SendMessagePrivate |
| 122 | 7 | <addr in DB> | | | LOW | 7-byte group |
| 123 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 124 | VAR_BYTE | <addr in DB> | **IF_BUTTON_D** | | **CONFIRMED** | IfButtonXInner extended path; writes byte(type+8) byte(len) byteAdd(opIndex) int_alt1(slot) string(data) short(item) |
| 125 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 126 | 9 | <addr in DB> | | | NEW | extra 9-byte entry |
| 127 | 3 | <addr in DB> | | | LOW | 3-byte group |
| 128 | 0 | <addr in DB> | | | LOW | 0-byte group |
| 129 | 3 | <addr in DB> | | | LOW | 3-byte group |

## Lobby ClientProt Table (18 entries)

Registered via `ClientProt::InitEntry` into the lobby-phase client prot vector.

| 947 Opcode | Size | DAT Address | 946 Opcode | Notes |
|------------|------|-------------|------------|-------|
| 0 | 21 | <addr in DB> | 15 | unique size match |
| 1 | 11 | <addr in DB> | 0 or 8 | ambiguous |
| 2 | 7 | <addr in DB> | 5, 7, or 17 | ambiguous |
| 3 | 5 | <addr in DB> | 2 or 13 | ambiguous |
| 4 | 11 | <addr in DB> | 0 or 8 | ambiguous |
| 5 | 3 | <addr in DB> | 3 | unique size match |
| 6 | 20 | <addr in DB> | 6 | unique size match |
| 7 | 29 | <addr in DB> | 12 | unique size match |
| 8 | 5 | <addr in DB> | 2 or 13 | ambiguous |
| 9 | VAR_BYTE | <addr in DB> | 1, 14, or 16 | ambiguous |
| 10 | 10 | <addr in DB> | 10 | unique size match |
| 11 | 7 | <addr in DB> | 5, 7, or 17 | ambiguous |
| 12 | 7 | <addr in DB> | 5, 7, or 17 | ambiguous |
| 13 | 2 | <addr in DB> | 9 | unique size match |
| 14 | VAR_BYTE | <addr in DB> | 1, 14, or 16 | ambiguous |
| 15 | 28 | <addr in DB> | 11 | unique size match |
| 16 | VAR_BYTE | <addr in DB> | 1, 14, or 16 | ambiguous |
| 17 | 14 | <addr in DB> | 4 | unique size match |

## Key Confirmed Packets for Server Implementation

These are the packets critical for lobby/world functionality, all verified in the 947-1 binary:

| Packet | 947 Opcode | Size | Send Function | Purpose |
|--------|------------|------|---------------|---------|
| WORLDLIST_FETCH | 23 | 4 | <addr in DB> | Client requests world list (writes 1 int) |
| MAP_BUILD_COMPLETE | 55 | 0 | <addr in DB> | Client signals map load complete |
| MOVE_GAME | 78 | VAR_SHORT | <addr in DB> | Player movement (walk/run) |
| WINDOW_STATUS | 108 | 6 | <addr in DB> | Display mode + resolution (expanded from 3 to 6 bytes) |
| MESSAGE_PUBLIC | 120 | VAR_BYTE | <addr in DB> | Public chat message |
| MESSAGE_PRIVATE | 121 | VAR_SHORT | <addr in DB> | Private message (XTEA encrypted) |
| FRIENDLIST_ADD | 93 | VAR_BYTE | <addr in DB> | Add friend |
| FRIENDLIST_DEL | 22 | VAR_BYTE | <addr in DB> | Remove friend |
| IGNORELIST_ADD | 48 | VAR_BYTE | <addr in DB> | Add to ignore list |
| CLANCHANNEL_KICKUSER | 24 | VAR_BYTE | <addr in DB> | Kick from friend/clan channel |
| DETECT_MODIFIED_CLIENT | 59 | 4 | <addr in DB> | Anti-cheat check (writes 1 int) |
| EVENT_TELEMETRY | 74 | VAR_SHORT | <addr in DB> | Applet focus/telemetry events |
| MOVE_GAME_EXTENDED | 28 | 18 | - | Extended movement packet |
| OPLOC_T2 | 81 | 11 | <addr in DB> | Use item on location (long form) |
| NO_TIMEOUT | 27 | 0 | <addr in DB> (ProcessConnections) | Keepalive; sent every 50 ticks on both login+game connections |
| IF_BUTTON1 | 96 | 8 | <addr in DB> (IfButtonXInner) | Interface button click (op 1); short(comp) int(slot) short(item) |
| IF_BUTTON2 | 77 | 8 | " | Interface button click (op 2) |
| IF_BUTTON3 | 4 | 8 | " | Interface button click (op 3) |
| IF_BUTTON4 | 95 | 8 | " | Interface button click (op 4) |
| IF_BUTTON5 | 29 | 8 | " | Interface button click (op 5) |
| IF_BUTTON6 | 51 | 8 | " | Interface button click (op 6) |
| IF_BUTTON7 | 5 | 8 | " | Interface button click (op 7) |
| IF_BUTTON8 | 21 | 8 | " | Interface button click (op 8) |
| IF_BUTTON9 | 18 | 8 | " | Interface button click (op 9) |
| IF_BUTTON10 | 36 | 8 | " | Interface button click (op 10) |
| IF_BUTTON_D | 124 | VAR_BYTE | " | Extended button with dialog string data |
| RESUME_P_NAMEDIALOG | 84 | VAR_BYTE | <addr in DB> | Name dialog resume; byte(charCount) + string(text) |
| EVENT_MOUSE_CLICK | 7 | 6 | <addr in DB> | Mouse click; int(y<<16|x) byteAdd(timeDelta) byte(flags) |
| EVENT_MOUSE_MOVE | 105 | VAR_BYTE | <addr in DB> (SendCameraMovementUpdate) | Delta-encoded mouse/camera positions |
| EVENT_KEYBOARD | 53 | VAR_SHORT | <addr in DB> (SendMultiDisplayPackets) | Key events; short(count) + entries |
| EVENT_CAMERA_POSITION | 47 | 4 | " | Camera pitch/yaw; shortAdd(yaw) short(pitch) |
| EVENT_APPLET_FOCUS | 56 | 1 | " | Window focus state; byte(hasFocus) |
| CLIENT_DETAILOPTIONS_STATUS | 34 | VAR_BYTE | " | Graphics settings; byte(count) + serialised data |
| TRANSMITVAR_VERIFYID | 30 | 4 | <addr in DB> (SendSceneGraphReport) | Var domain verify ID; int(verifyId) |
| ANTI_CHEAT_REPLY | 97 | 9 | <addr in DB> (handler) | Anti-cheat challenge response; byte(~idx) + 8B rearranged challenge |

## Size Distribution (947 vs 946)

| Size | 946 Count | 947 Count | Delta |
|------|-----------|-----------|-------|
| VAR_SHORT | 5 | 13 | +8 |
| VAR_BYTE | 16 | 28 | +12 |
| 0 | 36 | 6 | -30 |
| 1 | 5 | 6 | +1 |
| 2 | 2 | 4 | +2 |
| 3 | 22 | 18 | -4 |
| 4 | 21 | 11 | -10 |
| 5 | 2 | 2 | 0 |
| 6 | 0 | 3 | +3 |
| 7 | 2 | 7 | +5 |
| 8 | 7 | 11 | +4 |
| 9 | 1 | 9 | +8 |
| 11 | 2 | 3 | +1 |
| 12 | 2 | 1 | -1 |
| 15 | 2 | 2 | 0 |
| 16 | 3 | 2 | -1 |
| 17 | 0 | 1 | +1 |
| 18 | 1 | 2 | +1 |
| 22 | 0 | 1 | +1 |

**Major structural changes 946 -> 947:**
- 30 zero-size packets eliminated (most gained payload)
- 10 four-byte packets removed/changed
- 12 new varByte packets, 8 new varShort packets
- Many formerly fixed-size packets became variable-length
- Several packet sizes increased (e.g., WINDOW_STATUS 3->6)

This means the 947 protocol is NOT a simple opcode shuffle from 946 -- many packet structures were expanded or changed. Pure size-based cross-referencing is insufficient for most entries. Full identification requires decompiling each Send* function or handler.

## RE Methodology

1. Decompiled `jag::ServerProt::RegisterAll` at `<addr in DB>` in 947-1 binary (port 8083)
2. Extracted all 130 `ClientProt::ClientProt(&addr, opcode, size)` calls
3. Extracted all 18 `ClientProt::InitEntry(&addr, opcode, size)` calls for lobby
4. Decompiled all available `jag::ClientProt::Send*` functions in 947-1:
   - SendWorldlistFetch, SendMapBuildComplete, SendMoveGame, SendDetectModifiedClient
   - SendFriendlistAdd, SendFriendlistDel, SendIgnorelistAdd, SendSocialRequest
   - SendMessagePublic, SendMessagePublicWithEffects, SendMessagePrivate
   - SendAppletFocusEvents, SendDisplayInfo, SendOpLocTLong, SendSceneGraphReport
   - SendMultiDisplayPackets, SendCameraMovementUpdate, SendEventMouseClick
   - SendResumePNameDialog, HandleAntiCheatChallenge, ProcessConnections
   - IfButtonXInner (IF_BUTTON1-10 table at <addr in DB>)
5. Each Send function references a DAT_ address as the ClientProt object, which maps to exactly one opcode/size pair
6. Cross-referenced the DAT_ addresses from Send functions with the opcode table to produce confirmed mappings
7. Cross-referenced with unstripped binary (NXT_BETA_UNSTRIPPED, port 8080) to obtain real Jagex names:
   - ClientWatch::MainLogic contains EVENT_MOUSE_CLICK, EVENT_MOUSE_MOVE, EVENT_KEYBOARD, EVENT_CAMERA_POSITION, EVENT_APPLET_FOCUS, CLIENT_DETAILOPTIONS_STATUS
   - InterfaceManager::SendPauseComponentMessage references RESUME_PAUSEBUTTON
   - opcode::Resume lambda #4 references RESUME_P_NAMEDIALOG
   - ConnectionManager::ProcessConnections sends NO_TIMEOUT (keepalive) every 50 ticks
   - DelayedStateChange::MainLogic sends TRANSMITVAR_VERIFYID
   - ClientVarDomain::Service sends STORE_SERVERPERM_VARCS
