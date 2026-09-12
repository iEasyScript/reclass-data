> ⚠️ **SUPERSEDED (2026-06-28).** ServerProt opcode↔name↔size for 948-5 is now authoritative in

# ServerProt Table: Revision 947-1

Extracted from `rs2client.947-1` binary via Ghidra reverse engineering.

**Binary**: `rs2client` rev 947-1 (stripped, x86_64)
**Ghidra port**: 8083
**RegisterAll function**: `<addr in DB>` (body: `<addr in DB>` - `<addr in DB>`)
**BindHandlers function**: `<addr in DB>` (body: `<addr in DB>` - `<addr in DB>`)
**g_serverProtVector**: `<addr in DB>`
**Max valid opcode**: 217 (0xD9) -- checked in TcpIn dispatch at `<addr in DB>`
**Total entries**: 218 (opcodes 0-217), up from 217 in rev 946

## Changes from Rev 946

1. **One new packet added**: Opcode 149, size 17 (fixed). Not present in rev 946. No handler name identified yet.
2. **All opcodes reshuffled**: Every packet has a new opcode assignment.
3. **Sizes preserved**: The size for each named packet is identical between revisions. The size distribution is unchanged except for the new size-17 entry.
4. **Handler functions preserved**: The handler function implementations are the same (addresses shifted due to relinking).

## Mapping Methodology

Entries were matched between 947-1 and 946-5 using two techniques:
1. **Handler name matching** (CERTAIN/PROBABLE): The `BindHandlers` function in both binaries assigns named handler functions (e.g., `packethandlers::NPCInfo::NPC_INFO`) to ProtEntry objects. When the same handler name appears in both binaries, the match is certain. 77 entries matched this way.
2. **Unique size matching** (CERTAIN): After handler matching, remaining entries were matched by finding sizes that appeared exactly once among unmatched entries in both tables. Iterative narrowing was applied. 8 additional entries matched this way.

141 entries remain unmatched -- they share common sizes (varByte, varShort, 0-10) with multiple candidates and their handlers are unnamed `FUN_XXXX` functions in the stripped binary.

## Complete ServerProt Table (Rev 947-1)

Size notation: positive = fixed bytes, varByte = variable (1-byte length prefix), varShort = variable (2-byte length prefix)

| 947 Op | Size | Packet Name | 946 Op | Confidence | Match Method |
|--------|------|-------------|--------|------------|--------------|
| 0 | varByte | SET_PLAYER_OP | ??? | CERTAIN | handler: ClientState::SET_PLAYER_OP (decompiled) |
| 1 | 3 | ??? | ??? | UNMATCHED | |
| 2 | varShort | IF_SETTEXT | ??? | CERTAIN | handler: Interfaces::IF_SETTEXT (decompiled) |
| 3 | 1 | CAM_FORCEANGLE | 52 | CERTAIN | handler: Camera::CAM_FORCEANGLE |
| 4 | 4 | ??? | ??? | UNMATCHED | |
| 5 | varShort | UPDATE_INV_PARTIAL | 81 | CERTAIN | handler: Inventory::UPDATE_INV_PARTIAL |
| 6 | varByte | HASHED_WORLD_TOKEN | ??? | PROBABLE | handler: empty invoke (token consumed, not processed). 44B Base64url string at world login |
| 7 | varByte | MESSAGE_FRIENDCHANNEL | 56 | PROBABLE | handler: Chat::MESSAGE_FRIENDCHANNEL (multi) |
| 8 | 23 | IF_SETPOSITION | 38 | CERTAIN | unique size 23 |
| 9 | varShort | ??? | ??? | UNMATCHED | |
| 10 | 3 | ??? | ??? | UNMATCHED | |
| 11 | varShort | UNKNOWN_95 | 95 | CERTAIN | handler: Chat::CLANSETTINGS_DELTA_CHAT |
| 12 | varShort | NPC_INFO | 28 | CERTAIN | handler: NPCInfo::NPC_INFO |
| 13 | 6 | ??? | ??? | UNMATCHED | |
| 14 | 5 | ??? | ??? | UNMATCHED | |
| 15 | varShort | ??? | ??? | UNMATCHED | |
| 16 | 4 | ??? | ??? | UNMATCHED | |
| 17 | 8 | ??? | ??? | UNMATCHED | |
| 18 | 3 | UPDATE_ZONE_FULL_FOLLOWS | ??? | CERTAIN | handler: ZoneUpdates::UPDATE_ZONE_FULL_FOLLOWS (decompiled) |
| 19 | 1 | UPDATE_RUNENERGY | 27 | CERTAIN | handler: Misc::SET_RUN_ENERGY |
| 20 | 7 | ??? | ??? | UNMATCHED | |
| 21 | varByte | ??? | ??? | UNMATCHED | |
| 22 | 6 | ??? | ??? | UNMATCHED | |
| 23 | 4 | ??? | ??? | UNMATCHED | |
| 24 | varByte | UNKNOWN_9 | 9 | CERTAIN | handler: NPCInfo::SET_NPC_OP |
| 25 | 0 | ??? | ??? | UNMATCHED | |
| 26 | 6 | ??? | ??? | UNMATCHED | |
| 27 | varShort | PLAYER_INFO | 42 | CERTAIN | handler: PlayerList::ProcessPlayerInfo |
| 28 | varShort | CLANCHANNEL_FULL | 83 | CERTAIN | handler: Clans::CLANCHANNEL_FULL |
| 29 | 3 | ??? | ??? | UNMATCHED | |
| 30 | varShort | UPDATE_IGNORELIST | 17 | CERTAIN | handler: Lobby::CHANGE_LOBBY |
| 31 | varShort | ??? | ??? | UNMATCHED | |
| 32 | 10 | ??? | ??? | UNMATCHED | |
| 33 | 4 | IF_CLOSESUB | ??? | CERTAIN | handler: Interfaces::IF_CLOSESUB_ACTIVE (BindHandlers lambda #9). Cross-ref: unstripped IF_CLOSESUB |
| 34 | 10 | ??? | ??? | UNMATCHED | |
| 35 | 12 | ??? | ??? | UNMATCHED | |
| 36 | 28 | UPDATE_UID192 | 0 | CERTAIN | handler: PlayerInfo::REBUILD_PLAYERINFO_POSITIONS |
| 37 | 2 | ??? | ??? | UNMATCHED | |
| 38 | 5 | ??? | ??? | UNMATCHED | |
| 39 | varByte | CHAT_FILTER_SETTINGS | 107 | CERTAIN | handler: Chat::CHAT_FILTER_SETTINGS |
| 40 | 19 | ??? | ??? | UNMATCHED | |
| 41 | varByte | ??? | ??? | UNMATCHED | |
| 42 | 3 | ??? | ??? | UNMATCHED | |
| 43 | 0 | UNKNOWN_25 | 25 | CERTAIN | handler: Misc::RESET_ENTITY_LISTS |
| 44 | 6 | ??? | ??? | UNMATCHED | |
| 45 | varShort | MESSAGE_PUBLIC | 15 | CERTAIN | handler: Chat::MESSAGE_PUBLIC |
| 46 | varShort | CAMERA_UPDATE | 110 | CERTAIN | handler: Camera::CAM_UPDATE |
| 47 | 20 | MAP_PROJANIM | 24 | CERTAIN | unique size 20 |
| 48 | 0 | ??? | ??? | UNMATCHED | |
| 49 | 0 | ??? | ??? | UNMATCHED | |
| 50 | 3 | VARP_BIT | ??? | CERTAIN | handler: Variables::VARP_BIT (decompiled) |
| 51 | 7 | ??? | ??? | UNMATCHED | |
| 52 | 2 | UNKNOWN_22 | 22 | CERTAIN | handler: ClientState::SET_TICK_TIMER |
| 53 | 8 | ??? | ??? | UNMATCHED | |
| 54 | varByte | NPC_HEADICON_SPECIFIC | 86 | CERTAIN | handler: NPCInfo::NPC_HEADICON_SPECIFIC |
| 55 | 6 | ??? | ??? | UNMATCHED | |
| 56 | 10 | ??? | ??? | UNMATCHED | |
| 57 | 3 | ??? | ??? | UNMATCHED | |
| 58 | varByte | UNKNOWN_10 | 10 | CERTAIN | handler: Chat::MESSAGE_QUICKCHAT_CLANCHAT |
| 59 | 4 | JCOINS_UPDATE | 85 | CERTAIN | handler: Misc::SET_DISPLAY_INT |
| 60 | 7 | ??? | ??? | UNMATCHED | |
| 61 | 1 | UNKNOWN_102 | 102 | CERTAIN | handler: NPCInfo::SET_NPC_UPDATE_ORIGIN |
| 62 | 11 | ??? | ??? | UNMATCHED | |
| 63 | varShort | CLANSETTINGS_DELTA | 63 | CERTAIN | handler: Clans::CLANSETTINGS_DELTA |
| 64 | 8 | ??? | ??? | UNMATCHED | |
| 65 | 0 | SET_READY_FLAG | 35 | CERTAIN | handler: ClientState::SET_READY_FLAG |
| 66 | 6 | ??? | ??? | UNMATCHED | |
| 67 | varByte | ??? | ??? | UNMATCHED | |
| 68 | 6 | ??? | ??? | UNMATCHED | |
| 69 | varShort | UPDATE_INV_FULL | 121 | CERTAIN | handler: Inventory::UPDATE_INV_FULL_impl |
| 70 | 0 | ??? | ??? | UNMATCHED | |
| 71 | 6 | ??? | ??? | UNMATCHED | |
| 72 | 5 | ??? | ??? | UNMATCHED | |
| 73 | varByte | MESSAGE_QUICKCHAT_PRIVATE | 37 | CERTAIN | handler: Chat::MESSAGE_QUICKCHAT_PRIVATE |
| 74 | 8 | ??? | ??? | UNMATCHED | |
| 75 | 10 | ??? | ??? | UNMATCHED | |
| 76 | 10 | ??? | ??? | UNMATCHED | |
| 77 | 1 | UNKNOWN_80 | 80 | CERTAIN | handler: Misc::SET_MULTIWAY_STATE |
| 78 | 14 | UNKNOWN_47 | 47 | CERTAIN | handler: PlayerInfo::PLAYER_INFO_DECODE |
| 79 | varByte | ??? | ??? | UNMATCHED | |
| 80 | 0 | CAM_SMOOTHRESET | 118 | CERTAIN | handler: Camera::CAM_SMOOTHRESET |
| 81 | 4 | ??? | ??? | UNMATCHED | |
| 82 | varByte | MESSAGE_QUICKCHAT_CLANCHANNEL | 31 | CERTAIN | handler: Chat::MESSAGE_QUICKCHAT_CLANCHANNEL |
| 83 | varByte | CLANCHANNEL_DELTA | 123 | CERTAIN | handler: Chat::CLANCHANNEL_DELTA (note: varByte not varShort) |
| 84 | varShort | UNKNOWN_11 | 11 | CERTAIN | handler: Chat::CLANCHANNEL_FULL_CHAT |
| 85 | 8 | ??? | ??? | UNMATCHED | |
| 86 | varShort | ??? | ??? | UNMATCHED | empty BindHandlers invoke; likely handled in TcpIn dispatch (<in Ghidra DB>). 5518B during char creation |
| 87 | 5 | MIDI_SONG | ??? | CERTAIN | handler: Audio::MIDI_SONG (BindHandlers lambda #12). Cross-ref: unstripped MIDI_SONG |
| 88 | 10 | ??? | ??? | UNMATCHED | |
| 89 | 0 | CAM_RESET | 69 | CERTAIN | handler: Camera::CAM_RESET |
| 90 | varShort | REBUILD_REGION | ??? | CERTAIN | handler: ClientState::REBUILD_REGION (decompiled) |
| 91 | 35 | CUTSCENE | 53 | CERTAIN | unique size 35 |
| 92 | 8 | ??? | ??? | UNMATCHED | |
| 93 | 10 | ??? | ??? | UNMATCHED | |
| 94 | 19 | ??? | ??? | UNMATCHED | |
| 95 | 10 | ??? | ??? | UNMATCHED | |
| 96 | 8 | ??? | ??? | UNMATCHED | |
| 97 | 25 | ??? | ??? | UNMATCHED | |
| 98 | 10 | ??? | ??? | UNMATCHED | |
| 99 | varByte | ??? | ??? | UNMATCHED | |
| 100 | 10 | ??? | ??? | UNMATCHED | |
| 101 | varShort | RUNCLIENTSCRIPT | 16 | CERTAIN | handler: Chat::RUN_CLIENTSCRIPT |
| 102 | varShort | ??? | ??? | UNMATCHED | |
| 103 | 5 | IF_SETHIDE | ??? | CERTAIN | handler: Interfaces::IF_SETHIDE (BindHandlers lambda #14). Cross-ref: unstripped IF_SETHIDE. 1B hide flag + 4B component hash |
| 104 | varShort | CLANSETTINGS_FULL | 39 | CERTAIN | handler: Clans::CLANSETTINGS_FULL |
| 105 | varByte | MESSAGE_GAME | 1 | CERTAIN | handler: Chat::MESSAGE_GAME |
| 106 | 10 | ??? | ??? | UNMATCHED | |
| 107 | 25 | ??? | ??? | UNMATCHED | |
| 108 | 2 | UNKNOWN_97 | 97 | CERTAIN | handler: Misc::SET_PLAYER_OP_2 |
| 109 | varShort | PLAYER_GROUP_FULL | 66 | CERTAIN | handler: PlayerGroup::PLAYER_OP |
| 110 | 29 | ??? | ??? | UNMATCHED | |
| 111 | 6 | ??? | ??? | UNMATCHED | |
| 112 | 6 | ??? | ??? | UNMATCHED | |
| 113 | 1 | UNKNOWN_23 | 23 | CERTAIN | handler: Camera::CAM_TARGET |
| 114 | 2 | ??? | ??? | UNMATCHED | |
| 115 | 3 | ??? | ??? | UNMATCHED | |
| 116 | 1 | UNKNOWN_13 | 13 | CERTAIN | handler: Misc::SET_PLAYER_OP_3 |
| 117 | 32 | IF_SETANGLE | 21 | CERTAIN | unique size 32 |
| 118 | 25 | ??? | ??? | UNMATCHED | |
| 119 | varByte | MESSAGE_QUICKCHAT_FRIENDCHAT | 68 | CERTAIN | handler: Chat::MESSAGE_QUICKCHAT_FRIENDCHAT |
| 120 | 0 | ??? | ??? | UNMATCHED | |
| 121 | varShort | ??? | ??? | UNMATCHED | |
| 122 | 8 | ??? | ??? | UNMATCHED | |
| 123 | 8 | ??? | ??? | UNMATCHED | |
| 124 | 12 | ??? | ??? | UNMATCHED | |
| 125 | varByte | MESSAGE_CLANCHANNEL_SYSTEM | 46 | CERTAIN | handler: Chat::MESSAGE_CLANCHANNEL |
| 126 | varShort | ??? | ??? | UNMATCHED | |
| 127 | 11 | ??? | ??? | UNMATCHED | |
| 128 | 6 | ??? | ??? | UNMATCHED | |
| 129 | varByte | MESSAGE_PRIVATE_ECHO | 201 | CERTAIN | handler: Chat::MESSAGE_PRIVATE_ECHO |
| 130 | 0 | ??? | ??? | UNMATCHED | |
| 131 | 3 | ??? | ??? | UNMATCHED | |
| 132 | 4 | UPDATE_REBOOT_TIMER | 144 | CERTAIN | handler: Misc::SET_SYSUPDATE_TIMER |
| 133 | 2 | ??? | ??? | UNMATCHED | |
| 134 | varShort | ??? | ??? | UNMATCHED | |
| 135 | 3 | ??? | ??? | UNMATCHED | |
| 136 | 9 | ??? | ??? | UNMATCHED | |
| 137 | 8 | ??? | ??? | UNMATCHED | |
| 138 | 1 | UNKNOWN_181 | 181 | CERTAIN | handler: NPCInfo::SET_NPC_UPDATE_FLAG |
| 139 | varShort | ??? | ??? | UNMATCHED | |
| 140 | 5 | ??? | ??? | UNMATCHED | |
| 141 | 5 | ??? | ??? | UNMATCHED | |
| 142 | 0 | CLEAR_PENDING_UPDATES | ??? | CERTAIN | handler: Variables::CLEAR_PENDING_UPDATES (decompiled) |
| 143 | 1 | CREATE_CHECK_NAME_REPLY | 143 | CERTAIN | handler: AccountCreation::CREATE_CHECK_NAME_REPLY, bitmask 0xFE3 |
| 144 | 3 | UNKNOWN_175 | 175 | CERTAIN | handler: Misc::SET_INTERACTION_FLAG_D |
| 145 | 14 | ??? | ??? | UNMATCHED | |
| 146 | varByte | UNKNOWN_162 | 162 | CERTAIN | handler: Interfaces::IF_SETGRAPHIC_ACTIVE_handler |
| 147 | 0 | LOGOUT | 134 | CERTAIN | handler: Misc::LOGOUT |
| 148 | 9 | ??? | ??? | UNMATCHED | |
| 149 | 17 | **NEW_PACKET** | N/A | CERTAIN | new in 947-1, no 946 equivalent |
| 150 | 5 | ??? | ??? | UNMATCHED | |
| 151 | varByte | MESSAGE_PRIVATE | 130 | CERTAIN | handler: Chat::MESSAGE_PRIVATE |
| 152 | 4 | ??? | ??? | UNMATCHED | |
| 153 | 4 | ??? | ??? | UNMATCHED | |
| 154 | 1 | ??? | ??? | UNMATCHED | |
| 155 | 1 | UNKNOWN_188 | 188 | CERTAIN | handler: Chat::SET_CHAT_FILTER_B |
| 156 | 1 | CREATE_CHECK_EMAIL_REPLY | 156 | CERTAIN | handler: AccountCreation::CREATE_CHECK_EMAIL_REPLY, bitmask `<in Ghidra DB>` |
| 157 | 2 | ??? | ??? | UNMATCHED | |
| 158 | 12 | ??? | ??? | UNMATCHED | |
| 159 | varShort | WORLDLIST_FETCH_REPLY | 150 | CERTAIN | handler: Social::UPDATE_FRIENDCHAT_CHANNEL |
| 160 | 3 | ??? | ??? | UNMATCHED | |
| 161 | 10 | ??? | ??? | UNMATCHED | |
| 162 | 2 | ??? | ??? | UNMATCHED | |
| 163 | 2 | ??? | ??? | UNMATCHED | |
| 164 | 1 | ??? | ??? | UNMATCHED | |
| 165 | 4 | ??? | ??? | UNMATCHED | |
| 166 | varShort | UNKNOWN_192 | 192 | CERTAIN | handler: Misc::SKIP_DATA |
| 167 | varByte | ??? | ??? | UNMATCHED | |
| 168 | 2 | ??? | ??? | UNMATCHED | |
| 169 | 2 | ??? | ??? | UNMATCHED | |
| 170 | 10 | ??? | ??? | UNMATCHED | |
| 171 | 8 | SERVER_TICK_END | 203 | CERTAIN | handler: Misc::SERVER_TICK_END |
| 172 | varShort | REBUILD_NORMAL | ??? | CERTAIN | handler: ClientState::REBUILD_NORMAL (<addr in DB>) via BindHandlers. Cross-ref: unstripped REBUILD_NORMAL |
| 173 | varShort | UNKNOWN_141 | 141 | CERTAIN | handler: ZoneUpdates::UPDATE_ZONE_FULL_FOLLOWS_handler |
| 174 | 1 | CLEAR_PLAYER_SNAPSHOT | 205 | PROBABLE | handler: Misc::SET_INTERACTION_FLAG_C (shared w/ 946 op169) |
| 175 | 6 | ??? | ??? | UNMATCHED | |
| 176 | varShort | ??? | ??? | UNMATCHED | |
| 177 | varShort | UNKNOWN_168 | 168 | CERTAIN | handler: Inventory::UPDATE_INV_GROUP |
| 178 | varShort | UNKNOWN_163 | 163 | CERTAIN | handler: PlayerInfo::UPDATE_PLAYER_CHAT |
| 179 | varByte | UNKNOWN_199 | 199 | CERTAIN | handler: Chat::FRIENDCHAT_JOIN |
| 180 | varShort | UNKNOWN_189 | 189 | CERTAIN | handler: PlayerInfo::PLAYER_INFO_DECODE_2 |
| 181 | 6 | ??? | ??? | UNMATCHED | |
| 182 | 5 | ??? | ??? | UNMATCHED | |
| 183 | 4 | ??? | ??? | UNMATCHED | |
| 184 | 4 | ??? | ??? | UNMATCHED | |
| 185 | 1 | ??? | ??? | UNMATCHED | |
| 186 | varShort | UNKNOWN_173 | 173 | CERTAIN | handler: Interfaces::IF_OPENSUB_thunk |
| 187 | varByte | UNKNOWN_149 | 149 | CERTAIN | handler: WorldData::SET_WORLD_TARGET |
| 188 | varShort | ??? | ??? | UNMATCHED | |
| 189 | 3 | UNKNOWN_197 | 197 | CERTAIN | handler: Interfaces::IF_MOVESUB_thunk |
| 190 | 15 | UNKNOWN_193 | 193 | CERTAIN | unique size 15 |
| 191 | 2 | ??? | ??? | UNMATCHED | |
| 192 | 29 | ??? | ??? | UNMATCHED | |
| 193 | 5 | ??? | ??? | UNMATCHED | |
| 194 | 3 | ??? | ??? | UNMATCHED | |
| 195 | 0 | TRIGGER_ONDIALOGABORT | 212 | CERTAIN | handler: ClientState::TRIGGER_ONDIALOGABORT |
| 196 | 21 | PROJANIM_SPECIFIC | 214 | CERTAIN | unique size 21 |
| 197 | 5 | ??? | ??? | UNMATCHED | |
| 198 | 8 | ANTI_CHEAT_CHALLENGE | ??? | CERTAIN | handler: HandleAntiCheatChallenge (<addr in DB>). Server sends 8B, client responds with 9B (swapped + prefix). Sent every ~6s |
| 199 | 28 | UNKNOWN_159 | 159 | CERTAIN | unique size 28 (after handler matches removed other 28s) |
| 200 | varByte | UNKNOWN_171 | 171 | CERTAIN | handler: Misc::SET_URL_STRING |
| 201 | 3 | ??? | ??? | UNMATCHED | |
| 202 | 3 | ??? | ??? | UNMATCHED | |
| 203 | 4 | ??? | ??? | UNMATCHED | |
| 204 | 3 | ??? | ??? | UNMATCHED | |
| 205 | varShort | UNKNOWN_174 | 174 | CERTAIN | handler: NPCInfo::NPC_INFO_thunk |
| 206 | 33 | UNKNOWN_185 | 185 | CERTAIN | unique size 33 |
| 207 | varShort | PLAYER_GROUP_DELTA | 154 | CERTAIN | handler: PlayerGroup::UPDATE_PLAYER_GROUP |
| 208 | 14 | ??? | ??? | UNMATCHED | |
| 209 | 0 | LOGOUT_TRANSFER | 131 | CERTAIN | handler: Misc::LOGOUT_TRANSFER |
| 210 | 9 | ??? | ??? | UNMATCHED | |
| 211 | varByte | UNKNOWN_152 | 152 | CERTAIN | handler: Social::UPDATE_IGNORELIST_thunk |
| 212 | varShort | ??? | ??? | UNMATCHED | |
| 213 | 1 | ??? | ??? | UNMATCHED | |
| 214 | varByte | UNKNOWN_155 | 155 | CERTAIN | handler: Misc::UPDATE_URL_STRING |
| 215 | 6 | ??? | ??? | UNMATCHED | |
| 216 | 0 | ??? | ??? | UNMATCHED | |
| 217 | 1 | UNKNOWN_164 | 164 | CERTAIN | handler: Chat::SET_CHAT_FILTER_A |

## Summary Statistics

- **Total entries**: 218 (opcodes 0-217)
- **CERTAIN matches**: 76
- **PROBABLE matches**: 2 (MESSAGE_FRIENDCHANNEL, CLEAR_PLAYER_SNAPSHOT)
- **New in 947**: 1 (opcode 149, size 17)
- **UNMATCHED**: 139 (share common sizes, handlers are unnamed FUN_ in stripped binary)

## Key Matched Packets for Server Implementation

Critical packets for lobby/world operation that are confirmed:

| Purpose | 947 Op | Size | Name |
|---------|--------|------|------|
| Player sync | 27 | varShort | PLAYER_INFO |
| NPC sync | 12 | varShort | NPC_INFO |
| Login UID | 36 | 28 | UPDATE_UID192 |
| World list | 159 | varShort | WORLDLIST_FETCH_REPLY |
| Logout | 147 | 0 | LOGOUT |
| Logout transfer | 209 | 0 | LOGOUT_TRANSFER |
| Reboot timer | 132 | 4 | UPDATE_REBOOT_TIMER |
| Keep-alive | ??? | 0 | NO_TIMEOUT (unmatched) |
| Client script | 101 | varShort | RUNCLIENTSCRIPT |
| Server tick | 171 | 8 | SERVER_TICK_END |
| Map build | ??? | varShort | REBUILD_NORMAL (unmatched) |
| Inventory full | 69 | varShort | UPDATE_INV_FULL |
| Inventory partial | 5 | varShort | UPDATE_INV_PARTIAL |
| Run energy | 19 | 1 | UPDATE_RUNENERGY |
| Camera update | 46 | varShort | CAMERA_UPDATE |
| Cutscene | 91 | 35 | CUTSCENE |
| Interface position | 8 | 23 | IF_SETPOSITION |
| Interface angle | 117 | 32 | IF_SETANGLE |
| Clan settings | 104 | varShort | CLANSETTINGS_FULL |
| Clan delta | 63 | varShort | CLANSETTINGS_DELTA |
| Clan channel | 28 | varShort | CLANCHANNEL_FULL |
| Private message | 151 | varByte | MESSAGE_PRIVATE |
| Game message | 105 | varByte | MESSAGE_GAME |
| Public message | 45 | varShort | MESSAGE_PUBLIC |

## Technical Notes

### ProtEntry Structure Layout (947-1)
```
Offset  Size  Field
+0x00   4     opcode (int32)
+0x04   4     size (int32, -1=varByte, -2=varShort)
+0x08   8     name string pointer (constant, set by InitEntry)
+0x10   8     captured client pointer (set by BindHandlers)
+0x18   8     captured state data
+0x20   8     destructor function pointer
+0x28   8     handler function pointer (called by TcpIn dispatch)
```

### Dispatch Path
1. TcpIn reads ISAAC-decrypted opcode (1 or 2 bytes via Smart1or2)
2. Validates opcode <= 0xD9 (217)
3. Looks up ProtEntry from `g_serverProtVector[opcode]`
4. Reads size from ProtEntry+0x04 (or varByte/varShort from stream)
5. Reads payload bytes from stream
6. Calls handler at `*(ProtEntry+0x28)(ProtEntry+0x10, packet_buffer, &size)`

### How to Match Remaining Entries
To match the 139 unmatched entries, decompile the handler functions in both binaries:
1. In 946: find the handler address via BindHandlers for named entries
2. In 947: read the handler address from ProtEntry+0x28 at runtime, or find it in BindHandlers for FUN_ entries
3. Compare handler pseudocode structure to identify matches

Alternatively, use the unstripped `librs2client.so` (port 8080, rev ~890) to identify handler patterns by name, then locate equivalent patterns in both 946 and 947.
