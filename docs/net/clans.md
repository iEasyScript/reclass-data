# Clan System Protocol

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


## Overview

The NXT client implements full clan channel and clan settings management through a set of server-to-client packet handlers. The system supports two independent clan "slots": slot 0 (active/own clan) and slot 1 (guest clan).

## Data Structures

### ClanChannelUser (0x50 = 80 bytes)

Ghidra struct: `ClanChannelUser` in `/jag`

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0x00 | 24 | eastl::string | displayName | Current display name |
| 0x18 | 24 | eastl::string | previousDisplayName | Previous display name (if renamed) |
| 0x30 | 4 | int | world | World the user is on |
| 0x34 | 4 | int | rank | Clan rank (byte in packet, stored as int) |
| 0x38 | 24 | eastl::string | clanName | Clan name this user belongs to |

Constructor: `jag::ClanChannelUser::ClanChannelUser` at `<addr in DB>`

### ClanSettings (0xF0 = 240 bytes)

Ghidra struct: `ClanSettings` in `/jag`

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0x08 | 4 | int | settingsId | Unique settings identifier (gT_uint) |
| 0x10 | 24 | eastl::string | clanName | Clan name |
| 0x28 | 4 | uint | creationDate | Creation date (v2+; v3- adds `<in Ghidra DB>` correction) |
| 0x2C | 4 | uint | extraSettingsCount | Number of extra settings (v4+) |
| 0x30 | 1 | bool | allowNonMembers | Allow non-members flag |
| 0x34 | 4 | int | talkRank | Minimum rank to talk (signed byte in packet) |
| 0x38 | 4 | int | kickRank | Minimum rank to kick (signed byte in packet) |
| 0x3C | 4 | int | lootRank | Minimum rank for loot sharing (signed byte in packet) |
| 0x40 | 1 | bool | coinShare | Coin share enabled |
| 0x48 | 8 | long | membersBegin | eastl::vector begin ptr (ClanSettingsMember, stride 0x28) |
| 0x50 | 8 | long | membersEnd | eastl::vector end ptr |
| 0x58 | 8 | long | membersCapacity | eastl::vector capacity ptr |
| 0x80 | 8 | long | bannedBegin | eastl::vector begin ptr (eastl::string, stride 0x18) |
| 0x88 | 8 | long | bannedEnd | eastl::vector end ptr |
| 0x90 | 8 | long | bannedCapacity | eastl::vector capacity ptr |
| 0x98 | 8 | long | extraSettingsMap | Extra settings hash map |

The ClanSettings object is version-controlled (versions 1-6). Version determines which fields are decoded from the packet.

Constructor: `jag::ClanSettings::ClanSettings` at `<addr in DB>`

### ClanSettingsMember (0x28 = 40 bytes)

Ghidra struct: `ClanSettingsMember` in `/jag`

| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0x00 | 24 | eastl::string | displayName | Member display name |
| 0x18 | 4 | int | rank | Clan rank (signed byte in packet, stored as int) |
| 0x1C | 4 | uint | joinDate | Join date (v2+: gT_uint) |
| 0x20 | 4 | uint | world | World number (v5+: gT_ushort) |
| 0x24 | 1 | bool | muted | Muted flag (v6+: byte == 0x01) |

### ClanChannel

The clan channel is not a single struct but rather a collection of ClanChannelUser entries stored in an eastl::vector, managed at the handler level. Key fields on the parent object:
- ownerDisplayName (eastl::string)
- channelName (eastl::string)
- kickRank (byte)
- users (eastl::vector<ClanChannelUser>)

## Server Packet Handlers

### CLANSETTINGS_FULL

**Address:** `<addr in DB>`
**Ghidra name:** `jag::packethandlers::ClanSettings::CLANSETTINGS_FULL`

**Packet format:**
```
byte   slot        // 0 = active clan, 1 = guest clan, -1 = clear
<ClanSettings constructor data if slot != -1>
```

**Behavior:**
1. Reads slot byte
2. If slot == -1, clears the corresponding clan settings
3. Otherwise allocates a ClanSettings object (0xF0 bytes)
4. Calls `jag::ClanSettings::ClanSettings(this, packet)` to decode
5. Stores the settings in the appropriate slot (0 = active, 1 = guest)

### ClanSettings Constructor Decode Format (Version 1-6)

**Address:** `<addr in DB>`
**Ghidra name:** `jag::ClanSettings::ClanSettings`

```
byte   version           // 1-6
int    settingsId        // unique settings identifier
if version >= 2:
  long creationDate      // unix timestamp
int    memberCount
int    bannedCount

// For each member (memberCount times):
  string  displayName    // gStringCP1252ToUTF8
  byte    rank
  if version >= 5:
    ushort  world        // big-endian
  if version >= 2:
    long    joinDate     // unix timestamp
  if version >= 6:
    byte    muted        // 0 or 1

// For each banned user (bannedCount times):
  string  displayName    // gStringCP1252ToUTF8

// Clan name:
  string  clanName       // gStringCP1252ToUTF8

// If clanName is non-empty, read extra settings:
  // Variable system (loop until no more data):
  //   Top 2 bits of key determine type:
  //   00 = int (g4s)
  //   01 = long (g8)
  //   10 = string (gStringCP1252ToUTF8)
  //   11 = varbit
```

### CLANCHANNEL_FULL

**Address:** `<addr in DB>`
**Ghidra name:** `jag::packethandlers::ClanChannel::CLANCHANNEL_FULL`

**Packet format:**
```
byte   slot              // from param_3
// Clear existing channel for this slot

string ownerDisplayName  // gStringCP1252ToUTF8
string channelName       // gStringCP1252ToUTF8
byte   kickRank
int    userCount         // gSmart1or2s (signed)

// For each user (userCount times):
  string displayName           // gStringCP1252ToUTF8
  byte   hasPreviousName       // flag
  if hasPreviousName:
    string previousDisplayName // gStringCP1252ToUTF8
  ushort world                 // big-endian
  byte   rank                  // (signed byte)
  string clanName              // gStringCP1252ToUTF8
```

**Behavior:**
- Clears the existing channel for the given slot
- Reads owner info, channel name, kick rank
- Reads each user entry and constructs ClanChannelUser objects
- Compares each username against the local player name to determine own rank
- Stores the complete user list in the channel object

### CLANCHANNEL_DELTA

**Address:** `<addr in DB>`
**Ghidra name:** `jag::packethandlers::ClanChannel::CLANCHANNEL_DELTA`

**Packet format:**
```
// User data (same as CLANCHANNEL_FULL per-user format):
string displayName
byte   hasPreviousName
if hasPreviousName:
  string previousDisplayName
ushort world
byte   rank              // signed byte
string clanName
```

**Behavior:**
- If `rank == -128 (-0x80)`: **DELETE** user
  - Searches existing user list by displayName + world
  - Removes matching entry from the vector
- Otherwise: **ADD/UPDATE** user
  - Searches existing users by displayName
  - If found: updates world, rank, clanName, and optionally previousDisplayName
  - If not found: creates a new ClanChannelUser and appends to the list
- Re-sorts the user list after modification

### CLANSETTINGS_DELTA

**Address:** `<addr in DB>`
**Ghidra name:** `jag::packethandlers::ClanSettings::CLANSETTINGS_DELTA`

**Packet format:**
```
byte   slot              // 0 = active, 1 = guest
ulong  updateCounter1    // gT_ulong
ulong  updateCounter2    // gT_ulong

// Delta entries (loop until type == 0):
byte deltaType
  1 -> 0x30 byte delta object (AddMemberV1: version=0xFF, name, world(ushort), rank(byte), timestamp(ulong))
  3 -> 0x10 byte delta object (small delta: rank change, member removal)
  4 -> 0x30 byte delta object (string delta: SetClanName, SetExtraSetting*)
  5 -> 0x40 byte delta object (AddMemberV2: version=0xFF, name, world, rank, timestamp, hasPreviousName)
  0 -> end of deltas
```

**Behavior:**
1. Reads slot and two update counters
2. Reads delta entries in a loop:
   - Each delta has a type byte that determines the delta object size
   - Delta objects are decoded via vtable `Decode(Packet&)` method
3. Verifies update counter matches expected value
4. Applies all deltas **in reverse order** via vtable `Apply(ClanSettings&)` method

**Known delta types from symbol dump (different build):**
- `ClanSettingsDelta::AddMemberV1` - type 1 (0x30 bytes)
- `ClanSettingsDelta::AddMemberV2` - type 5 (0x40 bytes)
- `ClanSettingsDelta::DeleteMember` - type 3
- `ClanSettingsDelta::SetMemberRank` - type 3
- `ClanSettingsDelta::SetMemberMuted` - type 3
- `ClanSettingsDelta::AddBanned` - type 4
- `ClanSettingsDelta::DeleteBanned` - type 3
- `ClanSettingsDelta::SetClanName` - type 4
- `ClanSettingsDelta::SetExtraSettingInt` - type 3
- `ClanSettingsDelta::SetExtraSettingLong` - type 4
- `ClanSettingsDelta::SetExtraSettingString` - type 4
- `ClanSettingsDelta::SetExtraSettingVarbit` - type 3
- `ClanSettingsDelta::SetMemberExtraInfo` - type 4
- `ClanSettingsDelta::UpdateBaseSettings` - type 3

### Delta Vtable Functions (all named in Ghidra)

Each delta type byte maps to a vtable with Decode (+0x00), Apply (+0x08), and Destructor (+0x18) methods.

**Type 1 (AddMemberV1, 0x30 bytes):**
- Vtable: `<addr in DB>`
- Decode: `jag::ClanSettingsDelta::AddMemberV1::Decode` at `<addr in DB>`
  - Reads: version byte (must be 0xFF), displayName (string at +0x08), world (ushort at +0x20), rank (signed byte at +0x24), joinTimestamp (ulong at +0x28)
- Apply: `jag::ClanSettingsDelta::AddMemberV1::Apply` at `<addr in DB>`

**Type 3 (SmallDelta, 0x10 bytes):**
- Vtable: `<addr in DB>`
- Decode: `jag::ClanSettingsDelta::SmallDelta::Decode` at `<addr in DB>`
  - Reads: index (ushort at +0x08), sub-type byte (at +0x0C), flag byte (at +0x0D, -1 sentinel)
- Apply: `jag::ClanSettingsDelta::SmallDelta::Apply` at `<addr in DB>`
  - Removes member at index from members vector, cleans up banned names
- Used for: DeleteMember, SetMemberRank, SetMemberMuted, DeleteBanned, SetExtraSettingInt, SetExtraSettingVarbit, UpdateBaseSettings

**Type 4 (StringDelta, 0x30 bytes):**
- Vtable: `<addr in DB>`
- Decode: `jag::ClanSettingsDelta::StringDelta::Decode` at `<addr in DB>`
  - Reads: displayName (string at +0x08), flag (bool at +0x20), rank1 (signed byte at +0x24), rank2 (signed byte at +0x28)
- Apply: `jag::ClanSettingsDelta::StringDelta::Apply` at `<addr in DB>`
  - Copies string to ClanSettings+0x38 (clanName), sets flags at +0x50, +0x54, +0x58
- Used for: AddBanned, SetClanName, SetExtraSettingLong, SetExtraSettingString, SetMemberExtraInfo

**Type 5 (AddMemberV2, 0x40 bytes):**
- Vtable: `<addr in DB>`
- Decode: `jag::ClanSettingsDelta::AddMemberV2::Decode` at `<addr in DB>`
  - Reads: skips version byte, world (ushort at +0x08), rank (signed byte at +0x0C), extraWorld (ushort at +0x10), joinTimestamp (ulong at +0x18), displayName (string at +0x20), hasPreviousName (bool at +0x38)
- Apply: `jag::ClanSettingsDelta::AddMemberV2::Apply` at `<addr in DB>`

## CS2 Script Opcodes

### activeclanchannel_getuserworld

**Address:** `<addr in DB>`
**Ghidra name:** `jag::opcode::activeclanchannel_getuserworld`

Gets the world number for a user in the active clan channel by index.

## PlayerGroup System

The PlayerGroup system is structurally similar to the clan system but operates independently. From the symbol dump (different build), the key types are:

- **`jag::game::PlayerGroup`** - Main group object with `Decode(Packet&, PlayerGroupResourceProvider&)` method
- **`jag::game::PlayerGroupMember`** - Member entries (pool size 32)
- **`jag::game::PlayerGroupBannedUser`** - Banned user entries (pool size 16)
- **`jag::game::PlayerGroupDelta`** - Delta system with types:
  - `AddMember`, `DeleteMember`, `UpdateMemberBase`
  - `SetMemberRank`, `SetMemberReady`, `SetMemberTeam`, `SetMemberOnline`, `SetMemberOffline`
  - `AddBanned`, `DeleteBanned`
  - `SetVarValue`, `SetVarBitValue`
  - `SetGameLoading`, `StartGame`

The PlayerGroup packet handlers (`jag::packethandlers::PlayerGroups`) are registered through a separate mechanism and have not been located in this build's BindHandlers section. The CS2 opcode `player_group_member_get_same_world_var` at `<addr in DB>` is the only confirmed PlayerGroup function in this build.

## Related Functions

| Address | Name | Description |
|---------|------|-------------|
| <addr in DB> | jag::ClanSettings::ClanSettings | Constructor, decodes from Packet |
| <addr in DB> | jag::ClanChannelUser::ClanChannelUser | Constructor for channel user entries |
| <addr in DB> | jag::packethandlers::ClanSettings::CLANSETTINGS_FULL | Full settings packet handler |
| <addr in DB> | jag::packethandlers::ClanSettings::CLANSETTINGS_DELTA | Settings delta handler |
| <addr in DB> | jag::packethandlers::ClanChannel::CLANCHANNEL_FULL | Full channel packet handler |
| <addr in DB> | jag::packethandlers::ClanChannel::CLANCHANNEL_DELTA | Channel delta handler |
| <addr in DB> | jag::ClanSettingsDelta::AddMemberV1::Decode | Delta type 1 decode |
| <addr in DB> | jag::ClanSettingsDelta::AddMemberV1::Apply | Delta type 1 apply |
| <addr in DB> | jag::ClanSettingsDelta::SmallDelta::Decode | Delta type 3 decode |
| <addr in DB> | jag::ClanSettingsDelta::SmallDelta::Apply | Delta type 3 apply |
| <addr in DB> | jag::ClanSettingsDelta::StringDelta::Decode | Delta type 4 decode |
| <addr in DB> | jag::ClanSettingsDelta::StringDelta::Apply | Delta type 4 apply |
| <addr in DB> | jag::ClanSettingsDelta::AddMemberV2::Decode | Delta type 5 decode |
| <addr in DB> | jag::ClanSettingsDelta::AddMemberV2::Apply | Delta type 5 apply |
| <addr in DB> | jag::opcode::player_group_member_get_same_world_var | CS2: check same world |
