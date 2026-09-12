# Chat ServerProt Handlers

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Rev 947-1 update**: All opcodes reshuffled. Key verified 947 opcodes:
> MESSAGE_GAME=105, MESSAGE_PUBLIC=45, MESSAGE_PRIVATE=151, MESSAGE_PRIVATE_ECHO=129,
> RUNCLIENTSCRIPT=101, CHAT_FILTER_SETTINGS=39, MESSAGE_CLANCHANNEL_SYSTEM=125,
> MESSAGE_FRIENDCHANNEL=7, FRIENDCHAT_JOIN=179.
> See `serverprot-table.md` for the full 947-1 opcode/size table.

Category: `jag::packethandlers::Chat`
Symbol dump: 14 lambdas (E_ through E12_) in `jag::packethandlers::Chat::Chat(jag::Client &)`
Additional: 2 lambdas in `jag::packethandlers::FriendChat::FriendChat(jag::Client &)`
Client subsystem reference: `__DT_SYMTAB[0x490]` (ChatHistory + RelationshipManager)

All chat handlers are registered inline in `BindHandlers` (<addr in DB>). The Chat category encompasses chat messages, clan operations, friend chat, and quickchat variants.

## Handler Summary

| # | Name | Address | Description |
|---|------|---------|-------------|
| 1 | MESSAGE_GAME | `<addr in DB>` | Game/system messages with variable chat types |
| 2 | MESSAGE_PUBLIC | `<addr in DB>` | Public chat from other players |
| 3 | MESSAGE_PRIVATE | `<addr in DB>` | Incoming private message |
| 4 | MESSAGE_PRIVATE_ECHO | `<addr in DB>` | Echo of sent private message |
| 5 | MESSAGE_PRIVATE_SYSTEM | `<addr in DB>` | System-generated private message (thunk) |
| 6 | MESSAGE_FRIENDCHAT | `<addr in DB>` | Friend chat channel message |
| 7 | MESSAGE_CLANCHANNEL | `<addr in DB>` | Clan channel message |
| 8 | MESSAGE_QUICKCHAT_PRIVATE | `<addr in DB>` | Quickchat private message |
| 9 | MESSAGE_QUICKCHAT_FRIENDCHAT | `<addr in DB>` | Quickchat in friend chat |
| 10 | MESSAGE_QUICKCHAT_CLANCHANNEL | `<addr in DB>` | Quickchat in clan channel |
| 11 | MESSAGE_QUICKCHAT_CLANCHAT | `<addr in DB>` | Quickchat in clan chat |
| 12 | CHAT_FILTER_SETTINGS | `<addr in DB>` | Chat filter configuration update |
| 13 | RUN_CLIENTSCRIPT | `<addr in DB>` | Execute client script via chat system |
| 14 | FRIENDCHAT_JOIN | `<addr in DB>` | Join friend chat channel |
| 15 | CLANSETTINGS_DELTA | `<addr in DB>` | Incremental clan settings update |
| 16 | CLANCHANNEL_FULL | `<addr in DB>` | Full clan channel data |

## Chat Type Constants

Chat messages are classified by type ID passed to `AddChat`/`AddChat_hookable`:

| Type | Hex | Usage |
|------|-----|-------|
| 3 | 0x03 | Public chat (no world icon) |
| 6 | 0x06 | Client script message |
| 7 | 0x07 | Public chat (with world icon) |
| 9 | 0x09 | Friend chat message |
| 18 | 0x12 | Quickchat clan channel |
| 19 | 0x13 | Chat filter settings |
| 20 | 0x14 | Quickchat friend chat |
| 22 | 0x16 | Private message echo (direct) |
| 23 | 0x17 | Private message (incoming, direct) |
| 24 | 0x18 | Private message echo (via world) |
| 25 | 0x19 | Private message (incoming, via world) |
| 41 | 0x29 | Quickchat clan chat |
| 42 | 0x2a | Quickchat private |
| 43 | 0x2b | Clan channel message |

## Detailed Handler Analysis

### MESSAGE_GAME (<addr in DB>)

The most complex chat handler. Reads a variable chat sub-type from the packet and dispatches accordingly.

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1-2 | ushort | chatType | Sub-type (1 byte if < 0x80, 2 bytes if >= 0x80 with 0x8000 added) |
| varies | 4 | uint | param | Message parameter (big-endian swapped) |
| varies | 1 | byte | flags | Bitmask: bit0=has sender name, bit1=has separate display name |
| varies | string | - | senderName | Sender name (if flags & 1) |
| varies | string | - | displayName | Display name (if flags & 2, else copies senderName) |
| varies | string | - | message | Chat message text |

**Special sub-types:**
- `99 (0x63)` - Friend list notification (calls <in Ghidra DB> with type 1)
- `96 (0x60)` - Friend list update (calls <in Ghidra DB> with type 5)
- `98 (0x62)` - Relationship update (calls <in Ghidra DB>)
- All others - Standard AddChat with ignore list check

### MESSAGE_PUBLIC (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | senderType | 0=same name, 1=different display name |
| 1 | string | - | senderName | Player name |
| varies | string | - | displayName | Display name (if senderType==1, else copy of senderName) |
| varies | 2 | ushort | worldId | Source world |
| varies | 3 | bytes | timestamp | 3-byte message timestamp |
| varies | 1 | byte | channelByte | Channel index (indexes into <in Ghidra DB> graphic table) |
| varies | bytes | - | messageData | Encoded message content |

**Behavior:** Checks ignore list via `jag::RelationshipManager::IsOnIgnoreList`. Deduplicates via circular message ID buffer (<in Ghidra DB>, capacity 100). Decodes message via <in Ghidra DB>. Adds graphic icons (`<img=%d>`) if channel has an icon. Chat type: 3 (no icon) or 7 (with icon).

### MESSAGE_PRIVATE (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | string | - | senderName | Sender player name |
| varies | 2 | ushort | worldIdHigh | High bits of world+timestamp |
| varies | 3 | bytes | timestamp | 3-byte message timestamp |
| varies | 1 | byte | channelByte | Channel index |
| varies | 1 | byte | messageType | 1=direct, other=via world |
| varies | 2 | ushort | quickchatId | Quickchat message ID |
| varies | bytes | - | messageData | Encoded message content |

**Behavior:** Chat type 0x17 (direct) or 0x19 (via world) based on messageType. Checks ignore list. Deduplicates messages.

### MESSAGE_PRIVATE_ECHO (<addr in DB>)

**Packet format:** Variable (similar to MESSAGE_PRIVATE but without sender)
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | string | - | recipientName | Recipient player name |
| varies | 2 | ushort | worldIdHigh | World + timestamp high bits |
| varies | 3 | bytes | timestamp | 3-byte timestamp |
| varies | 1 | byte | channelByte | Channel index |
| varies | 1 | byte | messageType | 1=direct, other=via world |
| varies | bytes | - | messageData | Encoded message content |

**Behavior:** Echo of a private message sent by the local player. Chat type 0x16 (direct) or 0x18 (via world). No ignore list check needed.

### MESSAGE_PRIVATE_SYSTEM (<addr in DB>)

**Packet format:** Variable (thunk to <in Ghidra DB>)
**Behavior:** System-generated private message. Calls through to a complex handler that reads player names, world info, and message data. Used for automated system messages delivered via the private message system.

### MESSAGE_FRIENDCHAT (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | senderType | 0=same name, 1=different display name |
| 1 | string | - | senderName | Sender name |
| varies | string | - | displayName | Display name (if senderType==1) |
| varies | string | - | chatText | Additional text field |
| varies | 2 | ushort | worldIdHigh | World + timestamp high |
| varies | 3 | bytes | timestamp | 3-byte timestamp |
| varies | 1 | byte | channelByte | Channel/world icon index |
| varies | bytes | - | messageData | Encoded message content |

**Behavior:** Friend chat channel message. Checks ignore list. Deduplicates. Adds with chat type 9. Formats graphic icons for channel badge.

### MESSAGE_CLANCHANNEL (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | channelId | Clan channel ID (negative=default channel) |
| 1 | 2 | ushort | messageId | Message sequence ID |
| 3 | 3 | bytes | timestamp | 3-byte timestamp |
| 6 | bytes | - | messageData | Encoded message content |

**Behavior:** Clan chat channel message. References `__DT_SYMTAB[0x49e]` for message decoding. Looks up channel info. Checks ignore list. Deduplicates. Chat type: 0x2b.

### MESSAGE_QUICKCHAT_PRIVATE (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | channelId | Channel ID |
| 1 | string | - | senderName | Sender name |
| varies | 2 | ushort | worldIdHigh | World + timestamp high |
| varies | 3 | bytes | timestamp | 3-byte timestamp |
| varies | 1 | byte | channelByte | Channel index |
| varies | 2 | ushort | quickchatId | Quickchat phrase ID |
| varies | bytes | - | quickchatData | Quickchat parameters |

**Behavior:** Quickchat private message. Chat type: 0x2a + channel offset. Checks ignore list.

### MESSAGE_QUICKCHAT_FRIENDCHAT (<addr in DB>)

**Packet format:** Variable (similar to MESSAGE_FRIENDCHAT but with quickchat)
**Behavior:** Quickchat message in friend chat channel. Chat type: 0x14. Checks ignore list. Deduplicates.

### MESSAGE_QUICKCHAT_CLANCHANNEL (<addr in DB>)

**Packet format:** Variable (similar to MESSAGE_CLANCHANNEL but with quickchat)
**Behavior:** Quickchat message in clan channel. Chat type: 0x12. Checks ignore list. Deduplicates.

### MESSAGE_QUICKCHAT_CLANCHAT (<addr in DB>)

**Packet format:** Variable
**Behavior:** Quickchat in clan chat. Chat type: 0x29. Checks ignore list via `__DT_SYMTAB[0x4dc]` and `jag::RelationshipManager::IsOnIgnoreList`. Deduplicates via circular buffer.

### CHAT_FILTER_SETTINGS (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | string | - | filterName | Filter/channel name |
| varies | 2 | ushort | worldId | World ID |

**Behavior:** Looks up world info via <in Ghidra DB>. Formats filter string. Adds as chat type 0x13 via AddChat_hookable. Calls <in Ghidra DB> for post-processing.

### RUN_CLIENTSCRIPT (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | string | - | scriptName | Client script name/identifier |
| varies | bytes | - | scriptData | Script parameters |

**Behavior:** Reads a script name string, then decodes script parameters via <in Ghidra DB>. Processes the decoded data and adds to chat as type 6. May return yield (<in Ghidra DB>) if the script is not ready.

### FRIENDCHAT_JOIN (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | channelId | Friend chat channel ID |
| 2 | string | - | channelName | Channel name |
| varies | 2 | ushort | param1 | Channel parameter 1 |
| varies | 2 | ushort | param2 | Channel parameter 2 |
| varies | 1 | byte | isOwner | Whether player owns the channel |

**Behavior:** Sets up a friend chat channel entry object (0x30 bytes). Allocates via HeapInterface::Alloc. Stores in Client friend chat slot at `__DT_SYMTAB[0x49d]`. Calls `jag::Client::SetMainState(0x25)` to transition client to the lobby/channel join state.

### CLANSETTINGS_DELTA (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | channelByte | Channel selector |
| 1 | 8 | ulong | sequence | Sequence number (via gT_ulong) |
| 9 | 4 | uint | updateId | Update ID for deduplication |
| 13 | 1 | byte | entryType | First delta entry type (1-14) |
| varies | bytes | - | entryData | Entry-specific data |
| varies | 1 | byte | nextType | Next entry type (0 = end) |

**14 entry types** for delta updates: string modifications, integer fields, boolean flags, list operations, etc. Each type has its own vtable-dispatched decoder.

**Behavior:** Applies incremental updates to the ClanSettings object. References `__DT_SYMTAB[0x49c]` (clan system). Validates sequence number matches expected, then applies each delta entry to the stored ClanSettings.

### CLANCHANNEL_FULL (<addr in DB>)

**Packet format:** Variable
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | channelByte | Channel slot (-1=clear active, <-1=clear both, 0/1=slot index) |
| 1 | bytes | - | channelData | Full clan channel data |

**Behavior:** Allocates a ClanChannel object (0x80 bytes) via <in Ghidra DB>, decodes from Packet via <in Ghidra DB>, wraps in shared_ptr, and stores in Client clan channel slots at `__DT_SYMTAB[0x490]` + 0x20/0x30/0x50. Similar pattern to CLANSETTINGS_FULL.

## Common Infrastructure

### Message Deduplication
All incoming messages use a circular buffer (<in Ghidra DB>, capacity 100) to detect duplicate message IDs. The buffer is indexed by <in Ghidra DB> (wrapping at 100).

### Ignore List
Most incoming messages check `jag::RelationshipManager::IsOnIgnoreList` (`__DT_SYMTAB[0x49a]`) before displaying. Messages from ignored players are silently dropped.

### World Icons / Graphics
Channel messages reference a global graphic table at <in Ghidra DB> (12 bytes per entry):
- <in Ghidra DB> + idx*12 + 0: graphic data
- <in Ghidra DB> + idx*12: graphic image ID (-1 = none)
- <in Ghidra DB> + idx*12: has icon flag
- <in Ghidra DB> + idx*12: requires ignore check flag

When a graphic ID is present, messages are wrapped with `<img=%d>` formatting tags.

### Chat Display Functions
| Address | Name | Description |
|---------|------|-------------|
| `<addr in DB>` | `jag::ChatHistory::AddChat` | Add chat message (non-hookable) |
| `<addr in DB>` | `jag::ChatHistory::AddChat_hookable` | Add chat message (hookable, used by engine) |
| `<addr in DB>` | Post-add processing | Called after AddChat_hookable for additional processing |
| `<addr in DB>` | Message decoder | Decodes compressed message text from Packet |

## Client Subsystem References

- `__DT_SYMTAB[0x490]` - ChatHistory (`.st_value`) and Client state (`.st_size`)
- `__DT_SYMTAB[0x49a]` - RelationshipManager (ignore list)
- `__DT_SYMTAB[0x49c]` - Clan system
- `__DT_SYMTAB[0x49d]` - Friend chat channel
- `__DT_SYMTAB[0x49e]` - Message decoder/world info
- `__DT_SYMTAB[0x4dc]` - Privacy/filtering settings
- `__DT_SYMTAB[0x442]` - World lookup service
- `__DT_SYMTAB[0x498]` - Player lookup (for private messages)
- Return values: `<in Ghidra DB>` = success, `<in Ghidra DB>` = yield
