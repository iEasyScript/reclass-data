# Network Protocol Documentation

Comprehensive reverse engineering documentation of the RuneScape NXT client's network protocol (build 946-3). Sufficient for building a private server emulator.

## Document Index

### Foundation
| Document | Description |
|----------|-------------|
| [packet-class.md](packet-class.md) | `jag::Packet` class — struct layout, read/write methods, naming conventions |
| [crypto.md](crypto.md) | ISAAC stream cipher, XTEA block cipher, RSA encryption — algorithms and key management |
| [transport.md](transport.md) | ClientStream (TCP), ServerConnection (framing), ConnectionManager (lifecycle) |
| [framing.md](framing.md) | Packet framing — opcode encoding, size modes, dispatch table, ServerProt struct |

### Protocols
| Document | Description |
|----------|-------------|
| [login-protocol.md](login-protocol.md) | Login state machine — 37 states, RSA/XTEA handshake, SSO/TOTP, response codes |
| [player-info.md](player-info.md) | PLAYER_INFO — bit-packed positions, extended info blocks, appearance encoding |
| [npc-info.md](npc-info.md) | NPC_INFO — NPC positions, movement, 28 extended info blocks, appearance |
| [js5-protocol.md](js5-protocol.md) | JS5 cache protocol — container format, compression, master index, worker threads |

### ServerProt Handlers (Server → Client)
| Document | Description | Handlers |
|----------|-------------|----------|
| [serverprot/variables.md](serverprot/variables.md) | SET_VARP, SET_VARBIT, SET_VARC, RESET — variable system | 18 |
| [serverprot/interfaces.md](serverprot/interfaces.md) | IF_OPEN, IF_SET*, IF_CLOSE — interface operations | 37 |
| [serverprot/clientstate.md](serverprot/clientstate.md) | REBUILD, WORLDENTITY_INFO, MAP_FLAG, MINIMAP, tick/ready — map state | 18 |
| [serverprot/zone-updates.md](serverprot/zone-updates.md) | LOC/OBJ/MAP_ANIM/PROJANIM/SOUND — zone entity updates | 21 |
| [serverprot/camera.md](serverprot/camera.md) | CAM_MOVETO, CAM_LOOKAT, CAM_SHAKE, OCULUS_SYNC | 10 |
| [serverprot/audio.md](serverprot/audio.md) | MIDI, SYNTH, VORBIS, SOUND_GROUP — audio playback | 16 |
| [serverprot/chat.md](serverprot/chat.md) | MESSAGE_GAME/PRIVATE/CLAN, RUN_CLIENTSCRIPT, chat filters | 16 |
| [serverprot/clanchannel.md](serverprot/clanchannel.md) | CLANCHANNEL_FULL, CLANCHANNEL_DELTA — clan channel data | 2 |
| [serverprot/clansettings.md](serverprot/clansettings.md) | CLANSETTINGS_FULL, CLANSETTINGS_DELTA — clan settings | 2 |
| [serverprot/social.md](serverprot/social.md) | UPDATE_FRIENDCHAT_CHANNEL, UPDATE_FRIENDLIST — social data | 2 |
| [serverprot/npcinfo.md](serverprot/npcinfo.md) | NPC_INFO, NPC_ANIM_SPECIFIC — NPC update stream | 2 |
| [serverprot/worlddata.md](serverprot/worlddata.md) | SET_WORLD_TARGET — world switching | 1 |
| [serverprot/misc.md](serverprot/misc.md) | PLAYER_INFO, LOGOUT, NOOP, SET_RUN_ENERGY — uncategorized | 74 |

### ClientProt (Client → Server)
| Document | Description |
|----------|-------------|
| [clientprot-table.md](clientprot-table.md) | Complete table of all 130 ClientProt opcodes with sizes |
| [clientprot/actions.md](clientprot/actions.md) | OPLOC, OPNPC, OPOBJ, OPPLAYER — entity interaction packets |
| [clientprot/interface.md](clientprot/interface.md) | IF_BUTTON, CLOSE_MODAL, RESUME_* — interface responses |
| [clientprot/movement.md](clientprot/movement.md) | MOVE_GAME — player movement packets |
| [clientprot/misc.md](clientprot/misc.md) | NO_TIMEOUT, WINDOW_STATUS, CLIENT_CHEAT, telemetry |

### Social & World
| Document | Description |
|----------|-------------|
| [clans.md](clans.md) | ClanChannel, ClanSettings, delta protocols |
| [social.md](social.md) | Friend/ignore lists, relationship manager |
| [settings-pane.md](settings-pane.md) | The settings interface: how its rows are addressed, what each control sends, which var each row reads |
| [world-data.md](world-data.md) | World list, lobby data, UID system |

## Quick Reference

- **ServerProt opcodes**: 202 registered (0x00-0xD8, 15 gaps)
- **ClientProt opcodes**: 130 registered (0-129), 84 identified by name
- **Isaac cipher**: Opcode-only encryption (payload is cleartext)
- **Opcode encoding**: 1 byte (0-127) or 2 bytes (128-216), Isaac XOR
- **Size modes**: Fixed, var_byte (1B prefix), var_short (2B prefix)
- **Max packets/tick**: 100 (server→client processing limit)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Game Logic                            │
│  (PacketHandlers, InterfaceManager, PlayerList, etc.)   │
├─────────────────────────────────────────────────────────┤
│              ConnectionManager                           │
│  TcpIn (receive) │ ProcessConnections │ Login FSM        │
├─────────────────────────────────────────────────────────┤
│              ServerConnection                            │
│  Isaac encrypt/decrypt │ Message queue │ Packet buffer   │
├─────────────────────────────────────────────────────────┤
│              ClientStream                                │
│  Ring buffer read │ Buffered write │ TCP socket          │
├─────────────────────────────────────────────────────────┤
│              TCP/IP Network                               │
└─────────────────────────────────────────────────────────┘
```

## Connection Flow

1. **TCP Connect** → ClientStream opens socket
2. **JS5 Handshake** → Cache version check, master index download
3. **Login Request** → RSA block (XTEA key) + XTEA block (credentials)
4. **Login Response** → Server sends status code, session data
5. **Isaac Init** → Both sides seed ISAAC from shared XTEA key
6. **Game Loop** → ServerProt packets (Isaac-encrypted opcodes) dispatched via handler table
7. **Client Actions** → ClientProt packets sent via MakeClientMessage + SendClientMessage
