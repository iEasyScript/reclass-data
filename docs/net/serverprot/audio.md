# Audio ServerProt Handlers

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

Category: `jag::packethandlers::Audio`
Symbol dump: 16 lambdas (E_ through E14_) in `jag::packethandlers::Audio::Audio(jag::Client &)`
Client subsystem reference: `__DT_SYMTAB[0x4a2]` (SoundManager object)

All 16 audio handlers are registered inline in `BindHandlers` (<addr in DB>), not via a separate constructor call.

## Handler Summary

| # | Name | Address | Payload Size | Description |
|---|------|---------|-------------|-------------|
| 1 | SYNTH_SOUND | `<addr in DB>` | 12 | Play synthesized sound effect |
| 2 | MIDI_SONG | `<addr in DB>` | 10 | Play MIDI music track |
| 3 | MIDI_JINGLE | `<addr in DB>` | 10 | Play MIDI jingle (quest/level up) |
| 4 | MIDI_STOP | `<addr in DB>` | 0 | Stop MIDI playback |
| 5 | MIDI_SWAP | `<addr in DB>` | 5 | Cross-fade to new MIDI song |
| 6 | SOUND_GROUP | `<addr in DB>` | 11+ | Play 3D positioned sound |
| 7 | SOUND_STOP | `<addr in DB>` | 2 | Stop specific sound by ID |
| 8 | SOUND_STOP_ALL | `<addr in DB>` | 0 | Stop all sounds on buss 8 |
| 9 | SOUND_GROUP_SPEED | `<addr in DB>` | 6 | Set sound group playback speed |
| 10 | SOUND_GROUP_STOP | `<addr in DB>` | 2 | Stop all instances of a sound group |
| 11 | SOUND_MODIFY | `<addr in DB>` | 4 | Modify active sound speed/volume |
| 12 | SOUND_AREA | `<addr in DB>` | 4 | Trigger area sound via SoundManager |
| 13 | SOUND_AREA_SYNTH | `<addr in DB>` | 8 | Create area synth sound |
| 14 | SOUND_MIXBUSS_SETLEVEL | `<addr in DB>` | 5 | Set mix buss volume level |
| 15 | VORBIS_SONG | `<addr in DB>` | 6 | Play Vorbis-encoded music |
| 16 | VORBIS_PRELOAD | `<addr in DB>` | 4 | Preload Vorbis audio resource |

## Detailed Handler Analysis

### SYNTH_SOUND (<addr in DB>)

**Packet format:** 12 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | soundId | Sound resource ID (big-endian swapped) |
| 4 | 1 | byte | volume | Volume level |
| 5 | 2 | ushort | loopDelay | Delay between loops (big-endian swapped) |
| 7 | 1 | byte | loopCount | Number of times to loop |
| 8 | 2 | ushort | delay | Initial delay before playback (big-endian swapped) |
| 10 | 2 | ushort | attenuation | Distance attenuation (big-endian swapped) |

**Behavior:** Creates a synthesized sound instance via `jag::game::SoundManager::ClaimVorbis` (<in Ghidra DB>). The core sound creation function used by most audio handlers.

### MIDI_SONG (<addr in DB>)

**Packet format:** 10 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | songId | MIDI song resource ID |
| 4 | 1 | byte | volume | Volume level |
| 5 | 2 | ushort | fadeIn | Fade-in duration |
| 7 | 1 | byte | loop | Loop control |
| 8 | 2 | ushort | delay | Start delay |

**Behavior:** Starts MIDI music playback. Used for background music in different game areas.

### MIDI_JINGLE (<addr in DB>)

**Packet format:** 10 bytes (same structure as MIDI_SONG)
**Behavior:** Plays a short MIDI jingle (quest complete fanfare, level up sound, etc.). Same packet structure as MIDI_SONG but treated as a one-shot priority sound.

### MIDI_STOP (<addr in DB>)

**Packet format:** 0 bytes
**Behavior:** Stops all MIDI playback via `<in Ghidra DB>(soundMgr, 1)`. The parameter `1` indicates a graceful stop.

### MIDI_SWAP (<addr in DB>)

**Packet format:** 5 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | volume | Target volume for new song |
| 1 | 4 | int | songId | New song ID (g4s_alt3 encoded) |

**Behavior:** Cross-fades between the currently playing MIDI song and a new one. If songId is negative, stops current song. Otherwise, claims a new sound instance, sets cross-fade parameters (duration at +0x94 = 25 ticks, volume curve at +0x34..+0x44), and stores the new song reference at SoundManager+0x698/+0x6a8.

### SOUND_GROUP (<addr in DB>)

**Packet format:** 11+ bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | soundId | Sound resource ID |
| 4 | 1 | byte | volume | Volume level |
| 5 | 2 | ushort | x | X coordinate |
| 7 | 2 | ushort | y | Y coordinate |
| 9 | 1 | byte | boneId | Bone attachment ID |
| 10 | 1 | byte | type | Sound shape type |

**Behavior:** Creates a 3D positioned sound via `jag::game::SoundManager::ClaimVorbis` (<in Ghidra DB>). The sound is spatialized at the given world coordinates.

### SOUND_STOP (<addr in DB>)

**Packet format:** 2 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | soundId | Sound instance ID to stop |

**Behavior:** Iterates all active sound instances searching by ID. When found, marks the instance for fade-out and stop. Uses an unrolled loop (8x unroll factor) for performance.

### SOUND_STOP_ALL (<addr in DB>)

**Packet format:** 0 bytes
**Behavior:** Stops all sounds on audio buss 8 via `jag::game::SoundManager::StopAllSoundsOnBuss(soundMgr, 8)` (<in Ghidra DB>).

### SOUND_GROUP_SPEED (<addr in DB>)

**Packet format:** 6 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | soundId | Sound group ID (big-endian swapped) |
| 4 | 2 | ushort | speed | Playback speed parameter |

**Behavior:** Adjusts the playback speed of an active sound group.

### SOUND_GROUP_STOP (<addr in DB>)

**Packet format:** 2 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | groupId | Sound group ID to stop |

**Behavior:** Iterates all active sound instances. For each instance matching the group ID at +0x9c, clears the active flag (+0x98), checks state (+0x94 == 0 && +0x14 < 4), and initiates graceful shutdown. Uses an unrolled loop (4x unroll factor).

### SOUND_MODIFY (<addr in DB>)

**Packet format:** 4 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | soundId | Sound instance ID |
| 2 | 2 | ushort | speed | Speed/volume modifier |

**Behavior:** Searches active sound instances by ID at +0x34 using an 8-way unrolled loop. When found, applies a normalized float speed/volume value at +0x1c (clamped to [0.0, max]).

### SOUND_AREA (<addr in DB>)

**Packet format:** 4 bytes (gT_uint encoded)
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | soundId | Area sound ID (transform-encoded) |

**Behavior:** Triggers an area sound via a SoundManager vtable function at +0x670/+0x680. Uses an indirect call through the SoundManager's vtable at offset +0x38.

### SOUND_AREA_SYNTH (<addr in DB>)

**Packet format:** 8 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | uint | soundId | Sound resource ID (big-endian swapped) |
| 4 | 1 | byte | param1 | First parameter |
| 5 | 1 | byte | param2 | Second parameter |
| 6 | 2 | ushort | param3 | Third parameter (big-endian swapped) |

**Behavior:** Creates an area synth sound via <in Ghidra DB>. Uses a different creation path than SOUND_GROUP.

### SOUND_MIXBUSS_SETLEVEL (<addr in DB>)

**Packet format:** 5 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | level | Volume level (negated before use) |
| 1 | 4 | uint | bussId | Mix buss ID (big-endian swapped) |

**Behavior:** Sets the volume level of a specific mix buss via `<in Ghidra DB>(soundMgr, bussId, -level)`.

### VORBIS_SONG (<addr in DB>)

**Packet format:** 6 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | songId | Vorbis song resource ID |
| 2 | 2 | ushort | loopCount | Number of loops (0 = infinite) |
| 4 | 2 | ushort | duration | Playback duration |

**Behavior:** Starts Vorbis (OGG) encoded music playback. Used for higher-quality streamed audio tracks.

### VORBIS_PRELOAD (<addr in DB>)

**Packet format:** 4 bytes (g4s_alt3 encoded)
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 4 | int | resourceId | Vorbis resource to preload |

**Behavior:** Preloads a Vorbis audio resource into memory. Only acts if streaming audio is enabled (SoundManager+0x718 == 1). Calls <in Ghidra DB> to initiate the preload, then triggers a vtable callback.

## Key Subsystem Functions

| Address | Name | Description |
|---------|------|-------------|
| `<addr in DB>` | `jag::game::SoundManager::ClaimVorbis` | Core sound creation function |
| `<addr in DB>` | `jag::game::SoundManager::StopAllSoundsOnBuss` | Stop sounds on specific buss |
| `<addr in DB>` | SoundManager::SetMixBussLevel | Set mix buss volume |
| `<addr in DB>` | SoundManager::StopSoundsOnBuss | Stop sounds on buss by type |
| `<addr in DB>` | SoundManager::CreateAreaSynth | Create area synth sound |
| `<addr in DB>` | SoundManager::PreloadResource | Preload audio resource |

## Client Subsystem References

- `__DT_SYMTAB[0x4a2]` - SoundManager object
- SoundManager+0x698 - Current MIDI song ID
- SoundManager+0x6a8 - Current MIDI song instance pointer
- SoundManager+0x718 - Streaming audio enabled flag
- SoundManager+0x670 - Area sound function pointer
- Return values: `<in Ghidra DB>` = success, `<in Ghidra DB>` = yield
