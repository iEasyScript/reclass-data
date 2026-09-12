# Camera ServerProt Handlers

> 🔄 **Handler naming convention updated (2026-06-29).** The 948-5 Ghidra DB (`rs2client.948-5`) now names every ServerProt **dispatch
> handler** flat as `jag::PacketHandlers::<CamelName>` (e.g. `jag::PacketHandlers::VarpSmall`,
> `jag::PacketHandlers::IfOpensub`), resolved structurally from each packet's `ProtEntry+0x28` binding.
> This supersedes the per-subsystem `jag::packethandlers::<Subsystem>::<NAME>` scheme referenced below.
> For authoritative opcode↔name↔size and the current handler symbol use


> **Rev 947-1**: Opcodes reshuffled from 946. See `serverprot-table.md` for current opcode/size table.

Category: `jag::packethandlers::Camera`
Symbol dump: 10 lambdas (E_ through E8_) in `jag::packethandlers::Camera::Camera(jag::Client &)`
Client subsystem reference: `__DT_SYMTAB[0x491]` (Camera object)

All 10 camera handlers are registered inline in `BindHandlers` (<addr in DB>), not via a separate constructor call.

## Handler Summary

| # | Name | Address | Payload Size | Description |
|---|------|---------|-------------|-------------|
| 1 | CAM_UPDATE | `<addr in DB>` | Variable | Full camera state update (position, lookat, orientation, shake, mode flags) |
| 2 | CAM_RESET | `<addr in DB>` | 0 | Reset camera to default position; may yield |
| 3 | CAM_SMOOTHRESET | `<addr in DB>` | 0 | Smooth camera reset transition |
| 4 | CAM_FORCEANGLE | `<addr in DB>` | 1 | Force camera to specific angle |
| 5 | CAM_MOVETO | `<addr in DB>` | 6 | Move camera to absolute position |
| 6 | CAM_LOOKAT | `<addr in DB>` | 6 | Set camera lookat target |
| 7 | CAM_SHAKE | `<addr in DB>` | 4 | Apply camera shake effect |
| 8 | CAM_MOVETO_ARC | `<addr in DB>` | 4 | Move camera along arc path |
| 9 | CAM_LOOKAT_ARC | `<addr in DB>` | 6 | Set camera lookat via arc interpolation |
| 10 | OCULUS_SYNC | `<addr in DB>` | 0 | No-op acknowledgment for Orb of Oculus |

## Detailed Handler Analysis

### CAM_UPDATE (<addr in DB>)

The largest camera handler. Reads a comprehensive camera state update from the server.

**Packet format:** Variable-size, bitmask-controlled fields
- Reads camera position, lookat coordinates, orientation quaternion
- Shake effect parameters (type, intensity, duration)
- Camera mode flags via bitmask
- Entity tracking information

**Behavior:** Updates the Camera object (`__DT_SYMTAB[0x491]`) with all received state. This is the primary per-tick camera synchronization packet.

### CAM_RESET (<addr in DB>)

**Packet format:** 0 bytes payload
**Behavior:** Calls `jag::game::Camera::ProcessCameraReset` (<addr in DB>). Returns success (<in Ghidra DB>) or yield (<in Ghidra DB>) depending on whether the reset has completed. The reset may take multiple ticks to smoothly transition back to default.

### CAM_SMOOTHRESET (<addr in DB>)

**Packet format:** 0 bytes payload
**Behavior:** Reads a boolean from the client state, increments a counter, and sets a dirty flag. Initiates a smooth camera transition back to the default position over time.

### CAM_FORCEANGLE (<addr in DB>)

**Packet format:** 1 byte
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | angle | Camera angle to force |

**Behavior:** Forces the camera to a specific viewing angle. Used by server-controlled cutscenes or scripts.

### CAM_MOVETO (<addr in DB>)

**Packet format:** 6 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | x | X coordinate (adjusted: value - 0x80) |
| 1 | 1 | byte | y | Y coordinate (adjusted: value - 0x80) |
| 2 | 2 | ushort | height | Camera height |
| 4 | 1 | byte | speed | Movement speed |
| 5 | 1 | byte | accel | Acceleration |

**Behavior:** Calls helper at <addr in DB> to set camera movement target. Coordinates are offset by -128 from the byte value.

### CAM_LOOKAT (<addr in DB>)

**Packet format:** 6 bytes (same layout as CAM_MOVETO)
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | x | X coordinate (adjusted: value - 0x80) |
| 1 | 1 | byte | y | Y coordinate (adjusted: value - 0x80) |
| 2 | 2 | ushort | height | Lookat height |
| 4 | 1 | byte | speed | Movement speed |
| 5 | 1 | byte | accel | Acceleration |

**Behavior:** Calls helper at <addr in DB> to set camera lookat target position.

### CAM_SHAKE (<addr in DB>)

**Packet format:** 4 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 2 | ushort | shakeType | Type/axis of shake |
| 2 | 2 | ushort | intensity | Shake intensity |

**Behavior:** Applies a camera shake effect. Used for earthquakes, explosions, or dramatic events.

### CAM_MOVETO_ARC (<addr in DB>)

**Packet format:** 4 bytes (g4s_alt2 encoded int)
**Behavior:** Moves the camera along an arc path. Used for cinematic camera movements that follow curved trajectories rather than linear interpolation.

### CAM_LOOKAT_ARC (<addr in DB>)

**Packet format:** 6 bytes
| Offset | Size | Type | Name | Description |
|--------|------|------|------|-------------|
| 0 | 1 | byte | x1 | First coordinate (adjusted: value - 0x80) |
| 1 | 1 | byte | x2 | Second coordinate (adjusted: value - 0x80) |
| 2 | 1 | byte | x3 | Third coordinate (negated - 0x80) |
| 3 | 1 | byte | x4 | Fourth coordinate (negated - 0x80) |
| 4 | 2 | ushort | param | Additional parameter (big-endian swapped) |

**Behavior:** Sets camera lookat via arc interpolation. Calls vtable function at Camera+0x248 offset (CameraLookatManager). Also increments a counter and sets dirty flag on `__DT_SYMTAB[0x493]`.

### OCULUS_SYNC (<addr in DB>)

**Packet format:** 0 bytes payload
**Behavior:** No-op handler that immediately returns success. Used as a server acknowledgment for Orb of Oculus (free camera mode) state synchronization.

## Helper Functions

| Address | Name | Description |
|---------|------|-------------|
| `<addr in DB>` | `jag::game::Camera::ProcessCameraReset` | Performs camera reset logic, returns completion status |
| `<addr in DB>` | Camera MoveTo helper | Sets camera movement target from coordinates |
| `<addr in DB>` | Camera LookAt helper | Sets camera lookat target from coordinates |

## Client Subsystem References

- `__DT_SYMTAB[0x491]` - Camera object (position, lookat, orientation, shake state)
- `__DT_SYMTAB[0x493]` - Camera dirty/update counter
- Return values: `<in Ghidra DB>` = success, `<in Ghidra DB>` = yield
