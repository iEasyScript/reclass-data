# Project X — Documentation Index

The unified reverse-engineering and system documentation for the RS3 NXT client, the Project X
server, the Rust launcher, and the Project X injection engine.

These docs live in the **`re-resources` submodule** (`gitlab:iEasyScript/reclass-data`) and are
reachable from the monorepo through the `docs/` symlink. One knowledge base, shared by the server and
the engine.

> ⛔ **No addresses, offsets or packet opcodes belong in these files.** Per-build facts live in the
> Ghidra DB, in the updater's generated migration data, and in the engine's `resources/offsets/*.json`
> tables. Documentation carries durable, cross-revision *system* knowledge: how a subsystem works,
> its lifecycle, its invariants, and why it is shaped the way it is. Some older files below still
> carry a revision tag in their title — treat those tables as historical and confirm against the DB.

## Contents

- [Cache and content](#cache-and-content)
- [Clientscripts (CS2)](#clientscripts-cs2)
- [Network protocol](#network-protocol)
- [Client binary and patching](#client-binary-and-patching)
- [Reverse-engineering methodology](#reverse-engineering-methodology)
- [Engine](#engine)
- [Mobile (Android)](#mobile-android)
- [Related resources](#related-resources)

---

## Cache and content

| Document | What it covers |
|---|---|
| [cache/cache-update-flow.md](cache/cache-update-flow.md) | How a Jagex content update propagates into the project, how we measure what it changed, and what it can break |
| [cache/decode-coverage.md](cache/decode-coverage.md) | Living ledger of how much of the JS5 cache the `:core` library can actually read |
| [cache/master-index-format.md](cache/master-index-format.md) | The NXT master index (version table) — structure and signing |
| [cache/lzma-compression.md](cache/lzma-compression.md) | LZMA containers in JS5 |
| [cache/memorycache-write-path.md](cache/memorycache-write-path.md) | `Js5MemoryCache` write path |
| [cache/mapsv2-format.md](cache/mapsv2-format.md) | MAPSV2 archive structure |
| [cache/gameval_index67.md](cache/gameval_index67.md) | Index 67 — the gameval / RSCM id ↔ dev-name tables |
| [cache/music-http.md](cache/music-http.md) | JS5 over HTTP — music and bulk data |
| [cache/data-integrity-analysis.md](cache/data-integrity-analysis.md) | Cache data integrity analysis |

Related tooling: the `cache-update-check` and `gameval-beta-check` skills.

## Clientscripts (CS2)

| Document | What it covers |
|---|---|
| [cache/clientscript-cs2.md](cache/clientscript-cs2.md) | The format itself — container layout, operand widths, name provenance, the traps it sets, and the fidelity contract |
| [cache/cs2-toolchain.md](cache/cs2-toolchain.md) | How to *run* `:tools:cs2` — requirements, every sub-command, the opcode table, editing and hot reload, troubleshooting |

Related tooling: the `cs2-decompile` skill.

## Network protocol

Start at **[net/README.md](net/README.md)** — the protocol index, which covers the packet class,
crypto, transport, framing, login, JS5, and the per-category ClientProt/ServerProt handler docs.

| Foundation | |
|---|---|
| [net/packet-class.md](net/packet-class.md) | `jag::Packet` — layout, read/write methods, naming conventions |
| [net/crypto.md](net/crypto.md) | ISAAC, XTEA, RSA — algorithms and key management |
| [net/transport.md](net/transport.md) | ClientStream, ServerConnection, ConnectionManager |
| [net/framing.md](net/framing.md) | Packet framing and dispatch |
| [net/buffer-transform-patterns.md](net/buffer-transform-patterns.md) | Buffer transform ↔ disassembly pattern table |

| Login and lobby | |
|---|---|
| [net/login-protocol.md](net/login-protocol.md) | The login state machine end to end |
| [net/desktop-login-descriptor.md](net/desktop-login-descriptor.md) | The desktop login descriptor's XTEA tail |
| [net/lobby-login-data.md](net/lobby-login-data.md) | Lobby login data format |
| [net/lobby-state-init.md](net/lobby-state-init.md) | Lobby state initialisation |
| [net/tcpin-isaac-decoding.md](net/tcpin-isaac-decoding.md) | `TcpIn` ISAAC opcode decoding — the sniffer's read point |

| JS5 | |
|---|---|
| [net/js5-protocol.md](net/js5-protocol.md) | Architecture overview |
| [net/js5-tcp-handshake.md](net/js5-tcp-handshake.md) · [net/js5-response-format.md](net/js5-response-format.md) | Handshake and response framing |
| [net/js5-file-request-flow.md](net/js5-file-request-flow.md) · [net/js5-index-download-crc-flow.md](net/js5-index-download-crc-flow.md) | Request flow, disk-cache misses, CRC acceptance |
| [net/js5-post-master-index-flow.md](net/js5-post-master-index-flow.md) · [net/js5-handle-download-result.md](net/js5-handle-download-result.md) | What the client does after the master index |
| [net/js5-http-group-download.md](net/js5-http-group-download.md) | Group download over HTTP |

| Game systems | |
|---|---|
| [net/social.md](net/social.md) · [net/clans.md](net/clans.md) | Friends, ignore, chat, and the clan system |
| [net/world-data.md](net/world-data.md) · [net/worldmap-worldarea-system.md](net/worldmap-worldarea-system.md) | World data and the WorldArea/worldmap system |
| [net/player-rights-dev-features.md](net/player-rights-dev-features.md) | Player rights and dev-feature gating |
| [net/serverprot/](net/serverprot/) · [net/clientprot/](net/clientprot/) | Per-category handler documentation |

## Client binary and patching

| Document | What it covers |
|---|---|
| [binary/jav-config.md](binary/jav-config.md) | The `jav_config.ws` format and how the client consumes it |
| [binary/client-binary-download.md](binary/client-binary-download.md) | How the per-OS client binaries are fetched from the CDN |
| [binary/rs2client-rsa-keys.md](binary/rs2client-rsa-keys.md) · [binary/jagex-rsa-keys.md](binary/jagex-rsa-keys.md) | Where the RSA moduli live and how they are parsed |
| [binary/rs3linux-patch-targets.md](binary/rs3linux-patch-targets.md) | Linux `LD_PRELOAD` patch targets |
| [binary/patch-targets-macos.md](binary/patch-targets-macos.md) | macOS Mach-O patch targets |
| [binary/input-layer.md](binary/input-layer.md) | `jag::input` — the client's own input layer, below SDL/Win32/Cocoa |

## Reverse-engineering methodology

| Document | What it covers |
|---|---|
| [re-methodology/UPDATING.md](re-methodology/UPDATING.md) | The update-day process for moving to a new client build |
| [re-methodology/AUTO_UPDATER.md](re-methodology/AUTO_UPDATER.md) | The offset auto-updater — how it relocates functions and data across builds |
| [../CROSS_VERSION_MIGRATION.md](../CROSS_VERSION_MIGRATION.md) | Cross-build porting guide (submodule root) |

Related: the `rs3-update-migrator` agent and the `/re-*` commands.

## Engine

| Document | What it covers |
|---|---|
| [engine/engine-CLAUDE.md](engine/engine-CLAUDE.md) | Project X engine guidelines and the `Offsets.kt` cross-reference |

## Mobile (Android)

Start at **[mobile/README.md](mobile/README.md)** — the mobile index, with its own confidence-tag
convention. It covers the APK and native library, the `launchurl` startup-argument channel, the
config redirect, the login and JS5 handshakes, RSA key locations, packet-capture hook points, and
cross-architecture porting. Open questions are tracked in
[mobile/OPEN-QUESTIONS.md](mobile/OPEN-QUESTIONS.md).

⚠️ Desktop is a different sub-revision from mobile. The protocol and cache formats match; addresses
never port across.

## Related resources

Outside `docs/`, in the same submodule:

| Path | Contents |
|---|---|
| `re-resources/symbols/` | Symbol dumps from the outdated reference binary — namespace discovery and pattern matching only |
| `re-resources/gamevals/` | Cache id ↔ dev-name dictionaries for every config type, plus `gameval.py` |
| `re-resources/cs2/` | Per-build CS2 opcode table exports and cross-build maps |
| `re-resources/updater/`, `sigs-results/` | The offset auto-updater and its migration output |
| `re-resources/rstypes.rcnet`, `*.gzf` | ReClass types and compressed client-binary archives |

In the monorepo: [`CLAUDE.md`](../CLAUDE.md) for architecture and the agent roster,
[`README.md`](../README.md) for setup.
