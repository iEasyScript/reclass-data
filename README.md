# Reclass-Data — Unified RE Knowledge Hub

This repository is the **shared reverse-engineering knowledge hub** for the
`project-x` monorepo (consumed there as a git submodule). It is the single
source of truth for RE types, protocol/cache/binary documentation, symbol dumps,
cache-id dictionaries, and the live CS2 content dumps — shared by both the Project X
server and the Project X injection engine.

> It remains its **own git repository** (origin: `gitlab:iEasyScript/reclass-data`)
> and is included elsewhere as a submodule. The original ReClass type data is unchanged;
> the documentation/symbol/gameval aggregation below was added **additively** (existing
> files kept in place so the offset-updater's relative paths keep working).

## Layout

```
.
├── docs/                       # Unified documentation (aggregated from both projects)
│   ├── net/                    # Networking protocol + packet docs (login, JS5, world, social, framing)
│   ├── cache/                  # JS5 / cache format (master index, LZMA, SQLite, write path)
│   ├── binary/                 # Client patch targets, RSA keys, memory layout / offsets
│   ├── re-methodology/         # UPDATING.md, AUTO_UPDATER.md (cross-version update workflow)
│   ├── engine/                 # Project X engine offset notes (engine-CLAUDE.md, Offsets.kt cross-ref)
│   └── mobile/                 # RS3 Android client (AArch64) RE — apk/net/binary + cross-arch porting
├── symbols/                    # RE symbol dumps (functions.txt, parsed_functions.txt, *_handlers.txt, …)
├── gamevals/                   # Cache id ↔ dev-name dictionaries (37 types) + gameval.py helper
│
│   # --- original ReClass-Data content (unchanged, relative paths preserved) ---
├── rstypes.rcnet               # ReClass type definitions
├── *.gzf                       # compressed client binaries (939-1 … 948-5)
├── anchor_registry.json        # in-binary anchors for the offset auto-updater
├── run_updater.py / update_offsets.py
├── updater/  ghidra-scripts/  sigs-results/  948-2-phase4a/
├── clientprot_946-5_opcode_table.json  serverprot_946-5_opcode_table.json
├── CROSS_VERSION_MIGRATION.md  reshuffle_verification.md   # RE migration guides (root-level)
└── cs2_symbols.txt
```

## Sub-resources

- **`gamevals/`** — every cache config id → original RuneScape dev name
  (`npc`/`obj`/`loc`/`varbit`/`var_player`/`param`/`component`/`enum`/`struct`/`seq`/…).
  Decode any bare numeric id from decompilation, memory, hooks, or CS2 scripts:
  `./gamevals/gameval.py npc 7987`, `loc -s yew`, `-s magic_logs`.
- **`symbols/`** — flat symbol/handler dumps from an outdated reference build. Useful for
  namespace/class discovery and pattern matching only; **addresses, parameter types, enum
  values, and offsets do NOT match the current target binary.** Never copy concrete data.
- **`docs/mobile/`** — RE knowledge for the **RS3 Android client** (`liblibs.hal.system.rs2client.so`,
  AArch64) — same NXT engine as desktop, recompiled. APK structure, the `launchurl` config redirect,
  the login/JS5 handshake, RSA key locations, and Frida packet-capture hook points. Cross-references the
  desktop docs at the topical roots (desktop 949-4, mobile 949-3 — same major, different sub-revision). Runnable
  tooling lives in the monorepo root `mobile/`; android binaries in `data/client/android/`; owned by the
  `mobile-reverse-engineer` agent. Start at `docs/mobile/README.md`.

## Cloning

The third-party `cs2-dumps` nested submodule was removed — the consuming project generates
strictly better dumps itself (`:tools:cs2 decompile-all`, `:tools:cacheUnpack`). Clone
recursively anyway for the monorepo's other submodules:

```
git clone --recursive <monorepo-url>
# or, after a plain clone:
git submodule update --init --recursive
```
