# Cross-Version Client Migration Playbook

How to migrate Project X from one RS3 NXT client build to the next (e.g. 948-2-2 → 948-5).
Jagex ships frequently; most bumps are **sub-revisions** (code relayout, identical logic). This is the
canonical procedure so it does not have to be re-explained each time. Keep it current — when you learn
something new during a migration, add it here.

---

## 0. What the auto-updater DOES and DOES NOT do (read first)

The auto-updater (`re-resources/update_offsets.py` + the `RS3*.java` Ghidra scripts) has a **narrow** scope:

**It DOES:**
- Sig-match every named function from the OLD build against the NEW binary and **rename the matches**
  in the NEW Ghidra DB. Results land in `re-resources/sigs-results/results_<ver>.ndjson`
  (`FOUND` / `AMBIGUOUS` / `MISSING`) paired line-for-line with `sigs_<prev>.ndjson`.
- Update **`DoActionOpcode.kt`** (the only Kotlin file it touches).
- Import data types via `RS3DataTypeImporter.java` from `datatypes_<ver>.json` (structs/enums copied 1:1).

**It does NOT (you must do these by hand):**
- Update **`Offsets.kt`** — `OGlobal` + `OFunctions` addresses. **THIS IS THE #1 MANUAL TASK.**
- Update any **other** hardcoded address in Kotlin (e.g. `InputRecorder.kt` g_mouse globals). DoActionOpcode
  is the *only* auto-updated Kotlin file.
- Port **function prototypes** — renamed functions REVERT to `param_1/param_2`, `undefined` return,
  unknown calling convention. The name survives; the signature is lost.
- Port **decompiler/disassembly comments** — lost on rename.
- Identify **AMBIGUOUS / MISSING** functions — left as `FUN_`.
- **Validate** the imported structs — the importer copies offsets blindly and does NOT verify them
  against the new binary.

So a full migration = run the auto-updater, then manually: Offsets.kt → other hardcoded offsets →
AMBIGUOUS/MISSING renames → prototype port → comment port → struct validation → compile.

---

## 1. The three Ghidra binaries

- **`rs2client.<new>`** (e.g. `rs2client.948-5`) — TARGET. ALL writes go here.
- **`rs2client.<old>`** (e.g. `rs2client.948-2-2`) — previous build, fully reverse-engineered.
  READ-ONLY **source of truth** for names, prototypes, comments. Pass `binary_name="rs2client.<old>"`.
- **`librs2client.so`** — ancient unstripped reference. Pattern-match ONLY; never copy concrete data. Usually irrelevant for a sub-rev migration.

`list_binaries` at session start; `select_binary("rs2client.<new>")` so writes default to the target.

> **⚠️ The two `rs2client` instances can SWAP PORTS mid-session.** Both have Binary name `rs2client`
> (differing only by the Ghidra import Name). The bridge caches a name→port map; if Ghidra restarts or
> re-registers, the physical ports can swap (e.g. 8081 and 8082 trade places) while the cache stays stale,
> which **silently reverses `binary_name` routing** — your "write to 948-5" then lands in 948-2-2.
> Defenses: (1) run `discover_ghidra_instances` to refresh the cache; (2) before a write wave, VERIFY
> routing with a version-definitive address, e.g. `get_function_by_address("0x004900d0",
> binary_name="rs2client.<new>")` must be the NEW build's SetMainState and the same addr must be "no
> function" in the OLD build; (3) re-verify periodically during long agent runs. Function renames are
> NOT idempotent across a mis-route (different addresses per build → corruption); data-label renames ARE
> near-idempotent (same name@same address in both builds).

---

## 2. Sub-revision invariants (verified on 948-2-2 → 948-5)

These hold for sub-revision bumps and make the migration tractable. **Re-verify, don't assume**, but expect:

- **The `.data`/`.bss` segment does NOT move.** Global data labels keep their absolute addresses.
  Verified by disassembling the same function in both builds and seeing identical `[0x015…]` operands
  (e.g. `g_client = 0x015bf1f8` unchanged; float mouse globals `0x015b9734/8` unchanged;
  `0x01390dc0`, `0x015d4db8` unchanged). ⇒ `OGlobal.CLIENT` and `InputRecorder.kt`'s g_mouse globals
  (`0x016e7bb4/b8/be`) typically **do not change**.
- **Only `.text` (code) shifts**, and it shifts **in uniform blocks**. Within a region the delta is
  constant (e.g. the whole CS2 opcode block 0x2c8xxx–0x37axxx shifted **+0x1f0**; the input block
  shifted −0x8c0; SendClientMessage region +0x310). Different regions have different deltas.
- **Struct field offsets are unchanged** (network protocol / opcodes identical). So `Offsets.kt` struct
  objects (`OClient`, `ONPC`, `OEntity`, `OServerConnection`, `OWorld`, …) need NO edits — only
  `OGlobal` + `OFunctions` (absolute addresses) do.
- Call/jmp targets, RIP-relative string-table refs, and rodata `DAT_` addresses all shift with the code;
  this is expected and is **not** a mismatch signal when verifying a function identity.

---

## 3. Updating `Offsets.kt` (the primary manual task)

`Offsets.kt` has exactly two version-sensitive objects: **`OGlobal`** (data labels) and **`OFunctions`**
(function entry points). Everything else is struct field offsets (stable — leave alone).

**Build the old→new map mechanically.** `results_<new>.ndjson` and `sigs_<prev>.ndjson` are **parallel
files** (same order, same names, line N ↔ line N). Join them by line index to get, per function:
`full_name = namespace::name`, `orig_addr` (old), `status`, `new_addr`. Then for each `OFunctions`
entry, look up its current address as `orig_addr` → read the joined `new_addr`. (Script pattern lives in
the migration session history; ~30 lines of Python.)

- `FOUND` entries → take `new_addr` directly.
- `AMBIGUOUS` / `MISSING` `OFunctions` entries → resolve by sig-scan (§5). On 948-5 these were the 2
  left-button handlers, the 2 `TcpConnectionMessage` Init variants, and `SendClientMessage`.
- `OGlobal.CLIENT` is a data label (not in the function sig DB) → confirm via §2 (disassemble a function
  that reads it in both builds; the `[0x…]` operand is the address). It has been unchanged across sub-revs.

Keep the per-line comment style `//<new> (was 0x<old> in <prev>) — <semantic note>` and preserve the
semantic notes (they encode how ambiguous ones were disambiguated).

After editing: `cd client-plugin-engine && ./gradlew compileKotlin` must succeed.

---

## 4. Other hardcoded offsets in the engine

`DoActionOpcode.kt` is auto-updated — skip it. Everything else with a binary address is manual. To find
them: `grep -rnE "0x0(0[0-9a-fA-F]{4,5}|1[3-6][0-9a-fA-F]{4,5})" client-plugin-engine/src/main/kotlin` and ignore
comments + obvious non-addresses (colors, GL enums, collision flags). As of 948-5 the only LIVE
(non-comment) address constants outside Offsets.kt/DoActionOpcode.kt are the g_mouse globals in
`InputRecorder.kt` — and those are in the stable `.data` segment (§2), so they don't change on a sub-rev.

**Never hardcode an address anywhere — not even in commented-out/dead code.** If a hook needs an address,
add it to `OFunctions` and reference `@Hook(OFunctions.<NAME>)`. (This is why the dead `GetInterface`
hook's `0x5944b0` literal was removed.)

---

## 5. Identifying AMBIGUOUS / MISSING functions (sig-scan playbook)

`AMBIGUOUS` = the normalized signature matched multiple sites (near-identical sibling functions).
`MISSING` = relocated past the matcher's tolerance, or verification failed. Procedure per function
(this is what the `ghidra-reverse-engineer` agents do — fan them out in batches of ~25):

1. **Read the OLD function**: `get_function_signature`, `disassemble_function`,
   `decompile_function_by_address` — all with `binary_name="rs2client.<old>"`. Capture the entry comment.
2. **Predict the new address via a FOUND-neighbor anchor.** Find the nearest FOUND function below it in
   the OLD build; `predicted_new = below_new + (old_addr − below_old)`. Because code shifts in uniform
   blocks (§2) this is usually **exact**. Verify with `get_function_by_address(predicted, new)` (unnamed
   `FUN_`, matching body size) + a structural disassembly compare.
3. **Disambiguate siblings with a DISCRIMINATING sig-scan.** The auto-updater failed because it wildcards
   *all* immediates, making siblings identical. You do the opposite: build a ~12–24-byte pattern, wildcard
   only the relocated immediates (4 bytes after `E8`/`E9`; RIP-disp after `48 8b 05`/`48 8d 05`/`48 8b 0d`/
   `48 8d 0d`), and **keep LITERAL the byte(s) that distinguish this function from its twin** — the unique
   struct offset, the unique constant, the `1` vs `0` flag write, etc. `search_memory_pattern(..., new)`
   must return a UNIQUE hit at the predicted entry.
4. **Decisive shortcuts that worked on 948-5:**
   - **CS2 opcode handlers** (`jag::opcode::*`, `cc_if_*`) embed a self-naming `CreateOpcodeError("<exact
     name>")` string the decompiler inlines — one `decompile_function_by_address` on the predicted addr
     confirms identity verbatim. Secondary check: the component type-tag constant
     (`cVar != '\xNN'`: 5=modelgroup, 7=cutscenelayer, 9=check, 0x0a=list, 0x0d=combo, 0x0f=carousel,
     0x10=pagedcarousel, 0x11=radiogroup, 0x12=crmview, 0x15=grid, 0x16=pagedlayer).
   - **Byte-identical duplicates** (e.g. `SendClientMessage` vs its login-only twin; `TcpConnectionMessage::Init`
     vs `InitIncoming`) differ ONLY in a call target — disambiguate by **caller set**: `get_xrefs_to` each
     candidate in both builds and match the caller fingerprint (the real SendClientMessage has ~80 general
     senders; the twin has 3 login callers. InitIncoming is the one called by `TcpIn`; Init by `CreatePacket`).
   - **`search_memory_pattern` quirk:** RIP-relative patterns (`48 8d 05 ?? ?? ?? ??`) match reliably;
     embedded **imm64 constants** (e.g. magic divisors) often do NOT match even when present. Don't rely on
     imm64 bytes in a pattern — use the predicted address + disassembly identity + the inlined string instead.
5. **Commit** (only at ABSOLUTE certainty — a wrong rename is far worse than leaving `FUN_`):
   `rename_function_by_address(new, "<full::namespace::name>")`, then `set_function_prototype` from the OLD
   signature, then port the entry comment. If not certain, leave `FUN_` + a `HYPOTHESIS` comment and report it.

---

## 6. Porting prototypes + comments for the FOUND functions

The auto-updater renamed the FOUND functions but reverted their signatures and dropped their comments.
For 1:1 parity, port both. This is **mechanical** (identity already proven by the sig match) — use the
old→new join map and fan out agents over address ranges:
- `get_function_signature(old, "rs2client.<old>")` → `set_function_prototype(new, <proto>)` (carry param
  names/types, return type, and calling convention — many are `__stdcall`).
- `decompile_function_by_address(old, "rs2client.<old>")` → read the entry `/* */` comment →
  `set_decompiler_comment(new, …)`. **Strip stale version-specific addresses** from ported comments
  (old sibling addresses, "string at 0x…", "matches 947-3 @ 0x…") so they don't mislead in the new build.
- `set_decompiler_comment` occasionally returns a transient "Failed to set comment" — retry once.

---

## 7. Porting named data labels (globals, tables, vtables) — DON'T FORGET THIS

The auto-updater ports function names; the datatype importer ports struct/enum **types**. **Neither ports
named DATA LABELS** — global variables/pointers, tables, vtables, named constants. So after a migration the
new build is missing things like `jag::Client::Client` (the client global), `jag::g_highlightCategoryTable`,
`jag::g_highlightBaseAlpha0/1`, `jag::input::Input::g_mouseX/Y/g_leftButtonState`, vftables, etc. This is a
required parity step, easy to overlook because functions look "done".

- **Enumerate via `list_namespace_contents`, NOT `list_data_items`.** For each namespace in the OLD build,
  `list_namespace_contents("<ns>")` and take the `[Label]` entries (data); `[Function]` are already handled.
  `list_data_items` shows only the **leaf** name (it strips the namespace), so porting from it produces bare
  Global names — wrong, and it collides with the namespaced version. Use `list_data_items` only as a catch-all
  for genuinely Global (un-namespaced) labels, and dedupe against the namespaced pass.
- **Most game data lives as struct TYPES, not labels.** The `jag::game::*` type classes (ObjType, NPCType,
  LocType, …) carry their data in the DTM as structs — they have **zero** `[Label]` symbols. The named data
  labels cluster in top-level `jag`, `jag::Client`, `jag::input::Input`, `jag::HintArrow*`, `jag::LoginManager`, etc.
- **Port to the SAME address** (data segment is address-stable, §2): `rename_data("<addr>", "<ns>::<name>",
  binary_name="rs2client.<new>")`. Full namespace path (rename_data creates the hierarchy like rename_function).
- **EXCEPTION — `.rodata` string constants can shift** even when `.data`/`.bss` doesn't. E.g.
  `RSA_LOGIN_MODULUS_HEX` moved `0x0104a428` → `0x0104a740` (+0x318). If a label doesn't appear under its
  namespace after a same-address rename (the rename was a silent no-op), find the new address by
  cross-referencing the identical referencing instruction (disassemble the byte-identical accessor function
  in both builds and read the operand), then rename there.
- Skip auto/default names: `DAT_*`, `PTR_*`, `LAB_*`, `s_*`, `u_*`, `unk_*`, `switchD_*`, `caseD_*`, `Elf64_*`,
  `__DT_*`, `(unnamed)`, libc/import symbols (`stdout`, `recvfrom`, …).
- Fan out by namespace slice if large; data-label porting is near-idempotent so concurrent agents are safe,
  but make ONE pass authoritative for namespaced labels to avoid the leaf-vs-namespaced clobber described above.

## 8. Validating the imported structs

`RS3DataTypeImporter` copies struct/enum layouts 1:1 from `datatypes_<ver>.json` but **does NOT verify the
offsets against the new binary**. Since struct offsets are stable on sub-revs (§2) they are usually correct,
but validate:
- Cross-check the imported structs against `client-plugin-engine/.../Offsets.kt` (the engine offsets are the verified
  ground truth) — every struct field should match its `O*` offset object.
- Spot-check the load-bearing structs (`Client`, `Entity`, `NPC`, `ServerConnection`, `InterfaceComponent`,
  `MapSquare`, `World`) by decompiling a known reader/writer in the NEW binary and confirming it accesses
  the documented offsets. On a MAJOR bump (not a sub-rev), expect real drift (see the 948-2 `OMapSquare`
  +60KB inlining and `OWorld` non-uniform shift) and re-derive.
- `get_data_type("<name>", "rs2client.<new>")` shows whether a struct imported with its fields + comments.

---

## 9. Migration checklist

0. `discover_ghidra_instances` + **verify `binary_name` routing** (§1 warning) before any writes.
1. Load new binary in Ghidra; run the auto-updater (sig match + DoActionOpcode + datatype import).
2. Join `results_<new>.ndjson` ↔ `sigs_<prev>.ndjson`; build the old→new map.
3. **Offsets.kt**: update `OFunctions` (FOUND from map; AMBIGUOUS/MISSING via §5) + verify `OGlobal`.
4. Sweep engine for other hardcoded live addresses (§4); update if any (none expected on a sub-rev).
5. Rename all AMBIGUOUS/MISSING functions (§5), full namespaces, + prototypes + comments.
6. Port prototypes + comments for the FOUND functions (§6).
7. **Port named data labels** (§7) — globals/tables/vtables; the auto-updater skips them, easy to forget.
8. Validate imported structs (§8); fix any drift in Ghidra + Offsets.kt + Kotlin together (three-way sync).
9. Feed every newly-relocated KEY function back into the auto-updater signature DB so the next migration
   relocates it automatically (especially hook entry points, anchors, packet handlers).
10. `cd client-plugin-engine && ./gradlew compileKotlin` — must pass.
11. Record the new active version + deltas in the migration memory; update this playbook with anything new.

## 10. RS3ProjectXUpdater (new consolidated tool — supersedes the manual steps above)

`re-resources/ghidra-scripts/RS3ProjectXUpdater.java` + `re-resources/run_updater.py` collapse §3/§5/§6/§7 +
struct-offset *validation* into one headless export/import pair, and add **automatic struct-offset drift
detection** (the thing the manual flow could never do — see the ONPC HP motivation). The 5 legacy scripts are
KEPT (datatypes still go through `RS3DataTypeExporter/Importer`; everything else via the new tool).

- **The core asset:** `re-resources/updater/anchor_registry.json` — declarative anchors + a structural
  extraction-recipe DSL. Each offset is DERIVED from a reliable in-binary anchor every build, so a changed
  offset is flagged automatically. Add new offsets by editing this JSON (no code change). The `get_npc_stat`
  anchor (NPC CURRENT_HP/MAX_HP) is the validated template.
- **Run (headless, version auto-detected):**
  - EXPORT against the OLD build: `./run_updater.py export --binary <old> --project-dir <dir> --project-name <name> [--program-name <prog>]` → writes `re-resources/updater/updater_data_<ver>/` (functions+prototypes, datalabels, comments, sig-stamped anchors, manifest).
  - IMPORT against the NEW build, **dry-run first** (default, read-only — never writes the DB): `./run_updater.py import --binary <new> --project-dir <dir> --project-name <name>` → writes `updater/results_<ver>.json`, `updater/offsets/offsets_<ver>.kt` (with a DRIFT banner for any changed offset), `updater/offsets/DoActionOpcodes_<ver>.kt`.
  - Only when the dry-run looks right: `./run_updater.py import --apply …` to commit renames/prototypes/comments/labels/anchor-naming. **The program must be CLOSED in the Ghidra GUI for --apply** (exclusive lock; the runner detects and reports a lock failure).
- **Safety:** import defaults to dry-run; `--apply` is the only path that mutates, inside one transaction; the runner adds `-readOnly` on every non-apply run as a hard guard. Uses `-process` (existing program), never `-import`.
- **DoAction:** emits `DoActionOpcodes_<ver>.kt` with PLAYER_1..10 already at 2044..2053 (the +2000 fix is data-driven and logged — no manual edit). Root cause: the legacy `addDoAction(44, …)` single-arg form made key==output==44, dropping the +2000.
- **Status:** authored this session; NOT yet compiled in Ghidra. Validate by: compile in Ghidra Script Manager, then EXPORT 948-5 → IMPORT (dry-run) against 948-5 → every anchor must report `changed:false` and reproduce the `Offsets.kt` value (self-test). Then trust it on the next real bump.
