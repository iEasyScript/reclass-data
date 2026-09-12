# Updating Project X to a New Client Version

The exact, tested procedure for migrating the engine when Jagex ships a new RS3 NXT client
build (e.g. `949-1` → `949-4`). This is the operational checklist; the deep reference is
`re-resources/CROSS_VERSION_MIGRATION.md`.

The migration is driven by **`RS3ProjectXUpdater`** (a headless Ghidra script) via the
**`re-resources/run_updater.py`** runner. It auto-derives version-sensitive offsets from
reliable in-binary anchors, ports function names/prototypes/comments/data-labels, detects
**struct-offset drift**, disambiguates AMBIGUOUS sig matches via XREF fingerprints, and emits
copy-paste `Offsets.kt` / `DoActionOpcode.kt` fragments. Data types still go through the
existing `RS3DataTypeExporter/Importer`.

---

## 0. Prerequisites (once)

- The Ghidra build that owns the projects: `/home/trent/projects/ghidra/build/dist/ghidra_12.1_DEV`
  (export it as `GHIDRA` below). **Do not** use a different Ghidra version against these projects —
  it could try to upgrade them.
- The Ghidra project holding the program DBs: `--project-dir /home/trent/ghidra-proj`,
  `--project-name nxt-exe-2024-9-25`. Programs are named `rs2client.<version>` (e.g. `rs2client.948-5`).
- `analyzeHeadless` cannot open a project that's **open in the Ghidra GUI** (exclusive lock).
  - EXPORT and IMPORT **dry-run** are `-readOnly` and tolerate the GUI being open on a *different*
    program, but to be safe close the program you're targeting.
  - IMPORT **`--apply`** (the only step that writes the DB) requires the target program to be
    **CLOSED in the GUI**. The runner detects a lock failure and tells you.

```bash
export GHIDRA=/home/trent/projects/ghidra/build/dist/ghidra_12.1_DEV
export PROJ="--project-dir /home/trent/ghidra-proj --project-name nxt-exe-2024-9-25 --ghidra-home $GHIDRA"
export NEWBIN=/home/trent/.local/share/bolt-launcher/Jagex/launcher/rs2client   # the live installed client
```

---

## 1. Get the new binary into Ghidra

In the Ghidra GUI: import the new `rs2client` into the `nxt-exe-2024-9-25` project, run
auto-analysis, and name it `rs2client.<newver>` (e.g. `rs2client.949-4`). Then run the existing
auto-updater steps you already use (sig-match + DoAction + datatype import) — RS3ProjectXUpdater
complements them; it does not replace `RS3DataTypeExporter/Importer`.

Version is auto-detected from the binary's `RS2Engine-X-NXT-Y` string — you never type it.

The import can also be driven headlessly (`analyzeHeadless -import`), naming the program by staging
the binary under the desired program name. **The PE loader ignores `-loader-imagebase`**, so a
headless-imported `rs2client.exe` lands at its header base and every offset the updater would emit
becomes a VA. RS3ProjectXUpdater hard-fails on a non-zero base rather than emitting them; rebase
with `RS3SetImageBaseZero.java` (preserves analysis) and re-run. `RS3ProgramStats.java` prints the
base plus function/instruction counts, which is also the cheapest way to confirm auto-analysis
actually finished — an unanalyzed program produces a MISSING list that mimics real drift.

---

## 2. EXPORT from the OLD build (read-only)

Run once against the **previous** program (the fully-RE'd one, e.g. `rs2client.948-5`). This
writes a self-contained snapshot to `re-resources/updater/updater_data_<oldver>/`.

```bash
python3 re-resources/run_updater.py export --binary <old rs2client file> $PROJ \
  --program-name rs2client.<oldver>
```

Produces `updater_data_<oldver>/`: `functions.ndjson` (+prototypes, +caller/callee/string
fingerprints for disambiguation), `datalabels.ndjson`, `comments.ndjson`, `anchors.json`
(sig-stamped + self-resolved), `manifest.json`. The log prints each anchor's resolved value —
confirm they match the current `Offsets.kt` (self-test).

---

## 3. IMPORT into the NEW build — DRY RUN first (read-only, never writes the DB)

```bash
python3 re-resources/run_updater.py import --binary $NEWBIN $PROJ \
  --program-name rs2client.<newver>
```

Writes ONLY output files (no DB changes):
- `re-resources/updater/results_<newver>.json` — per-item: functions (FOUND/AMBIGUOUS/MISSING,
  with `xref-disambiguated` notes), data labels, anchors (located, old→new, `changed`).
- `re-resources/updater/offsets/offsets_<newver>.kt` — copy-paste `Offsets.kt` fragment:
  the **full `OFunctions` block** (all 37 function addresses, resolved from the sig-match — these
  move every build), then `OGlobal.CLIENT` + the struct-field anchor offsets, with a
  **`!!! DRIFT DETECTED`** banner listing any anchored offset whose value changed vs the previous
  build (e.g. a moved `ONPC.CURRENT_HP`). `UNRESOLVED` lines list anchors that need attention.
  Model: OFunctions/OGlobal are emitted in full every run; struct fields are drift-detected via
  anchors (stable struct offsets won't appear as changes; a real shift fires the banner).
- `re-resources/updater/offsets/DoActionOpcodes_<newver>.kt` — full copy-paste enum body.
  PLAYER_1..10 are already `2044..2053` (the +2000 fix is automatic and logged).

**Review the dry-run before applying.** Check: the DRIFT banner (act on any real changes), the
AMBIGUOUS list, and that resolved anchor values look sane.

---

## 4. IMPORT with `--apply` (writes the DB) — only after the dry-run looks right

Close `rs2client.<newver>` in the Ghidra GUI first (lock). Then:

```bash
python3 re-resources/run_updater.py import --apply --binary $NEWBIN $PROJ \
  --program-name rs2client.<newver>
```

This commits to the new program DB (inside one transaction; per-item failures are recorded, never
aborts): renames functions (full namespaces) + prototypes + comments, names data labels, names
located anchor functions. Re-open in the GUI to inspect.

**Run the data-type import BEFORE this step.** A prototype naming a type the new program does not
yet carry fails to parse and silently lands as a bare `undefined f()`, which looks like a successful
port in every counter the run prints. The tell is a prototype-string diff, not a missing name — so
compare prototype STRINGS in the acceptance test, and re-run `--apply` after importing types.

Anchors resolve by looking up *named* functions, and step 2 does the renaming, so a **dry run
cannot resolve most anchors** — a long `anchor-not-located` list in a dry run is expected and is not
drift. Judge anchors from the `--apply` results, and compare against whether the same anchor
resolved on the previous build before treating it as a regression.

Note `--apply` reads its OFunctions list from the baseline `updater_data_*/anchors.json`, not from
`anchor_registry.json` directly. Adding an entry to the registry therefore takes effect only after
an EXPORT regenerates that baseline.

---

## 5. Apply offsets to the engine

- Paste the relevant `const val`s from `offsets/offsets_<newver>.kt` into
  `client-plugin-engine/src/main/kotlin/com/projectx/game/nxt/Offsets.kt` (`OGlobal`, `OFunctions`, and any drifted
  struct-field offsets). **For any `*** CHANGED ***` line, update the value** and verify (these are the
  drift cases the whole tool exists to catch).
- Paste `offsets/DoActionOpcodes_<newver>.kt` into
  `client-plugin-engine/src/main/kotlin/com/projectx/game/nxt/DoActionOpcode.kt`.
- `cd client-plugin-engine && ./gradlew compileKotlin` — must pass.

---

## 6. Handle the residual (what the tool does NOT fully auto-resolve)

The tool resolves the large majority automatically. Two residual buckets need a human:

- **Remaining AMBIGUOUS functions** (typically ~15–20): near-identical siblings whose callers are
  unnamed and that share no unique string (e.g. `OnLeftButtonDown`/`OnLeftButtonUp`,
  `TcpConnectionMessage::Init`, `BindHandlers` clones). Resolve with a **discriminating sig-scan**
  (§5 of `CROSS_VERSION_MIGRATION.md`): the byte that differs between the twins kept literal
  (e.g. the `c6 05 <disp> 01` vs `00` flag write for the button pair), or a caller fingerprint.
- **UNRESOLVED anchors**: any offset listed `UNRESOLVED` in `offsets_<newver>.kt` lacks a working
  recipe. Fix by editing `re-resources/updater/anchor_registry.json` (declarative — no code change):
  point the anchor at a reliable function and write its extraction recipe (DSL documented at the top
  of that file). Validate by re-running EXPORT against the *old* build — the anchor must reproduce the
  known `Offsets.kt` value before you trust it.
  - As of 948-5: **all 37 `OFunctions` auto-resolve** (37/37) + `OGlobal.CLIENT`; working struct-field
    anchors (8): `ONPC.CURRENT_HP`/`MAX_HP`/`SHOW_AS_IMPORTANT`, `OWorld.VIEW_MATRIX`/`PROJECTION_MATRIX`/
    `HEIGHT_MAP`/`LINK_MAP`, `OMapSquare.CHUNK_SIZE_FLAG`.
  - TODO anchors (need better anchor functions): `OEntity.ANIMATION_ID`, `OPathingEntity.HITMARKS_AND_HEADBARS`,
    `OClient.NPC_MANAGER`, `OMainLogicManager.STAT_TABLE`. And the remaining struct-field offsets from the
    request list (the rest of `OClient`, `OWorld`, `OMapSquare`, `OMainLogicManager`, `OEntity`, `ONPC`,
    `OPathingEntity`) are not yet anchored — add them to `anchor_registry.json` as needed. Struct offsets
    are usually stable across sub-revs, so the priority is OFunctions (auto) + drift-detection on the
    load-bearing fields (anchored).

---

## 7. Layout growth, engine windows, and the end-to-end gate (learned on 949-5 -> 950-1)

Porting every offset is not the finish line. On 950-1 every table value was right and scripts still
did nothing: the interface-list pointer had moved one slot outward inside the interface manager, and
the engine wrapper read that object through a window sized by hand for the old layout. Every read
through it threw, the script loop swallowed the exception, and the user saw a bot that started and
sat there. No table-parity check can see that class of bug, because the bug lives in a size literal
in wrapper source, not in a value.

What now prevents it, and what you must still do on update day:

- **Windows come from the table, and wrappers size themselves.** Every wrapper widens whatever
  segment it is handed to its own `OffsetObject.extent`, computed from the object's last declared
  field plus slack, so a ported offset resizes the window with it and a caller's window can never be
  too small (the second 950-1 hit was a 24-byte entity handle whose type byte had moved to 32).
  `WindowExtentTest` fails the engine build on any hand-sized object window, so do not add one;
  declare the object in `Offsets.kt` and let the wrapper size itself.
- **Read the growth report.** The import dry run ends with a `LAYOUT GREW` list per platform: every
  object whose last field moved outward. Each is a place where a wrapper that reads an inline
  structure past the last declared field, or a read the extent does not model, can still break.
  Check those wrappers before declaring parity.
- **Run one script end to end before parity is declared.** A script that touches interfaces, scenery
  and an NPC, on each platform you ship. The DoAction table, the interface path and the scene scan
  are exercised by nothing else, and a silent no-op only shows up when something actually runs. The
  in-process MCP (`start_script`, `list_open_interfaces`, `list_locations`, `read_logs`) makes this a
  two-minute check; `read_logs` with `errors_only` shows an exception loop the overlay hides.
- **A start failure must name its cause.** The scripts tab prints the constructor's real exception,
  not the reflective wrapper's null message. If it ever prints `null` again, that is a bug in the
  tab, not in the script.

## Adding a new auto-detected offset

Edit `re-resources/updater/anchor_registry.json`: add an anchor entry (id, target object/field, the
anchor function, an `extract` recipe in the DSL, and a `old_value` seeded from current `Offsets.kt`).
Re-run EXPORT against the old build; if it self-resolves to the seed value, it's good. No Java changes
needed. The validated `get_npc_stat` → `ONPC.CURRENT_HP/MAX_HP` entry is the reference template.

---

## Safety notes

- IMPORT defaults to **dry-run**; only `--apply` mutates, and the runner adds `-readOnly` to every
  non-apply run as a hard guard. Uses `-process` (existing program), never `-import`.
- Compile the script after edits: `javac -cp "$(find $GHIDRA -name '*.jar'|tr '\n' ':')" -d /tmp/x re-resources/ghidra-scripts/RS3ProjectXUpdater.java` (0 errors expected; deprecation warnings on `CodeUnit.*_COMMENT` are benign).
- The 5 legacy `RS3*.java` scripts are kept as fallback and still used for data types.
