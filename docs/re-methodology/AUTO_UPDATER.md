We have intel that the offsets for CURRENT_HP and MAX_HP changed for NPCs. Did you manage to find this? We need to plan out a comprehensive update to our offset exporter script that can be ran after we run the auto-updater. The offset exporter should be able to identify reliable locations that offets such as these live and be able to detect changes in these structures reliably. I'll give you a list of offsets that should be automatically detected given absurdly reliable patterns through our offset exporter script.

Current flow:
  1: I use RS3DoActionUpdater to update DoActionOpcodes.kt manually.
  2: I have to change all player options to add 2000 to each opcode for some reason (not sure why the updater is getting the wrong value)
  3: I use RS3SignatureUpdater to dump a signature list of the previous binary manually.
  4: I use RS3SignatureUpdater to import and attempt to identify as many automatic functions as possible (doesn't find fields like the client pointe automatically which is annoying)
  5: I use RS3DataTypeExporter to export data types and then RS3DataTypeImporter to import them into the new binary (with likely incorrect offsets for some structs since new binary changes)
  6: I then have to tell you to identify manually all the signature updater failures and find them which is okay to a degree (outside of the common ones that fail such as StatUpdate and ClientProt stuff)

  Note: DETECTED_VERSION in the below should be an automatically detected and parsed version number from the binary the script is being ran against.

  Ideal flow:
  1: I use a newly created RS3ProjectXUpdater against the old binary to export a file that contains signatures from the previous binary and all functions/fields that are within the jag/eastl/ref_counter_base namespaces.
    - ~/projects/iEasyScript/re-resources/updater/updater_data_DETECTED_VERSION.json
  3: The updater_data_DETECTED_VERSION.json should be a large multifile that contains ALL metadata required including lots of the comment data and where it should belong. It should contain data type information as well to be directly imported. As well as locations for the various reliable patterns/signatures for spots we identify to locate sub-offsets for structs.
  4: I use the file from the RS3ProjectXUpdater script in import mode against the new binary to identify everything and it should automatically name/output to the right folders without me having to select them.
    - ~/projects/iEasyScript/re-resources/updater/results_DETECTED_VERSION.json
    - ~/projects/iEasyScript/re-resources/updater/offsets/offsets_DETECTED_VERSION.kt
    - ~/projects/iEasyScript/re-resources/updater/offsets/DoActionOpcodes_DETECTED_VERSION.kt //every DoAction the client constructs, in copy-paste form. (The historic "add 2000 to each PLAYER op" step is answered below: nothing is added, the client really does construct both bands.)
  5: The import script should use data from the updater to detect and name all functions/fields in the new ghidra database, detect and import data types into the new ghidra database, place any comments and notes where they should be in the new binary, etc. It should also output that offsets_DETECTED_VERSION.kt file that we can then copy paste anything we need in or out of. It should note failures to locate things as well. Doesn't have to be every single offset in the entire main engine Offsets.kt or anything.

  Here are the specific offsets that change frequently enough that we should be able to reliably automatically identify them. I have both binaries open so you can test these locations/signatures as you go along to find reliable locations. If you utilize a function to find these sub-struct offsets such as ONPC, you should at least name the function something akin to the official naming or the actual official name if posssible (sourced from the NXT BETA binary you have access to).

```
[offset table removed — per-build values live ONLY in the Ghidra DB and the
updater's generated tables (`re-resources/updater/offsets/`). Never mirrored here.]
```
## How the DoAction walk finds the table

The client builds the same set of action objects on both platforms, but by opposite mechanisms, so the
walk is platform-specific by construction rather than by tuning.

On the ELF build the objects live in .bss and nothing about them is in the image. One file-scope
initialiser writes each object's action id and kind as a pair of adjacent RIP-relative imm32 stores and
registers a destructor for it; the ids exist ONLY as those immediates, which is why searching the data
for them finds nothing. The senders are installed separately, by the MiniMenu constructor, which stores
each eastl::function's manager and invoke pointers into the object — the invoke pointer is the sender the
engine tables. The alias ids get no store of their own: the constructor byte-copies a whole already-built
object into them, so an alias always shares its donor's sender.

On the PE build the objects are static data, so the id and kind ARE in the image, but the callable
pointer is written only at run time. The object-to-sender pairing therefore exists solely as the ORDER of
references inside the two registration functions: the callable vtable is referenced, then the object it
is swapped into. A cloning registration names its donor by reading that object's engaged pointer instead,
and shares its sender. The sender is the invoke slot of the callable vtable; the surrounding vtable shape
(a paired destructor, and two allocator helpers shared by every callable of that signature) is checked on
every run, so a layout change stops the walk rather than moving the slot silently.

Nothing in either walk is a hardcoded address, and the field offsets are derived, not declared: the id
offset comes from the distance between the object reference and the id store (ELF) or from the single
displacement at which every registered object reads as a distinct in-range id (PE), and the invoke slot
from the last pointer the constructor writes into the object (ELF). Both roots are found by their own
shape — the function holding the most id/kind store pairs, the functions storing into those objects —
so neither needs a name to be located. `anchor_registry.json`'s `doaction_roots` only supplies names to
label them with on `--apply`.

### There is no +2000 fudge

The client constructs TWO bands of player action objects, and both are real: the low band and a second
band 2000 higher whose objects are byte-copy aliases of the low ones. The same is true of several other
actions (the alias ids the table spells `*_ALT`). The old walk found only one band and the difference was
patched by hand every build; the current walk reads both ids out of the binary, so the engine's opcode is
whatever the client stored, and the `_ALT` suffix marks the alias rather than an arithmetic correction.

### Failing loudly

The walk is checked against the PREVIOUS build's table: any action name that table carried and this walk
did not produce is listed by name and the run is failed (`run_updater.py` exits non-zero on the parity
marker). Reporting only what was found is what let a build silently drop 26 of 65 actions while the log
read "39 added, 0 dropped".

## Self-test baseline (949-4, both platforms)

`run_updater.py` defaults to a dry run: `import` passes `-readOnly` and uses `-process`, never
`-import`, so it cannot write to the project DB or discard existing analysis. Only `--apply` commits.
The Ghidra project has a single-process lock, so stop the headless MCP host before either mode and
restart it afterwards.

```bash
GH=/home/trent/projects/ghidra/build/dist/ghidra_12.1_DEV
python run_updater.py export --project-dir /home/trent/ghidra-proj \
  --project-name nxt-exe-2024-9-25 --program-name rs2client.949-4 --ghidra-home "$GH"
```

Re-running both modes against the build they were exported from must reproduce every value. On
949-4 Linux that baseline is: 1102 functions / 1707 data labels / 620 comments exported, and every
anchor self-resolving to the value already in the offset table. **`MISSING` must be 0** — a non-zero
count means a recipe stopped matching.

> ⚠️ The pre-2026-07-27 figures (1089 / 1707 / 566, `FOUND=1046 AMBIGUOUS=43`) are **not** comparable.
> The exporter under-collected back then: it skipped hand-named functions outside the target
> namespaces, and the importer anchored comments by raw byte offset. Self-testing against those
> numbers would ratify the shortfall. A self-test now passes only if the parity diff
> (`names_in_<old> − names_in_<new>`) is EMPTY — counts alone never proved parity, because new names
> mask disappearances.

A dry run does **not** write into the repo. `import` emits its offset table preview to
`re-resources/updater/offsets/preview-<platform>-<build>.json`; only `--apply` writes
`client-plugin-engine/src/main/resources/offsets/<platform>-<build>.json`. It merges rather than
replaces — unresolved keys and hand-written `objectNotes` survive.

### The six unrelocatable `OFunctions` — CLOSED at 949-4

Historically `OFunctions resolved: 37/43`. Six entries carried correct values but named functions
never applied to the **Linux** Ghidra DB, so the importer had nothing to match and they returned
`new: null`: `STATTABLE_UPDATESTAT`, `SERVERPROT_DECODE_UPDATE_INV_PARTIAL`,
`SERVERPROT_DECODE_UPDATE_INV_FULL`, `TCPCONNECTIONMESSAGE_INIT`,
`CLIENTPROT_SENDEVENTMOUSECLICK`, `APPLY_LOC_CHANGE`.

The fix this note called for — applying those names to the Linux DB — was done during the 949-4
migration. **949-4 reports `OFunctions resolved: 43/43`, with all 43 entries carrying a non-null,
non-`0x0` value.** No manual sig-scan is needed for them on the next build. If a future run drops
back below 43/43, the cause is a name missing from the Linux DB, not drift.
