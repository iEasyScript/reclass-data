# The CS2 toolchain — requirements, commands, and how to run it

> How to *use* `:tools:cs2`. For the format itself, the naming provenance, and the traps the
> container sets, see [clientscript-cs2.md](clientscript-cs2.md).
>
> ⛔ No opcode ids, addresses or operand widths in this file. Those are per-build facts and live in
> the Ghidra DB and in the generated, gitignored tables under `data/cs2/`.

The toolchain disassembles, decompiles, recompiles, simulates and hot-reloads the clientscripts in
cache index 12. It exists because a CS2 update is otherwise opaque: the index carries no meaningful
version, so a CRC is the only signal that anything changed, and the opcode set is renumbered per
client build, so a table from one build is worthless against another.

## Requirements

| Requirement | Detail |
|---|---|
| JDK 25 and the Gradle wrapper | Everything is `./gradlew :tools:cs2 -Pargs="…"`, run from the repo root |
| A cache | `./data/cache` by default; `--cache <dir>` overrides. A missing path exits non-zero |
| An installed opcode table | `data/cs2/opcodes-<index12Crc>.json` — see [The opcode table](#the-opcode-table) |
| Heap | The 4 GB in `gradle.properties` covers every whole-corpus command |

The task's working directory is the repo root regardless of where you invoke it from, so the default
relative paths (`./data/cache`, `data/cs2/`, `cs2-dump/`) always resolve the same way.

### The cache is opened read-only, always

`SQLiteCache.load(path, readOnly = true)`, immediately followed by `Cache.init(cache)` so that
everything reaching the cache through the static accessors lands on that same read-only handle
rather than opening the default path for writing.

Two consequences worth stating plainly:

- **The toolchain is safe to run against a live cache**, with the servers up or the client running.
  Nothing needs to be stopped. This is a deliberate property, not an accident.
- **Nothing the toolchain does ever writes a script back to the cache.** Edits and hot reloads
  install an in-memory override; they last as long as the process.

Outside the toolchain the same discipline applies: a `.jcache` is read through
`sqlite3 "file:/abs/path/x.jcache?immutable=1"` (no locks, no sidecars) or `?mode=ro` when the file
may be concurrently written. A bare path opens read-write, takes a lock, leaves `-wal`/`-shm`
sidecars, and can force a multi-gigabyte re-download.

### Generated artifacts

| Path | Contents | Tracked |
|---|---|---|
| `data/cs2/` | The installed opcode table plus the RE exports it is built from | No — gitignored |
| `cs2-dump/` | The default decompilation output folder | No — gitignored |
| `re-resources/cs2/` | Per-build table exports written by `export-table`, and the cross-build maps | Yes — in the submodule |

Never hand-edit a generated table; regenerate it.

## Invocation

```bash
./gradlew -q :tools:cs2 -Pargs="<sub-command> [args] [flags]"
./gradlew -q :tools:cs2 -Pargs="--cache /path/to/other/cache decompile 10000"
./gradlew -q :tools:cs2                        # no sub-command: prints the command list
```

`-Pargs` is split on whitespace, so arguments cannot contain spaces. Every run prints the opcode
table it loaded and its source before doing anything else.

### Global flags

| Flag | Effect |
|---|---|
| `--cache <dir>` | The cache to read, opened read-only. Default `./data/cache` |
| `--legacy-opcodes` | Use the built-in pre-RS3 table instead of the solved one. Diagnostic only |
| `--shape-heuristic` | On the commands that emit source, keep readings that rest on a value's shape alone, emitted marked `/* unverified */`. Left off, such a value stays the integer it is — so by default **nothing unverified reaches the output** |

## Commands

### Reading

| Command | What it does |
|---|---|
| `info <id>` | The script's header — name, argument and local counts |
| `dump <id>` | The raw instruction listing |
| `decompile <id>` | Structured TypeScript for one script |
| `decompile-all [dir]` | The whole corpus, plus the declarations, into a folder |
| `export <dir> [id]` | One script into a source folder, verified; without an id, just the declarations |
| `declarations <dir>` | `cs2.d.ts` + `tsconfig.json` only |
| `trace <id>` | Simulate the script, printing the stacks per instruction |
| `run <id> [intArgs…]` | Execute against a no-op host and log every host call and the return values |

### Verification

Check these in order — each layer needs strictly less than the next, so a failure localises.

| Command | Layer |
|---|---|
| `verify` | The codec alone: decode and re-encode every script, assert byte identity. Needs only operand widths |
| `analyse` | Corpus-wide analysis pass: string parameters, return signatures, and the problems grouped by opcode |
| `structure` | How much of the corpus reads as structured control flow, and where the structured rendering first diverges. With an id, the block/goto/label counts for one script |
| `roundtrip [limit]` | End-to-end: decompile, recompile, compare bytes, and report whether any mismatch changed the actual work |
| `roots` | Splits the validation failures into roots and cascade |
| `diff <id> [faithful]` | One script beside its recompilation; `faithful` renders the literal block-by-block fallback instead |
| `sources <dir> [n]` | Compile every source file in a folder and report the byte-exact rate |

**The acceptance gate is byte-identical over every script**, at the codec layer and end-to-end. On
the current build both pass at 21097/21097 — the codec layer in under half a second, the full
decompile/recompile round-trip in a few seconds, with a handful of scripts reaching identity through
the literal fallback rather than structured control flow. That fallback is deliberate: readability
yields to fidelity, and it must not be optimised away. Anything short of PASS is a decompiler or
code-generator bug, not a formatting preference.

### The opcode table

| Command | What it does |
|---|---|
| `import <csv>` | Install a table exported from the client's own dispatch table — authoritative, covers unused opcodes |
| `calibrate` | Solve every opcode's operand encoding from the corpus. Cross-checks rather than overwrites an installed dispatch-table export |
| `names [csv]` | Attach the recovered opcode names |
| `behaviour [csv]` | Attach names and argument types read from the handlers, with evidence and confidence |
| `reference [csv]` | Attach Jagex's own handler names, matched from another build |
| `variants [csv]` | Settle the opcodes the handler read left with several candidates |
| `effects [csv]` | Install stack effects read from the handlers |
| `stacks` | Solve stack effects from the corpus instead |
| `vartypes` | Print the script variable types and what they index |
| `gamevals` | Count how often each operand renders as a gameval name |
| `types [value]` | What the corpus typed, or every place one number has been seen |

The table is keyed by the CRC of the index-12 reference table, so a solve is bound to the exact cache
it was solved against. When the cache changes under it the tool says so and falls back to the pre-RS3
table — at which point every reading above it is worthless until the table is rebuilt.

Two independent sources exist and both should be used: the client's dispatch table (authoritative,
and it covers opcodes no script exercises) and the corpus solve (derived, but needs no binary). They
agreed on every opcode they both covered. A disagreement means one of the two is wrong — most often
that the build changed the width rule — and is reported loudly rather than reconciled silently.

### Cross-build migration

| Command | What it does |
|---|---|
| `export-table [build]` | Write the current build's table into `re-resources/cs2/` as the anchor |
| `coldstart` | Re-solve this build's widths with nothing installed and diff, so the corpus-only recovery rate is known in advance |
| `rehearse [--churn f] [--seed n]` | Run the whole derivation against a renumbering generated here, where the truth is known. `--churn` also edits a share of the scripts, which is what a real build looks like |
| `unscramble --to <new cache dir> [--to-build <id>] [--dispatch <csv>] [--from-table <json>]` | Derive the new build's opcode numbering from this build's table |

During `unscramble`, `--cache` still points at the **old** build's cache: both disassemblies are
needed, because the derivation works by matching the same scripts across the two numberings. An
opcode the derivation cannot confirm is left unresolved rather than inheriting its old number.

This is `rs3-update-migrator` territory on a real update. The methodology is in
[../re-methodology/UPDATING.md](../re-methodology/UPDATING.md).

### Editing and hot reload

| Command | What it does |
|---|---|
| `compile <dir> <id>` | Compile one edited script and byte-compare it against the cache |
| `hotswap <dir> <id> [intArgs…]` | Run the script as cached, reload from source, run it again — both return values, both host-call sequences |
| `watch [dir] [secs]` | Reload scripts as they are saved. With a duration it runs unattended; without one it takes `r <id>` / `v <id>` / `l` / `q` on stdin |

A source folder is one `clientscript-<id>.ts` per script plus `cs2.d.ts`, `vars.d.ts` and
`tsconfig.json`; the default is `cs2-dump`. **The `// clientscript <id>` header is the script's
identity**, not the file name and not the function name — so a function can be renamed and a file
moved freely, but losing the header loses the binding. Renamed identifiers resolve only through the
folder's own declarations, making the symbol table folder-scoped state that is re-read whenever
those files change.

## A worked path: what does this interface actually do?

```bash
# 1. Dump once. Seconds for the whole corpus; the folder is gitignored.
./gradlew -q :tools:cs2 -Pargs="decompile-all cs2-dump"

# 2. Name the ids you are holding before guessing at them.
./re-resources/gamevals/gameval.py obj -n coins
./re-resources/gamevals/gameval.py -s magic_logs        # search every type

# 3. Find the script by a name, not a number.
rg -l 'rs3tli_button_layer_type' cs2-dump/

# 4. Read it, then watch it run.
./gradlew -q :tools:cs2 -Pargs="decompile 10000"
./gradlew -q :tools:cs2 -Pargs="run 10000 1 2"
```

The decompiled source renders gameval names for operands that index a gameval table and unpacks
composite operands into constructors. Both renderings are bidirectional, which is exactly why the
output still compiles — see
[clientscript-cs2.md](clientscript-cs2.md#making-scripts-readable).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No such cache directory` | No cache, or `--cache` points somewhere that does not exist |
| `No solved opcode table for index-12 crc …` | The cache changed under the table. `import` the dispatch-table export, or `calibrate` from the corpus |
| Output is full of bare numeric operators | The table loaded without its name layers — re-run `names` / `behaviour` / `reference` |
| `verify` fails | Operand widths are wrong. Nothing above the codec can be trusted; fix the table first |
| `roundtrip` fails while `verify` passes | A decompiler or code-generator bug. `diff <id>` shows both listings; `diff <id> faithful` shows the literal fallback |
| `structure` reports a script falling back | Expected for a few scripts, and they still round-trip. Only a fidelity failure is a defect |
| A `--shape-heuristic` reading appears in something you are citing | It is marked `/* unverified */` for a reason. Confirm it in the Ghidra DB or drop it |
