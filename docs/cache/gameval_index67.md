# Cache Index 67 — Gameval / RSCM id ↔ dev-name Index

**Source:** Reverse-engineered from real beta bytes in `data/betacache/js5-67.jcache` (RS3 beta, rev
949), cross-validated against the bundled `re-resources/gamevals/<type>.json` dictionaries.

**Status:** Index 67 is **beta-only** — the live RS3 cache ships it empty, so consuming it is purely
additive. Decoder + validation live in `:core`:

- `core/.../world/gregs/voidps/cache/gameval/GamevalIndex.kt` — constants + archive→type map
- `core/.../world/gregs/voidps/cache/gameval/GamevalIndexDecoder.kt` — the decoder
- `core/src/test/.../cache/gameval/GamevalIndexDecoderTest.kt` — round-trips against the bundled gamevals

---

## 1. What it is

Index 67 is the client's **gameval / RSCM** (RuneScape Content Mapping) index: for each content
*type* (npc, loc, obj, seq, sound, component, …) it stores a table mapping a numeric content **id**
to its developer **name** (e.g. `seq 0 → "swarm_walk"`, `npc 0 → "hans"`, `obj 0 → "mcannonremains"`).
These are exactly the names `re-resources/gamevals/` and `gameval.py` resolve — index 67 is their
in-cache origin.

---

## 2. Container & group layer (standard JS5)

Each archive is a **single-file group** (file id 0) stored as a normal JS5 container:

```
u8     compressionType   // 0 NONE, 1 BZIP2, 2 GZIP, 3 LZMA  (observed: mostly BZIP2, a few GZIP, one NONE)
u32    compressedSize
[u32   decompressedSize]  // present only when compressionType != 0
u8   payload            // compressed (or raw, for NONE)
```

Because the group has a single file, there is **no multi-file framing** (no leading `0x01`, no
trailing chunk table) — the decompressed container payload *is* the gameval file. In code:
`cache.data(67, archive, 0)` returns the decompressed file directly (the `fileCount <= 1` path in
`SQLiteCache.data`).

### Ref table / archive listing

The index-67 reference table is a normal archive index (`SQLiteCache.parseRefTable`). Key facts
confirmed from the bytes:

- **36 archives**, with **sparse** ids: `0, 5, 9, 12, 14, 15, 16, 20, 21, 24, 25, 28, 29, 32, 34, 35,
  36, 37, 41, 44, 49, 50, 55, 56, 57, 59, 60, 61, 64, 69, 80, 89, 90, 92, 96, 97`. The archive set is
  **not fixed** — archive `29` (`mapelement`) first appeared in the 2026-07-15 beta refresh, so an
  unknown archive id is a new content type, not a decode error.
- Each archive has exactly **1 file** (id 0).
- Archives are **NOT name-hashed** (ref-table names flag `0x1` unset, every `nameHash == 0`). The
  archive **id itself is the type discriminator** — it is the client's RSCM **type-enum ordinal**,
  decoded to a type name purely by the cross-validation in §6 (do **not** identify archives by
  name-hash here).

> The archive id is **not** the `world.gregs.voidps.cache.Config` id of the same name: archive `69`
> is `midi` (not `varbit`), archive `60` is `var_object` (not `var_player`), archive `61` is
> `var_player`. The two enumerations are unrelated.

---

## 3. File format (the per-type id→name table)

All multi-byte integers are **big-endian**. Two layout **versions** exist, selected by the first
int. The string blob and CP1252/null-termination are identical in both.

```
i32    version          // 1 = dense (implicit ids) | 2 = sparse (explicit keys)
i32    count            // number of table slots
--- version 1 (dense) ---
i32[count]  offset      // slot i is content-id i; offset is into the blob, or -1 = "id i has no name"
--- version 2 (sparse) ---
(i32 key, i32 offset)[count]   // explicit key + blob offset; keys may be sparse or composite
--- both ---
u8   blob             // null-terminated CP1252 strings
```

- **`offset` is relative to the start of the blob**, i.e. the first byte *after* the offset/pair
  table (`blobBase = 8 + count*4` for v1, `8 + count*8` for v2).
- Each name = the CP1252 bytes from `blob[offset]` up to the next `0x00` (null-terminated). Reading
  by null terminator and reading by `offset[i+1] - offset[i]` are equivalent — offsets are
  cumulative and include the terminator — but the entries are *not* required to be in blob order, so
  read by null terminator.
- **version 1** is used where ids are dense from 0 (npc, loc, obj, seq, sound, cursor, …); a `-1`
  offset is a hole (that id has no name). **version 2** is used where ids are sparse or composite
  (component, enum, midi, the `var_*` types). Of the 36 archives, 8 are v2 (`0, 16, 55, 56, 59, 60,
  69, 80`); the other 28 are v1.

### Worked example — archive 80 (`var_player_group`, version 2, count 3, 79 bytes)

```
00 00 00 02                       version = 2
00 00 00 03                       count   = 3
00 00 00 10  00 00 00 00          key=16  offset=0
00 00 00 11  00 00 00 0b          key=17  offset=11
00 00 00 15  00 00 00 1f          key=21  offset=31
| blob (base = 8 + 3*8 = 32) |
47 52 4f 55 50 5f 54 59 50 45 00            "GROUP_TYPE\0"            (blob 0..10)
47 52 4f 55 50 5f 57 41 4e 54 53 5f 4d 45 4d 42 45 52 53 00  "GROUP_WANTS_MEMBERS\0"  (blob 11..30)
47 52 4f 55 50 5f 4c 4f 4f 54 53 48 41 52 45 00            "GROUP_LOOTSHARE\0"      (blob 31..46)
```

→ `{16: "group_type", 17: "group_wants_members", 21: "group_lootshare"}` (after §5 normalisation).

### Worked example — archive 12 (`cursor`, version 1, count 213)

```
00 00 00 01   version = 1
00 00 00 d5   count   = 213
00 00 00 00   id 0  -> blob 0    ("CURSOR_MOVE")
00 00 00 0c   id 1  -> blob 12   ("CURSOR_ARCH_SCREENING")
00 00 00 22   id 2  -> blob 34
...           (213 offsets total; blob base = 8 + 213*4 = 860)
ff ff ff ff   id k  -> -1        (no name for this id — skipped)
```

Of 213 slots, 185 are named (28 holes). The 213th offset's string ends exactly at the end of the
blob (verified: zero trailing bytes for every archive).

---

## 4. Component archive (id 0) — composite keys

Archive 0 (`component`, version 2) uses **composite** keys:

```
key = (interfaceId << 16) | componentId      // interfaceId = key >>> 16, componentId = key & 0xFFFF
```

Its raw blob strings encode `INTERFACE_NAME__COMPONENT_NAME` (double-underscore separator), e.g.
`100GUIDE_EGGS_OVERLAY__100_Q_ANIM5` at key `1` = `(0<<16)|1` → interface 0, component 1.

`GamevalIndexDecoder.decodeComponents(cache)` exposes this as `"interfaceId:componentId" → name`
(e.g. `"0:1" → "100guide_eggs_overlay:100_q_anim5"`), matching the bundled `component.json` keys.

---

## 5. Name normalisation (raw cache → RSCM dev-name)

Raw cache names are **UPPERCASE** (`SWARM_WALK`). The decoder produces the canonical lowercase RSCM
dev-name used everywhere in the project (and by the bundled gamevals):

- **general:** `rawName.lowercase` → `swarm_walk`
- **component:** lowercase, then rewrite the **first** `__` to `:` →
  `100guide_eggs_overlay:100_q_anim5` (matches `component.json`'s `interface:component` values).

This makes the decoder a drop-in, cache-backed source for `world.gregs.voidps.gameval.Gameval`
(which currently loads the bundled json). Wiring `Gameval` to load from a real index-67 cache is left
for later — the names are byte-for-byte identical, so it is a clean swap.

---

## 6. Archive-id → type map (derived by cross-validation)

Each archive was decoded and its id→name table compared against every `re-resources/gamevals/
<type>.json`; the file whose `entries` it matches names the type. Result: **34 of 35 archives match
the bundled json at 100% precision**; `component` differs only for the stale `escape_menu` interface
(1433) in the bundled json (a data drift in the bundled snapshot, not a decode error — the decode is
byte-faithful to the cache).

| archive | ver | type | slots (`count`) | named | bundled json # | overlap | precision |
|--------:|:---:|------|----------------:|------:|---------------:|--------:|----------:|
| 0  | 2 | component        | 104065 | 104065 | 104065 | 104063 | 99.95%¹ |
| 5  | 1 | bas              | 4913   | 4908   | 4908   | 4908   | 100% |
| 9  | 1 | category         | 3268   | 3268   | 3264   | 3264   | 100% |
| 12 | 1 | cursor           | 213    | 185    | 185    | 185    | 100% |
| 14 | 1 | dbrow            | 18232  | 15340  | 18123  | 15340  | 100% |
| 15 | 1 | dbtable          | 361    | 242    | 362    | 242    | 100% |
| 16 | 2 | enum             | 8563   | 8563   | 8563   | 8563   | 100% |
| 20 | 1 | headbar          | 63     | 63     | 63     | 63     | 100% |
| 21 | 1 | hitmark          | 527    | 527    | 527    | 527    | 100% |
| 24 | 1 | interface        | 1947   | 1870   | 1870   | 1870   | 100% |
| 25 | 1 | inv              | 996    | 934    | 934    | 934    | 100% |
| 28 | 1 | loc              | 137210 | 137174 | 137174 | 137174 | 100% |
| 29 | 1 | mapelement       | 5809³  | 5809³  | —      | —      | —    |
| 32 | 1 | material         | 23881  | 23880  | 23861  | 23861  | 100% |
| 34 | 1 | model            | 140384 | 140367 | 140366 | 140366 | 100% |
| 35 | 1 | npc              | 32801  | 32703  | 32703  | 32703  | 100% |
| 36 | 1 | obj              | 61618  | 61328  | 61328  | 61328  | 100% |
| 37 | 1 | param            | 9434   | 5992   | 5992   | 5992   | 100% |
| 41 | 1 | quest            | 531    | 531    | 531    | 531    | 100% |
| 44 | 1 | seq              | 37904  | 37889  | 37889  | 37889  | 100% |
| 49 | 1 | graphic          | 35988  | 35925  | 35924  | 35924  | 100% |
| 50 | 1 | struct           | 53139  | 35613  | 35613  | 35613  | 100% |
| 55 | 2 | var_clan         | 1752   | 1752   | 521    | 521    | 100%² |
| 56 | 2 | var_clan_setting | 708    | 708    | 132    | 132    | 100%² |
| 57 | 1 | var_client       | 8414   | 7681   | 7681   | 7681   | 100% |
| 59 | 2 | var_npc          | 1105   | 1105   | 167    | 167    | 100%² |
| 60 | 2 | var_object       | 448    | 448    | 5      | 5      | 100%² |
| 61 | 1 | var_player       | 73782  | 60227  | 10056  | 10056  | 100%² |
| 64 | 1 | sound            | 59857  | 59852  | 59852  | 59852  | 100% |
| 69 | 2 | midi             | 2650   | 2650   | 2650   | 2650   | 100% |
| 80 | 2 | var_player_group | 3      | 3      | 3      | 3      | 100% |
| 89 | 1 | achievement      | 4994   | 4901   | 4901   | 4901   | 100% |
| 90 | 1 | fontmetrics      | 308    | 225    | 225    | 225    | 100% |
| 92 | 1 | stylesheet       | 410    | 318    | 318    | 318    | 100% |
| 96 | 1 | ui_anim_curve    | 15     | 14     | 14     | 14     | 100% |
| 97 | 1 | ui_anim          | 17     | 16     | 16     | 16     | 100% |

- **named** = entries with a non-`-1` offset (version-1 holes are excluded).
- **overlap** = decoded ids that the bundled json also contains; **precision** = of those, how many
  names match.
- ¹ `component`: the only mismatches (≈52 entries) are all in interface **1433** (`escape_menu`),
  where the bundled `component.json` is a few slots stale vs the beta cache. The cache is ground
  truth; the decode is byte-faithful.
- ² These `var_*` (+ `var_player`) bundled jsons are smaller curated **subsets** of the beta cache,
  so `named` ≫ bundled count, but every overlapping id matches (100% precision). The bundled
  `dbrow`/`dbtable` jsons are conversely *supersets* (more ids than this beta cache) — still 100% on
  the overlap.
- ³ `mapelement` did not exist in this snapshot; the row carries its counts from the 2026-07-15
  refresh, where it appeared as a wholly new archive (world-map elements: icons, lodestones,
  quest-start/progress markers, dungeon entrances/exits — `ME_QUEST_START_…`, `GODWARS_EXIT`,
  `FAIRYRING_ICON_ALP`). There was no bundled json to cross-validate against, so the type name comes
  from the `mapelement` CS2 type (the generated CS2 opcode table) plus the `ME_` /
  `…_MAPELEMENT_LEGACY` name conventions in the table itself.

> The table above is a **point-in-time snapshot** (beta cache of 2026-06-26). The beta refreshes
> its gameval data over time — e.g. the 2026-07-07 update grew `category` from 3268 to 5760 named
> entries and added 4 `obj` ids, and the 2026-07-15 update added the whole `mapelement` archive — so
> re-derive counts from a fresh download (§8), not from here.

### Combined `var_*` archives — varps + varbits in one table

There is **no separate `varbit` archive** in index 67. Instead each `var_<domain>` archive is a
**combined** table holding both kinds of names:

- **varp** entries sit at their varp id with a plain name (`var_player 0 = LASTCASTSPELL`);
- **varbit** entries follow in a contiguous key block, each raw name prefixed with `_`
  (e.g. `_ZAROS_SPELLBOOK`).

`GamevalIndexDecoder.splitVarDomain` splits on that `_` prefix and re-bases the varbit ids:
`varbitId = key - firstPrefixedKey`. The re-based numbering **is** the classic varbit numbering
(`varbit_player 0 = zaros_spellbook`, byte-identical to the legacy bundled `varbit.json`, which the
exporter deletes as superseded). Splitting the 7 var domains yields up to **41 output types from
the 36 archives** — `var_client` and `var_player_group` contain no `_`-prefixed entries, so no
varbit file is produced for them.

---

## 7. Decoder API (`:core`)

```kotlin
val decoder = GamevalIndexDecoder

// All types: typeName -> (id -> name). Component ids are the packed (iface<<16)|comp keys.
val all: Map<String, Map<Int, String>> = decoder.decode(cache)

// A single type, or a single archive:
val seq: Map<Int, String>? = decoder.decode(cache, "seq")
val byArchive: Map<Int, String>? = decoder.decodeArchive(cache, 44)

// Component as "iface:comp" -> name:
val components: Map<String, String> = decoder.decodeComponents(cache)   // "0:1" -> "100guide_eggs_overlay:100_q_anim5"

// Low-level: one already-decompressed file's bytes:
val table: Map<Int, String> = decoder.decodeFile(bytes, type = "seq")
```

`GamevalIndex.TYPE_BY_ARCHIVE` / `ARCHIVE_BY_TYPE` expose the §6 mapping; `GamevalIndex.INDEX == 67`.

The validation test loads `data/betacache` read-only via `SQLiteCache.load(path)`, asserts the spot
values (`seq 0 = swarm_walk`, `var_player 0 = lastcastspell`, `npc 0 = hans`, `obj 0 =
mcannonremains`, `component 0:1`), and asserts 100% precision + close counts against the bundled
gamevals for `seq, npc, loc, obj, enum, cursor, bas, sound`. It skips when the beta cache is absent.

---

## 7b. Component slots are BETA slots — aligning them to the served cache

Index 67 exists only on beta, so every `component.json` id is a **beta** slot. Beta and live do not
ship the same interfaces: when beta inserts or removes a component, **every slot after it shifts**,
and the name no longer addresses the component the server actually serves. Names resolved through
`Gameval.componentHash`/`requireComponentId` then land one or more slots off — silently, because the
id still exists.

The vast majority of interfaces are identical between the two caches — as of the 2026-08-10 live
cache against the 2026-07-15 beta gameval build, 19 of 1881 drift, 9 of them recoverable.
`toplevel_v2` is the one that matters — the server resolves ~74 placements through it — where beta
carries two more slots than the server serves, shifting most window backgrounds by −1.

`:tools gamevalExport --align <serverCacheDir>` (`ComponentAlignment`) re-keys the names onto the
served layout. It aligns each interface's component sequence with Needleman–Wunsch over a **shape**
key (leading structural bytes + length) rather than content — only ~16% of components are
byte-identical across the two caches, but the shape survives content edits — and accepts a remap only
at **≥90% shape agreement**, so an interface beta has rebuilt outright is left alone rather than
guessed at.

Verify a remap by hand with **component byte lengths** rather than content — rare lengths make
unmistakable anchors, and a genuine insertion shows up as one unmatched length followed by a
constant offset that holds to the end of the interface. `toplevel_v2` is the bulk form of the same
argument: its rare 98-byte components sit one slot later on beta throughout, and whole-sequence
length agreement is near-perfect shifted and poor unshifted, with the two sequences agreeing exactly
before the insertion point.

**Interfaces beta has rebuilt — component ids NOT usable against the served cache** (left at beta
numbering, reported by the exporter on every run). As of the 2026-08-10 live cache these are
`stockmarket`, `stockmarket_collectall`, `stock_favourites`, `marketplace_featured`,
`marketplace_preview`, `gwd2_rep`, and the league cluster (`league_info_popup`,
`league_parent_areas`, `league_parent_ranks`, `league_parent_tasks`).

Beta rebuilt the whole Grand Exchange, so there is no recoverable mapping for it — treat every
`stockmarket*` component id as beta-only until live catches up. No server or engine code references
any interface in this set today; the exporter's summary is the place to notice when that changes.
Do not lower the agreement threshold to force one of these to align — that trades a loud gap for
silent wrong ids.

**Drift guard.** `--align` stamps `component.json` with an `alignment` block: the served interface
index's reference-table CRC (the value the JS5 master index advertises for index 3) plus the ids of the
interfaces it could not align. `GamevalAlignment` in `:core` compares that CRC with the cache a server is
about to serve: the lobby and world log an error at startup when they differ, and
`GamevalComponentAlignmentTest` fails `:core:test` on the same mismatch and whenever an aligned name
addresses a slot past the served interface's component count. A download that moves index 3 therefore
cannot pass unnoticed, and the fix is always the same re-export.

> Re-run the alignment whenever **either** cache moves — a new beta gameval dump *or* a fresh live
> cache download. The `--align` source must be the cache the JS5 server actually serves.
>
> To find out *whether* either cache moved, snapshot and diff them (`:tools:cacheSnapshot` +
> `:tools:cacheDiff`) — see `cache-update-flow.md` and the `cache-update-check` skill. ⛔ Trigger
> the re-alignment on an interface's **crc** changing, not on its component count changing: an
> interface can keep its count and still reorder slots, so counts under-report drift.

---

## 8. Refreshing `re-resources/gamevals/` (runbook)

When Jagex updates the beta gameval data (new content names land on `content.beta.runescape.com`),
regenerate the bundled dumps. The whole flow is read-only against the live cache; downloads go to
the gitignored `./data/betacache`.

1. **Get the current JS5 token** — param 29 of the beta jav_config. It regenerates per fetch, so
   never reuse a saved one; the same fetch gives you the handshake major (`server_version`) and the
   JS5 host (params 37/49):

   ```
   curl -sL 'https://www.runescape.com/l=0/jav_config_beta.ws?binaryType=4' \
     | grep -E '^(server_version=|param=(29|37|49)=)'
   ```

2. **Scan (optional, writes nothing)** — confirms the handshake revision still works and prints
   index 67's crc/version/file-count, so you can tell whether the gameval data actually changed
   before downloading anything:

   ```
   ./gradlew :tools:betaScanner -Pargs="--host content.beta.runescape.com --major 949 --minor 1 --token <param29> --scan"
   ```

   A `GAME_UPDATE` (response 6) rejection means the beta revision moved: set `--major` to the
   jav_config `server_version` and probe `--minor` upward from 0.

3. **Download index 67** into the isolated dir (IsolationGuard refuses live-cache paths):

   ```
   ./gradlew :tools:betaScanner -Pargs="--host content.beta.runescape.com --major 949 --minor 1 --token <param29> --download 67"
   ```

4. **Export the JSON dumps** (read-only on the cache; overwrites the 40 index-67 `<type>.json`
   files in place, leaves everything else in the dir untouched):

   ```
   ./gradlew :tools:gamevalExport -Pargs="--cache ./data/betacache --out re-resources/gamevals \
     --revision 949 --source content.beta.runescape.com --align ./data/cache"
   ```

   **`--align` is not optional in practice** — without it `component.json` carries beta slots, which
   are wrong for any interface beta has changed (§7b). Read the alignment summary it prints: the
   remapped interfaces are fixed, the "NOT aligned" ones are beta-only ids.

   Pass `--revision <n>` / `--source <s>` if the beta revision moved (defaults: 949 /
   `content.beta.runescape.com`).

5. **Verify** — check what changed and that lookups resolve:

   ```
   git -C re-resources diff --stat -- gamevals/
   ./re-resources/gamevals/gameval.py npc 0          # -> hans (regression)
   ./re-resources/gamevals/gameval.py <type> <newId> # spot-check an id added by the diff
   ```

`re-resources` is a submodule — the refreshed dumps are committed to the `reclass-data` repo, not
this one.
