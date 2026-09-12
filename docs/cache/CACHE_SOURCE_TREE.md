# Cache source tree: unpacking, editing and rebuilding any cache

A packed cache - the NXT client's `js5-<n>.jcache` SQLite databases, or a legacy client's
`main_file_cache.dat2` + `.idx<n>` sector store - is a binary blob to git. The **cache source tree**
is the whole cache unpacked into one file per asset (an image where the asset is an image, JSON where
a codec exists, the decompressed bytes otherwise) plus a little metadata, in a plain directory that
can become a git repository. A pack rebuilds the packed cache from it - byte for byte when nothing
was edited - and the same tree can be built into either store.

The design and most of the code are the 727 server's (`projectx/server`, `docs/cache-source.md`),
generalised so that one library reads and writes every RuneScape cache revision: the legacy Java
clients and the NXT client, the sector store and the SQLite store, gzip, bzip2 and LZMA.

## Guarantees

1. **Parity.** Unpacking a cache and packing the result with no edits reproduces every container
   byte for byte, every reference table byte for byte, and therefore every CRC, checksum, length,
   whirlpool and version table the client checks. `cacheSource verify` proves it and exits 1 on any
   difference; `WholeCacheSourceTest` runs it. Parity is *by construction*: whatever a codec cannot
   reproduce is kept beside its editable form until that form is edited (the pristine and payload
   sidecars below), so an imperfect codec costs disk, never bytes.
2. **Git without LFS.** One file per asset, deterministic output, stable names keyed by id, no churn
   on re-unpack: files are compared before they are written and a second unpack of the same cache
   touches nothing.
3. **Any revision.** The tree records which client era it belongs to and everything that follows
   from it (index names, config archive names, encryption, store kind), and the store layer converts
   between the two on-disk shapes without decompressing anything.
4. **Fast rebuilds.** The packed cache is a build output beside a manifest of what it was built
   from; a rebuild stats the tree and repacks only the archives whose inputs changed.

## What determines the served bytes

Measured over the NXT cache (build 949) and the 727 cache; the library encodes these as code, not
as data files:

| Fact | Consequence |
|---|---|
| gzip containers reproduce with a standard ten byte header and a raw deflate stream, but Jagex's packers used **deflate levels 1 to 6** at different times, per archive | the level that reproduces each payload is detected on unpack and recorded when it is not 6 |
| bzip2 containers are block size 1, almost all from libbzip2 1.0.8 (`BZip2Encoder`, a Kotlin port); a few legacy reference tables only reproduce with commons-compress | the variant is recorded when it is not libbzip2 |
| LZMA containers (the NXT model index, mostly) are the **LZMA SDK in fast mode with 32 fast bytes**, a 4 MiB dictionary and `lc=3 lp=0 pb=2`; the SDK's own Java encoder reproduces them; both the bt4 and bt2 match finders occur | the match finder and, if ever different, the property bytes are recorded |
| NXT reference tables are format 7 with the lengths and uncompressed-checksum sections; legacy ones are 5 to 7 with names and optional whirlpools | all four sections are derived at pack time and none is stored |
| A sector store keeps a two byte version trailer on every archive container; a SQLite store keeps the version in a column | the trailer is derived from the version in the table; the tree never stores it |
| NXT map archives are plain; legacy ones are XTEA encrypted per region | keys are metadata on the archive, supplied at unpack from a `xteaKeys.json` |
| Multi-file groups on the wire end in a chunk table; the NXT client's own on-disk cache leads with an offset table | both layouts split; the layout is recorded when it is not the wire one |

The version table (the master index) is never stored in the tree: it is derived from the reference
tables and signed with the server's key on every pack, and written into `js5-255` for a SQLite build.

## Layout

```
<tree>/
  cache.json                  format, revision, store kind, index count, passthrough indices
  gamevals/<type>.json        the catalogs - index 67 unpacked when the cache has it, seeded otherwise
  <index>/index.json          reference-table metadata + one line per archive
  <index>/...                 the archives, laid out by the index's codec
```

Index directories use Jagex's own names (`config_obj`, `clientscripts`, `textures_png`); an index
nobody has identified is `index<n>`. Which name belongs to which id differs between the eras -
index 22 is `config_varbit` for a legacy cache and `config_struct` for an NXT one - and the table
lives in `IndexNames`.

### `cache.json`

```json
{
  "format": 2,
  "revision": 949,
  "store": "sqlite",
  "indices": 67,
  "passthrough": [14, 40]
}
```

`revision` is the client build and decides the era (`CacheEra`: legacy below 800, NXT from it).
`store` is the shape the cache is packed into by default; `pack --store` overrides it.
`passthrough` lists indices the tree does not hold at all: the audio indices are gigabytes nobody
wants in a repository, so a pack copies them verbatim from the cache the tree was unpacked from
(`pack --from`). A tree with passthrough indices is not self-contained; a tree with none is.

### `index.json`

```json
{
  "index": 19,
  "format": 7,
  "revision": 1787139004,
  "flags": ["lengths", "checksums"],
  "compression": "bzip2",
  "archives": {
    "0": {"version": 1787053638, "compression": "gzip", "fileCount": 256},
    "3": {"version": 1784730781, "compression": "bzip2", "fileCount": 256},
    "9": {"version": 1784730781, "compression": "gzip", "gzipLevel": 4, "fileCount": 256}
  }
}
```

The first block describes the reference table (its format, revision, flags and the compression of
its own container, with `gzipLevel`/`bzip2`/`lzma`/`lzmaProperties` when not the default). Each
archive line carries, always in this order and only when not the default:

- `version` - the full reference-table version
- `compression` - `none` | `bzip2` | `gzip` | `lzma`, always written
- `gzipLevel`, `gzipOs`, `bzip2`, `lzma`, `lzmaProperties` - how the payload was compressed
- `nameHash` - the archive's name hash, in indices whose table carries names
- `file`, `fileCount`, `files` - the file ids, for codecs whose layout cannot spell them out
- `fileNames` - `{"<fileId>": <nameHash>}` for indices whose table names files
- `layout`, `layoutVersion` - the group layout when it is the offsets one
- `xtea` - the key of an encrypted legacy map archive
- `pristine` - `{"<fileId>": "<sha256 of the editable file>"}`, see below
- `payload` - the sha256 of the group whose compressed payload is kept beside it, see below
- `verbatim` - `true` for a multi-chunk group kept whole as `<archive>.grp`, see below
- `opaque` - `true` for an archive whose container was never opened

CRCs, whirlpools, lengths, checksums and the file ids of a codec that lays files out by id are all
derived from the files and never stored.

### The four sidecars

- **`<archive>.container`** (`opaque`): the container as the cache holds it, minus the trailer, for
  an archive nothing can open - a legacy map archive whose key was never published - or one the
  unpack was told to leave closed (`--opaque <indices>`), the cheapest exact form of an index nobody
  wants to decode.
- **`<archive>.payload`** (`payload`): the compressed payload of an archive that opened fine but
  whose payload no encoder here reproduces. The group is still unpacked into editable files; the
  sidecar is emitted while the group still hashes to the recorded guard and recompressed once it
  does not. Zero of these exist for the 727 and 949 caches; the mechanism is what keeps parity
  when a future packer does something new.
- **`<archive>.grp`** (`verbatim`): a group stored in several chunks whose codec would rejoin it as
  one - the NXT skeletal animation index keeps three chunks per group (header, flags, values) - kept
  whole, chunk table and all. The framework keeps such a group itself whenever the codec does not
  declare it preserves the split, so a chunked index can never silently lose parity.
- **`<file>.pristine`** (`pristine`): the shipped bytes of one file whose codec could not reproduce
  it - a definition whose encoder is not yet exact, a clientscript the decompiler normalises. Emitted
  while the editable file still hashes to its guard, compiled once it does not. `cacheSource status`
  counts them per index; the goal is zero and the count can only shrink.

### Codecs

Each index is unpacked by one `SourceCodec`, which owns the layout under the index directory and the
two directions (`unpack(group) -> files`, `pack(files) -> group`), answers which archive a path
belongs to (so an incremental build knows what to repack), and may write index-level files through
`unpackIndex`/`packIndex`. `SourceCodecs` maps index to codec in two layers: built-ins per era, and
explicit registrations that replace one. Every codec lives in the cache library itself, the
clientscript compiler included, because packing a tree back into a cache is what a server does on
startup and not only what the tools CLI does - a codec that only the tools module had would leave the
server unable to build the very index it was asked to serve. Codecs are told the tree's era and can
read its gameval catalogs through `SourceCodecs.context`.

| codec | layout | used for |
|---|---|---|
| `raw` | `<archive>.dat`, or `<archive>/<file>.dat` for a multi-file archive | every index nothing better exists for; the default |
| `raw` typed | `<archive>.jagmidi` / `.jagpatch` / `.ttf` / `.otf` | the legacy midi indices and the NXT font index, whose files are their own format |
| `audio-stream` | `<archive>.json` + `<archive>/<position>.ogg`, or `<archive>.ogg` for a bare chunk group | indices 14 and 40: the `JAGA` container's header and chunk table, whose group-id column names sibling chunk groups; every group of both indices reproduces |
| `skeletal` | `bases/<id>.json`, `anims_rt7/<archive>.json` (all frames, the file id as time), `anims_keyframes/<id>.json` | indices 1, 48, 56, from `skeletal-animation-formats.md`; the three-chunk split of index 48 is rebuilt from the frames, and the 54 groups whose framebase is a stub stay `verbatim` |
| `gltf-model` | `models_rt7/<id>.glb` | index 47, the RT7 model as a glTF 2.0 binary with everything glTF cannot say in `extras.rs` (`rt7-model-format.md`); the six shipped models whose index count overflowed keep a pristine sidecar |
| `worldmap-area` | `worldmap_area_data/<area>/area.json` + `elements.json`, `worldmap_area_coords/<area>.json`, directories named through the solved area-name formula with the hash in `index.json` the truth | indices 41 and 42 (`nxt-worldmap-audio-formats.md`) |
| `config` | `config/<archive name>/...` | the config index: one directory per archive, each with its own sub-codec, named in the gameval vocabulary per era |
| `gameval-catalog` | `gamevals/<type>.json` | the NXT gameval index, written as the catalogs everything else reads |
| `json-*` (57 types) | `config_obj/4151.json`, `config/param/12.json`, ... with a `gameval` name beside the id | loc, enum, npc, obj, seq, spotanim, struct, 29 config archives and the twenty-one record types of the indices below; every one byte-exact over the whole 949 cache through the ported `OpcodeOrdered`/`OpcodeEncoder` mechanism |
| `map-json` | `maps/<x>_<y>/terrain.json`, `locs.json`, `environment.json`, `lights.json`, `patches.json`, `npcs.json`, `underwater_locs.json`, `legacy_terrain.json`, `legacy_underwater.json` | index 5: one directory per map square and one file per file the archive holds, the region read off the archive id rather than a name hash - index 5's reference table carries neither names nor hashes. Tiles and terrain cells are token lines, one row per line; locations, npc spawns, lights and patches are one object per line, in file order. All 41,271 files of the 949 cache are byte-exact |
| `component` | `interfaces/<interface>/<component>.json`, named through the `component` catalog | index 3: one interface per directory and one component per file, positional rather than opcode keyed |
| `worldmapdata` | `worldmapdata/details/29.json`, `coords/29.json`, `image/29.png`, `colours/<square>.json`, `composite/29.png` + `.json` | index 23's five archives are five unrelated things; the two PNG archives stay images and the composite's overlay table is decoded beside its image |
| `dbtableindex` | `dbtableindex/<table>/<column>.json`, the table named through the `dbtable` catalog | index 49: an archive is a table and a file is one indexed column |
| record codecs | `fontmetrics_legacy/494.json`, `fontmetrics/<id>.json`, `materials/<id>.json`, `quickchat/quickchatphrase/113.json`, `config_particle/producer/1.json`, `defaults/group7.json`, `config_billboard/<id>.json`, `loading_screens/<id>.json`, `cutscenes/<id>.json`, `config_achievement/<id>.json`, `binary/huffman.json`, `stylesheets/<id>.json`, `particle_effects/<id>.json`, `anim_state_machines/<id>.json`, `ui_anims/<group>/<id>.json`, `cutscene_overlays/<id>.json`, `config/archive_31/<id>.json`, `config/archive_76/<id>.json` | indices 10, 13, 24, 26, 27, 28, 29, 33, 35, 57, 58, 60, 61, 62, 65, 66 and config archives 31 and 76; see `record-index-formats.md`, `nxt-misc-formats.md` and `nxt-config-archives.md`. The eight remaining config archives are dead single-byte terminators and stay raw |
| `graphic-png` | `graphics/<archive>/<frame>.png` | indices 8, 32, 34: one full-canvas RGBA PNG per frame, with the palette, frame box and storage order in private `rsPL`/`rsFR`/`rsIX` chunks; a stripped PNG is rebuilt from its pixels |
| texture codecs | `textures_dxt/<id>.dds`, `textures_png/<id>.png`, `textures_png_mipped/<id>/<level>.png`, `textures_etc/<id>.ktx` (cube maps as `<id>/<face>...`) | indices 52 to 55: the client's framing is a face count and per-image lengths, all derived |
| `cs2-source` | `clientscripts/<category>/<name>.ts` + `cs2.d.ts`, `vars.d.ts`, `tsconfig.json` | index 12 as the decompiler's TypeScript project, named through the `clientscript` catalog and compiled back on pack; all 21,097 scripts of build 949 compile back byte-identical. The compiler behind it is the cache library's own, so a server repacks the index exactly as the CLI does; the CLI keeps only its interactive surface - the command line, the calibrator, the hot reloader and the interpreter |

The exact registrations are `NxtCodecs` and `SourceCodecs.installLegacy`; the per-index status of a
real tree is `cacheSource status`. Indices 61, 62 and 66 zero-pad every group to a ceiling; the
padding count is a field of the record so the group comes back exact.

### Gamevals

The catalogs are cache assets and live in the tree. The NXT beta host serves them as index 67, and a
tree unpacked from it gets them through the gameval codec, one type per archive in exactly the format
`re-resources/gamevals` has always used (lower case names under `entries`, components keyed
`<interface>:<component>`, a combined var archive split into the domain's vars and its varbits with
the split's offset recorded). A tree unpacked from the live host, which has no index 67, is seeded
from `GAMEVAL_PATH`. Either way every typed codec reads the catalogs to write a `"gameval"` name
after each id it unpacks - a display aid the pack ignores, never a source of ids.

## Serving from a tree

| variable | default | meaning |
|---|---|---|
| `CACHE_PATH` | `./data/cache` | the prepacked cache the server serves, and the cache passthrough indices are copied from |
| `CACHE_SOURCE_PATH` | unset | a source tree; when set the server builds it on startup and serves the build instead |
| `CACHE_BUILD_PATH` | `./data/cache-build` | where that build goes (gitignored, with a manifest of what it was built from) |

The switch is `org.projectx.core.cache.CacheSource`: every default cache open goes through
`servedPath()`, which is `CACHE_PATH` unless a tree is configured, in which case `ensureBuilt()`
runs first - a full pack the first time, an incremental rebuild of only the archives whose files
changed afterwards, a stat walk when nothing did. The packed cache stays the default; the tree is
opt-in.

Compiling a clientscript resolves each call against its callee's signature, so the codec analyses the
whole corpus before it packs any of it, and it cannot read that corpus from the cache the build is
still writing: `ensureBuilt` points it at `CACHE_PATH` first. That is the only thing a tree with no
passthrough indices still needs the prepacked cache for.

Two rules keep that from deadlocking, and both are load-bearing. The corpus is built in the codec's
`packIndex`, on the single thread that calls it, never lazily by a packing worker - a worker that
built it would hold the codec's monitor while decoding config records. And nothing under a pack may
ask for the process-wide cache: a server runs the whole build from inside `Cache.get()`, so for its
duration the process has no cache and the monitor that would make one is already held. The records
the CS2 work needs therefore come from the corpus's own cache, through `Cs2Records`.

## Tools

```
./gradlew :tools:cacheSource -Pargs="unpack  [--cache <dir>] [--tree <dir>] [--indices <sel>] [--passthrough <sel>] [--opaque <sel>] [--xteas <file>]"
./gradlew :tools:cacheSource -Pargs="pack    [--tree <dir>] --out <dir> [--from <cache>] [--store sqlite|sector]"
./gradlew :tools:cacheSource -Pargs="build   [--tree <dir>] --out <dir> [--from <cache>]"
./gradlew :tools:cacheSource -Pargs="verify  [--tree <dir>] [--cache <dir>]"
./gradlew :tools:cacheSource -Pargs="status  [--tree <dir>]"
./gradlew :tools:cacheSource -Pargs="convert --cache <dir> --out <dir> [--store sqlite|sector]"
```

`--cache` defaults to `./data/cache` and `--tree` to `./unpacked-cache` (gitignored until it becomes
a repository of its own). `convert` copies a cache between the two stores container for container -
a legacy sector cache becomes SQLite databases, and back, losslessly. The library itself is
`world.gregs.voidps.cache.store` (containers, tables, groups, the two stores, the converter) and
`world.gregs.voidps.cache.source` (the tree, the unpacker, packer, builder, verifier and codecs).

Every cache is opened read-only for an unpack (`immutable` for a SQLite store: no lock, no sidecar),
and a pack refuses to write into a client-owned cache directory.
