# The record indices: interfaces, fonts, materials, world map, quick chat, achievements and the rest

Twelve JS5 indices of the NXT cache hold *records* rather than images, models or scripts: index 3
(`interfaces`), 13 (`fontmetrics`), 23 (`worldmapdata`), 24 (`quickchat`), 26 (`materials`),
27 (`config_particle`), 28 (`defaults`), 29 (`config_billboard`), 33 (`loading_screens`),
35 (`cutscenes`), 49 (`dbtableindex`) and 57 (`config_achievement`). Each is unpacked into one
editable JSON file per record by the cache source tree (`CACHE_SOURCE_TREE.md`), and every one of
them re-encodes to the shipped bytes, so nothing in this file rests on a guess about a field's
presence or width — an encoder that got one wrong would fail parity on the first file that used it.

This document is about the *shapes*: which archive holds what, whether a record list is opcode keyed
or positional, and the invariants a reader can rely on across a client update. Per-build values -
opcode numbers, field indices, addresses - live in the Ghidra DB and nowhere else.

## The two grammars

Every record index uses one of two grammars, and which one it uses is a property of the index rather
than of the record:

**Opcode keyed.** A list of `opcode, payload` records terminated by a zero opcode. The payload width
is a function of the opcode alone. Indices 24, 28, 29, 57 and both archives of 27 are this shape,
as are the config types of index 2. Two things about such a file survive nowhere in the decoded
fields — the order the packer emitted the records in, and the payload of a record a later record of
the same opcode overwrote — so a byte exact writer has to be able to replay both
(`OpcodeOrdered`/`OpcodeEncoder`). Order matters in practice: most files of every one of these
indices follow one canonical order, and a minority permute it.

**Positional.** Fields read in a fixed sequence to the end of the buffer, with no opcodes and no
terminator; optional blocks are gated on a version byte or on a flag word read earlier in the same
record. Indices 3, 13, 23, 26, 33, 35 and 49 are this shape. Every file of every one of them ends
exactly at end of buffer.

## The read path never derives

The client's own decoders routinely fold, scale or invert what they read: a texture size code becomes
a pixel count, two floats become their reciprocals, a packed byte becomes two bit fields, a sentinel
becomes -1, three ints become floats. **None of that is invertible**, and a definition re-encoded
after it no longer matches its file. Every decoder here therefore stores the file's own value and
leaves the derivation to whoever consumes it, exactly as `changeValues` is kept out of the read path
for the config types. Where a fold *is* exactly invertible - an alpha byte that is its own inverse,
a `0xffff` that means "none" - the encoder inverts it and the field carries the friendly value.

A record whose absence cannot be told from a default value is a **nullable** field rather than a
sentinel, so presence is a null check and never a guess. This matters more than it sounds: index 28
carries fields whose legitimate value is the same bit pattern a `-1` sentinel would use.

## Index 3 `interfaces`

An archive is one interface and a file is one component; the reference table is unnamed and the
component's own id is the file id. The record is positional and driven by a leading version byte,
with a distinct "legacy" value that behaves as -1; the settings field is three bytes below a
threshold version and four above it, with an extra byte above a higher one.

The header byte carries the component type in its low seven bits and a "has debug name" flag in the
top bit. The type selects one of twelve content blocks - layer, rectangle, text, graphic, model,
line, a compound type, panel, checkbox, input, grid and dropdown - and no other value occurs. Text
and graphic blocks are shared: the text block *is* the whole payload of a text component, and input
and dropdown additionally embed a "graphic triple" of four bytes and three graphic blocks.

Then, in order: key bindings as a zero terminated list whose header byte packs a slot in the high
nibble and the top bits of a twelve bit modifier in the low nibble; the name; a byte whose two
nibbles are the option count and the mouse icon count (the icon count selects "read one pair" or
"read a second pair" and is not a loop); the drag and target fields; the component parameters; the
script hooks; and five trigger lists back to back, each a count byte and that many ints.

**Component parameters are not the opcode keyed parameter block the config types use.** They are two
counted groups, ints first and strings second, and a string value is prefixed by a version byte
whose non-zero case yields an empty value and consumes nothing further.

**Script hooks** are written one per slot in a fixed slot order with three version gated extensions,
and an absent hook is a single zero count byte rather than an omission. Each entry is preceded by a
type tag; the first entry's tag is consumed and ignored and its payload is the script id, and later
entries read an int for one tag, a string for another, and nothing at all for any other. Only the
int and string tags occur, so an argument's tag is recoverable from its value's type.

## Index 13 `fontmetrics`

One archive per font - the archive id *is* the font id, and this reference table does carry archive
names - holding a single file. The record is positional and fixed length: two leading bytes, three
256 entry unsigned byte tables (glyph advance width, glyph height, glyph top offset) indexed by
cp1252 code, the atlas width and height, two 256 entry unsigned short tables (glyph atlas X and Y),
and six trailing bytes.

The six trailing bytes are **per-font constants, not derived**: they were tested against every
plausible derivation from the glyph tables (extremes, cap and x heights, ascent plus descent sums)
and none holds across the corpus, so they must be carried as data. The glyph *bitmaps* are the
graphic group of the same id in index 8, so a font is one file in each index.

The client exports a complex-kerning loader, so the format has an optional kerning block, but no font
in the served cache carries one - every file is the fixed length form. That is worth re-measuring on
update day rather than assuming.

## Index 23 `worldmapdata`

Five archives, addressed by literal id, with an unnamed reference table; archive names are not
recoverable and the tree names the directories itself. Four archives are keyed by **map area id** and
one by **map square id**.

| archive | tree name | keyed by | what it holds |
|---|---|---|---|
| 0 | `details` | map area | the area's definition |
| 1 | `coords` | map area | how world map squares and zones map onto the drawn area |
| 2 | `image` | map area | one whole PNG |
| 3 | `colours` | map square | the square's per-zone area colours |
| 4 | `composite` | map area | a length prefixed PNG followed by an overlay table |

One map area object is built from archive 0 and archive 1 of the same file id in a single client
constructor, which is what establishes that the two are the same thing seen twice.

**Details** is positional: two null terminated cp1252 strings (the internal name and the shown name),
a packed coordinate, a colour int with a "none" sentinel, a boolean byte, a kept byte, one byte the
client skips but which is non-zero in some files and therefore has to be carried, and a byte counted
list of 17 byte sections. A section is a level and two rectangles - a world rect and an area rect,
four shorts each - which the client stores as an origin and an extent. The area's bounding box is the
extremes of its sections and is derived, not stored.

**Coords** is positional: a short counted list of eleven byte map square links, a short counted list
of fifteen byte zone links, then the area's width and height in map squares. Each link carries a
level, a source square (and, for a zone link, a source zone), and the destination square and zone
that feed the area's bounding box. The link levels always match the details sections' levels, and the
width and height always equal the span of the details sections' area rects.

**Colours** is a run length grid over a map square's 64 zones, laid out X major in an 8x8: a three
byte colour then a one byte run length, and **the final run carries no length** - it runs to the end
of the grid. Run lengths are never zero and never the whole grid.

**Composite** is a four byte big endian length, exactly one PNG of that length, then a table of
fourteen byte overlay records - an unestablished int, two argb colours whose alpha is only ever fully
opaque or fully transparent, and a trailing short. The length is derived from the PNG's own size and
is not stored in the tree.

## Index 24 `quickchat`

Two archives and nothing else: the categories/menus in one and the phrases in the other, both flat,
one file per id, both opcode keyed. Index 25 `quickchat_global` holds the same two types; at runtime
the client tells them apart by setting a high bit on every id it reads out of the global index, which
is a consumer derivation and not in the files.

Hotkeys in both archives are single cp1252 bytes with zero meaning "no hotkey". A category title is a
plain string, not a versioned one.

A phrase's text is stored **split on the delimiter that introduces a dynamic value**, one fragment per
value slot plus a trailing fragment, which is exactly what the client does and is exactly invertible;
fragments therefore always number one more than the parameters. Each parameter is a value type id
followed by however many shorts the client's dynamic command table says that type carries, and a type
the table does not cover carries none - which is what the client does too, and is recorded rather
than assumed.

Both types have a bare flag record, and **their polarity is opposite**: the category's sets a boolean
that defaults false, the phrase's clears one that defaults true. The phrase packer emits its flag
record first, ahead of the text; the category packer emits ascending.

## Index 26 `materials`

One archive whose file ids are the material ids - a material definition *is* a single file of that
group, and there is no bulk record. A leading version byte selects one of two positional layouts, and
everything after it is driven by flag words: one layout has two flag words, one before and one after
a packed byte, and the other has one. All multi-byte fields are big endian. The second layout always
ends with one trailing byte the client reads and discards, and the first layout's tail block is gated
by a byte whose value must be exactly one.

Three client side derivations must not be baked into a round tripping decoder: the texture size byte
is a **code** that the client expands to a pixel size, two floats of one optional block are stored by
the client as their reciprocals, and the packed byte is split into two three bit fields, which throws
its top two bits away.

## Index 27 `config_particle` and index 29 `config_billboard`

Index 27 has **two archives with two different record grammars** - producers (emitters) and particles
(the force fields a producer's output is deflected by) - sharing nothing but the opcode/payload/zero
terminator envelope. Index 29 is a single archive, one file per billboard, which is what a model's
footer pins to a face.

All three are pure record lists with **no cross-field conditionals anywhere**: no field's presence or
width depends on anything read earlier other than its own leading count. Three list shapes occur in
the producer grammar - a count byte then that many shorts; a count byte then that many two byte
records and a two byte trailer; and the same with three byte records - and all observed counts are
small. Where a sub-record has no attested meaning its payload is carried verbatim, count byte
included, rather than decomposed into invented fields.

Record order is not fixed in any of the three: most files follow one canonical order and the rest
permute a handful of the zero length flags, so a byte exact writer must be able to replay the file's
own order. A few producer files and a couple of particle files repeat an opcode, the later record
winning, so the earlier payload has to be kept.

Structurally, a producer's angle ranges are bounded at the RS angular units and its speeds are
16.16 fixed point; two of its records are packed colours. No sentinel and no off-by-one storage
appears in any billboard of the served cache, so if the client applies either it is a derived value
and belongs outside the read path.

**The client's decoders for both indices could not be located.** The archive handles reach the
graphics side only through the bundle assembled at render core construction, and a sweep of every
sizeable function in `.text` found no opcode switch for either grammar - the only small integer
switches in the binary are the known config type decoders. Given how regular the grammar turned out
to be, the likely explanation is a **table driven reader** whose switch is over a field type code
rather than over the opcode, so there is no opcode switch to find; the next step is the descriptor
table in `.rodata`, not another function sweep. Both formats above are therefore derived from the
bytes and validated by exact consumption of every file.

## Index 28 `defaults`

Eleven archives of eleven unrelated settings files, one file each, all opcode keyed, and **the same
opcode means a different thing in every one of them** - so each archive gets its own type. Two of the
eleven are a single terminator byte, which must round trip to one byte.

There is no name for any of them: RTTI is stripped, every archive descriptor stores an empty name,
and the group ids are raw literals, so naming them would be invention and the tree numbers them
instead. Two are semantically certain from the client - one is the light source table and one is the
skill and experience curve table - and one is the equipment slot table the server already reads. The
client decodes eight of the eleven; three are served but never fetched.

Two records take their length from a *different* record of the same file rather than carrying a count
of their own, which fixes an emission order: the record that sizes the other has to come first. That
is the only place in any of these twelve indices where one record's width depends on another.

## Index 33 `loading_screens`

The first archive is the master table and every other archive is a counted element list; which shape
a file is is decided by its archive id. The master carries a format byte, a per render type
signature, and a block of timing-shaped values. An element is a type byte and a body, and the element
types that occur share a common five byte block (a stage, an alpha and some flags); one of them
leads with a null terminated string.

Everything the client checks and then folds is kept raw - the format version and the render type
signature it bails out on, flags as the bytes they are rather than as booleans, and anchors and
alignments as their ordinals.

## Index 35 `cutscenes`

One archive per cutscene, one file each, positional. A header - a format byte, an aspect width and
height, and a terminator byte - then five counted lists (the map areas the cutscene assembles, the
camera paths, the actors, the objects, and the actor paths) and a smart counted action list.

An area's packed coordinate is a plane, a world x and a world z; that reading is cross checked because
the packed plane always equals the separate plane byte and the chunk offsets move x and z by exactly
one zone per chunk. An actor is a kind byte and then either a type id and a null terminated label or
a label alone - and **the label is read and discarded by the client**, so without keeping it the file
cannot be rebuilt at all. An action is a type byte, a duration, and a body; durations are non
decreasing and the last action of every file is the terminating type, whose duration is the total.

**One signed-versus-unsigned smart reading is decisive rather than cosmetic.** The movement action's
trailing field is the *signed* one or two byte smart: read signed, every value in the corpus lands
inside the engine's angle range, with a meaningful number of them exactly zero; read unsigned they
would all sit in a band with no meaning. Reading the same field as two fixed bytes produces a phantom
action type and makes a sixth of the files unparseable - the one byte form is the whole difference.

**Neither index 33 nor index 35 has a decoder in the current client.** The master index constructor
is the only place archive descriptors are made and its literal index set omits both, so there is no
fetch path and therefore no action dispatch table to read. Both formats are derived from the bytes
alone and validated by exact consumption of every file, and every action type described above
actually occurs - none rests on the client and there are no dead ids to fail on.

## Index 49 `dbtableindex`

One archive per dbtable and one file per indexed column, so a table indexes as many columns as it has
files. Positional. An optional version marker byte and version follow; when the marker is absent the
record is the older version, which is exactly how the client tests it.

Then a var-int field count, and per field a value type tag, a var-int distinct value count, and per
value the typed value plus a var-int row id count and that many var-int row ids. Above the older
version a trailing block follows: a flags byte of which the client keeps only the lowest bit, a
var-int entry count, and per entry a tag, a value count, a row id count, that many values ascending,
that many var-int row ids concatenated in value order, and one var-int run length per value. **The
ranges' starts and ends are an accumulation of those lengths and are not stored.**

Value encodings are a four byte int, an eight byte long, a null terminated cp1252 string, and a
compound of a byte and three four byte ints - which the client converts to floats, a one way
conversion that must not be stored. Every var-int in the served cache is minimum width, so a plain
var-int writer reproduces them; a cache that ever wrote one wide would need the width recorded.

## Index 57 `config_achievement`

Archives of up to 128 files each, opcode keyed, with the achievement id split across the archive and
the file id.

**Every requirement record begins with a group index byte.** Seven requirement kinds - a skill level,
a varp counter, a varbit counter, a varp value, a varbit value, an achievement link and a quest link -
each exist in *two* forms: a grouped form, which the client buckets into a vector indexed by that
byte, and a flat form, which it appends in order keeping the byte as a field. The two forms are
separate records with the same wire shape, so an encoder has to put each back under its own record
kind rather than merging them. All four record shapes fill one shared client struct; the link shape
leaves the amount and value unset and the text empty, and only the value shapes fill a trailing byte.

Two group target lists - one over the grouped records, one over the flat - hold, per group, how many
of that group's records must be met, each paired with a count of how many groups the achievement
needs. The client fills both in when they are absent, a zero element meaning "all of this group", so
they are stored as read and the completion is left to the consumer.

Outer record counts are one or two byte smarts and the counter kinds' amounts are two or four byte
smarts that reach into the millions. All strings are versioned and every served file leaves the
version byte at zero.
