# CS2 clientscripts — format, toolchain, and naming provenance

> How the clientscript index works, how our decompiler/recompiler is structured, and — the part
> that matters most — **where every name in the output comes from**.
>
> ⛔ No opcode ids, addresses or offsets in this file. Those are per-build facts and live in the
> Ghidra DB and in the generated, gitignored tables. This describes mechanism only.

## Why this index is special

Clientscripts are the largest scripted surface in the cache and the one that changes most in a
content update. Two properties make them uniquely awkward:

- **The index carries no meaningful version.** Its reference-table version field is inert, so a CRC
  is the *only* signal that anything changed. You cannot tell what a script update did without
  decoding it.
- **The opcode set is per-build.** Opcode ids differ between client builds, so a table derived from
  one build is worthless against another.

Together those mean: without a working decompiler, a CS2 update is completely opaque to us.

## Container layout

A script is read partly from the front and partly from the **end**. The counts and switch tables are
a *footer*, not a header — treating them as a leading header mis-slices the instruction stream on
every script.

```
front:   name (NUL-terminated, or a lone zero byte when absent)
         instruction stream — a 2-byte opcode followed by a per-opcode operand
back:    a trailing size field, then the switch block, then six counts, then the instruction count
```

The six counts are **locals first, then arguments**, each triple ordered int, string, long. The
trailing size field covers the switch block but excludes itself. Both of those are easy to get
backwards and both fail silently — the parse succeeds and every value is wrong.

Arguments are copied into the front of the locals, so `localCount >= argCount` per type is an
invariant you can assert across the whole corpus. It holds on every script, which makes it a cheap
check that your footer ordering is right.

**The container needs no opcode knowledge, and that is the module boundary.** Because the footer
locates the end of the instruction stream by working backwards from the trailing size field, the
name, the counts and the switch tables can all be read and rewritten without knowing how wide a
single instruction is. The cache library therefore owns the framing and carries the instruction
stream as an opaque blob; the width-aware walk across that blob stays with the toolchain that owns
the per-build width table. One parse of the container, one place that needs recalibrating on an
update.

## Operand widths

Width is **not** a range test on the opcode and **not** derivable from the opcode alone. The client
holds a per-opcode flag in its dispatch table, and consults it only *after* special-casing a few
families:

- the variable/varbit push and pop pairs, which carry a domain or id plus a trailing byte;
- a single **type-tagged constant push** — one opcode, then a tag byte selecting int, long or
  string payload. There is no separate push-int / push-string / push-long triple, and an
  implementation that assumes one cannot represent this at all;
- everything else: wide flag set means a four-byte operand, otherwise one byte.

A useful mental model: **every opcode carries at least one trailing byte unless it is wide**; the
special cases prepend extra fields rather than replacing that byte.

### Two independent ways to recover the table

Both were run, and they agreed on every opcode they both covered. Doing only one is a mistake:

1. **From the binary** — extract the dispatch table directly. Authoritative, and covers opcodes the
   corpus never exercises.
2. **From the corpus** — a constraint solve. A script's instruction stream must consume *exactly*
   the bytes between the name and the footer **and** yield *exactly* the declared instruction count.
   Where only one width fits, the width is proven.

The corpus solve cannot reach opcodes that never appear in any script, and it leaves genuinely
ambiguous opcodes — ones whose widths trade against each other — unresolved. Those limits are real,
not solver defects; the binary settles them. Conversely the corpus solve is what proves the binary
table against real data.

Techniques that made the corpus solve converge: process shortest scripts first so common opcodes
pin cheaply; feed global cardinality limits back in *during* propagation rather than after; and vote
only from stream positions that every valid parse must cross.

## Opcode names: the attestation mechanism, and why most opcodes have none

A CS2 opcode's name is recoverable from the client **only** when its handler passes its own name as a
string literal to the opcode-error constructor. That is the entire mechanism. A handler with no failure
path never constructs an error, therefore never references its name, therefore cannot be named from the
binary at all — no amount of further reading changes that.

This is not a hypothesis. Two independent passes read the thirty highest-volume unnamed handlers and
returned **zero** attested names between them, with the great majority having no error call whatsoever.
Treat the ceiling as measured: for an opcode in that state the honest output is its number, and any name
is invention.

**Three ways an error call can fail to yield a name** — all three found in this binary, each of which
will produce a false attestation if you check carelessly:

1. **A runtime string.** One handler passes a data record's *own* name field. The error text is the
   record's name, not the opcode's.
2. **A non-string argument.** One passes a bare integer where the pointer would go.
3. **Pooled literals.** Sibling opcodes share one string at different offsets, so a handler may load a
   pointer that is not a string start — reading from the middle of a longer literal. A plain string
   listing will not show the shorter name and will wrongly condemn a genuine one.

So the test is narrow: the argument must be a load of a read-only-data pointer, near the call. Presence
of the call proves nothing on its own.

⚠️ **Do not use naming *style* as a verdict.** It is tempting, because fabricated names in this DB have
tended to be written in a different case convention from the attested ones, and that screen does find
real fabrications. But the binary attests names in the "wrong" style too — verified byte-for-byte in
read-only data. Style is a screen for deciding what to check; the literal is the only verdict.

**When you do remove a name, prove the absence rather than assuming it.** The strongest evidence that a
batch of removals is safe is a corroborating negative: search the whole binary for the family the names
belong to and show it contains no such literal anywhere. That converts "we could not find attestation"
into "attestation does not exist", which is what justifies the deletion.

Reverting an unattested name to an unnamed function, with its behaviour recorded in a comment, is a
**good** outcome. An unnamed function that says what it does is strictly better than a plausible
fabrication, because the fabrication will be read back by a later pass and cited as evidence.

## Naming provenance — the important part

Names come from four places, and the distinction between them is load-bearing:

| tier | meaning |
|---|---|
| **canonical** | a literal string in *the binary we ship against*. Strongest. |
| **derived** | a mechanical split of a canonical string by a rule with independent corroboration. |
| **reference** | **Jagex-authored, recovered from an older build's debug symbols and matched to this build behaviourally.** Jagex's word, but not from this build. |
| **structural** | a descriptive name *we* assigned from handler behaviour. Ours, not Jagex's. |

An opcode with none of these renders as a number.

⚠ **Order these correctly.** The precedence chain once ranked *structural* above *canonical*, so a
name we invented outranked one Jagex wrote. That inversion is invisible while the two happen to
agree and silently wrong the moment they do not.

### The reference binary is a legitimate name source — and only a name source

The shipped binary contains no opcode name table. That is not the end of the line: an older
unstripped build carries Jagex's own C++ method names as debug symbols, and those cover families the
current build names nowhere. The project rules already sanction that binary for symbol discovery and
code-pattern comparison, while banning it as a source of concrete data — which is exactly this use.

**Take the name; derive every value locally.** The reference's own event-slot numbers were *wrong*
for the current build — one block sits three slots lower there — so copying them would have
mislabelled the entire family. The names came from the reference and every slot number from the
target, each then tied to an independently named handler.

That distinction is the whole discipline. A name is a label Jagex chose and tends to survive a
rebuild; a number is a coordinate that does not.



**The client contains no opcode name table and no script-var-type name table.** This was checked
exhaustively and is a hard negative: the iconic names are not present as bytes, every
lowercase-identifier string in the binary is referenced from code, and the dispatch entry has no
name field.

What *does* exist: each handler's error path loads a pointer to a Jagex-authored name string before
tail-calling the error constructor. The release build discards it, but the load is still emitted —
so roughly a quarter of the opcode names survive as **dead arguments**, byte-for-byte.

That yields three tiers, and the distinction must survive into the code and the output:

| tier | meaning |
|---|---|
| **canonical** | the literal string from the binary |
| **derived** | a mechanical transformation of a canonical string, by a rule with independent corroboration — recorded in a *separate* field, never merged into canonical |
| **none** | rendered as a stable numeric form |

⛔ **An opcode with no recovered name gets a number, not a guess.** Importing names from third-party
tooling would look like progress and would be indistinguishable, in the output, from knowledge.

The same rule governs the type system: the client stores each script var type's **legacy type
character** but no human name. The character is the real identity and the join key; a human label is
only applied where a source we own supplies one.

## Script names are in the cache, as hashes

The clientscript index sets the reference table's **names flag**, so every script carries a name hash —
not a name. That is a Jagex-authored name source hiding in plain sight, and it is worth knowing three
things about it.

**The hash is the ordinary Java string hash** — accumulate `h = h*31 + c` over the name's CP1252 bytes
and read the result as a signed 32-bit int. Don't take that on trust from this document: it is provable
in a closed loop, because another index also sets the names flag *and* we independently hold its names
in the gameval tables. Hashing those names and comparing against the stored hashes either matches every
single entry or it doesn't. When this was checked it matched all of them, which pins the algorithm, the
encoding and the signedness at once. Re-run that check on a new build rather than assuming it carries.

**The hashed string includes its category and its brackets** — the form is `[category,name]`, and the
two categories observed are the ones you would expect for scripts and procedures. The bare name and the
post-comma substring both fail to match anything, so this is not a detail you can shrug off: get the
wrapper wrong and a correct name looks like a miss.

**A hash match is proof, and that changes what a third-party dump is good for.** Ordinarily an outside
dump has no authority here. But once you hold the oracle, an outside dump becomes a legitimate
*candidate generator*: it proposes, our hash disposes, and a name that survives is confirmed by our own
verification rather than by anyone's say-so. The same applies to generated candidates — a name built by
crossing a vocabulary with a grammar is a guess until it hashes, and a fact afterwards.

Two things the names are **not** in, both measured rather than assumed: the gameval tables (using their
entries verbatim as script names finds essentially nothing beyond coincidental collisions of short junk
strings) and the client binary's string table (likewise). Recovery has to come from candidate
generation.

⚠️ **Expect coincidental hits.** A 32-bit hash across tens of thousands of targets will collide, and the
collisions have a recognisable shape — very short strings, or strings that are not plausibly a name at
all. Sanity-check accepted matches for name-shape, and if two candidates hash to the same target, record
the ambiguity instead of choosing. Any script whose name is not recovered stays numeric: a placeholder
that could later be mistaken for a real name is worse than no name.

### Cracking the names: what actually worked

Brute force is hopeless — real names are long — but the hash is **algebraically invertible**, and that
changes the problem completely. Because the accumulator satisfies `h(x+y) = h(x)·31^len(y) + h(y)` and
the multiplier is odd (hence invertible modulo 2³²), a script's target hash can be solved backwards for
the *exact hash the tail must have*, once per candidate head and length. Head×tail stops being a product
to enumerate and becomes a dictionary lookup. That is the difference between a search that cannot finish
and a full pass over every script in well under a minute.

**Candidates should come from each script's own body, not from a global word list.** A script that
manipulates a given interface is overwhelmingly likely to be named after it. The single largest jump
came from decoding the **interface hook bindings** out of the interface index: those yield both the
interface name and the hook slot it is bound to, and the slot is very often the name's tail. Tails mined
from already-confirmed names feed the next round, so the process bootstraps — each round's output widens
the next round's vocabulary.

**Measure the false-positive rate, don't estimate it.** Run the identical pipeline against *randomised*
target hashes: every hit it produces is by construction noise, so the count is a direct measurement of
what that tier contributes in collisions. Tiers whose control runs hot get filtered or dropped, and the
clean stopping signal is a round whose real yield falls to its control yield. A tier that finds a
hundred names and a hundred phantoms has found nothing.

Beyond the arithmetic, **a correct hash on an implausible string is more likely a collision than a
discovery**. Cross-check accepted names against what the script actually does; several names that hashed
perfectly were verbatim unrelated content identifiers whose bodies contradicted them outright, and they
belong out of the table however well they verify.

⚠️ **The format carries a name field of its own, and it is empty.** Every script ships it blank, which is
precisely why only the hash survives to be cracked. It is still a real field with a real round-trip
channel, so writing recovered names into it re-encodes them into the bytes and breaks byte-identity
wholesale. Recovered names belong in the header line; the format's own field stays reserved for the
format.

Worth re-running after every game update: new content ships new scripts, and their names reuse existing
families, so the bootstrap picks them up cheaply.

**Measured dead ends** — the gameval store has no clientscript table at all (its archives are fully
mapped and none of them is this), only the two categories exist (every alternative probed came back at
exactly the noise floor), and historical third-party snapshots contain nothing the current one doesn't.

## Rendering a packed integer needs its TYPE, not a lookup

The tempting way to make a numeric operand readable is to look it up in the gameval dictionaries and
use whatever hits. **That is worthless here, and actively dangerous.** The id spaces of the content
types overlap almost completely, so nearly every integer large enough to be interesting is a valid id
of a dozen different types at once. Measured across the corpus's switch labels, the overwhelming
majority resolved under *every* major type simultaneously. "Is this a valid id" therefore carries
essentially no information, and a lookup that tries tables in priority order would emit confident
wrong names at a scale no reader could audit — the worst possible failure, because the output looks
right.

The constraint is **type determination**, and the only ground truth is the argument slots the client's
own handlers type. Everything else is propagation: a value's type flows through the places it moves —
parameter slots, locals, variables, return slots — so a value that ever lands in one typed slot types
every carrier it touches. In practice **script parameters carry most of the work**, which is why
propagating across the call graph matters far more than it might look.

Two rules keep this safe, and both are load-bearing:

- **Type the switch, not the label.** A subject has one type and every label shares it. If the subject
  is undetermined, every label stays numeric — no per-label rescue.
- **A determined type that fails to name its labels is a wrong determination.** If the chosen table
  cannot name the cases, do not render the ones it happens to cover; abandon the whole switch. A
  partially-naming table is evidence the type is wrong, not an opportunity.

Carriers seen as two types are **dropped, never narrowed to the popular reading**. Worth knowing why
that matters more than it sounds: in practice almost nothing conflicts, because the evidence is sparse
rather than contradictory. Most determinations rest on a single typed slot. So the safety does *not*
come from conflict detection catching mistakes — it comes from the two rules above. Do not weaken them
on the grounds that conflicts are rare.

**Two independent confirmations that the propagation is right**, both worth reproducing on a new build.
First, run with no prior knowledge it rediscovers the language's own type-character alphabet purely
from how values flow — the letters the format uses to tag types fall out of the corpus rather than
being told to it. Second, it *corrected* pre-existing renderings: a couple of values that a shape-based
heuristic had been rendering as named components turned out to be packed positions. That is the
failure mode this section warns about, caught in our own output — a heuristic producing a plausible
name for the wrong type.

The honest limit: only a minority of opcodes carry handler-read argument types, and that is the sole
root of all determination. Most switches stay numeric simply because nothing in their script or their
callers ever puts the value into a typed slot. **Reading more argument types out of the handlers is
the lever that widens everything downstream** — it is worth far more per opcode than naming a rare
opcode, because each typed slot propagates.

## Making scripts readable

Two mechanisms, both reversible so that an edited script still compiles:

- **Gamevals.** Most operand kinds correspond to a gameval table, which gives Jagex's own dev name
  for an id. Names are unique per type, so the rendering is bidirectional. An id with no gameval
  name keeps its number.
- **Unpacking composites.** Several operand kinds are packed integers — an interface component
  carries both interface and component, a position carries level and coordinates. Spelling those out
  as constructors is what turns a wall of magic numbers into something legible.

Identity that must survive a rename lives **outside** the name: a script's id in its header comment,
a variable's id in the doc comment on its declaration. That is what lets an editor rename freely.

## Traps this format sets, all of which have cost real time

**A canonical name can describe only one of an opcode's behaviours.** The tagged constant push is
named, by Jagex, for the *string* case — yet the same opcode emits an int, a long or a string
depending on its tag byte. A disassembly listing that shows the name but omits the tag therefore
reads as though integers are being pushed onto the string stack. That misreading was made, acted
on, and had to be withdrawn. **Any diagnostic that renders a multi-behaviour opcode must show the
field that selects the behaviour.**

**A crash site is not a diagnosis.** A desync surfaces as an exception at some arbitrary later
field, so where the parse died tells you the record went wrong, not which field is misread. A
plausible bug found by reading our own source is a hypothesis; only the binary settles it. Twice a
confident local diagnosis turned out to be a symptom of an earlier problem entirely.

**Validate that a fix moved the number it was supposed to move.** A large batch of opcode stack
effects was recovered from the binary and changed *nothing* — the failing script set stayed
byte-for-byte identical, because those opcodes were never the blocker. The work still had value
(provenance that survives a build bump) but the diagnosis behind it was wrong, and only an
end-to-end re-measurement revealed that.

**A statistical ranking points at correlation, not cause.** The toolchain ranks opcodes by how
over-represented they are in failing scripts, which reads like a defect list. It is not one. Every
one of the four highest-ranked opcodes turned out to be *already correct* — they simply belong to
one family that co-occurs in the same handful of scripts as the real defect. Ranking narrows where
to look; only reading the handler decides whether something is wrong.

**Two independent derivations are worth the duplication.** Recovering the opcode table from the
binary and solving it from the corpus were run separately three times over. Every time, the
agreement confirmed something real, and every time the disagreements were genuine errors — twice in
the corpus solver, once in a hand-written table. A solver that agrees with itself proves nothing;
this is the cheapest way to find out that a table is wrong before it silently corrupts output.

## Where a value's type actually comes from

A variable push or pop **takes its stack from the variable's declared type**, and that type lives in
config data — it is nowhere in the instruction stream. A decompiler that infers the type from what
the corpus writes can only ever type the variables the corpus *writes*; on this cache that left
roughly two in five silently defaulting to the integer stack, which is the single largest cause of
downstream stack-underflow failures.

The declared type is a **numeric script-var-type id**, which resolves to a base primitive. Two
independent derivations were run against each other — the config declaration, and a stack-balance
solve over the corpus — and across every variable where both had an opinion there were **zero
disagreements**. Prefer the config declaration; keep inference as the fallback for the domains whose
config records are simply absent from the cache.

Two traps found the hard way:

- **A missing config record is not a declared type.** An absent record leaves the field at its
  sentinel default, which passes a naive "is it set?" filter and inflates coverage counts.
  Distinguish *declared* from *absent* before trusting a total.
- **The compiler needs the same type source as the decompiler.** Typing variables correctly on the
  way out while the recompiler still assumes integers turns string concatenation back into
  arithmetic — a byte-level round-trip failure caused purely by the two halves disagreeing.

Varbits carry no declared type: a varbit is a bit field of its base variable and is integer by
construction rather than by default.

## Fidelity contract

**Byte-identical round trip over every script is the acceptance gate.** Decompile, recompile, compare
bytes. Anything less is not a passing state.

Where structured control flow cannot reproduce a script's exact branch layout, the decompiler falls
back to literal block-by-block rendering with labels and explicit jumps, which always round-trips.
**Readability yields to fidelity**; that fallback exists on purpose and must not be optimised away.

Verify in layers so a failure localises: the codec alone first (it needs no opcode semantics, only
widths — if it is not exact, nothing above it can be), then an instruction census with jumps
excluded to separate a cosmetic layout difference from a gained or lost instruction, then the full
round trip.
