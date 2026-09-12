# Client engine changelog

Durable notes on what each NXT client build changed in the engine as reverse engineering found it,
and what that meant for the injected engine. Mechanism only: values live in the Ghidra database and
the generated offset tables, never here.

## 949-5 -> 950-1 (September 2026)

Jagex called this a large engine change. Measured against what the engine reads, it was a modest
set of layout changes, one subsystem refactor, and a container reorganisation. The protocol and
CS2 opcode tables were re-scrambled as every major bump does; those were re-derived and are not
repeated here.

### What changed in the client

- **Entity header reordered.** The entity type byte and the graph-node pointer moved to later slots
  in the common entity header. On linux the header did not grow; later entity fields stayed put.
  Windows carries its own larger entity header, as it did before, so its subclass fields sit later
  than the linux ones on both builds.
- **Location grew twice.** A Location's own fields shifted outward in two steps: a small growth
  early in the object and a second further in. Its type pointers, shape, rotation, coordinates,
  deleted and hidden flags, and highlight fields all moved with it.
- **Combined locations unchanged on linux, grown on windows.** The multi-section location and its
  section objects kept their linux layout; on windows both grew by one pointer slot. The tile
  scanner reads sections through the same vector and type pointer as before.
- **Location container reorganised.** Where a container held three location vectors followed by one
  dispatch slot table, it now holds two groups, each a run of vectors followed by its own five-slot
  table, and the slot stride grew. The map square's container entries became shared-pointer pairs,
  so a container is reached through the object half of an entry rather than a raw pointer. The
  chunk-size compare in the container accessor was removed; the accessor now divides by a constant.
- **Map square header grew.** Every map-square field moved outward by one header's worth; the
  composite-data pointer store in the constructor is now the stable anchor for the whole header.
- **Interface manager grew** and its interface-list pointer moved one slot outward.
- **Interface component layout refactored.** The four origin and anchor mode bytes no longer exist.
  The decoder now resolves them into placement floats per axis: an anchor fraction, an origin
  fraction, a size scale and integer offsets, plus an aspect-lock mode. The origin-mode dispatcher
  function is gone. The paged layer's page array and page bytes moved outward; its vtable tag
  changed.
- **Script hook event record grew** and its suppress-dispatch byte and source-component pointer
  moved with it. Two 949-5 windows entries had filed those on the interface component; they never
  belonged there.
- **Hitmarks and headbars container moved** on the pathing entity to a later slot.
- **DoAction table unchanged.** The client constructs the same sixty-six action objects with the
  same ids and kinds on both platforms; only their sender addresses moved.

### What it meant for the injected engine, and what was fixed

Every value above was ported into the offset tables. The breakage that followed came from engine
code that had the previous layout baked in rather than from the tables:

- Wrappers read objects through windows sized by hand for the old layout. When a field moved past
  its window every read threw, the script loop swallowed the exception, and a bot started and sat
  idle. Windows now derive from the table (`OffsetObject.extent`), every wrapper widens whatever
  segment it is handed to its own extent, and `WindowExtentTest` fails the build on a hand-sized
  window.
- The auto-updater's DoAction walk found neither the linux static-initialiser root nor the windows
  registration functions and silently dropped twenty-six actions; scripts that fired them became
  no-ops. The walk is structural now, fails loudly on any dropped id, and the anchor import reads
  the live registry.
- Two table values were filed one slot off by the migration and passed every parity check because
  the checks compare tables, not behaviour: a combined-location section's position is a plane, x, y
  triple and its first slot had been filed as x, so every section read x as 0 and was dropped from
  the scene walk; and the component text field had been filed on the button caption, an embedded
  string that is empty on ordinary components, so every text-driven wait read nothing. Both were
  found by running a script and reading what it saw, which is the gate the procedure now requires.
- Memory reading stays the existing system, unchanged. Two defensive reading layers were added and
  removed the same day: an invalid memory access is an engine defect - a structure sized or laid out
  wrong, a traversal that does not match the client, or a thread race - and is fixed at that root,
  never survived.
- The update procedure now ends with a per-object layout-growth report from the updater and a
  mandatory end-to-end script run (interfaces, scenery, an NPC) on each shipped platform before
  parity is declared. See `re-methodology/UPDATING.md`, section 7.

### Migration coverage

| | functions found | missing | ambiguous | anchors located | DoActions |
|---|---|---|---|---|---|
| linux | 925 | 223 | 35 | 44 | 66 |
| windows | 146 | 36 | 19 | 44 | 66 |

"Missing" functions are ones the signature scan could not relocate, not ones shown to be removed;
the two removed functions established directly are the origin-mode dispatcher and the chunk-size
compare noted above.
