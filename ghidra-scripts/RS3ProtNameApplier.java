// SPDX-License-Identifier: MIT
// @category RS3ProjectX
// RS3ProtNameApplier.java
//
// Applies prot names to bound packet handlers in the CURRENT program.
//
//   RS3ProtNameApplier <mapping.tsv> [--apply]
//
// The TSV is produced by pairing RS3ProtFinder's structural opcode->handler mapping with the
// handler's existing symbol. Default is a dry run; --apply commits inside one transaction.
//
// A name is either OFFICIAL (attested outside this binary -- the client itself carries no prot
// name strings at all) or ASSIGNED (invented here because no attested name is known). The TSV's
// optional name_source column picks which marker is written, and the two are deliberately
// different strings so that reading a comment tells you which kind of name you are looking at.
// Anything ASSIGNED is a placeholder and must never be treated as fact by downstream tooling.
//
// The SCREAMING_SNAKE spelling is recorded verbatim in the function's plate comment
// because the established symbol convention (jag::PacketHandlers::CamelCase) cannot represent
// it: CLIENT_SETVARC_LARGE and CLIENT_SETVARCLARGE both camel to ClientSetvarcLarge. Symbols
// are left untouched; only the comment line owned by this tool is rewritten.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class RS3ProtNameApplier extends GhidraScript {

    private static final String OFFICIAL_MARKER = "OFFICIAL_PROT_NAME=";
    private static final String ASSIGNED_MARKER = "ASSIGNED_PROT_NAME=";

    /** Every marker this tool has ever written; all are stripped before the current one is added,
     *  so a name that stops being OFFICIAL cannot leave its old claim behind in the comment. */
    private static final String[] MARKERS = { OFFICIAL_MARKER, ASSIGNED_MARKER };

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { printerr("Usage: RS3ProtNameApplier <mapping.tsv> [--apply]"); return; }
        boolean apply = Arrays.asList(args).contains("--apply");
        Path tsv = Paths.get(args[0]);
        if (!Files.exists(tsv)) { printerr("mapping not found: " + tsv); return; }

        List<String> lines = Files.readAllLines(tsv, StandardCharsets.UTF_8);
        int applied = 0, unchanged = 0, noFunction = 0, entryMismatch = 0, malformed = 0;
        List<String> problems = new ArrayList<>();

        int tx = -1;
        if (apply) tx = currentProgram.startTransaction("RS3ProtNameApplier");
        boolean ok = false;
        try {
            for (String line : lines) {
                if (line.isEmpty() || line.startsWith("handler_addr")) continue;
                String[] f = line.split("\t");
                if (f.length < 5) { malformed++; problems.add("malformed: " + line); continue; }
                String addrHex = f[0], protName = f[1], direction = f[2], opcode = f[3], size = f[4];
                boolean assigned = f.length >= 7 && "ASSIGNED".equalsIgnoreCase(f[6].trim());

                Address a;
                try { a = toAddr(Long.parseLong(addrHex.replace("0x", "").trim(), 16)); }
                catch (Exception e) { malformed++; problems.add("bad address: " + line); continue; }

                Function fn = getFunctionContaining(a);
                if (fn == null) { noFunction++; problems.add("no function at " + addrHex + " for " + protName); continue; }
                if (!fn.getEntryPoint().equals(a)) {
                    entryMismatch++;
                    problems.add("address is not a function entry: " + addrHex + " for " + protName);
                    continue;
                }

                String want = (assigned ? ASSIGNED_MARKER : OFFICIAL_MARKER) + protName
                        + " direction=" + direction + " opcode=" + opcode + " size=" + size
                        + (assigned ? " name_source=ASSIGNED" : "");
                // A bound handler is often a thunk, and a comment left only on the thunk is invisible to
                // every consumer that skips thunks. Label the thunk and the body it forwards to.
                List<Address> targets = new ArrayList<>();
                targets.add(a);
                Function thunked = fn.isThunk() ? fn.getThunkedFunction(true) : null;
                if (thunked != null && !thunked.getEntryPoint().equals(a)) targets.add(thunked.getEntryPoint());

                boolean changedAny = false;
                for (Address t : targets) {
                    String existing = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, t);
                    String rebuilt = withMarkerLine(existing, want);
                    if (rebuilt.equals(existing == null ? "" : existing)) continue;
                    if (apply) currentProgram.getListing().setComment(t, CodeUnit.PLATE_COMMENT, rebuilt);
                    changedAny = true;
                }
                if (changedAny) applied++; else unchanged++;
            }
            ok = true;
        } finally {
            if (tx != -1) currentProgram.endTransaction(tx, ok && apply);
        }

        println("prot names: " + applied + (apply ? " applied" : " would be applied")
                + ", " + unchanged + " already current");
        println("  skipped: noFunction=" + noFunction + " entryMismatch=" + entryMismatch + " malformed=" + malformed);
        for (String p : problems) println("  PROBLEM " + p);
        if (!apply) println("(dry run - pass --apply to commit)");
    }

    private String withMarkerLine(String existing, String want) {
        List<String> kept = new ArrayList<>();
        if (existing != null && !existing.isEmpty()) {
            for (String l : existing.split("\n", -1)) {
                boolean isMarker = false;
                for (String m : MARKERS) if (l.startsWith(m)) { isMarker = true; break; }
                if (!isMarker) kept.add(l);
            }
        }
        while (!kept.isEmpty() && kept.get(kept.size() - 1).trim().isEmpty()) kept.remove(kept.size() - 1);
        kept.add(want);
        return String.join("\n", kept);
    }
}
