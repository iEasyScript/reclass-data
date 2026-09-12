// SPDX-License-Identifier: MIT
// @category RS3
// RS3Cs2OpcodeNames.java
//
// Recovers each CS2 opcode's own name from the client. Every opcode handler passes its name as a
// string literal to the opcode-error helper, so the name is IN the binary and never has to be
// carried across a build. Reads a dispatch CSV (opcode,...,handlerAddr,...) and writes
// opcode,handler,canonical_name,derived_name,evidence.
//
// Args: <dispatch-csv> <out-csv>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class RS3Cs2OpcodeNames extends GhidraScript {

    private static final int MIN_NAME = 3;
    private static final int MAX_NAME = 96;
    private static final int MAX_CALLEE_DEPTH = 1;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: RS3Cs2OpcodeNames <dispatch-csv> <out-csv>");
            return;
        }
        List<String[]> rows = readCsv(new File(args[0]));
        int opcodeCol = -1, handlerCol = -1;
        String[] header = rows.get(0);
        for (int i = 0; i < header.length; i++) {
            if (header[i].equals("opcode")) opcodeCol = i;
            if (header[i].equals("handlerAddr")) handlerCol = i;
        }
        if (opcodeCol < 0 || handlerCol < 0) {
            printerr("dispatch CSV needs 'opcode' and 'handlerAddr' columns");
            return;
        }

        StringBuilder out = new StringBuilder("opcode,handler,canonical_name,derived_name,evidence\n");
        int named = 0, ambiguous = 0, none = 0;
        for (int r = 1; r < rows.size(); r++) {
            String[] row = rows.get(r);
            if (row.length <= Math.max(opcodeCol, handlerCol)) continue;
            String opcode = row[opcodeCol].trim();
            String handlerText = row[handlerCol].trim();
            if (handlerText.isEmpty()) continue;
            Address handler = toAddr(handlerText);
            Set<String> found = new LinkedHashSet<>();
            collect(handler, found, 0, new HashSet<>());
            String evidence;
            String name = "";
            if (found.size() == 1) {
                name = found.iterator().next();
                evidence = "sole name-shaped literal reachable from the handler";
                named++;
            } else if (found.isEmpty()) {
                evidence = "no name-shaped literal";
                none++;
            } else {
                evidence = "AMBIGUOUS: " + String.join("|", found);
                ambiguous++;
            }
            out.append(opcode).append(',').append(handlerText).append(',')
               .append(csv(name)).append(',').append(csv(name)).append(',').append(csv(evidence)).append('\n');
        }
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[1]), StandardCharsets.UTF_8)) {
            w.write(out.toString());
        }
        println("opcodes named " + named + ", ambiguous " + ambiguous + ", none " + none + " -> " + args[1]);
    }

    private void collect(Address entry, Set<String> found, int depth, Set<Address> seen) {
        if (entry == null || !seen.add(entry)) return;
        Function fn = getFunctionAt(entry);
        Address end = fn != null ? fn.getBody().getMaxAddress() : entry.add(0x400);
        List<Address> callees = new ArrayList<>();
        Instruction insn = getInstructionAt(entry);
        while (insn != null && insn.getAddress().compareTo(end) <= 0) {
            for (Reference ref : insn.getReferencesFrom()) {
                Address to = ref.getToAddress();
                if (to == null) continue;
                if (ref.getReferenceType().isCall()) {
                    if (depth < MAX_CALLEE_DEPTH) callees.add(to);
                    continue;
                }
                String s = readName(to);
                if (s != null) found.add(s);
            }
            insn = insn.getNext();
        }
        for (Address callee : callees) collect(callee, found, depth + 1, seen);
    }

    /** A CS2 opcode name is lowercase ASCII with underscores and digits; anything else is not one. */
    private String readName(Address at) {
        MemoryBlock block = currentProgram.getMemory().getBlock(at);
        if (block == null || block.isExecute() || !block.isInitialized()) return null;
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < MAX_NAME + 1; i++) {
                byte b = currentProgram.getMemory().getByte(at.add(i));
                if (b == 0) break;
                char c = (char) (b & 0xFF);
                if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_') return null;
                sb.append(c);
            }
        } catch (Exception e) {
            return null;
        }
        String s = sb.toString();
        if (s.length() < MIN_NAME || s.length() > MAX_NAME) return null;
        if (s.chars().noneMatch(Character::isLetter)) return null;
        return s;
    }

    private static String csv(String v) {
        if (v.indexOf(',') < 0 && v.indexOf('"') < 0) return v;
        return '"' + v.replace("\"", "\"\"") + '"';
    }

    private static List<String[]> readCsv(File f) throws IOException {
        List<String[]> rows = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) if (!line.isEmpty()) rows.add(line.split(",", -1));
        }
        return rows;
    }
}
