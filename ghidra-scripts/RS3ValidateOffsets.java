import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Validates a generated engine offset table against the binary it claims to describe: every function
 * address must be a real entry point (not mid-body, which is how a mis-relocated hook target presents),
 * and every absolute data address must land in a real memory block.
 */
public class RS3ValidateOffsets extends GhidraScript {

    private int pass, fail;
    private final List<String> failures = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { printerr("usage: RS3ValidateOffsets <table.json>"); return; }
        String json = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);

        println("VALIDATE table=" + args[0] + " program=" + currentProgram.getName()
                + " imageBase=0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));

        for (String[] fn : entriesOf(json, "OFunctions")) checkFunction("OFunctions." + fn[0], fn[1], fn[2]);
        for (String[] da : doActionsOf(json)) checkFunction("doAction." + da[0], da[1], null);
        for (String obj : new String[]{"OGlobal", "OInputGlobals", "OHeightMap", "OInput",
                                       "OInputState", "OScriptRunner", "OServerProtTable"})
            for (String[] f : entriesOf(json, obj)) checkAbsoluteData(obj + "." + f[0], f[1]);

        println("VALIDATE RESULT pass=" + pass + " fail=" + fail);
        for (String f : failures) println("  FAIL " + f);
    }

    private void checkFunction(String id, String hex, String expectedName) {
        Address a = addr(hex);
        if (a == null) { record(id, "unparseable address " + hex); return; }
        Function f = getFunctionAt(a);
        if (f == null) {
            Function containing = getFunctionContaining(a);
            record(id, hex + " is NOT a function entry"
                    + (containing != null ? " (lies inside " + containing.getName() + " @" + containing.getEntryPoint() + ")"
                                          : " (no function here at all)"));
            return;
        }
        if (expectedName != null && !expectedName.isEmpty()) {
            String want = expectedName.trim();
            int sp = want.indexOf(' ');
            if (sp > 0) want = want.substring(0, sp);
            String got = f.getName(true);
            if (!got.equals(want) && !got.endsWith("::" + simple(want)) && !simple(got).equals(simple(want))) {
                record(id, hex + " resolves to '" + got + "', table says '" + want + "'");
                return;
            }
        }
        pass++;
    }

    private void checkAbsoluteData(String id, String hex) {
        long v = parse(hex);
        if (v < 0x100000L) { pass++; return; }   // struct-relative displacement, not an address
        Address a = addr(hex);
        MemoryBlock b = a == null ? null : currentProgram.getMemory().getBlock(a);
        if (b == null) { record(id, hex + " is not inside ANY memory block"); return; }
        Symbol s = getSymbolAt(a);
        println("  data " + id + " " + hex + " block=" + b.getName()
                + (b.isWrite() ? " [rw]" : " [ro]") + (s != null ? " symbol=" + s.getName(true) : ""));
        pass++;
    }

    private void record(String id, String why) { fail++; failures.add(id + ": " + why); }

    private static String simple(String n) { int i = n.lastIndexOf("::"); return i < 0 ? n : n.substring(i + 2); }

    private Address addr(String hex) {
        try { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(parse(hex)); }
        catch (Exception e) { return null; }
    }

    private static long parse(String s) {
        s = s.trim();
        return s.startsWith("0x") || s.startsWith("0X") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
    }

    /** Minimal extraction: the generated tables are machine-written with a stable shape. */
    private List<String[]> entriesOf(String json, String object) {
        List<String[]> out = new ArrayList<>();
        Matcher om = Pattern.compile("\"" + Pattern.quote(object) + "\"\\s*:\\s*\\{").matcher(json);
        if (!om.find()) return out;
        String body = balanced(json, om.end() - 1);
        Matcher fm = Pattern.compile("\"([A-Za-z0-9_]+)\"\\s*:\\s*\\{").matcher(body);
        while (fm.find()) {
            String fb = balanced(body, fm.end() - 1);
            out.add(new String[]{fm.group(1), field(fb, "value"), field(fb, "note")});
        }
        return out;
    }

    private List<String[]> doActionsOf(String json) {
        List<String[]> out = new ArrayList<>();
        Matcher om = Pattern.compile("\"doActions\"\\s*:\\s*\\[").matcher(json);
        if (!om.find()) return out;
        String body = balanced(json, om.end() - 1);
        Matcher em = Pattern.compile("\\{").matcher(body);
        while (em.find()) {
            String eb = balanced(body, em.start());
            out.add(new String[]{field(eb, "name"), field(eb, "value")});
            em.region(Math.min(em.start() + eb.length(), body.length()), body.length());
        }
        return out;
    }

    private static String balanced(String s, int open) {
        char oc = s.charAt(open), cc = oc == '{' ? '}' : ']';
        int depth = 0; boolean q = false, esc = false;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') q = !q;
            if (q) continue;
            if (c == oc) depth++;
            else if (c == cc && --depth == 0) return s.substring(open, i + 1);
        }
        return s.substring(open);
    }

    private static String field(String obj, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(obj);
        return m.find() ? m.group(1) : null;
    }
}
