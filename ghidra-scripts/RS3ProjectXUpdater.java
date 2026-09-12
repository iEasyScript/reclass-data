// SPDX-License-Identifier: MIT
// @category RS3ProjectX
// RS3ProjectXUpdater.java
//
// Consolidated, HEADLESS export/import migration tool for Project X.
// Runs via analyzeHeadless (getScriptArgs), never interactively.
//
//   export                         (run against OLD binary, -readOnly)
//   import        [--apply]        (run against NEW binary; DEFAULT = dry-run, NO db writes)
//
// EXPORT writes re-resources/updater/updater_data_<VERSION>/{manifest,functions,datalabels,
//   comments,anchors}. (Data TYPES remain handled by the existing RS3DataTypeExporter/Importer,
//   referenced from the manifest — the 5 legacy scripts are kept as-is.)
// IMPORT (dry-run) reads that dir, locates+extracts every anchor against the NEW binary, detects
//   drift, and writes ONLY output files + log: re-resources/updater/results_<VERSION>.json,
//   updater/offsets/offsets_<VERSION>.kt, updater/offsets/DoActionOpcodes_<VERSION>.kt.
//   With --apply it ADDITIONALLY commits DB edits (rename/prototype/comment/label/anchor-name).
//
// Algorithm provenance (ported, cited per method):
//   * signature blob/mask/normsig/masked-Hamming/index/resolve/namespace/NDJSON  <- RS3SignatureUpdater.java
//   * _INIT_2 DoAction dispatch walk                                            <- RS3DoActionUpdater.java
//   * RS2Engine version regex + RIP/displacement scans                          <- RS3OffsetExporter.java
//
// SAFETY: import is dry-run by default; DB mutation happens ONLY under --apply, inside a single
// transaction with try/finally. Run with analyzeHeadless -readOnly as an extra hard guard.

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class RS3ProjectXUpdater extends GhidraScript {

    // ---- Tunables (ported from RS3SignatureUpdater) ----
    private static final int FUNC_MAX_INSNS = 40;
    private static final int VERIFY_MAX_MISMATCH = 6;
    private static final int RECIPE_MAX_INSNS = 6000;
    private static final String[] TARGET_NAMESPACES = {"jag", "eastl", "ref_counter_base"};
    private static final Pattern VERSION_PATTERN = Pattern.compile("RS2Engine-(\\d+)-NXT-(\\d+)");

    // default-name prefixes to skip for data labels
    private static final String[] DEFAULT_LABEL_PREFIXES = {
        "DAT_", "PTR_", "LAB_", "SUB_", "FUN_", "s_", "u_", "unk_", "switchD_", "caseD_",
        "Elf64_", "__DT_", "fde_", "cie_", "GnuBuildId", "NoteAbiTag"
    };
    private static final Set<String> LIBC_LABELS = new HashSet<>(Arrays.asList(
        "stdout", "stderr", "stdin", "__progname", "environ"
    ));

    private boolean apply = false;
    private String version = null;
    private long imageBase = 0;
    private PlatformProfile profile;
    private Path updaterRoot;     // re-resources/updater
    private Path dataDir;         // updater/updater_data_<ver>
    private final List<Path> fallbackDataDirs = new ArrayList<>(); // back-fill baselines, primary-first precedence
    private Path offsetsDir;      // updater/offsets
    private Map<String, Function> nameMap;     // qualified name -> function (built once)
    private Map<String, Function> stringFnMap; // string value -> referencing function (built once)
    private final Map<String, Address> resolvedFuncByName = new HashMap<>(); // qualified name -> resolved NEW addr (from sig-match)

    // Every parity loss this tool has caused was a swallowed exception, so nothing in the apply path is
    // allowed to fail quietly: each failure is counted by reason and listed by subject in the residual report.
    private final Map<String, Integer> applyFailCounts = new LinkedHashMap<>();
    private final List<String> applyFailDetail = new ArrayList<>();

    private void applyFailure(String category, String reason, String subject) {
        applyFailCounts.merge(category + ": " + reason, 1, Integer::sum);
        applyFailDetail.add(category + "\t" + reason + "\t" + subject);
    }

    private final Map<String, String> unresolvedIds = new LinkedHashMap<>();
    private List<String> doActionParityLoss = new ArrayList<>();
    private final List<Function> doActionRoots = new ArrayList<>();

    /**
     * An unverifiable absolute is omitted, never carried. The engine throws on an absent offset but has
     * no defence against a present-but-wrong pointer, so a visible gap is strictly safer than a stale value.
     */
    private void unresolved(String id, String reason) {
        unresolvedIds.put(id, reason);
        applyFailure("offset-table", "UNRESOLVED (omitted, not carried): " + reason, id);
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) { printerr("No program."); return; }

        String[] args = getScriptArgs();
        String mode = (args.length > 0) ? args[0].trim().toLowerCase() : "";
        String dataDirOverride = null;
        for (int i = 1; i < args.length; i++) {
            String a = args[i].trim();
            if ("--apply".equalsIgnoreCase(a)) apply = true;
            else if ("--data-dir".equalsIgnoreCase(a) && i + 1 < args.length) dataDirOverride = args[++i].trim();
        }

        profile = selectProfile();
        version = detectVersion();
        if (version == null) { printerr("FATAL: could not detect RS2Engine-X-NXT-Y version from binary."); return; }
        imageBase = currentProgram.getImageBase().getOffset();
        // Every address this script emits is used as a module-relative value by the engine, and the
        // project imports every binary at base 0 so Ghidra addresses ARE those values. A non-zero base
        // would silently turn the whole offset table into VAs.
        if (imageBase != 0) {
            printerr("FATAL: image base is 0x" + Long.toHexString(imageBase) + ", expected 0. "
                    + "Re-import the binary at base 0 or emitted offsets will be VAs, not RVAs.");
            return;
        }

        updaterRoot = locateUpdaterRoot();
        // Both builds of a version share the same version string, so the non-native platform qualifies
        // its data dir to avoid overwriting the Linux baseline. Linux keeps the unprefixed historical name.
        dataDir = updaterRoot.resolve(profile instanceof SysVElfProfile
                ? "updater_data_" + version
                : "updater_data_" + profile.id() + "-" + version);
        // IMPORT baseline override (go-forward pointer from run_updater.py): diff the NEW binary against an
        // EXPLICIT baseline dir rather than the version-derived one. EXPORT ignores it (writes updater_data_<ver>).
        // A comma-separated chain lets a later baseline back-fill names an earlier migration dropped:
        // the first dir that carries a name wins, so recovery can never override current work.
        fallbackDataDirs.clear();
        if ("import".equals(mode) && dataDirOverride != null && !dataDirOverride.isEmpty()) {
            String[] parts = dataDirOverride.split(",");
            for (int i = 0; i < parts.length; i++) {
                String t = parts[i].trim();
                if (t.isEmpty()) continue;
                Path ov = Paths.get(t);
                Path resolved = ov.isAbsolute() ? ov : updaterRoot.resolve(t);
                if (i == 0) dataDir = resolved; else fallbackDataDirs.add(resolved);
            }
        }
        offsetsDir = updaterRoot.resolve("offsets");

        println("RS3ProjectXUpdater mode=" + mode + " apply=" + apply + " version=" + version
                + " platform=" + profile.id() + " imageBase=0x" + Long.toHexString(imageBase));

        switch (mode) {
            case "export" -> doExport();
            case "import" -> doImport();
            case "dump" -> doDump(args);
            default -> printerr("Usage: RS3ProjectXUpdater <export|import|dump> [--apply] [names...]");
        }
    }

    // ============================================================ PLATFORM PROFILE ============================================================
    // The two builds of the same client differ in ABI and container format, not in behaviour. Everything
    // that depends on which register carries `this`, which registers carry arguments, where file-scope
    // static initialisers are rooted, and which blocks hold read-only data lives behind this interface;
    // the signature engine, export/import, drift detection and output writers are shared verbatim.

    private abstract class PlatformProfile {
        abstract String id();
        /** Register holding the implicit `this` argument at a member-function call site. */
        abstract String thisRegister();
        /** Integer/pointer argument registers, arg1 first. */
        abstract String[] argRegisters();
        abstract boolean isRodataBlock(String blockName);
        /** Every DoAction the client constructs, read out of however this build's toolchain builds them. */
        abstract List<ActionRecord> walkDoActions();
    }

    private class SysVElfProfile extends PlatformProfile {
        String id() { return "linux-x86_64"; }
        String thisRegister() { return "RDI"; }
        String[] argRegisters() { return new String[]{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}; }
        boolean isRodataBlock(String n) { return n.contains("rodata") || n.contains(".data"); }
        List<ActionRecord> walkDoActions() { return elfWalkDoActions(); }
    }

    private class Win64PeProfile extends PlatformProfile {
        String id() { return "windows-x86_64"; }
        String thisRegister() { return "RCX"; }
        String[] argRegisters() { return new String[]{"RCX", "RDX", "R8", "R9"}; }
        boolean isRodataBlock(String n) { return n.contains("rdata") || n.contains(".data"); }
        List<ActionRecord> walkDoActions() { return peWalkDoActions(); }
    }

    private PlatformProfile selectProfile() {
        String format = currentProgram.getExecutableFormat();
        boolean pe = format != null && format.toLowerCase().contains("portable executable");
        return pe ? new Win64PeProfile() : new SysVElfProfile();
    }

    // Read-only diagnostic: print disassembly of functions (for authoring anchor recipes).
    //   <name|0xaddr>            -> dump that function's body
    //   callersof:<name>         -> for the first few callers, dump the ~14 insns before their CALL to <name>
    private void doDump(String[] args) {
        buildLookupMaps();
        for (int i = 1; i < args.length; i++) {
            String t = args[i];
            if (t.equals("managers")) { dumpManagers(0x18000, 0x1a000); continue; }
            if (t.startsWith("managers:")) { String[] rr = t.substring("managers:".length()).split("-"); dumpManagers(parseHexOrDec(rr[0]), parseHexOrDec(rr[1])); continue; }
            if (t.startsWith("ctorstores:")) { String[] rr = t.substring("ctorstores:".length()).split("@"); String[] bd = rr[1].split("-"); dumpCtorStores(rr[0], parseHexOrDec(bd[0]), parseHexOrDec(bd[1])); continue; }
            if (t.startsWith("disasm:")) { dumpDisasm(t.substring("disasm:".length())); continue; }
            if (t.startsWith("field:")) { String s = t.substring("field:".length()); int at = s.indexOf('@'); long d = parseHexOrDec(at >= 0 ? s.substring(0, at) : s); int lim = at >= 0 ? (int) parseHexOrDec(s.substring(at + 1)) : 40; dumpFieldAccess(d, lim); continue; }
            if (t.startsWith("callersof:")) { dumpCallers(t.substring("callersof:".length())); continue; }
            Function f = t.startsWith("0x") ? getFunctionAt(parseAddr(t)) : findFunctionByQualifiedName(t);
            if (f == null) { println("DUMP not found: " + t); continue; }
            println("=== " + fullNameOf(f) + " @ 0x" + f.getEntryPoint() + " ===");
            for (Instruction insn : bodyInstructions(f, 120)) println("  0x" + insn.getAddress() + ": " + insn.toString());
        }
    }

    // Cached this-load consensus: namespace -> {offset->count}. Built once per run by scanning every
    // CALL to a jag:: method and reading the preceding "MOV/LEA RDI,[base+off]" this-pointer load.
    // This is the most reliable manager anchor: every callsite of a class agrees on its client offset.
    private Map<String, Map<Long, Integer>> managerConsensus;

    private Map<String, Map<Long, Integer>> buildManagerConsensus() {
        if (managerConsensus != null) return managerConsensus;
        Map<String, Map<Long, Integer>> hist = new HashMap<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            List<Instruction> body = bodyInstructions(f, 3000);
            for (int i = 0; i < body.size(); i++) {
                Instruction in = body.get(i);
                if (!"CALL".equalsIgnoreCase(in.getMnemonicString())) continue;
                Function callee = callTargetOf(in);
                if (callee == null) continue;
                String ns = fullNs(callee.getParentNamespace());
                if (ns.isEmpty() || !ns.startsWith("jag")) continue;
                for (int j = i - 1; j >= 0 && j > i - 10; j--) {
                    Instruction p = body.get(j);
                    Register w = firstWrittenRegister(p);
                    if (w == null || !w.getName().equalsIgnoreCase(profile.thisRegister())) continue;
                    Long off = thisLoadOffset(p);
                    if (off != null && off > 0) hist.computeIfAbsent(ns, k -> new HashMap<>()).merge(off, 1, Integer::sum);
                    break;
                }
            }
        }
        managerConsensus = hist;
        return hist;
    }

    // Resolve a manager class to its client offset via consensus. Returns null if class unknown or
    // the winning offset is below min_sites callsites (too weak to trust). out[0]=offset, out[1]=count, out[2]=total.
    // Offsets are filtered to [dispMin,dispMax]: a manager method is also called on nested objects
    // (this=[parent+0x20] etc.), so small offsets must be excluded — the real OClient pointer band is high.
    private long[] resolveManagerClass(String ns, int minSites, long dispMin, long dispMax) {
        Map<Long, Integer> h = buildManagerConsensus().get(ns);
        if (h == null) return null;
        long bestOff = 0; int bestC = 0, total = 0;
        for (Map.Entry<Long, Integer> o : h.entrySet()) {
            if (o.getKey() < dispMin || o.getKey() > dispMax) continue;
            total += o.getValue();
            if (o.getValue() > bestC) { bestC = o.getValue(); bestOff = o.getKey(); }
        }
        if (bestC < minSites) return null;
        return new long[]{bestOff, bestC, total};
    }

    private void dumpManagers(long lo, long hi) {
        Map<String, Map<Long, Integer>> hist = buildManagerConsensus();
        println("=== manager class -> client offset (this-load consensus, range 0x" + Long.toHexString(lo) + "-0x" + Long.toHexString(hi) + ") ===");
        for (Map.Entry<String, Map<Long, Integer>> e : hist.entrySet()) {
            long bestOff = 0; int bestC = 0, total = 0;
            for (Map.Entry<Long, Integer> o : e.getValue().entrySet()) { total += o.getValue(); if (o.getValue() > bestC) { bestC = o.getValue(); bestOff = o.getKey(); } }
            if (bestOff < lo || bestOff > hi) continue;
            println(String.format("  %-44s 0x%-6x (%d/%d sites)", e.getKey(), bestOff, bestC, total));
        }
    }

    // Discovery: in a ctor, each heap-allocated manager is `CALL <Mgr>::<Mgr>; MOV [this+off],RAX`.
    // Scans the named function for writes [reg+disp] (disp in band) and reports the nearest preceding
    // CALL target — i.e. off -> manager class, for the pointer managers not callable via this-load.
    private void dumpCtorStores(String funcName, long lo, long hi) {
        if ("*".equals(funcName)) { dumpCtorStoresAll(lo, hi); return; }
        Function f = findFunctionByQualifiedName(funcName);
        if (f == null) { println("ctorstores: function not found: " + funcName); return; }
        println("=== ctor stores in " + funcName + " @ " + f.getEntryPoint() + " (disp 0x" + Long.toHexString(lo) + "-0x" + Long.toHexString(hi) + ") ===");
        List<Instruction> body = bodyInstructions(f, 60000);
        String lastCall = "-";
        for (int i = 0; i < body.size(); i++) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            if ("CALL".equalsIgnoreCase(mn)) { Function c = callTargetOf(in); lastCall = c == null ? "-" : (fullNs(c.getParentNamespace()) + "::" + c.getName()); continue; }
            if (!"MOV".equalsIgnoreCase(mn) && !"LEA".equalsIgnoreCase(mn)) continue;
            if (in.getNumOperands() < 1) continue;
            int t = in.getOperandType(0);
            if (!OperandType.isDynamic(t) && !OperandType.isAddress(t)) continue;
            Long disp = dispOfOperand(in, 0);
            if (disp == null || disp < lo || disp > hi) continue;
            println(String.format("  +0x%-6x  %-28s  after CALL %s", disp, in.toString(), lastCall));
        }
    }

    // Binary-wide: for every high-band STORE [reg+disp], record disp -> {preceding-call -> count}.
    // Reveals where each pointer-manager is constructed/stored even when the storing fn isn't named "ctor".
    private void dumpCtorStoresAll(long lo, long hi) {
        Map<Long, Map<String, Integer>> byOff = new HashMap<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            List<Instruction> body = bodyInstructions(f, 8000);
            String lastCall = "-";
            for (int i = 0; i < body.size(); i++) {
                Instruction in = body.get(i);
                String mn = in.getMnemonicString();
                if ("CALL".equalsIgnoreCase(mn)) { Function c = callTargetOf(in); lastCall = c == null ? "-" : (fullNs(c.getParentNamespace()) + "::" + c.getName()); continue; }
                if (!"MOV".equalsIgnoreCase(mn)) continue;
                if (in.getNumOperands() < 1) continue;
                if (!OperandType.isDynamic(in.getOperandType(0))) continue;
                Long disp = dispOfOperand(in, 0);
                if (disp == null || disp < lo || disp > hi) continue;
                byOff.computeIfAbsent(disp, k -> new HashMap<>()).merge(lastCall, 1, Integer::sum);
            }
        }
        println("=== high-band STORES: offset -> preceding CALL (disp 0x" + Long.toHexString(lo) + "-0x" + Long.toHexString(hi) + ") ===");
        List<Long> offs = new ArrayList<>(byOff.keySet());
        Collections.sort(offs);
        for (Long off : offs) {
            StringBuilder sb = new StringBuilder();
            byOff.get(off).entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(3)
                    .forEach(e -> sb.append(e.getKey()).append("(").append(e.getValue()).append(") "));
            println(String.format("  +0x%-6x  %s", off, sb.toString()));
        }
    }

    // Displacement of a [base+disp] memory operand at index opIdx, else null.
    private Long dispOfOperand(Instruction in, int opIdx) {
        for (Object o : in.getOpObjects(opIdx)) if (o instanceof Scalar) return ((Scalar) o).getUnsignedValue();
        return null;
    }

    // disasm:<qualifiedName-or-0xADDR>[@maxInsns] — print a function's instructions (default 220).
    private void dumpDisasm(String spec) {
        String name = spec; int max = 220;
        int at = spec.indexOf('@');
        if (at >= 0) { name = spec.substring(0, at); max = (int) parseHexOrDec(spec.substring(at + 1)); }
        Function f = name.startsWith("0x") ? getFunctionContaining(toAddr(parseHexOrDec(name))) : findFunctionByQualifiedName(name);
        if (f == null) { println("disasm: not found: " + name); return; }
        println("=== disasm " + fullNs(f.getParentNamespace()) + "::" + f.getName() + " @ " + f.getEntryPoint() + " ===");
        for (Instruction in : bodyInstructions(f, max)) println("  " + in.getAddress() + ": " + in.toString());
    }

    // field:<disp>[@limit] — find every function with a [reg+disp] memory access (read or write) to a
    // specific displacement. Reports containingFunc + instruction. Use to locate accessors of a plain
    // struct field (animationId, stat-table ptr) that isn't reached via a method this-load.
    private void dumpFieldAccess(long disp, int limit) {
        println("=== field [reg+0x" + Long.toHexString(disp) + "] accesses (read/write) ===");
        int shown = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled() && shown < limit) {
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            for (Instruction in : bodyInstructions(f, 6000)) {
                String mn = in.getMnemonicString();
                if (!"MOV".equalsIgnoreCase(mn) && !"LEA".equalsIgnoreCase(mn) && !"CMP".equalsIgnoreCase(mn) && !"ADD".equalsIgnoreCase(mn)) continue;
                boolean hit = false;
                for (int op = 0; op < in.getNumOperands() && !hit; op++) {
                    if (!OperandType.isDynamic(in.getOperandType(op))) continue;
                    Long d = dispOfOperand(in, op);
                    if (d != null && d == disp) hit = true;
                }
                if (hit) {
                    println(String.format("  %-40s %s: %s", fullNs(f.getParentNamespace()) + "::" + f.getName(), in.getAddress(), in.toString()));
                    if (++shown >= limit) break;
                }
            }
        }
        if (shown == 0) println("  (no accesses found)");
    }

    private Function callTargetOf(Instruction in) {
        for (Reference r : in.getReferencesFrom()) if (r.getReferenceType().isCall()) { Function f = getFunctionAt(r.getToAddress()); if (f != null) return f; }
        return null;
    }

    private void dumpCallers(String calleeName) {
        Function callee = findFunctionByQualifiedName(calleeName);
        if (callee == null) { println("CALLERSOF not found: " + calleeName); return; }
        println("=== callers of " + fullNameOf(callee) + " @ 0x" + callee.getEntryPoint() + " ===");
        int shown = 0;
        for (Reference r : getReferencesTo(callee.getEntryPoint())) {
            if (!r.getReferenceType().isCall()) continue;
            Function c = getFunctionContaining(r.getFromAddress());
            if (c == null) continue;
            println("  --- caller " + fullNameOf(c) + ", CALL @ 0x" + r.getFromAddress() + " ---");
            List<Instruction> body = bodyInstructions(c, 1200);
            int callIdx = -1;
            for (int k = 0; k < body.size(); k++) if (body.get(k).getAddress().equals(r.getFromAddress())) { callIdx = k; break; }
            if (callIdx < 0) continue;
            for (int k = Math.max(0, callIdx - 14); k <= callIdx; k++)
                println("    0x" + body.get(k).getAddress() + ": " + body.get(k).toString());
            if (++shown >= 4) break;
        }
    }

    // ---- xref fingerprints (for AMBIGUOUS disambiguation) ----
    private String[] namedCallers(Function f) {
        java.util.TreeSet<String> s = new java.util.TreeSet<>();
        for (Reference ref : getReferencesTo(f.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) continue;
            Function c = getFunctionContaining(ref.getFromAddress());
            if (c != null && !c.getName().startsWith("FUN_")) s.add(fullNameOf(c));
        }
        return s.toArray(new String[0]);
    }
    private String[] namedCallees(Function f) {
        java.util.TreeSet<String> s = new java.util.TreeSet<>();
        for (Function c : f.getCalledFunctions(monitor)) if (!c.getName().startsWith("FUN_")) s.add(fullNameOf(c));
        return s.toArray(new String[0]);
    }
    private String[] refStrings(Function f) {
        java.util.TreeSet<String> s = new java.util.TreeSet<>();
        for (Instruction insn : bodyInstructions(f, 160))
            for (Reference ref : insn.getReferencesFrom()) {
                Data d = currentProgram.getListing().getDefinedDataAt(ref.getToAddress());
                if (d != null && d.getValue() instanceof String sv) s.add(sv);
            }
        return s.toArray(new String[0]);
    }
    private Set<String> splitSet(String v) {
        Set<String> out = new HashSet<>();
        if (v != null && !v.isEmpty()) for (String p : v.split(";;;")) if (!p.isEmpty()) out.add(p);
        return out;
    }
    private int overlap(Set<String> a, Set<String> b) { int n = 0; for (String x : a) if (b.contains(x)) n++; return n; }

    // Pick the candidate whose caller/callee/string fingerprint best matches the exported record.
    // Strings (e.g. CreateOpcodeError self-names) dominate; callers next; callees least. Null if tie/none.
    private Function disambiguateByXref(Map<String, String> rec, List<Function> cands) {
        Set<String> expC = splitSet(rec.get("callers")), expE = splitSet(rec.get("callees")), expS = splitSet(rec.get("strings"));
        if (expC.isEmpty() && expE.isEmpty() && expS.isEmpty()) return null;
        Function best = null; double bestScore = 0; boolean tie = false;
        for (Function c : cands) {
            double score = 5.0 * overlap(new HashSet<>(Arrays.asList(refStrings(c))), expS)
                         + 1.0 * overlap(new HashSet<>(Arrays.asList(namedCallers(c))), expC)
                         + 0.5 * overlap(new HashSet<>(Arrays.asList(namedCallees(c))), expE);
            if (score > bestScore) { bestScore = score; best = c; tie = false; }
            else if (score == bestScore && score > 0) tie = true;
        }
        return (best != null && !tie && bestScore > 0) ? best : null;
    }

    // ============================================================ EXPORT ============================================================

    private void doExport() throws Exception {
        Files.createDirectories(dataDir);
        SymbolTable st = currentProgram.getSymbolTable();

        // --- functions.ndjson (sig + prototype + calling convention) ---
        List<String> funcLines = new ArrayList<>();
        Set<Function> processed = new HashSet<>();
        for (String nsName : TARGET_NAMESPACES) {
            Namespace ns = st.getNamespace(nsName, null);
            if (ns == null) { println("WARN: namespace '" + nsName + "' missing"); continue; }
            collectFunctions(ns, funcLines, processed);
        }
        int inNamespaces = funcLines.size();
        int strays = collectStrayNamedFunctions(funcLines, processed);
        writeLines(dataDir.resolve("functions.ndjson"), funcLines);
        println("exported functions: " + funcLines.size() + " (" + inNamespaces + " in target namespaces, "
                + strays + " hand-named outside them)");

        // An export is only trustworthy against the total it could have chosen from. Counting every
        // non-default function name independently of the namespace walk turns "the DB is sparse" into a
        // measured claim rather than an assumption about how much work was ever done on this program.
        int totalFuncs = 0, namedFuncs = 0, userNamed = 0;
        List<String> unexported = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            totalFuncs++;
            if (isDefaultName(f.getName())) continue;
            namedFuncs++;
            Symbol s = f.getSymbol();
            if (s != null && s.getSource() == SourceType.USER_DEFINED) userNamed++;
            if (!processed.contains(f)) unexported.add(fullNameOf(f) + " @0x" + f.getEntryPoint()
                    + " src=" + (s == null ? "?" : s.getSource()));
        }
        println("function census: " + totalFuncs + " functions, " + namedFuncs + " non-default names, "
                + userNamed + " USER_DEFINED, " + funcLines.size() + " exported, "
                + unexported.size() + " named-but-not-exported");
        for (int i = 0; i < Math.min(unexported.size(), 40); i++) println("   not exported: " + unexported.get(i));
        if (!unexported.isEmpty())
            writeLines(dataDir.resolve("unexported_named_functions.txt"), unexported);

        // --- datalabels.ndjson ---
        List<String> labelLines = exportDataLabels();
        writeLines(dataDir.resolve("datalabels.ndjson"), labelLines);
        println("exported data labels: " + labelLines.size());

        // --- comments.ndjson ---
        List<String> commentLines = exportComments(processed);
        writeLines(dataDir.resolve("comments.ndjson"), commentLines);
        println("exported comments: " + commentLines.size());

        // --- anchors.json (sig-stamped + old_value re-resolved) ---
        String anchorsJson = exportAnchors();
        writeText(dataDir.resolve("anchors.json"), anchorsJson);

        // --- manifest.json ---
        StringBuilder m = new StringBuilder();
        m.append("{\n");
        m.append("  \"tool\": \"RS3ProjectXUpdater\",\n");
        m.append("  \"schema_version\": 1,\n");
        m.append("  \"source_version\": ").append(jstr(version)).append(",\n");
        m.append("  \"source_program\": ").append(jstr(currentProgram.getName())).append(",\n");
        m.append("  \"image_base\": ").append(jstr("0x" + Long.toHexString(imageBase))).append(",\n");
        m.append("  \"parts\": {\n");
        m.append("    \"functions\": \"functions.ndjson\",\n");
        m.append("    \"datalabels\": \"datalabels.ndjson\",\n");
        m.append("    \"comments\": \"comments.ndjson\",\n");
        m.append("    \"anchors\": \"anchors.json\",\n");
        m.append("    \"datatypes\": \"../../sigs-results/datatypes_").append(version).append(".json (via RS3DataTypeExporter)\"\n");
        m.append("  }\n");
        m.append("}\n");
        writeText(dataDir.resolve("manifest.json"), m.toString());

        println("EXPORT complete -> " + dataDir);
    }

    // ported from RS3SignatureUpdater.collectFunctionsFromNamespace (recursive)
    private void collectFunctions(Namespace ns, List<String> out, Set<Function> processed) throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getSymbols(ns);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.getSymbolType() != SymbolType.FUNCTION) continue;
            Function f = getFunctionAt(sym.getAddress());
            if (f == null || processed.contains(f)) continue;
            processed.add(f);
            String rec = functionRecord(f, sym.getName(), fullNs(ns));
            if (rec != null) out.add(rec);
        }
        // recurse into child namespaces declared directly under ns
        SymbolIterator nsSyms = st.getSymbols(ns);
        Set<String> childNames = new LinkedHashSet<>();
        while (nsSyms.hasNext()) {
            Symbol s = nsSyms.next();
            if (s.getSymbolType() == SymbolType.NAMESPACE || s.getSymbolType() == SymbolType.CLASS) childNames.add(s.getName());
        }
        for (String cn : childNames) {
            Namespace child = st.getNamespace(cn, ns);
            if (child != null && !child.isGlobal()) collectFunctions(child, out, processed);
        }
    }

    private String functionRecord(Function f, String name, String nsPath) throws Exception {
        FuncSig sig = buildFunctionSignature(f);
        if (sig == null) return null;
        LinkedHashMap<String, String> r = new LinkedHashMap<>();
        r.put("ver", "1");
        r.put("name", name);
        r.put("namespace", nsPath);
        r.put("orig_addr", "0x" + f.getEntryPoint().toString());
        r.put("func_norm_sig", sig.normSig);
        r.put("func_insn_count", Integer.toString(sig.insnCount));
        r.put("blob_hex", toHex(sig.blob));
        r.put("mask_hex", toHex(sig.mask));
        r.put("feat_hash", sha256(sig.normSig + "|" + toHex(sig.blob) + "|" + toHex(sig.mask)));
        String proto = null, cc = null;
        try {
            proto = f.getPrototypeString(true, false);
            cc = f.getCallingConventionName();
        } catch (Exception e) { applyFailure("export-prototype", String.valueOf(e.getMessage()), name); }
        if (proto != null) r.put("prototype", proto);
        if (cc != null) r.put("calling_convention", cc);
        String[] callers = namedCallers(f), callees = namedCallees(f), strs = refStrings(f);
        if (callers.length > 0) r.put("callers", String.join(";;;", callers));
        if (callees.length > 0) r.put("callees", String.join(";;;", callees));
        if (strs.length > 0) r.put("strings", String.join(";;;", strs));
        return ndjsonEncode(r);
    }

    /**
     * Hand-named functions that never made it into a target namespace are invisible to the namespace
     * walk, so a migration drops both their names and every comment on them. USER_DEFINED is what
     * separates human RE work from the loader's and the analyzers' own symbols.
     */
    private int collectStrayNamedFunctions(List<String> out, Set<Function> processed) throws Exception {
        int n = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (f.isExternal() || f.isThunk() || processed.contains(f)) continue;
            Symbol s = f.getSymbol();
            if (s == null || s.getSource() != SourceType.USER_DEFINED) continue;
            // A switch-case label promoted to a function presents as a clean leaf ("default") under a
            // generated namespace ("switchD_005cf7dc"), so the whole path has to be screened.
            if (isDefaultName(f.getName())) continue;
            boolean generated = false;
            for (String part : fullNameOf(f).split("::")) if (isDefaultName(part)) generated = true;
            if (generated) continue;
            processed.add(f);
            String rec = functionRecord(f, f.getName(), fullNs(f.getParentNamespace()));
            if (rec == null) continue;
            out.add(rec);
            n++;
            println("  stray named function: " + fullNameOf(f) + " @ 0x" + f.getEntryPoint());
        }
        return n;
    }

    private List<String> exportDataLabels() throws Exception {
        List<String> out = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getDefinedSymbols();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSymbolType() != SymbolType.LABEL) continue;
            if (s.getSource() == SourceType.DEFAULT) continue;
            String name = s.getName();
            if (isDefaultName(name) || LIBC_LABELS.contains(name)) continue;
            // Switch-case labels present as a clean leaf ("switchD"/"default") under a generated parent,
            // and the analyser re-creates them at different addresses in every program.
            boolean generated = false;
            for (String part : fullNs(s.getParentNamespace()).split("::")) if (isDefaultName(part)) generated = true;
            if (generated) continue;
            Address a = s.getAddress();
            if (a == null || !a.isMemoryAddress()) continue;
            MemoryBlock blk = currentProgram.getMemory().getBlock(a);
            String seg = (blk != null) ? blk.getName() : "";
            LinkedHashMap<String, String> r = new LinkedHashMap<>();
            r.put("name", name);
            r.put("namespace", fullNs(s.getParentNamespace()));
            r.put("orig_addr", "0x" + a.toString());
            r.put("segment", seg);
            r.put("kind", "label");
            // ref_anchor for .rodata (shift-prone): first function that references this label
            if (seg != null && seg.contains("rodata")) {
                Reference[] refs = getReferencesTo(a);
                for (Reference ref : refs) {
                    Function rf = getFunctionContaining(ref.getFromAddress());
                    if (rf == null) continue;
                    int idx = insnIndexFromEntry(rf, ref.getFromAddress());
                    if (idx >= 0) {
                        r.put("ref_func", fullNameOf(rf));
                        r.put("ref_func_addr", "0x" + rf.getEntryPoint().toString());
                        r.put("ref_insn_index", Integer.toString(idx));
                        break;
                    }
                }
            }
            out.add(ndjsonEncode(r));
        }
        return out;
    }

    private List<String> exportComments(Set<Function> funcs) {
        List<String> out = new ArrayList<>();
        Listing listing = currentProgram.getListing();
        int[] kinds = {CodeUnit.PRE_COMMENT, CodeUnit.EOL_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT};
        String[] kindNames = {"pre", "eol", "post", "plate"};
        for (Function f : funcs) {
            Address entry = f.getEntryPoint();
            int index = 0;
            for (CodeUnit cu : listing.getCodeUnits(f.getBody(), true)) {
                for (int ki = 0; ki < kinds.length; ki++) {
                    String c = cu.getComment(kinds[ki]);
                    if (c == null || c.isEmpty()) continue;
                    long off = cu.getAddress().subtract(entry);
                    LinkedHashMap<String, String> r = new LinkedHashMap<>();
                    r.put("func", fullNameOf(f));
                    r.put("func_addr", "0x" + entry.toString());
                    r.put("kind", kindNames[ki]);
                    r.put("insn_offset_from_entry", Long.toString(off));
                    // Byte offsets only survive a build when every preceding instruction keeps its
                    // encoded length; the ordinal survives any re-encoding, so import prefers it.
                    r.put("cu_index_from_entry", Integer.toString(index));
                    r.put("text", c);
                    out.add(ndjsonEncode(r));
                }
                index++;
            }
        }
        return out;
    }

    // ============================================================ IMPORT ============================================================

    private void doImport() throws Exception {
        if (!Files.isDirectory(dataDir)) {
            // export was produced against the OLD version dir; allow override via arg-less newest-dir search
            Path found = newestDataDir();
            if (found != null) { dataDir = found; println("Using data dir: " + dataDir); }
            else { printerr("No updater_data_* dir found under " + updaterRoot); return; }
        }
        Files.createDirectories(offsetsDir);

        int tx = -1;
        if (apply) tx = currentProgram.startTransaction("RS3ProjectXUpdater import --apply");
        boolean ok = false;
        try {
            // 1) sig index (shared by function resolve + anchor sig strategy)
            Map<String, List<Function>> normIndex = indexFunctionsByNormalizedSignature();

            // 2) functions: resolve (+ apply rename/proto/comments)
            List<String> fnResults = importFunctions(normIndex);

            // 3) data labels (apply only)
            List<String> lblResults = importDataLabels();

            // 4) anchors: locate -> extract -> diff (+ name on apply)
            List<String> anchorResults = importAnchors(normIndex);

            // 4b) OFunctions block (resolved function addresses)
            List<String[]> ofunctions = importOFunctions(); // [const, qualifiedName, "0xADDR"|null]

            // 5) DoAction
            DoActionResult doAction = runDoAction();

            // ---- outputs (always) ----
            writeResultsJson(fnResults, lblResults, anchorResults, doAction, ofunctions);
            writeOffsetsKt(anchorResults, ofunctions);
            writeOffsetsJson(anchorResults, ofunctions, doAction);
            writeText(offsetsDir.resolve("DoActionOpcodes_" + version + ".kt"), doAction.ktBody);
            writeResidualReport(fnResults, lblResults, anchorResults);

            ok = true;
            println("IMPORT complete (" + (apply ? "APPLIED to DB" : "DRY-RUN, no DB writes") + "). Outputs in " + updaterRoot);
            if (!doActionParityLoss.isEmpty())
                printerr("*** DOACTION PARITY FAILURE (" + profile.id() + "): " + doActionParityLoss.size()
                        + " missing from this build's walk: " + doActionParityLoss);
        } finally {
            if (tx != -1) currentProgram.endTransaction(tx, ok && apply); // commit only if apply && ok
        }
    }

    private static String qualify(Map<String, String> r) {
        return (notEmpty(r.get("namespace")) ? r.get("namespace") + "::" : "") + r.get("name");
    }

    /** A signature carrying neither a return type nor a parameter list holds no information to preserve. */
    private static boolean bareSignature(String proto) {
        if (proto == null || proto.isEmpty()) return true;
        String p = proto.trim();
        int open = p.indexOf('('), close = p.lastIndexOf(')');
        if (open < 0 || close < open) return true;
        String params = p.substring(open + 1, close).trim();
        return p.startsWith("undefined ") && (params.isEmpty() || params.equals("void"));
    }

    /** Primary baseline first; each fallback contributes only names no earlier dir already carries. */
    private List<Map<String, String>> mergedFunctionRecords() throws IOException {
        List<Map<String, String>> out = new ArrayList<>();
        // A qualified name can legitimately cover several distinct functions (overloads, duplicated
        // bodies), so de-duplication happens only ACROSS baselines — never within one.
        Map<String, List<Map<String, String>>> byName = new LinkedHashMap<>();
        List<Path> chain = new ArrayList<>();
        chain.add(dataDir);
        chain.addAll(fallbackDataDirs);
        int protoBackfilled = 0;
        for (Path d : chain) {
            Path p = d.resolve("functions.ndjson");
            if (!Files.exists(p)) { println("WARN: no functions.ndjson under " + d); continue; }
            boolean primary = d.equals(dataDir);
            int added = 0, backfilledHere = 0;
            for (Map<String, String> r : readNdjson(p)) {
                String key = qualify(r);
                List<Map<String, String>> existing = byName.get(key);
                if (existing != null && !primary) {
                    for (Map<String, String> e : existing) {
                        if (bareSignature(e.get("prototype")) && !bareSignature(r.get("prototype"))) {
                            e.put("prototype", r.get("prototype"));
                            if (notEmpty(r.get("calling_convention"))) e.put("calling_convention", r.get("calling_convention"));
                            e.put("proto_origin", d.getFileName().toString());
                            backfilledHere++;
                        }
                    }
                    continue;
                }
                if (!primary) r.put("origin", d.getFileName().toString());
                byName.computeIfAbsent(key, k -> new ArrayList<>()).add(r);
                out.add(r);
                added++;
            }
            protoBackfilled += backfilledHere;
            println("baseline " + d.getFileName() + ": contributed " + added + " function records"
                    + (backfilledHere > 0 ? ", back-filled " + backfilledHere + " prototypes" : ""));
        }
        if (protoBackfilled > 0) println("prototypes back-filled from fallback baselines: " + protoBackfilled);
        return out;
    }

    private Map<String, List<Map<String, String>>> mergedComments() throws IOException {
        Map<String, List<Map<String, String>>> byFunc = new HashMap<>();
        List<Path> chain = new ArrayList<>();
        chain.add(dataDir);
        chain.addAll(fallbackDataDirs);
        for (Path d : chain) {
            Path p = d.resolve("comments.ndjson");
            if (!Files.exists(p)) continue;
            for (Map<String, String> c : readNdjson(p)) {
                // A fallback baseline may only supply comments for a function the primary said nothing
                // about; otherwise the older build's text would shadow the newer build's.
                List<Map<String, String>> cur = byFunc.get(c.get("func"));
                if (cur != null && !d.equals(dataDir) && !cur.isEmpty() && !d.equals(cur.get(0).get("__dir"))) continue;
                c.put("__dir", d.toString());
                byFunc.computeIfAbsent(c.get("func"), k -> new ArrayList<>()).add(c);
            }
        }
        return byFunc;
    }

    // returns result strings; applies rename+proto+comments when --apply
    private List<String> importFunctions(Map<String, List<Function>> normIndex) throws Exception {
        List<String> results = new ArrayList<>();
        List<Map<String, String>> recs = mergedFunctionRecords();
        Map<String, List<Map<String, String>>> commentsByFunc = mergedComments();

        // Pass 1: sig-match everything. AMBIGUOUS records are parked; their siblings are byte-identical
        // under the mask, so they can only be separated once the surrounding layout is known.
        Map<Map<String, String>, ResolveResult> resolved = new LinkedHashMap<>();
        for (Map<String, String> r : recs) {
            if (monitor.isCancelled()) break;
            ResolveResult res = resolveFunction(r, normIndex);
            if (res.status == ResolveStatus.AMBIGUOUS && res.candidates != null) {
                Function pick = disambiguateByXref(r, res.candidates);
                if (pick != null) { res.status = ResolveStatus.FOUND; res.address = pick.getEntryPoint(); res.note = "xref-disambiguated"; }
            }
            resolved.put(r, res);
        }

        int byOrder = resolveAmbiguousByLayout(resolved);

        // A fallback record can carry a DIFFERENT name for a function the primary already claimed
        // (the build renamed it), and sig-match it to the same address. Name-level precedence does not
        // catch that, so the address has to be claimed too or recovery silently reverts current work.
        Map<Long, String> claimedByPrimary = new HashMap<>();
        for (Map.Entry<Map<String, String>, ResolveResult> en : resolved.entrySet()) {
            if (en.getValue().status == ResolveStatus.FOUND && en.getValue().address != null
                    && en.getKey().get("origin") == null) {
                claimedByPrimary.putIfAbsent(en.getValue().address.getOffset(), qualify(en.getKey()));
            }
        }
        int supplanted = 0;
        for (Map.Entry<Map<String, String>, ResolveResult> en : resolved.entrySet()) {
            ResolveResult res = en.getValue();
            if (res.status != ResolveStatus.FOUND || res.address == null) continue;
            if (en.getKey().get("origin") == null) continue;
            String owner = claimedByPrimary.get(res.address.getOffset());
            if (owner == null) continue;
            String loser = qualify(en.getKey());
            res.status = ResolveStatus.COLLISION;
            res.note = "address already named '" + owner + "' by the current baseline";
            supplanted++;
            applyFailure("collision", "fallback name rejected, current name kept",
                    "0x" + res.address + "  keep='" + owner + "'  reject='" + loser + "'");
            println("  collision 0x" + res.address + ": keeping '" + owner + "', rejecting '" + loser + "'");
        }
        if (supplanted > 0) println("fallback records rejected to protect current names: " + supplanted);

        int found = 0, missing = 0, ambiguous = 0, renamed = 0, recovered = 0, collisions = 0;
        for (Map.Entry<Map<String, String>, ResolveResult> en : resolved.entrySet()) {
            Map<String, String> r = en.getKey();
            ResolveResult res = en.getValue();
            String full = qualify(r);
            String origin = r.get("origin");
            if (res.status == ResolveStatus.FOUND) {
                found++;
                if (origin != null) recovered++;
                resolvedFuncByName.put(full, res.address);
                if (apply) {
                    try {
                        Namespace tns = createNamespaceHierarchy(r.get("namespace"));
                        Symbol fs = currentProgram.getSymbolTable().getPrimarySymbol(res.address);
                        if (fs == null) applyFailure("rename", "no primary symbol at target", full);
                        else { fs.setNameAndNamespace(r.get("name"), tns, SourceType.USER_DEFINED); renamed++; }
                    } catch (Exception e) { applyFailure("rename", String.valueOf(e.getMessage()), full); }
                }
                // Both run in dry-run too: they resolve and count without mutating, so the preview reports
                // what an --apply would fail to place instead of discovering it after the fact.
                applyPrototype(res.address, r.get("prototype"), r.get("calling_convention"), full);
                applyComments(res.address, commentsByFunc.get(full), full);
            } else if (res.status == ResolveStatus.MISSING) missing++;
            else if (res.status == ResolveStatus.COLLISION) collisions++;
            else ambiguous++;
            String candList = null;
            if (res.status == ResolveStatus.AMBIGUOUS && res.candidates != null) {
                StringBuilder cb = new StringBuilder();
                for (Function c : res.candidates) { if (cb.length() > 0) cb.append(','); cb.append("0x").append(c.getEntryPoint()); }
                candList = cb.toString();
            }
            results.add(String.format("{\"name\":%s,\"namespace\":%s,\"status\":\"%s\",\"new\":%s,\"old\":%s,\"note\":%s,\"origin\":%s,\"candidates\":%s}",
                    jstr(r.get("name")), jstr(r.get("namespace")), res.status,
                    res.address != null ? jstr("0x" + res.address.toString()) : "null",
                    jstr(r.get("orig_addr")), jstr(res.note), origin != null ? jstr(origin) : "null",
                    candList != null ? jstr(candList) : "null"));
        }
        println("functions: FOUND=" + found + " (of which " + byOrder + " were rescued from AMBIGUOUS by layout order, "
                + recovered + " genuinely recovered from fallback baselines)"
                + " MISSING=" + missing + " AMBIGUOUS-still-unresolved=" + ambiguous
                + " COLLISION-rejected=" + collisions);
        if (apply) println("applied: renames=" + renamed + " prototypes=" + protoApplied
                + " callingConventions=" + ccApplied + " comments=" + commentsPlaced);
        return results;
    }

    /**
     * Functions keep their relative order in .text across a build, so an ambiguous record's true match is
     * the candidate lying between its nearest unambiguously-resolved neighbours. Where the window still
     * admits several, the one closest to the neighbour-delta prediction wins. This is what separates the
     * near-identical sibling families (the prot handlers, the button-pair handlers) that mask-equal
     * signature matching cannot tell apart on its own.
     */
    private int resolveAmbiguousByLayout(Map<Map<String, String>, ResolveResult> resolved) {
        // Each baseline's orig_addr lives in its own build's address space, so anchors may only ever be
        // compared with records from the same baseline; one shared map would place a record between two
        // neighbours it has no ordering relationship with and pick a confidently wrong sibling.
        Map<String, TreeMap<Long, Long>> anchorsByOrigin = new HashMap<>();
        Map<Long, Integer> shiftHistogram = new HashMap<>();
        for (Map.Entry<Map<String, String>, ResolveResult> e : resolved.entrySet()) {
            if (e.getValue().status != ResolveStatus.FOUND || e.getValue().address == null) continue;
            Long oldA = parseAddrLong(e.getKey().get("orig_addr"));
            if (oldA == null) continue;
            String origin = e.getKey().getOrDefault("origin", "");
            anchorsByOrigin.computeIfAbsent(origin, k -> new TreeMap<>()).put(oldA, e.getValue().address.getOffset());
            if (origin.isEmpty()) shiftHistogram.merge(e.getValue().address.getOffset() - oldA, 1, Integer::sum);
        }
        Long modalShift = null;
        int modalCount = 0, shiftTotal = 0;
        for (Map.Entry<Long, Integer> e : shiftHistogram.entrySet()) {
            shiftTotal += e.getValue();
            if (e.getValue() > modalCount) { modalCount = e.getValue(); modalShift = e.getKey(); }
        }
        // Only trust it when most of the binary actually agrees; a scattered histogram means the build
        // moved code in many independent steps and the modal value carries no information.
        if (modalShift != null && modalCount * 2 <= shiftTotal) modalShift = null;
        if (modalShift != null)
            println("dominant .text shift: " + (modalShift >= 0 ? "+0x" : "-0x")
                    + Long.toHexString(Math.abs(modalShift)) + " (" + modalCount + "/" + shiftTotal + " functions)");

        int fixed = resolveUniformStrideBlocks(resolved);

        for (Map.Entry<Map<String, String>, ResolveResult> e : resolved.entrySet()) {
            ResolveResult res = e.getValue();
            if (res.status != ResolveStatus.AMBIGUOUS || res.candidates == null || res.candidates.size() < 2) continue;
            Long oldA = parseAddrLong(e.getKey().get("orig_addr"));
            if (oldA == null) continue;

            // Tested before the neighbour window, not after: the shift the rest of the binary agreed on
            // does not depend on how densely the local region happens to be anchored, and a sparse window
            // can otherwise discard the very candidate the global evidence points at.
            if (modalShift != null) {
                List<Function> onModal = new ArrayList<>();
                for (Function c : res.candidates) if (c.getEntryPoint().getOffset() == oldA + modalShift) onModal.add(c);
                if (onModal.size() == 1) {
                    res.status = ResolveStatus.FOUND; res.address = onModal.get(0).getEntryPoint();
                    res.note = "modal-shift(+0x" + Long.toHexString(modalShift) + ")";
                    fixed++; continue;
                }
            }

            TreeMap<Long, Long> anchorsByOld = anchorsByOrigin.get(e.getKey().getOrDefault("origin", ""));
            if (anchorsByOld == null || anchorsByOld.size() < 2) continue;
            Map.Entry<Long, Long> lo = anchorsByOld.lowerEntry(oldA), hi = anchorsByOld.higherEntry(oldA);
            if (lo == null && hi == null) continue;

            List<Function> inWindow = new ArrayList<>();
            for (Function c : res.candidates) {
                long a = c.getEntryPoint().getOffset();
                if (lo != null && a <= lo.getValue()) continue;
                if (hi != null && a >= hi.getValue()) continue;
                inWindow.add(c);
            }
            if (inWindow.isEmpty()) continue;
            if (inWindow.size() == 1) {
                res.status = ResolveStatus.FOUND; res.address = inWindow.get(0).getEntryPoint();
                res.note = "layout-window"; fixed++; continue;
            }
            Map.Entry<Long, Long> ref = (lo != null) ? lo : hi;
            long predicted = ref.getValue() + (oldA - ref.getKey());
            Function best = null; long bestD = Long.MAX_VALUE, runnerUp = Long.MAX_VALUE;
            for (Function c : inWindow) {
                long d = Math.abs(c.getEntryPoint().getOffset() - predicted);
                if (d < bestD) { runnerUp = bestD; bestD = d; best = c; }
                else if (d < runnerUp) runnerUp = d;
            }
            // An unconvincing lead is worse than an admitted ambiguity: a wrong rename is silent.
            if (best != null && runnerUp != Long.MAX_VALUE && runnerUp > bestD * 4) {
                res.status = ResolveStatus.FOUND; res.address = best.getEntryPoint();
                res.note = "layout-predicted(delta=" + bestD + ")"; fixed++;
            }
        }
        return fixed;
    }

    /**
     * A contiguous block of identical thunks — the DoOp menu wrappers are the standing example — is
     * byte-identical member to member, so no signature can ever separate them and scoring is the wrong
     * instrument. What does distinguish them is position: the block keeps its stride and its internal
     * order across a build. Such a block is self-anchoring, which matters because when every member is
     * ambiguous at once there is no resolved neighbour left to interpolate from.
     */
    private int resolveUniformStrideBlocks(Map<Map<String, String>, ResolveResult> resolved) {
        Map<String, List<Map.Entry<Map<String, String>, ResolveResult>>> groups = new LinkedHashMap<>();
        for (Map.Entry<Map<String, String>, ResolveResult> e : resolved.entrySet()) {
            ResolveResult r = e.getValue();
            if (r.status != ResolveStatus.AMBIGUOUS || r.candidates == null || r.candidates.size() < 2) continue;
            if (parseAddrLong(e.getKey().get("orig_addr")) == null) continue;
            TreeSet<Long> key = new TreeSet<>();
            for (Function c : r.candidates) key.add(c.getEntryPoint().getOffset());
            groups.computeIfAbsent(key.toString(), k -> new ArrayList<>()).add(e);
        }

        int fixed = 0;
        for (List<Map.Entry<Map<String, String>, ResolveResult>> g : groups.values()) {
            if (g.size() < 3) continue;
            g.sort(Comparator.comparingLong(x -> parseAddrLong(x.getKey().get("orig_addr"))));
            long stride = parseAddrLong(g.get(1).getKey().get("orig_addr")) - parseAddrLong(g.get(0).getKey().get("orig_addr"));
            if (stride <= 0) continue;
            boolean uniform = true;
            for (int i = 2; i < g.size(); i++) {
                long d = parseAddrLong(g.get(i).getKey().get("orig_addr")) - parseAddrLong(g.get(i - 1).getKey().get("orig_addr"));
                if (d != stride) { uniform = false; break; }
            }
            if (!uniform) continue;

            TreeSet<Long> cands = new TreeSet<>();
            for (Function c : g.get(0).getValue().candidates) cands.add(c.getEntryPoint().getOffset());
            List<List<Long>> runs = new ArrayList<>();
            List<Long> cur = new ArrayList<>();
            Long prev = null;
            for (Long a : cands) {
                if (prev != null && a - prev == stride) cur.add(a);
                else { if (cur.size() >= g.size()) runs.add(new ArrayList<>(cur)); cur = new ArrayList<>(); cur.add(a); }
                prev = a;
            }
            if (cur.size() >= g.size()) runs.add(cur);
            // Exactly one run of exactly the block's length, or the mapping is a guess and is refused.
            List<List<Long>> exact = new ArrayList<>();
            for (List<Long> r : runs) if (r.size() == g.size()) exact.add(r);
            if (exact.size() != 1) {
                println("  stride block of " + g.size() + " @stride 0x" + Long.toHexString(stride)
                        + ": " + exact.size() + " candidate runs of matching length — refusing to guess");
                continue;
            }
            List<Long> run = exact.get(0);
            long oldSpan = parseAddrLong(g.get(g.size() - 1).getKey().get("orig_addr")) - parseAddrLong(g.get(0).getKey().get("orig_addr"));
            if (run.get(run.size() - 1) - run.get(0) != oldSpan) {
                println("  stride block span mismatch — refusing to guess");
                continue;
            }
            for (int i = 0; i < g.size(); i++) {
                ResolveResult r = g.get(i).getValue();
                r.status = ResolveStatus.FOUND;
                r.address = addrOf(run.get(i));
                r.note = "stride-block(ordinal " + i + "/" + g.size() + " @0x" + Long.toHexString(stride) + ")";
                fixed++;
                println("  stride block: " + qualify(g.get(i).getKey()) + " -> 0x" + Long.toHexString(run.get(i)));
            }
        }
        return fixed;
    }

    private Long parseAddrLong(String s) {
        if (s == null) return null;
        try { return Long.parseLong(s.replace("0x", "").trim(), 16); } catch (Exception e) { return null; }
    }

    // Resolve the OFunctions block (const -> qualified name) via the function sig-match results.
    @SuppressWarnings("unchecked")
    private List<String[]> importOFunctions() throws Exception {
        List<String[]> out = new ArrayList<>();
        Path p = dataDir.resolve("anchors.json");
        if (!Files.exists(p)) return out;
        Object root = Json.parse(readText(p));
        Object ofs = ((Map<String, Object>) root).get("ofunctions");
        if (!(ofs instanceof List)) return out;
        int found = 0, bySig = 0;
        for (Object o : (List<Object>) ofs) {
            Map<String, Object> e = (Map<String, Object>) o;
            String c = str(e.get("const")), name = str(e.get("name"));
            Address a = resolvedFuncByName.get(name);
            if (a == null) { Function f = findFunctionByQualifiedName(name); if (f != null) a = f.getEntryPoint(); }
            String how = a != null ? "name" : null;
            if (a == null) {
                Function f = locateBySig(e, null);
                if (f != null) { a = f.getEntryPoint(); how = "signature"; bySig++; }
            }
            if (a != null) found++;
            else applyFailure("ofunction", "unresolved by name and by signature", c + " (" + name + ")");
            out.add(new String[]{c, name, a != null ? "0x" + a.toString() : null});
        }
        println("OFunctions resolved: " + found + "/" + out.size() + " (" + bySig + " by stamped signature)");
        return out;
    }

    private int protoApplied = 0, ccApplied = 0, commentsPlaced = 0;
    private FunctionSignatureParser sigParser;

    private void applyPrototype(Address addr, String proto, String cc, String subject) {
        Function f = getFunctionAt(addr);
        if (f == null) { applyFailure("prototype", "no function at target", subject); return; }
        if (cc != null && !cc.isEmpty()) {
            try { if (apply) f.setCallingConvention(cc); ccApplied++; }
            catch (Exception e) { applyFailure("calling-convention", String.valueOf(e.getMessage()), subject + " cc=" + cc); }
        }
        if (proto == null || proto.isEmpty()) { applyFailure("prototype", "not present in export", subject); return; }
        try {
            if (sigParser == null) sigParser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
            FunctionDefinitionDataType def = sigParser.parse(f.getSignature(), proto);
            if (def == null) { applyFailure("prototype", "parser returned null", subject); return; }
            if (!apply) { protoApplied++; return; }
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(addr, def, SourceType.USER_DEFINED);
            if (cmd.applyTo(currentProgram, monitor)) protoApplied++;
            else applyFailure("prototype", "apply rejected: " + cmd.getStatusMsg(), subject);
        } catch (Exception e) {
            // Almost always a data type the export references that this program's DTM has not been given
            // yet; RS3DataTypeImporter must run before the names carry their real signatures.
            applyFailure("prototype", "parse failed: " + e.getMessage(), subject);
        }
    }

    /**
     * Re-anchor by code-unit ordinal. A byte offset only survives a build when every preceding
     * instruction keeps its encoded length, so on any re-encoding it lands mid-instruction and the
     * comment is lost; the ordinal survives that.
     */
    private void applyComments(Address newEntry, List<Map<String, String>> comments, String subject) {
        if (comments == null || comments.isEmpty()) return;
        Listing listing = currentProgram.getListing();
        Function f = getFunctionAt(newEntry);
        if (f == null) {
            for (Map<String, String> c : comments) applyFailure("comment", "no function at target", subject + " [" + c.get("kind") + "]");
            return;
        }
        List<Address> units = new ArrayList<>();
        for (CodeUnit cu : listing.getCodeUnits(f.getBody(), true)) units.add(cu.getAddress());
        if (units.isEmpty()) {
            for (Map<String, String> c : comments) applyFailure("comment", "no code units in body", subject + " [" + c.get("kind") + "]");
            return;
        }
        for (Map<String, String> c : comments) {
            String kindName = c.getOrDefault("kind", "pre");
            String what = subject + " [" + kindName + "]";
            Address at = null;
            String idxRaw = c.get("cu_index_from_entry");
            if (idxRaw != null) {
                try {
                    int idx = Integer.parseInt(idxRaw);
                    if (idx >= 0 && idx < units.size()) at = units.get(idx);
                } catch (NumberFormatException ignore) { }
            }
            if (at == null) {
                // Older export data, or an ordinal past the end of a body that shrank: fall back to the
                // byte offset, snapped to the code unit containing it so it can never land mid-instruction.
                try {
                    long off = Long.parseLong(c.get("insn_offset_from_entry"));
                    Address raw = newEntry.add(off);
                    CodeUnit cu = listing.getCodeUnitContaining(raw);
                    if (cu != null && f.getBody().contains(cu.getAddress())) at = cu.getAddress();
                } catch (Exception ignore) { }
            }
            if (at == null) { applyFailure("comment", "no anchor in new body", what); continue; }
            int kind = switch (kindName) {
                case "eol" -> CodeUnit.EOL_COMMENT;
                case "post" -> CodeUnit.POST_COMMENT;
                case "plate" -> CodeUnit.PLATE_COMMENT;
                default -> CodeUnit.PRE_COMMENT;
            };
            try { if (apply) listing.setComment(at, kind, stripStaleAddrs(c.get("text"))); commentsPlaced++; }
            catch (Exception e) { applyFailure("comment", "setComment: " + e.getMessage(), what); }
        }
    }

    private List<String> importDataLabels() throws Exception {
        List<String> results = new ArrayList<>();
        Path p = dataDir.resolve("datalabels.ndjson");
        if (!Files.exists(p)) return results;
        SymbolTable st = currentProgram.getSymbolTable();
        for (Map<String, String> r : readNdjson(p)) {
            String name = r.get("name");
            String nsPath = r.get("namespace");
            Address a = parseAddr(r.get("orig_addr"));
            boolean placed = false;
            String note = "dry-run";
            if (apply && a != null) {
                try {
                    Namespace ns = createNamespaceHierarchy(nsPath);
                    // rename existing symbol at addr, or create label
                    Symbol existing = st.getPrimarySymbol(a);
                    if (existing != null && existing.getSymbolType() == SymbolType.LABEL) {
                        existing.setNameAndNamespace(name, ns, SourceType.USER_DEFINED);
                        placed = true; note = "renamed";
                    } else {
                        Symbol ns2 = st.createLabel(a, name, ns, SourceType.USER_DEFINED);
                        placed = ns2 != null; note = placed ? "created" : "noop";
                    }
                } catch (Exception e) { note = "fail: " + e.getMessage(); }
                if (!placed) note = recoverRodataLabel(r, name, nsPath) ? "recovered-via-ref" : "noop-needs-review";
            }
            results.add(String.format("{\"label\":%s,\"namespace\":%s,\"old\":%s,\"placed\":%s,\"note\":%s}",
                    jstr(name), jstr(nsPath), jstr(r.get("orig_addr")), placed, jstr(note)));
        }
        return results;
    }

    // .rodata shift recovery: re-read the referencing instruction's operand address in the NEW binary
    private boolean recoverRodataLabel(Map<String, String> r, String name, String nsPath) {
        try {
            String refFuncName = r.get("ref_func");
            int idx = r.containsKey("ref_insn_index") ? Integer.parseInt(r.get("ref_insn_index")) : -1;
            if (refFuncName == null || idx < 0) return false;
            Function rf = findFunctionByQualifiedName(refFuncName);
            if (rf == null) return false;
            Instruction insn = getInstructionAt(rf.getEntryPoint());
            for (int i = 0; i < idx && insn != null; i++) insn = insn.getNext();
            if (insn == null) return false;
            Address tgt = firstAddressOperand(insn);
            if (tgt == null) return false;
            Namespace ns = createNamespaceHierarchy(nsPath);
            Symbol s = currentProgram.getSymbolTable().createLabel(tgt, name, ns, SourceType.USER_DEFINED);
            return s != null;
        } catch (Exception e) { return false; }
    }

    // ============================================================ ANCHORS ============================================================

    private List<String> importAnchors(Map<String, List<Function>> normIndex) throws Exception {
        List<String> results = new ArrayList<>();
        // The REGISTRY is the recipe; the exported snapshot only carries what the old binary could stamp
        // onto it (signatures and the value it self-resolved). Iterating the snapshot instead meant every
        // registry edit was invisible until the next export — a repaired recipe, a renamed target and a
        // newly added anchor all silently kept using the version the baseline was exported with.
        List<Object> anchors = registryAnchors();
        if (anchors.isEmpty()) { println("no anchors in anchor_registry.json"); return results; }
        Map<String, Map<String, Object>> stamped = exportedAnchorSnapshot();
        int skipped = 0;

        for (Object ao : anchors) {
            Map<String, Object> a = (Map<String, Object>) ao;
            String id = str(a.get("id"));
            if (a.containsKey("shared_anchor")) continue; // emitted by its owner
            mergeStampedSignature(a, stamped.get(id));
            // A recipe written for the other toolchain is not a gap in this one. Evaluating it here
            // produced a MISSING per platform for every platform-scoped pair, which is half the
            // migration's "unlocated" count and hides the anchors that really did break.
            String scope = anchorPlatform(a, id);
            if (scope != null && !scope.equals(profile.id())) {
                skipped++;
                results.add(anchorResult(id, false, str(a.get("old_value")), null, "SKIPPED",
                        "platform-scoped to " + scope, null));
                continue;
            }
            String oldVal = str(a.get("old_value"));
            if (a.containsKey("manager_class")) {
                String mc = str(a.get("manager_class"));
                int minSites = a.get("min_sites") == null ? 3 : ((Number) a.get("min_sites")).intValue();
                long dmin = a.get("disp_min") == null ? 0x400L : parseHexOrDec(str(a.get("disp_min")));
                long dmax = a.get("disp_max") == null ? 0x20000L : parseHexOrDec(str(a.get("disp_max")));
                long[] r = resolveManagerClass(mc, minSites, dmin, dmax);
                if (r == null) { results.add(anchorResult(id, false, oldVal, null, "MISSING", "manager-class-no-consensus:" + mc, null)); continue; }
                String newVal = "0x" + Long.toHexString(r[0]);
                boolean changed = oldVal != null && !normHex(oldVal).equals(normHex(newVal));
                results.add(anchorResult(id, true, oldVal, newVal, "HIGH",
                        "manager_class " + mc + " (" + r[1] + "/" + r[2] + " sites)" + (changed ? " CHANGED" : ""), null));
                continue;
            }
            Map<String, Object> anchorDef = (Map<String, Object>) a.get("anchor");
            Map<String, Object> extract = (Map<String, Object>) a.get("extract");
            if (anchorDef == null || extract == null) {
                results.add(anchorResult(id, false, oldVal, null, "MISSING", "no-anchor-or-recipe", null));
                continue;
            }
            // locate
            Located loc = locateAnchor(anchorDef, normIndex);
            if (loc == null || loc.func == null) {
                results.add(anchorResult(id, false, oldVal, null, "MISSING", "anchor-not-located", null));
                continue;
            }
            // extract (may emit multiple offsets)
            try {
                Map<String, Long> emitted = extractAnchor(anchorDef, extract, loc.func);
                for (Map.Entry<String, Long> e : emitted.entrySet()) {
                    String emitId = e.getKey();
                    String newVal = "0x" + Long.toHexString(e.getValue());
                    String prevOld = emitId.equals(id) ? oldVal : lookupOldValue(anchors, emitId);
                    boolean changed = prevOld != null && !normHex(prevOld).equals(normHex(newVal));
                    results.add(anchorResult(emitId, true, prevOld, newVal, loc.confidence,
                            loc.method + (changed ? " CHANGED" : ""), "0x" + loc.func.getEntryPoint().toString()));
                }
                if (apply) nameAnchor(loc.func, anchorDef);
            } catch (Ambiguous ex) {
                results.add(anchorResult(id, false, oldVal, null, "AMBIGUOUS", "no majority: " + ex.getMessage(),
                        "0x" + loc.func.getEntryPoint().toString()));
            } catch (Exception ex) {
                results.add(anchorResult(id, false, oldVal, null, "FAIL", "recipe-error: " + ex.getMessage(),
                        "0x" + loc.func.getEntryPoint().toString()));
            }
        }
        if (skipped > 0) println("anchors: " + skipped + " skipped — scoped to the other platform");
        return results;
    }

    @SuppressWarnings("unchecked")
    private List<Object> registryAnchors() throws IOException {
        Path regPath = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(regPath)) { println("WARN: anchor_registry.json missing"); return List.of(); }
        Object rows = ((Map<String, Object>) Json.parse(readText(regPath))).get("anchors");
        return (rows instanceof List) ? (List<Object>) rows : List.of();
    }

    /** What EXPORT stamped onto each anchor against the OLD binary, keyed by id. */
    @SuppressWarnings("unchecked")
    private Map<String, Map<String, Object>> exportedAnchorSnapshot() throws IOException {
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Path dir : allDataDirs()) {
            Path p = dir.resolve("anchors.json");
            if (!Files.exists(p)) continue;
            Object rows = ((Map<String, Object>) Json.parse(readText(p))).get("anchors");
            if (!(rows instanceof List)) continue;
            for (Object o : (List<Object>) rows) {
                Map<String, Object> a = (Map<String, Object>) o;
                String id = str(a.get("id"));
                if (id != null) out.putIfAbsent(id, a);
            }
        }
        return out;
    }

    private List<Path> allDataDirs() {
        List<Path> chain = new ArrayList<>();
        chain.add(dataDir);
        chain.addAll(fallbackDataDirs);
        return chain;
    }

    /**
     * A signature can only be taken from the binary that was exported, so the snapshot supplies it — but
     * only onto a recipe the registry still spells the same way. A recipe that has been edited since the
     * export keeps the registry's own text; only the stamped fields are borrowed.
     */
    @SuppressWarnings("unchecked")
    private void mergeStampedSignature(Map<String, Object> live, Map<String, Object> snap) {
        if (snap == null) return;
        if (live.get("old_value") == null && snap.get("old_value") != null) live.put("old_value", snap.get("old_value"));
        Object ld = live.get("anchor"), sd = snap.get("anchor");
        if (!(ld instanceof Map) || !(sd instanceof Map)) return;
        Map<String, Object> l = (Map<String, Object>) ld, sm = (Map<String, Object>) sd;
        for (String k : new String[]{"sig_blob", "sig_mask", "feat_hash"})
            if (l.get(k) == null && sm.get(k) != null) l.put(k, sm.get(k));
    }

    /**
     * Which platform an anchor is written for. Declared by `platform`, else inferred from the `.msvc`
     * suffix the registry has always used to mark a recipe as the MSVC counterpart of an ELF one.
     */
    private String anchorPlatform(Map<String, Object> a, String id) {
        String declared = str(a.get("platform"));
        if (declared != null && !declared.isEmpty()) return declared;
        return (id != null && id.endsWith(".msvc")) ? "windows-x86_64" : null;
    }

    /** Anchor ids the registry currently declares, snapshot or not. Empty means the registry is unreadable. */
    @SuppressWarnings("unchecked")
    private Set<String> liveAnchorIds() throws IOException {
        Set<String> out = new LinkedHashSet<>();
        Path regPath = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(regPath)) return out;
        Object rows = ((Map<String, Object>) Json.parse(readText(regPath))).get("anchors");
        if (rows instanceof List) for (Object o : (List<Object>) rows) {
            String id = str(((Map<String, Object>) o).get("id"));
            if (id != null) out.add(id);
        }
        return out;
    }

    /**
     * Some OFunctions entries were established by address alone — an inlined or unnamed routine that
     * carries no symbol to look up in the next build. Name resolution can never recover those, and on a
     * platform whose .text shifts they cannot be carried either, so the only durable handle is a
     * signature taken from the function that currently lives at the recorded address.
     */
    @SuppressWarnings("unchecked")
    private void stampOFunctionSignatures(Map<String, Object> rootMap) throws Exception {
        Object ofs = rootMap.get("ofunctions");
        if (!(ofs instanceof List)) return;
        Path table = engineOffsetsDir().resolve(profile.id() + "-" + version + ".json");
        if (!Files.exists(table)) { println("no engine table for " + profile.id() + "-" + version + "; OFunctions signatures not stamped"); return; }
        Map<String, Object> t = (Map<String, Object>) Json.parse(readText(table));
        Map<String, Object> objects = (Map<String, Object>) t.get("objects");
        if (objects == null) return;
        Map<String, Object> of = (Map<String, Object>) objects.get("OFunctions");
        if (of == null) return;

        int stamped = 0, unnamed = 0;
        for (Object o : (List<Object>) ofs) {
            Map<String, Object> e = (Map<String, Object>) o;
            Map<String, Object> entry = (Map<String, Object>) of.get(str(e.get("const")));
            if (entry == null) continue;
            Address a = parseAddr(str(entry.get("value")));
            if (a == null) continue;
            Function f = getFunctionAt(a);
            if (f == null) continue;
            FuncSig sig = buildFunctionSignature(f);
            if (sig == null) continue;
            e.put("old_addr", "0x" + a.toString());
            e.put("sig_blob", toHex(sig.blob));
            e.put("sig_mask", toHex(sig.mask));
            e.put("sig_norm", sig.normSig);
            stamped++;
            if (isDefaultName(f.getName())) unnamed++;
        }
        println("OFunctions signatures stamped from the engine table: " + stamped
                + " (" + unnamed + " of them have no symbol and are recoverable ONLY by signature)");
    }

    /**
     * Stamp the value this binary actually yields into the exported anchor snapshot. The registry stays
     * declarative; without this the next import diffs the new build against whatever build last had its
     * old_value hand-edited, which both invents drift and hides it.
     */
    @SuppressWarnings("unchecked")
    private void reseed(List<Object> anchors, String id, String value) {
        if (id == null) return;
        for (Object ao : anchors) {
            Map<String, Object> a = (Map<String, Object>) ao;
            if (id.equals(str(a.get("id")))) { a.put("old_value", value); return; }
        }
    }

    private String lookupOldValue(List<Object> anchors, String id) {
        for (Object ao : anchors) {
            Map<String, Object> a = (Map<String, Object>) ao;
            if (id.equals(str(a.get("id")))) return str(a.get("old_value"));
        }
        return null;
    }

    private static class Located { Function func; String method; String confidence; }

    // Lazy, short-circuiting location (cheap strategies first; the O(funcs) sig scan is last resort).
    // Uses prebuilt nameMap/stringFnMap so this is O(1) per anchor for the common cases.
    private Located locateAnchor(Map<String, Object> anchorDef, Map<String, List<Function>> normIndex) {
        buildLookupMaps();
        Set<String> strats = new HashSet<>();
        for (Object s : (List<Object>) anchorDef.getOrDefault("identify_by", Collections.emptyList())) strats.add(str(s));
        Located out = new Located();
        if (strats.contains("string_xref")) {
            Function f = locateByString(str(anchorDef.get("string")));
            if (f != null) { out.func = f; out.method = "string_xref"; out.confidence = "HIGH"; return out; }
        }
        if (strats.contains("func_name")) {
            Function f = findFunctionByQualifiedName(str(anchorDef.get("official_name")));
            if (f != null) { out.func = f; out.method = "func_name"; out.confidence = "HIGH"; return out; }
        }
        if (strats.contains("sig")) {
            Function f = locateBySig(anchorDef, normIndex);
            if (f != null) { out.func = f; out.method = "sig"; out.confidence = "MEDIUM"; return out; }
        }
        return null;
    }

    private void buildLookupMaps() {
        if (nameMap != null) return;
        nameMap = new HashMap<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) nameMap.putIfAbsent(fullNameOf(f), f);
        stringFnMap = new HashMap<>();
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        while (di.hasNext() && !monitor.isCancelled()) {
            Data d = di.next();
            Object v = d.getValue();
            if (v instanceof String sv && !stringFnMap.containsKey(sv)) {
                for (Reference ref : getReferencesTo(d.getAddress())) {
                    Function f = getFunctionContaining(ref.getFromAddress());
                    if (f != null) { stringFnMap.put(sv, f); break; }
                }
            }
        }
        println("lookup maps: " + nameMap.size() + " named funcs, " + stringFnMap.size() + " referenced strings");
    }

    private Function locateByString(String s) {
        if (s == null) return null;
        buildLookupMaps();
        return stringFnMap.get(s);
    }

    private Function locateBySig(Map<String, Object> anchorDef, Map<String, List<Function>> normIndex) {
        String blobHex = str(anchorDef.get("sig_blob"));
        String maskHex = str(anchorDef.get("sig_mask"));
        if (blobHex == null || maskHex == null) return null;
        byte[] blob = fromHex(blobHex), mask = fromHex(maskHex);
        Function best = null; int bestMis = Integer.MAX_VALUE; int matches = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            byte[] fb = readFunctionBytes(f, blob.length);
            if (fb == null) continue;
            int mis = maskedHamming(blob, mask, fb);
            if (mis <= VERIFY_MAX_MISMATCH) { matches++; if (mis < bestMis) { bestMis = mis; best = f; } }
        }
        return matches == 1 ? best : null; // ambiguous sig => null (reported elsewhere)
    }

    private void nameAnchor(Function f, Map<String, Object> anchorDef) {
        String official = str(anchorDef.get("official_name"));
        try {
            if (official != null && !official.isEmpty()) {
                int idx = official.lastIndexOf("::");
                String nm = idx >= 0 ? official.substring(idx + 2) : official;
                String ns = idx >= 0 ? official.substring(0, idx) : "";
                Namespace tns = createNamespaceHierarchy(ns);
                f.getSymbol().setNameAndNamespace(nm, tns, SourceType.USER_DEFINED);
            } else {
                setPlateComment(f.getEntryPoint(), "HYPOTHESIS: RS3ProjectXUpdater anchor (no official name)");
            }
        } catch (Exception e) {
            applyFailure("anchor-name", String.valueOf(e.getMessage()), official + " @ 0x" + f.getEntryPoint());
        }
    }

    // ---- the DSL interpreter ----
    private Map<String, Long> runRecipe(Function f, Map<String, Object> extract) {
        List<Instruction> insns = bodyInstructions(f, RECIPE_MAX_INSNS);
        List<Object> steps = (List<Object>) extract.get("steps");
        Map<String, Long> captures = new LinkedHashMap<>();
        Map<String, String> regBinds = new HashMap<>(); // @name -> register string
        int cursor = 0;
        for (Object so : steps) {
            Map<String, Object> step = (Map<String, Object>) so;
            String op = str(step.get("op"));
            switch (op) {
                case "find", "find_after" -> {
                    int start = "find".equals(op) ? 0 : cursor;
                    int occ = step.containsKey("occurrence") ? ((Number) step.get("occurrence")).intValue() : 1;
                    int seen = 0, matchIdx = -1;
                    for (int i = start; i < insns.size(); i++) {
                        if (matchesStep(insns.get(i), step, regBinds)) {
                            if (++seen == occ) { matchIdx = i; break; }
                        }
                    }
                    if (matchIdx < 0) throw new RuntimeException("step '" + op + "' no match");
                    cursor = matchIdx + 1;
                    bindAndCapture(insns.get(matchIdx), step, regBinds, captures);
                }
                case "find_before" -> {
                    int occ = step.containsKey("occurrence") ? ((Number) step.get("occurrence")).intValue() : 1;
                    int seen = 0, matchIdx = -1;
                    for (int i = cursor - 2; i >= 0; i--) {
                        if (matchesStep(insns.get(i), step, regBinds)) {
                            if (++seen == occ) { matchIdx = i; break; }
                        }
                    }
                    if (matchIdx < 0) throw new RuntimeException("step 'find_before' no match");
                    cursor = matchIdx + 1;
                    bindAndCapture(insns.get(matchIdx), step, regBinds, captures);
                }
                case "rip_target" -> {
                    Map<String, Object> match = (Map<String, Object>) step.getOrDefault("match", step);
                    String mn = str(match.get("mnemonic"));
                    Long t = null;
                    for (Instruction in : insns) {
                        if (mn != null && !mn.equalsIgnoreCase(in.getMnemonicString())) continue;
                        for (Reference rf : in.getReferencesFrom()) {
                            if (!rf.getReferenceType().isData()) continue;
                            MemoryBlock blk = currentProgram.getMemory().getBlock(rf.getToAddress());
                            if (blk != null && blk.isWrite()) { t = rf.getToAddress().getOffset(); break; } // global ptr lives in writable .data/.bss
                        }
                        if (t != null) break;
                    }
                    if (t == null) throw new RuntimeException("rip_target: no writable-data reference found");
                    captures.put(str(step.get("as")), t);
                }
                case "call_arg" -> {
                    // capture LEA argN,[base+disp] immediately before a CALL to the named function
                    String callee = str(step.get("call"));
                    int argN = ((Number) step.get("arg")).intValue();
                    Long disp = captureCallArg(insns, callee, argN, step);
                    if (disp == null) throw new RuntimeException("call_arg not found for " + callee);
                    captures.put(captureName(step), disp);
                }
                case "back_scan" -> {
                    String callee = str(step.get("from_call"));
                    Long disp = backScanDisp(insns, callee, step, regBinds);
                    if (disp == null) throw new RuntimeException("back_scan not found for " + callee);
                    captures.put(captureName(step), disp);
                }
                default -> throw new RuntimeException("unknown op " + op);
            }
        }
        // emit
        Map<String, Long> out = new LinkedHashMap<>();
        for (Object eo : (List<Object>) extract.get("emit")) {
            Map<String, Object> em = (Map<String, Object>) eo;
            out.put(str(em.get("id")), evalExpr(str(em.get("value")), captures));
        }
        return out;
    }

    /** No majority among the callers: the anchor has not resolved, and must not emit a value. */
    private static class Ambiguous extends RuntimeException {
        Ambiguous(String m) { super(m); }
    }

    // For via_caller anchors, the recipe (call_arg/back_scan) runs inside a CALLER of the named function.
    private Map<String, Long> extractAnchor(Map<String, Object> anchorDef, Map<String, Object> extract, Function located) {
        if (!Boolean.TRUE.equals(anchorDef.get("via_caller"))) return runRecipe(located, extract);
        Set<Function> callers = new LinkedHashSet<>();
        for (Reference r : getReferencesTo(located.getEntryPoint())) {
            if (!r.getReferenceType().isCall()) continue;
            Function c = getFunctionContaining(r.getFromAddress());
            if (c != null) callers.add(c);
            if (callers.size() >= 80) break;
        }
        // Consensus, not first-past-the-post. A via_caller recipe reads a displacement out of whichever
        // caller happens to match first, and one caller whose register holds something else yields a
        // plausible-looking wrong offset with no way to tell. Callers that agree outvote one that does not.
        Map<String, Map<String, Long>> byResult = new LinkedHashMap<>();
        Map<String, Integer> votes = new LinkedHashMap<>();
        RuntimeException last = null;
        for (Function c : callers) {
            try {
                Map<String, Long> m = runRecipe(c, extract);
                if (m.isEmpty()) continue;
                String key = m.toString();
                byResult.putIfAbsent(key, m);
                votes.merge(key, 1, Integer::sum);
            } catch (RuntimeException e) { last = e; }
        }
        Map.Entry<String, Integer> best = votes.entrySet().stream().max(Map.Entry.comparingByValue()).orElse(null);
        if (best == null)
            throw last != null ? last : new RuntimeException("no caller of " + fullNameOf(located) + " satisfied the recipe");
        int agreeing = best.getValue(), totalVotes = votes.values().stream().mapToInt(Integer::intValue).sum();
        // A plurality is not a consensus. With two callers disagreeing one-all the winner was whichever
        // the iterator reached first, which is how a wrong displacement shipped at HIGH confidence.
        long topScores = votes.values().stream().filter(v -> v == agreeing).count();
        if (votes.size() > 1 && (topScores > 1 || agreeing * 2 <= totalVotes))
            throw new Ambiguous("callers of " + fullNameOf(located) + " disagree " + votes.values()
                    + " with no majority: " + votes.keySet());
        if (votes.size() > 1)
            println("anchor via_caller consensus for " + fullNameOf(located) + ": " + agreeing + "/" + totalVotes
                    + " callers agree on " + best.getKey() + "; dissenting " + votes.keySet());
        return byResult.get(best.getKey());
    }

    private boolean matchesStep(Instruction insn, Map<String, Object> step, Map<String, String> regBinds) {
        Map<String, Object> match = (Map<String, Object>) step.getOrDefault("match", step);
        String mn = str(match.get("mnemonic"));
        if (mn != null && !mn.equalsIgnoreCase(insn.getMnemonicString())) return false;
        // operand_size (32/64/8) — best-effort via result/operand representation
        if (match.containsKey("operand_size")) {
            int want = ((Number) match.get("operand_size")).intValue();
            if (!operandSizeMatches(insn, want)) return false;
        }
        // mem base/index/scale/disp constraints (step.mem)
        Map<String, Object> mem = (Map<String, Object>) step.get("mem");
        if (mem != null && !memMatches(insn, mem, regBinds)) return false;
        // immediate match
        if (match.containsKey("imm")) {
            long want = ((Number) match.get("imm")).longValue();
            if (!hasImmediate(insn, want)) return false;
        }
        return true;
    }

    private boolean memMatches(Instruction insn, Map<String, Object> mem, Map<String, String> regBinds) {
        // A [reg+disp]/[reg+idx*scale] memory operand — dynamic dereference, OR a LEA address operand.
        int op = memOperandIndex(insn);
        if (op < 0) return false;
        MemParts p = memParts(insn, op);
        Register base = p.base, index = p.index;
        if (mem.containsKey("base")) {
            String b = str(mem.get("base"));
            if (b != null && b.startsWith("@")) {
                String bound = regBinds.get(b);
                if (bound != null && (base == null || !bound.equals(base.getName()))) return false;
            } else if (b != null && !b.equals("*")) { // literal register, e.g. "RDI" (the implicit this)
                if (base == null || !base.getName().equalsIgnoreCase(b)) return false;
            }
        }
        if (mem.containsKey("scale") && index == null) return false; // need an index*scale form
        if (mem.containsKey("index")) {
            String ix = str(mem.get("index"));
            if (index == null) return false;
            if (ix != null && ix.startsWith("@")) {
                String bound = regBinds.get(ix);
                if (bound != null && !bound.equals(index.getName())) return false;
            } else if (ix != null && !ix.equals("*") && !index.getName().equalsIgnoreCase(ix)) return false;
        }
        if (mem.containsKey("disp_min")) {
            long lo = parseHexOrDec(str(mem.get("disp_min"))), hi = parseHexOrDec(str(mem.get("disp_max")));
            long d = p.disp != null ? p.disp : 0;
            if (d < lo || d > hi) return false;
        }
        return true;
    }

    private int firstDynamicOp(Instruction insn) {
        for (int op = 0; op < insn.getNumOperands(); op++)
            if (OperandType.isDynamic(insn.getOperandType(op))) return op;
        return -1;
    }

    // Like firstDynamicOp but also returns a LEA's [base+disp] address operand (which is an ADDRESS
    // operand type, not a DYNAMIC dereference). Lets recipes match `LEA reg,[base+disp]`.
    private int memOperandIndex(Instruction insn) {
        int d = firstDynamicOp(insn);
        if (d >= 0) return d;
        if ("LEA".equalsIgnoreCase(insn.getMnemonicString())) {
            for (int op = 1; op < insn.getNumOperands(); op++) {
                boolean hasReg = false, hasScalar = false;
                for (Object o : insn.getOpObjects(op)) { if (o instanceof Register) hasReg = true; if (o instanceof Scalar) hasScalar = true; }
                if (hasReg && hasScalar) return op;
            }
        }
        return -1;
    }

    private void bindAndCapture(Instruction insn, Map<String, Object> step, Map<String, String> regBinds, Map<String, Long> captures) {
        // bind dst register if step.dst is "@name"
        String dst = str(step.get("dst"));
        if (dst != null && dst.startsWith("@")) {
            Register r = firstWrittenRegister(insn);
            if (r != null) regBinds.put(dst, r.getName());
        }
        // capture mem disp
        if (step.containsKey("capture")) {
            Map<String, Object> cap = (Map<String, Object>) step.get("capture");
            String from = str(cap.get("from"));
            String as = str(cap.get("as"));
            Long val = null;
            if ("mem.disp".equals(from)) val = firstMemDisp(insn);
            else if ("imm".equals(from)) val = firstImmediate(insn);
            if (val != null) captures.put(as, val);
        }
    }

    // ============================================================ DOACTION ============================================================

    private static final int ACTION_ID_MAX = 5000;
    private static final int ACTION_KIND_MAX = 32;
    private static final int MIN_ACTION_OBJECTS = 10;
    private static final int MIN_INSTALLER_SITES = 4;
    private static final int WIN_MIN_REGISTRAR_OBJECTS = 5;
    private static final int WIN_VTABLE_SLOTS = 6;
    private static final int WIN_VTABLE_INVOKE_SLOT = 2;

    /** One action object as the client constructs it: its id, its kind, and the sender the ctor installs. */
    private static class ActionRecord {
        final long object;
        final int id;
        final int kind;
        long sender;
        long aliasOf = -1;
        ActionRecord(long object, int id, int kind) { this.object = object; this.id = id; this.kind = kind; }
    }

    private static class DoActionResult {
        String ktBody = "";
        List<String> playerLog = new ArrayList<>();
        List<String[]> entries = new ArrayList<>();   // {name, id, method, "0xRVA", kind}
    }

    private DoActionResult runDoAction() {
        DoActionResult res = new DoActionResult();
        List<ActionRecord> acts;
        try {
            acts = profile.walkDoActions();
        } catch (Exception e) {
            applyFailure("doaction", "walk failed", String.valueOf(e));
            printerr("DoAction walk FAILED on " + profile.id() + ": " + e);
            return res;
        }
        acts.sort(Comparator.comparingInt(a -> a.id));
        Map<Integer, String> names = DoActionNames.build();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < acts.size(); i++) {
            ActionRecord a = acts.get(i);
            String name = names.get(a.id);
            if (name == null) {
                name = "UNKNOWN_" + a.id;
                println("DoAction NEW: id " + a.id + " (kind " + a.kind + ") is not in the name table; emitted as " + name);
            }
            if (a.sender == 0) {
                applyFailure("doaction", "object constructed but no sender installed", name + " (id " + a.id + ")");
                continue;
            }
            String method = name.endsWith("_ALT") ? null : senderName(a.sender);
            sb.append("    ").append(name).append("(").append(a.id).append(", \"")
              .append(method != null ? method : name).append("\", 0x")
              .append(Long.toHexString(a.sender).toUpperCase()).append(")")
              .append(i == acts.size() - 1 ? ";" : ",").append("\n");
            res.entries.add(new String[]{name, String.valueOf(a.id), method,
                    "0x" + Long.toHexString(a.sender), String.valueOf(a.kind)});
            if (a.aliasOf >= 0) res.playerLog.add(name + " (id " + a.id + ") aliases the action at 0x"
                    + Long.toHexString(a.aliasOf) + "; both dispatch the same sender");
        }
        res.ktBody = sb.toString();
        println("doAction walk: " + res.entries.size() + " of " + acts.size() + " constructed actions resolved a sender");
        if (apply) nameDoActionRoots();
        return res;
    }

    /**
     * The walk finds its roots structurally, so these names are documentation rather than a locator: a
     * root that still carries a default name is labelled from the registry so a fresh import leaves the
     * DB readable. A root that already has a name is never overwritten.
     */
    @SuppressWarnings("unchecked")
    private void nameDoActionRoots() {
        try {
            Path regPath = updaterRoot.resolve("anchor_registry.json");
            if (!Files.exists(regPath)) return;
            Object roots = ((Map<String, Object>) Json.parse(readText(regPath))).get("doaction_roots");
            if (!(roots instanceof Map)) return;
            Object rows = ((Map<String, Object>) roots).get(profile.id());
            if (!(rows instanceof List)) return;
            List<Object> list = (List<Object>) rows;
            for (int i = 0; i < doActionRoots.size() && i < list.size(); i++) {
                Function f = doActionRoots.get(i);
                String name = str(((Map<String, Object>) list.get(i)).get("official_name"));
                if (name == null || !f.getName().startsWith("FUN_")) continue;
                try {
                    f.setName(leaf(name), SourceType.USER_DEFINED);
                    f.setParentNamespace(createNamespaceHierarchy(nsOf(name)));
                    println("doAction root named: " + name + " @ 0x" + f.getEntryPoint());
                } catch (Exception e) {
                    applyFailure("doaction", "could not name root", name + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            applyFailure("doaction", "root naming failed", String.valueOf(e.getMessage()));
        }
    }

    private String senderName(long addr) {
        Function f = getFunctionAt(addrOf(addr));
        if (f == null) return null;
        String n = f.getName();
        return (n.startsWith("FUN_") || n.startsWith("SUB_") || n.startsWith("thunk_FUN_")) ? null : n;
    }

    /**
     * Every action id the client has ever constructed, mapped to the engine's name for it. Ids are the
     * client's own and do not move between builds, so this is the one part of the walk that is a table
     * rather than a derivation; an id absent from it is emitted as UNKNOWN_&lt;id&gt; and logged.
     */
    private static class DoActionNames {
        static Map<Integer, String> build() {
            Map<Integer, String> t = new LinkedHashMap<>();
            t.put(1, "SELECT_OBJECT");
            t.put(2, "OBJECT_1");
            t.put(3, "OBJECT_2");
            t.put(4, "OBJECT_3");
            t.put(5, "OBJECT_4");
            t.put(6, "OBJECT_5_ALT");
            t.put(7, "OBJECT_6_ALT");
            t.put(8, "SELECT_NPC");
            t.put(9, "NPC_1");
            t.put(10, "NPC_2");
            t.put(11, "NPC_3");
            t.put(12, "NPC_4");
            t.put(13, "NPC_5");
            t.put(15, "PLAYER_SELECT");
            t.put(16, "COMP_ON_PLAYER");
            t.put(17, "SELECT_GROUND_ITEM");
            t.put(18, "GROUND_ITEM_1");
            t.put(19, "GROUND_ITEM_2");
            t.put(20, "GROUND_ITEM_3");
            t.put(21, "GROUND_ITEM_4");
            t.put(22, "GROUND_ITEM_5");
            t.put(23, "WALK");
            t.put(25, "SELECT_COMPONENT");
            t.put(30, "DIALOGUE");
            t.put(44, "PLAYER_1_ALT");
            t.put(45, "PLAYER_2_ALT");
            t.put(46, "PLAYER_3_ALT");
            t.put(47, "PLAYER_4_ALT");
            t.put(48, "PLAYER_5_ALT");
            t.put(49, "PLAYER_6_ALT");
            t.put(50, "PLAYER_7_ALT");
            t.put(51, "PLAYER_8_ALT");
            t.put(52, "PLAYER_9_ALT");
            t.put(53, "PLAYER_10_ALT");
            t.put(57, "COMPONENT");
            t.put(58, "SELECT_COMPONENT_ITEM");
            t.put(59, "SELECT_TILE");
            t.put(60, "UNKNOWN_60");
            t.put(1001, "OBJECT_5");
            t.put(1002, "OBJECT_6");
            t.put(1003, "NPC_6");
            t.put(1004, "GROUND_ITEM_6");
            t.put(1005, "UNK_1005");
            t.put(1006, "UNKNOWN_1006");
            t.put(1007, "COMPONENT_SIXPLUS");
            t.put(1008, "UNKNOWN_1008");
            t.put(1009, "UNKNOWN_1009");
            t.put(1010, "UNKNOWN_1010");
            t.put(1011, "UNKNOWN_1011");
            t.put(1012, "UNKNOWN_1012");
            t.put(2009, "NPC_1_ALT");
            t.put(2010, "NPC_2_ALT");
            t.put(2011, "NPC_3_ALT");
            t.put(2012, "NPC_4_ALT");
            t.put(2013, "NPC_5_ALT");
            t.put(2044, "PLAYER_1");
            t.put(2045, "PLAYER_2");
            t.put(2046, "PLAYER_3");
            t.put(2047, "PLAYER_4");
            t.put(2048, "PLAYER_5");
            t.put(2049, "PLAYER_6");
            t.put(2050, "PLAYER_7");
            t.put(2051, "PLAYER_8");
            t.put(2052, "PLAYER_9");
            t.put(2053, "PLAYER_10");
            t.put(3003, "NPC_6_ALT");
            return t;
        }
    }

    // ---------------------------------------------------------------- ELF walk

    /**
     * The ELF build never stores an action id: the whole table lives in .bss and a single file-scope
     * initialiser writes each object's id and kind as a pair of adjacent RIP-relative imm32 stores, so
     * the ids exist only as immediates in that one function. The senders are installed separately by the
     * MiniMenu constructor, which stores each eastl::function's invoke pointer into the object and then
     * byte-copies whole objects to build the alias ids.
     */
    private List<ActionRecord> elfWalkDoActions() {
        List<long[]> sites = scanIdKindStores();               // {siteAddr, idAddr, id, kind}
        if (sites.isEmpty()) throw new IllegalStateException("no id/kind store pairs found in executable memory");
        Function root = densestFunction(sites, MIN_ACTION_OBJECTS);
        if (root == null) throw new IllegalStateException("no function holds " + MIN_ACTION_OBJECTS + " id/kind store pairs");
        println("doAction ELF static initialiser: " + fullNameOf(root) + " @ 0x" + root.getEntryPoint());
        doActionRoots.add(root);

        List<Instruction> body = bodyInstructions(root, 500000);
        Map<Long, Integer> indexByAddr = new HashMap<>();
        for (int i = 0; i < body.size(); i++) indexByAddr.put(body.get(i).getAddress().getOffset(), i);

        Map<Long, ActionRecord> byObject = new LinkedHashMap<>();
        Map<Integer, Integer> idOffVotes = new HashMap<>();
        for (long[] s : sites) {
            Integer at = indexByAddr.get(s[0]);
            if (at == null) continue;
            boolean registered = false;
            for (int j = at + 2; j < Math.min(at + 5, body.size()); j++)
                if ("CALL".equals(body.get(j).getMnemonicString())) { registered = true; break; }
            if (!registered) continue;
            Long object = null;
            for (int j = at - 1; j >= 0 && j > at - 11; j--) {
                Instruction p = body.get(j);
                if (!"LEA".equals(p.getMnemonicString())) continue;
                Long t = memAbsOperand(p, 1);
                if (t == null) continue;
                long d = s[1] - t;
                if (d >= 0 && d <= 0x40 && (object == null || t > object)) object = t;
            }
            if (object == null) {
                applyFailure("doaction", "id/kind stores with no object address in the block", "id " + s[2]);
                continue;
            }
            byObject.put(object, new ActionRecord(object, (int) s[2], (int) s[3]));
            idOffVotes.merge((int) (s[1] - object), 1, Integer::sum);
        }
        if (idOffVotes.size() != 1)
            throw new IllegalStateException("action objects disagree on the id field offset: " + idOffVotes);
        int idOff = idOffVotes.keySet().iterator().next();
        println("doAction ELF: " + byObject.size() + " action objects, id at object+0x" + Integer.toHexString(idOff));

        elfInstallSenders(byObject, idOff, root);
        return new ArrayList<>(byObject.values());
    }

    /**
     * The invoke pointer is the last pointer slot the constructor writes into the object, and the alias
     * objects get theirs from a whole-object copy rather than a store of their own, so both the slot and
     * the aliasing are read off the constructor rather than assumed.
     */
    private void elfInstallSenders(Map<Long, ActionRecord> byObject, int idOff, Function initRoot) {
        Map<Long, Long> slotOwner = new HashMap<>();
        for (long o : byObject.keySet()) for (int d = 0; d < idOff; d += 8) slotOwner.put(o + d, o);

        Map<Function, Integer> tally = new HashMap<>();
        for (long slot : slotOwner.keySet())
            for (Reference r : getReferencesTo(addrOf(slot))) {
                if (!r.getReferenceType().isWrite()) continue;
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) tally.merge(f, 1, Integer::sum);
            }
        if (tally.isEmpty())
            for (Address a : scanRipQwordStores(slotOwner.keySet())) {
                Function f = getFunctionContaining(a);
                if (f != null) tally.merge(f, 1, Integer::sum);
            }

        Map<Integer, Integer> senderOffVotes = new HashMap<>();
        Map<Long, Integer> bestDisp = new HashMap<>();
        List<long[]> aliases = new ArrayList<>();
        String arg1 = profile.argRegisters()[0], arg2 = profile.argRegisters()[1];
        boolean any = false;
        for (Map.Entry<Function, Integer> e : tally.entrySet()) {
            // The initialiser zeroes the same slots it later fills, so it tallies as an installer too and
            // would otherwise be reported twice and mislabelled from the registry's role order.
            if (e.getKey().equals(initRoot) || e.getValue() < MIN_INSTALLER_SITES) continue;
            any = true;
            println("doAction ELF sender installer: " + fullNameOf(e.getKey()) + " @ 0x" + e.getKey().getEntryPoint()
                    + " (" + e.getValue() + " stores into action objects)");
            doActionRoots.add(e.getKey());
            Map<String, Long> regVal = new HashMap<>();
            for (Instruction in : bodyInstructions(e.getKey(), 500000)) {
                String m = in.getMnemonicString();
                if ("LEA".equals(m)) {
                    Register d = firstWrittenRegister(in);
                    Long t = memAbsOperand(in, 1);
                    if (d == null) continue;
                    if (t != null) regVal.put(baseRegName(d), t); else regVal.remove(baseRegName(d));
                    continue;
                }
                if ("CALL".equals(m)) {
                    Long dst = regVal.get(arg1), src = regVal.get(arg2);
                    if (dst != null && src != null && !dst.equals(src)
                            && byObject.containsKey(dst) && byObject.containsKey(src))
                        aliases.add(new long[]{dst, src});
                    regVal.clear();
                    continue;
                }
                if ("MOV".equals(m)) {
                    Long dst = memAbsOperand(in, 0);
                    if (dst != null) {
                        Object[] src = in.getOpObjects(1);
                        if (src.length == 1 && src[0] instanceof Register r) {
                            Long v = regVal.get(baseRegName(r));
                            Long owner = slotOwner.get(dst);
                            if (v != null && owner != null && isExecutableAddr(v)) {
                                int disp = (int) (dst - owner);
                                Integer prev = bestDisp.get(owner);
                                if (prev == null || disp > prev) {
                                    bestDisp.put(owner, disp);
                                    byObject.get(owner).sender = v;
                                }
                            }
                        }
                        continue;
                    }
                }
                Register d = firstWrittenRegister(in);
                if (d != null) regVal.remove(baseRegName(d));
            }
        }
        if (!any) throw new IllegalStateException("no function installs senders into the action objects");

        for (boolean changed = true; changed; ) {
            changed = false;
            for (long[] pair : aliases) {
                ActionRecord dst = byObject.get(pair[0]), src = byObject.get(pair[1]);
                if (dst == null || src == null || src.sender == 0 || dst.sender == src.sender) continue;
                dst.sender = src.sender;
                dst.aliasOf = src.object;
                changed = true;
            }
        }
        for (int d : bestDisp.values()) senderOffVotes.merge(d, 1, Integer::sum);
        if (senderOffVotes.size() > 1)
            throw new IllegalStateException("action objects disagree on the invoke pointer slot: " + senderOffVotes);
        println("doAction ELF: invoke pointer at object+0x" + Integer.toHexString(senderOffVotes.keySet().iterator().next())
                + ", " + bestDisp.size() + " direct installs, " + aliases.size() + " aliases");
    }

    // ---------------------------------------------------------------- PE walk

    /**
     * The PE build stores each action object statically, so the id and kind are in the image, but the
     * object's callable pointer is only written at run time: the object-to-callable pairing exists solely
     * as the order in which the registration functions reference the callable vtable and then the object
     * they install it into. An alias registration clones an already-registered object instead, naming its
     * donor by a read of the donor's engaged pointer.
     */
    private List<ActionRecord> peWalkDoActions() {
        Register objectArg = nthArgRegister(2);
        Map<Function, Set<Long>> byFunction = new LinkedHashMap<>();
        for (long[] site : scanRegistrationObjectLoads(objectArg))
            byFunction.computeIfAbsent(getFunctionContaining(addrOf(site[0])), k -> new LinkedHashSet<>()).add(site[1]);
        byFunction.remove(null);

        List<Function> registrars = new ArrayList<>();
        Set<Long> objects = new LinkedHashSet<>();
        Integer idOff = null;
        for (Map.Entry<Function, Set<Long>> e : byFunction.entrySet()) {
            Integer d = qualifyRegistrar(e.getValue());
            if (d == null) continue;
            if (idOff != null && !idOff.equals(d))
                throw new IllegalStateException("registration functions disagree on the id field offset: " + idOff + " vs " + d);
            idOff = d;
            registrars.add(e.getKey());
            objects.addAll(e.getValue());
            println("doAction PE registration: " + fullNameOf(e.getKey()) + " @ 0x" + e.getKey().getEntryPoint()
                    + " (" + e.getValue().size() + " action objects)");
        }
        if (registrars.isEmpty()) throw new IllegalStateException("no action registration function found");
        registrars.sort((x, y) -> Integer.compare(byFunction.get(y).size(), byFunction.get(x).size()));
        doActionRoots.addAll(registrars);
        println("doAction PE: " + objects.size() + " action objects, id at object+0x" + Integer.toHexString(idOff));

        Map<Long, Long> vtableOf = new LinkedHashMap<>();
        Map<Long, Long> cloneOf = new LinkedHashMap<>();
        for (Function f : registrars) {
            Long pending = null, pendingDonor = null;
            for (Instruction in : bodyInstructions(f, 500000)) {
                String m = in.getMnemonicString();
                if ("LEA".equals(m)) {
                    Long t = memAbsOperand(in, 1);
                    if (t == null) continue;
                    if (objects.contains(t)) {
                        if (pending != null) {
                            vtableOf.putIfAbsent(t, pending);
                            if (pendingDonor != null) cloneOf.putIfAbsent(t, pendingDonor);
                        }
                        pending = null; pendingDonor = null;
                    } else if (isReadOnlyDataAddr(t)) {
                        pending = t; pendingDonor = null;
                    }
                    continue;
                }
                if ("MOV".equals(m)) {
                    Long read = memAbsOperand(in, 1);
                    if (read == null) continue;
                    Long donor = ownerOf(objects, read, idOff);
                    if (donor != null && vtableOf.containsKey(donor)) { pending = vtableOf.get(donor); pendingDonor = donor; }
                }
            }
        }
        long delta = peStoredPointerDelta(vtableOf.values());
        validatePeCallableVtables(vtableOf.values(), delta);
        println("doAction PE: invoke pointer at callable vtable slot " + WIN_VTABLE_INVOKE_SLOT
                + ", " + (vtableOf.size() - cloneOf.size()) + " direct installs, " + cloneOf.size() + " clones");

        List<ActionRecord> out = new ArrayList<>();
        for (long o : objects) {
            Integer id = readInt(o + idOff), kind = readInt(o + idOff + 4);
            if (id == null || kind == null) {
                applyFailure("doaction", "action object outside readable memory", "0x" + Long.toHexString(o));
                continue;
            }
            ActionRecord r = new ActionRecord(o, id, kind);
            Long vt = vtableOf.get(o);
            if (vt != null) {
                Long invoke = readPointer(vt + (long) WIN_VTABLE_INVOKE_SLOT * 8, delta);
                if (invoke != null) r.sender = invoke;
            }
            Long donor = cloneOf.get(o);
            if (donor != null) r.aliasOf = donor;
            out.add(r);
        }
        return out;
    }

    /**
     * An action object carries its id and kind as an adjacent int pair, so the registration functions can
     * be told apart from every other eastl::function registration by whether one single displacement
     * reads as a distinct, in-range id for every object the function touches.
     */
    private Integer qualifyRegistrar(Set<Long> objects) {
        if (objects.size() < WIN_MIN_REGISTRAR_OBJECTS) return null;
        List<Long> sorted = new ArrayList<>(objects);
        Collections.sort(sorted);
        Integer found = null;
        for (int d = 0; d < 0x100; d += 4) {
            Set<Integer> ids = new HashSet<>();
            boolean ok = true;
            for (long o : sorted) {
                Integer id = readInt(o + d), kind = readInt(o + d + 4);
                if (id == null || kind == null || id <= 0 || id > ACTION_ID_MAX || kind < 0 || kind >= ACTION_KIND_MAX
                        || !ids.add(id)) { ok = false; break; }
            }
            if (!ok) continue;
            boolean packed = false;
            for (int i = 1; i < sorted.size(); i++) if (sorted.get(i) - sorted.get(i - 1) < d + 8) { packed = true; break; }
            if (packed) continue;
            if (found != null) return null;   // ambiguous: this is not an action-object layout
            found = d;
        }
        return found;
    }

    /**
     * Pointers in a PE image are written as preferred-base virtual addresses while the program is loaded
     * at base zero, so every stored pointer has to be shifted back. The shift is the image base recorded
     * in the PE headers, which the loader maps like any other section; it is then proved against the
     * callable vtables rather than trusted, because a wrong shift turns every sender into a plausible
     * address somewhere else in .text.
     */
    private long peStoredPointerDelta(Collection<Long> vtables) {
        Set<Long> uniq = new LinkedHashSet<>(vtables);
        for (long d : new long[]{peHeaderImageBase(), 0}) {
            if (d < 0) continue;
            boolean all = true;
            for (long vt : uniq)
                for (int i = 0; i < WIN_VTABLE_SLOTS && all; i++) {
                    Long q = readLong(vt + i * 8L);
                    all = q != null && q != 0 && isExecutableAddr(q - d);
                }
            if (all) {
                println("doAction PE: stored pointers shift by 0x" + Long.toHexString(d)
                        + " (all " + uniq.size() + " callable vtables resolve)");
                return d;
            }
        }
        throw new IllegalStateException("no stored-pointer shift resolves the callable vtables; "
                + "the PE headers report image base 0x" + Long.toHexString(peHeaderImageBase()));
    }

    /** The image base the PE headers record, read out of the mapped headers rather than assumed. */
    private long peHeaderImageBase() {
        try {
            Address base = currentProgram.getImageBase();
            Memory mem = currentProgram.getMemory();
            if (mem.getShort(base) != 0x5A4D) return -1;                  // 'MZ'
            long pe = base.getOffset() + (mem.getInt(base.add(0x3C)) & 0xFFFFFFFFL);
            if (mem.getInt(addrOf(pe)) != 0x00004550) return -1;          // 'PE\0\0'
            long opt = pe + 24;
            int magic = mem.getShort(addrOf(opt)) & 0xFFFF;
            if (magic == 0x20B) return mem.getLong(addrOf(opt + 24));
            if (magic == 0x10B) return mem.getInt(addrOf(opt + 28)) & 0xFFFFFFFFL;
            return -1;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * The invoke slot is the one part of the PE walk that is a declared position rather than a derivation,
     * so the surrounding shape of the callable vtable is checked instead: a paired destructor, and the two
     * allocator helpers shared by every callable of this signature. If that shape ever changes the slot
     * has moved too, and the walk must stop rather than emit whatever now sits at that position.
     */
    private void validatePeCallableVtables(Collection<Long> vtables, long delta) {
        Set<Long> uniq = new LinkedHashSet<>(vtables);
        Long sharedA = null, sharedB = null;
        for (long vt : uniq) {
            Long[] slot = new Long[WIN_VTABLE_SLOTS];
            for (int s = 0; s < WIN_VTABLE_SLOTS; s++) {
                slot[s] = readPointer(vt + s * 8L, delta);
                if (slot[s] == null || !isExecutableAddr(slot[s]))
                    throw new IllegalStateException("callable vtable 0x" + Long.toHexString(vt)
                            + " slot " + s + " is not executable; the vtable layout has changed");
            }
            if (!slot[0].equals(slot[1]))
                throw new IllegalStateException("callable vtable 0x" + Long.toHexString(vt)
                        + " has no paired destructor; the vtable layout has changed");
            if (sharedA == null) { sharedA = slot[4]; sharedB = slot[5]; }
            else if (!sharedA.equals(slot[4]) || !sharedB.equals(slot[5]))
                throw new IllegalStateException("callable vtable 0x" + Long.toHexString(vt)
                        + " does not share the allocator helpers; the vtable layout has changed");
        }
    }

    private Long ownerOf(Set<Long> objects, long addr, int idOff) {
        Long best = null;
        for (long o : objects) if (addr >= o && addr - o < idOff && (best == null || o > best)) best = o;
        return best;
    }

    // ---------------------------------------------------------------- byte scanners

    /** Adjacent `MOV dword ptr [RIP+d], imm32` pairs four bytes apart whose immediates read as an id and a kind. */
    private List<long[]> scanIdKindStores() {
        List<long[]> out = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute()) continue;
            byte[] buf = readBlock(b);
            if (buf == null) continue;
            long base = b.getStart().getOffset();
            for (int i = 0; i + 20 <= buf.length; i++) {
                if (buf[i] != (byte) 0xC7 || buf[i + 1] != 0x05 || buf[i + 10] != (byte) 0xC7 || buf[i + 11] != 0x05) continue;
                long a1 = base + i + 10 + le32(buf, i + 2), a2 = base + i + 20 + le32(buf, i + 12);
                if (a2 != a1 + 4) continue;
                long id = le32u(buf, i + 6), kind = le32u(buf, i + 16);
                if (id <= 0 || id > ACTION_ID_MAX || kind >= ACTION_KIND_MAX) continue;
                out.add(new long[]{base + i, a1, id, kind});
            }
        }
        return out;
    }

    /** `MOV [RIP+d], r64` stores landing on one of the given addresses — the reference-free fallback. */
    private List<Address> scanRipQwordStores(Set<Long> targets) {
        List<Address> out = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute()) continue;
            byte[] buf = readBlock(b);
            if (buf == null) continue;
            long base = b.getStart().getOffset();
            for (int i = 0; i + 7 <= buf.length; i++) {
                if ((buf[i] != 0x48 && buf[i] != 0x4C) || buf[i + 1] != (byte) 0x89) continue;
                if ((buf[i + 2] & 0xC7) != 0x05) continue;
                if (targets.contains(base + i + 7 + le32(buf, i + 3))) out.add(addrOf(base + i));
            }
        }
        return out;
    }

    /**
     * `LEA argReg,[RIP+object]` immediately ahead of the registration call — the one shape both the direct
     * and the cloning registration take. The byte scan only narrows the field; each surviving site is
     * re-read as a decoded instruction before it is believed.
     */
    private List<long[]> scanRegistrationObjectLoads(Register objectArg) {
        List<long[]> out = new ArrayList<>();
        if (objectArg == null) return out;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute()) continue;
            byte[] buf = readBlock(b);
            if (buf == null) continue;
            long base = b.getStart().getOffset();
            for (int i = 0; i + 7 <= buf.length; i++) {
                if ((buf[i] != 0x48 && buf[i] != 0x4C) || buf[i + 1] != (byte) 0x8D) continue;
                if ((buf[i + 2] & 0xC7) != 0x05) continue;
                if (!isWritableAddr(base + i + 7 + le32(buf, i + 3))) continue;
                Instruction in = getInstructionAt(addrOf(base + i));
                if (in == null || !"LEA".equals(in.getMnemonicString())) continue;
                Register w = firstWrittenRegister(in);
                if (w == null || !baseRegName(w).equals(baseRegName(objectArg))) continue;
                Long target = memAbsOperand(in, 1);
                if (target == null) continue;
                boolean registered = false;
                Instruction next = in;
                for (int k = 0; k < 6 && (next = next.getNext()) != null; k++)
                    if ("CALL".equals(next.getMnemonicString())) { registered = true; break; }
                if (registered) out.add(new long[]{base + i, target});
            }
        }
        return out;
    }

    private byte[] readBlock(MemoryBlock b) {
        try {
            long size = b.getSize();
            if (size <= 0 || size > Integer.MAX_VALUE) return null;
            byte[] buf = new byte[(int) size];
            b.getBytes(b.getStart(), buf);
            return buf;
        } catch (Exception e) {
            return null;
        }
    }

    private Function densestFunction(List<long[]> sites, int min) {
        Map<Function, Integer> tally = new HashMap<>();
        for (long[] s : sites) {
            Function f = getFunctionContaining(addrOf(s[0]));
            if (f != null) tally.merge(f, 1, Integer::sum);
        }
        Map.Entry<Function, Integer> best = tally.entrySet().stream().max(Map.Entry.comparingByValue()).orElse(null);
        return (best != null && best.getValue() >= min) ? best.getKey() : null;
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) | (b[off + 3] << 24);
    }

    private static long le32u(byte[] b, int off) { return le32(b, off) & 0xFFFFFFFFL; }

    // ---------------------------------------------------------------- memory + operand helpers

    private String baseRegName(Register r) {
        Register base = r.getBaseRegister();
        return (base != null ? base : r).getName();
    }

    /** Absolute address of a RIP-relative memory operand, however this build's decoder spells it. */
    private Long memAbsOperand(Instruction insn, int opIndex) {
        Object[] objs = insn.getOpObjects(opIndex);
        if (objs != null && objs.length == 1 && objs[0] instanceof Address a) return a.getOffset();
        for (Reference r : insn.getReferencesFrom()) {
            if (r.getOperandIndex() != opIndex) continue;
            if (!r.isMemoryReference() || r.isStackReference() || r.getReferenceType().isFlow()) continue;
            return r.getToAddress().getOffset();
        }
        return null;
    }

    private MemoryBlock blockOf(long addr) {
        if (addr <= 0) return null;
        try { return currentProgram.getMemory().getBlock(addrOf(addr)); } catch (Exception e) { return null; }
    }

    private boolean isExecutableAddr(long addr) { MemoryBlock b = blockOf(addr); return b != null && b.isExecute(); }
    private boolean isWritableAddr(long addr) { MemoryBlock b = blockOf(addr); return b != null && b.isWrite(); }
    private boolean isReadOnlyDataAddr(long addr) {
        MemoryBlock b = blockOf(addr);
        return b != null && b.isInitialized() && !b.isExecute() && !b.isWrite();
    }

    private Integer readInt(long addr) {
        try { return currentProgram.getMemory().getInt(addrOf(addr)); } catch (Exception e) { return null; }
    }

    private Long readLong(long addr) {
        try { return currentProgram.getMemory().getLong(addrOf(addr)); } catch (Exception e) { return null; }
    }

    private Long readPointer(long addr, long delta) {
        Long v = readLong(addr);
        return (v == null || v == 0) ? null : v - delta;
    }

    // ============================================================ OUTPUT WRITERS ============================================================

    private void writeResultsJson(List<String> fn, List<String> lbl, List<String> anc, DoActionResult da, List<String[]> ofunctions) throws IOException {
        StringBuilder b = new StringBuilder();
        b.append("{\n  \"version\": ").append(jstr(version)).append(",\n  \"applied\": ").append(apply).append(",\n");
        b.append("  \"functions\": [\n    ").append(String.join(",\n    ", fn)).append("\n  ],\n");
        List<String> ofl = new ArrayList<>();
        for (String[] o : ofunctions) ofl.add(String.format("{\"const\":%s,\"name\":%s,\"new\":%s}", jstr(o[0]), jstr(o[1]), o[2] != null ? jstr(o[2]) : "null"));
        b.append("  \"ofunctions\": [\n    ").append(String.join(",\n    ", ofl)).append("\n  ],\n");
        b.append("  \"dataLabels\": [\n    ").append(String.join(",\n    ", lbl)).append("\n  ],\n");
        b.append("  \"anchors\": [\n    ").append(String.join(",\n    ", anc)).append("\n  ],\n");
        List<String> dal = new ArrayList<>();
        for (String[] d : da.entries) dal.add(String.format("{\"name\":%s,\"id\":%s,\"kind\":%s,\"method\":%s,\"value\":%s}",
                jstr(d[0]), d[1], d[4], d[2] != null ? jstr(d[2]) : "null", jstr(d[3])));
        b.append("  \"doActions\": [\n    ").append(String.join(",\n    ", dal)).append("\n  ],\n");
        b.append("  \"doActionAliases\": [").append(da.playerLog.isEmpty() ? "" :
                "\"" + String.join("\",\"", da.playerLog) + "\"").append("]\n}\n");
        // Platform-qualified: both binaries of a build share updaterRoot, and an unqualified name meant
        // the second run silently replaced the first run's results.
        writeText(updaterRoot.resolve("results_" + version + "_" + profile.id() + ".json"), b.toString());
        reportApplyFailures();
    }

    private void reportApplyFailures() throws IOException {
        if (applyFailCounts.isEmpty()) {
            println("NOT APPLIED: none");
            // A previous run's list left on disk reads as this run's result.
            Files.deleteIfExists(updaterRoot.resolve("apply_failures_" + version + "_" + profile.id() + ".tsv"));
            return;
        }
        println("NOT APPLIED (" + applyFailDetail.size() + " total):");
        for (Map.Entry<String, Integer> e : applyFailCounts.entrySet()) println("  " + e.getKey() + " x" + e.getValue());
        // Platform-qualified: both binaries of a build share updaterRoot and would otherwise overwrite
        // each other's failure list, leaving whichever ran second as the only visible one.
        Path fp = updaterRoot.resolve("apply_failures_" + version + "_" + profile.id() + ".tsv");
        List<String> rows = new ArrayList<>();
        rows.add("category\treason\tsubject");
        rows.addAll(applyFailDetail);
        writeLines(fp, rows);
        println("  detail -> " + fp);
    }

    /**
     * The counterpart to the applied totals. A run that reports only what it placed cannot distinguish a
     * complete port from a partial one, which is how the previous migration lost ~100 functions and ~140
     * comments without anything looking wrong.
     */
    @SuppressWarnings("unchecked")
    private void writeResidualReport(List<String> fnResults, List<String> lblResults, List<String> anchorResults) throws IOException {
        println("---- residual (" + (apply ? "APPLIED" : "DRY-RUN preview") + ") ----");
        List<String> unresolved = new ArrayList<>();
        for (String r : fnResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            String status = str(m.get("status"));
            if ("FOUND".equals(status)) continue;
            String ns = str(m.get("namespace"));
            unresolved.add(status + "\t" + (notEmpty(ns) ? ns + "::" : "") + str(m.get("name"))
                    + "\told=" + str(m.get("old")) + "\t" + str(m.get("note"))
                    + (m.get("candidates") != null ? "\tcandidates=" + str(m.get("candidates")) : ""));
        }
        for (String r : lblResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            if (Boolean.TRUE.equals(m.get("placed"))) continue;
            String note = str(m.get("note"));
            if (!apply && "dry-run".equals(note)) continue;
            unresolved.add("LABEL\t" + str(m.get("label")) + "\told=" + str(m.get("old")) + "\t" + note);
        }
        for (String r : anchorResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            if (Boolean.TRUE.equals(m.get("located")) && m.get("new_value") != null) continue;
            if ("SKIPPED".equals(str(m.get("confidence")))) continue;
            unresolved.add("ANCHOR\t" + str(m.get("id")) + "\told=" + str(m.get("old_value")) + "\t" + str(m.get("note")));
        }
        Path rp = updaterRoot.resolve("residual_" + version + "_" + profile.id() + ".tsv");
        List<String> rows = new ArrayList<>();
        rows.add("kind\tsubject\told\tnote");
        rows.addAll(unresolved);
        writeLines(rp, rows);
        println("unresolved subjects: " + unresolved.size() + " -> " + rp);
    }

    private void writeOffsetsKt(List<String> anchorResults, List<String[]> ofunctions) throws IOException {
        // anchorResults entries are JSON strings; parse minimal fields for the .kt fragment.
        StringBuilder banner = new StringBuilder();
        StringBuilder body = new StringBuilder();
        body.append("// Generated by RS3ProjectXUpdater for ").append(version).append(" — copy/paste into Offsets.kt.\n");
        // ---- OFunctions block (absolute function addresses; change every build, no drift flag) ----
        int ofFound = 0; for (String[] o : ofunctions) if (o[2] != null) ofFound++;
        body.append("\nobject OFunctions { // ").append(ofFound).append("/").append(ofunctions.size()).append(" resolved\n");
        for (String[] o : ofunctions) {
            if (o[2] != null) body.append("    const val ").append(o[0]).append(" = ").append(o[2]).append("L   //").append(version).append(" — ").append(o[1]).append("\n");
            else body.append("    // ").append(o[0]).append(" — UNRESOLVED (").append(o[1]).append(" not sig-matched)\n");
        }
        body.append("}\n\n// ---- OGlobal + struct-field offsets (from anchors), grouped by object ----\n");
        // Group anchor results by their object prefix (id "OClient.NPC_MANAGER" -> object "OClient").
        LinkedHashMap<String, List<String>> byObject = new LinkedHashMap<>();
        for (String r : anchorResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            String id = str(m.get("id"));
            String nv = str(m.get("new_value"));
            String ov = str(m.get("old_value"));
            String conf = str(m.get("confidence"));
            boolean changed = Boolean.TRUE.equals(m.get("changed"));
            int dot = id.indexOf('.');
            String obj = dot >= 0 ? id.substring(0, dot) : "OMisc";
            String field = dot >= 0 ? id.substring(dot + 1) : id;
            String line;
            if (nv == null) {
                line = "    // " + field + " — UNRESOLVED (" + str(m.get("note")) + ")";
            } else {
                if (changed) banner.append("//   ").append(id).append(": ").append(ov).append(" -> ").append(nv).append("\n");
                line = "    const val " + field + " = " + nv + "L   //" + version + " (was " + ov + ") — " + conf + (changed ? " *** CHANGED ***" : "");
            }
            byObject.computeIfAbsent(obj, k -> new ArrayList<>()).add(line);
        }
        for (Map.Entry<String, List<String>> e : byObject.entrySet()) {
            body.append("\nobject ").append(e.getKey()).append(" {\n");
            for (String l : e.getValue()) body.append(l).append("\n");
            body.append("}\n");
        }
        int unresolvedAnchors = 0;
        for (String r : anchorResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            if (m.get("new_value") == null && !"SKIPPED".equals(str(m.get("confidence")))) unresolvedAnchors++;
        }
        StringBuilder out = new StringBuilder();
        out.append("// ==== RS3ProjectXUpdater offsets ").append(version).append(" ====\n");
        if (banner.length() > 0) out.append("// !!! DRIFT DETECTED — offsets that CHANGED vs previous build:\n").append(banner).append("//\n");
        // "No drift" is only meaningful once every anchor resolved; otherwise the quiet banner is just
        // absence of evidence, which is exactly how a silent breakage gets shipped.
        else if (unresolvedAnchors > 0) out.append("// DRIFT UNDETERMINED — ").append(unresolvedAnchors)
                .append(" anchor(s) did not resolve, so no comparison was possible for them.\n");
        else out.append("// No struct-offset drift detected vs previous build.\n");
        if (unresolvedAnchors > 0 && banner.length() > 0) out.append("// (").append(unresolvedAnchors)
                .append(" further anchor(s) unresolved — drift undetermined for those.)\n");
        out.append(body);
        writeText(offsetsDir.resolve("offsets_" + version + ".kt"), out.toString());
    }

    // Struct fields that were established by hand against a specific build and that no anchor recipe can
    // derive. Without this the updater can only ever emit OFunctions, anchor results and doActions, so a
    // hand-established field survives only as an untracked leftover in the JSON and is lost the moment the
    // file is regenerated from scratch. Entries carry the build they were verified against; when that no
    // longer matches, the value is still emitted (dropping it would silently disable engine features) but
    // is downgraded and flagged so it shows up as work to redo rather than as a trusted number.
    @SuppressWarnings("unchecked")
    private int[] emitVerifiedFields(Map<String, Object> objects) throws IOException {
        int added = 0, updated = 0;
        Path regPath = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(regPath)) return new int[]{0, 0};
        Map<String, Object> reg = (Map<String, Object>) Json.parse(readText(regPath));
        Object vf = reg.get("verified_fields");
        if (!(vf instanceof Map)) return new int[]{0, 0};
        Object rows = ((Map<String, Object>) vf).get(profile.id());
        if (!(rows instanceof List)) return new int[]{0, 0};

        List<String> stale = new ArrayList<>();
        for (Object o : (List<Object>) rows) {
            Map<String, Object> f = (Map<String, Object>) o;
            String id = str(f.get("id")), val = str(f.get("value"));
            if (id == null || val == null) continue;
            if (withheldFieldIds().contains(id)) {
                applyFailure("offset-table", "withheld: previous value disproved, correct offset not yet located", id);
                continue;
            }
            String forBuild = str(f.get("build"));
            boolean current = version != null && version.equals(forBuild);
            // An absolute address proven against a DIFFERENT build is not evidence about this one: the
            // engine degrades safely on an absent entry and not at all on a present-but-wrong pointer.
            if (!current && looksAbsolute(val)) {
                unresolved(id, "absolute verified against " + forBuild + ", not re-derived for " + version);
                continue;
            }
            int dot = id.indexOf('.');
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("value", val);
            e.put("confidence", current ? str(f.get("confidence")) : "STALE_CARRY");
            String ev = str(f.get("evidence"));
            if (ev != null && !ev.isEmpty()) e.put("note", ev);
            e.put("verified_build", forBuild);
            if (!current) { e.put("carried_from", forBuild); e.put("needs_reverification", Boolean.TRUE); stale.add(id); }
            if (upsertOffset(objects, dot >= 0 ? id.substring(0, dot) : "OMisc",
                             dot >= 0 ? id.substring(dot + 1) : id, e)) added++; else updated++;
        }
        println("verified_fields[" + profile.id() + "]: " + (added + updated) + " emitted"
                + (stale.isEmpty() ? " (all verified against " + version + ")"
                                   : ", " + stale.size() + " struct-relative CARRIED (labelled, re-verify): " + stale));
        return new int[]{added, updated};
    }

    /**
     * Upsert what this run resolved into the engine's offset table for this (platform, build),
     * leaving every key the updater does not resolve untouched — the table also carries entries
     * established by hand that no anchor recipe covers.
     */
    @SuppressWarnings("unchecked")
    private void writeOffsetsJson(List<String> anchorResults, List<String[]> ofunctions, DoActionResult da) throws IOException {
        // A dry-run previews into the updater's own output dir. Writing the engine's table from a
        // preview once silently rewrote a committed build's doActions with a mis-walked one.
        Path out = apply
                ? engineOffsetsDir().resolve(profile.id() + "-" + version + ".json")
                : offsetsDir.resolve("preview-" + profile.id() + "-" + version + ".json");
        Files.createDirectories(out.getParent());

        Map<String, Object> root;
        if (Files.exists(out)) {
            root = (Map<String, Object>) Json.parse(readText(out));
        } else {
            root = new LinkedHashMap<>();
            root.put("schema", 1L);
            root.put("imageBase", "0x0");
            carryForwardPreviousTable(root);
        }
        root.put("platform", profile.id());
        root.put("build", version);

        Map<String, Object> objects = (Map<String, Object>) root.computeIfAbsent("objects", k -> new LinkedHashMap<String, Object>());
        // Also strip on the update-in-place path: a disproved value already sitting in the table would
        // otherwise outlive the registry entry that retired it.
        for (String id : withheldFieldIds()) {
            int dot = id.indexOf('.');
            if (dot < 0) continue;
            Map<String, Object> obj = (Map<String, Object>) objects.get(id.substring(0, dot));
            if (obj != null && obj.remove(id.substring(dot + 1)) != null)
                applyFailure("offset-table", "withheld: previous value disproved, correct offset not yet located", id);
        }

        int added = 0, updated = 0;
        // Emitted FIRST so that anchors and OFunctions below overwrite anything a recipe can derive:
        // a value the tooling re-derives from this build always beats one recorded by hand.
        int[] vf = emitVerifiedFields(objects);
        added += vf[0]; updated += vf[1];

        // Emitted after the withheld strip above, so a disproved OFunction would otherwise be re-added
        // by every run — the withhold has to be re-checked here or it silently never takes effect.
        Set<String> withheldNow = withheldFieldIds();
        for (String[] o : ofunctions) {
            if (o[2] == null) continue;
            if (withheldNow.contains("OFunctions." + o[0])) {
                unresolved("OFunctions." + o[0], "withheld: disproved against this build");
                continue;
            }
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("value", o[2]);
            e.put("confidence", "CERTAIN");
            e.put("note", o[1]);
            if (upsertOffset(objects, "OFunctions", o[0], e)) added++; else updated++;
        }

        for (String r : anchorResults) {
            Map<String, Object> m = (Map<String, Object>) Json.parse(r);
            String nv = str(m.get("new_value"));
            if (nv == null) continue;
            String id = str(m.get("id"));
            if (withheldNow.contains(id)) {
                applyFailure("offset-table", "withheld: previous value disproved, correct offset not yet located", id);
                continue;
            }
            if (!isTableKey(id, objects)) {
                applyFailure("offset-table", "anchor target is not a table key (reported here, not written to the table)", id);
                continue;
            }
            int dot = id.indexOf('.');
            String obj = dot >= 0 ? id.substring(0, dot) : "OMisc";
            String field = dot >= 0 ? id.substring(dot + 1) : id;
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("value", nv);
            e.put("confidence", str(m.get("confidence")));
            String note = str(m.get("note"));
            if (note != null && !note.isEmpty()) e.put("note", note);
            if (upsertOffset(objects, obj, field, e)) added++; else updated++;
        }

        // Replace, and account for the difference. The walk reads every action the client constructs, so
        // an entry it does not produce is a gap in the walk and not a table to preserve: carrying one
        // forward is how a build shipped 26 stale handler addresses that still looked resolved.
        List<Object> prior = (root.get("doActions") instanceof List) ? (List<Object>) root.get("doActions") : new ArrayList<>();
        LinkedHashMap<String, Map<String, Object>> was = new LinkedHashMap<>();
        for (Object o : prior) {
            Map<String, Object> e = (Map<String, Object>) o;
            was.put(str(e.get("name")), e);
        }
        LinkedHashMap<String, Map<String, Object>> byName = new LinkedHashMap<>();
        // A walk that produced nothing is a broken walk, not an empty table. Replacing on that would
        // erase every action in one run, which is worse than the drift the replace exists to prevent.
        Set<String> baseline = previousDoActionNames();
        boolean walkFailed = da.entries.isEmpty() && !baseline.isEmpty();
        if (walkFailed) {
            applyFailure("doaction", "walk produced no actions; previous table left intact", profile.id());
            doActionParityLoss = new ArrayList<>(baseline);
            printerr("*** DOACTION PARITY FAILURE (" + profile.id() + "): the walk produced no actions at all; "
                    + "the " + was.size() + " entries already in this build's table were left untouched rather than erased.");
        }
        for (String[] d : da.entries) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("name", d[0]);
            e.put("id", Long.parseLong(d[1]));
            e.put("kind", Long.parseLong(d[4]));
            if (d[2] != null) e.put("method", d[2]);
            else { Object m = was.containsKey(d[0]) ? was.get(d[0]).get("method") : null; if (m != null) e.put("method", m); }
            e.put("value", d[3]);
            e.put("verified_build", version);
            byName.put(d[0], e);
        }
        if (!walkFailed) root.put("doActions", new ArrayList<Object>(byName.values()));

        // The walk reporting only what it found is what let 26 entries disappear in silence, so the
        // previous build's table is the yardstick and every name it carried that this one lacks is named.
        List<String> lost = new ArrayList<>();
        if (!walkFailed) for (String name : baseline) if (!byName.containsKey(name)) lost.add(name);
        println("doActions: " + byName.size() + " emitted from the walk; parity baseline is "
                + previousTableBuild + " with " + baseline.size() + " action(s)");
        if (!lost.isEmpty()) {
            doActionParityLoss = lost;
            printerr("*** DOACTION PARITY FAILURE (" + profile.id() + "): " + lost.size()
                    + " action(s) the previous build's table carried are missing from this build's walk: " + lost);
        }

        reconcileUnresolved(objects, walkFailed ? was.keySet() : byName.keySet());

        if (unresolvedIds.isEmpty()) {
            root.remove("unresolved");
        } else {
            Map<String, Object> u = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : unresolvedIds.entrySet()) u.put(e.getKey(), e.getValue());
            root.put("unresolved", u);
        }

        writeText(out, Json.write(root) + "\n");
        println("offsets JSON -> " + out + " (" + added + " added, " + updated + " updated, "
                + unresolvedIds.size() + " UNRESOLVED omitted)");
        if (!unresolvedIds.isEmpty()) {
            println("UNRESOLVED (omitted from the table, must be re-derived):");
            for (Map.Entry<String, String> e : unresolvedIds.entrySet())
                println("    " + e.getKey() + " - " + e.getValue());
        }
        if (apply) registerInOffsetIndex();
    }

    /**
     * A key no table declares and no table ever carried is a name the tooling made up, and writing one
     * hands the engine an entry nothing can read while burying the entries that matter. The registry's
     * own hand-curated verified_fields may introduce a key; a recipe's emit id may not.
     */
    @SuppressWarnings("unchecked")
    private boolean isTableKey(String id, Map<String, Object> objects) throws IOException {
        if (id == null) return false;
        if (previousTableKeys().contains(id)) return true;
        if (declaredOffsetKeys().contains(id)) return true;
        if (verifiedFieldIds().contains(id)) return true;
        int dot = id.indexOf('.');
        if (dot < 0) return false;
        Object obj = objects.get(id.substring(0, dot));
        return obj instanceof Map && ((Map<String, Object>) obj).containsKey(id.substring(dot + 1));
    }

    private Set<String> declaredKeys;

    /** The engine's own declarations, which are what decides whether a table key is readable at runtime. */
    private Set<String> declaredOffsetKeys() {
        if (declaredKeys != null) return declaredKeys;
        declaredKeys = new LinkedHashSet<>();
        Path kt = engineOffsetsDir().getParent().getParent().getParent()
                .resolve("kotlin").resolve("com").resolve("projectx").resolve("game").resolve("nxt").resolve("Offsets.kt");
        if (!Files.exists(kt)) { println("WARN: Offsets.kt not found at " + kt + "; table-key checking falls back to the tables"); return declaredKeys; }
        try {
            Pattern objPat = Pattern.compile("^\\s*(?:internal\\s+)?object\\s+(\\w+)\\s*\\{");
            Pattern valPat = Pattern.compile("^\\s*val\\s+(\\w+)\\s+by\\s+\\w+");
            String obj = null;
            for (String line : readText(kt).split("\n")) {
                Matcher m = objPat.matcher(line);
                if (m.find()) { obj = m.group(1); continue; }
                Matcher v = valPat.matcher(line);
                if (v.find() && obj != null) declaredKeys.add(obj + "." + v.group(1));
            }
        } catch (IOException e) {
            println("WARN: could not read Offsets.kt: " + e);
        }
        return declaredKeys;
    }

    private Set<String> verifiedIds;

    @SuppressWarnings("unchecked")
    private Set<String> verifiedFieldIds() throws IOException {
        if (verifiedIds != null) return verifiedIds;
        verifiedIds = new LinkedHashSet<>();
        Path regPath = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(regPath)) return verifiedIds;
        Object vf = ((Map<String, Object>) Json.parse(readText(regPath))).get("verified_fields");
        if (!(vf instanceof Map)) return verifiedIds;
        Object rows = ((Map<String, Object>) vf).get(profile.id());
        if (rows instanceof List) for (Object o : (List<Object>) rows) {
            String id = str(((Map<String, Object>) o).get("id"));
            if (id != null) verifiedIds.add(id);
        }
        return verifiedIds;
    }

    /**
     * `unresolved` names what this build lost, and nothing else. A name that never reached a table cannot
     * be lost from one: registry-only anchor targets and retired keys reported themselves here for builds,
     * which turned the field into a list nobody could act on and hid the entries that mattered. Everything
     * dropped from it is still counted and named in the residual report.
     */
    @SuppressWarnings("unchecked")
    private void reconcileUnresolved(Map<String, Object> objects, Set<String> doActionNames) throws IOException {
        Set<String> present = new LinkedHashSet<>();
        for (Map.Entry<String, Object> oe : objects.entrySet()) {
            if (!(oe.getValue() instanceof Map)) continue;
            for (String f : ((Map<String, Object>) oe.getValue()).keySet()) present.add(oe.getKey() + "." + f);
        }
        for (String n : doActionNames) present.add("doAction." + n);

        Map<String, String> reconciled = new LinkedHashMap<>();
        for (String id : previousTableKeys()) {
            if (present.contains(id)) continue;
            String why = unresolvedIds.get(id);
            reconciled.put(id, why != null ? why : "carried by " + previousTableBuild + ", not re-derived for " + version);
        }
        for (Map.Entry<String, String> e : unresolvedIds.entrySet())
            if (!reconciled.containsKey(e.getKey()))
                applyFailure("offset-table", "not a key of any table (reported outside unresolved): " + e.getValue(), e.getKey());
        unresolvedIds.clear();
        unresolvedIds.putAll(reconciled);
    }

    private Set<String> previousTableKeys;
    private String previousTableBuild;
    private Set<String> previousDoActions;

    /** Every `Object.FIELD` and `doAction.NAME` the newest table for another build of this platform carries. */
    @SuppressWarnings("unchecked")
    private Set<String> previousTableKeys() throws IOException {
        if (previousTableKeys != null) return previousTableKeys;
        previousTableKeys = new LinkedHashSet<>();
        previousDoActions = new LinkedHashSet<>();
        Path dir = engineOffsetsDir();
        Path best = null;
        if (Files.isDirectory(dir)) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, profile.id() + "-*.json")) {
                for (Path p : ds) {
                    String n = p.getFileName().toString();
                    String b = n.substring((profile.id() + "-").length(), n.length() - ".json".length());
                    if (b.equals(version)) continue;
                    if (previousTableBuild == null || b.compareTo(previousTableBuild) > 0) { previousTableBuild = b; best = p; }
                }
            }
        }
        if (best == null) return previousTableKeys;
        Map<String, Object> prev = (Map<String, Object>) Json.parse(readText(best));
        Object objs = prev.get("objects");
        if (objs instanceof Map) for (Map.Entry<String, Object> oe : ((Map<String, Object>) objs).entrySet())
            if (oe.getValue() instanceof Map)
                for (String f : ((Map<String, Object>) oe.getValue()).keySet()) previousTableKeys.add(oe.getKey() + "." + f);
        Object acts = prev.get("doActions");
        if (acts instanceof List) for (Object o : (List<Object>) acts) {
            String n = str(((Map<String, Object>) o).get("name"));
            if (n != null) { previousDoActions.add(n); previousTableKeys.add("doAction." + n); }
        }
        return previousTableKeys;
    }

    private Set<String> previousDoActionNames() throws IOException {
        previousTableKeys();
        return previousDoActions;
    }

    /**
     * Objects whose values are absolute module addresses rather than struct-relative displacements.
     * Every one of these moves on any build, so carrying one forward would hand the engine a valid-looking
     * pointer into the wrong place — a silent garbage read rather than an absent-entry failure.
     */
    private static final Set<String> ABSOLUTE_ADDRESS_OBJECTS =
            new HashSet<>(Arrays.asList("OFunctions", "OGlobal", "OInputGlobals", "OReferenceFunctions"));

    /** No struct in this client is megabytes wide, so a value this large is a module address. */
    private static boolean looksAbsolute(String v) {
        if (v == null) return false;
        try { return parseHexOrDec(v) >= 0x100000L; } catch (Exception e) { return false; }
    }

    /**
     * Field ids the registry marks as disproved. The declaration stays in the engine's Offsets.kt so a
     * later session can fill it in; leaving the key out of the generated table makes the accessor throw
     * instead of dereferencing a value that analysis has shown describes something else.
     */
    @SuppressWarnings("unchecked")
    private Set<String> withheldIds;

    @SuppressWarnings("unchecked")
    private Set<String> withheldFieldIds() throws IOException {
        if (withheldIds != null) return withheldIds;
        Set<String> out = withheldIds = new LinkedHashSet<>();
        Path regPath = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(regPath)) return out;
        Object wf = ((Map<String, Object>) Json.parse(readText(regPath))).get("withheld_fields");
        if (!(wf instanceof Map)) return out;
        for (String key : new String[]{"common", profile.id()}) {
            Object rows = ((Map<String, Object>) wf).get(key);
            if (!(rows instanceof List)) continue;
            for (Object o : (List<Object>) rows) {
                String id = (o instanceof Map) ? str(((Map<String, Object>) o).get("id")) : String.valueOf(o);
                if (id != null) out.add(id);
            }
        }
        if (!out.isEmpty()) println("withheld_fields[" + profile.id() + "]: " + out.size() + " not carried - " + out);
        return out;
    }

    /**
     * A new build starts with no table, but only a couple of dozen of its several hundred entries come
     * from anchor recipes; the rest were established by hand and would vanish on every bump. Struct-relative
     * offsets are carried and flagged for revalidation; absolute addresses are deliberately dropped.
     */
    @SuppressWarnings("unchecked")
    private void carryForwardPreviousTable(Map<String, Object> root) throws IOException {
        Path dir = engineOffsetsDir();
        if (!Files.isDirectory(dir)) return;
        Path best = null; String bestBuild = null;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, profile.id() + "-*.json")) {
            for (Path p : ds) {
                String n = p.getFileName().toString();
                String b = n.substring((profile.id() + "-").length(), n.length() - ".json".length());
                if (b.equals(version)) continue;
                if (bestBuild == null || b.compareTo(bestBuild) > 0) { bestBuild = b; best = p; }
            }
        }
        if (best == null) return;
        Map<String, Object> prev = (Map<String, Object>) Json.parse(readText(best));
        Map<String, Object> prevObjects = (Map<String, Object>) prev.get("objects");
        if (prevObjects == null) return;

        Set<String> withheld = withheldFieldIds();
        Map<String, Object> objects = new LinkedHashMap<>();
        int carried = 0, dropped = 0;
        for (Map.Entry<String, Object> oe : prevObjects.entrySet()) {
            Map<String, Object> fields = (Map<String, Object>) oe.getValue();
            if (ABSOLUTE_ADDRESS_OBJECTS.contains(oe.getKey())) {
                for (String f : fields.keySet()) {
                    dropped++;
                    applyFailure("offset-table", "absolute address not carried across builds", oe.getKey() + "." + f);
                }
                continue;
            }
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Object> fe : fields.entrySet()) {
                String fieldId = oe.getKey() + "." + fe.getKey();
                if (withheld.contains(fieldId)) {
                    dropped++;
                    applyFailure("offset-table", "withheld: previous value disproved, correct offset not yet located", fieldId);
                    continue;
                }
                Map<String, Object> e = new LinkedHashMap<>((Map<String, Object>) fe.getValue());
                // A module-sized value inside an otherwise struct-relative object is an absolute address
                // that the object-level list did not catch; carrying one is a silent garbage read.
                if (looksAbsolute(str(e.get("value")))) {
                    dropped++;
                    unresolved(fieldId, "absolute address from " + bestBuild + " not carried across builds");
                    continue;
                }
                e.put("carried_from", bestBuild);
                copy.put(fe.getKey(), e);
                carried++;
            }
            objects.put(oe.getKey(), copy);
        }
        root.put("objects", objects);
        // Human-written per-object documentation has no address to re-derive, so it can only survive
        // by being carried; without this every build silently discards it.
        Object notes = prev.get("objectNotes");
        if (notes != null) root.put("objectNotes", notes);
        // Seeded so the merge below has a prior set to preserve rather than starting from empty.
        // Every doAction value is a .text RVA, so a carried one is stale by construction; it is stamped
        // here rather than trusted, and the merge clears the stamp only for entries this run re-derives.
        Object prevActs = prev.get("doActions");
        if (prevActs instanceof List) {
            List<Object> seeded = new ArrayList<>();
            for (Object o : (List<Object>) prevActs) {
                Map<String, Object> e = new LinkedHashMap<>((Map<String, Object>) o);
                if (!version.equals(str(e.get("verified_build")))) {
                    unresolved("doAction." + str(e.get("name")),
                            "handler RVA from " + bestBuild + " not carried across builds");
                    continue;
                }
                seeded.add(e);
            }
            root.put("doActions", seeded);
        } else if (prevActs != null) {
            root.put("doActions", prevActs);
        }
        println("offset table seeded from " + best.getFileName() + ": " + carried
                + " struct-relative entries carried, " + dropped + " absolute addresses dropped (must be re-derived)"
                + (notes != null ? ", objectNotes carried" : ""));
    }

    /**
     * A table the engine's index does not list is invisible at runtime however complete it is, and
     * relying on a human to add the line has already been missed twice.
     */
    @SuppressWarnings("unchecked")
    private void registerInOffsetIndex() throws IOException {
        Path idx = engineOffsetsDir().resolve("index.json");
        String entry = profile.id() + "-" + version;
        Map<String, Object> root = Files.exists(idx)
                ? (Map<String, Object>) Json.parse(readText(idx))
                : new LinkedHashMap<>();
        List<Object> tables = (root.get("tables") instanceof List)
                ? (List<Object>) root.get("tables") : new ArrayList<>();
        for (Object t : tables) if (entry.equals(str(t))) { println("offset index already lists " + entry); return; }
        tables.add(entry);
        root.put("tables", tables);
        writeText(idx, Json.write(root) + "\n");
        println("offset index: registered " + entry);
    }

    @SuppressWarnings("unchecked")
    private boolean upsertOffset(Map<String, Object> objects, String obj, String field, Map<String, Object> entry) {
        Map<String, Object> fields = (Map<String, Object>) objects.computeIfAbsent(obj, k -> new LinkedHashMap<String, Object>());
        return fields.put(field, entry) == null;
    }

    /** updaterRoot is &lt;repo&gt;/re-resources/updater, so the engine module is two levels up. */
    private Path engineOffsetsDir() {
        return updaterRoot.getParent().getParent()
                .resolve("client-plugin-engine").resolve("src").resolve("main")
                .resolve("resources").resolve("offsets");
    }

    private String anchorResult(String id, boolean located, String oldV, String newV, String conf, String note, String anchorAddr) {
        return String.format("{\"id\":%s,\"located\":%s,\"old_value\":%s,\"new_value\":%s,\"changed\":%s,\"confidence\":%s,\"note\":%s,\"anchor_addr\":%s}",
                jstr(id), located, jstr(oldV), jstr(newV),
                (oldV != null && newV != null && !normHex(oldV).equals(normHex(newV))),
                jstr(conf), jstr(note), jstr(anchorAddr));
    }

    // anchors.json export: fill sig + re-resolve old_value by running the recipe against THIS (old) binary
    private String exportAnchors() throws Exception {
        Path reg = updaterRoot.resolve("anchor_registry.json");
        if (!Files.exists(reg)) { println("WARN: anchor_registry.json missing; anchors.json will be empty"); return "{\"anchors\":[]}"; }
        Object root = Json.parse(readText(reg));
        Map<String, Object> rootMap = (Map<String, Object>) root;
        List<Object> anchors = (List<Object>) rootMap.get("anchors");
        Map<String, List<Function>> idx = null; // anchors locate via string/name; sig fallback self-scans
        for (Object ao : anchors) {
            Map<String, Object> a = (Map<String, Object>) ao;
            if (a.containsKey("shared_anchor")) continue;
            String scope = anchorPlatform(a, str(a.get("id")));
            if (scope != null && !scope.equals(profile.id())) continue;   // written for the other toolchain
            if (a.containsKey("manager_class")) {
                String mc = str(a.get("manager_class"));
                int minSites = a.get("min_sites") == null ? 3 : ((Number) a.get("min_sites")).intValue();
                long dmin = a.get("disp_min") == null ? 0x400L : parseHexOrDec(str(a.get("disp_min")));
                long dmax = a.get("disp_max") == null ? 0x20000L : parseHexOrDec(str(a.get("disp_max")));
                long[] r = resolveManagerClass(mc, minSites, dmin, dmax);
                if (r != null) {
                    reseed(anchors, str(a.get("id")), "0x" + Long.toHexString(r[0]));
                    println("anchor self-resolve " + str(a.get("id")) + " = 0x" + Long.toHexString(r[0]) + " (manager_class " + mc + " " + r[1] + "/" + r[2] + " sites)");
                } else println("anchor self-resolve FAILED " + str(a.get("id")) + ": no consensus for " + mc);
                continue;
            }
            Map<String, Object> anchorDef = (Map<String, Object>) a.get("anchor");
            Map<String, Object> extract = (Map<String, Object>) a.get("extract");
            if (anchorDef == null) continue;
            Located loc = locateAnchor(anchorDef, idx);
            if (loc != null && loc.func != null) {
                FuncSig sig = buildFunctionSignature(loc.func);
                if (sig != null) { anchorDef.put("sig_blob", toHex(sig.blob)); anchorDef.put("sig_mask", toHex(sig.mask)); anchorDef.put("feat_hash", sha256(sig.normSig)); }
                if (extract != null) {
                    try {
                        Map<String, Long> emitted = extractAnchor(anchorDef, extract, loc.func);
                        for (Map.Entry<String, Long> e : emitted.entrySet()) {
                            reseed(anchors, e.getKey(), "0x" + Long.toHexString(e.getValue()));
                            println("anchor self-resolve " + e.getKey() + " = 0x" + Long.toHexString(e.getValue()));
                        }
                    } catch (Exception ex) { println("anchor self-resolve FAILED " + str(a.get("id")) + ": " + ex.getMessage()); }
                }
            } else println("anchor NOT located in old binary: " + str(a.get("id")));
        }
        stampOFunctionSignatures(rootMap);
        return Json.write(root);
    }

    // ============================================================ PORTED SIG ENGINE (RS3SignatureUpdater) ============================================================

    private static class FuncSig { String normSig; int insnCount; byte[] blob; byte[] mask; }

    private FuncSig buildFunctionSignature(Function f) {
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionAt(f.getEntryPoint());
        if (insn == null) return null;
        List<Instruction> instructions = new ArrayList<>();
        int count = 0;
        while (insn != null && f.getBody().contains(insn.getAddress()) && count < FUNC_MAX_INSNS) {
            instructions.add(insn); insn = insn.getNext(); count++;
        }
        if (instructions.isEmpty()) return null;
        String norm = buildNormalizedSignature(instructions);
        ByteArrayOutputStream blobStream = new ByteArrayOutputStream();
        ByteArrayOutputStream maskStream = new ByteArrayOutputStream();
        for (Instruction i : instructions) {
            byte[] bytes;
            try { bytes = i.getBytes(); } catch (MemoryAccessException e) { continue; }
            byte[] mask = new byte[bytes.length];
            Arrays.fill(mask, (byte) 0xFF);
            if (hasRelocatableOperand(i) && bytes.length >= 2)
                for (int k = 2; k < mask.length; k++) mask[k] = 0x00;
            blobStream.write(bytes, 0, bytes.length);
            maskStream.write(mask, 0, mask.length);
        }
        FuncSig sig = new FuncSig();
        sig.normSig = norm; sig.insnCount = instructions.size();
        sig.blob = blobStream.toByteArray(); sig.mask = maskStream.toByteArray();
        return sig;
    }

    private String buildNormalizedSignature(List<Instruction> instructions) {
        StringBuilder sb = new StringBuilder();
        for (Instruction i : instructions) {
            sb.append(i.getMnemonicString()).append('(');
            int n = i.getNumOperands();
            for (int op = 0; op < n; op++) { sb.append(operandShape(i.getOpObjects(op))); if (op + 1 < n) sb.append(','); }
            sb.append(");");
        }
        return sb.toString();
    }

    private String operandShape(Object[] o) {
        if (o == null || o.length == 0) return "0";
        boolean a = false, r = false, im = false;
        for (Object x : o) { if (x instanceof Address) a = true; else if (x instanceof Register) r = true; else if (x instanceof Scalar) im = true; }
        if (a) return "ADDR";
        if (im && !r) return "IMM";
        if (r && !im) return "REG";
        if (im && r) return "REGIMM";
        return "X";
    }

    private boolean hasRelocatableOperand(Instruction i) {
        for (int op = 0; op < i.getNumOperands(); op++) {
            Object[] objs = i.getOpObjects(op);
            if (objs == null) continue;
            for (Object o : objs) {
                if (o instanceof Address) return true;
                if (o instanceof Scalar s && s.getUnsignedValue() > 0xFFFF) return true;
            }
        }
        return false;
    }

    private Map<String, List<Function>> indexFunctionsByNormalizedSignature() {
        Map<String, List<Function>> index = new HashMap<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            FuncSig sig = buildFunctionSignature(f);
            if (sig == null) continue;
            index.computeIfAbsent(sig.normSig, k -> new ArrayList<>()).add(f);
        }
        return index;
    }

    private enum ResolveStatus { FOUND, MISSING, AMBIGUOUS, COLLISION }
    private static class ResolveResult { ResolveStatus status; Address address; String note; List<Function> candidates;
        ResolveResult(ResolveStatus s, Address a, String n) { status = s; address = a; note = n; } }

    private ResolveResult resolveFunction(Map<String, String> rec, Map<String, List<Function>> normIndex) {
        String norm = rec.get("func_norm_sig"), blobHex = rec.get("blob_hex"), maskHex = rec.get("mask_hex");
        if (norm == null || blobHex == null || maskHex == null) return new ResolveResult(ResolveStatus.MISSING, null, "malformed");
        byte[] blob = fromHex(blobHex), mask = fromHex(maskHex);
        List<Function> cands = normIndex.getOrDefault(norm, Collections.emptyList());
        if (cands.isEmpty()) return new ResolveResult(ResolveStatus.MISSING, null, "no matching signature");
        List<Function> matches = new ArrayList<>();
        for (Function f : cands) {
            byte[] fb = readFunctionBytes(f, blob.length);
            if (fb == null) continue;
            if (maskedHamming(blob, mask, fb) <= VERIFY_MAX_MISMATCH) matches.add(f);
        }
        if (matches.isEmpty()) return new ResolveResult(ResolveStatus.MISSING, null, "verification failed");
        if (matches.size() == 1) return new ResolveResult(ResolveStatus.FOUND, matches.get(0).getEntryPoint(), null);
        ResolveResult amb = new ResolveResult(ResolveStatus.AMBIGUOUS, null, matches.size() + " matches");
        amb.candidates = matches;
        return amb;
    }

    private byte[] readFunctionBytes(Function f, int maxBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Instruction insn = currentProgram.getListing().getInstructionAt(f.getEntryPoint());
        while (insn != null && f.getBody().contains(insn.getAddress()) && out.size() < maxBytes) {
            try { byte[] b = insn.getBytes(); out.write(b, 0, b.length); } catch (MemoryAccessException e) {}
            insn = insn.getNext();
        }
        byte[] res = out.toByteArray();
        return res.length < maxBytes ? Arrays.copyOf(res, maxBytes) : res;
    }

    private int maskedHamming(byte[] p, byte[] m, byte[] t) {
        int mis = 0, len = Math.min(p.length, Math.min(m.length, t.length));
        for (int i = 0; i < len; i++) { if ((m[i] & 0xFF) == 0) continue; if ((p[i] & 0xFF) != (t[i] & 0xFF)) mis++; }
        return mis + Math.max(0, p.length - len);
    }

    private Namespace createNamespaceHierarchy(String path) throws Exception {
        if (path == null || path.isEmpty()) return currentProgram.getGlobalNamespace();
        Namespace parent = currentProgram.getGlobalNamespace();
        SymbolTable st = currentProgram.getSymbolTable();
        for (String part : path.split("::")) {
            Namespace ex = st.getNamespace(part, parent);
            if (ex == null) ex = st.createNameSpace(parent, part, SourceType.USER_DEFINED);
            parent = ex;
        }
        return parent;
    }

    // ============================================================ INSTRUCTION HELPERS ============================================================

    private List<Instruction> bodyInstructions(Function f, int cap) {
        List<Instruction> out = new ArrayList<>();
        Instruction insn = currentProgram.getListing().getInstructionAt(f.getEntryPoint());
        int n = 0;
        while (insn != null && f.getBody().contains(insn.getAddress()) && n < cap) { out.add(insn); insn = insn.getNext(); n++; }
        return out;
    }

    private int findFrom(List<Instruction> insns, int start, Map<String, Object> step, Map<String, String> binds) {
        for (int i = start; i < insns.size(); i++) if (matchesStep(insns.get(i), step, binds)) return i;
        return -1;
    }

    private Long captureCallArg(List<Instruction> insns, String calleeFull, int argN, Map<String, Object> step) {
        Register argReg = nthArgRegister(argN);
        Map<String, Object> mem = step != null ? (Map<String, Object>) step.get("mem") : null;
        long lo = (mem != null && mem.containsKey("disp_min")) ? parseHexOrDec(str(mem.get("disp_min"))) : Long.MIN_VALUE;
        long hi = (mem != null && mem.containsKey("disp_max")) ? parseHexOrDec(str(mem.get("disp_max"))) : Long.MAX_VALUE;
        for (int i = 0; i < insns.size(); i++) {
            Instruction in = insns.get(i);
            if (!isCallTo(in, calleeFull)) continue;
            // scan backward for LEA argReg,[base+disp] (the arg load for this call), honoring a disp window
            for (int j = i - 1; j >= 0 && j > i - 30; j--) {
                Instruction p = insns.get(j);
                if (!"LEA".equalsIgnoreCase(p.getMnemonicString())) continue;
                Register w = firstWrittenRegister(p);
                if (w != null && argReg != null && w.getName().equalsIgnoreCase(argReg.getName())) {
                    Long d = firstMemDisp(p);
                    if (d != null && d >= lo && d <= hi) return d;
                    break; // the nearest LEA to argReg before the call is the arg load; if out of window, this caller is wrong
                }
            }
        }
        return null;
    }

    private Long backScanDisp(List<Instruction> insns, String calleeFull, Map<String, Object> step, Map<String, String> binds) {
        Map<String, Object> mem = (Map<String, Object>) step.get("mem");
        String dstReg = str(step.get("dst_reg"));
        // "@this" is the ABI-neutral spelling: RDI on SysV, RCX on Win64. A recipe that hardcodes a
        // register name silently matches the wrong instruction on the other platform.
        if ("@this".equals(dstReg)) dstReg = profile.thisRegister();
        int window = step.containsKey("window") ? ((Number) step.get("window")).intValue() : 40;
        for (int i = 0; i < insns.size(); i++) {
            if (!isCallTo(insns.get(i), calleeFull)) continue;
            for (int j = i - 1; j >= 0 && j > i - window; j--) {
                Instruction p = insns.get(j);
                if (dstReg != null) {
                    // Find the instruction that sets dstReg to client±off (the this-arg load).
                    Register w = firstWrittenRegister(p);
                    if (w == null || !w.getName().equalsIgnoreCase(dstReg)) continue;
                    // memOperandIndex, not firstDynamicOp: a `LEA reg,[base+disp]` address operand is
                    // ADDRESS, not DYNAMIC, so the window silently did not apply to the one instruction
                    // shape a this-load actually takes, and an unrelated object's displacement passed.
                    if (mem != null && memOperandIndex(p) >= 0 && !memMatches(p, mem, binds)) continue;
                    Long off = thisLoadOffset(p);   // MOV/LEA [base+disp]->disp ; ADD/SUB imm->imm
                    if (off != null) return off;
                } else {
                    if (firstDynamicOp(p) < 0) continue;             // must be a memory load
                    if (mem != null && !memMatches(p, mem, binds)) continue;
                    Long d = firstMemDisp(p); if (d != null) return d;
                }
            }
        }
        return null;
    }

    // Offset by which an instruction sets a register relative to a base: MOV/LEA reg,[base+disp]->disp; ADD/SUB reg,imm->imm.
    private Long thisLoadOffset(Instruction p) {
        String mn = p.getMnemonicString();
        int dyn = firstDynamicOp(p);
        if (dyn >= 0) { for (Object o : p.getOpObjects(dyn)) if (o instanceof Scalar s) return s.getUnsignedValue(); return 0L; }
        if (mn.equalsIgnoreCase("LEA")) { for (Object o : p.getOpObjects(1)) if (o instanceof Scalar s) return s.getUnsignedValue(); }
        if (mn.equalsIgnoreCase("ADD") || mn.equalsIgnoreCase("SUB")) return firstImmediate(p);
        return null;
    }

    private boolean isCallTo(Instruction insn, String calleeFull) {
        if (!"CALL".equalsIgnoreCase(insn.getMnemonicString())) return false;
        for (Reference r : insn.getReferencesFrom()) {
            if (r.getReferenceType().isCall()) {
                Function f = getFunctionAt(r.getToAddress());
                if (f != null && (fullNameOf(f).equals(calleeFull) || f.getName().equals(leaf(calleeFull)))) return true;
            }
        }
        return false;
    }

    private Register nthArgRegister(int n) {
        String[] order = profile.argRegisters();
        if (n < 1 || n > order.length) return null;
        return currentProgram.getLanguage().getRegister(order[n - 1]);
    }

    private Register firstWrittenRegister(Instruction insn) {
        Object[] o = insn.getOpObjects(0);
        if (o != null) for (Object x : o) if (x instanceof Register) return (Register) x;
        return null;
    }

    private Long firstMemDisp(Instruction insn) {
        int op = memOperandIndex(insn);
        return op < 0 ? null : memParts(insn, op).disp;
    }

    /**
     * A memory operand's base, index and displacement. An indexed operand carries the scale as a scalar
     * too, and reading "the first scalar" as the displacement silently captured the SCALE out of every
     * `[base + idx*4 + disp]` load — a 4 that passes for an offset. The scale is identified and removed
     * by value rather than by position, because the object order is the decoder's business, not ours.
     */
    private static class MemParts {
        Register base, index;
        Long disp;
    }

    private MemParts memParts(Instruction insn, int op) {
        MemParts m = new MemParts();
        List<Scalar> scalars = new ArrayList<>();
        for (Object o : insn.getOpObjects(op)) {
            if (o instanceof Register r) { if (m.base == null) m.base = r; else if (m.index == null) m.index = r; }
            else if (o instanceof Scalar sc) scalars.add(sc);
        }
        if (m.index != null) {
            for (int i = 0; i < scalars.size(); i++) {
                long v = scalars.get(i).getUnsignedValue();
                if (v == 1 || v == 2 || v == 4 || v == 8) { scalars.remove(i); break; }
            }
        }
        if (!scalars.isEmpty()) m.disp = scalars.get(scalars.size() - 1).getUnsignedValue();
        return m;
    }

    private Long firstImmediate(Instruction insn) {
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] objs = insn.getOpObjects(op);
            if (objs == null) continue;
            boolean hasReg = false; Scalar s = null;
            for (Object o : objs) { if (o instanceof Register) hasReg = true; else if (o instanceof Scalar) s = (Scalar) o; }
            if (!hasReg && s != null) return s.getUnsignedValue();
        }
        return null;
    }

    private boolean hasImmediate(Instruction insn, long want) {
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] objs = insn.getOpObjects(op);
            if (objs == null) continue;
            for (Object o : objs) if (o instanceof Scalar s && (s.getValue() == want || s.getUnsignedValue() == want)) return true;
        }
        return false;
    }

    private Address firstAddressOperand(Instruction insn) {
        for (int op = 0; op < insn.getNumOperands(); op++) {
            Object[] objs = insn.getOpObjects(op);
            if (objs == null) continue;
            for (Object o : objs) if (o instanceof Address) return (Address) o;
        }
        // fall back to a memory reference target
        for (Reference r : insn.getReferencesFrom()) if (r.getReferenceType().isData()) return r.getToAddress();
        return null;
    }

    private boolean operandSizeMatches(Instruction insn, int want) {
        // best-effort: 32-bit reg names start with E or are R8D..R15D; 64-bit start with R..; 8-bit end with L/B
        Register w = firstWrittenRegister(insn);
        if (w == null) return true; // unknown -> don't reject
        int bits = w.getBitLength();
        return bits == want;
    }

    private String captureName(Map<String, Object> step) {
        if (step.containsKey("capture")) {
            Object c = step.get("capture");
            if (c instanceof Map) return str(((Map<String, Object>) c).get("as"));
            return str(c);
        }
        return "v";
    }

    private long evalExpr(String expr, Map<String, Long> vars) {
        // tiny evaluator: tokens of vars/hex/dec with + - * << and parens
        return new ExprParser(expr, vars).parse();
    }

    // ============================================================ MISC HELPERS ============================================================

    private String detectVersion() {
        try {
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                if (!b.isInitialized() || !b.isRead()) continue;
                if (!profile.isRodataBlock(b.getName())) continue;
                long size = Math.min(b.getSize(), 12_000_000L);
                byte[] buf = new byte[(int) size];
                b.getBytes(b.getStart(), buf, 0, (int) size);
                String s = new String(buf, StandardCharsets.ISO_8859_1);
                Matcher m = VERSION_PATTERN.matcher(s);
                if (m.find()) return m.group(1) + "-" + m.group(2);
            }
        } catch (Exception e) { printerr("version detect error: " + e.getMessage()); }
        return null;
    }

    private Path locateUpdaterRoot() {
        try {
            File src = getSourceFile().getFile(false); // .../re-resources/ghidra-scripts/RS3ProjectXUpdater.java
            Path p = src.toPath().getParent().getParent().resolve("updater"); // re-resources/updater
            return p;
        } catch (Exception e) {
            return Paths.get(System.getProperty("user.home"), "projects", "iEasyScript", "re-resources", "updater");
        }
    }

    private Path newestDataDir() throws IOException {
        if (!Files.isDirectory(updaterRoot)) return null;
        Path best = null;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(updaterRoot, "updater_data_*")) {
            for (Path p : ds) if (best == null || p.getFileName().toString().compareTo(best.getFileName().toString()) > 0) best = p;
        }
        return best;
    }

    private Function getFunctionByName(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) if (name.equals(f.getName())) return f;
        return null;
    }

    private Function findFunctionByQualifiedName(String full) {
        if (full == null) return null;
        if (nameMap != null) { Function f = nameMap.get(full); if (f != null) return f; }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true))
            if (fullNameOf(f).equals(full)) return f;
        return null;
    }

    private int insnIndexFromEntry(Function f, Address at) {
        int i = 0;
        Instruction insn = getInstructionAt(f.getEntryPoint());
        while (insn != null && f.getBody().contains(insn.getAddress())) {
            if (insn.getAddress().equals(at)) return i;
            insn = insn.getNext(); i++;
        }
        return -1;
    }

    // (plate comments use the inherited FlatProgramAPI.setPlateComment(Address,String))

    private boolean isDefaultName(String n) { for (String p : DEFAULT_LABEL_PREFIXES) if (n.startsWith(p)) return true; return false; }

    private String fullNameOf(Function f) { String ns = fullNs(f.getParentNamespace()); return ns.isEmpty() ? f.getName() : ns + "::" + f.getName(); }
    private String fullNs(Namespace ns) {
        if (ns == null || ns.isGlobal()) return "";
        List<String> parts = new ArrayList<>(); Namespace c = ns;
        while (c != null && !c.isGlobal()) { parts.add(0, c.getName()); c = c.getParentNamespace(); }
        return String.join("::", parts);
    }
    private static String leaf(String full) { int i = full.lastIndexOf("::"); return i >= 0 ? full.substring(i + 2) : full; }
    private static String nsOf(String full) { int i = full.lastIndexOf("::"); return i >= 0 ? full.substring(0, i) : ""; }

    private Address addrOf(long v) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
    private Address parseAddr(String s) { if (s == null) return null; try { return addrOf(Long.parseLong(s.replace("0x", ""), 16)); } catch (Exception e) { return null; } }

    private String stripStaleAddrs(String text) {
        if (text == null) return null;
        // remove "947-3 @ 0x...", "@ 0x...", "0x00xxxxxx" version-specific refs but keep substance
        return text.replaceAll("@\\s*0x[0-9a-fA-F]+", "").replaceAll("\\b94[0-9]-[0-9]+ ?@? ?0x[0-9a-fA-F]+", "");
    }

    private static long parseHexOrDec(String s) {
        if (s == null) return 0;
        s = s.trim();
        return s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
    }
    private static String normHex(String s) { if (s == null) return ""; s = s.toLowerCase().replace("0x", ""); int i = 0; while (i < s.length() - 1 && s.charAt(i) == '0') i++; return s.substring(i); }

    private static boolean notEmpty(String s) { return s != null && !s.isEmpty(); }
    private static String str(Object o) { return o == null ? null : o.toString(); }
    private static String jstr(String s) { if (s == null) return "null"; return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\t", "\\t") + '"'; }

    // ---- NDJSON tab codec (ported from RS3SignatureUpdater.Record) ----
    private String ndjsonEncode(LinkedHashMap<String, String> kv) {
        StringBuilder sb = new StringBuilder(); boolean first = true;
        for (Map.Entry<String, String> e : kv.entrySet()) {
            if (!first) sb.append('\t'); first = false;
            sb.append(ndEsc(e.getKey())).append('=').append(ndEsc(e.getValue()));
        }
        return sb.toString();
    }
    private List<Map<String, String>> readNdjson(Path p) throws IOException {
        List<Map<String, String>> out = new ArrayList<>();
        if (!Files.exists(p)) return out;
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            line = line.strip(); if (line.isEmpty() || line.startsWith("#")) continue;
            Map<String, String> r = new LinkedHashMap<>();
            for (String part : line.split("\t")) { int i = part.indexOf('='); if (i <= 0) continue; r.put(ndUnesc(part.substring(0, i)), ndUnesc(part.substring(i + 1))); }
            out.add(r);
        }
        return out;
    }
    private static String ndEsc(String s) { if (s == null) return ""; return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("=", "\\e"); }
    private static String ndUnesc(String s) {
        StringBuilder o = new StringBuilder(); boolean e = false;
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i);
            if (!e) { if (c == '\\') e = true; else o.append(c); }
            else { switch (c) { case 't' -> o.append('\t'); case 'n' -> o.append('\n'); case 'e' -> o.append('='); case '\\' -> o.append('\\'); default -> o.append(c); } e = false; } }
        return o.toString();
    }

    private void writeLines(Path p, List<String> lines) throws IOException { Files.write(p, lines, StandardCharsets.UTF_8); }
    private void writeText(Path p, String s) throws IOException { Files.write(p, s.getBytes(StandardCharsets.UTF_8)); }
    private String readText(Path p) throws IOException { return new String(Files.readAllBytes(p), StandardCharsets.UTF_8); }

    private String toHex(byte[] b) { StringBuilder sb = new StringBuilder(b.length * 2); for (byte x : b) sb.append(String.format("%02x", x & 0xFF)); return sb.toString(); }
    private byte[] fromHex(String h) { int n = h.length(); byte[] b = new byte[n / 2]; for (int i = 0; i < n; i += 2) b[i / 2] = (byte) Integer.parseInt(h.substring(i, i + 2), 16); return b; }
    private String sha256(String s) throws Exception { MessageDigest md = MessageDigest.getInstance("SHA-256"); return toHex(md.digest(s.getBytes(StandardCharsets.UTF_8))); }

    // ============================================================ tiny expr parser ============================================================
    private static class ExprParser {
        private final String s; private int pos; private final Map<String, Long> vars;
        ExprParser(String s, Map<String, Long> vars) { this.s = s; this.vars = vars; }
        long parse() { return shift(); }
        private long shift() { long v = add(); while (true) { skip(); if (match("<<")) v = v << add(); else return v; } }
        private long add() { long v = mul(); while (true) { skip(); if (peek('+')) { pos++; v += mul(); } else if (peek('-')) { pos++; v -= mul(); } else return v; } }
        private long mul() { long v = atom(); while (true) { skip(); if (peek('*')) { pos++; v *= atom(); } else return v; } }
        private long atom() { skip(); if (peek('(')) { pos++; long v = shift(); skip(); if (peek(')')) pos++; return v; }
            int start = pos; if (s.startsWith("0x", pos)) { pos += 2; while (pos < s.length() && isHex(s.charAt(pos))) pos++; return Long.parseLong(s.substring(start + 2, pos), 16); }
            while (pos < s.length() && (Character.isLetterOrDigit(s.charAt(pos)) || s.charAt(pos) == '_')) pos++;
            String tok = s.substring(start, pos);
            if (tok.isEmpty()) return 0;
            if (tok.equals("min") || tok.equals("max")) {
                skip();
                if (peek('(')) {
                    pos++;
                    long a = shift(); skip();
                    if (peek(',')) pos++;
                    long b = shift(); skip();
                    if (peek(')')) pos++;
                    return tok.equals("min") ? Math.min(a, b) : Math.max(a, b);
                }
            }
            if (vars.containsKey(tok)) return vars.get(tok);
            try { return Long.parseLong(tok); } catch (Exception e) { return 0; } }
        private void skip() { while (pos < s.length() && s.charAt(pos) == ' ') pos++; }
        private boolean peek(char c) { return pos < s.length() && s.charAt(pos) == c; }
        private boolean match(String t) { skip(); if (s.startsWith(t, pos)) { pos += t.length(); return true; } return false; }
        private boolean isHex(char c) { return Character.isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
    }

    // ============================================================ minimal JSON (parse + write) ============================================================
    static final class Json {
        private final String s; private int i;
        private Json(String s) { this.s = s; }
        static Object parse(String s) { Json j = new Json(s); j.ws(); Object v = j.val(); return v; }
        private Object val() { ws(); char c = s.charAt(i);
            return switch (c) { case '{' -> obj(); case '[' -> arr(); case '"' -> strv(); case 't','f' -> bool(); case 'n' -> nul(); default -> num(); }; }
        private Map<String, Object> obj() { Map<String, Object> m = new LinkedHashMap<>(); i++; ws(); if (s.charAt(i) == '}') { i++; return m; }
            while (true) { ws(); String k = strv(); ws(); i++; /* : */ Object v = val(); m.put(k, v); ws(); char c = s.charAt(i++); if (c == '}') break; } return m; }
        private List<Object> arr() { List<Object> a = new ArrayList<>(); i++; ws(); if (s.charAt(i) == ']') { i++; return a; }
            while (true) { a.add(val()); ws(); char c = s.charAt(i++); if (c == ']') break; } return a; }
        private String strv() { StringBuilder b = new StringBuilder(); i++; while (true) { char c = s.charAt(i++); if (c == '"') break; if (c == '\\') { char e = s.charAt(i++); switch (e) { case 'n' -> b.append('\n'); case 't' -> b.append('\t'); case 'r' -> b.append('\r'); case '"' -> b.append('"'); case '\\' -> b.append('\\'); case '/' -> b.append('/'); case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; } default -> b.append(e); } } else b.append(c); } return b.toString(); }
        private Object bool() { if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; } i += 5; return Boolean.FALSE; }
        private Object nul() { i += 4; return null; }
        private Object num() { int st = i; while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++; String t = s.substring(st, i).trim();
            try { if (t.indexOf('.') >= 0 || t.indexOf('e') >= 0 || t.indexOf('E') >= 0) return Double.parseDouble(t); return Long.parseLong(t); } catch (Exception e) { return t; } }
        private void ws() { while (i < s.length()) { char c = s.charAt(i); if (c == ' ' || c == '\n' || c == '\t' || c == '\r') i++; else if (c == '/' && i + 1 < s.length() && s.charAt(i + 1) == '/') { while (i < s.length() && s.charAt(i) != '\n') i++; } else break; } }

        @SuppressWarnings("unchecked")
        static String write(Object o) { StringBuilder b = new StringBuilder(); w(o, b, 0); return b.toString(); }
        @SuppressWarnings("unchecked")
        private static void w(Object o, StringBuilder b, int ind) {
            if (o == null) { b.append("null"); return; }
            if (o instanceof Map) { Map<String, Object> m = (Map<String, Object>) o; b.append("{\n"); int n = 0; for (Map.Entry<String, Object> e : m.entrySet()) { indent(b, ind + 1); b.append('"').append(e.getKey()).append("\": "); w(e.getValue(), b, ind + 1); if (++n < m.size()) b.append(','); b.append('\n'); } indent(b, ind); b.append('}'); }
            else if (o instanceof List) { List<Object> a = (List<Object>) o; b.append("[\n"); for (int k = 0; k < a.size(); k++) { indent(b, ind + 1); w(a.get(k), b, ind + 1); if (k < a.size() - 1) b.append(','); b.append('\n'); } indent(b, ind); b.append(']'); }
            else if (o instanceof Boolean) b.append(o.toString());
            else if (o instanceof Number) b.append(o.toString()); // numbers unquoted so re-parse yields Long/Double, not String
            else b.append('"').append(o.toString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")).append('"');
        }
        private static void indent(StringBuilder b, int n) { for (int k = 0; k < n; k++) b.append("  "); }
    }
}
