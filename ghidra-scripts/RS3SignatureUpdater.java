// SPDX-License-Identifier: MIT
// @category Analysis
// RS3SignatureUpdater.java
//
// Exports function signatures from specific namespaces and applies them to new projects.
// Modes:
//   1) Export signatures from namespaces (jag, eastl, ref_counter_base)
//   2) Import signatures and rename functions in new project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class RS3SignatureUpdater extends GhidraScript {

    // Tunables
    private static final int FUNC_MAX_INSNS = 40;
    private static final int VERIFY_MAX_MISMATCH = 6;
    private static final String[] TARGET_NAMESPACES = {"jag", "eastl", "ref_counter_base"};
    
    // NDJSON keys
    private static final String K_VER  = "ver";
    private static final String K_NAME = "name";
    private static final String K_NS   = "namespace";
    private static final String K_OLD  = "orig_addr";
    private static final String K_FNS  = "func_norm_sig";
    private static final String K_FCNT = "func_insn_count";
    private static final String K_BLOB = "blob_hex";
    private static final String K_MASK = "mask_hex";
    private static final String K_HASH = "feat_hash";

    private enum Mode { EXPORT_FROM_NAMESPACES, IMPORT_AND_RENAME, IMPORT_AND_RENAME_JSON }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program first.");
            return;
        }

        Mode mode = askChoice("Namespace Signature Transfer",
                "Select mode:",
                Arrays.asList(Mode.EXPORT_FROM_NAMESPACES, Mode.IMPORT_AND_RENAME, Mode.IMPORT_AND_RENAME_JSON),
                Mode.EXPORT_FROM_NAMESPACES);

        switch (mode) {
            case EXPORT_FROM_NAMESPACES -> doExport();
            case IMPORT_AND_RENAME -> doImport();
            case IMPORT_AND_RENAME_JSON -> doImportWithJson();
        }
    }

    // EXPORT: Capture signatures from target namespaces
    private void doExport() throws Exception {
        println("Exporting signatures from namespaces: " + String.join(", ", TARGET_NAMESPACES));
        
        List<Record> records = new ArrayList<>();
        Set<Function> processedFunctions = new HashSet<>();
        SymbolTable symTable = currentProgram.getSymbolTable();
        
        // Collect functions from target namespaces recursively
        for (String nsName : TARGET_NAMESPACES) {
            Namespace ns = symTable.getNamespace(nsName, null);
            if (ns == null) {
                println("Warning: Namespace '" + nsName + "' not found");
                continue;
            }
            collectFunctionsFromNamespace(nsName, ns, records, processedFunctions);
        }
        
        if (records.isEmpty()) {
            printerr("No functions found in target namespaces!");
            return;
        }
        
        println("Captured " + records.size() + " function signatures");
        
        File outFile = askFile("Save namespace signatures (e.g., namespace_sigs.ndjson)", "Save");
        if (outFile == null) return;
        
        writeNdjson(outFile, records);
        println("Saved " + records.size() + " signatures to " + outFile.getAbsolutePath());
    }
    
    // Recursively collect functions from namespace and its children
    private void collectFunctionsFromNamespace(String rootName, Namespace ns, 
                                              List<Record> records, 
                                              Set<Function> processed) throws Exception {
        if (ns == null) return;
        
        SymbolTable symTable = currentProgram.getSymbolTable();
        
        println("Processing namespace: " + getFullNamespacePath(ns));
        
        // Process function symbols in this namespace
        SymbolIterator symbols = symTable.getSymbols(ns);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.getSymbolType() != SymbolType.FUNCTION) continue;
            
            Address addr = sym.getAddress();
            Function func = getFunctionAt(addr);
            if (func == null || processed.contains(func)) continue;
            
            processed.add(func);
            
            // Build signature
            FuncSig sig = buildFunctionSignature(func);
            if (sig == null) {
                printerr("Failed to build signature for " + sym.getName());
                continue;
            }
            
            // Create record
            Record r = new Record();
            r.put(K_VER, "1");
            r.put(K_NAME, sym.getName());
            r.put(K_NS, getFullNamespacePath(ns));
            r.put(K_OLD, "0x" + addr.toString());
            r.put(K_FNS, sig.normSig);
            r.put(K_FCNT, Integer.toString(sig.insnCount));
            r.put(K_BLOB, toHex(sig.blob));
            r.put(K_MASK, toHex(sig.mask));
            r.put(K_HASH, sha256(sig.normSig + "|" + toHex(sig.blob) + "|" + toHex(sig.mask)));
            
            records.add(r);
            
            if (records.size() % 100 == 0) {
                println("Processed " + records.size() + " functions...");
            }
        }
        
        // Find child namespaces more reliably
        // Look for all namespaces whose parent is this namespace
        SymbolIterator allSymbols = symTable.getAllSymbols(false);
        Set<Namespace> childNamespaces = new HashSet<>();
        
        while (allSymbols.hasNext()) {
            Symbol sym = allSymbols.next();
            
            // Check if this symbol's namespace is a child of our current namespace
            Namespace symNamespace = sym.getParentNamespace();
            if (symNamespace != null && symNamespace.getParentNamespace() == ns 
                && !childNamespaces.contains(symNamespace) && !symNamespace.isGlobal()) {
                childNamespaces.add(symNamespace);
            }
        }
        
        // Also check for namespace symbols directly
        SymbolIterator nsSymbols = symTable.getSymbols(ns);
        while (nsSymbols.hasNext()) {
            Symbol sym = nsSymbols.next();
            if (sym.getSymbolType() == SymbolType.NAMESPACE) {
                // For namespace symbols, we need to find the actual namespace
                String childName = sym.getName();
                Namespace child = symTable.getNamespace(childName, ns);
                if (child != null && !childNamespaces.contains(child)) {
                    childNamespaces.add(child);
                }
            }
        }
        
        // Recursively process child namespaces
        for (Namespace child : childNamespaces) {
            println("Found child namespace: " + getFullNamespacePath(child));
            collectFunctionsFromNamespace(rootName, child, records, processed);
        }
    }
    
    // Get full namespace path (e.g., "jag::math::utils")
    private String getFullNamespacePath(Namespace ns) {
        if (ns == null || ns.isGlobal()) return "";
        
        List<String> parts = new ArrayList<>();
        Namespace current = ns;
        while (current != null && !current.isGlobal()) {
            parts.add(0, current.getName());
            current = current.getParentNamespace();
        }
        return String.join("::", parts);
    }

    // IMPORT: Apply signatures to rename functions
    private void doImport() throws Exception {
        File sigFile = askFile("Select signature file (NDJSON)", "Open");
        if (sigFile == null || !sigFile.exists()) {
            printerr("Signature file not found.");
            return;
        }
        
        List<Record> records = readNdjson(sigFile);
        println("Loaded " + records.size() + " signatures");
        
        // Build function index
        println("Building function index...");
        Map<String, List<Function>> normIndex = indexFunctionsByNormalizedSignature();
        
        // Resolve and rename
        List<ResolveResult> results = new ArrayList<>();
        int found = 0, missing = 0, ambiguous = 0;
        
        for (int i = 0; i < records.size(); i++) {
            if (monitor.isCancelled()) break;
            
            Record r = records.get(i);
            String name = r.get(K_NAME);
            String nsPath = r.get(K_NS);
            
            monitor.setProgress(i + 1);
            monitor.setMessage("Resolving " + name);
            
            ResolveResult result = resolveFunction(r, normIndex);
            results.add(result);
            
            if (result.status == ResolveStatus.FOUND) {
                found++;
                // Create namespace and rename function
                try {
                    Namespace targetNs = createNamespaceHierarchy(nsPath);
                    Symbol funcSym = currentProgram.getSymbolTable().getPrimarySymbol(result.address);
                    if (funcSym != null) {
                        funcSym.setNameAndNamespace(name, targetNs, SourceType.USER_DEFINED);
                        println(String.format("[FOUND] %s::%s -> 0x%s", 
                                            nsPath, name, result.address.toString()));
                    }
                } catch (Exception e) {
                    printerr("Failed to rename " + name + ": " + e.getMessage());
                }
            } else if (result.status == ResolveStatus.MISSING) {
                missing++;
                println(String.format("[MISSING] %s::%s - %s", 
                                    nsPath, name, result.note));
            } else if (result.status == ResolveStatus.AMBIGUOUS) {
                ambiguous++;
                println(String.format("[AMBIGUOUS] %s::%s - %s", 
                                    nsPath, name, result.note));
            }
        }
        
        // Print summary
        println("\n=== Import Summary ===");
        println("Total signatures: " + records.size());
        println("Successfully renamed: " + found);
        println("Missing (not found): " + missing);
        println("Ambiguous (multiple matches): " + ambiguous);
        
        // Export results to CSV
        boolean exportCsv = askYesNo("Export Results", "Export results to CSV?");
        if (exportCsv) {
            File csvFile = askFile("Save results CSV", "Save");
            if (csvFile != null) {
                exportResultsCsv(results, csvFile);
                println("Results exported to " + csvFile.getAbsolutePath());
            }
        }
    }
    
    // IMPORT with JSON output: Same as doImport but writes machine-readable JSON
    private void doImportWithJson() throws Exception {
        File sigFile = askFile("Select signature file (NDJSON)", "Open");
        if (sigFile == null || !sigFile.exists()) {
            printerr("Signature file not found.");
            return;
        }

        List<Record> records = readNdjson(sigFile);
        println("Loaded " + records.size() + " signatures");

        // Build function index
        println("Building function index...");
        Map<String, List<Function>> normIndex = indexFunctionsByNormalizedSignature();

        // Resolve and rename
        List<ResolveResult> results = new ArrayList<>();
        int found = 0, missing = 0, ambiguous = 0;

        for (int i = 0; i < records.size(); i++) {
            if (monitor.isCancelled()) break;

            Record r = records.get(i);
            String name = r.get(K_NAME);
            String nsPath = r.get(K_NS);

            monitor.setProgress(i + 1);
            monitor.setMessage("Resolving " + name);

            ResolveResult result = resolveFunction(r, normIndex);
            result.namespace = nsPath;
            result.origAddr = r.get(K_OLD);
            results.add(result);

            if (result.status == ResolveStatus.FOUND) {
                found++;
                try {
                    Namespace targetNs = createNamespaceHierarchy(nsPath);
                    Symbol funcSym = currentProgram.getSymbolTable().getPrimarySymbol(result.address);
                    if (funcSym != null) {
                        funcSym.setNameAndNamespace(name, targetNs, SourceType.USER_DEFINED);
                    }
                } catch (Exception e) {
                    printerr("Failed to rename " + name + ": " + e.getMessage());
                }
            } else if (result.status == ResolveStatus.MISSING) {
                missing++;
            } else if (result.status == ResolveStatus.AMBIGUOUS) {
                ambiguous++;
            }
        }

        // Print summary
        println("\n=== Import Summary ===");
        println("Total signatures: " + records.size());
        println("Successfully renamed: " + found);
        println("Missing (not found): " + missing);
        println("Ambiguous (multiple matches): " + ambiguous);

        // Export JSON results
        File jsonFile = askFile("Save results JSON", "Save");
        if (jsonFile != null) {
            exportResultsJson(results, jsonFile);
            println("JSON results exported to " + jsonFile.getAbsolutePath());
        }
    }

    // Export results as JSON for orchestrator consumption
    private void exportResultsJson(List<ResolveResult> results, File file) throws IOException {
        try (BufferedWriter w = new BufferedWriter(new FileWriter(file, StandardCharsets.UTF_8))) {
            w.write("{\n");
            w.write("  \"total\": " + results.size() + ",\n");

            int found = 0, miss = 0, ambig = 0;
            for (ResolveResult r : results) {
                if (r.status == ResolveStatus.FOUND) found++;
                else if (r.status == ResolveStatus.MISSING) miss++;
                else ambig++;
            }

            w.write("  \"found\": " + found + ",\n");
            w.write("  \"missing\": " + miss + ",\n");
            w.write("  \"ambiguous\": " + ambig + ",\n");
            w.write("  \"results\": [\n");

            for (int i = 0; i < results.size(); i++) {
                ResolveResult r = results.get(i);
                w.write("    {");
                w.write("\"name\": \"" + escJson(r.name) + "\"");
                w.write(", \"namespace\": \"" + escJson(r.namespace != null ? r.namespace : "") + "\"");
                w.write(", \"status\": \"" + r.status + "\"");
                w.write(", \"address\": " + (r.address != null ? "\"0x" + r.address.toString() + "\"" : "null"));
                w.write(", \"orig_addr\": " + (r.origAddr != null ? "\"" + r.origAddr + "\"" : "null"));
                w.write(", \"note\": " + (r.note != null ? "\"" + escJson(r.note) + "\"" : "null"));
                w.write("}");
                if (i < results.size() - 1) w.write(",");
                w.write("\n");
            }

            w.write("  ]\n");
            w.write("}\n");
        }
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    // Create namespace hierarchy (e.g., "jag::math" creates jag and jag::math)
    private Namespace createNamespaceHierarchy(String path) throws Exception {
        if (path == null || path.isEmpty()) return currentProgram.getGlobalNamespace();
        
        String[] parts = path.split("::");
        Namespace parent = currentProgram.getGlobalNamespace();
        SymbolTable symTable = currentProgram.getSymbolTable();
        
        for (String part : parts) {
            Namespace existing = symTable.getNamespace(part, parent);
            if (existing == null) {
                existing = symTable.createNameSpace(parent, part, SourceType.USER_DEFINED);
            }
            parent = existing;
        }
        
        return parent;
    }
    
    // Build index of all functions by normalized signature
    private Map<String, List<Function>> indexFunctionsByNormalizedSignature() {
        Map<String, List<Function>> index = new HashMap<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        
        int count = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            
            FuncSig sig = buildFunctionSignature(f);
            if (sig == null) continue;
            
            index.computeIfAbsent(sig.normSig, k -> new ArrayList<>()).add(f);
            count++;
            
            if (count % 500 == 0) {
                println("Indexed " + count + " functions (unique sigs: " + index.size() + ")");
            }
        }
        
        println("Indexed " + count + " functions with " + index.size() + " unique signatures");
        return index;
    }
    
    // Resolve a function record to an address
    private ResolveResult resolveFunction(Record rec, Map<String, List<Function>> normIndex) {
        String name = rec.get(K_NAME);
        String norm = rec.get(K_FNS);
        String blobHex = rec.get(K_BLOB);
        String maskHex = rec.get(K_MASK);
        
        if (norm == null || blobHex == null || maskHex == null) {
            return new ResolveResult(name, ResolveStatus.MISSING, null, "Malformed signature");
        }
        
        byte[] blob = fromHex(blobHex);
        byte[] mask = fromHex(maskHex);
        
        List<Function> candidates = normIndex.getOrDefault(norm, Collections.emptyList());
        if (candidates.isEmpty()) {
            return new ResolveResult(name, ResolveStatus.MISSING, null, "No matching signature");
        }
        
        // Find exact match
        List<Function> matches = new ArrayList<>();
        for (Function f : candidates) {
            byte[] funcBytes = readFunctionBytes(f, blob.length);
            if (funcBytes == null) continue;
            
            int mismatch = maskedHamming(blob, mask, funcBytes);
            if (mismatch <= VERIFY_MAX_MISMATCH) {
                matches.add(f);
            }
        }
        
        if (matches.isEmpty()) {
            return new ResolveResult(name, ResolveStatus.MISSING, null, 
                                   "Signature found but verification failed");
        } else if (matches.size() == 1) {
            return new ResolveResult(name, ResolveStatus.FOUND, 
                                   matches.get(0).getEntryPoint(), null);
        } else {
            return new ResolveResult(name, ResolveStatus.AMBIGUOUS, null, 
                                   matches.size() + " matches found");
        }
    }
    
    // Function signature structure
    private static class FuncSig {
        String normSig;
        int insnCount;
        byte[] blob;
        byte[] mask;
    }
    
    // Build signature for a function
    private FuncSig buildFunctionSignature(Function f) {
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionAt(f.getEntryPoint());
        if (insn == null) return null;
        
        List<Instruction> instructions = new ArrayList<>();
        int count = 0;
        
        while (insn != null && f.getBody().contains(insn.getAddress()) && count < FUNC_MAX_INSNS) {
            instructions.add(insn);
            insn = insn.getNext();
            count++;
        }
        
        if (instructions.isEmpty()) return null;
        
        // Build normalized signature
        String norm = buildNormalizedSignature(instructions);
        
        // Build byte blob and mask
        ByteArrayOutputStream blobStream = new ByteArrayOutputStream();
        ByteArrayOutputStream maskStream = new ByteArrayOutputStream();
        
        for (Instruction i : instructions) {
            byte[] bytes;
            try {
                bytes = i.getBytes();
            } catch (MemoryAccessException e) {
                continue;
            }
            
            byte[] mask = new byte[bytes.length];
            Arrays.fill(mask, (byte)0xFF);
            
            // Mask out operands that may change (addresses, large immediates)
            if (hasRelocatableOperand(i) && bytes.length >= 2) {
                for (int k = 2; k < mask.length; k++) {
                    mask[k] = 0x00;
                }
            }
            
            blobStream.write(bytes, 0, bytes.length);
            maskStream.write(mask, 0, mask.length);
        }
        
        FuncSig sig = new FuncSig();
        sig.normSig = norm;
        sig.insnCount = instructions.size();
        sig.blob = blobStream.toByteArray();
        sig.mask = maskStream.toByteArray();
        
        return sig;
    }
    
    // Build normalized signature string
    private String buildNormalizedSignature(List<Instruction> instructions) {
        StringBuilder sb = new StringBuilder();
        for (Instruction i : instructions) {
            sb.append(i.getMnemonicString());
            sb.append('(');
            int numOps = i.getNumOperands();
            for (int op = 0; op < numOps; op++) {
                sb.append(getOperandShape(i.getOpObjects(op)));
                if (op + 1 < numOps) sb.append(',');
            }
            sb.append(");");
        }
        return sb.toString();
    }
    
    // Get operand shape for normalization
    private String getOperandShape(Object[] opObjects) {
        if (opObjects == null || opObjects.length == 0) return "∅";
        
        boolean hasAddr = false, hasReg = false, hasImm = false;
        for (Object o : opObjects) {
            if (o instanceof Address) hasAddr = true;
            else if (o instanceof ghidra.program.model.lang.Register) hasReg = true;
            else if (o instanceof ghidra.program.model.scalar.Scalar) hasImm = true;
        }
        
        if (hasAddr) return "ADDR";
        if (hasImm && !hasReg) return "IMM";
        if (hasReg && !hasImm) return "REG";
        if (hasImm && hasReg) return "REGIMM";
        return "X";
    }
    
    // Check if instruction has relocatable operands
    private boolean hasRelocatableOperand(Instruction i) {
        int numOps = i.getNumOperands();
        for (int op = 0; op < numOps; op++) {
            Object[] objs = i.getOpObjects(op);
            if (objs == null) continue;
            for (Object o : objs) {
                if (o instanceof Address) return true;
                if (o instanceof ghidra.program.model.scalar.Scalar) {
                    ghidra.program.model.scalar.Scalar s = (ghidra.program.model.scalar.Scalar) o;
                    if (s.getUnsignedValue() > 0xFFFF) return true;
                }
            }
        }
        return false;
    }
    
    // Read bytes from function
    private byte[] readFunctionBytes(Function f, int maxBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionAt(f.getEntryPoint());
        
        while (insn != null && f.getBody().contains(insn.getAddress()) && out.size() < maxBytes) {
            try {
                byte[] bytes = insn.getBytes();
                out.write(bytes, 0, bytes.length);
            } catch (MemoryAccessException e) {
                // Skip
            }
            insn = insn.getNext();
        }
        
        byte[] result = out.toByteArray();
        if (result.length < maxBytes) {
            result = Arrays.copyOf(result, maxBytes);
        }
        return result;
    }
    
    // Calculate masked Hamming distance
    private int maskedHamming(byte[] pattern, byte[] mask, byte[] target) {
        int mismatches = 0;
        int len = Math.min(pattern.length, Math.min(mask.length, target.length));
        
        for (int i = 0; i < len; i++) {
            if ((mask[i] & 0xFF) == 0) continue; // Skip masked bytes
            if ((pattern[i] & 0xFF) != (target[i] & 0xFF)) {
                mismatches++;
            }
        }
        
        return mismatches + Math.max(0, pattern.length - len);
    }
    
    // Result tracking
    private enum ResolveStatus { FOUND, MISSING, AMBIGUOUS }
    
    private static class ResolveResult {
        String name;
        String namespace;
        String origAddr;
        ResolveStatus status;
        Address address;
        String note;

        ResolveResult(String name, ResolveStatus status, Address address, String note) {
            this.name = name;
            this.status = status;
            this.address = address;
            this.note = note;
        }
    }
    
    // Export results to CSV
    private void exportResultsCsv(List<ResolveResult> results, File file) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write("Name,Status,Address,Note\n");
            for (ResolveResult r : results) {
                writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\"\n",
                    r.name,
                    r.status,
                    r.address != null ? "0x" + r.address.toString() : "",
                    r.note != null ? r.note : ""));
            }
        }
    }
    
    // NDJSON Record class
    private static class Record {
        private final LinkedHashMap<String, String> kv = new LinkedHashMap<>();
        
        void put(String k, String v) {
            if (v != null) kv.put(k, v);
        }
        
        String get(String k) {
            return kv.get(k);
        }
        
        String encode() {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Map.Entry<String, String> e : kv.entrySet()) {
                if (!first) sb.append('\t');
                first = false;
                sb.append(escape(e.getKey())).append('=').append(escape(e.getValue()));
            }
            return sb.toString();
        }
        
        static Record decode(String line) {
            Record r = new Record();
            String[] parts = line.split("\t");
            for (String p : parts) {
                int i = p.indexOf('=');
                if (i <= 0) continue;
                String k = unescape(p.substring(0, i));
                String v = unescape(p.substring(i + 1));
                r.put(k, v);
            }
            return r;
        }
        
        private static String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\")
                   .replace("\t", "\\t")
                   .replace("\n", "\\n")
                   .replace("=", "\\e");
        }
        
        private static String unescape(String s) {
            StringBuilder out = new StringBuilder();
            boolean esc = false;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (!esc) {
                    if (c == '\\') esc = true;
                    else out.append(c);
                } else {
                    switch (c) {
                        case 't': out.append('\t'); break;
                        case 'n': out.append('\n'); break;
                        case 'e': out.append('='); break;
                        case '\\': out.append('\\'); break;
                        default: out.append(c); break;
                    }
                    esc = false;
                }
            }
            return out.toString();
        }
    }
    
    // NDJSON I/O
    private void writeNdjson(File f, List<Record> records) throws IOException {
        try (BufferedWriter w = new BufferedWriter(new FileWriter(f, StandardCharsets.UTF_8))) {
            for (Record r : records) {
                w.write(r.encode());
                w.newLine();
            }
        }
    }
    
    private List<Record> readNdjson(File f) throws IOException {
        List<Record> records = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                records.add(Record.decode(line));
            }
        }
        return records;
    }
    
    // Utility functions
    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    
    private byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }
    
    private String sha256(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return toHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
    }
}