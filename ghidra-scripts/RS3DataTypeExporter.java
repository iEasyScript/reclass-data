// SPDX-License-Identifier: MIT
// @category Analysis
// RS3DataTypeExporter.java
//
// Exports all custom data types from /jag and /jag/* categories to portable JSON.
// Includes structs (with fields), enums (with values), and unions.
// Detects binary version from RS2Engine string.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class RS3DataTypeExporter extends GhidraScript {

    // Compiler- and loader-generated type archives. Everything else is exported: a whitelist of
    // categories silently drops every struct filed anywhere else, which is how hand-built types
    // (PacketCore, OutboundPacket, ...) went missing from the migration entirely.
    private static final String[] EXCLUDED_CATEGORY_PREFIXES = {
        "/DWARF", "/demangler", "/std", "/__gnu_cxx", "/__cxxabiv1", "/ELF", "/bits", "/sys",
    };
    private static final Pattern VERSION_PATTERN = Pattern.compile("RS2Engine-(\\d+)-NXT-(\\d+)");

    private boolean excludedCategory(String path) {
        for (String p : EXCLUDED_CATEGORY_PREFIXES) if (path.equals(p) || path.startsWith(p + "/")) return true;
        // The ELF loader recreates its header-derived archives (/ssl.h, /x509.h, ...) in every program,
        // so re-importing them is churn; only hand-authored categories carry migration value.
        int slash = path.indexOf('/', 1);
        String top = slash < 0 ? path : path.substring(0, slash);
        return top.endsWith(".h");
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program first.");
            return;
        }

        String version = detectVersion();
        if (version == null) {
            version = askString("Version", "Could not auto-detect version. Enter manually (e.g., 946-3):");
            if (version == null || version.isBlank()) {
                printerr("Version is required.");
                return;
            }
        }
        println("Detected version: " + version);

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        List<Map<String, Object>> structs = new ArrayList<>();
        List<Map<String, Object>> enums = new ArrayList<>();
        List<Map<String, Object>> unions = new ArrayList<>();

        // Census first: an export can only be trusted against the total it had to choose from.
        int availStruct = 0, availEnum = 0, availUnion = 0, skipped = 0;
        Map<String, Integer> byCategory = new TreeMap<>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            DataType dt = all.next();
            if (!(dt instanceof Structure || dt instanceof Union || dt instanceof ghidra.program.model.data.Enum)) continue;
            String path = dt.getCategoryPath().getPath();
            if (excludedCategory(path)) { skipped++; continue; }
            if (dt instanceof Structure) availStruct++;
            else if (dt instanceof Union) availUnion++;
            else availEnum++;
            byCategory.merge(path, 1, Integer::sum);
        }
        println("DB census (excluding compiler/loader archives): " + availStruct + " structs, "
                + availEnum + " enums, " + availUnion + " unions across " + byCategory.size()
                + " categories (" + skipped + " skipped as generated)");
        for (Map.Entry<String, Integer> e : byCategory.entrySet()) println("   category " + e.getKey() + " -> " + e.getValue());

        Set<String> visitedCategories = new HashSet<>();
        collectAllCategories(dtm.getRootCategory(), structs, enums, unions, visitedCategories);

        int got = structs.size() + enums.size() + unions.size();
        int avail = availStruct + availEnum + availUnion;
        println("exported " + got + " of " + avail + " available composites"
                + (got < avail ? "  *** SHORTFALL " + (avail - got) + " ***" : ""));
        println("Found " + structs.size() + " structs, " + enums.size() + " enums, " + unions.size() + " unions");

        if (structs.isEmpty() && enums.isEmpty() && unions.isEmpty()) {
            printerr("No data types found in target categories.");
            return;
        }

        // Build output JSON
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"version\": ").append(jsonStr(version)).append(",\n");
        json.append("  \"exported_from\": ").append(jsonStr(currentProgram.getName())).append(",\n");
        json.append("  \"export_date\": ").append(jsonStr(new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new Date()))).append(",\n");

        // Structs
        json.append("  \"structs\": [\n");
        for (int i = 0; i < structs.size(); i++) {
            json.append(mapToJson(structs.get(i), 4));
            if (i < structs.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");

        // Enums
        json.append("  \"enums\": [\n");
        for (int i = 0; i < enums.size(); i++) {
            json.append(mapToJson(enums.get(i), 4));
            if (i < enums.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");

        // Unions
        json.append("  \"unions\": [\n");
        for (int i = 0; i < unions.size(); i++) {
            json.append(mapToJson(unions.get(i), 4));
            if (i < unions.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ]\n");
        json.append("}\n");

        // Write output
        File outDir = new File(getSourceFile().getFile(false).getParentFile().getParentFile(), "sigs-results");
        if (!outDir.exists()) outDir.mkdirs();
        File outFile = new File(outDir, "datatypes_" + version + ".json");

        // A script arg names the output directly; asking would abort the run under analyzeHeadless.
        String[] args = getScriptArgs();
        if (args.length > 0) {
            outFile = new File(args[0]);
            if (outFile.getParentFile() != null) outFile.getParentFile().mkdirs();
        } else if (!askYesNo("Output File", "Save to " + outFile.getAbsolutePath() + "?")) {
            outFile = askFile("Save data types JSON", "Save");
            if (outFile == null) return;
        }

        try (BufferedWriter w = new BufferedWriter(new FileWriter(outFile, StandardCharsets.UTF_8))) {
            w.write(json.toString());
        }

        println("Exported " + structs.size() + " structs, " + enums.size() + " enums, " + unions.size() + " unions to " + outFile.getAbsolutePath());
    }

    private void collectAllCategories(Category cat, List<Map<String, Object>> structs,
                                      List<Map<String, Object>> enums, List<Map<String, Object>> unions,
                                      Set<String> visited) {
        if (excludedCategory(cat.getCategoryPath().getPath())) return;
        collectFromCategory(cat, structs, enums, unions, visited);
    }

    private void collectFromCategory(Category cat, List<Map<String, Object>> structs,
                                     List<Map<String, Object>> enums, List<Map<String, Object>> unions,
                                     Set<String> visited) {
        String path = cat.getCategoryPath().getPath();
        if (visited.contains(path)) return;
        visited.add(path);

        println("Scanning category: " + path);

        for (DataType dt : cat.getDataTypes()) {
            if (dt instanceof Structure s) {
                structs.add(exportStruct(s));
            } else if (dt instanceof ghidra.program.model.data.Enum e) {
                enums.add(exportEnum(e));
            } else if (dt instanceof Union u) {
                unions.add(exportUnion(u));
            }
        }

        // Recurse into subcategories
        for (Category child : cat.getCategories()) {
            if (excludedCategory(child.getCategoryPath().getPath())) continue;
            collectFromCategory(child, structs, enums, unions, visited);
        }
    }

    private Map<String, Object> exportStruct(Structure s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", s.getName());
        m.put("category", s.getCategoryPath().getPath());
        m.put("size", s.getLength());
        m.put("description", s.getDescription() != null ? s.getDescription() : "");

        List<Map<String, Object>> fields = new ArrayList<>();
        for (DataTypeComponent comp : s.getDefinedComponents()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("offset", comp.getOffset());
            f.put("type", comp.getDataType().getDisplayName());
            f.put("name", comp.getFieldName() != null ? comp.getFieldName() : "");
            f.put("length", comp.getLength());
            f.put("comment", comp.getComment() != null ? comp.getComment() : "");
            fields.add(f);
        }
        m.put("fields", fields);
        return m;
    }

    private Map<String, Object> exportEnum(ghidra.program.model.data.Enum e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", e.getName());
        m.put("category", e.getCategoryPath().getPath());
        m.put("size", e.getLength());
        m.put("description", e.getDescription() != null ? e.getDescription() : "");

        List<Map<String, Object>> values = new ArrayList<>();
        for (String name : e.getNames()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("name", name);
            v.put("value", e.getValue(name));
            values.add(v);
        }
        m.put("values", values);
        return m;
    }

    private Map<String, Object> exportUnion(Union u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", u.getName());
        m.put("category", u.getCategoryPath().getPath());
        m.put("size", u.getLength());
        m.put("description", u.getDescription() != null ? u.getDescription() : "");

        List<Map<String, Object>> fields = new ArrayList<>();
        for (DataTypeComponent comp : u.getDefinedComponents()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", comp.getDataType().getDisplayName());
            f.put("name", comp.getFieldName() != null ? comp.getFieldName() : "");
            f.put("length", comp.getLength());
            f.put("comment", comp.getComment() != null ? comp.getComment() : "");
            fields.add(f);
        }
        m.put("fields", fields);
        return m;
    }

    private String detectVersion() {
        try {
            Memory mem = currentProgram.getMemory();
            MemoryBlock[] blocks = mem.getBlocks();

            for (MemoryBlock block : blocks) {
                if (!block.getName().equals(".rodata") && !block.isRead()) continue;
                if (!block.isInitialized()) continue;

                long size = block.getSize();
                if (size > 100_000_000) continue; // Skip huge blocks

                byte[] data = new byte[(int) Math.min(size, 10_000_000)];
                block.getBytes(block.getStart(), data);
                String content = new String(data, StandardCharsets.US_ASCII);

                Matcher m = VERSION_PATTERN.matcher(content);
                if (m.find()) {
                    String major = m.group(1);
                    String minor = m.group(2);
                    String full = major + "-" + minor;
                    println("Found version string: RS2Engine-" + major + "-NXT-" + minor + " in " + block.getName());
                    return full;
                }
            }
        } catch (Exception e) {
            printerr("Version detection error: " + e.getMessage());
        }
        return null;
    }

    // Simple JSON serialization (no external dependencies)
    private String jsonStr(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\t", "\\t") + "\"";
    }

    private String mapToJson(Map<String, Object> map, int indent) {
        StringBuilder sb = new StringBuilder();
        String pad = " ".repeat(indent);
        String pad2 = " ".repeat(indent + 2);
        sb.append(pad).append("{\n");

        Iterator<Map.Entry<String, Object>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Object> entry = it.next();
            sb.append(pad2).append(jsonStr(entry.getKey())).append(": ");

            Object val = entry.getValue();
            if (val instanceof String s) {
                sb.append(jsonStr(s));
            } else if (val instanceof Number n) {
                sb.append(n);
            } else if (val instanceof List<?> list) {
                if (list.isEmpty()) {
                    sb.append("[]");
                } else {
                    sb.append("[\n");
                    for (int i = 0; i < list.size(); i++) {
                        Object item = list.get(i);
                        if (item instanceof Map<?, ?> m) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> castMap = (Map<String, Object>) m;
                            sb.append(mapToJson(castMap, indent + 4));
                        } else {
                            sb.append(" ".repeat(indent + 4)).append(val);
                        }
                        if (i < list.size() - 1) sb.append(",");
                        sb.append("\n");
                    }
                    sb.append(pad2).append("]");
                }
            } else {
                sb.append(String.valueOf(val));
            }

            if (it.hasNext()) sb.append(",");
            sb.append("\n");
        }

        sb.append(pad).append("}");
        return sb.toString();
    }
}
