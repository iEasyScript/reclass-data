// SPDX-License-Identifier: MIT
// @category Analysis
// RS3DataTypeImporter.java
//
// Imports a datatypes_{version}.json into a new Ghidra project.
// Creates structs with all fields, enums with all values, and unions.
// Optionally accepts an offset delta map for structs that changed.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class RS3DataTypeImporter extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program first.");
            return;
        }

        // Script args make this runnable under analyzeHeadless: <datatypes.json> [deltas.json].
        // askFile blocks forever without a GUI, so headless is the only mode that needs the args.
        String[] args = getScriptArgs();
        File jsonFile = (args.length > 0) ? new File(args[0]) : askFile("Select data types JSON file", "Open");
        if (jsonFile == null || !jsonFile.exists()) {
            printerr("File not found: " + jsonFile);
            return;
        }

        String content = readFile(jsonFile);
        Map<String, Object> root = parseJson(content);

        String version = (String) root.get("version");
        println("Importing data types from version: " + version);

        File deltaFile = (args.length > 1) ? new File(args[1]) : null;
        Map<String, Map<Integer, Integer>> deltaMap = new HashMap<>();
        if (deltaFile == null && args.length == 0
                && askYesNo("Offset Deltas", "Load an offset delta map for adjusted struct fields?")) {
            deltaFile = askFile("Select offset delta JSON", "Open");
        }
        if (deltaFile != null && deltaFile.exists()) {
            deltaMap = parseDeltaMap(readFile(deltaFile));
            println("Loaded delta map with " + deltaMap.size() + " struct adjustments");
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int txId = dtm.startTransaction("Import Data Types from " + version);
        try {
            int structCount = 0, enumCount = 0, unionCount = 0;
            int structFail = 0, enumFail = 0, unionFail = 0;

            // Import structs
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> structs = (List<Map<String, Object>>) root.getOrDefault("structs", Collections.emptyList());
            for (Map<String, Object> s : structs) {
                try {
                    importStruct(dtm, s, deltaMap);
                    structCount++;
                } catch (Exception e) {
                    printerr("Failed to import struct " + s.get("name") + ": " + e.getMessage());
                    structFail++;
                }
            }

            // Import enums
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> enums = (List<Map<String, Object>>) root.getOrDefault("enums", Collections.emptyList());
            for (Map<String, Object> e : enums) {
                try {
                    importEnum(dtm, e);
                    enumCount++;
                } catch (Exception ex) {
                    printerr("Failed to import enum " + e.get("name") + ": " + ex.getMessage());
                    enumFail++;
                }
            }

            // Import unions
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> unions = (List<Map<String, Object>>) root.getOrDefault("unions", Collections.emptyList());
            for (Map<String, Object> u : unions) {
                try {
                    importUnion(dtm, u);
                    unionCount++;
                } catch (Exception ex) {
                    printerr("Failed to import union " + u.get("name") + ": " + ex.getMessage());
                    unionFail++;
                }
            }

            dtm.endTransaction(txId, true);

            println("\n=== Import Summary ===");
            println("Structs: " + structCount + " imported" + (structFail > 0 ? ", " + structFail + " failed" : ""));
            println("Enums:   " + enumCount + " imported" + (enumFail > 0 ? ", " + enumFail + " failed" : ""));
            println("Unions:  " + unionCount + " imported" + (unionFail > 0 ? ", " + unionFail + " failed" : ""));
        } catch (Exception e) {
            dtm.endTransaction(txId, false);
            throw e;
        }
    }

    private void importStruct(DataTypeManager dtm, Map<String, Object> s, Map<String, Map<Integer, Integer>> deltaMap) throws Exception {
        String name = (String) s.get("name");
        String category = (String) s.get("category");
        int size = toInt(s.get("size"));
        String desc = (String) s.getOrDefault("description", "");

        CategoryPath catPath = new CategoryPath(category);
        if (dtm.getCategory(catPath) == null) {
            dtm.createCategory(catPath);
        }

        // Check for existing struct
        DataType existing = dtm.getDataType(catPath, name);
        if (existing != null) {
            println("Struct " + name + " already exists, replacing...");
            dtm.remove(existing, monitor);
        }

        StructureDataType struct = new StructureDataType(catPath, name, size, dtm);
        if (desc != null && !desc.isEmpty()) {
            struct.setDescription(desc);
        }

        // Get field deltas for this struct if any
        Map<Integer, Integer> fieldDeltas = deltaMap.getOrDefault(name, Collections.emptyMap());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) s.getOrDefault("fields", Collections.emptyList());
        for (Map<String, Object> f : fields) {
            int offset = toInt(f.get("offset"));
            String typeName = (String) f.get("type");
            String fieldName = (String) f.get("name");
            int length = toInt(f.get("length"));
            String comment = (String) f.getOrDefault("comment", "");

            // Apply delta if present
            if (fieldDeltas.containsKey(offset)) {
                int newOffset = fieldDeltas.get(offset);
                println("  Delta: " + name + "." + fieldName + " offset " + offset + " -> " + newOffset);
                offset = newOffset;
            }

            DataType fieldType = resolveType(dtm, typeName);
            if (fieldType == null) {
                println("  Warning: Could not resolve type '" + typeName + "' for " + name + "." + fieldName + ", using undefined");
                fieldType = Undefined.getUndefinedDataType(length);
            }

            try {
                if (offset + length <= size) {
                    struct.replaceAtOffset(offset, fieldType, length, fieldName,
                            comment != null && !comment.isEmpty() ? comment : null);
                } else {
                    printerr("  Field " + fieldName + " at offset " + offset + " + length " + length + " exceeds struct size " + size);
                }
            } catch (Exception e) {
                printerr("  Failed to add field " + fieldName + " at offset " + offset + ": " + e.getMessage());
            }
        }

        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
        println("Imported struct: " + name + " (" + size + " bytes, " + fields.size() + " fields) in " + category);
    }

    private void importEnum(DataTypeManager dtm, Map<String, Object> e) throws Exception {
        String name = (String) e.get("name");
        String category = (String) e.get("category");
        int size = toInt(e.get("size"));
        String desc = (String) e.getOrDefault("description", "");

        CategoryPath catPath = new CategoryPath(category);
        if (dtm.getCategory(catPath) == null) {
            dtm.createCategory(catPath);
        }

        DataType existing = dtm.getDataType(catPath, name);
        if (existing != null) {
            println("Enum " + name + " already exists, replacing...");
            dtm.remove(existing, monitor);
        }

        EnumDataType enumDt = new EnumDataType(catPath, name, size, dtm);
        if (desc != null && !desc.isEmpty()) {
            enumDt.setDescription(desc);
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> values = (List<Map<String, Object>>) e.getOrDefault("values", Collections.emptyList());
        for (Map<String, Object> v : values) {
            String vName = (String) v.get("name");
            long vValue = toLong(v.get("value"));
            enumDt.add(vName, vValue);
        }

        dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
        println("Imported enum: " + name + " (" + size + " bytes, " + values.size() + " values) in " + category);
    }

    private void importUnion(DataTypeManager dtm, Map<String, Object> u) throws Exception {
        String name = (String) u.get("name");
        String category = (String) u.get("category");
        String desc = (String) u.getOrDefault("description", "");

        CategoryPath catPath = new CategoryPath(category);
        if (dtm.getCategory(catPath) == null) {
            dtm.createCategory(catPath);
        }

        DataType existing = dtm.getDataType(catPath, name);
        if (existing != null) {
            println("Union " + name + " already exists, replacing...");
            dtm.remove(existing, monitor);
        }

        UnionDataType union = new UnionDataType(catPath, name, dtm);
        if (desc != null && !desc.isEmpty()) {
            union.setDescription(desc);
        }

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> fields = (List<Map<String, Object>>) u.getOrDefault("fields", Collections.emptyList());
        for (Map<String, Object> f : fields) {
            String typeName = (String) f.get("type");
            String fieldName = (String) f.get("name");
            int length = toInt(f.get("length"));
            String comment = (String) f.getOrDefault("comment", "");

            DataType fieldType = resolveType(dtm, typeName);
            if (fieldType == null) {
                fieldType = Undefined.getUndefinedDataType(length);
            }

            union.add(fieldType, length, fieldName, comment != null && !comment.isEmpty() ? comment : null);
        }

        dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
        println("Imported union: " + name + " (" + fields.size() + " fields) in " + category);
    }

    private DataType resolveType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isEmpty()) return null;

        // Handle pointer types
        if (typeName.endsWith(" *") || typeName.endsWith("*")) {
            String baseName = typeName.replace("*", "").strip();
            DataType baseType = resolveType(dtm, baseName);
            if (baseType != null) {
                return new PointerDataType(baseType, dtm);
            }
            // Fallback to void*
            return new PointerDataType(dtm);
        }

        // Built-in types
        DataType builtIn = resolveBuiltIn(typeName);
        if (builtIn != null) return builtIn;

        // Search DTM by name (all categories)
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(typeName, found);
        if (!found.isEmpty()) return found.get(0);

        // Search BuiltInDataTypeManager
        List<DataType> builtInSearch = new ArrayList<>();
        BuiltInDataTypeManager.getDataTypeManager().findDataTypes(typeName, builtInSearch);
        if (!builtInSearch.isEmpty()) return builtInSearch.get(0);

        return null;
    }

    private DataType resolveBuiltIn(String name) {
        return switch (name.toLowerCase()) {
            case "int", "int32" -> IntegerDataType.dataType;
            case "uint", "uint32", "unsigned int" -> UnsignedIntegerDataType.dataType;
            case "short", "int16" -> ShortDataType.dataType;
            case "ushort", "uint16", "unsigned short" -> UnsignedShortDataType.dataType;
            case "long", "int64", "long long", "longlong" -> LongLongDataType.dataType;
            case "ulong", "uint64", "unsigned long long", "ulonglong" -> UnsignedLongLongDataType.dataType;
            case "byte", "int8" -> ByteDataType.dataType;
            case "ubyte", "uint8", "unsigned byte" -> UnsignedCharDataType.dataType;
            case "char" -> CharDataType.dataType;
            case "bool" -> BooleanDataType.dataType;
            case "float" -> FloatDataType.dataType;
            case "double" -> DoubleDataType.dataType;
            case "void" -> VoidDataType.dataType;
            case "pointer", "addr" -> new PointerDataType();
            case "word" -> WordDataType.dataType;
            case "dword" -> DWordDataType.dataType;
            case "qword" -> QWordDataType.dataType;
            case "undefined", "undefined1" -> Undefined1DataType.dataType;
            case "undefined2" -> Undefined2DataType.dataType;
            case "undefined4" -> Undefined4DataType.dataType;
            case "undefined8" -> Undefined8DataType.dataType;
            default -> null;
        };
    }

    // Minimal JSON parser (no external dependencies)
    // Handles the exact format produced by RS3DataTypeExporter

    private String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJson(String json) {
        return (Map<String, Object>) new JsonParser(json).parseValue();
    }

    private Map<String, Map<Integer, Integer>> parseDeltaMap(String json) {
        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) new JsonParser(json).parseValue();
        Map<String, Map<Integer, Integer>> result = new HashMap<>();

        for (Map.Entry<String, Object> entry : root.entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> innerMap = (Map<String, Object>) entry.getValue();
            Map<Integer, Integer> deltas = new HashMap<>();
            for (Map.Entry<String, Object> delta : innerMap.entrySet()) {
                deltas.put(Integer.parseInt(delta.getKey()), toInt(delta.getValue()));
            }
            result.put(entry.getKey(), deltas);
        }

        return result;
    }

    private int toInt(Object o) {
        if (o instanceof Number n) return n.intValue();
        if (o instanceof String s) return Integer.parseInt(s);
        return 0;
    }

    private long toLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        if (o instanceof String s) return Long.parseLong(s);
        return 0;
    }

    // Minimal recursive-descent JSON parser
    private static class JsonParser {
        private final String input;
        private int pos;

        JsonParser(String input) {
            this.input = input;
            this.pos = 0;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= input.length()) return null;
            char c = input.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') return parseNull();
            return parseNumber();
        }

        Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (peek() == ',') { pos++; }
                else break;
            }
            skipWhitespace();
            expect('}');
            return map;
        }

        List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                if (peek() == ',') { pos++; }
                else break;
            }
            skipWhitespace();
            expect(']');
            return list;
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < input.length()) {
                char c = input.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    c = input.charAt(pos++);
                    switch (c) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        case 'r': sb.append('\r'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u':
                            String hex = input.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default: sb.append(c);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Number parseNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < input.length() && input.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++;
            }
            if (pos < input.length() && (input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < input.length() && (input.charAt(pos) == '+' || input.charAt(pos) == '-')) pos++;
                while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++;
            }
            String numStr = input.substring(start, pos);
            if (isFloat) return Double.parseDouble(numStr);
            long val = Long.parseLong(numStr);
            if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) return (int) val;
            return val;
        }

        Boolean parseBoolean() {
            if (input.startsWith("true", pos)) { pos += 4; return true; }
            if (input.startsWith("false", pos)) { pos += 5; return false; }
            throw new RuntimeException("Expected boolean at pos " + pos);
        }

        Object parseNull() {
            if (input.startsWith("null", pos)) { pos += 4; return null; }
            throw new RuntimeException("Expected null at pos " + pos);
        }

        void skipWhitespace() {
            while (pos < input.length() && Character.isWhitespace(input.charAt(pos))) pos++;
        }

        char peek() {
            return pos < input.length() ? input.charAt(pos) : 0;
        }

        void expect(char c) {
            skipWhitespace();
            if (pos >= input.length() || input.charAt(pos) != c) {
                throw new RuntimeException("Expected '" + c + "' at pos " + pos + " but got '" + (pos < input.length() ? input.charAt(pos) : "EOF") + "'");
            }
            pos++;
        }
    }
}
