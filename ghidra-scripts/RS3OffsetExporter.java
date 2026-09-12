// SPDX-License-Identifier: MIT
// @category Analysis
// RS3OffsetExporter.java
//
// Extracts all offset values needed for Offsets.kt from a Ghidra project.
// After RS3SignatureUpdater has imported function names, this script:
//   1. Detects binary version from RS2Engine string
//   2. Extracts OFunctions addresses from named symbols
//   3. Discovers OGlobal.CLIENT via caller analysis
//   4. Discovers OClient field offsets via anchor functions and constructor analysis
//
// Output: JSON file with offset values, confidence levels, and discovery sources.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class RS3OffsetExporter extends GhidraScript {

    private static final Pattern VERSION_PATTERN = Pattern.compile("RS2Engine-(\\d+)-NXT-(\\d+)");

    // OFunctions: maps Offsets.kt constant name -> Ghidra fully-qualified function name
    private static final LinkedHashMap<String, String> OFUNCTIONS_MAP = new LinkedHashMap<>();
    static {
        OFUNCTIONS_MAP.put("CONNECTIONMANAGER_TCPIN", "jag::ConnectionManager::TcpIn");
        OFUNCTIONS_MAP.put("CLIENT_SETMAINSTATE", "jag::Client::SetMainState");
        OFUNCTIONS_MAP.put("STATTABLE_UPDATESTAT", "jag::StatTable::UpdateStat");
        OFUNCTIONS_MAP.put("CLIENT_MAINLOGIC", "jag::Client::MainLogic");
        OFUNCTIONS_MAP.put("SERVERPROT_DECODE_UPDATE_INV_PARTIAL", "jag::ServerProt::decode::UPDATE_INV_PARTIAL");
        OFUNCTIONS_MAP.put("SERVERPROT_DECODE_UPDATE_INV_FULL", "jag::ServerProt::decode::UPDATE_INV_FULL");
        OFUNCTIONS_MAP.put("CHATHISTORY_ADDCHAT_HOOKABLE", "jag::ChatHistory::AddChat_hookable");
        OFUNCTIONS_MAP.put("PLAYERVARDOMAIN_SET", "jag::PlayerVarDomain::set");
        OFUNCTIONS_MAP.put("PLAYERVARDOMAIN_SETBIT", "jag::PlayerVarDomain::setBit");
        OFUNCTIONS_MAP.put("CLIENTVARDOMAIN_SETVARVALUE", "jag::ClientVarDomain::SetVarValue");
        OFUNCTIONS_MAP.put("MINIMENU_DOACTIONENTRY", "jag::MiniMenu::DoActionEntry");
        OFUNCTIONS_MAP.put("INTERFACEMANAGER_IFBUTTONXINNER", "jag::InterfaceManager::IfButtonXInner");
        OFUNCTIONS_MAP.put("PROJECTILELIST_ADD", "jag::ProjectileList::Add");
        OFUNCTIONS_MAP.put("ENTITY_ENTITY", "jag::game::Entity::Entity");
        OFUNCTIONS_MAP.put("ENTITY_ENTITY_DESTRUCT", "jag::game::Entity::~Entity");
        OFUNCTIONS_MAP.put("INVENTORYMANAGER_GETINVENTORY", "jag::InventoryManager::GetInventory");
        OFUNCTIONS_MAP.put("HITMARKSANDHEADBARS_ADDHEADBAR", "jag::HitmarksAndHeadbars::AddHeadbar");
        OFUNCTIONS_MAP.put("HITMARKSANDHEADBARS_ADDHITMARK", "jag::HitmarksAndHeadbars::AddHitmark");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONKEYDOWNINNER", "jag::input::Input::OnKeyDownInner");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONKEYUPINNER", "jag::input::Input::OnKeyUpInner");
        OFUNCTIONS_MAP.put("SCRIPTRUNNER_EXECUTEHOOKINNER", "jag::ScriptRunner::ExecuteHookInner");
        OFUNCTIONS_MAP.put("SCRIPTRUNNER_EXECUTESCRIPT", "jag::ScriptRunner::ExecuteScript");
        OFUNCTIONS_MAP.put("SCRIPTRUNNER_GETCLIENTSCRIPTSTATE", "jag::ScriptRunner::GetClientScriptState");
        OFUNCTIONS_MAP.put("SCRIPTRUNNER_CONTINUESCRIPT", "jag::ScriptRunner::ContinueScript");
        OFUNCTIONS_MAP.put("SCRIPTRUNNER_GET_BY_ID", "jag::ScriptRunner::GetById");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONMOUSEMOTION", "jag::input::Input::OnMouseMotion");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONLEFTBUTTONDOWN", "jag::input::Input::OnLeftButtonDown");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONLEFTBUTTONUP", "jag::input::Input::OnLeftButtonUp");
        OFUNCTIONS_MAP.put("INPUT_INPUT_ONSCROLLWHEEL", "jag::input::Input::OnScrollWheel");
        OFUNCTIONS_MAP.put("INPUT_INPUT_INJECTSYNTHETICRIGHTCLICK", "jag::input::Input::InjectSyntheticRightClick");
        OFUNCTIONS_MAP.put("TCPCONNECTIONMESSAGE_INIT", "jag::TcpConnectionMessage::Init");
        OFUNCTIONS_MAP.put("SENDCLIENTMESSAGE", "jag::SendClientMessage");
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program first.");
            return;
        }

        // Step 1: Detect version
        String version = detectVersion();
        if (version == null) {
            version = askString("Version", "Could not auto-detect version. Enter manually (e.g., 947-1):");
            if (version == null || version.isBlank()) {
                printerr("Version is required.");
                return;
            }
        }
        println("=== RS3 Offset Exporter ===");
        println("Version: " + version);

        long imageBase = currentProgram.getImageBase().getOffset();
        println("Image base: 0x" + Long.toHexString(imageBase));

        // Load anchor registry if available
        Map<String, Object> anchorRegistry = loadAnchorRegistry();

        // Results
        Map<String, OffsetResult> globalResults = new LinkedHashMap<>();
        Map<String, OffsetResult> functionResults = new LinkedHashMap<>();
        Map<String, OffsetResult> clientResults = new LinkedHashMap<>();
        List<Map<String, String>> missing = new ArrayList<>();
        List<Map<String, String>> manualReview = new ArrayList<>();

        // Step 2: Extract OFunctions
        println("\n--- OFunctions Extraction ---");
        for (Map.Entry<String, String> entry : OFUNCTIONS_MAP.entrySet()) {
            String constName = entry.getKey();
            String funcName = entry.getValue();

            Address addr = findFunctionByQualifiedName(funcName);
            if (addr != null) {
                long offset = addr.getOffset() - imageBase;
                functionResults.put(constName, new OffsetResult(
                        "0x" + String.format("%08x", offset), "HIGH", "signature match: " + funcName));
                println("[FOUND] " + constName + " = 0x" + String.format("%08x", offset) + " (" + funcName + ")");
            } else {
                functionResults.put(constName, new OffsetResult(null, "MISSING", "function not found: " + funcName));
                Map<String, String> m = new LinkedHashMap<>();
                m.put("name", "OFunctions." + constName);
                m.put("reason", "function not found: " + funcName);
                missing.add(m);
                println("[MISSING] " + constName + " - function not found: " + funcName);
            }
        }

        // Step 3: Discover OGlobal.CLIENT
        println("\n--- OGlobal.CLIENT Discovery ---");
        OffsetResult clientGlobal = discoverGlobalClient(imageBase);
        if (clientGlobal != null) {
            globalResults.put("CLIENT", clientGlobal);
            println("[FOUND] OGlobal.CLIENT = " + clientGlobal.value + " (confidence: " + clientGlobal.confidence + ")");
        } else {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("name", "OGlobal.CLIENT");
            m.put("reason", "could not discover via caller analysis");
            missing.add(m);
            println("[MISSING] OGlobal.CLIENT");
        }

        // Step 4: Discover OClient field offsets
        println("\n--- OClient Field Discovery ---");
        discoverOClientOffsets(anchorRegistry, clientResults, missing, manualReview, imageBase);

        // Build output JSON
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"version\": \"").append(version).append("\",\n");
        json.append("  \"extracted_from\": \"RS2Engine-").append(version.replace("-", "-NXT-")).append("\",\n");
        json.append("  \"image_base\": \"0x").append(Long.toHexString(imageBase)).append("\",\n");

        // OGlobal
        json.append("  \"offsets\": {\n");
        json.append("    \"OGlobal\": {\n");
        appendOffsetResults(json, globalResults, 6);
        json.append("    },\n");

        // OFunctions
        json.append("    \"OFunctions\": {\n");
        appendOffsetResults(json, functionResults, 6);
        json.append("    },\n");

        // OClient
        json.append("    \"OClient\": {\n");
        appendOffsetResults(json, clientResults, 6);
        json.append("    }\n");

        json.append("  },\n");

        // Missing
        json.append("  \"missing\": [\n");
        for (int i = 0; i < missing.size(); i++) {
            Map<String, String> m = missing.get(i);
            json.append("    {\"name\": \"").append(m.get("name")).append("\", \"reason\": \"").append(escJson(m.get("reason"))).append("\"}");
            if (i < missing.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");

        // Manual review
        json.append("  \"manual_review\": [\n");
        for (int i = 0; i < manualReview.size(); i++) {
            Map<String, String> m = manualReview.get(i);
            json.append("    {");
            Iterator<Map.Entry<String, String>> it = m.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, String> e = it.next();
                json.append("\"").append(e.getKey()).append("\": \"").append(escJson(e.getValue())).append("\"");
                if (it.hasNext()) json.append(", ");
            }
            json.append("}");
            if (i < manualReview.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ]\n");
        json.append("}\n");

        // Write output
        File outDir = new File(getSourceFile().getFile(false).getParentFile().getParentFile(), "sigs-results");
        if (!outDir.exists()) outDir.mkdirs();
        File outFile = new File(outDir, "offsets_" + version + ".json");

        boolean useDefault = askYesNo("Output File", "Save to " + outFile.getAbsolutePath() + "?");
        if (!useDefault) {
            outFile = askFile("Save offsets JSON", "Save");
            if (outFile == null) return;
        }

        try (BufferedWriter w = new BufferedWriter(new FileWriter(outFile, StandardCharsets.UTF_8))) {
            w.write(json.toString());
        }

        // Summary
        int foundFuncs = (int) functionResults.values().stream().filter(r -> r.value != null).count();
        int foundClient = (int) clientResults.values().stream().filter(r -> r.value != null).count();
        println("\n=== Summary ===");
        println("OFunctions: " + foundFuncs + "/" + OFUNCTIONS_MAP.size() + " found");
        println("OGlobal.CLIENT: " + (clientGlobal != null ? "found" : "MISSING"));
        println("OClient fields: " + foundClient + " found, " + missing.stream().filter(m -> m.get("name").startsWith("OClient.")).count() + " missing");
        println("Manual review items: " + manualReview.size());
        println("Output: " + outFile.getAbsolutePath());
    }

    // --- OGlobal.CLIENT Discovery ---
    // Strategy: Find callers of SetMainState. In each caller, look for MOV reg, [rip+disp]
    // that loads the Client pointer immediately before the call.

    private OffsetResult discoverGlobalClient(long imageBase) {
        // Try multiple anchor functions that receive Client as first param
        String[] anchors = {
                "jag::Client::SetMainState",
                "jag::Client::MainLogic"
        };

        Map<Long, Integer> addressVotes = new HashMap<>();

        for (String anchor : anchors) {
            Address funcAddr = findFunctionByQualifiedName(anchor);
            if (funcAddr == null) continue;

            println("  Analyzing callers of " + anchor + " at 0x" + funcAddr.toString());

            // Find all callers
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(funcAddr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (!ref.getReferenceType().isCall()) continue;

                Address callSite = ref.getFromAddress();
                println("    Call site: 0x" + callSite.toString());

                // Scan backwards from call site looking for MOV reg, [rip+disp] (loading global ptr)
                Long globalAddr = scanForGlobalLoad(callSite, imageBase);
                if (globalAddr != null) {
                    addressVotes.merge(globalAddr, 1, Integer::sum);
                    println("    -> Global candidate: 0x" + Long.toHexString(globalAddr) + " (relative: 0x" + Long.toHexString(globalAddr - imageBase) + ")");
                }
            }
        }

        if (addressVotes.isEmpty()) return null;

        // Find consensus
        Map.Entry<Long, Integer> best = addressVotes.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .orElse(null);

        if (best == null) return null;

        long relAddr = best.getKey() - imageBase;
        String confidence = best.getValue() >= 2 ? "HIGH" : "MEDIUM";
        String source = "caller analysis (" + best.getValue() + " callers agree)";

        return new OffsetResult("0x" + Long.toHexString(relAddr), confidence, source);
    }

    // Scan backwards from a call instruction to find a global pointer load
    // Looking for patterns like:
    //   MOV RDI, qword ptr [RIP + offset]   (load Client* into first arg)
    //   CALL <target>
    private Long scanForGlobalLoad(Address callSite, long imageBase) {
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionBefore(callSite);
        int scanned = 0;

        while (insn != null && scanned < 20) {
            String mnemonic = insn.getMnemonicString();

            if (mnemonic.equals("MOV") || mnemonic.equals("LEA")) {
                // Check if this loads from a RIP-relative address (shows as absolute address operand)
                int numOps = insn.getNumOperands();
                if (numOps >= 2) {
                    Object[] srcOps = insn.getOpObjects(1);
                    for (Object op : srcOps) {
                        if (op instanceof Address addr) {
                            long absAddr = addr.getOffset();
                            // Validate: should be in a reasonable data segment range
                            if (absAddr > imageBase && absAddr < imageBase + 0x2000000) {
                                // Read the pointer value at this address to get the actual global
                                try {
                                    // This is the address of the global variable itself
                                    return absAddr;
                                } catch (Exception e) {
                                    // ignore
                                }
                            }
                        }
                    }
                }
            }

            // Stop if we hit another CALL or a label target
            if (mnemonic.equals("CALL") || mnemonic.equals("RET") || mnemonic.equals("JMP")) break;

            insn = listing.getInstructionBefore(insn.getAddress());
            scanned++;
        }

        return null;
    }

    // --- OClient Field Discovery ---

    private void discoverOClientOffsets(Map<String, Object> anchorRegistry,
                                        Map<String, OffsetResult> results,
                                        List<Map<String, String>> missing,
                                        List<Map<String, String>> manualReview,
                                        long imageBase) {
        // Strategy 1: Anchor function analysis
        if (anchorRegistry != null && !anchorRegistry.isEmpty()) {
            println("  Using anchor registry (" + anchorRegistry.size() + " entries)");
            discoverViaAnchors(anchorRegistry, results, missing, manualReview, imageBase);
        }

        // Strategy 2: Constructor analysis for manager pointers
        println("  Attempting constructor analysis for manager fields...");
        discoverViaConstructor(results, missing, manualReview, imageBase);

        // Strategy 3: Caller-chain tracing for remaining fields
        println("  Attempting caller-chain tracing for remaining fields...");
        discoverViaCallerChains(results, missing, manualReview, imageBase);
    }

    private void discoverViaAnchors(Map<String, Object> registry,
                                     Map<String, OffsetResult> results,
                                     List<Map<String, String>> missing,
                                     List<Map<String, String>> manualReview,
                                     long imageBase) {
        for (Map.Entry<String, Object> entry : registry.entrySet()) {
            String fieldName = entry.getKey();
            if (results.containsKey(fieldName) && results.get(fieldName).value != null) continue;

            @SuppressWarnings("unchecked")
            Map<String, Object> config = (Map<String, Object>) entry.getValue();
            String anchorFunc = (String) config.get("anchor");
            String pattern = (String) config.get("pattern");
            @SuppressWarnings("unchecked")
            List<Number> range = (List<Number>) config.get("range");

            Address funcAddr = findFunctionByQualifiedName(anchorFunc);
            if (funcAddr == null) {
                println("    [SKIP] " + fieldName + " - anchor " + anchorFunc + " not found");
                continue;
            }

            Function func = getFunctionAt(funcAddr);
            if (func == null) continue;

            long minRange = range != null && range.size() >= 2 ? range.get(0).longValue() : 0;
            long maxRange = range != null && range.size() >= 2 ? range.get(1).longValue() : 0x20000;

            Long offset = extractDisplacementFromFunction(func, pattern, minRange, maxRange);

            if (offset != null) {
                results.put(fieldName, new OffsetResult(
                        "0x" + Long.toHexString(offset), "HIGH", "anchor: " + anchorFunc));
                println("    [FOUND] " + fieldName + " = 0x" + Long.toHexString(offset) + " via " + anchorFunc);
            } else {
                println("    [MISS] " + fieldName + " - displacement not found in " + anchorFunc);
            }
        }
    }

    private void discoverViaConstructor(Map<String, OffsetResult> results,
                                         List<Map<String, String>> missing,
                                         List<Map<String, String>> manualReview,
                                         long imageBase) {
        // Look for jag::Client::Client or jag::Client::Init
        Address ctorAddr = findFunctionByQualifiedName("jag::Client::Client");
        if (ctorAddr == null) {
            ctorAddr = findFunctionByQualifiedName("jag::Client::Init");
        }
        if (ctorAddr == null) {
            println("    Client constructor/init not found, skipping constructor analysis");
            return;
        }

        Function ctor = getFunctionAt(ctorAddr);
        if (ctor == null) return;

        println("    Analyzing constructor at 0x" + ctorAddr.toString());

        // Scan instructions for MOV [base+large_disp], reg patterns
        // These are stores of manager pointers into Client struct fields
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionAt(ctor.getEntryPoint());
        int count = 0;
        List<long[]> storePatterns = new ArrayList<>(); // [offset, callTargetAddr]

        Address lastCallTarget = null;

        while (insn != null && ctor.getBody().contains(insn.getAddress()) && count < 2000) {
            String mnemonic = insn.getMnemonicString();

            if (mnemonic.equals("CALL")) {
                // Track the last call target
                Object[] ops = insn.getOpObjects(0);
                for (Object op : ops) {
                    if (op instanceof Address addr) {
                        lastCallTarget = addr;
                    }
                }
            }

            // Look for MOV [reg + large_displacement], reg
            if (mnemonic.equals("MOV")) {
                Object[] destOps = insn.getOpObjects(0);
                boolean hasReg = false;
                long displacement = -1;

                for (Object op : destOps) {
                    if (op instanceof ghidra.program.model.lang.Register) hasReg = true;
                    if (op instanceof Scalar s) {
                        long val = s.getUnsignedValue();
                        // Manager offsets are typically in 0x18000-0x1A000 range
                        if (val >= 0x18000 && val <= 0x1A000) {
                            displacement = val;
                        }
                    }
                }

                if (hasReg && displacement >= 0) {
                    long callAddr = lastCallTarget != null ? lastCallTarget.getOffset() : 0;
                    storePatterns.add(new long[]{displacement, callAddr});
                    println("      Store at offset 0x" + Long.toHexString(displacement) +
                            (lastCallTarget != null ? " (after call to 0x" + lastCallTarget.toString() + ")" : ""));
                }
            }

            insn = insn.getNext();
            count++;
        }

        // Match stored offsets to known manager names by examining call targets
        for (long[] sp : storePatterns) {
            long offset = sp[0];
            long callAddr = sp[1];

            String managerName = identifyManagerByCallTarget(callAddr, imageBase);
            if (managerName != null && !results.containsKey(managerName)) {
                results.put(managerName, new OffsetResult(
                        "0x" + Long.toHexString(offset), "HIGH", "constructor analysis"));
                println("    [FOUND] " + managerName + " = 0x" + Long.toHexString(offset) + " (constructor)");
            }
        }
    }

    private String identifyManagerByCallTarget(long callAddr, long imageBase) {
        if (callAddr == 0) return null;
        Address addr = toAddr(callAddr);
        Function func = getFunctionAt(addr);
        if (func == null) return null;

        String name = getFullFunctionName(func);
        if (name == null) return null;

        String lower = name.toLowerCase();
        if (lower.contains("npcmanager") || lower.contains("npc_manager")) return "NPC_MANAGER";
        if (lower.contains("playermanager") || lower.contains("player_manager")) return "PLAYER_MANAGER";
        if (lower.contains("scenemanager") || lower.contains("scene_manager")) return "SCENE_MANAGER";
        if (lower.contains("inventorymanager") || lower.contains("inventory_manager")) return "INVENTORY_MANAGER";
        if (lower.contains("connectionmanager") || lower.contains("connection_manager")) return "CONNECTION_MANAGER";
        if (lower.contains("interfacelist") || lower.contains("interface_list")) return "INTERFACE_LIST";
        if (lower.contains("spotanim")) return "SPOTANIM_MANAGER";
        if (lower.contains("projectile")) return "PROJECTILE_LIST";
        if (lower.contains("mainlogic")) return "MAINLOGIC_MANAGER";
        if (lower.contains("objectmanager") || lower.contains("object_manager")) return "OBJECT_MANAGER";
        if (lower.contains("sdl")) return "SDL_MANAGER";
        if (lower.contains("itemstack")) return "ITEMSTACK_LIST";
        if (lower.contains("hinttrail")) return "HINTTRAIL_LIST";

        return null;
    }

    private void discoverViaCallerChains(Map<String, OffsetResult> results,
                                          List<Map<String, String>> missing,
                                          List<Map<String, String>> manualReview,
                                          long imageBase) {
        // For each undiscovered OClient field, try to find it via caller chain tracing
        // Map: field name -> function that operates on that manager
        Map<String, String> managerFunctions = new LinkedHashMap<>();
        managerFunctions.put("INVENTORY_MANAGER", "jag::InventoryManager::GetInventory");
        managerFunctions.put("CONNECTION_MANAGER", "jag::ConnectionManager::TcpIn");
        managerFunctions.put("SPOTANIM_MANAGER", "jag::SpotAnimManager::Add");

        for (Map.Entry<String, String> entry : managerFunctions.entrySet()) {
            String field = entry.getKey();
            if (results.containsKey(field) && results.get(field).value != null) continue;

            String funcName = entry.getValue();
            Address funcAddr = findFunctionByQualifiedName(funcName);
            if (funcAddr == null) continue;

            println("    Tracing callers of " + funcName + " for " + field);

            // Find callers, look for pattern: MOV reg, [client + offset]; ... CALL <funcName>
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(funcAddr);
            Map<Long, Integer> candidates = new HashMap<>();

            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (!ref.getReferenceType().isCall()) continue;

                Address callSite = ref.getFromAddress();
                Long offset = scanForManagerLoad(callSite, 0x18000, 0x1A000);
                if (offset != null) {
                    candidates.merge(offset, 1, Integer::sum);
                }
            }

            if (!candidates.isEmpty()) {
                Map.Entry<Long, Integer> best = candidates.entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .orElse(null);
                if (best != null) {
                    String conf = best.getValue() >= 2 ? "HIGH" : "MEDIUM";
                    results.put(field, new OffsetResult(
                            "0x" + Long.toHexString(best.getKey()), conf,
                            "caller trace: " + funcName + " (" + best.getValue() + " callers)"));
                    println("    [FOUND] " + field + " = 0x" + Long.toHexString(best.getKey()) + " (" + conf + ")");
                }
            }
        }

        // Record any still-missing fields
        String[] allClientFields = {
                "CLIENT_CYCLE", "CLIENT_RENDER_CYCLE", "SDL_MANAGER", "OBJECT_MANAGER",
                "CONNECTION_MANAGER", "HINTTRAIL_LIST", "INTERFACE_LIST", "MAINLOGIC_MANAGER",
                "NPC_MANAGER", "ITEMSTACK_LIST", "PLAYER_MANAGER", "PROJECTILE_LIST",
                "SPOTANIM_MANAGER", "INVENTORY_MANAGER", "SCENE_MANAGER",
                "MAIN_STATE", "LOGGED_IN_PLAYER", "PLAYER_VAR_DOMAIN"
        };

        for (String field : allClientFields) {
            if (!results.containsKey(field) || results.get(field).value == null) {
                Map<String, String> m = new LinkedHashMap<>();
                m.put("name", "OClient." + field);
                m.put("reason", "no discovery method succeeded");
                missing.add(m);
            }
        }
    }

    // Scan backwards from a call site looking for MOV reg, [base + displacement]
    // where displacement is in the expected range for a Client struct field load
    private Long scanForManagerLoad(Address callSite, long minDisp, long maxDisp) {
        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionBefore(callSite);
        int scanned = 0;

        while (insn != null && scanned < 15) {
            String mnemonic = insn.getMnemonicString();

            if (mnemonic.equals("MOV")) {
                // Look for [reg + displacement] pattern in source operand
                Object[] srcOps = insn.getOpObjects(1);
                boolean hasReg = false;
                long disp = -1;

                for (Object op : srcOps) {
                    if (op instanceof ghidra.program.model.lang.Register) hasReg = true;
                    if (op instanceof Scalar s) {
                        long val = s.getUnsignedValue();
                        if (val >= minDisp && val <= maxDisp) {
                            disp = val;
                        }
                    }
                }

                if (hasReg && disp >= 0) return disp;
            }

            if (mnemonic.equals("CALL") || mnemonic.equals("RET") || mnemonic.equals("JMP")) break;

            insn = listing.getInstructionBefore(insn.getAddress());
            scanned++;
        }

        return null;
    }

    // Extract a displacement operand from a function matching a pattern
    private Long extractDisplacementFromFunction(Function func, String pattern, long minRange, long maxRange) {
        if (pattern == null) pattern = "first [param1 + disp32] read";

        Listing listing = currentProgram.getListing();
        Instruction insn = listing.getInstructionAt(func.getEntryPoint());
        int count = 0;

        while (insn != null && func.getBody().contains(insn.getAddress()) && count < 500) {
            String mnemonic = insn.getMnemonicString();

            if (mnemonic.equals("MOV") || mnemonic.equals("LEA") || mnemonic.equals("CMP")) {
                // Scan all operands for displacement in range
                for (int opIdx = 0; opIdx < insn.getNumOperands(); opIdx++) {
                    Object[] ops = insn.getOpObjects(opIdx);
                    boolean hasReg = false;
                    long disp = -1;

                    for (Object op : ops) {
                        if (op instanceof ghidra.program.model.lang.Register) hasReg = true;
                        if (op instanceof Scalar s) {
                            long val = s.getUnsignedValue();
                            if (val >= minRange && val <= maxRange) {
                                disp = val;
                            }
                        }
                    }

                    if (hasReg && disp >= 0) return disp;
                }
            }

            insn = insn.getNext();
            count++;
        }

        return null;
    }

    // --- Utility Methods ---

    private Address findFunctionByQualifiedName(String qualifiedName) {
        SymbolTable symTable = currentProgram.getSymbolTable();

        // Parse "jag::Client::SetMainState" -> namespace=jag::Client, name=SetMainState
        String[] parts = qualifiedName.split("::");
        if (parts.length == 0) return null;

        String funcName = parts[parts.length - 1];
        Namespace ns = currentProgram.getGlobalNamespace();

        for (int i = 0; i < parts.length - 1; i++) {
            Namespace child = symTable.getNamespace(parts[i], ns);
            if (child == null) return null;
            ns = child;
        }

        // Find function symbol in namespace
        SymbolIterator syms = symTable.getSymbols(ns);
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            if (sym.getName().equals(funcName) && sym.getSymbolType() == SymbolType.FUNCTION) {
                return sym.getAddress();
            }
        }

        return null;
    }

    private String getFullFunctionName(Function func) {
        Symbol sym = func.getSymbol();
        if (sym == null) return func.getName();

        List<String> parts = new ArrayList<>();
        Namespace ns = sym.getParentNamespace();
        while (ns != null && !ns.isGlobal()) {
            parts.add(0, ns.getName());
            ns = ns.getParentNamespace();
        }
        parts.add(sym.getName());
        return String.join("::", parts);
    }

    private String detectVersion() {
        try {
            Memory mem = currentProgram.getMemory();
            for (MemoryBlock block : mem.getBlocks()) {
                if (!block.isInitialized()) continue;
                long size = block.getSize();
                if (size > 100_000_000) continue;

                byte[] data = new byte[(int) Math.min(size, 10_000_000)];
                block.getBytes(block.getStart(), data);
                String content = new String(data, StandardCharsets.US_ASCII);

                Matcher m = VERSION_PATTERN.matcher(content);
                if (m.find()) {
                    return m.group(1) + "-" + m.group(2);
                }
            }
        } catch (Exception e) {
            printerr("Version detection error: " + e.getMessage());
        }
        return null;
    }

    private Map<String, Object> loadAnchorRegistry() {
        try {
            File scriptDir = getSourceFile().getFile(false).getParentFile();
            File reResources = scriptDir.getParentFile();
            File registryFile = new File(reResources, "anchor_registry.json");

            if (!registryFile.exists()) {
                println("No anchor_registry.json found at " + registryFile.getAbsolutePath());
                return Collections.emptyMap();
            }

            String content = readFileContent(registryFile);
            println("Loaded anchor registry from " + registryFile.getAbsolutePath());
            return parseJsonMap(content);
        } catch (Exception e) {
            printerr("Failed to load anchor registry: " + e.getMessage());
            return Collections.emptyMap();
        }
    }

    private String readFileContent(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    // Minimal JSON map parser for the anchor registry
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonMap(String json) {
        // Reuse the JsonParser from RS3DataTypeImporter would be ideal,
        // but since Ghidra scripts are standalone, embed a minimal parser
        return (Map<String, Object>) new JsonParser(json).parseValue();
    }

    private void appendOffsetResults(StringBuilder json, Map<String, OffsetResult> results, int indent) {
        String pad = " ".repeat(indent);
        Iterator<Map.Entry<String, OffsetResult>> it = results.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, OffsetResult> e = it.next();
            OffsetResult r = e.getValue();
            json.append(pad).append("\"").append(e.getKey()).append("\": {");
            json.append("\"value\": ").append(r.value != null ? "\"" + r.value + "\"" : "null");
            json.append(", \"confidence\": \"").append(r.confidence).append("\"");
            json.append(", \"source\": \"").append(escJson(r.source)).append("\"");
            json.append("}");
            if (it.hasNext()) json.append(",");
            json.append("\n");
        }
    }

    private String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static class OffsetResult {
        String value;
        String confidence;
        String source;

        OffsetResult(String value, String confidence, String source) {
            this.value = value;
            this.confidence = confidence;
            this.source = source;
        }
    }

    // Minimal recursive-descent JSON parser
    private static class JsonParser {
        private final String input;
        private int pos;

        JsonParser(String input) { this.input = input; this.pos = 0; }

        Object parseValue() {
            skipWs();
            if (pos >= input.length()) return null;
            char c = input.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBool();
            if (c == 'n') { pos += 4; return null; }
            return parseNumber();
        }

        Map<String, Object> parseObject() {
            Map<String, Object> m = new LinkedHashMap<>();
            expect('{');
            skipWs();
            if (peek() == '}') { pos++; return m; }
            while (true) {
                skipWs(); String k = parseString(); skipWs(); expect(':');
                m.put(k, parseValue()); skipWs();
                if (peek() == ',') pos++; else break;
            }
            skipWs(); expect('}');
            return m;
        }

        List<Object> parseArray() {
            List<Object> l = new ArrayList<>();
            expect('['); skipWs();
            if (peek() == ']') { pos++; return l; }
            while (true) {
                l.add(parseValue()); skipWs();
                if (peek() == ',') pos++; else break;
            }
            skipWs(); expect(']');
            return l;
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
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        default: sb.append(c);
                    }
                } else sb.append(c);
            }
            return sb.toString();
        }

        Number parseNumber() {
            int s = pos;
            if (peek() == '-') pos++;
            while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++;
            boolean flt = false;
            if (pos < input.length() && input.charAt(pos) == '.') { flt = true; pos++; while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++; }
            if (pos < input.length() && (input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) { flt = true; pos++; if (pos < input.length() && (input.charAt(pos)=='+' || input.charAt(pos)=='-')) pos++; while (pos < input.length() && Character.isDigit(input.charAt(pos))) pos++; }
            String n = input.substring(s, pos);
            if (flt) return Double.parseDouble(n);
            long v = Long.parseLong(n); return v >= Integer.MIN_VALUE && v <= Integer.MAX_VALUE ? (int)v : v;
        }

        Boolean parseBool() {
            if (input.startsWith("true", pos)) { pos += 4; return true; }
            if (input.startsWith("false", pos)) { pos += 5; return false; }
            throw new RuntimeException("Expected boolean at " + pos);
        }

        void skipWs() { while (pos < input.length() && Character.isWhitespace(input.charAt(pos))) pos++; }
        char peek() { return pos < input.length() ? input.charAt(pos) : 0; }
        void expect(char c) { skipWs(); if (pos >= input.length() || input.charAt(pos) != c) throw new RuntimeException("Expected '" + c + "' at " + pos); pos++; }
    }
}
