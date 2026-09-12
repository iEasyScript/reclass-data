import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.util.*;

/**
 * @Author Javatar
 * Modified Version to Match Expected Output Format with Verification
 */
public class RS3DoActionUpdater extends GhidraScript {
    public static Map<Integer, String> doActionNames = new HashMap<>();
    public static Map<Integer, Integer> mappedOpcodes = new HashMap<>();
    public static Map<Integer, String> doActionOffsetNames = new HashMap<>();
    public static List<DoActionType> doActionTypes = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        initDoActionNames();
        
        Function init2 = getFunctionByName("_INIT_2");
        if (init2 != null)
            parseDoActions(init2);
        else
            printf("Warning: _INIT_2 function not found. Will use expected addresses only.%n");

        detectOpcodeShifts();
        generateVerifiedOutput();
    }

    private void parseDoActions(Function init2) {
        Set<Function> fncs = init2.getCalledFunctions(monitor);

        Instruction start = null;
        for (Function fnc : fncs) {
            for (Instruction instr : getFunctionInstructions(fnc)) {
                if (!instr.getMnemonicString().equals("MOV"))
                    continue;
                Object[] ops = instr.getOpObjects(1);
                if (ops.length == 1 && ops[0] instanceof Scalar scalar) {
                    if (scalar.getValue() == 2053) {
                        start = instr.getNext().getNext();
                        break;
                    }
                }
            }
            if (start != null)
                break;
        }

        if (start == null) {
            printf("Warning: start instruction not found. Will use expected addresses.%n");
            return;
        }

        Instruction current = start;
        try {
            while (!current.getMnemonicString().equals("JZ"))
                current = parseBlock(current);
        } catch (Exception e) {
            printf("Warning: Exception during parsing: %s. Will continue with expected addresses.%n", e.getMessage());
        }
    }

    private Instruction parseBlock(Instruction instr) {
        try {
            Instruction cleanupCall = instr;
            Instruction idk = cleanupCall.getPrevious();
            Instruction actionId = idk.getPrevious();
            Instruction idk1 = actionId.getPrevious();
            Instruction cleanupFuncAddress = idk1.getPrevious();
            Instruction actionStruct = cleanupFuncAddress.getPrevious();
            Instruction dosHandle = actionStruct.getPrevious();
    
            int id = parseActionId(actionId);
            Function callback = parseActionCallback(actionStruct, id);
            long callbackAddress = 0;
            if (callback != null) {
                callbackAddress = callback.getEntryPoint().getOffset();
                doActionTypes.add(new DoActionType(doActionNames.get(id), doActionOffsetNames.get(id), callbackAddress, id));
                printf("Successfully parsed opcode %d with address 0x%X%n", id, callbackAddress);
            }
            return dosHandle.getPrevious();
        } catch (Exception e) {
            printf("Warning: Error parsing a block: %s%n", e.getMessage());
            throw e;  // Re-throw to stop parsing
        }
    }

    private Function parseActionCallback(Instruction instr, int actionId) {
        Object[] ops = instr.getOpObjects(1);
        if (ops.length == 1 && ops[0] instanceof Scalar scalar) {
            Address structAddress = getAddressFrom(scalar.getUnsignedValue());
            printf("Action Struct for opcode %d: %s%n", actionId, structAddress);
            Address callback = structAddress.add(0x18);
            Reference[] refs = getReferencesTo(callback);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isWrite()) {
                    Instruction writeInstr = getInstructionAt(ref.getFromAddress());
                    Instruction assign = findScalarAssignment(writeInstr);
                    Object[] ops2 = assign.getOpObjects(1);
                    if (ops2.length == 1 && ops2[0] instanceof Scalar scalar1) {
                        Address funcAddress = getAddressFrom(scalar1.getUnsignedValue());
                        Function func = getFunctionAt(funcAddress);
                        if (func != null)
                            return func;
                    }
                }
            }
        }
        return null;
    }

    private int parseActionId(Instruction instr) {
        Object[] ops = instr.getOpObjects(1);
        if (ops.length == 1 && ops[0] instanceof Scalar scalar)
            return (int) scalar.getValue();
        return -1;
    }

    /**
     * Catch opcode-set changes across builds so a silent shift/renumber (like the 949-1 object
     * opcodes shifting -1) is FLAGGED instead of mislabeled. Compares the binary's parsed opcodes
     * against the expected map: a MISSING named action = removed or shifted; an UNMAPPED binary
     * opcode = new (or a shift target).
     */
    private void detectOpcodeShifts() {
        java.util.TreeSet<Integer> parsed = new java.util.TreeSet<>();
        for (DoActionType a : doActionTypes) parsed.add(a.opcode);
        java.util.TreeSet<Integer> missing = new java.util.TreeSet<>(mappedOpcodes.keySet());
        missing.removeAll(parsed);
        missing.remove(1007); // known alias of opcode 57, never a distinct binary opcode
        java.util.TreeSet<Integer> unmapped = new java.util.TreeSet<>(parsed);
        unmapped.removeAll(mappedOpcodes.keySet());
        if (missing.isEmpty() && unmapped.isEmpty()) {
            printf("[DoAction] opcode set unchanged vs the known map (%d parsed).%n", parsed.size());
            return;
        }
        printf("%n===== !!! DoAction OPCODE SET CHANGED — verify before trusting the output !!! =====%n");
        if (!missing.isEmpty())
            printf("  MISSING (a NAMED action's opcode vanished — REMOVED or part of a SHIFT): %s%n", missing);
        if (!unmapped.isEmpty())
            printf("  UNMAPPED (opcodes present in the binary with no name in initDoActionNames): %s%n", unmapped);
        printf("  If a contiguous group renumbered, re-map its names by handler ADDRESS ORDER (not the%n");
        printf("  fixed opcode number) and update initDoActionNames. UNMAPPED entries are emitted below as UNKNOWN_<op>.%n");
        printf("==================================================================================%n%n");
    }

    /**
     * Generate the output with verification against expected addresses
     */
    public void generateVerifiedOutput() {
        Map<Integer, String> parsedAddresses = new HashMap<>();
        for (DoActionType action : doActionTypes)
            parsedAddresses.put(action.opcode, "0x" + Long.toHexString(action.callback).toUpperCase());
        
        Set<Integer> allOpcodes = new HashSet<>();
        allOpcodes.addAll(doActionNames.keySet());
        allOpcodes.addAll(parsedAddresses.keySet()); // surface unmapped/new binary opcodes as UNKNOWN_<op>
        
        List<Integer> sortedOpcodes = new ArrayList<>(allOpcodes);
        Collections.sort(sortedOpcodes);
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sortedOpcodes.size(); i++) {
            int opcode = sortedOpcodes.get(i);
            
            String offsetName = doActionOffsetNames.get(opcode);
            if (offsetName == null)
                offsetName = "UNKNOWN_" + opcode;
            
            String methodName = null;
            if (doActionNames.get(opcode) != null) {
                String fullName = doActionNames.get(opcode);
                methodName = fullName.substring(fullName.lastIndexOf("::") + 2);
            } else
                methodName = "Unknown" + opcode;
            
            String address = parsedAddresses.get(opcode);
            if (address == null && opcode == 1007) //comp 6+ should match comp
                address = parsedAddresses.get(57);
            if (address == null)
                address = "0x000000";
            
            sb.append("    ")
              .append(offsetName)
              .append("(")
              .append(mappedOpcodes.getOrDefault(opcode, opcode))
              .append(", \"")
              .append(methodName)
              .append("\", ")
              .append(address)
              .append(")")
              .append(i == sortedOpcodes.size() - 1 ? ";" : ",")
              .append("\n");
        }
        
        printf("```\n%s```\n", sb.toString());
    }

    public Address getAddressFrom(long value) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    Function getFunctionByName(String name) {
        Program program = currentProgram;
        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);

        while (functions.hasNext()) {
            Function function = functions.next();
            if (name.equals(function.getName()))
                return function;
        }
        return null;
    }

    Instruction findScalarAssignment(Instruction start) {
        Instruction insn = start;
        while (true) {
            if (monitor.isCancelled())
                return null;
            if (insn == null)
                return null;
            insn = findNextAssignment(insn);
            if (insn != null && insn.getOpObjects(1).length == 1 && insn.getOpObjects(1)[0] instanceof Scalar)
                return insn;
        }
    }

    private Instruction findNextAssignment(Instruction insn) {
        Instruction instr = insn;
        Object[] ops1 = insn.getOpObjects(1);
        while (!monitor.isCancelled()) {
            instr = instr.getPrevious();
            if (instr == null)
                break;
            if (Arrays.equals(instr.getOpObjects(0), ops1))
                return instr;
        }
        return null;
    }

    List<Instruction> getFunctionInstructions(Function fn) {
        List<Instruction> insns = new ArrayList<>();

        for (CodeUnit codeUnit : currentProgram.getListing().getCodeUnits(fn.getBody(), true)) {
            Instruction insn = getInstructionAt(codeUnit.getAddress());
            if (insn == null)
                continue;
            insns.add(insn);
        }

        return insns;
    }

    private static class DoActionType {
        String name;
        String offsetName;
        long callback;
        int opcode;

        public DoActionType(String name, String offsetName, long callback, int opcode) {
            this.name = name;
            this.offsetName = offsetName;
            this.callback = callback;
            this.opcode = opcode;
        }
    }

    private static void addDoAction(int mappedOpcode, int realOpcode, String refactorName, String offsetName) {
        doActionNames.put(mappedOpcode, refactorName);
        doActionOffsetNames.put(mappedOpcode, offsetName);
        mappedOpcodes.put(mappedOpcode, realOpcode);
    }

    private static void addDoAction(int realOpcode, String refactorName, String offsetName) {
        addDoAction(realOpcode, realOpcode, refactorName, offsetName);
    }

    public static void initDoActionNames() {
        addDoAction(23, "jag::MiniMenu::DoOpWalk", "WALK");
        addDoAction(8, "jag::MiniMenu::DoOpTargetNpc", "SELECT_NPC");
        addDoAction(2009, 9, "jag::MiniMenu::DoOpNpc1", "NPC_1");
        addDoAction(2010, 10, "jag::MiniMenu::DoOpNpc2", "NPC_2");
        addDoAction(2011, 11, "jag::MiniMenu::DoOpNpc3", "NPC_3");
        addDoAction(2012, 12, "jag::MiniMenu::DoOpNpc4", "NPC_4");
        addDoAction(2013, 13, "jag::MiniMenu::DoOpNpc5", "NPC_5");
        addDoAction(3003, 1003, "jag::MiniMenu::DoOpNpc6", "NPC_6");
        addDoAction(2, "jag::MiniMenu::DoOpSelectLoc", "SELECT_OBJECT");
        addDoAction(3, "jag::MiniMenu::DoOpLoc1", "OBJECT_1");
        addDoAction(4, "jag::MiniMenu::DoOpLoc2", "OBJECT_2");
        addDoAction(5, "jag::MiniMenu::DoOpLoc3", "OBJECT_3");
        addDoAction(6, "jag::MiniMenu::DoOpLoc4", "OBJECT_4");
        addDoAction(1001, "jag::MiniMenu::DoOpLoc5", "OBJECT_5");
        addDoAction(1002, "jag::MiniMenu::DoOpLoc6", "OBJECT_6");
        addDoAction(25, "jag::MiniMenu::DoOpTargetComponent", "SELECT_COMPONENT");
        addDoAction(30, "jag::MiniMenu::DoOpDialog", "DIALOGUE");
        addDoAction(57, "jag::MiniMenu::DoOpComponent", "COMPONENT");
        addDoAction(1007, "jag::MiniMenu::DoOpComponent6Plus", "COMPONENT_SIXPLUS"); //TODO should use the same opcode as 57
        addDoAction(58, "jag::MiniMenu::DoOpTargetComponentItem", "SELECT_COMPONENT_ITEM");
        addDoAction(59, "jag::MiniMenu::DoOpSelectTile", "SELECT_TILE");

        addDoAction(16, "jag::MiniMenu::DoOpComponentOnPlayer", "COMP_ON_PLAYER");
        addDoAction(17, "jag::MiniMenu::DoOpSelectObjStack", "SELECT_GROUND_ITEM");
        addDoAction(18, "jag::MiniMenu::DoOpObjStack1", "GROUND_ITEM_1");
        addDoAction(19, "jag::MiniMenu::DoOpObjStack2", "GROUND_ITEM_2");
        addDoAction(20, "jag::MiniMenu::DoOpObjStack3", "GROUND_ITEM_3");
        addDoAction(21, "jag::MiniMenu::DoOpObjStack4", "GROUND_ITEM_4");
        addDoAction(22, "jag::MiniMenu::DoOpObjStack5", "GROUND_ITEM_5");
        addDoAction(1004, "jag::MiniMenu::DoOpObjStack6", "GROUND_ITEM_6");

        addDoAction(15, "jag::MiniMenu::DoOpSelectPlayer", "PLAYER_SELECT");
        addDoAction(44, "jag::MiniMenu::DoOpPlayer1", "PLAYER_1");
        addDoAction(45, "jag::MiniMenu::DoOpPlayer2", "PLAYER_2");
        addDoAction(46, "jag::MiniMenu::DoOpPlayer3", "PLAYER_3");
        addDoAction(47, "jag::MiniMenu::DoOpPlayer4", "PLAYER_4");
        addDoAction(48, "jag::MiniMenu::DoOpPlayer5", "PLAYER_5");
        addDoAction(49, "jag::MiniMenu::DoOpPlayer6", "PLAYER_6");
        addDoAction(50, "jag::MiniMenu::DoOpPlayer7", "PLAYER_7");
        addDoAction(51, "jag::MiniMenu::DoOpPlayer8", "PLAYER_8");
        addDoAction(52, "jag::MiniMenu::DoOpPlayer9", "PLAYER_9");
        addDoAction(53, "jag::MiniMenu::DoOpPlayer10", "PLAYER_10");
        addDoAction(1005, "jag::MiniMenu::Unk1005", "UNK_1005");
    }
}