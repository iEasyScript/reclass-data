//Recovers DoAction sender addresses from a WINDOWS rs2client PE, which neither RS3ProjectXUpdater
//(walks .CRT$XCU) nor RS3DoActionUpdater (walks the GCC "_INIT_2" init array) can do -- both key off
//structures that only exist in the ELF build, so the Windows values have to come from the registration
//code itself.
//
//jag::MiniMenu::RegisterDoActions installs one eastl::function into each action object. The action
//object holds the id/kind; the callable vtable holds the sender. Neither alone is enough: the object's
//vtable slot is zero in the file and only written at runtime, so the object->vtable pairing exists ONLY
//as the order of data references inside the registration function.
//
//  action object  0x50 bytes: +0x00 vtable (runtime), +0x08 captured Client*, +0x38 engaged ptr,
//                             +0x40 actionId, +0x44 kind
//  callable vtable 0x30 bytes: +0x00/+0x08 dtor, +0x10 INVOKE == the sender, +0x18 clone,
//                             +0x20 destroy, +0x28 alloc
//
//Stored pointers are absolute PE VAs. Programs are imported at image base 0 (see RS3SetImageBaseZero), so
//they are rebased here and the result is range-checked against the executable blocks rather than
//trusted.
//@category RS3

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RS3WindowsDoActions extends GhidraScript {

    private static final String[] REGISTRARS = {
        "jag::MiniMenu::RegisterDoActions",
        "jag::MiniMenu::RegisterComponentDoActions",
    };

    private static final long PE_IMAGE_BASE = 0x140000000L;
    private static final int ACTION_ID = 0x40;
    private static final int ACTION_KIND = 0x44;
    private static final int ACTION_ENGAGED = 0x38;
    private static final int VTABLE_INVOKE = 0x10;
    private static final int VTABLE_SLOTS = 6;

    private long imageDelta;

    @Override
    public void run() throws Exception {
        imageDelta = currentProgram.getImageBase().getOffset() == 0 ? PE_IMAGE_BASE : 0;

        Map<Long, Long> actionToVtable = new LinkedHashMap<>();
        for (String registrar : REGISTRARS) {
            Function fn = findFunction(registrar);
            if (fn == null) {
                println("MISSING registrar: " + registrar);
                continue;
            }
            int before = actionToVtable.size();
            collectPairs(fn, actionToVtable);
            println(registrar + " @ " + fn.getEntryPoint() + " -> " + (actionToVtable.size() - before) + " pairings");
        }

        println("");
        println("id\tkind\taction\tvtable\tsender");
        int emitted = 0, suspect = 0;
        for (Map.Entry<Long, Long> e : actionToVtable.entrySet()) {
            long action = e.getKey(), vtable = e.getValue();
            int id = getInt(addr(action + ACTION_ID));
            int kind = getInt(addr(action + ACTION_KIND));
            long sender = deref(vtable + VTABLE_INVOKE);
            boolean ok = isExecutable(sender);
            if (!ok) suspect++;
            emitted++;
            println(id + "\t" + kind + "\t" + hex(action) + "\t" + hex(vtable) + "\t" + hex(sender)
                    + (ok ? "" : "\t*** SENDER NOT IN EXECUTABLE MEMORY ***"));
        }
        println("");
        println("emitted " + emitted + " actions, " + suspect + " with an out-of-range sender");
    }

    /**
     * The registration sequence references the vtable (in initialised .rdata) and then the action
     * object it is installed into. A "copy" registration clones an already-registered action instead,
     * referencing that donor at +0x38, in which case both share one sender.
     */
    private void collectPairs(Function fn, Map<Long, Long> out) {
        Long pendingVtable = null;
        for (Instruction instr : currentProgram.getListing().getInstructions(fn.getBody(), true)) {
            for (Reference ref : instr.getReferencesFrom()) {
                if (!ref.getReferenceType().isData()) continue;
                long target = ref.getToAddress().getOffset();

                if (looksLikeVtable(target)) {
                    pendingVtable = target;
                    continue;
                }
                Long donor = donorAction(target);
                if (donor != null && out.containsKey(donor)) {
                    pendingVtable = out.get(donor);
                    continue;
                }
                if (pendingVtable != null && looksLikeAction(target)) {
                    out.putIfAbsent(target, pendingVtable);
                    pendingVtable = null;
                }
            }
        }
    }

    private Long donorAction(long target) {
        long base = target - ACTION_ENGAGED;
        return looksLikeAction(base) ? base : null;
    }

    private boolean looksLikeVtable(long target) {
        for (int slot = 0; slot < VTABLE_SLOTS; slot++) {
            if (!isExecutable(deref(target + slot * 8L))) return false;
        }
        return true;
    }

    private boolean looksLikeAction(long target) {
        Integer kind = tryGetInt(target + ACTION_KIND);
        Integer id = tryGetInt(target + ACTION_ID);
        if (kind == null || id == null) return false;
        return kind >= 0 && kind < 32 && id > 0 && id <= 5000 && isWritable(target);
    }

    private long deref(long at) {
        try {
            long raw = currentProgram.getMemory().getLong(addr(at));
            return raw == 0 ? 0 : raw - imageDelta;
        } catch (Exception e) {
            return 0;
        }
    }

    private Integer tryGetInt(long at) {
        try {
            return currentProgram.getMemory().getInt(addr(at));
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isExecutable(long value) {
        MemoryBlock block = blockAt(value);
        return block != null && block.isExecute();
    }

    private boolean isWritable(long value) {
        MemoryBlock block = blockAt(value);
        return block != null && block.isWrite();
    }

    private MemoryBlock blockAt(long value) {
        if (value <= 0) return null;
        try {
            return currentProgram.getMemory().getBlock(addr(value));
        } catch (Exception e) {
            return null;
        }
    }

    private Function findFunction(String name) {
        List<Function> matches = new ArrayList<>();
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            if (name.equals(fn.getName(true))) matches.add(fn);
        }
        return matches.isEmpty() ? null : matches.get(0);
    }

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private String hex(long value) {
        return "0x" + Long.toHexString(value);
    }
}
