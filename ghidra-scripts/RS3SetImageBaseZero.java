//The PE loader ignores -loader-imagebase, so a headless-imported rs2client.exe lands at its header
//base. Every offset the updater emits is module-relative, and RS3ProjectXUpdater hard-fails on a
//non-zero base rather than silently emitting VAs. Run this as a -preScript: rebasing before
//auto-analysis avoids relocating a fully analyzed database.
//@category RS3

import ghidra.app.script.GhidraScript;

public class RS3SetImageBaseZero extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long base = currentProgram.getImageBase().getOffset();
        if (base == 0) {
            println("REBASE already zero for " + currentProgram.getName());
            return;
        }
        int tx = currentProgram.startTransaction("set image base 0");
        boolean ok = false;
        try {
            currentProgram.setImageBase(currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(0), true);
            ok = true;
        } finally {
            currentProgram.endTransaction(tx, ok);
        }
        println("REBASE " + currentProgram.getName() + " 0x" + Long.toHexString(base)
                + " -> 0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
    }
}
