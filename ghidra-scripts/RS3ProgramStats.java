import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class RS3ProgramStats extends GhidraScript {
    @Override
    protected void run() throws Exception {
        int total = 0, named = 0, external = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            total++;
            if (f.isExternal()) external++;
            String n = f.getName();
            if (!n.startsWith("FUN_") && !n.startsWith("thunk_FUN_")) named++;
        }
        long instructions = currentProgram.getListing().getNumInstructions();
        long defined = currentProgram.getListing().getNumDefinedData();
        StringBuilder blocks = new StringBuilder();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks())
            blocks.append(b.getName()).append(':').append(b.isInitialized() ? "I" : "-").append(' ');
        println("STATS program=" + currentProgram.getName()
                + " imageBase=0x" + Long.toHexString(currentProgram.getImageBase().getOffset())
                + " functions=" + total + " named=" + named + " external=" + external
                + " instructions=" + instructions + " definedData=" + defined);
        println("STATS blocks=" + blocks);
    }
}
