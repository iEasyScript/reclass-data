// Every function's entry and instruction shape (mnemonics and operands with numbers masked), for confirming a
// function placed by its neighbours across builds is the same code.
//
//   analyzeHeadless <proj> <name> -process <program> -noanalysis -readOnly
//       -postScript RS3FunctionShapes.java <out dir>
//
// Writes function_shapes_<program>.tsv: entry, instruction count, SHA-1 of the masked shape.
//@category RS3

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.regex.Pattern;

public class RS3FunctionShapes extends GhidraScript {

    private static final Pattern NUMBER = Pattern.compile("-?0x[0-9a-fA-F]+|\\b[0-9]+\\b");

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { printerr("usage: RS3FunctionShapes <out dir>"); return; }
        Path outDir = Paths.get(args[0]);
        Files.createDirectories(outDir);
        Path out = outDir.resolve("function_shapes_" + currentProgram.getName() + ".tsv");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        int written = 0;
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) break;
                if (f.isThunk() || f.isExternal()) continue;
                StringBuilder shape = new StringBuilder();
                int count = 0;
                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (it.hasNext()) {
                    Instruction i = it.next();
                    shape.append(i.getMnemonicString());
                    for (int op = 0; op < i.getNumOperands(); op++) {
                        shape.append(' ').append(NUMBER.matcher(i.getDefaultOperandRepresentation(op)).replaceAll("#"));
                    }
                    shape.append(';');
                    count++;
                }
                String hash = HexFormat.of().formatHex(sha.digest(shape.toString().getBytes(StandardCharsets.UTF_8)));
                w.write("0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\t" + count + "\t" + hash + "\n");
                written++;
            }
        }
        println("function shapes: " + written + " -> " + out);
    }
}
