// The instruction shape of code at given addresses, whether or not analysis made a function there, such as handlers
// reached only through a table. Disassembles from each address along the fall-through path until a return or an
// unconditional jump, masking numbers as RS3FunctionShapes does, so the two outputs compare directly.
//
//   analyzeHeadless <proj> <name> -process <program> -noanalysis -readOnly
//       -postScript RS3AddressShapes.java <addresses file> <out file> [literal]
//
// The addresses file holds one hex address per line. Writes address, instruction count, SHA-1 of the masked shape and
// the data addresses the code refers to. With "literal", only operands that refer to an address are masked and every
// other constant is kept, which tells apart stubs that differ only in the value they pass on (one handler per menu
// option, say); stubs that differ only in which descriptor they load are told apart by the data column.
//@category RS3

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

public class RS3AddressShapes extends GhidraScript {

    private static final Pattern NUMBER = Pattern.compile("-?0x[0-9a-fA-F]+|\\b[0-9]+\\b");
    private static final int MAX_INSTRUCTIONS = 400;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { printerr("usage: RS3AddressShapes <addresses file> <out file> [literal]"); return; }
        boolean literal = args.length > 2 && args[2].equalsIgnoreCase("literal");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        int written = 0;
        try (BufferedWriter w = Files.newBufferedWriter(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
                String text = line.trim();
                if (text.isEmpty()) continue;
                Address start = toAddr(Long.decode(text));
                StringBuilder shape = new StringBuilder();
                List<String> data = new ArrayList<>();
                int count = 0;
                Address at = start;
                while (count < MAX_INSTRUCTIONS) {
                    Instruction i = getInstructionAt(at);
                    if (i == null) {
                        disassemble(at);
                        i = getInstructionAt(at);
                    }
                    if (i == null) break;
                    shape.append(i.getMnemonicString());
                    for (int op = 0; op < i.getNumOperands(); op++) {
                        String operand = i.getDefaultOperandRepresentation(op);
                        boolean refers = literal && i.getOperandReferences(op).length > 0;
                        shape.append(' ').append(!literal || refers ? NUMBER.matcher(operand).replaceAll("#") : operand);
                    }
                    shape.append(';');
                    for (Reference r : i.getReferencesFrom()) {
                        if (r.getReferenceType().isData() && r.getToAddress().isMemoryAddress()) {
                            data.add("0x" + Long.toHexString(r.getToAddress().getOffset()));
                        }
                    }
                    count++;
                    if (i.getFlowType().isTerminal() || (i.getFlowType().isJump() && !i.getFlowType().isConditional())) break;
                    at = i.getFallThrough();
                    if (at == null) break;
                }
                String hash = HexFormat.of().formatHex(sha.digest(shape.toString().getBytes(StandardCharsets.UTF_8)));
                w.write("0x" + Long.toHexString(start.getOffset()) + "\t" + count + "\t" + hash + "\t" + String.join(",", data) + "\n");
                written++;
            }
        }
        println("address shapes: " + written + " -> " + args[1]);
    }
}
