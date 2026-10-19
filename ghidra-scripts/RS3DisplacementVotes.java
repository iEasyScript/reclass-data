// Cross-build struct-offset evidence: pairs functions whose instruction shape is identical and unique in both
// builds, walks each pair in lockstep, and votes every `[reg + disp]` displacement old -> new.
//
//   analyzeHeadless <proj> <name> -process <new program> -noanalysis -readOnly
//       -postScript RS3DisplacementVotes.java <old program path> <out dir>
//
// Writes displacement_votes_<old>__<new>.tsv (old, new, votes, base registers, sample pairs),
// function_pairs_<old>__<new>.tsv, pair_accesses_<old>__<new>.tsv (every voted operand, per pair and base register)
// and address_votes_<old>__<new>.tsv (data and call targets, old -> new). A unanimous old -> old vote says a field that compiles to that displacement
// stayed put; a unanimous old -> new vote says it moved. Small displacements are shared by many structs, so a
// mixed vote there is expected and decides nothing; large ones are effectively unique to one struct.
//@category RS3

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class RS3DisplacementVotes extends GhidraScript {

    private static final int MIN_INSTRUCTIONS = 8;
    private static final Pattern HEX = Pattern.compile("-?0x[0-9a-fA-F]+|\\b[0-9]+\\b");
    private static final Pattern MEMORY = Pattern.compile("\\[([A-Z0-9]+)(?: \\+ [A-Z0-9]+(?:\\*\\d)?)? ([+-]) (0x[0-9a-fA-F]+)\\]");

    private record Shape(String hash, List<Instruction> instructions) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) { printerr("usage: RS3DisplacementVotes <old program path> <out dir>"); return; }
        DomainFile oldFile = state.getProject().getProjectData().getFile(args[0]);
        if (oldFile == null) { printerr("no program at " + args[0]); return; }
        Path outDir = Paths.get(args[1]);
        Files.createDirectories(outDir);

        Program oldProgram = (Program) oldFile.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
        try {
            Map<String, Function> oldUnique = uniqueShapes(oldProgram);
            Map<String, Function> newUnique = uniqueShapes(currentProgram);
            println("unique shapes: old=" + oldUnique.size() + " new=" + newUnique.size());

            Map<String, int[]> votes = new TreeMap<>();
            Map<String, Set<String>> bases = new HashMap<>();
            Map<String, List<String>> samples = new HashMap<>();
            List<String> pairLines = new ArrayList<>();
            List<String> accessLines = new ArrayList<>();
            Map<String, int[]> addressVotes = new TreeMap<>();
            int pairs = 0;
            for (Map.Entry<String, Function> e : oldUnique.entrySet()) {
                Function nf = newUnique.get(e.getKey());
                if (nf == null) continue;
                Function of = e.getValue();
                pairs++;
                pairLines.add(of.getEntryPoint() + "\t" + nf.getEntryPoint() + "\t" + of.getName(true) + "\t" + nf.getName(true));
                List<Instruction> oi = instructions(oldProgram, of);
                List<Instruction> ni = instructions(currentProgram, nf);
                for (int i = 0; i < oi.size() && i < ni.size(); i++) {
                    vote(oi.get(i), ni.get(i), of, nf, votes, bases, samples, accessLines);
                    voteAddresses(oi.get(i), ni.get(i), addressVotes);
                }
            }
            println("function pairs: " + pairs);

            String tag = oldProgram.getName() + "__" + currentProgram.getName();
            try (BufferedWriter w = Files.newBufferedWriter(outDir.resolve("displacement_votes_" + tag + ".tsv"), StandardCharsets.UTF_8)) {
                w.write("old\tnew\tvotes\tbases\tsamples\n");
                for (Map.Entry<String, int[]> v : votes.entrySet()) {
                    w.write(v.getKey() + "\t" + v.getValue()[0] + "\t" + String.join(",", bases.get(v.getKey()))
                            + "\t" + String.join(" ", samples.get(v.getKey())) + "\n");
                }
            }
            Files.write(outDir.resolve("function_pairs_" + tag + ".tsv"), pairLines, StandardCharsets.UTF_8);
            Files.write(outDir.resolve("pair_accesses_" + tag + ".tsv"), accessLines, StandardCharsets.UTF_8);
            try (BufferedWriter w = Files.newBufferedWriter(outDir.resolve("address_votes_" + tag + ".tsv"), StandardCharsets.UTF_8)) {
                w.write("kind\told\tnew\tvotes\n");
                for (Map.Entry<String, int[]> v : addressVotes.entrySet()) w.write(v.getKey() + "\t" + v.getValue()[0] + "\n");
            }
            println("address votes: " + addressVotes.size() + " distinct old->new data and call targets");
            println("votes: " + votes.size() + " distinct old->new displacement pairs -> " + outDir);
        } finally {
            oldProgram.release(this);
        }
    }

    private void vote(Instruction o, Instruction n, Function of, Function nf,
                      Map<String, int[]> votes, Map<String, Set<String>> bases, Map<String, List<String>> samples,
                      List<String> accessLines) {
        for (int op = 0; op < o.getNumOperands() && op < n.getNumOperands(); op++) {
            Matcher mo = MEMORY.matcher(o.getDefaultOperandRepresentation(op));
            Matcher mn = MEMORY.matcher(n.getDefaultOperandRepresentation(op));
            if (!mo.find() || !mn.find()) continue;
            if (mo.group(1).equals("RIP") || mo.group(1).equals("RSP") || mo.group(1).equals("RBP")) continue;
            long od = Long.decode(mo.group(3)) * (mo.group(2).equals("-") ? -1 : 1);
            long nd = Long.decode(mn.group(3)) * (mn.group(2).equals("-") ? -1 : 1);
            if (od < 0 || nd < 0) continue;
            String key = String.format("0x%x\t0x%x", od, nd);
            accessLines.add(of.getEntryPoint() + "\t" + nf.getEntryPoint() + "\t" + o.getAddress() + "\t" + mo.group(1) + "\t" + key);
            votes.computeIfAbsent(key, k -> new int[1])[0]++;
            bases.computeIfAbsent(key, k -> new TreeSet<>()).add(mo.group(1));
            List<String> s = samples.computeIfAbsent(key, k -> new ArrayList<>());
            if (s.size() < 3) s.add(of.getEntryPoint() + ">" + nf.getEntryPoint());
        }
    }

    /** A paired instruction's data and call targets: how globals and functions moved, including ones that changed. */
    private void voteAddresses(Instruction o, Instruction n, Map<String, int[]> addressVotes) {
        Reference[] or = o.getReferencesFrom();
        Reference[] nr = n.getReferencesFrom();
        for (Reference a : or) {
            if (!a.getToAddress().isMemoryAddress()) continue;
            for (Reference b : nr) {
                if (b.getOperandIndex() != a.getOperandIndex() || !b.getToAddress().isMemoryAddress()) continue;
                if (a.getReferenceType().isCall() != b.getReferenceType().isCall()) continue;
                if (!a.getReferenceType().isCall() && !a.getReferenceType().isData()) continue;
                String kind = a.getReferenceType().isCall() ? "CALL" : "DATA";
                String key = kind + "\t0x" + Long.toHexString(a.getToAddress().getOffset()) + "\t0x" + Long.toHexString(b.getToAddress().getOffset());
                addressVotes.computeIfAbsent(key, k -> new int[1])[0]++;
            }
        }
    }

    private Map<String, Function> uniqueShapes(Program p) {
        Map<String, Function> unique = new HashMap<>();
        Set<String> duplicated = new HashSet<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (f.isThunk() || f.isExternal()) continue;
            List<Instruction> ins = instructions(p, f);
            if (ins.size() < MIN_INSTRUCTIONS) continue;
            StringBuilder sb = new StringBuilder(ins.size() * 16);
            for (Instruction i : ins) {
                sb.append(i.getMnemonicString());
                for (int op = 0; op < i.getNumOperands(); op++) {
                    sb.append(' ').append(HEX.matcher(i.getDefaultOperandRepresentation(op)).replaceAll("#"));
                }
                sb.append(';');
            }
            String hash = sb.toString();
            if (duplicated.contains(hash)) continue;
            if (unique.put(hash, f) != null) { unique.remove(hash); duplicated.add(hash); }
        }
        return unique;
    }

    private List<Instruction> instructions(Program p, Function f) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) out.add(it.next());
        return out;
    }
}
