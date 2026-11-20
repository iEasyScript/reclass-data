"""Port every absolute address of an offset table to a new build from RS3DisplacementVotes' cross-build evidence.

    python -I port_absolutes.py <old table.json> <function_pairs.tsv> <address_votes.tsv>
        <old function_shapes.tsv> <new function_shapes.tsv> <new build> <out table.json>
        [--probe <prefix>] [--address-shapes <old.tsv> <new.tsv>] [--literal-shapes <old.tsv> <new.tsv>]

An absolute is a value in OFunctions, OGlobal, OInputGlobals, OReferenceFunctions or OVulkanGlobals, a doAction
handler, or any other field holding an image-relative address (a vtable, a static sentinel). Each is decided by what
the paired functions say about it: an identical function paired at that entry, and the call and data targets the
paired instructions agree on. A function with no direct evidence, such as a small handler reached only through a
table, is placed by the nearest voted functions on both sides when they moved by the same amount, and accepted only
if the function at that place has exactly its old instruction shape. A global with no direct evidence is placed the
same way by nearby voted globals.

Code that analysis never made a function of (a handler reached only through a table) has no function shape. Run once
with --probe to list those addresses, old and as predicted in the new build, shape both lists with
RS3AddressShapes.java, and run again with --address-shapes to accept each only where the two shapes match.

A block of near-identical stubs (one per menu option) can be reordered inside a build, so its neighbours disagree on
the move and every stub has the same masked shape. --probe also lists those stubs and every same-shaped function near
either neighbour's prediction; shape both with RS3AddressShapes.java in literal mode, which keeps the constants that
tell the stubs apart, and pass the results as --literal-shapes. A stub is accepted only when exactly one candidate has
its literal code. Anything else is left out of the new table and listed as unresolved, never carried
from the old build.
"""

import argparse
import bisect
import csv
import json
import sys
from collections import Counter, defaultdict

ABSOLUTE = {"OFunctions", "OGlobal", "OInputGlobals", "OReferenceFunctions", "OVulkanGlobals"}
CODE = {"OFunctions", "OReferenceFunctions"}
IMAGE_MIN = 0x100000
DATA_REACH = 0x1000
FUNCTION_REACH = 0x20000
MAJORITY = 0.9
STUB_WINDOW = 0x4000


def hexval(text):
    return int(text, 16)


def load_votes(pairs_path, votes_path):
    evidence = defaultdict(Counter)
    kinds = defaultdict(set)
    for row in csv.reader(open(pairs_path, encoding="utf-8"), delimiter="\t"):
        if len(row) < 2:
            continue
        old, new = hexval(row[0]), hexval(row[1])
        evidence[old][new] += 1
        kinds[old].add("PAIR")
    for row in csv.DictReader(open(votes_path, encoding="utf-8"), delimiter="\t"):
        old, new = hexval(row["old"]), hexval(row["new"])
        evidence[old][new] += int(row["votes"])
        kinds[old].add(row["kind"])
    return evidence, kinds


def load_shapes(path):
    return {hexval(row[0]): row[2] for row in csv.reader(open(path, encoding="utf-8"), delimiter="\t") if len(row) >= 3}


def load_refs(path):
    return {hexval(row[0]): tuple(hexval(x) for x in row[3].split(",") if x)
            for row in csv.reader(open(path, encoding="utf-8"), delimiter="\t") if len(row) >= 4}


class Anchors:
    """Addresses whose move every vote agrees on, sorted, for placing a neighbour between two of them."""

    def __init__(self, evidence, keep):
        moves = sorted((old, next(iter(c))) for old, c in evidence.items() if len(c) == 1 and keep(old))
        self.olds = [o for o, _ in moves]
        self.deltas = [n - o for o, n in moves]

    def place(self, value, reach):
        i = bisect.bisect_left(self.olds, value)
        if i == 0 or i >= len(self.olds):
            return None
        below, above = i - 1, i
        if self.olds[above] == value:
            return None
        if value - self.olds[below] > reach or self.olds[above] - value > reach:
            return None
        if self.deltas[below] != self.deltas[above]:
            return None
        return value + self.deltas[below], self.olds[below], self.olds[above]

    def bracket_deltas(self, value):
        i = bisect.bisect_left(self.olds, value)
        return {self.deltas[j] for j in (i - 1, i) if 0 <= j < len(self.olds)}


def decide(counter):
    total = sum(counter.values())
    new, n = counter.most_common(1)[0]
    if n == total or n / total >= MAJORITY:
        return new, n, total
    return None, n, total


def describe(kinds):
    labels = []
    if "PAIR" in kinds:
        labels.append("identical function paired at this entry")
    if "CALL" in kinds:
        labels.append("call-target votes")
    if "DATA" in kinds:
        labels.append("data-reference votes")
    return " and ".join(labels)


class Porter:
    def __init__(self, evidence, kinds, old_shapes, new_shapes, old_build, new_build, old_code=None, new_code=None,
                 old_literal=None, new_literal=None, old_refs=None, new_refs=None):
        self.evidence, self.kinds = evidence, kinds
        self.old_shapes, self.new_shapes = old_shapes, new_shapes
        self.old_code, self.new_code = old_code or {}, new_code or {}
        self.old_literal, self.new_literal = old_literal or {}, new_literal or {}
        self.old_refs, self.new_refs = old_refs or {}, new_refs or {}
        self.probes = []
        self.stub_probes = []
        self.by_shape = defaultdict(list)
        for address, shape in new_shapes.items():
            self.by_shape[shape].append(address)
        self.old_build, self.new_build = old_build, new_build
        self.functions = Anchors(evidence, lambda a: a in old_shapes)
        self.data = Anchors(evidence, lambda a: a not in old_shapes)

    def stub(self, name, head, value):
        predictions = [value + d for d in self.functions.bracket_deltas(value)]
        candidates = sorted(a for a in self.by_shape.get(self.old_shapes[value], [])
                            if any(abs(a - p) <= STUB_WINDOW for p in predictions))
        if not candidates:
            return None, f"{name}: function with no paired evidence, no agreeing neighbours and no same-shaped code nearby"
        self.stub_probes.append((value, candidates))
        if value not in self.old_literal or any(c not in self.new_literal for c in candidates):
            return None, f"{name}: {len(candidates)} same-shaped stubs nearby; shape them in literal mode to choose"
        matches = [c for c in candidates if self.new_literal[c] == self.old_literal[value]]
        if len(matches) == 1:
            note = (f"{head} its stub block was reordered, so its neighbours moved by different amounts; of "
                    f"{len(candidates)} same-shaped stubs near their predictions, only this one has exactly its old code, "
                    f"constants included.")
            return (matches[0], "HIGH", note), None
        old_refs = self.old_refs.get(value, ())
        moved = tuple(self.map_data(r) for r in old_refs)
        if not old_refs or None in moved:
            return None, f"{name}: {len(matches)} of {len(candidates)} nearby same-shaped stubs have its literal code"
        keyed = [c for c in matches if self.new_refs.get(c) == moved]
        if len(keyed) != 1:
            return None, f"{name}: {len(keyed)} of {len(matches)} identical stubs load its moved data"
        refs = ", ".join(f"{o:#x}->{n:#x}" for o, n in zip(old_refs, moved))
        note = (f"{head} its stub block was reordered and {len(matches)} stubs share its code; only this one loads its "
                f"data, which moved by the paired functions' votes ({refs}).")
        return (keyed[0], "HIGH", note), None

    def map_data(self, address):
        counter = self.evidence.get(address)
        placed = self.data.place(address, DATA_REACH)
        if counter:
            new, _, _ = decide(counter)
            if new is not None:
                return new
            # Mixed votes count only when their plurality is the move both voted neighbours agree on.
            top = counter.most_common(2)
            if placed and top[0][0] == placed[0] and (len(top) == 1 or top[0][1] > top[1][1]):
                return placed[0]
            return None
        return placed[0] if placed else None

    def port(self, name, value, code=False):
        head = f"{name} at {self.new_build} ({self.old_build}: {value:#x}):"
        counter = self.evidence.get(value)
        if counter:
            new, n, total = decide(counter)
            if new is None:
                spread = ", ".join(f"{k:#x}:{v}" for k, v in counter.most_common(3))
                return None, f"{name}: evidence disagrees ({spread})"
            note = f"{head} {n}/{total} {describe(self.kinds[value])} from paired functions."
            if value in self.old_shapes and self.old_shapes[value] != self.new_shapes.get(new):
                note += " Its body changed in this build."
            return (new, "HIGH", note), None
        if value in self.old_shapes:
            placed = self.functions.place(value, FUNCTION_REACH)
            if not placed or self.new_shapes.get(placed[0]) != self.old_shapes[value]:
                return self.stub(name, head, value)
            new, lo, hi = placed
            note = (f"{head} reached only indirectly; the paired functions either side ({lo:#x}, {hi:#x}) both moved "
                    f"by {new - value:#x} and the function there has exactly its old instruction shape.")
            return (new, "HIGH", note), None
        if code:
            placed = self.functions.place(value, FUNCTION_REACH)
            if not placed:
                return None, f"{name}: code with no paired evidence and no agreeing neighbours"
            new, lo, hi = placed
            self.probes.append((value, new))
            old_shape = self.old_code.get(value)
            if old_shape is None or new not in self.new_code:
                return None, f"{name}: neighbours place it at {new:#x}; shape both with RS3AddressShapes to confirm"
            if self.new_code[new] != old_shape:
                return None, f"{name}: neighbours place it at {new:#x}, but the code there is not its old code"
            note = (f"{head} reached only through a table; the paired functions either side ({lo:#x}, {hi:#x}) both "
                    f"moved by {new - value:#x} and the code there disassembles to exactly its old instructions.")
            return (new, "HIGH", note), None
        placed = self.data.place(value, DATA_REACH)
        if not placed:
            return None, f"{name}: no paired evidence and no agreeing neighbours"
        new, lo, hi = placed
        note = (f"{head} not referenced by any paired instruction; its voted neighbours {lo:#x} and {hi:#x} both "
                f"moved by {new - value:#x}.")
        return (new, "MEDIUM", note), None


def symbol(entry, fallback):
    note = entry.get("note", "")
    head = note.split(" at ", 1)[0]
    return head if " at " in note and " " not in head else fallback


def table_label(table, build):
    renderer = table.get("renderer")
    return f"{build}-{renderer}" if renderer and renderer != "opengl" else build


def main():
    cli = argparse.ArgumentParser()
    for name in ("old_table", "pairs", "votes", "old_shapes", "new_shapes", "new_build", "out"):
        cli.add_argument(name)
    cli.add_argument("--probe")
    cli.add_argument("--address-shapes", nargs=2)
    cli.add_argument("--literal-shapes", nargs=2)
    args = cli.parse_args()
    old_path, new_build, out_path = args.old_table, args.new_build, args.out
    table = json.load(open(old_path, encoding="utf-8"))
    evidence, kinds = load_votes(args.pairs, args.votes)
    old_code, new_code = (load_shapes(p) for p in args.address_shapes) if args.address_shapes else ({}, {})
    old_literal, new_literal = (load_shapes(p) for p in args.literal_shapes) if args.literal_shapes else ({}, {})
    old_refs, new_refs = (load_refs(p) for p in args.literal_shapes) if args.literal_shapes else ({}, {})
    porter = Porter(evidence, kinds, load_shapes(args.old_shapes), load_shapes(args.new_shapes), table["build"], new_build,
                    old_code, new_code, old_literal, new_literal, old_refs, new_refs)
    label = table_label(table, new_build)
    unresolved, medium, changed = [], [], []
    ported = 0

    for group, fields in table["objects"].items():
        for field in list(fields):
            entry = fields[field]
            raw = entry.get("value")
            if not isinstance(raw, str) or raw.startswith("-"):
                continue
            value = hexval(raw)
            if group not in ABSOLUTE and value < IMAGE_MIN:
                continue
            result, problem = porter.port(symbol(entry, f"{group}.{field}"), value, code=group in CODE)
            if problem:
                unresolved.append(problem)
                del fields[field]
                continue
            new, confidence, note = result
            entry.update(value=f"{new:#x}", confidence=confidence, note=note, verified_build=label)
            (medium if confidence != "HIGH" else changed if "body changed" in note else []).append(note)
            ported += 1

    kept = []
    for action in table["doActions"]:
        result, problem = porter.port(f"doAction {action['name']}", hexval(action["value"]), code=True)
        if problem:
            unresolved.append(problem)
            continue
        new, confidence, note = result
        action["value"] = f"{new:#x}"
        action["verified_build"] = new_build
        (medium if confidence != "HIGH" else changed if "body changed" in note else []).append(note)
        kept.append(action)
        ported += 1
    table["doActions"] = kept

    if args.probe:
        with open(args.probe + ".old.txt", "w", encoding="utf-8") as o, open(args.probe + ".new.txt", "w", encoding="utf-8") as n:
            for old, new in sorted(set(porter.probes)):
                o.write(f"{old:#x}\n")
                n.write(f"{new:#x}\n")
        stub_olds = sorted({old for old, _ in porter.stub_probes})
        stub_news = sorted({c for _, cs in porter.stub_probes for c in cs})
        with open(args.probe + ".literal.old.txt", "w", encoding="utf-8") as o:
            o.writelines(f"{a:#x}\n" for a in stub_olds)
        with open(args.probe + ".literal.new.txt", "w", encoding="utf-8") as n:
            n.writelines(f"{a:#x}\n" for a in stub_news)
        print(f"probe: {len(set(porter.probes))} addresses to shape -> {args.probe}.old.txt / .new.txt")
        print(f"probe: {len(stub_olds)} stubs and {len(stub_news)} candidates to shape in literal mode -> "
              f"{args.probe}.literal.old.txt / .literal.new.txt")
        return

    table["build"] = new_build
    table["unresolved"] = unresolved
    with open(out_path, "w", encoding="utf-8", newline="\n") as out:
        json.dump(table, out, indent=2, ensure_ascii=False)
        out.write("\n")

    print(f"ported {ported} absolutes; {len(medium)} placed by neighbouring globals; "
          f"{len(changed)} functions whose body changed; {len(unresolved)} unresolved")
    for line in medium:
        print("  NEIGHBOURS", line)
    for line in changed:
        print("  CHANGED   ", line)
    for line in unresolved:
        print("  UNRESOLVED", line)


if __name__ == "__main__":
    main()
