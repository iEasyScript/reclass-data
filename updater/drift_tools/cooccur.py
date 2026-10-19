"""Attribute displacement votes to one struct by co-occurrence with known moves of that struct.

    python -I cooccur.py <pair_accesses.tsv> <seed old:new,...> [<table.json> <Object,...>]

A (function pair, base register) group that contains a seed move reads the seed's struct through that register, so
every other displacement in the group is a vote about the same struct. With a table and object names, each field of
those objects is judged on the attributed votes alone.
"""
import csv
import json
import sys
from collections import Counter, defaultdict


def main():
    groups = defaultdict(set)
    for row in csv.reader(open(sys.argv[1], encoding="utf-8"), delimiter="\t"):
        old_f, new_f, _, base, od, nd = row
        groups[(old_f, new_f, base)].add((int(od, 16), int(nd, 16)))
    seeds = {tuple(int(x, 16) for x in s.split(":")) for s in sys.argv[2].split(",")}
    seed_olds = {o for o, _ in seeds}

    attributed = defaultdict(Counter)
    witness = 0
    contradictions = Counter()
    for g, accesses in groups.items():
        if not accesses & seeds:
            if any(o in seed_olds for o, _ in accesses):
                for o, n in accesses:
                    if o in seed_olds: contradictions[(o, n)] += 1
            continue
        witness += 1
        for o, n in accesses:
            attributed[o][n] += 1
    print(f"witness groups: {witness}; seed displacements read some other way elsewhere: {dict(contradictions)}")

    if len(sys.argv) > 4:
        table = json.load(open(sys.argv[3], encoding="utf-8"))["objects"]
        for obj in sys.argv[4].split(","):
            for name, e in table.get(obj, {}).items():
                d = int(e["value"], 0)
                c = attributed.get(d, Counter())
                total = sum(c.values())
                if total == 0:
                    verdict = "NONE"
                elif len(c) == 1:
                    verdict = "STABLE" if next(iter(c)) == d else f"MOVED {next(iter(c)):#x}"
                else:
                    verdict = "MIXED " + " ".join(f"{k:#x}:{n}" for k, n in c.most_common(4))
                print(f"  {obj:16} {name:32} {d:#7x}  n={total:<4} {verdict}")
    else:
        for o in sorted(attributed):
            print(f"  {o:#7x}  " + " ".join(f"{n:#x}:{c}" for n, c in attributed[o].most_common(4)))


main()
