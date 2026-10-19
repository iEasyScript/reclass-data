"""Per-struct layout evidence: how many function groups read a struct's fields unchanged, and how many read them
all shifted by one amount.

    python -I struct_support.py <table.json> <pair_accesses.tsv>

A group supports "stable" for struct S when it touches at least two of S's field offsets, all unchanged, and nothing
else in the group moved. It supports "shifted by k" when at least two of S's field offsets appear and every one of
them moved by k. Offsets read more than COMMON_LIMIT times across all pairs are left out: every struct has them, so they identify nothing.
"""
import csv
import json
import sys
from collections import Counter, defaultdict

COMMON_LIMIT = 1500
ABSOLUTE = {"OFunctions", "OGlobal", "OInputGlobals", "OReferenceFunctions", "OVulkanGlobals"}


def main():
    table = json.load(open(sys.argv[1], encoding="utf-8"))["objects"]
    groups = defaultdict(set)
    reads = Counter()
    for row in csv.reader(open(sys.argv[2], encoding="utf-8"), delimiter="\t"):
        groups[(row[0], row[1], row[3])].add((int(row[4], 16), int(row[5], 16)))
        reads[int(row[4], 16)] += 1

    for obj, fields in sorted(table.items()):
        if obj in ABSOLUTE:
            continue
        own = set()
        for e in fields.values():
            try:
                d = int(e["value"], 0)
            except (ValueError, TypeError):
                continue
            if 0x10 < d < 0x100000 and reads[d] <= COMMON_LIMIT:
                own.add(d)
        if len(own) < 2:
            print(f"{obj:28} too few distinctive fields to judge ({len(own)})")
            continue
        stable = 0
        shifted = Counter()
        for acc in groups.values():
            mine = [(o, n) for o, n in acc if o in own]
            if len({o for o, _ in mine}) < 2:
                continue
            shifts = {n - o for o, n in mine}
            if shifts == {0}:
                if all(n == o for o, n in acc):
                    stable += 1
            elif len(shifts) == 1:
                shifted[next(iter(shifts))] += 1
        moved = " ".join(f"{k:+#x}:{v}" for k, v in shifted.most_common(4))
        flag = "CHECK" if shifted and sum(shifted.values()) * 4 >= max(stable, 1) else ("weak" if shifted else "")
        print(f"{obj:28} stable={stable:<5} shifted=[{moved}] {flag}")


main()
