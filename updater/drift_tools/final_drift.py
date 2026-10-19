"""Per-field verdicts for an offset table, with moved structs' votes kept away from the structs they do not belong to.

    python -I final_drift.py <table.json> <pair_accesses.tsv> <out.tsv> <Family=Obj,Obj:seed old:new,...> ...

Each family argument names objects that share one layout lineage (an entity hierarchy, say) and seed moves known to
be theirs. A family's witness groups are the (function pair, base register) groups containing one of its moves,
bootstrapped until no new move appears; its fields are judged on those groups alone. Every other field is judged on
all groups except the families' witnesses, so one struct's growth cannot be mistaken for another's.
"""
import csv
import json
import sys
from collections import Counter, defaultdict

ABSOLUTE = {"OFunctions", "OGlobal", "OInputGlobals", "OReferenceFunctions", "OVulkanGlobals"}


def verdict(d, c):
    total = sum(c.values())
    if total == 0:
        return "NONE", None, 0, ""
    top, n = c.most_common(1)[0]
    dist = " ".join(f"{k:#x}:{v}" for k, v in c.most_common(4))
    if len(c) == 1:
        return ("STABLE" if top == d else "MOVED"), top, total, dist
    if n / total >= 0.95 and total >= 10:
        return "MAJORITY", top, total, dist
    return "MIXED", top, total, dist


def main():
    table = json.load(open(sys.argv[1], encoding="utf-8"))["objects"]
    groups = defaultdict(set)
    for row in csv.reader(open(sys.argv[2], encoding="utf-8"), delimiter="\t"):
        groups[(row[0], row[1], row[3])].add((int(row[4], 16), int(row[5], 16)))

    families = []
    for spec in sys.argv[4:]:
        name, rest = spec.split("=", 1)
        objs, seeds = rest.split(":", 1)
        families.append((name, set(objs.split(",")), {tuple(int(x, 16) for x in s.split(":")) for s in seeds.split(",")}))

    family_of = {}
    family_witness = {}
    claimed = set()
    for name, objs, seeds in families:
        own = {int(e["value"], 0) for o in objs for e in table.get(o, {}).values()}
        while True:
            witness = {g for g, acc in groups.items() if acc & seeds}
            attributed = defaultdict(Counter)
            for g in witness:
                for o, n in groups[g]:
                    attributed[o][n] += 1
            grown = set(seeds)
            for d in own:
                c = attributed.get(d)
                if c and len(c) == 1 and next(iter(c)) != d and sum(c.values()) >= 2:
                    grown.add((d, next(iter(c))))
            if grown == seeds:
                break
            seeds = grown
        family_witness[name] = witness
        claimed |= witness
        for o in objs:
            family_of[o] = name
        print(f"family {name}: {len(witness)} witness groups, {len(seeds)} moves")

    rest_votes = defaultdict(Counter)
    for g, acc in groups.items():
        if g in claimed:
            continue
        for o, n in acc:
            rest_votes[o][n] += 1
    fam_votes = {}
    for name, witness in family_witness.items():
        v = defaultdict(Counter)
        for g in witness:
            for o, n in groups[g]:
                v[o][n] += 1
        fam_votes[name] = v

    out = []
    for obj, fields in table.items():
        if obj in ABSOLUTE:
            continue
        votes = fam_votes[family_of[obj]] if obj in family_of else rest_votes
        judged = {}
        for name, e in fields.items():
            try:
                d = int(e["value"], 0)
            except (ValueError, TypeError):
                continue
            if not 0 <= d < 0x100000:
                continue
            judged[name] = (d, verdict(d, votes.get(d, Counter())))
        firm = sorted((d, v[1] - d) for d, v in judged.values() if v[0] in ("STABLE", "MOVED", "MAJORITY") and v[2] >= 2)
        for name, (d, v) in judged.items():
            if v[0] == "NONE":
                below = [s for x, s in firm if x < d]
                above = [s for x, s in firm if x > d]
                if below and above and below[-1] == above[0]:
                    v = ("INTERPOLATED", d + below[-1], 0, f"neighbours both {below[-1]:+#x}")
            out.append((obj, name, hex(d), v[0], hex(v[1]) if v[1] is not None else "", v[2], v[3],
                        family_of.get(obj, "")))

    print("fields:", len(out), dict(Counter(r[3] for r in out)))
    with open(sys.argv[3], "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["object", "field", "old", "verdict", "new", "votes", "evidence", "family"])
        w.writerows(out)


main()
