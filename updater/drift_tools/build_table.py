"""Finish a new build's offset table from the updater's seed, the cross-build field verdicts and hand-verified values.

    python -I build_table.py <table.json> <verdicts.tsv> <overrides.json> <build label>

The table is rewritten in place. Every struct-relative field still carried from the previous build is replaced by its
verdict (or an override), and stamped with the evidence that decided it. A field whose verdict disagrees with a value
the updater derived for this build is reported and left alone; a carried field with no usable verdict is reported and
left out, so the engine fails loudly on it instead of reading through a stale offset.
"""
import csv
import json
import sys

ABSOLUTE = {"OFunctions", "OGlobal", "OInputGlobals", "OReferenceFunctions", "OVulkanGlobals"}
TRUSTED = {"STABLE", "MOVED", "MAJORITY", "INTERPOLATED"}


def main():
    path, verdict_path, override_path, label = sys.argv[1:5]
    table = json.load(open(path, encoding="utf-8"))
    verdicts = {(r["object"], r["field"]): r for r in csv.DictReader(open(verdict_path, encoding="utf-8"), delimiter="\t")}
    overrides = json.load(open(override_path, encoding="utf-8"))

    objects = table["objects"]
    conflicts, dropped, applied = [], [], 0
    for key, o in overrides.items():
        obj, field = key.split(".", 1)
        if o.get("remove"):
            if objects.get(obj, {}).pop(field, None) is not None:
                applied += 1
            continue
        objects.setdefault(obj, {})[field] = {
            "value": o["value"], "confidence": o.get("confidence", "HIGH"), "note": o["note"], "verified_build": label,
        }
        applied += 1

    for obj, fields in objects.items():
        for field, e in list(fields.items()):
            if f"{obj}.{field}" in overrides:
                continue
            if not e.get("carried_from"):
                v = verdicts.get((obj, field))
                if v and v["verdict"] in TRUSTED and v["new"] and int(v["new"], 16) != int(e["value"], 0):
                    conflicts.append(f"{obj}.{field}: updater {e['value']} vs evidence {v['new']} ({v['verdict']} {v['evidence']})")
                continue
            if obj in ABSOLUTE:
                dropped.append(f"{obj}.{field} (absolute, not re-derived)")
                del fields[field]
                continue
            v = verdicts.get((obj, field))
            if not v or v["verdict"] not in TRUSTED or not v["new"]:
                dropped.append(f"{obj}.{field} ({v['verdict'] if v else 'no verdict'})")
                del fields[field]
                continue
            moved = int(v["new"], 16) != int(e["value"], 0)
            fields[field] = {
                "value": v["new"],
                "confidence": "HIGH" if v["verdict"] in ("STABLE", "MOVED") and int(v["votes"] or 0) >= 3 else "MEDIUM",
                "note": (f"Moved from {e['value']} in {e['carried_from']}" if moved else f"Unchanged from {e['carried_from']}")
                        + f": {v['verdict'].lower()} across paired functions ({v['evidence'] or 'no direct read; ' + v['verdict'].lower()}).",
                "verified_build": label,
            }

    table["unresolved"] = []
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(table, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"overrides applied: {applied}")
    print(f"conflicts with updater-derived values ({len(conflicts)}):", *conflicts, sep="\n  ")
    print(f"left out, no usable evidence ({len(dropped)}):", *dropped, sep="\n  ")


main()
