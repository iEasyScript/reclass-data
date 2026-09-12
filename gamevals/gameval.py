#!/usr/bin/env python3
"""gameval.py — RS3 cache ID <-> developer-name lookup over rs3-gamevals/*.json.

Each <type>.json maps numeric cache config IDs to the original RuneScape
developer ("rscm") names extracted from an OpenRS2 cache dump. This tool turns
the "magic numbers" found in binary/memory analysis (npc ids, obj/item ids, loc
ids, varbits, params, components, ...) into readable names, and back again.

Examples
--------
  # ID -> name (one type)
  ./gameval.py npc 7987                 -> sum1_ghost_erik_bonde_no_wander
  ./gameval.py obj 995                  -> coins  (etc.)
  ./gameval.py component 1473:5         -> backpack component name

  # name search (substring, case-insensitive) within a type
  ./gameval.py loc -s yew              -> all loc ids whose name contains "yew"
  ./gameval.py npc -s goblin

  # exact name -> ID within a type
  ./gameval.py obj -n coins

  # search every type at once (substring)
  ./gameval.py -s magic_logs

  # reverse a whole list of ids (e.g. from a memory dump) for one type
  ./gameval.py npc 0 1 2 7987

Types == json file stems: npc obj loc varbit var_player var_client param enum
struct component interface inv seq graphic model sound material dbrow dbtable
quest achievement category cursor headbar hitmark bas midi fontmetrics
stylesheet ui_anim ui_anim_curve var_clan var_clan_setting var_npc var_object
var_player_group  (run `./gameval.py --types` for the live list with counts).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def _path(t):
    return os.path.join(ROOT, t + ".json")


def types():
    return sorted(
        f[:-5] for f in os.listdir(ROOT)
        if f.endswith(".json") and os.path.isfile(os.path.join(ROOT, f))
    )


def load(t):
    p = _path(t)
    if not os.path.isfile(p):
        sys.exit(f"unknown type {t!r}. Run --types for the list.")
    with open(p) as fh:
        return json.load(fh)


def cmd_types():
    for t in types():
        d = load(t)
        e = d.get("entries", {})
        print(f"{t:24s} rev={d.get('revision')} count={len(e)}")


def cmd_search_all(sub):
    sub = sub.lower()
    for t in types():
        e = load(t).get("entries", {})
        hits = [(k, v) for k, v in e.items() if sub in str(v).lower()]
        if hits:
            print(f"== {t} ({len(hits)}) ==")
            for k, v in hits:
                print(f"  {k}\t{v}")


def cmd_type(t, args):
    d = load(t)
    e = d.get("entries", {})
    if args and args[0] in ("-s", "--search"):
        sub = " ".join(args[1:]).lower()
        hits = [(k, v) for k, v in e.items() if sub in str(v).lower()]
        for k, v in hits:
            print(f"{k}\t{v}")
        print(f"# {len(hits)} match(es) for {sub!r} in {t} (rev {d.get('revision')})",
              file=sys.stderr)
        return
    if args and args[0] in ("-n", "--name"):
        name = args[1] if len(args) > 1 else ""
        ids = [k for k, v in e.items() if v == name]
        for k in ids:
            print(k)
        if not ids:
            print(f"# no exact name {name!r} in {t}", file=sys.stderr)
        return
    # one or more ids -> names
    for k in args:
        v = e.get(str(k))
        print(f"{k}\t{v if v is not None else '<not found>'}")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    if argv[0] == "--types":
        cmd_types()
        return
    if argv[0] in ("-s", "--search"):
        cmd_search_all(" ".join(argv[1:]))
        return
    cmd_type(argv[0], argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
