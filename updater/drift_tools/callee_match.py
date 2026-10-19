"""Find where a function moved to by the company it keeps: map its call targets across builds and see which new
function calls most of them.

    python -I callee_match.py <function_pairs.tsv> <address_votes.tsv> <old addr> [<old addr> ...]

Reads the old program on :8081 and the new one on :8080 (the headless GhidraMCP host). A function whose own body
changed still calls functions that did not, so its mapped callee set points at it even when no signature matches.
"""
import csv
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

OLD, NEW = "http://127.0.0.1:8081", "http://127.0.0.1:8080"
CALL = re.compile(r"^\s*([0-9a-fA-F]+):\s+CALL\s+(?:0x)?([0-9a-fA-F]+)\b", re.M)
CALLER = re.compile(r"From ([0-9a-fA-F]+) in (\S+) \[(?:UNCONDITIONAL_CALL|CONDITIONAL_CALL|COMPUTED_CALL)")


def get(base, path, **params):
    url = f"{base}/{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read().decode("utf-8", "replace")


def callees(base, addr):
    return [int(t, 16) for _, t in CALL.findall(get(base, "disassemble_function", address=hex(addr)))]


def callers(base, addr):
    return CALLER.findall(get(base, "xrefs_to", address=hex(addr), limit=2000))


def main():
    mapping = {int(r[0], 16): int(r[1], 16) for r in csv.reader(open(sys.argv[1], encoding="utf-8"), delimiter="\t")}
    votes = defaultdict(Counter)
    for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"), delimiter="\t"):
        if r["kind"] == "CALL":
            votes[int(r["old"], 16)][int(r["new"], 16)] += int(r["votes"])
    for old, c in votes.items():
        mapping.setdefault(old, c.most_common(1)[0][0])

    for raw in sys.argv[3:]:
        old = int(raw, 16)
        targets = set(callees(OLD, old))
        mapped = {mapping[t] for t in targets if t in mapping}
        score = Counter()
        for t in mapped:
            for fn in {fn for _, fn in callers(NEW, t)}:
                score[fn] += 1
        best = score.most_common(4)
        print(f"{old:#x}: {len(targets)} callees, {len(mapped)} mapped; candidates: "
              + ", ".join(f"{fn} ({n}/{len(mapped)})" for fn, n in best))


main()
