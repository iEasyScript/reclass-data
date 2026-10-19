"""Score how alike two builds' decompilations of a candidate pair are, once numbers and generated names are masked.

    python -I decomp_compare.py <old addr>:<new addr> [...]

Reads the old program on :8081 and the new one on :8080. A ratio near 1 means the same code with moved constants
and offsets; a low one means a different function.
"""
import difflib
import json
import re
import sys
import urllib.parse
import urllib.request

OLD, NEW = "http://127.0.0.1:8081", "http://127.0.0.1:8080"
GENERATED = re.compile(r"\b(?:FUN|DAT|LAB|PTR|uVar|iVar|lVar|cVar|bVar|pHVar|pcVar|plVar|puVar|piVar|local|param|in_|unaff|extraout|switchD|caseD|thunk)_?[0-9a-zA-Z_]*\b")
NUMBER = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+\b")


def decompile(base, addr):
    url = f"{base}/decompile_function?" + urllib.parse.urlencode({"address": addr})
    with urllib.request.urlopen(url, timeout=180) as r:
        text = r.read().decode("utf-8", "replace")
    try:
        text = json.loads(text).get("result", text)
    except ValueError:
        pass
    return text


def normalise(code):
    code = GENERATED.sub("ID", code)
    code = NUMBER.sub("N", code)
    return [line.strip() for line in code.splitlines() if line.strip()]


def main():
    for pair in sys.argv[1:]:
        old, new = pair.split(":")
        a, b = decompile(OLD, old), decompile(NEW, new)
        na, nb = normalise(a), normalise(b)
        ratio = difflib.SequenceMatcher(None, na, nb).ratio()
        calls_a = sorted(set(re.findall(r"\b([A-Za-z_][\w:]*[A-Za-z]\w*)\(", a)) - {"if", "while", "for", "switch", "return"})
        calls_b = sorted(set(re.findall(r"\b([A-Za-z_][\w:]*[A-Za-z]\w*)\(", b)) - {"if", "while", "for", "switch", "return"})
        named = [c for c in calls_a if not c.startswith(("FUN_", "LAB_"))]
        shared = [c for c in named if c in calls_b]
        print(f"{old} -> {new}: lines {len(na)}/{len(nb)}  similarity {ratio:.2f}  named calls shared {len(shared)}/{len(named)} {shared[:6]}")


main()
