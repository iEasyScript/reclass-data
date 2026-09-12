#!/usr/bin/env python3
"""
run_updater.py — thin headless orchestrator for RS3ProjectXUpdater.java.

Replaces nothing; the 5 legacy scripts stay. This only drives the new consolidated
script via analyzeHeadless against an EXISTING Ghidra project/program.

  export:  read-only, run against the OLD binary's project. Writes re-resources/updater/updater_data_<ver>/.
  import:  run against the NEW binary's project. DEFAULT = dry-run (-readOnly, no DB writes); writes
           re-resources/updater/{results_<ver>.json, offsets/offsets_<ver>.kt, offsets/DoActionOpcodes_<ver>.kt}.
           Pass --apply to actually commit DB edits (rename/prototype/comment/label/anchor naming).

KEY: uses `-process` (operates on the already-analyzed program) — never `-import` (which would create a
fresh program and discard your work). Save is Ghidra's default; `-readOnly` opts out. The target program
must NOT be open in the Ghidra GUI during an --apply run (exclusive lock); this script detects and reports
that. Version is auto-detected from the binary (RS2Engine-X-NXT-Y).

Usage:
  ./run_updater.py export --binary /path/to/old/rs2client --project-dir <dir> --project-name <name> [--program-name <prog>]
  ./run_updater.py import [--apply] --binary /path/to/new/rs2client --project-dir <dir> --project-name <name> [--program-name <prog>]

GHIDRA: --ghidra-home, or $GHIDRA_INSTALL_DIR, or analyzeHeadless on PATH.
"""

import argparse
import os
import re
import shutil
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
GHIDRA_SCRIPTS_DIR = SCRIPT_DIR / "ghidra-scripts"
UPDATER_DIR = SCRIPT_DIR / "updater"
SCRIPT_NAME = "RS3ProjectXUpdater.java"

# Go-forward baseline chain, primary first, forwarded to RS3ProjectXUpdater as `--data-dir`. The primary
# supplies anchors, data labels and drift diffing; each later dir only back-fills names (and prototypes)
# the earlier ones lost, so a migration that dropped RE work can recover it from the build before it.
# Bump the primary to the newest updater_data_<ver> after each EXPORT, and keep the build that preceded
# Single baseline: the immediately-preceding build. Chaining an older one silently pulled
# cross-platform names onto wrong addresses; pass --data-dir explicitly if a chain is ever wanted.
IMPORT_BASELINE_DIR = "updater_data_949-5"

# The updater prints this when the DoAction walk lost an action the previous build's table carried.
# analyzeHeadless always exits 0, so the marker is the only channel a caller can gate on.
PARITY_MARKER = "*** DOACTION PARITY FAILURE"

LOCK_PATTERNS = [
    "is already open", "Unable to lock", "currently checked out", "Could not get an exclusive lock",
    "open for update by", "another process", "LockException",
]


def detect_version_from_binary(binary_path: str) -> str | None:
    """Scan binary for RS2Engine-X-NXT-Y (ported from update_offsets.py)."""
    pattern = re.compile(rb"RS2Engine-(\d+)-NXT-(\d+)")
    try:
        with open(binary_path, "rb") as f:
            chunk_size = 10 * 1024 * 1024
            overlap = 64
            prev_tail = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                m = pattern.search(prev_tail + chunk)
                if m:
                    return f"{m.group(1).decode()}-{m.group(2).decode()}"
                prev_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
    except IOError as e:
        print(f"Error reading binary: {e}", file=sys.stderr)
    return None


def find_analyze_headless(ghidra_home: str | None) -> str:
    # The support dir ships both launchers on every host, so an unqualified existence check finds the
    # POSIX shell script on Windows and hands subprocess something it cannot execute.
    launcher = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    if ghidra_home:
        p = os.path.join(ghidra_home, "support", launcher)
        if os.path.exists(p):
            return p
        raise FileNotFoundError(f"{launcher} not found under --ghidra-home {ghidra_home}")
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = os.path.join(env, "support", launcher)
        if os.path.exists(p):
            return p
    on_path = shutil.which(launcher)
    if on_path:
        return on_path
    raise FileNotFoundError(
        f"Could not locate {launcher}. Pass --ghidra-home, set $GHIDRA_INSTALL_DIR, or put it on PATH."
    )


def report_layout_growth(version: str, previous: str) -> None:
    """Print every offset object whose last field moved outward between the two builds.

    The engine sizes its read windows from the table, so a grown object needs no code change by
    itself - but any wrapper that reads an inline structure past the last declared field, or any
    literal that slipped past the WindowExtentTest, is exactly where the next silent no-op hides.
    """
    offsets_dir = UPDATER_DIR / "offsets"
    for new_path in sorted(offsets_dir.glob(f"preview-*-{version}.json")):
        platform = new_path.name[len("preview-"):-len(f"-{version}.json")]
        old_path = offsets_dir / f"preview-{platform}-{previous}.json"
        if not old_path.exists():
            print(f"[run_updater] layout growth: no {old_path.name} to compare {platform} against")
            continue
        grown = []
        old_objects = json.loads(old_path.read_text()).get("objects", {})
        new_objects = json.loads(new_path.read_text()).get("objects", {})
        for name, fields in new_objects.items():
            if name in ADDRESS_OBJECTS:
                continue
            last_new = _last_offset(fields)
            last_old = _last_offset(old_objects.get(name, {}))
            if last_new is not None and last_old is not None and last_new > last_old:
                grown.append(f"    {name}: 0x{last_old:x} -> 0x{last_new:x}")
        if grown:
            print(f"[run_updater] LAYOUT GREW on {platform} ({len(grown)} objects) - windows derive from the table, "
                  "but check inline reads past the last field and rerun the engine's WindowExtentTest:")
            print("\n".join(grown))
        else:
            print(f"[run_updater] layout growth on {platform}: none")


def _last_offset(fields: dict):
    """The outermost struct field; absolute image addresses (globals, functions) are not a layout."""
    values = []
    for raw in fields.values():
        text = raw.get("value") if isinstance(raw, dict) else raw
        try:
            value = int(str(text), 16)
        except (TypeError, ValueError):
            continue
        if value < ABSOLUTE_ADDRESS_FLOOR:
            values.append(value)
    return max(values) if values else None


ABSOLUTE_ADDRESS_FLOOR = 0x100000
ADDRESS_OBJECTS = {"OFunctions", "OGlobal", "OInputGlobals"}


def refuse_cross_platform_baseline(data_dir: str, program_name: str | None) -> None:
    """A baseline export carries one platform's signatures; scanning them against the other platform's
    program finds nothing and reports every function missing. Refuse instead of running."""
    if not program_name:
        return
    manifest_path = UPDATER_DIR / data_dir / "manifest.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text())
    source_program = str(manifest.get("source_program") or "")
    baseline_platform = "windows-x86_64" if ".exe" in source_program or "windows" in data_dir else "linux-x86_64"
    program_platform = "windows-x86_64" if ".exe" in program_name else "linux-x86_64"
    if baseline_platform != program_platform:
        raise SystemExit(
            f"refusing: baseline {data_dir} is {baseline_platform} but program {program_name} is {program_platform}; "
            f"pass --data-dir updater_data_{program_platform}-<version> (linux baselines carry no platform prefix)"
        )


def run(mode: str, args) -> int:
    binary = args.binary
    version = detect_version_from_binary(binary) if binary else None
    if binary and not version:
        print(f"WARNING: could not detect version from {binary}; the Ghidra script will re-detect from the program.",
              file=sys.stderr)

    analyze = find_analyze_headless(args.ghidra_home)

    apply = getattr(args, "apply", False)
    cmd = [analyze, args.project_dir, args.project_name, "-process"]
    if args.program_name:
        cmd.append(args.program_name)  # restrict -process to a single program
    cmd += ["-noanalysis"]
    if not (mode == "import" and apply):
        cmd += ["-readOnly"]           # headless option (BEFORE -postScript): export / import dry-run never touch the DB
    cmd += ["-scriptPath", str(GHIDRA_SCRIPTS_DIR), "-postScript", SCRIPT_NAME, mode]
    if mode == "import":
        data_dir = getattr(args, "data_dir", None) or IMPORT_BASELINE_DIR
        refuse_cross_platform_baseline(data_dir, args.program_name)
        cmd += ["--data-dir", data_dir]
        if apply:
            cmd += ["--apply"]         # script arg (AFTER script): the only path that writes the DB

    UPDATER_DIR.mkdir(parents=True, exist_ok=True)
    (UPDATER_DIR / "offsets").mkdir(parents=True, exist_ok=True)

    print(f"[run_updater] version={version} mode={mode} apply={apply}")
    print("[run_updater] " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_path = UPDATER_DIR / f"run_{mode}_{version or 'unknown'}.log"
    log_path.write_text(out)
    sys.stdout.write(proc.stdout or "")
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or "")

    if PARITY_MARKER in out:
        for line in out.splitlines():
            if PARITY_MARKER in line:
                print("\n" + line.strip(), file=sys.stderr)
        print("    The DoAction walk lost entries the previous build's table carried. Fix the walk;\n"
              "    the emitted table is incomplete and must not be applied.", file=sys.stderr)
        return 3

    if any(p.lower() in out.lower() for p in LOCK_PATTERNS):
        print("\n*** Ghidra could not get an exclusive lock on the program. ***", file=sys.stderr)
        print("    Close the program (and its project) in the Ghidra GUI, then re-run.", file=sys.stderr)
        return 2

    if mode == "import" and version:
        report_layout_growth(version, Path(getattr(args, "data_dir", None) or IMPORT_BASELINE_DIR).name.replace("updater_data_", ""))

    print(f"[run_updater] log: {log_path}")
    if mode == "export":
        print(f"[run_updater] export output dir: {UPDATER_DIR / ('updater_data_' + (version or '<ver>'))}")
    else:
        print(f"[run_updater] results: {UPDATER_DIR / ('results_' + (version or '<ver>') + '.json')}")
        print(f"[run_updater] offsets: {UPDATER_DIR / 'offsets'}")
        if not apply:
            print("[run_updater] (dry-run — no DB changes were saved; pass --apply to commit)")
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description="Headless runner for RS3ProjectXUpdater")
    sub = ap.add_subparsers(dest="mode", required=True)
    for m in ("export", "import"):
        sp = sub.add_parser(m)
        sp.add_argument("--binary", help="Path to the binary (for version detection / naming)")
        sp.add_argument("--project-dir", required=True, help="Ghidra project location (the .gpr's dir)")
        sp.add_argument("--project-name", required=True, help="Ghidra project name")
        sp.add_argument("--program-name", help="Program name within the project (restricts -process)")
        sp.add_argument("--ghidra-home", help="Ghidra install dir (else $GHIDRA_INSTALL_DIR or PATH)")
        if m == "import":
            sp.add_argument("--apply", action="store_true",
                            help="Commit DB edits. Default is dry-run (read-only). Program must be CLOSED in the GUI.")
            sp.add_argument("--data-dir",
                            help=f"Comma-separated baseline chain, primary first (default: {IMPORT_BASELINE_DIR})")
    args = ap.parse_args()
    sys.exit(run(args.mode, args))


if __name__ == "__main__":
    main()
