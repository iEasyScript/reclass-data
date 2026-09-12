#!/usr/bin/env python3
"""
RS3 Binary Update Auto-Offset Pipeline

Orchestrates the full offset update process when the NXT client binary changes.
Communicates with Ghidra via headless analysis (analyzeHeadless) to run scripts.

Pipeline stages:
  0. Parse args (new binary path, old version, Ghidra project path)
  1. Detect version from binary (regex scan for RS2Engine-X-NXT-Y in .rodata)
  2. Run RS3SignatureUpdater IMPORT on new Ghidra project (transfers function names)
  3. Run RS3OffsetExporter on new project (extracts all offset values)
  4. Run RS3DataTypeExporter on OLD project, then RS3DataTypeImporter on NEW project
  5. Run RS3SignatureUpdater EXPORT on new project (saves sigs for next update)
  6. Generate Offsets.kt from extracted offset JSON
  7. Generate update report (markdown)

Usage:
  python3 update_offsets.py \\
    --new-binary /path/to/rs2client_new \\
    --old-version 946-3 \\
    --ghidra-home /opt/ghidra \\
    --project-dir /path/to/ghidra/projects \\
    --new-project-name RS3_947-1 \\
    --old-project-name RS3_946-3 \\
    [--offsets-json /path/to/precomputed/offsets.json]  # skip Ghidra, just generate Offsets.kt
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
GHIDRA_SCRIPTS_DIR = SCRIPT_DIR / "ghidra-scripts"
SIGS_RESULTS_DIR = SCRIPT_DIR / "sigs-results"
ENGINE_DIR = SCRIPT_DIR.parent / "engine"
OFFSETS_KT_PATH = ENGINE_DIR / "src" / "main" / "kotlin" / "com" / "projectx" / "game" / "nxt" / "Offsets.kt"


def detect_version_from_binary(binary_path: str) -> str | None:
    """Scan binary .rodata for RS2Engine-X-NXT-Y version string."""
    pattern = re.compile(rb"RS2Engine-(\d+)-NXT-(\d+)")
    try:
        with open(binary_path, "rb") as f:
            # Read in chunks to handle large binaries
            chunk_size = 10 * 1024 * 1024  # 10MB
            overlap = 64  # overlap to catch strings split across chunks
            prev_tail = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                search_data = prev_tail + chunk
                m = pattern.search(search_data)
                if m:
                    major = m.group(1).decode()
                    minor = m.group(2).decode()
                    return f"{major}-{minor}"
                prev_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
    except IOError as e:
        print(f"Error reading binary: {e}", file=sys.stderr)
    return None


def run_ghidra_headless(ghidra_home: str, project_dir: str, project_name: str,
                        script_name: str, script_args: list[str] | None = None,
                        import_binary: str | None = None,
                        pre_script: str | None = None,
                        post_script: str | None = None) -> subprocess.CompletedProcess:
    """Run a Ghidra script via analyzeHeadless."""
    analyze_headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.exists(analyze_headless):
        raise FileNotFoundError(f"analyzeHeadless not found at {analyze_headless}")

    cmd = [analyze_headless, project_dir, project_name]

    if import_binary:
        cmd += ["-import", import_binary]
    else:
        cmd += ["-process"]

    cmd += ["-scriptPath", str(GHIDRA_SCRIPTS_DIR)]

    if pre_script:
        cmd += ["-preScript", pre_script]

    if post_script:
        cmd += ["-postScript", post_script]
    elif script_name:
        cmd += ["-postScript", script_name]

    if script_args:
        cmd += script_args

    cmd += ["-noanalysis"]  # Skip auto-analysis if we just need script execution

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"Ghidra headless STDERR:\n{result.stderr}", file=sys.stderr)
    return result


def parse_offsets_kt(path: Path) -> dict:
    """Parse Offsets.kt into structured data preserving formatting."""
    content = path.read_text()
    lines = content.split("\n")

    objects = {}
    current_obj = None
    obj_lines = {}

    for i, line in enumerate(lines):
        # Match object declarations
        obj_match = re.match(r"^object (\w+)\s*(?:\{|\s*//.*)?$", line)
        if obj_match:
            current_obj = obj_match.group(1)
            objects[current_obj] = {}
            obj_lines[current_obj] = []
            continue

        if current_obj and line.strip() == "}":
            current_obj = None
            continue

        if current_obj:
            obj_lines.setdefault(current_obj, []).append(line)

            # Match const val declarations
            const_match = re.match(
                r"\s*const\s+val\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+)L\s*(//.*)?$",
                line
            )
            if const_match:
                name = const_match.group(1)
                value = const_match.group(2)
                comment = const_match.group(3) or ""
                objects[current_obj][name] = {
                    "value": value,
                    "comment": comment.strip(),
                    "line_index": i,
                }

    return {
        "raw_lines": lines,
        "objects": objects,
        "obj_lines": obj_lines,
    }


def generate_offsets_kt(parsed: dict, offsets_json: dict, new_version: str, output_path: Path):
    """Generate updated Offsets.kt from extracted offset JSON."""
    lines = list(parsed["raw_lines"])
    offset_data = offsets_json.get("offsets", {})
    changes = []

    # Map JSON sections to Offsets.kt object names
    section_map = {
        "OGlobal": "OGlobal",
        "OFunctions": "OFunctions",
        "OClient": "OClient",
    }

    for json_section, kt_object in section_map.items():
        if json_section not in offset_data:
            continue
        if kt_object not in parsed["objects"]:
            continue

        section = offset_data[json_section]
        kt_fields = parsed["objects"][kt_object]

        for field_name, field_info in section.items():
            if field_name not in kt_fields:
                print(f"  WARNING: {kt_object}.{field_name} in JSON but not in Offsets.kt")
                continue

            kt_entry = kt_fields[field_name]
            line_idx = kt_entry["line_index"]

            value = field_info.get("value")
            confidence = field_info.get("confidence", "MISSING")

            if value is None or confidence == "MISSING":
                # Keep old value, add UNVERIFIED tag
                old_line = lines[line_idx]
                if f"//UNVERIFIED-{new_version}" not in old_line:
                    # Strip existing version comment and add UNVERIFIED
                    stripped = re.sub(r"\s*//.*$", "", old_line)
                    lines[line_idx] = f"{stripped} //UNVERIFIED-{new_version}"
                    changes.append(f"  {kt_object}.{field_name}: UNVERIFIED (kept old value)")
                continue

            # Normalize value format
            if json_section == "OFunctions":
                # OFunctions uses 0x00xxxxxxL format (8 hex digits with leading zeros)
                hex_val = value.lower().replace("0x", "")
                formatted_value = f"0x{hex_val.zfill(8)}"
            elif json_section == "OGlobal":
                # OGlobal uses 0xXXXXXXX format (uppercase hex, no leading zeros)
                hex_val = value.upper().replace("0X", "")
                formatted_value = f"0x{hex_val}"
            else:
                # OClient uses 0xXXXXX format
                hex_val = value.upper().replace("0X", "")
                formatted_value = f"0x{hex_val}"

            # Build version tag
            if confidence == "HIGH":
                version_tag = f"//{new_version}"
            elif confidence == "MEDIUM":
                version_tag = f"//{new_version} //REVIEW"
            else:
                version_tag = f"//{new_version} //LOW-CONFIDENCE"

            # Reconstruct the line preserving formatting
            old_line = lines[line_idx]
            old_value = kt_entry["value"]

            # Calculate padding for alignment
            # Match the original line structure
            prefix_match = re.match(r"(\s*const\s+val\s+\w+\s*=\s*)", old_line)
            if prefix_match:
                prefix = prefix_match.group(1)
                # Calculate how much space the old value+L+padding+comment took
                after_prefix = old_line[len(prefix):]
                # Find where the comment starts
                comment_match = re.match(r"0x[0-9a-fA-F]+L(\s*)(//.*)?$", after_prefix)
                if comment_match:
                    padding = comment_match.group(1) or " "
                    # Adjust padding to maintain alignment
                    old_val_len = len(old_value) + 1  # +1 for L
                    new_val_len = len(formatted_value) + 1  # +1 for L
                    pad_diff = old_val_len - new_val_len
                    if len(padding) + pad_diff > 0:
                        new_padding = " " * max(1, len(padding) + pad_diff)
                    else:
                        new_padding = " "
                    new_line = f"{prefix}{formatted_value}L{new_padding}{version_tag}"
                else:
                    new_line = f"{prefix}{formatted_value}L {version_tag}"
            else:
                new_line = old_line  # fallback: keep original

            if old_value.lower() != formatted_value.lower():
                changes.append(f"  {kt_object}.{field_name}: {old_value} -> {formatted_value} ({confidence})")
            else:
                changes.append(f"  {kt_object}.{field_name}: unchanged, updated version tag")

            lines[line_idx] = new_line

    # Write output
    output_path.write_text("\n".join(lines))
    print(f"Generated {output_path}")
    print(f"Changes ({len(changes)}):")
    for c in changes:
        print(c)

    return changes


def generate_report(old_version: str, new_version: str, offsets_json: dict,
                    changes: list[str], output_path: Path):
    """Generate markdown update report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    offset_data = offsets_json.get("offsets", {})
    missing = offsets_json.get("missing", [])
    manual_review = offsets_json.get("manual_review", [])

    lines = [
        f"# Offset Update Report: {old_version} -> {new_version}",
        f"",
        f"Generated: {now}",
        f"",
        f"## Summary",
        f"",
    ]

    # Per-section stats
    for section_name in ["OGlobal", "OFunctions", "OClient"]:
        section = offset_data.get(section_name, {})
        total = len(section)
        found = sum(1 for v in section.values() if v.get("value") is not None)
        high = sum(1 for v in section.values() if v.get("confidence") == "HIGH")
        medium = sum(1 for v in section.values() if v.get("confidence") == "MEDIUM")
        lines.append(f"- **{section_name}**: {found}/{total} found ({high} HIGH, {medium} MEDIUM)")

    lines.extend([
        f"",
        f"## Changes",
        f"",
    ])

    if changes:
        for c in changes:
            lines.append(f"- {c.strip()}")
    else:
        lines.append("No changes detected.")

    lines.extend([
        f"",
        f"## Missing Offsets ({len(missing)})",
        f"",
    ])

    if missing:
        lines.append("| Name | Reason |")
        lines.append("|------|--------|")
        for m in missing:
            lines.append(f"| `{m.get('name', '?')}` | {m.get('reason', '?')} |")
    else:
        lines.append("All offsets found.")

    lines.extend([
        f"",
        f"## Manual Review ({len(manual_review)})",
        f"",
    ])

    if manual_review:
        for m in manual_review:
            lines.append(f"- **{m.get('name', '?')}**: {m.get('reason', '?')}")
            if 'candidates' in m:
                lines.append(f"  - Candidates: {m['candidates']}")
    else:
        lines.append("No items need manual review.")

    lines.append("")
    output_path.write_text("\n".join(lines))
    print(f"Report written to {output_path}")


def run_pipeline(args):
    """Execute the full update pipeline."""
    SIGS_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Stage 0: Determine versions
    old_version = args.old_version
    if args.new_version:
        new_version = args.new_version
    elif args.new_binary:
        print("Stage 0: Detecting version from binary...")
        new_version = detect_version_from_binary(args.new_binary)
        if not new_version:
            print("ERROR: Could not detect version from binary.", file=sys.stderr)
            sys.exit(1)
        print(f"  Detected: {new_version}")
    else:
        print("ERROR: Must provide --new-version or --new-binary.", file=sys.stderr)
        sys.exit(1)

    print(f"\n=== Offset Update Pipeline: {old_version} -> {new_version} ===\n")

    offsets_json_path = SIGS_RESULTS_DIR / f"offsets_{new_version}.json"

    # If pre-computed offsets JSON provided, skip Ghidra stages
    if args.offsets_json:
        print(f"Using pre-computed offsets from {args.offsets_json}")
        offsets_json_path = Path(args.offsets_json)
    elif args.ghidra_home and args.project_dir:
        # Stage 2: Run RS3SignatureUpdater IMPORT
        print("Stage 2: Importing function signatures into new project...")
        old_sigs = SIGS_RESULTS_DIR / f"sigs_{old_version}.ndjson"
        if not old_sigs.exists():
            print(f"  WARNING: Old sigs file not found: {old_sigs}", file=sys.stderr)
            print(f"  Available sig files:")
            for f in sorted(SIGS_RESULTS_DIR.glob("sigs_*.ndjson")):
                print(f"    {f.name}")
            sys.exit(1)

        result = run_ghidra_headless(
            args.ghidra_home, args.project_dir, args.new_project_name,
            "RS3SignatureUpdater.java",
        )
        print(f"  Signature import: {'OK' if result.returncode == 0 else 'FAILED'}")

        # Stage 3: Run RS3OffsetExporter
        print("Stage 3: Extracting offsets from new project...")
        result = run_ghidra_headless(
            args.ghidra_home, args.project_dir, args.new_project_name,
            "RS3OffsetExporter.java",
        )
        print(f"  Offset extraction: {'OK' if result.returncode == 0 else 'FAILED'}")

        # Stage 4: Data type export/import
        print("Stage 4: Transferring data types...")
        if args.old_project_name:
            result = run_ghidra_headless(
                args.ghidra_home, args.project_dir, args.old_project_name,
                "RS3DataTypeExporter.java",
            )
            print(f"  Data type export: {'OK' if result.returncode == 0 else 'FAILED'}")

            result = run_ghidra_headless(
                args.ghidra_home, args.project_dir, args.new_project_name,
                "RS3DataTypeImporter.java",
            )
            print(f"  Data type import: {'OK' if result.returncode == 0 else 'FAILED'}")

        # Stage 5: Export new sigs
        print("Stage 5: Exporting signatures from new project...")
        result = run_ghidra_headless(
            args.ghidra_home, args.project_dir, args.new_project_name,
            "RS3SignatureUpdater.java",
        )
        print(f"  Signature export: {'OK' if result.returncode == 0 else 'FAILED'}")
    else:
        if not offsets_json_path.exists():
            print("ERROR: No Ghidra args provided and no pre-computed offsets found.", file=sys.stderr)
            print(f"  Expected: {offsets_json_path}", file=sys.stderr)
            print(f"  Provide --ghidra-home and --project-dir for full pipeline,", file=sys.stderr)
            print(f"  or --offsets-json for code generation only.", file=sys.stderr)
            sys.exit(1)
        print(f"Using existing offsets from {offsets_json_path}")

    # Stage 6: Generate Offsets.kt
    print(f"\nStage 6: Generating Offsets.kt...")
    if not offsets_json_path.exists():
        print(f"ERROR: Offset JSON not found: {offsets_json_path}", file=sys.stderr)
        sys.exit(1)

    with open(offsets_json_path) as f:
        offsets_json = json.load(f)

    if not OFFSETS_KT_PATH.exists():
        print(f"ERROR: Offsets.kt not found: {OFFSETS_KT_PATH}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_offsets_kt(OFFSETS_KT_PATH)

    # Write to a new file (don't overwrite in-place by default)
    output_kt = OFFSETS_KT_PATH if args.in_place else SIGS_RESULTS_DIR / f"Offsets_{new_version}.kt"
    changes = generate_offsets_kt(parsed, offsets_json, new_version, output_kt)

    # Stage 7: Generate report
    print(f"\nStage 7: Generating update report...")
    report_path = SIGS_RESULTS_DIR / f"update_report_{old_version}-to-{new_version}.md"
    generate_report(old_version, new_version, offsets_json, changes, report_path)

    print(f"\n=== Pipeline Complete ===")
    print(f"  Offsets: {output_kt}")
    print(f"  Report: {report_path}")

    # Summary of what needs attention
    missing = offsets_json.get("missing", [])
    manual = offsets_json.get("manual_review", [])
    if missing or manual:
        print(f"\n  *** ATTENTION ***")
        if missing:
            print(f"  {len(missing)} offsets could not be found automatically")
        if manual:
            print(f"  {len(manual)} offsets need manual review")


def main():
    parser = argparse.ArgumentParser(
        description="RS3 Binary Update Auto-Offset Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline with Ghidra
  python3 update_offsets.py --new-binary ./rs2client --old-version 946-3 \\
    --ghidra-home /opt/ghidra --project-dir ~/ghidra-projects \\
    --new-project-name RS3_947-1 --old-project-name RS3_946-3

  # Code generation only (skip Ghidra, use pre-computed JSON)
  python3 update_offsets.py --old-version 946-3 --new-version 947-1 \\
    --offsets-json ./sigs-results/offsets_947-1.json

  # Detect version + generate code from existing offset JSON
  python3 update_offsets.py --new-binary ./rs2client --old-version 946-3
        """
    )

    parser.add_argument("--new-binary", help="Path to new RS3 binary")
    parser.add_argument("--old-version", required=True, help="Old version string (e.g., 946-3)")
    parser.add_argument("--new-version", help="New version string (auto-detected from binary if omitted)")
    parser.add_argument("--ghidra-home", help="Path to Ghidra installation")
    parser.add_argument("--project-dir", help="Path to Ghidra project directory")
    parser.add_argument("--new-project-name", help="Name of the new Ghidra project")
    parser.add_argument("--old-project-name", help="Name of the old Ghidra project (for data type transfer)")
    parser.add_argument("--offsets-json", help="Path to pre-computed offsets JSON (skip Ghidra)")
    parser.add_argument("--in-place", action="store_true",
                        help="Write Offsets.kt in-place (default: write to sigs-results/)")

    args = parser.parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
