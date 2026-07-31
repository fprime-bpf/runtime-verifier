from __future__ import annotations
import argparse
import concurrent.futures
import contextlib
import csv
import io
import os
import sys
import time
from pathlib import Path

from main import read_bpf_file, get_blocks_tree
from dfs import (
    find_loops,
    unroll_loops_in_cfg,
    build_iter_value_map,
    dfs_blocks,
    build_op_info_by_name,
    build_cycle_mapping,
    instr_counts_to_cycles,
)
from profiles import PROFILES

TARGET_FAMILIES = ["polarfire", "noelv"]
# (csv/label suffix, PROFILES key suffix); actual == the bare target name, no suffix
MODES = [("naive", "all_miss"), ("optimistic", "all_hit"), ("actual", None)]

FIELDNAMES = ["binary"] + [
    f"{target}_{mode}_{unit}"
    for target in TARGET_FAMILIES
    for mode, _ in MODES
    for unit in ("cycles", "ms")
]


def profile_key(target: str, suffix: str | None) -> str:
    return f"{target}_{suffix}" if suffix else target


def analyze_binary(a_o_path: Path) -> dict[str, str]:
    """Runs the CFG/loop/DFS pipeline once, then re-costs the resulting
    path_results against all 6 target x mode profiles. See the plan's Context
    section for why a single DFS run (at the largest cache_size in play) is
    sufficient -- cache_size only bounds how many candidate distances get
    recorded per load; classification against each target's own thresholds
    happens later and is unaffected."""
    dfs_profile = max((PROFILES[t] for t in TARGET_FAMILIES), key=lambda p: p.cache_size)

    with contextlib.redirect_stdout(io.StringIO()):
        instructions = read_bpf_file(str(a_o_path))
        first_block = get_blocks_tree(instructions)
        loop_list = find_loops(first_block, instructions)
        unrolled = unroll_loops_in_cfg(first_block, loop_list)
        iter_value_by_call_site = build_iter_value_map(loop_list, instructions)
        path_results = dfs_blocks(unrolled, instructions, dfs_profile, iter_value_by_call_site)

    row: dict[str, str] = {}
    for target in TARGET_FAMILIES:
        for mode_label, suffix in MODES:
            variant = PROFILES[profile_key(target, suffix)]
            op_info_by_name = build_op_info_by_name(variant)
            cycle_mapping = build_cycle_mapping(op_info_by_name)
            cycles = max(
                (instr_counts_to_cycles(t, cycle_mapping, op_info_by_name, variant)
                 for t in path_results),
                default=0,
            )
            runtime_ms = cycles / variant.cpu_freq_hz * 1000
            row[f"{target}_{mode_label}_cycles"] = str(cycles)
            row[f"{target}_{mode_label}_ms"] = repr(runtime_ms)

    return row


def _run_job(name: str, a_o_path: Path) -> tuple[str, dict[str, str] | None, float, str | None]:
    """Worker-process entry point: times analyze_binary and turns any exception
    into a plain string instead of letting it propagate, since not every
    exception type (e.g. Z3Exception) is guaranteed picklable back to the
    parent process."""
    start = time.monotonic()
    try:
        row = analyze_binary(a_o_path)
        return name, row, time.monotonic() - start, None
    except Exception as e:
        return name, None, time.monotonic() - start, str(e)


def discover_binaries(tests_dir: Path) -> list[tuple[str, Path]]:
    binaries = []
    for subdir in sorted(tests_dir.iterdir()):
        a_o = subdir / "a.o"
        if subdir.is_dir() and a_o.is_file():
            binaries.append((subdir.name, a_o))
    return binaries


def main():
    parser = argparse.ArgumentParser(description="Sweep WCET estimates for every test binary across every profile")
    parser.add_argument("--tests-dir", default="/home/harry/Documents/bpf-prime/tests",
                         help="Directory containing one subdirectory per test, each with an a.o binary")
    parser.add_argument("--output", default="estimates.csv", help="Path to write the CSV to")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1,
                         help="Number of binaries to analyze in parallel (default: CPU count)")
    args = parser.parse_args()

    tests_dir = Path(args.tests_dir)
    binaries = discover_binaries(tests_dir)
    if not binaries:
        print(f"No a.o binaries found under {tests_dir}", file=sys.stderr)
        sys.exit(1)

    with open(args.output, "w", newline="") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        out_file.flush()

        with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = [executor.submit(_run_job, name, a_o_path) for name, a_o_path in binaries]

            for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                name, row_data, elapsed, error = future.result()
                row = {"binary": name}
                if error is not None:
                    print(f"[{i}/{len(binaries)}] {name}: FAILED ({error}) ({elapsed:.1f}s)", file=sys.stderr)
                    for field in FIELDNAMES:
                        if field != "binary":
                            row.setdefault(field, "ERROR")
                else:
                    row.update(row_data)
                    print(f"[{i}/{len(binaries)}] {name}: done ({elapsed:.1f}s)")
                writer.writerow(row)
                out_file.flush()

    print(f"Wrote {len(binaries)} rows to {args.output}")


if __name__ == "__main__":
    main()
