#!/usr/bin/env python3
"""Computes the max cycles from reaching PC A to next reaching PC B,
across every feasible path in a trace. Reuses replay_path (see
runtime_benchmark.py) for the per-instruction cumulative-cost walk.

Matching: each B consumes the oldest not-yet-consumed A (FIFO), not
the nearest-preceding one. Gives per-iteration spans when A and B
recur together in a loop, and the true worst-case (earliest A) span
when A recurs but B is a single point after the loop. A == B yields
consecutive-occurrence gaps. Unmatched occurrences are dropped.
"""
import argparse
from collections import deque
from collections.abc import Generator
from pathlib import Path

import yaml

from dfs import (
    find_loops, unroll_loops_in_cfg, build_op_info_by_name, build_cycle_mapping,
    build_helper_call_costs, load_trace, check_trace_soundness,
    DEFAULT_MAX_UNROLLED_BLOCKS,
)
from runtime_benchmark import replay_path, format_iteration
from main import read_bpf_file, get_blocks_tree
from profiles import PROFILES

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("filename", help="Path to raw eBPF instructions (.o) the trace was generated from")
parser.add_argument("--trace", required=True, metavar="PATH",
                     help="Trace YAML from main.py --emit-trace (must include decision_path)")
parser.add_argument("--profile", choices=sorted(PROFILES), default="polarfire",
                     help="Target hardware profile to cost against (default: polarfire)")
parser.add_argument("--queries", required=True, metavar="PATH",
                     help="YAML file: {queries: [{start: PC, end: PC, name: optional}, ...]}")
parser.add_argument("--max-unrolled-blocks", type=int, default=DEFAULT_MAX_UNROLLED_BLOCKS,
                     metavar="N",
                     help=f"Refuse to unroll a CFG projected to exceed N basic blocks "
                          f"(default: {DEFAULT_MAX_UNROLLED_BLOCKS}). Must match the value the "
                          f"trace was generated under, since the CFG is rebuilt here to replay it.")


def find_gaps(steps: list[tuple[int, str, int, int, "int | None"]],
              start_pc: int, end_pc: int) -> list[tuple[int, "int | None", "int | None"]]:
    # Returns (gap_cycles, start_iteration, end_iteration) for every
    # FIFO-matched (start_pc, end_pc) pair. See module docstring.
    gaps: list[tuple[int, "int | None", "int | None"]] = []
    pending: deque[tuple[int, "int | None"]] = deque()  # oldest first

    for pc, name, cost, cumulative, iteration in steps:
        if pc == end_pc and pending:
            start_cumulative, start_iteration = pending.popleft()
            gaps.append((cumulative - start_cumulative, start_iteration, iteration))
        if pc == start_pc:
            pending.append((cumulative, iteration))

    return gaps

def findGaps1(steps: list[tuple[int, str, int, int, "int | None"]],
              start_pc: int, end_pc: int,
              disallowed: set[int]) -> list[tuple[int, "int | None", "int | None"]]:
    """Return FIFO-matched gaps that do not cross a disallowed PC.

    Encountering a disallowed instruction invalidates every unmatched start
    seen so far.  A later start can still form a valid gap, since only the
    portion of the path between the matched endpoints is constrained.
    """
    gaps: list[tuple[int, "int | None", "int | None"]] = []
    pending: deque[tuple[int, "int | None"]] = deque()

    for pc, _name, _cost, cumulative, iteration in steps:
        if pc in disallowed:
            pending.clear()
            continue
        if pc == end_pc and pending:
            start_cumulative, start_iteration = pending.popleft()
            gaps.append((cumulative - start_cumulative, start_iteration, iteration))
        if pc == start_pc:
            pending.append((cumulative, iteration))

    return gaps


def _gaps_in_steps(
    pcs: set[int],
    all_steps: list[list[tuple[int, str, int, int, "int | None"]]],
    whole_program_entry: "int | None" = None,
) -> tuple[list[tuple[int, int, int]], "int | None"]:
    """Compute constrained boundary gaps and an unconstrained entry span.

    Boundary-pair gaps may not cross another PC in ``pcs``.  The optional
    whole-program span deliberately uses :func:`find_gaps` instead, so reaching
    another boundary between the program entry and a reachable endpoint does
    not invalidate it.
    """
    boundary_gaps: list[tuple[int, int, int]] = []
    max_entry_gap: int | None = None

    for start_pc in sorted(pcs):
        for end_pc in sorted(pcs):
            if start_pc == end_pc:
                continue

            disallowed = pcs - {start_pc, end_pc}
            max_gap: int | None = None
            for steps in all_steps:
                for gap, _start_iteration, _end_iteration in findGaps1(
                    steps, start_pc, end_pc, disallowed
                ):
                    if max_gap is None or gap > max_gap:
                        max_gap = gap

                if start_pc == whole_program_entry:
                    for gap, _start_iteration, _end_iteration in find_gaps(
                        steps, start_pc, end_pc
                    ):
                        if max_entry_gap is None or gap > max_entry_gap:
                            max_entry_gap = gap

            if max_gap is not None:
                boundary_gaps.append((start_pc, end_pc, max_gap))

    return boundary_gaps, max_entry_gap

def gapsInSet(
    pcs: set[int],
    filename: Path,
    trace: Path,
    profile: str = "polarfire",
    max_unrolled_blocks: int = DEFAULT_MAX_UNROLLED_BLOCKS,
) -> Generator[tuple[int, int, int], None, None]:
    """Yield the maximum FIFO-matched gap for every reachable ordered PC pair.

    ``filename`` and ``trace`` are the same inputs accepted by the command
    line's ``filename`` argument and ``--trace`` option. ``profile`` and
    ``max_unrolled_blocks`` mirror their command-line defaults. Pairs for which
    no path reaches ``end`` after ``start`` are omitted.
    """
    gaps, _max_entry_gap = gapAnalysisInSet(
        pcs, filename, trace, profile, max_unrolled_blocks=max_unrolled_blocks
    )
    yield from gaps


def replay_steps(
    filename: Path,
    trace: Path,
    profile: str = "polarfire",
    *,
    max_unrolled_blocks: int = DEFAULT_MAX_UNROLLED_BLOCKS,
) -> list[list[tuple[int, str, int, int, "int | None"]]]:
    """Replay every feasible path once and return its cumulative-cost steps."""
    target_profile = PROFILES[profile]

    path_results, metadata = load_trace(trace)
    check_trace_soundness(metadata, target_profile)

    instructions = read_bpf_file(filename)
    first_block = get_blocks_tree(instructions)
    loop_list = find_loops(first_block, instructions)
    unrolled_block = unroll_loops_in_cfg(
        first_block, loop_list, max_unrolled_blocks=max_unrolled_blocks
    )

    op_info_by_name = build_op_info_by_name(target_profile)
    cycle_mapping = build_cycle_mapping(op_info_by_name)
    helper_call_costs = build_helper_call_costs(target_profile)
    all_steps = []
    for path_idx, path_trace in enumerate(path_results):
        if path_trace.decision_path is None:
            raise ValueError(
                f"path {path_idx} in {str(trace)!r} has no decision_path -- this trace predates "
                f"decision_path being persisted. Re-run main.py --emit-trace to regenerate it."
            )
        all_steps.append(replay_path(unrolled_block, instructions, path_trace, cycle_mapping,
                                     helper_call_costs, op_info_by_name, target_profile))

    return all_steps


def gap_analyses_in_sets(
    pc_sets: list[set[int]],
    filename: Path,
    trace: Path,
    profile: str = "polarfire",
    *,
    whole_program_entry: "int | None" = None,
    max_unrolled_blocks: int = DEFAULT_MAX_UNROLLED_BLOCKS,
) -> dict[frozenset[int], tuple[list[tuple[int, int, int]], "int | None"]]:
    """Analyze exact boundary sets while replaying the program only once.

    A gap is constrained by every other PC in its own set, so an analysis for
    a superset cannot be filtered to produce the analysis for a subset.
    Duplicate sets are analyzed once.
    """
    unique_sets = {frozenset(pcs) for pcs in pc_sets}
    if not unique_sets:
        return {}

    all_steps = replay_steps(
        filename,
        trace,
        profile,
        max_unrolled_blocks=max_unrolled_blocks,
    )
    return {
        pcs: _gaps_in_steps(set(pcs), all_steps, whole_program_entry)
        for pcs in unique_sets
    }


def gapAnalysisInSet(
    pcs: set[int],
    filename: Path,
    trace: Path,
    profile: str = "polarfire",
    *,
    whole_program_entry: "int | None" = None,
    max_unrolled_blocks: int = DEFAULT_MAX_UNROLLED_BLOCKS,
) -> tuple[list[tuple[int, int, int]], "int | None"]:
    """Return boundary gaps and the unrestricted maximum entry span."""
    return gap_analyses_in_sets(
        [pcs],
        filename,
        trace,
        profile,
        whole_program_entry=whole_program_entry,
        max_unrolled_blocks=max_unrolled_blocks,
    )[frozenset(pcs)]

def main():
    args = parser.parse_args()
    profile = PROFILES[args.profile]

    with open(args.queries) as f:
        queries = yaml.safe_load(f)["queries"]

    path_results, metadata = load_trace(args.trace)
    check_trace_soundness(metadata, profile)

    instructions = read_bpf_file(args.filename)
    first_block = get_blocks_tree(instructions)
    loop_list = find_loops(first_block, instructions)
    try:
        unrolled_block = unroll_loops_in_cfg(first_block, loop_list,
                                              max_unrolled_blocks=args.max_unrolled_blocks)
    except ValueError as e:
        parser.error(str(e))

    op_info_by_name = build_op_info_by_name(profile)
    cycle_mapping = build_cycle_mapping(op_info_by_name)
    helper_call_costs = build_helper_call_costs(profile)

    all_steps = []
    for path_idx, trace in enumerate(path_results):
        if trace.decision_path is None:
            raise ValueError(
                f"path {path_idx} in {args.trace!r} has no decision_path -- this trace predates "
                f"decision_path being persisted. Re-run main.py --emit-trace to regenerate it."
            )
        all_steps.append(replay_path(unrolled_block, instructions, trace, cycle_mapping,
                                      helper_call_costs, op_info_by_name, profile))

    known_pcs = set(instructions.keys())

    for query in queries:
        start_pc, end_pc = query["start"], query["end"]
        label = query.get("name", f"{start_pc}->{end_pc}")

        for pc in (start_pc, end_pc):
            if pc not in known_pcs:
                print(f"{label}: WARNING -- pc={pc} is not a valid instruction offset in {args.filename!r}")

        best: "tuple[int, int, int | None, int | None] | None" = None  # (gap, path_idx, start_iter, end_iter)
        for path_idx, steps in enumerate(all_steps):
            for gap, start_iteration, end_iteration in find_gaps(steps, start_pc, end_pc):
                if best is None or gap > best[0]:
                    best = (gap, path_idx, start_iteration, end_iteration)

        if best is None:
            print(f"{label}: no path ever reaches pc={end_pc} after pc={start_pc}")
        else:
            gap, path_idx, start_iteration, end_iteration = best
            start_iter_str = f"iter={format_iteration(start_iteration)}" if start_iteration is not None else "outside any loop"
            end_iter_str = f"iter={format_iteration(end_iteration)}" if end_iteration is not None else "outside any loop"
            print(f"{label}: max {gap} cycles (path {path_idx}, start {start_iter_str} -> end {end_iter_str})")


if __name__ == "__main__":
    main()
