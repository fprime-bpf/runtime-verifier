#!/usr/bin/env python3
"""Replays a DFS trace's decision_path over the CFG to get a
per-instruction cumulative cycle count per path, then greedily places
and reconciles checkpoints across all paths at a cost threshold.
Requires a trace with decision_path (main.py --emit-trace).
"""
import argparse

from dfs import (
    find_loops, unroll_loops_in_cfg, build_op_info_by_name, build_cycle_mapping,
    build_helper_call_costs, instr_name_cost, classify_mem_event_cost,
    load_trace, check_trace_soundness, ExecutionTraceProfile,
    DEFAULT_MAX_UNROLLED_BLOCKS,
)
from mem_access import _decode_instruction, _LOAD_PREFIXES
from main import read_bpf_file, get_blocks_tree
from machine_profile import MachineProfile
from profiles import PROFILES

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("filename", help="Path to raw eBPF instructions (.o) the trace was generated from")
parser.add_argument("--trace", required=True, metavar="PATH",
                     help="Trace YAML from --emit-trace (must include decision_path)")
parser.add_argument("--profile", choices=sorted(PROFILES), default="polarfire",
                     help="Target hardware profile to cost against (default: polarfire)")
parser.add_argument("--checkpoint-threshold", type=int, metavar="CYCLES", default=None,
                     help="Also compute checkpoint placement: greedily insert a checkpoint "
                          "wherever cost accumulated since the last one reaches this many "
                          "cycles, per path, then reconcile across all paths into one "
                          "checkpoint set sound for all of them -- see reconcile_checkpoints.")
parser.add_argument("--max-unrolled-blocks", type=int, default=DEFAULT_MAX_UNROLLED_BLOCKS,
                     metavar="N",
                     help=f"Refuse to unroll a CFG projected to exceed N basic blocks "
                          f"(default: {DEFAULT_MAX_UNROLLED_BLOCKS}). Must match the value the "
                          f"trace was generated under, since the CFG is rebuilt here to replay it.")


def is_real_load(name: str) -> bool:
    # True for loads that touch memory and were recorded as a
    # MemEvent. Immediate-only loads never touch memory.
    if name.startswith("LD_IMM_") or name.startswith("LDX_IMM_") or name == "LDDW":
        return False
    return name.startswith(_LOAD_PREFIXES)


def block_iteration(block) -> "tuple[int, ...] | None":
    # Iteration vector, one int per enclosing unrolled loop, outermost
    # first. None outside any loop. E.g. ".3.7" -> (3, 7).
    return tuple(int(x) for x in block.suffix.split(".")[1:]) if block.suffix else None


def format_iteration(iteration: "tuple[int, ...] | None") -> str:
    # Renders block_iteration's vector for display.
    return "outside any loop" if iteration is None else ".".join(str(x) for x in iteration)


def replay_path(unrolled_block, instructions: dict, trace: ExecutionTraceProfile,
                 mapping: dict, helper_call_costs: dict, op_info_by_name: dict,
                 profile: MachineProfile) -> list[tuple[int, str, int, int, "int | None"]]:
    # Walks the CFG per trace.decision_path, consuming trace.mem_events
    # for real loads. Returns [(pc, name, cost, cumulative, iteration)].
    events = iter(trace.mem_events)
    decisions = iter(trace.decision_path)
    block = unrolled_block
    cumulative = 0
    steps: list[tuple[int, str, int, int, "int | None"]] = []

    while True:
        iteration = block_iteration(block)
        sorted_pcs = sorted(pc for pc in instructions.keys() if block.start <= pc <= block.end)
        for pc in sorted_pcs:
            decoded = _decode_instruction(instructions[pc])
            name = decoded.name
            if name == "CALL":
                name = f"CALL_{decoded.imm}"

            if is_real_load(name):
                try:
                    event = next(events)
                except StopIteration:
                    raise ValueError(
                        f"pc={pc}: ran out of mem_events while replaying -- trace/CFG mismatch "
                        f"(wrong .o file for this trace, or trace predates a CFG/unroll change?)"
                    )
                cost = classify_mem_event_cost(event, op_info_by_name, profile)
            else:
                cost = instr_name_cost(name, mapping, helper_call_costs, profile)

            cumulative += cost
            steps.append((pc, name, cost, cumulative, iteration))

        if not block.next:
            break
        elif len(block.next) == 1:
            block = block.next[0]
        else:
            try:
                taken = next(decisions)
            except StopIteration:
                raise ValueError(
                    f"ran out of decision_path entries at a 2-successor block "
                    f"(BB {block.start}-{block.end}) -- trace/CFG mismatch."
                )
            block = block.next[0] if taken else block.next[1]

    leftover_events = sum(1 for _ in events)
    leftover_decisions = sum(1 for _ in decisions)
    if leftover_events or leftover_decisions:
        raise ValueError(
            f"replay finished with {leftover_events} unconsumed mem_events and "
            f"{leftover_decisions} unconsumed decision_path entries -- trace/CFG mismatch."
        )
    return steps


def find_checkpoints(steps: list[tuple[int, str, int, int, "int | None"]],
                      threshold: int) -> list[tuple[int, "int | None"]]:
    # Greedily places a checkpoint wherever cost since the last one
    # reaches threshold. Returns [(pc, iteration), ...] in path order;
    # one path's own view, not yet sound across paths (see
    # reconcile_checkpoints).
    checkpoints: list[tuple[int, "int | None"]] = []
    baseline = 0
    for pc, name, cost, cumulative, iteration in steps:
        if cumulative - baseline >= threshold:
            checkpoints.append((pc, iteration))
            baseline = cumulative
    return checkpoints


def _gap_violations(steps: list[tuple[int, str, int, int, "int | None"]],
                     checkpoint_pcs: "set[int]", threshold: int) -> list[int]:
    # One pass against a fixed checkpoint_pcs set. Returns every pc
    # where the gap since the last hit reaches threshold.
    violations: list[int] = []
    baseline = 0
    for pc, name, cost, cumulative, iteration in steps:
        if pc in checkpoint_pcs:
            baseline = cumulative
        elif cumulative - baseline >= threshold:
            violations.append(pc)
            baseline = cumulative
    return violations


def reconcile_checkpoints(paths_steps: list[list[tuple[int, str, int, int, "int | None"]]],
                           threshold: int) -> list[int]:
    # Merges checkpoint needs across all paths into one PC set sound
    # for all of them. Starts empty and lets violations pull PCs in
    # (not a union of each path's own find_checkpoints result, which
    # over-checkpoints when paths share a loop body but drift to
    # different crossing PCs). Updates the candidate set immediately
    # per path, not per pass, so later paths see earlier paths'
    # additions. Repeats until a full pass adds nothing.
    checkpoint_pcs: "set[int]" = set()

    while True:
        added_this_pass = False
        for steps in paths_steps:
            new_pcs = set(_gap_violations(steps, checkpoint_pcs, threshold)) - checkpoint_pcs
            if new_pcs:
                checkpoint_pcs |= new_pcs
                added_this_pass = True
        if not added_this_pass:
            break

    # Prune redundant PCs: drop each in turn, keep the drop only if
    # every path is still violation-free without it.
    for pc in sorted(checkpoint_pcs, reverse=True):
        candidate = checkpoint_pcs - {pc}
        if all(not _gap_violations(steps, candidate, threshold) for steps in paths_steps):
            checkpoint_pcs = candidate

    return sorted(checkpoint_pcs)


def verify_checkpoint_set(steps: list[tuple[int, str, int, int, "int | None"]],
                           checkpoint_pcs: "set[int]"):
    # Replays a path against a fixed checkpoint set. Returns
    # (hits, max_gap, trailing_gap): hits is every (pc, iteration,
    # cumulative) touched, max_gap the largest span between hits,
    # trailing_gap the span from the last hit to path end.
    hits: list[tuple[int, "int | None", int]] = []
    baseline = 0
    max_gap = 0
    for pc, name, cost, cumulative, iteration in steps:
        if pc in checkpoint_pcs:
            max_gap = max(max_gap, cumulative - baseline)
            hits.append((pc, iteration, cumulative))
            baseline = cumulative
    total = steps[-1][3] if steps else 0
    trailing_gap = total - baseline
    max_gap = max(max_gap, trailing_gap)
    return hits, max_gap, trailing_gap


def main():
    args = parser.parse_args()
    profile = PROFILES[args.profile]

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

        steps = replay_path(unrolled_block, instructions, trace, cycle_mapping,
                             helper_call_costs, op_info_by_name, profile)
        all_steps.append(steps)

        print(f"=== path {path_idx} ({len(trace.decision_path)} branch decisions, {len(steps)} instructions) ===")
        for pc, name, cost, cumulative, iteration in steps:
            iter_str = f" iter={format_iteration(iteration)}" if iteration is not None else ""
            print(f"  pc={pc:5d}{iter_str}  {name:16s}  +{cost:5d}  cumulative={cumulative}")
        total = steps[-1][3] if steps else 0
        print(f"  path total: {total} cycles")

        if args.checkpoint_threshold is not None:
            checkpoints = find_checkpoints(steps, args.checkpoint_threshold)
            cumulative_by_step = {(pc, iteration): cumulative for pc, _, _, cumulative, iteration in steps}
            trailing_gap = total - (cumulative_by_step[checkpoints[-1]] if checkpoints else 0)
            print(f"  per-path greedy checkpoints (threshold={args.checkpoint_threshold} cycles): {checkpoints}")
            print(f"  {len(checkpoints)} checkpoint(s), trailing gap after last checkpoint = {trailing_gap} cycles")
        print()

    if args.checkpoint_threshold is not None and all_steps:
        checkpoint_pcs = reconcile_checkpoints(all_steps, args.checkpoint_threshold)
        print(f"=== reconciled checkpoint set (threshold={args.checkpoint_threshold} cycles, "
              f"{len(all_steps)} path(s)) ===")
        print(f"  {len(checkpoint_pcs)} physical pc(s): {checkpoint_pcs}")
        checkpoint_pc_set = set(checkpoint_pcs)
        for path_idx, steps in enumerate(all_steps):
            hits, max_gap, trailing_gap = verify_checkpoint_set(steps, checkpoint_pc_set)
            # max_gap can exceed threshold by one instruction's cost;
            # check for unpatched violations directly instead.
            unresolved = _gap_violations(steps, checkpoint_pc_set, args.checkpoint_threshold)
            status = "OK" if not unresolved else f"VIOLATION at pc(s) {unresolved}"
            print(f"  path {path_idx}: {len(hits)} hit(s), max gap = {max_gap} cycles, "
                  f"trailing gap = {trailing_gap} cycles  [{status}]")
        print()


if __name__ == "__main__":
    main()
