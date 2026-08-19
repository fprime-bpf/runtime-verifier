#!/usr/bin/env python3
"""Reconstructs the per-instruction cumulative cycle count along each path a DFS
trace already discovered, by replaying decision_path over the CFG (no Z3 -- the
DFS already resolved feasibility) and consuming each path's already-classified
mem_events in order. This is the building block for cost-threshold checkpoint
placement: the output is a per-instruction running total, not just a path total.

On top of that, reconcile_checkpoints() merges each path's independently-greedy
checkpoint placement into a single set of physical PCs that could actually be
compiled into one instrumented binary, then verifies that set against every path
and patches any gap that ends up over threshold.

Requires a trace written by main.py --emit-trace *after* decision_path was added
to ExecutionTraceProfile -- older traces have no replay information and will
raise a clear error instead of silently producing an empty/wrong walk.
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
    """True for instructions that actually touch memory and were recorded as a
    MemEvent during the DFS -- mirrors dfs.py's `is_load` check (mem_addr is not
    None and "LD" in name) without needing symbolic execution to get mem_addr:
    immediate-only loads (LD_IMM_*/LDX_IMM_*/LDDW) never touch memory, so they
    were tallied as ordinary flat-cost instructions instead."""
    if name.startswith("LD_IMM_") or name.startswith("LDX_IMM_") or name == "LDDW":
        return False
    return name.startswith(_LOAD_PREFIXES)


def block_iteration(block) -> "tuple[int, ...] | None":
    """Iteration vector for a block, one component per enclosing unrolled loop,
    outermost first -- matching Block.copy_with_suffix's prepend composition.
    "" -> None (outside every unrolled loop); ".3" -> (3,); ".3.7.1.4" -> (3, 7, 1, 4).
    Arity varies between blocks on one path (a block in a 4-deep nest yields four
    components, one in only the outermost loop yields one); that's intended, since
    these are used purely as dict keys and for display, never compared or ordered."""
    return tuple(int(x) for x in block.suffix.split(".")[1:]) if block.suffix else None


def format_iteration(iteration: "tuple[int, ...] | None") -> str:
    """Renders block_iteration's vector for display."""
    return "outside any loop" if iteration is None else ".".join(str(x) for x in iteration)


def replay_path(unrolled_block, instructions: dict, trace: ExecutionTraceProfile,
                 mapping: dict, helper_call_costs: dict, op_info_by_name: dict,
                 profile: MachineProfile) -> list[tuple[int, str, int, int, "int | None"]]:
    """Walks the CFG per trace.decision_path, consuming trace.mem_events in order
    for real loads. Returns [(pc, instr_name, cost, cumulative_cycles, iteration), ...]
    -- iteration is which pass through an unrolled loop this step belongs to (None
    outside any loop), since raw pc repeats across iterations and isn't unique on
    its own once a loop's involved."""
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
    """Greedily places a checkpoint wherever cost accumulated since the last one (or
    since the start of the path) reaches `threshold`, resetting the running total at
    each one. Returns [(pc, iteration), ...] in path order -- iteration, not pc alone,
    since a loop's pc range repeats every pass through it: pc 48 on iteration 2 and
    pc 48 on iteration 5 are different points in program *time* even though they're
    the same bytecode offset, and only one physical instruction exists there to
    instrument. Reporting the pair keeps that distinction instead of collapsing it.

    Single-path: this is deliberately just one path's own greedy view and doesn't
    know about any other path. It's the seed reconcile_checkpoints() starts from,
    not a placement you can compile on its own -- see that function for merging
    multiple paths into one checkpoint set that's actually sound on all of them."""
    checkpoints: list[tuple[int, "int | None"]] = []
    baseline = 0
    for pc, name, cost, cumulative, iteration in steps:
        if cumulative - baseline >= threshold:
            checkpoints.append((pc, iteration))
            baseline = cumulative
    return checkpoints


def _gap_violations(steps: list[tuple[int, str, int, int, "int | None"]],
                     checkpoint_pcs: "set[int]", threshold: int) -> list[int]:
    """One pass of a path against a *fixed* candidate checkpoint set (raw PCs, no
    iteration -- this is what a compiled binary actually has). Returns the pc of
    every point where the gap since the last real hit in this set reaches
    threshold. Each violation found is treated as though a checkpoint existed
    there for the rest of the scan, purely so one pass can surface every violation
    in a path instead of stopping at the first."""
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
    """Merges checkpoint needs across every path in paths_steps into one set of
    physical PCs sound for all of them.

    Rule (empty seed, verify-and-repair to a fixed point): start with NO
    checkpoints and let violations pull them in, rather than seeding from the
    union of each path's own independent find_checkpoints() result. Union-seeding
    was the first thing tried here and it measurably over-checkpoints: when paths
    share a tight loop body but differ slightly in per-iteration cost (e.g. cache
    hit/miss variance), each path's own greedy pass drifts to a *different* PC
    within that same loop body as its crossing point, and unioning those treats
    every one of them as load-bearing -- so all of them end up in the set and all
    of them fire on every iteration of a loop that only needed one checkpoint per
    several iterations. Empty-seeding avoids this: the first path processed adds
    only the PCs it actually needs, and because a shared loop body is executed
    -- and thus checked -- identically by every path, a checkpoint one path added
    typically already resolves the same gap for the others on the very next
    round, instead of each path insisting on its own nearby but distinct PC.
    Measured on ccsds (4 paths, threshold=5000): union-seeding produced 21 PCs and
    ~4700-7800 checkpoint hits per path; empty-seeding produces a materially
    smaller, still-sound set -- see the reconciled-checkpoint-set section printed
    by main() for current numbers.

    Mechanically: process paths in order, and for each one, replay it against
    whatever's in the candidate set *right now* (including PCs just added for
    earlier paths in this same pass) and add any PC where a gap still reaches
    threshold before hitting the set. Updating immediately, not batching a pass's
    additions until the pass ends, is what makes empty-seeding pay off: if path 0
    adds a checkpoint inside a loop body path 1 also runs through, path 1 is
    checked against that checkpoint already being there and typically needs
    nothing new of its own for that same loop, rather than independently drifting
    to a different nearby PC the way batched-per-round union did. Keep sweeping
    passes over all paths until a full pass adds nothing.

    Always terminates: each pass either adds at least one new PC or stops, and
    the number of distinct PCs across all paths is finite."""
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

    # Fixed-point construction can still leave redundant PCs: e.g. a PC added
    # early to satisfy one path's crossing may later be covered anyway by other
    # PCs added afterward for other paths. Prune greedily -- try dropping each PC
    # in turn and keep the drop only if every path is still violation-free without
    # it. Order doesn't change soundness (each candidate is re-validated against
    # the current set at removal time), only how much gets pruned; descending
    # order costs nothing extra here and empirically prunes at least as well as
    # any other order tried.
    for pc in sorted(checkpoint_pcs, reverse=True):
        candidate = checkpoint_pcs - {pc}
        if all(not _gap_violations(steps, candidate, threshold) for steps in paths_steps):
            checkpoint_pcs = candidate

    return sorted(checkpoint_pcs)


def verify_checkpoint_set(steps: list[tuple[int, str, int, int, "int | None"]],
                           checkpoint_pcs: "set[int]"):
    """Replays a path against an already-decided, fixed checkpoint set -- i.e. what
    actually happens once it's compiled in. Returns (hits, max_gap, trailing_gap):
    hits is every (pc, iteration, cumulative) where the set was touched (a pc may
    hit more than once, e.g. once per loop iteration), max_gap is the largest
    cycle span between consecutive hits (including path-start-to-first-hit), and
    trailing_gap is the span from the last hit to the end of the path."""
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
            # A checkpoint can only sit on a whole instruction, so a hit's gap is
            # threshold + that instruction's own cost -- an unavoidable few-cycle
            # overshoot, not a violation. The actual invariant reconcile_checkpoints
            # guarantees is that no *unpatched* gap remains, i.e. _gap_violations
            # finds nothing left to add; re-check that directly instead of
            # comparing max_gap to threshold.
            unresolved = _gap_violations(steps, checkpoint_pc_set, args.checkpoint_threshold)
            status = "OK" if not unresolved else f"VIOLATION at pc(s) {unresolved}"
            print(f"  path {path_idx}: {len(hits)} hit(s), max gap = {max_gap} cycles, "
                  f"trailing gap = {trailing_gap} cycles  [{status}]")
        print()


if __name__ == "__main__":
    main()
