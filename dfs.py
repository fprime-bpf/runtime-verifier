import hashlib
import itertools
import os
import yaml
from dataclasses import dataclass, replace as replace_profile
from block import Block
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from machine_profile import MachineProfile
from mem_access import process_instruction, State, MemEvent, fresh_gp_var, fresh_fp_var, get_all_var_names, get_vars_from_expr, \
    normalize_huge_bv
from z3 import Solver, sat, unsat, BoolRef, Not, unknown, Z3Exception, simplify
from collections import deque
from typing import Optional, Set

# All cache/latency/helper-call-cost tuning now lives on a per-target MachineProfile
# (see profiles/) rather than module-level constants -- this file has no built-in
# notion of "the" hardware target, only how to apply whichever profile it's given.

# Load instructions are NOT tallied into a path's hist during the DFS. Their cost depends
# on cache locality, which depends on a target cache profile (line size, associativity)
# that isn't chosen yet at DFS time — so each load is instead recorded as a MemEvent
# (see mem_access.py), carrying its address and the path's last profile.cache_size prior
# memory addresses. A later realization pass (mem_events_to_cycles) replays these against
# a specific profile to classify each as an L1/L2/L3 hit or a miss and fold it into the
# histogram. Stores still update the recency window (`"LD" in name` distinguishes the
# two, same predicate as before), but go straight into hist under their plain name, same
# as any other profile-independent instruction.

# CALL instructions get their histogram key suffixed with their helper ID too:
# "CALL_<imm>" instead of a single shared "CALL" bucket. Helper-specific cost is looked
# up from a map (keyed by imm, not the full instruction name) built from
# profile.miss_cycles/default_helper_call_cost in instr_counts_to_cycles -- imm 1/2/3
# are bpf_map_lookup_elem/update_elem/delete_elem (see create_test/bpf_shim.h), which
# touch a map's backing memory, so they're priced like a cache miss; imm 5/6/7 are
# bpf_iter_num_new/_next/_destroy, which are genuinely trivial (no mutex, no
# container) and get their own measured-cheap fields instead. Any other helper ID
# (bpf_rand_int, bpf_math_sqrt/sin/cos/atan2, ...) falls back to
# profile.default_helper_call_cost -- still an unmeasured flat guess.


def is_fpu_instr(instr: BpfInstruction) -> bool:
    cls_ = instr.get_class()

    raw = instr._to_int(instr.instruction)
    offset_u = (raw & Mask.OFFSET) >> Shift.OFFSET
    imm_u = (raw & Mask.IMM) >> Shift.IMM

    # FPU Arithmetic: ALU / ALU64 + offset bit1=1
    if cls_ in (BpfClass.ALU, BpfClass.ALU64):
        f_flag = (offset_u >> 1) & 0x1
        return f_flag == 1

    # FPU Branch: JMP / JMP32 + Not CALL/EXIT + imm bit1=1
    if cls_ in (BpfClass.JMP, BpfClass.JMP32):
        code = instr.opcode & Mask.CODE

        # Exclude CALL and EXIT
        if code in (BpfCode.JMP.CALL, BpfCode.JMP.EXIT):
            return False

        imm_bit1 = (imm_u >> 1) & 0x1
        return imm_bit1 == 1

    return False


def build_op_info_by_name(profile: MachineProfile) -> dict[str, MachineProfile]:
    """Builds a name-keyed MachineProfile table from BPF_INFO/BPF_INFO_FPU's base
    latencies and the given target profile. Each instruction's copy inherits every
    cache/global field from `profile` (line size, associativity, hit/miss cycles,
    cpu_freq_hz, cache_size, default_helper_call_cost, latency_overrides -- the last
    four are simply unused at this per-instruction granularity) and only overrides
    name+latency, substituting `profile.latency_overrides[name]` when present."""
    return {
        instr.name: replace_profile(
            profile,
            name=instr.name,
            latency=profile.latency_overrides.get(instr.name, instr.latency),
        )
        for instr in list(BPF_INFO.values()) + list(BPF_INFO_FPU.values())
    }


def build_cycle_mapping(op_info_by_name: dict[str, MachineProfile]) -> dict[str, int]:
    """Builds an instruction-name -> cycle-cost mapping from build_op_info_by_name's
    result, which already has each instruction's final (override-applied) latency for
    the chosen target. Load instruction costs are handled separately by
    mem_events_to_cycles and are not included here."""
    return {
        name: op.latency
        for name, op in op_info_by_name.items()
        if op.latency is not None
    }


def classify_mem_event_cost(
    event: MemEvent,
    op_info_by_name: dict[str, MachineProfile],
    profile: MachineProfile,
) -> int:
    """Converts a single pending load MemEvent into a cycle cost using the cache profile
    bundled into its instruction's MachineProfile. Assumes an inclusive cache hierarchy.

    Filters distances to same-line accesses (addr_delta < line_size_bytes), takes the
    minimum recency among those, then classifies into L1/L2/L3/miss by comparing against
    each level's associativity threshold. Falls back to the target `profile`'s fields
    when the instruction's MachineProfile has no cache profile set (in practice
    unreachable today, since build_op_info_by_name always populates every instruction
    from `profile` -- kept as defensive handling for `op is None`).

    profile.cache_mode short-circuits this classification entirely: "always_hit" charges
    L1_hit_cycles and "always_miss" charges miss_cycles, regardless of recency/associativity
    or whether a same-line entry was even found -- these are the best-/worst-case bounding
    profiles (see profiles/polarfire.py's *_ALL_HIT_PROFILE/*_ALL_MISS_PROFILE), not just
    extreme tuning of the realistic model.
    """
    op = op_info_by_name.get(event.load_name)

    l1_cost   = op.l1_hit_cycles if op and op.l1_hit_cycles is not None else profile.l1_hit_cycles
    miss_cost = op.miss_cycles   if op and op.miss_cycles   is not None else profile.miss_cycles

    if profile.cache_mode == "always_hit":
        return l1_cost
    if profile.cache_mode == "always_miss":
        return miss_cost

    line_size = op.line_size_bytes  if op and op.line_size_bytes  is not None else profile.line_size_bytes
    l1_assoc  = op.l1_associativity if op and op.l1_associativity is not None else profile.l1_associativity
    l2_cost   = op.l2_hit_cycles    if op and op.l2_hit_cycles    is not None else profile.l2_hit_cycles
    l3_cost   = op.l3_hit_cycles    if op and op.l3_hit_cycles    is not None else profile.l3_hit_cycles

    same_line = sorted(recency for addr_delta, recency in event.distances
                       if addr_delta < line_size)

    cost = miss_cost
    for recency in same_line:
        if recency < l1_assoc:
            cost = l1_cost
        elif op and op.l2_associativity is not None and recency < op.l2_associativity:
            cost = l2_cost
        elif op and op.l3_associativity is not None and recency < op.l3_associativity:
            cost = l3_cost
        break  # sorted ascending: first entry is the minimum; no subsequent entry can do better

    return cost


def mem_events_to_cycles(
    mem_events: list[MemEvent],
    op_info_by_name: dict[str, MachineProfile],
    profile: MachineProfile,
) -> int:
    """Sums classify_mem_event_cost over a path's pending load MemEvents."""
    return sum(classify_mem_event_cost(event, op_info_by_name, profile) for event in mem_events)


@dataclass
class ExecutionTraceProfile:
    """Per-path DFS output: what a single feasible program path actually does,
    decoupled from which hardware costs get applied to it (see MachineProfile)."""
    instr_counts: dict[str, int]   # profile-independent instruction histogram
    mem_events: list[MemEvent]     # pending per-access load records
    decision_path: list[bool]      # True/False choice at each 2-successor branch, in order


TRACE_FORMAT_VERSION = 1


def _yaml_dumper():
    return yaml.CSafeDumper if getattr(yaml, "__with_libyaml__", False) else yaml.SafeDumper


def _yaml_loader():
    return yaml.CSafeLoader if getattr(yaml, "__with_libyaml__", False) else yaml.SafeLoader


def save_trace(path_results: list[ExecutionTraceProfile], out_path: str, *, program_path: str, dfs_cache_size: int) -> None:
    """Persists phase-1 (DFS) output so phase-2 (instr_counts_to_cycles/mem_events_to_cycles)
    can be re-run against different MachineProfiles later without re-paying the DFS cost.
    dfs_cache_size MUST be the cache_size of the profile the DFS was actually run with --
    see check_trace_soundness."""
    program_sha256 = None
    if os.path.isfile(program_path):
        with open(program_path, "rb") as pf:
            program_sha256 = hashlib.sha256(pf.read()).hexdigest()

    data = {
        "metadata": {
            "format_version": TRACE_FORMAT_VERSION,
            "program_path": str(program_path),
            "program_sha256": program_sha256,
            "dfs_cache_size": dfs_cache_size,
        },
        "paths": [
            {
                "instr_counts": dict(trace.instr_counts),
                "mem_events": [
                    {"load_name": e.load_name, "distances": [list(d) for d in e.distances]}
                    for e in trace.mem_events
                ],
                "decision_path": list(trace.decision_path),
            }
            for trace in path_results
        ],
    }
    with open(out_path, "w") as f:
        yaml.dump(data, f, Dumper=_yaml_dumper(), sort_keys=False, default_flow_style=None)


def load_trace(path: str) -> tuple[list[ExecutionTraceProfile], dict]:
    """Inverse of save_trace. Returns (path_results, metadata) -- caller must call
    check_trace_soundness(metadata, profile) before costing."""
    with open(path) as f:
        data = yaml.load(f, Loader=_yaml_loader())

    metadata = data.get("metadata", {})
    path_results = [
        ExecutionTraceProfile(
            instr_counts=dict(p["instr_counts"]),
            mem_events=[
                MemEvent(e["load_name"], [tuple(d) for d in e["distances"]])
                for e in p["mem_events"]
            ],
            # older traces (written before decision_path was persisted) have no
            # replay-path information; leave None rather than faking an empty path.
            decision_path=list(p["decision_path"]) if "decision_path" in p else None,
        )
        for p in data.get("paths", [])
    ]
    return path_results, metadata


def check_trace_soundness(metadata: dict, profile: MachineProfile) -> None:
    """Raises ValueError if `profile` might require recency-window entries a trace's DFS
    run wasn't wide enough to have recorded (dfs_blocks only ever consults profile.cache_size
    to bound State.recent_window). Sound iff the trace's dfs_cache_size >= profile.cache_size."""
    trace_cache_size = metadata.get("dfs_cache_size")
    if trace_cache_size is None:
        raise ValueError(
            "trace file has no 'dfs_cache_size' in its metadata (written by an "
            "incompatible/older tool version?); refusing to cost it."
        )
    if profile.cache_size is not None and trace_cache_size < profile.cache_size:
        raise ValueError(
            f"trace was generated with dfs_cache_size={trace_cache_size}, smaller "
            f"than --profile {profile.name!r}'s cache_size={profile.cache_size}. "
            f"This trace is UNSOUND for this profile. Re-run with --emit-trace "
            f"using a profile whose cache_size >= {profile.cache_size}."
        )


def build_helper_call_costs(profile: MachineProfile) -> dict[int, int]:
    """Maps a CALL instruction's helper-id (imm) to its per-target cycle cost."""
    return {
        1: profile.map_lookup_cycles if profile.map_lookup_cycles is not None else profile.miss_cycles,
        2: profile.map_update_cycles if profile.map_update_cycles is not None else profile.miss_cycles,
        3: profile.map_delete_cycles if profile.map_delete_cycles is not None else profile.miss_cycles,
        5: profile.iter_new_cycles if profile.iter_new_cycles is not None else profile.default_helper_call_cost,
        6: profile.iter_next_cycles if profile.iter_next_cycles is not None else profile.default_helper_call_cost,
        7: profile.iter_destroy_cycles if profile.iter_destroy_cycles is not None else profile.default_helper_call_cost,
        9: profile.math_sqrt_cycles if profile.math_sqrt_cycles is not None else profile.default_helper_call_cost,
        10: profile.math_sin_cycles if profile.math_sin_cycles is not None else profile.default_helper_call_cost,
        11: profile.math_cos_cycles if profile.math_cos_cycles is not None else profile.default_helper_call_cost,
        # 13, not 12: llvmbpf hardcodes helper index 12 as bpf_tail_call (unused in this project).
        13: profile.math_atan2_cycles if profile.math_atan2_cycles is not None else profile.default_helper_call_cost,
    }


def instr_name_cost(name: str, mapping: dict[str, int], helper_call_costs: dict[int, int], profile: MachineProfile) -> int:
    """Cost of a single non-load instruction occurrence: CALL_{imm} via helper_call_costs, everything else via `mapping`."""
    if name.startswith("CALL_"):
        imm = int(name.removeprefix("CALL_"))
        return helper_call_costs.get(imm, profile.default_helper_call_cost)
    return mapping.get(name, 0)


def instr_counts_to_cycles(
    trace: ExecutionTraceProfile,
    mapping: dict[str, int],
    op_info_by_name: dict[str, MachineProfile],
    profile: MachineProfile,
) -> int:
    """Converts a path's ExecutionTraceProfile into an estimated cycle count for the
    given target `profile`. Non-load instructions are costed via `mapping`; CALL_{imm}
    entries via a helper-cost map derived from `profile`; loads via mem_events_to_cycles."""
    helper_call_costs = build_helper_call_costs(profile)
    total = sum(count * instr_name_cost(name, mapping, helper_call_costs, profile)
                for name, count in trace.instr_counts.items())
    total += mem_events_to_cycles(trace.mem_events, op_info_by_name, profile)
    return total


def dfs_blocks(
    first_block: 'Block | None',
    instructions: dict[int, BpfInstruction],
    profile: MachineProfile,
    iter_value_by_call_site: Optional[dict[str, int]] = None,
    collect_leaves_at: Optional[int] = None,
    forced_decisions: Optional[list[bool]] = None,
) -> tuple[list[ExecutionTraceProfile], list[list[bool]]]:
    """
    Perform a depth-first search over the Block graph with Path Constraints.
    Returns (path_results, leaves): path_results is, per feasible *completed* path
    through the CFG, an ExecutionTraceProfile (a histogram of profile-independent
    instruction counts -- name -> count; everything except loads -- and the list of
    pending load MemEvents for that path). A separate realization pass
    (instr_counts_to_cycles) turns an ExecutionTraceProfile plus a chosen `profile`
    into a complete cost.

    `profile` is only consulted here for `profile.cache_size` (bounding
    state.recent_window) -- the rest of the DFS itself has no target-specific
    behavior; instruction/cache costing happens entirely in the later realization pass.

    `iter_value_by_call_site` (see build_iter_value_map) lets bpf_iter_num_next()
    calls resolve to their statically-known concrete per-iteration value instead
    of a fresh unconstrained symbol, so loop-indexed memory reuse is detectable.

    `collect_leaves_at`/`forced_decisions` split exploration across processes (see
    solve_in_parallel in main.py) without ever needing to serialize a Z3 Solver:
    every 2-successor branch appends the taken side (True/False) to
    state.decision_path, so a sequence of bools fully identifies a subtree.
    - collect_leaves_at=K: once a path's decision_path reaches length K, stop
      exploring it and record the K-bool path in `leaves` instead of recursing
      further; paths that complete in fewer than K decisions land in
      path_results as usual. Used single-threaded to enumerate independent
      subtrees to hand out to workers.
    - forced_decisions=[...]: at each 2-successor branch while
      len(state.decision_path) < len(forced_decisions), only explore the
      specified side instead of both. Used by each worker to cheaply replay
      down to its assigned leaf (re-deriving the same prefix state, not
      resuming a snapshot) before exploring the rest of that subtree normally.
    """
    if iter_value_by_call_site is None:
        iter_value_by_call_site = {}
    print("\n======DFS Start======")

    if first_block is None:
        return [], []

    leaves: list[list[bool]] = []
    onpath: Set['Block'] = set()
    path_results: list[ExecutionTraceProfile] = []  # one per completed path

    def make_solver() -> Solver:
        s = Solver()
        s.set("timeout", 1000)
        s.set("smt.relevancy", 2)
        s.set("smt.arith.nl", True)
        return s

    solver = make_solver()

    # Initialize state
    initial_state = State()

    # The stack stores tuples of: (Action_Type, *args)
    # Actions:
    # 'VISIT': Process the basic block.
    # 'EVAL_BRANCH': Handle solver pushes, branch conditions, and trigger the next VISIT.
    # 'BACKTRACK_BLOCK': Remove block from onpath (back-edge/cycle detection).
    # 'POP_SOLVER': Pop the Z3 solver state.
    stack = [('VISIT', first_block, initial_state)]

    while stack:
        item = stack.pop()
        action = item[0]

        if action == 'POP_SOLVER':
            solver.pop()

        elif action == 'BACKTRACK_BLOCK':
            _, block = item
            onpath.remove(block)

        elif action == 'EVAL_BRANCH':
            _, nxt_block, cond, nxt_state, needs_check, is_false_branch = item

            solver.push()

            if cond is not None:
                solver.add(cond)

            if needs_check:
                try:
                    result = solver.check()
                except Z3Exception:
                    result = unknown
                if result == sat or result == unknown:
                    stack.append(('POP_SOLVER',))
                    stack.append(('VISIT', nxt_block, nxt_state))
                elif result == unsat:
                    print(f"  [Pruned] Path to BB {nxt_block.start}{nxt_block.suffix} is unreachable (UNSAT).")
                    if is_false_branch:
                        print(f"Solver Statistics: {solver.statistics()}")
                    # Immediately pop since we won't schedule a VISIT
                    solver.pop()
                else:
                    raise ValueError(f"Unexpected solver result: {result}")
            else:
                # Unconditional or unchecked branch
                stack.append(('POP_SOLVER',))
                stack.append(('VISIT', nxt_block, nxt_state))

        elif action == 'VISIT':
            _, block, state = item

            # 1. Cycle detection (Back-edge)
            if block in onpath:
                print(f"Back-edge hit at BB({block.start}, {block.end}); ignoring extra iteration for now.")
                continue

            onpath.add(block)

            # Schedule the backtrack action to run AFTER all children are processed
            stack.append(('BACKTRACK_BLOCK', block))

            instr_count = block.end - block.start + 1
            print(f"\n======Visiting BB({block.start}, {block.end}){block.suffix}, instructions={instr_count}======")

            last_branch_cond: Optional[BoolRef] = None
            sorted_pcs = sorted([pc for pc in instructions.keys() if block.start <= pc <= block.end])

            for i in sorted_pcs:
                current_idx = i
                instruction = instructions[current_idx]
                unique_instr_id = f"{current_idx}{block.suffix}"

                if is_fpu_instr(instruction):
                    instr_op_info = BPF_INFO_FPU.get(instruction.opcode)
                else:
                    instr_op_info = BPF_INFO.get(instruction.opcode)
                instr_name = instr_op_info.name if instr_op_info else f"UNKNOWN_{instruction.opcode:#04x}"

                # Helper calls: key by helper ID so cost can vary per-helper downstream.
                if instr_name == "CALL":
                    instr_name = f"CALL_{instruction.imm}"

                # 2. Symbolic Execution
                iter_value = iter_value_by_call_site.get(unique_instr_id)
                branch_cond, mem_addr = process_instruction(instruction, state, unique_instr_id, iter_value)

                if branch_cond is not None:
                    last_branch_cond = branch_cond

                is_load = mem_addr is not None and instr_op_info is not None and "LD" in instr_op_info.name

                if is_load:
                    # Compute (addr_delta, recency) pairs now, while the solver has this
                    # path's full constraint set. recent_window[0] = most recent (recency 0).
                    # addr_delta is the concrete byte distance between the two addresses;
                    # symbolic pairs where we can't get a concrete delta are skipped
                    # (conservative: missed alias => predicted miss => higher cost).
                    distances = []
                    for recency, cached_addr in enumerate(state.recent_window):
                        try:
                            diff = simplify(mem_addr - cached_addr)
                            if hasattr(diff, 'as_signed_long'):
                                distances.append((abs(diff.as_signed_long()), recency))
                        except Z3Exception:
                            pass
                    state.mem_events.append(MemEvent(instr_name, distances))
                else:
                    # Everything else (ALU/branch/CALL/stores) has a profile-independent
                    # cost, so tally it directly.
                    state.hist[instr_name] = state.hist.get(instr_name, 0) + 1

                if mem_addr is not None:
                    # Both loads and stores refresh the recency window (stores populate
                    # the cache too), capped at profile.cache_size — the largest
                    # associativity we'll ever realize against. Index 0 = most recently used.
                    state.recent_window.insert(0, mem_addr)
                    if len(state.recent_window) > profile.cache_size:
                        state.recent_window.pop()

            if not block.next:
                print(f"Reaching an exit point {block.end}")
                path_results.append(ExecutionTraceProfile(dict(state.hist), list(state.mem_events), list(state.decision_path)))
            else:
                successors = block.next

                # Push successors onto the stack.
                # Remember: Stack is LIFO. To evaluate True branch first, we must push False branch first.
                if len(successors) == 1:
                    nxt = successors[0]
                    # args: action, block, cond, state, needs_check, is_false_branch
                    stack.append(('EVAL_BRANCH', nxt, last_branch_cond, state.fork(), False, False))

                elif len(successors) == 2:
                    nxt_true = successors[0]
                    nxt_false = successors[1]
                    depth = len(state.decision_path)

                    if collect_leaves_at is not None and depth >= collect_leaves_at:
                        leaves.append(list(state.decision_path))
                        continue

                    true_state = state.fork()
                    true_state.decision_path.append(True)
                    false_state = state.fork()
                    false_state.decision_path.append(False)

                    force = forced_decisions[depth] if forced_decisions is not None and depth < len(forced_decisions) else None

                    if last_branch_cond is None:
                        print("Warning: Branch with 2 successors but no condition found! Exploring both blindly.")
                        if force is not True:
                            stack.append(('EVAL_BRANCH', nxt_false, None, false_state, False, True))
                        if force is not False:
                            stack.append(('EVAL_BRANCH', nxt_true, None, true_state, False, False))
                    else:
                        # Push False branch (Not Taken) - executed second
                        if force is not True:
                            stack.append(('EVAL_BRANCH', nxt_false, Not(last_branch_cond), false_state, True, True))
                        # Push True branch (Taken) - executed first
                        if force is not False:
                            stack.append(('EVAL_BRANCH', nxt_true, last_branch_cond, true_state, True, False))

    print(f"\n======DFS Complete: {len(path_results)} feasible path(s) enumerated, {len(leaves)} leaf/leaves handed off======")
    for idx, trace in enumerate(path_results):
        print(f"  Path {idx}: {sum(trace.instr_counts.values())} non-memory instructions, "
              f"{len(trace.mem_events)} pending load(s) -> base={trace.instr_counts}")

    return path_results, leaves


class Loop:
    """
    Metadata for a natural loop in the CFG.
    """
    def __init__(self, header: Block, tail: Block, members: set[Block]):
        self.header = header
        self.tail = tail
        self.members = members
        # Pre-unroll snapshot: unroll_loops_in_cfg repairs `members` of enclosing
        # loops to point at clones, so anything needing the original block ranges
        # (build_iter_value_map, the size projection) must read this instead.
        self.original_members: set[Block] = set(members)
        # (Source, Target)
        self.entry_edges: set[tuple[Block, Block]] = set()
        self.exit_edges: set[tuple[Block, Block]] = set()
        # Loop-nesting forest (see build_loop_forest). depth 0 == outermost.
        self.parent: 'Loop | None' = None
        self.children: list['Loop'] = []
        self.depth: int = 0
        # Loop iteration metadata
        self.max_iterations: int | None = None
        # The concrete start value (w2) the iterator counts up from; iteration
        # i (0-indexed, matching the unroll suffix ".{i}") therefore returns
        # start_value + i from bpf_iter_num_next(). Used by build_iter_value_map.
        self.start_value: int | None = None
        # Track the exact instruction PCs for loop initialization
        self.call_5_pc: int | None = None
        self.w2_pc: int | None = None
        self.w3_pc: int | None = None

    def find_boundaries(self):
        """
        Populate entry and exit edges based on membership.
        """
        for member in self.members:
            # Exit: source is inside, target is outside
            for succ in member.next:
                if succ not in self.members:
                    self.exit_edges.add((member, succ))
            # Entry: source is outside, target is inside
            for pred in member.prev:
                if pred not in self.members:
                    self.entry_edges.add((pred, member))
                    
    def analyze_max_iterations(self, instructions: dict[int, 'BpfInstruction']):
        """
        Use a standard Breadth-First Search (BFS) with a queue to scan backwards 
        through the CFG. Looks for `bpf_iter_num_new` (call 0x5) and the 
        initialization of its boundary arguments (w2 and w3).
        """
        for pred_block, _ in self.entry_edges:
            
            # Initialize the BFS queue.
            # Queue element structure: 
            # (current_block, found_call_5, val_w2, val_w3, pc_call, pc_w2, pc_w3)
            bfs_queue = deque()
            bfs_queue.append((pred_block, False, None, None, None, None, None))
            
            # Keep track of visited blocks to prevent infinite loops in cyclic CFGs
            visited = set()
            
            # Start BFS traversal
            while len(bfs_queue) > 0:
                # Pop a node from the front of the queue
                (curr_block, found_call_5, val_w2, val_w3, 
                 pc_call, pc_w2, pc_w3) = bfs_queue.popleft()
                
                # Skip if we have already evaluated this block in the current path
                if curr_block in visited:
                    continue
                visited.add(curr_block)
                
                # Extract the instruction PCs for the current block and sort them 
                # in descending order (bottom-up scan because we are moving backwards)
                pcs = sorted([pc for pc in instructions.keys() 
                              if curr_block.start <= pc <= curr_block.end], reverse=True)
                
                for pc in pcs:
                    instr = instructions[pc]
                    
                    # Step 1: Look for the iterator initialization (call 0x5)
                    # Opcode 0x85 is CALL, immediate value 5 is bpf_iter_num_new
                    if getattr(instr, 'opcode', -1) == 0x85 and getattr(instr, 'imm', -1) == 5:
                        found_call_5 = True
                        pc_call = pc
                        continue
                    
                    # Step 2: Once call 0x5 is found, look upwards for w2 and w3 assignments
                    if found_call_5:
                        # Opcode 0xb4 is ALU32 | MOV | K (Assign immediate value to 32-bit register)
                        if getattr(instr, 'opcode', -1) == 0xb4:
                            if getattr(instr, 'dst', -1) == 2 and val_w2 is None:
                                val_w2 = instr.imm
                                pc_w2 = pc
                            elif getattr(instr, 'dst', -1) == 3 and val_w3 is None:
                                val_w3 = instr.imm
                                pc_w3 = pc
                        
                        # Step 3: If both w2 and w3 are successfully found, calculate and save
                        if val_w2 is not None and val_w3 is not None:
                            self.max_iterations = val_w3 - val_w2
                            self.start_value = val_w2

                            self.call_5_pc = pc_call
                            self.w2_pc = pc_w2
                            self.w3_pc = pc_w3
                            
                            print(
                                f"Loop Header {self.header.start}: Identified {self.max_iterations} max iterations.\n"
                                f"  -> w2={val_w2} at PC {self.w2_pc}, "
                                f"w3={val_w3} at PC {self.w3_pc}, call 0x5 at PC {self.call_5_pc}"
                            )
                            # Target found, exit the analysis for this entry edge
                            return 

                # Step 4: If values are not fully resolved in this block, 
                # enqueue all unvisited predecessor blocks to continue the BFS
                if curr_block.prev:
                    print(f"Traversing previous blocks")
                else:
                    print(f"Error, no prev found!")
                for prev_block in curr_block.prev:
                    if prev_block not in visited:
                        bfs_queue.append((
                            prev_block, found_call_5, val_w2, val_w3, 
                            pc_call, pc_w2, pc_w3
                        ))

def find_loops(root_block: Block, instructions: dict[int, BpfInstruction]) -> list[Loop]:
    """
    Identifies loops using Three-Color DFS and collects members via reverse traversal.
    """
    # DFS to find header and tail of loops
    visited = set()
    visiting = set()
    
    loop_list = []
    back_edges = []    # (tail, header) pairs

    def dfs(current_block: Block):
        visiting.add(current_block)
        
        for next_block in current_block.next:
            if next_block in visiting:  # Loop detected
                back_edges.append((current_block, next_block))
            elif next_block not in visited:
                dfs(next_block)
        
        visiting.remove(current_block)
        visited.add(current_block)
    dfs(root_block)

    # Create loop_list: list[loop]
    for tail, header in back_edges:
        members = {header, tail}
        stack = [tail]
        
        while stack:
            curr = stack.pop()
            for pred in curr.prev:
                if pred not in members:
                    members.add(pred)
                    stack.append(pred)
        
        new_loop = Loop(header, tail, members)
        new_loop.find_boundaries()
        new_loop.analyze_max_iterations(instructions)
        loop_list.append(new_loop)
        
    build_loop_forest(loop_list)

    return loop_list


def build_loop_forest(loop_list: list[Loop]) -> None:
    """Populates each Loop's parent/children/depth from member-set containment.

    Loop A is nested inside loop B exactly when A.members is a proper subset of
    B.members: find_loops seeds each member set with {header, tail} and then walks
    predecessors from the tail only, so the header's own predecessors are never
    explored and the set is exactly the natural loop body. A's parent is its
    smallest strict container, so a chain like 139 < 121 < 104 < 90 links up one
    level at a time rather than every ancestor claiming every descendant.
    """
    for loop in loop_list:
        containers = [other for other in loop_list
                      if other is not loop and loop.members < other.members]
        loop.parent = min(containers, key=lambda c: len(c.members)) if containers else None
        loop.children = []

    for loop in loop_list:
        if loop.parent is not None:
            loop.parent.children.append(loop)

    for loop in loop_list:
        depth, ancestor = 0, loop.parent
        while ancestor is not None:
            depth += 1
            ancestor = ancestor.parent
        loop.depth = depth

    for loop in sorted(loop_list, key=lambda l: l.depth):
        parent_desc = f"inside header {loop.parent.header.start}" if loop.parent else "outermost"
        print(f"Loop header {loop.header.start}: depth {loop.depth} ({parent_desc}), "
              f"{loop.max_iterations} iterations")


def loop_ancestors(loop: Loop) -> list[Loop]:
    """Ancestors of `loop`, outermost first (excludes `loop` itself)."""
    chain: list[Loop] = []
    ancestor = loop.parent
    while ancestor is not None:
        chain.append(ancestor)
        ancestor = ancestor.parent
    chain.reverse()
    return chain


DEFAULT_MAX_UNROLLED_BLOCKS = 500_000


def project_unrolled_block_count(root_block: 'Block | None',
                                  loop_list: list[Loop]) -> tuple[int, dict[Loop, int]]:
    """Projects how many Blocks unrolling will produce, per loop and in total.

    A loop's own body (its members minus whatever its nested children own) gets
    cloned once per iteration of itself AND of every enclosing loop, so the count
    is own_blocks * product(trip counts of the loop and its ancestors). Blocks
    outside every loop are unaffected by unrolling and pass through 1:1 -- counted
    here via a BFS over the pre-unroll graph, since project_unrolled_block_count
    is always called before unroll_loops_in_cfg touches anything. Lets
    unroll_loops_in_cfg refuse a nest that would blow up before it allocates
    anything, instead of running for hours and then OOMing.
    """
    per_loop: dict[Loop, int] = {}
    total = 0

    if root_block is not None:
        in_any_loop: set[Block] = set()
        for loop in loop_list:
            in_any_loop |= loop.original_members
        seen: set[Block] = set()
        queue = deque([root_block])
        while queue:
            block = queue.popleft()
            if block in seen:
                continue
            seen.add(block)
            queue.extend(block.next)
        total += len(seen - in_any_loop)

    for loop in loop_list:
        if loop.max_iterations is None or loop.max_iterations <= 0:
            continue

        nested: set[Block] = set()
        for child in loop.children:
            nested |= child.original_members
        own_blocks = len(loop.original_members - nested)

        factor = loop.max_iterations
        for ancestor in loop_ancestors(loop):
            if ancestor.max_iterations is not None and ancestor.max_iterations > 0:
                factor *= ancestor.max_iterations

        per_loop[loop] = own_blocks * factor
        total += own_blocks * factor

    return total, per_loop


def unroll_loops_in_cfg(root_block: Block, loop_list: list[Loop],
                         max_unrolled_blocks: 'int | None' = DEFAULT_MAX_UNROLLED_BLOCKS) -> Block:
    """
    Unrolls loops in the CFG based on the identified max_iterations.

    max_iterations is a known concrete bound, so the loop always runs its
    body exactly that many times -- there is no real choice to model at any
    iteration, including the last one. Internal (within-members) edges are
    therefore linked the same way for every iteration, and the loop's exit
    edge(s) are attached exactly once, after the *last* iteration's tail --
    never as an alternative to running that iteration's body.

    (This used to attach the exit edge to the last iteration's header as a
    second successor alongside the body, i.e. "exit instead of running the
    last iteration" -- a fork the DFS can't resolve away since nothing
    constrains it, even though it can never actually happen. That spurious
    fork multiplies across every loop in a program: a kernel with N bounded
    loops could see up to 2^N spurious path combinations from this alone,
    on top of any genuine data-dependent branching.)

    Nested loops are unrolled innermost-first. Each pass replaces its loop's
    members with fresh clones, which leaves every ancestor holding a stale
    member set pointing at blocks no longer in the graph -- so after unrolling a
    loop we repair the ancestors, swapping the originals for the clones just
    made. Boundaries are recomputed per loop for the same reason. Suffixes
    compose rather than replace (see Block.copy_with_suffix), so a block in a
    4-deep nest ends up uniquely identified as e.g. ".12.34.2.4".
    """
    projected, per_loop = project_unrolled_block_count(root_block, loop_list)
    print(f"Projected unrolled CFG size: {projected} blocks.")
    if max_unrolled_blocks is not None and projected > max_unrolled_blocks:
        worst = max(per_loop, key=per_loop.get)
        raise ValueError(
            f"Unrolling this CFG would produce ~{projected} blocks, over the "
            f"{max_unrolled_blocks} limit. Worst offender: loop at header "
            f"{worst.header.start} (depth {worst.depth}, {worst.max_iterations} iterations) "
            f"expanding to ~{per_loop[worst]} blocks once its {worst.depth} enclosing "
            f"loop(s) are unrolled. Raise --max-unrolled-blocks to proceed anyway."
        )

    # Innermost-first: an outer loop must clone its inner loops' already-unrolled
    # chain, not the original cyclic body. Siblings are disjoint, so the
    # header.start tiebreak only matters for deterministic output.
    sorted_loops = sorted(loop_list, key=lambda l: (-l.depth, -l.header.start))

    for loop in sorted_loops:
        if loop.max_iterations is None or loop.max_iterations <= 0:
            print(f"Warning: Loop at {loop.header.start} has no bound. Skipping unroll.")
            continue

        print(f"Unrolling loop at header {loop.header.start} (depth {loop.depth}) "
              f"for {loop.max_iterations} iterations.")

        # Recompute against the current graph: an inner pass may have rewired the
        # blocks these edges refer to.
        loop.entry_edges.clear()
        loop.exit_edges.clear()
        loop.find_boundaries()

        # Identify exit targets (blocks outside the loop) and entry sources. Sorted
        # because entry_edges/exit_edges are sets of Blocks whose hash includes a str:
        # iteration order varies with PYTHONHASHSEED, which would permute a block's
        # `next` list between processes -- and runtime_benchmark.py/pc_gap.py rebuild
        # this CFG in a fresh process to replay decision_path against next[0]/next[1].
        block_key = lambda b: (b.start, b.end, b.suffix)
        exit_targets = sorted((exit_target for _, exit_target in loop.exit_edges), key=block_key)
        entry_sources = sorted((entry_source for entry_source, _ in loop.entry_edges), key=block_key)

        prev_tail = None
        all_clones: set[Block] = set()

        # Clone the loop body (members) N times
        for i in range(loop.max_iterations):
            block_map: dict[Block, Block] = {}

            # 1. Create clones with new suffix
            for member in loop.members:
                block_map[member] = member.copy_with_suffix(f".{i}")
            all_clones.update(block_map.values())

            # 2. Re-establish connections within this iteration slice.
            # Exit edges are handled once, after the loop, not per-member.
            for member in loop.members:
                new_member = block_map[member]
                for succ in member.next:
                    if succ in loop.members:
                        if succ == loop.header:
                            continue
                        # Internal link to new blocks, disconnect back edges
                        new_member.add(block_map[succ])

            # Link the previous iteration's tail to this iteration's header
            if i == 0:
                for entry_source in entry_sources:
                    entry_source.remove_edge(loop.header)
                    entry_source.add(block_map[loop.header])
            else:
                prev_tail.add(block_map[loop.header])

            prev_tail = block_map[loop.tail]

        # The loop always exits after the last iteration's tail runs --
        # attach the exit edge(s) there, unconditionally.
        for exit_target in exit_targets:
            prev_tail.add(exit_target)

        # This loop's originals are now retired -- fully detach them (both edge
        # directions), or they linger as stale predecessors/successors that a
        # later (ancestor) find_boundaries() pass would misread as still live.
        # Without this, an ancestor's entry_sources can include an orphaned
        # original whose `.next` was never updated, crashing the next loop's
        # `entry_source.remove_edge(loop.header)` on a header that was already
        # replaced by clones two levels down.
        for member in loop.members:
            member.detach()

        # Every enclosing loop must see the clones instead of the (now detached)
        # originals, or its own pass would clone blocks no longer in the graph
        # and lose the unrolled inner chain entirely.
        for ancestor in loop_ancestors(loop):
            ancestor.members = (ancestor.members - loop.members) | all_clones

    return root_block


BPF_CALL_OPCODE = 0x85
BPF_ITER_NEXT_HELPER_ID = 6


def build_iter_value_map(loop_list: list[Loop], instructions: dict[int, BpfInstruction]) -> dict[str, int]:
    """
    For every bpf_iter_num_next() (CALL imm=6) call site inside a loop that
    was successfully bounded and unrolled, maps that call's per-iteration
    unique_instr_id (pc + unroll suffix, e.g. "68.3") to the concrete
    loop-counter value it returns on that iteration (loop.start_value + i).

    Feed this into dfs_blocks so process_instruction can model each
    unrolled call's result concretely instead of as a fresh unconstrained
    symbol -- see process_instruction's CALL handling for why that matters
    (it's what lets loop-indexed array/table accesses be recognized as
    aliasing/reusing across iterations rather than every access looking
    like an unrelated fresh address).
    """
    result: dict[str, int] = {}

    def is_iter_next(pc: int) -> bool:
        instr = instructions.get(pc)
        return (getattr(instr, "opcode", -1) == BPF_CALL_OPCODE
                and getattr(instr, "imm", -1) == BPF_ITER_NEXT_HELPER_ID)

    bounded = [loop for loop in loop_list
               if loop.max_iterations is not None and loop.max_iterations > 0
               and loop.start_value is not None]

    def unrolled_ancestors(loop: Loop) -> list[Loop]:
        return [a for a in loop_ancestors(loop) if a in bounded]

    def keys_for(pc: int, chain: list[Loop]):
        """One key per combination of iteration indices along `chain` (outermost first),
        matching the suffix Block.copy_with_suffix composes during unrolling."""
        for combo in itertools.product(*(range(l.max_iterations) for l in chain)):
            yield f"{pc}" + "".join(f".{k}" for k in combo), combo

    # Claim each loop's one-time priming bpf_iter_num_next() FIRST. It sits between
    # that loop's bpf_iter_num_new and its header -- which puts it inside the PARENT's
    # body, so a naive "blocks this loop owns" scan would hand it to the parent and
    # map it to the parent's counter. Worse, the key shapes coincide exactly (the
    # child's priming call has one suffix component per ancestor; the parent's own
    # call sites have one per ancestor plus its own index, and the child has exactly
    # one more ancestor than the parent) -- so the collision is silent.
    priming_owner: dict[int, Loop] = {}
    for loop in bounded:
        if loop.call_5_pc is None:
            continue
        # Nearest call site BEFORE the header, not the first in range: call_5_pc is
        # only as good as analyze_max_iterations' backwards BFS, which for a second
        # sibling loop can walk past its own bpf_iter_num_new and report an earlier
        # loop's (cfdp_chunk reports 55 for both of its loops). That widens the range
        # to cover earlier loops' call sites, and the priming call is the last one.
        candidates = sorted(pc for pc in instructions
                            if loop.call_5_pc < pc < loop.header.start and is_iter_next(pc))
        if candidates:
            priming_owner[candidates[-1]] = loop

    # Every other call site belongs to the INNERMOST loop whose (pre-unroll) members
    # contain its block: a nested loop's blocks are a subset of its parent's, so
    # depth breaks the tie.
    innermost_by_block: dict[Block, Loop] = {}
    for loop in bounded:
        for block in loop.original_members:
            current = innermost_by_block.get(block)
            if current is None or loop.depth > current.depth:
                innermost_by_block[block] = loop

    in_loop_owner: dict[int, Loop] = {}
    for block, loop in innermost_by_block.items():
        for pc in range(block.start, block.end + 1):
            if pc in instructions and is_iter_next(pc) and pc not in priming_owner:
                in_loop_owner[pc] = loop

    # An in-loop call site carries one suffix component per unrolled ancestor plus
    # its own iteration index; the value depends only on that own index, since
    # bpf_iter_num_new re-initializes the iterator on every pass through the
    # enclosing loops.
    for pc, loop in sorted(in_loop_owner.items()):
        chain = unrolled_ancestors(loop) + [loop]
        for key, combo in keys_for(pc, chain):
            result[key] = loop.start_value + combo[-1]

    # The priming call always succeeds once max_iterations is known positive --
    # concretize it too, or the DFS treats "loop runs zero times" as an open
    # question and wastes a full explore-then-backtrack on a hypothesis the
    # unrolling above already ruled out. Its key carries the ancestors' components
    # but not this loop's own, since it runs before the loop body is entered.
    for pc, loop in sorted(priming_owner.items()):
        for key, _ in keys_for(pc, unrolled_ancestors(loop)):
            result[key] = loop.start_value

    return result
