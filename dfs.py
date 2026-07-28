from block import Block
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from machine_profile import MachineProfile
from mem_access import process_instruction, State, MemEvent, fresh_gp_var, fresh_fp_var, get_all_var_names, get_vars_from_expr, \
    normalize_huge_bv
from z3 import Solver, If, ULT, ULE, sat, unsat, BitVecRef, BoolRef, Not, unknown, Z3Exception, Then, simplify
from collections import deque
from typing import Optional, Set

# NOEL-V target: flat 2-level cache (L1 associativity 4, L2 up to the full
# 12-entry recency window tracked per path; no L3 tier -- see
# build_op_info_by_name below, which is what actually activates the L2 tier
# by setting l2_associativity on every op (mem_events_to_cycles leaves L2/L3
# inactive by default until a MachineProfile sets their associativity).
CACHE_LINE_DIFF = 2
COST_MEM_L1_HIT = 13
COST_MEM_L2_HIT = 100
COST_MEM_L3_HIT = COST_MEM_L2_HIT
COST_MEM_MISS = 300
CACHE_SIZE = 12

# Load instructions are NOT tallied into a path's hist during the DFS. Their cost depends
# on cache locality, which depends on a target cache profile (line size, associativity)
# that isn't chosen yet at DFS time — so each load is instead recorded as a MemEvent
# (see mem_access.py), carrying its address and the path's last CACHE_SIZE prior memory
# addresses. A later realization pass (not implemented yet) replays these against a
# specific profile to classify each as "<name>_CACHED_<d>"/"<name>_MISS" and fold it into
# the histogram. Stores still update the recency window (`"LD" in name` distinguishes the
# two, same predicate as before), but go straight into hist under their plain name, same
# as any other profile-independent instruction.

# CALL instructions get their histogram key suffixed with their helper ID too:
# "CALL_<imm>" instead of a single shared "CALL" bucket. Helper-specific cost is looked
# up from this map (keyed by imm, not the full instruction name) — separate from the
# general name -> cycles mapping so it's easy to override just the helper costs.
# imm 1/2/3 are bpf_map_lookup_elem/update_elem/delete_elem (see create_test/bpf_shim.h),
# which touch a map's backing memory, so they're priced like a cache miss, matching the
# old ad hoc special-case. Any other helper ID falls back to DEFAULT_HELPER_CALL_COST.
DEFAULT_HELPER_CALL_COSTS: dict[int, int] = {
    1: COST_MEM_MISS,
    2: COST_MEM_MISS,
    3: COST_MEM_MISS,
}
DEFAULT_HELPER_CALL_COST = 150


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


def build_op_info_by_name() -> dict[str, MachineProfile]:
    """Builds a name-keyed MachineProfile table from BPF_INFO and BPF_INFO_FPU.

    NOEL-V's cache model is flat (same L1/L2 thresholds for every load, no
    per-instruction variation), so every entry gets the same cache profile.
    l2_associativity must be set explicitly here -- mem_events_to_cycles
    leaves the L2/L3 tiers inactive (falls straight from L1 to a miss) unless
    a MachineProfile provides them; there's no module-level fallback for it
    the way there is for L1 (hardcoded to associativity 8 in that function)."""
    return {
        instr.name: MachineProfile(
            instr.name,
            instr.latency,
            line_size_bytes=CACHE_LINE_DIFF,
            l1_associativity=4,
            l1_hit_cycles=COST_MEM_L1_HIT,
            l2_associativity=CACHE_SIZE,
            l2_hit_cycles=COST_MEM_L2_HIT,
            miss_cycles=COST_MEM_MISS,
        )
        for instr in list(BPF_INFO.values()) + list(BPF_INFO_FPU.values())
    }


def build_default_cycle_mapping() -> dict[str, int]:
    """Builds a default instruction-name -> cycle-cost mapping from the static
    BPF_INFO/BPF_INFO_FPU latency tables. Load instruction costs are handled separately
    by mem_events_to_cycles and are not included here."""
    return {
        op.name: op.latency
        for op in list(BPF_INFO.values()) + list(BPF_INFO_FPU.values())
        if op.latency is not None
    }


def mem_events_to_cycles(
    mem_events: list[MemEvent],
    op_info_by_name: dict[str, MachineProfile],
) -> int:
    """Converts a path's pending load MemEvents into a cycle cost using the cache profile
    bundled into each instruction's MachineProfile. Assumes an inclusive cache hierarchy.

    For each load: filter distances to same-line accesses (addr_delta < line_size_bytes),
    take the minimum recency among those, then classify into L1/L2/L3/miss by comparing
    against each level's associativity threshold. Falls back to module-level COST_MEM_*
    constants when the MachineProfile has no cache profile set.
    """
    total = 0
    for event in mem_events:
        op = op_info_by_name.get(event.load_name)

        line_size = op.line_size_bytes  if op and op.line_size_bytes  is not None else CACHE_LINE_DIFF
        l1_assoc  = op.l1_associativity if op and op.l1_associativity is not None else 8
        l1_cost   = op.l1_hit_cycles    if op and op.l1_hit_cycles    is not None else COST_MEM_L1_HIT
        l2_cost   = op.l2_hit_cycles    if op and op.l2_hit_cycles    is not None else COST_MEM_L2_HIT
        l3_cost   = op.l3_hit_cycles    if op and op.l3_hit_cycles    is not None else COST_MEM_L3_HIT
        miss_cost = op.miss_cycles      if op and op.miss_cycles      is not None else COST_MEM_MISS

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

        total += cost
    return total


def instr_counts_to_cycles(
    histogram: dict[str, int],
    mem_events: list[MemEvent],
    mapping: dict[str, int],
    op_info_by_name: dict[str, MachineProfile],
    helper_call_costs: dict[int, int] = DEFAULT_HELPER_CALL_COSTS,
    default_helper_call_cost: int = DEFAULT_HELPER_CALL_COST,
) -> int:
    """Converts a path's instruction-count histogram and pending load MemEvents into an
    estimated cycle count. Non-load instructions are costed via `mapping`; CALL_{imm}
    entries via `helper_call_costs`; loads via mem_events_to_cycles."""
    total = 0
    for name, count in histogram.items():
        if name.startswith("CALL_"):
            imm = int(name.removeprefix("CALL_"))
            cost = helper_call_costs.get(imm, default_helper_call_cost)
        else:
            cost = mapping.get(name, 0)
        total += count * cost
    total += mem_events_to_cycles(mem_events, op_info_by_name)
    return total


def find_cache_position(curr_addr: BitVecRef, cache_list: list[BitVecRef], solver: Solver, state: State) -> int:
    """
    Finds `curr_addr`'s 0-indexed position in `cache_list` (0 = most recently used),
    using a pre-configured solver (expected to already have all path constraints asserted).
    Returns -1 if the address isn't present anywhere in the list.
    """
    for i, cached in enumerate(cache_list):
        if curr_addr.eq(cached):
            return i

    # Concrete Value Check
    if hasattr(curr_addr, 'as_long') and curr_addr.as_long() is not None:
        curr_val = curr_addr.as_long()
        for i, cached in enumerate(cache_list):
            if hasattr(cached, 'as_long') and cached.as_long() is not None:
                # Check if the difference is within the Cache Line size
                if abs(curr_val - cached.as_long()) <= CACHE_LINE_DIFF:
                    return i
        return -1

    # Symbolic Range Check
    for i, cached in enumerate(cache_list):
        solver.push()

        diff = If(ULT(curr_addr, cached),
                  cached - curr_addr,
                  curr_addr - cached)

        solver.add(ULE(diff, CACHE_LINE_DIFF))

        try:
            result = solver.check()
        except Z3Exception:
            result = unknown

        solver.pop()  # Unconditionally pop to match the push()

        if result == sat:
            return i

        if result == unknown:
            print(f"Warning: Cache check returned unknown for {curr_addr}")
            pass

    return -1


def dfs_blocks(
    first_block: 'Block | None',
    instructions: dict[int, BpfInstruction],
    iter_value_by_call_site: Optional[dict[str, int]] = None,
) -> list[tuple[dict[str, int], list[MemEvent]]]:
    """
    Perform a depth-first search over the Block graph with Path Constraints.
    Returns, per feasible path through the CFG: a histogram of profile-independent
    instruction counts (name -> count; everything except loads), and the list of pending
    load MemEvents for that path. A separate realization pass (not implemented yet) turns
    (histogram, mem_events) plus a chosen cache profile into a complete cost.

    `iter_value_by_call_site` (see build_iter_value_map) lets bpf_iter_num_next()
    calls resolve to their statically-known concrete per-iteration value instead
    of a fresh unconstrained symbol, so loop-indexed memory reuse is detectable.
    """
    if iter_value_by_call_site is None:
        iter_value_by_call_site = {}
    print("\n======DFS Start======")

    if first_block is None:
        return []

    onpath: Set['Block'] = set()
    path_results: list[tuple[dict[str, int], list[MemEvent]]] = []  # (hist, mem_events) per completed path

    def make_solver() -> Solver:
        s = Solver()
        s.set("timeout", 1000)
        s.set("smt.relevancy", 2)
        s.set("smt.arith.nl", True)
        return s

    solver = make_solver()

    # A long DFS trace (many chained loops, each individually cheap) makes
    # each solver.check() progressively more expensive even when the
    # *logical* set of active assertions at any moment stays modest --
    # incremental z3 solvers accumulate internal search state (e.g. learned
    # clauses) across calls that push()/pop() alone doesn't fully discard.
    # Periodically rebuild the Solver from its own current assertions to
    # flush that accumulated internal state while keeping the exact same
    # logical constraints in effect. push_depth tracks how many push()
    # calls are currently outstanding (i.e. how many POP_SOLVER actions are
    # still queued on the stack) so the rebuilt solver can be given that
    # many empty scopes -- those future pops still need something to pop,
    # even though the constraints they'd have discarded are now baked into
    # the rebuilt solver's permanent (unpushed) base scope instead. Popping
    # an empty scope is a no-op on the assertion set, so this is exactly
    # equivalent to not having compacted at all.
    push_depth = 0
    pushes_since_compact = 0
    COMPACT_EVERY = 100

    def compact_solver():
        nonlocal solver, pushes_since_compact
        assertions = solver.assertions()
        solver = make_solver()
        for a in assertions:
            solver.add(a)
        for _ in range(push_depth):
            solver.push()
        pushes_since_compact = 0

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
            push_depth -= 1

        elif action == 'BACKTRACK_BLOCK':
            _, block = item
            onpath.remove(block)

        elif action == 'EVAL_BRANCH':
            _, nxt_block, cond, nxt_state, needs_check, is_false_branch = item

            solver.push()
            push_depth += 1
            pushes_since_compact += 1
            if pushes_since_compact >= COMPACT_EVERY:
                compact_solver()

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
                    push_depth -= 1
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
                    # the cache too), capped at CACHE_SIZE — the largest associativity
                    # we'll ever realize against. Index 0 = most recently used.
                    state.recent_window.insert(0, mem_addr)
                    if len(state.recent_window) > CACHE_SIZE:
                        state.recent_window.pop()

            if not block.next:
                print(f"Reaching an exit point {block.end}")
                path_results.append((dict(state.hist), list(state.mem_events)))
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

                    if last_branch_cond is None:
                        print("Warning: Branch with 2 successors but no condition found! Exploring both blindly.")
                        stack.append(('EVAL_BRANCH', nxt_false, None, state.fork(), False, True))
                        stack.append(('EVAL_BRANCH', nxt_true, None, state.fork(), False, False))
                    else:
                        # Push False branch (Not Taken) - executed second
                        stack.append(('EVAL_BRANCH', nxt_false, Not(last_branch_cond), state.fork(), True, True))
                        # Push True branch (Taken) - executed first
                        stack.append(('EVAL_BRANCH', nxt_true, last_branch_cond, state.fork(), True, False))

    print(f"\n======DFS Complete: {len(path_results)} feasible path(s) enumerated======")
    for idx, (hist, mem_events) in enumerate(path_results):
        print(f"  Path {idx}: {sum(hist.values())} non-memory instructions, "
              f"{len(mem_events)} pending load(s) -> base={hist}")

    return path_results


class Loop:
    """
    Metadata for a natural loop in the CFG.
    """
    def __init__(self, header: Block, tail: Block, members: set[Block]):
        self.header = header
        self.tail = tail
        self.members = members
        # (Source, Target)
        self.entry_edges: set[tuple[Block, Block]] = set()
        self.exit_edges: set[tuple[Block, Block]] = set()
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
        
    # If nested loops found, error out
    for l1 in loop_list:
        for l2 in loop_list:
            if l1 == l2:
                continue
            
            # Check if any entry-edge source is in l2 AND any exit-edge target is in l2
            entry_from_l2 = any(src in l2.members for src, _ in l1.entry_edges)
            exit_to_l2 = any(target in l2.members for _, target in l1.exit_edges)
            
            if entry_from_l2 and exit_to_l2:
                raise Exception(
                    f"Nested Loop Error: Loop (Header {l1.header.start}) is nested "
                    f"inside Loop (Header {l2.header.start})."
                )

    return loop_list


def unroll_loops_in_cfg(root_block: Block, loop_list: list[Loop]) -> Block:
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
    """
    sorted_loops = sorted(loop_list, key=lambda l: l.header.start, reverse=True)

    for loop in sorted_loops:
        if loop.max_iterations is None or loop.max_iterations <= 0:
            print(f"Warning: Loop at {loop.header.start} has no bound. Skipping unroll.")
            continue

        print(f"Unrolling loop at header {loop.header.start} for {loop.max_iterations} iterations.")

        # Identify exit targets (blocks outside the loop) and entry sources
        exit_targets = [exit_target for _, exit_target in loop.exit_edges]
        entry_sources = [entry_source for entry_source, _ in loop.entry_edges]

        prev_tail = None

        # Clone the loop body (members) N times
        for i in range(loop.max_iterations):
            block_map: dict[Block, Block] = {}

            # 1. Create clones with new suffix
            for member in loop.members:
                block_map[member] = member.copy_with_suffix(f".{i}")

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
                    entry_source.next.remove(loop.header)
                    entry_source.add(block_map[loop.header])
            else:
                prev_tail.add(block_map[loop.header])

            prev_tail = block_map[loop.tail]

        # The loop always exits after the last iteration's tail runs --
        # attach the exit edge(s) there, unconditionally.
        for exit_target in exit_targets:
            prev_tail.add(exit_target)

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

    for loop in loop_list:
        if loop.max_iterations is None or loop.max_iterations <= 0 or loop.start_value is None:
            continue

        next_call_pcs = [
            pc
            for member in loop.members
            for pc in instructions.keys()
            if member.start <= pc <= member.end
            and getattr(instructions[pc], "opcode", -1) == BPF_CALL_OPCODE
            and getattr(instructions[pc], "imm", -1) == BPF_ITER_NEXT_HELPER_ID
        ]

        for i in range(loop.max_iterations):
            value = loop.start_value + i
            for pc in next_call_pcs:
                result[f"{pc}.{i}"] = value

    return result
