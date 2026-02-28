from block import Block
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from mem_access import process_instruction, State, fresh_gp_var, fresh_fp_var, get_all_var_names, get_vars_from_expr, \
    normalize_huge_bv
from z3 import Solver, If, ULT, ULE, sat, BitVecRef, BoolRef, Not, unknown, Z3Exception, Then
from collections import deque

CACHE_LINE_DIFF = 4
COST_MEM_L1_HIT = 0
COST_MEM_L2_HIT = 12
COST_MEM_MISS = 87 + 87
CACHE_TTL_N = 8  # Set to 8/16 for test


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


def instr_to_runtime(instructions:dict[int, BpfInstruction], start:int, end:int) -> int:
    """
    Calculate runtime of the given instructions from `start` to `end` (inclusive).

    Parameters
    ----------
    instructions : dict[int, BpfInstruction]
        A dictionary mapping program counter to decoded eBPF instructions.
    start : int
        Start index (inclusive).
    end : int
        End index (inclusive).

    Returns
    -------
    int
        CPU cycles. Returns 0 if the input is invalid.
    """
    runtime = 0
    for idx in (pc for pc in sorted(instructions.keys()) if start <= pc <= end):
        instr = instructions[idx]
        if is_fpu_instr(instr):
            op_info = BPF_INFO_FPU.get(instr.opcode)  # FADD / FNEG / JFEQ / JFOGT ...
        else:
            op_info = BPF_INFO.get(instr.opcode)      # ALU/MEM ... + FLDX & FSTX

        if op_info:
            print(f"idx={idx}: name={op_info.name}, latency={op_info.latency}")
        if op_info:
            if op_info.latency:
                runtime += op_info.latency

    return runtime


# def check_cache_hit(curr_addr, cache_list, path_constraints: list, state: State) -> int:    
#     solver = Solver()
#     solver.set("smt.relevancy", 2)
#     for i in reversed(range(len(cache_list))):
#         if curr_addr.eq(cache_list[i]):
#             return i
        
#     if hasattr(curr_addr, 'as_long') and curr_addr.as_long() is not None:
#         curr_val = curr_addr.as_long()
#         for i in reversed(range(len(cache_list))):
#             if hasattr(cache_list[i], 'as_long') and cache_list[i].as_long() is not None:
#                 if abs(curr_val - cache_list[i].as_long()) <= CACHE_LINE_DIFF: 
#                     return i
#         return -1

#     for i in reversed(range(len(cache_list))):
#         solver.push()
#         solver.set("timeout", 1000) 
#         solver.set("smt.arith.nl", True)
        
#         diff = If(ULT(curr_addr, cache_list[i]), 
#                   cache_list[i] - curr_addr, 
#                   curr_addr - cache_list[i])
        
#         solver.add(ULE(diff, CACHE_LINE_DIFF))
        
#         try:
#             result = solver.check()
#         except Z3Exception:
#             result = unknown
#         finally:
#             solver.pop()

#         if result == unknown:
#             print(f"Warning: Z3 returned unknown at addr {curr_addr}")
#             print(f"Unknown reason: {solver.reason_unknown()}")
#             print(f"Statistics: {solver.statistics()}")
#         if result == sat:
#             return i
            
#     return -1
    
    
def check_cache_hit(curr_addr: BitVecRef, cache_list: list[BitVecRef], path_constraints: list, state: State) -> int:    
    """
    Checks if the current memory address hits the simulated cache.
    Uses symbolic minimization to filter irrelevant constraints for better performance.
    """
    solver = Solver()
    solver.set("timeout", 1000) 
    solver.set("smt.relevancy", 2)
    solver.set("smt.arith.nl", True)

    # Constraint Slicing (Minimization)
    active_vars = get_all_var_names(state.gp) | \
                  get_all_var_names(state.fp) | \
                  get_all_var_names(state.memory)
    
    for cond_expr, cond_vars in path_constraints:
        if cond_vars.issubset(active_vars):
            solver.add(cond_expr)

    for i in reversed(range(len(cache_list))):
        if curr_addr.eq(cache_list[i]):
            return i
        
    # Concrete Value Check
    if hasattr(curr_addr, 'as_long') and curr_addr.as_long() is not None:
        curr_val = curr_addr.as_long()
        for i in reversed(range(len(cache_list))):
            target = cache_list[i]
            if hasattr(target, 'as_long') and target.as_long() is not None:
                # Check if the difference is within the Cache Line size
                if abs(curr_val - target.as_long()) <= CACHE_LINE_DIFF: 
                    return i
        return -1

    # Symbolic Range Check
    for i in reversed(range(len(cache_list))):
        solver.push()
        
        diff = If(ULT(curr_addr, cache_list[i]), 
                  cache_list[i] - curr_addr, 
                  curr_addr - cache_list[i])
        
        solver.add(ULE(diff, CACHE_LINE_DIFF)) 
        
        try:
            result = solver.check()
        except Z3Exception:
            result = unknown
        
        if result == sat:
            solver.pop()
            return i
            
        if result == unknown:
            print(f"Warning: Cache check returned unknown for {curr_addr}")
            pass
            
        solver.pop()

    return -1
    
    
def dfs_blocks(first_block: 'Block | None', instructions: dict[int, BpfInstruction]) -> int:
    """
    Perform a depth-first search over the Block graph with Path Constraints & Cache Simulation.
    Returns an integer value (CPU cycles) representing an estimated runtime upper bound.
    """
    print("\n======DFS Start======")
    
    if first_block is None:
        return 0

    onpath: Set['Block'] = set()
    path_runtime_ub = 0
    path_runtime = 0  # Tracks cumulative runtime for the current path

    def dfs(block: 'Block', state: 'State', cache_state: deque[BitVecRef], path_constraints: list[tuple[BoolRef, set[str]]]):
        nonlocal path_runtime_ub, path_runtime

        # 1. Cycle detection (Back-edge)
        if block in onpath:
            # TODO: Plug a loop bound policy here.
            print(f"Back-edge hit at BB({block.start}, {block.end}); ignoring extra iteration for now.")
            return

        onpath.add(block)

        # Basic block information
        instr_count = block.end - block.start + 1
        block_instrs = [instructions[pc] for pc in sorted(instructions.keys()) if block.start <= pc <= block.end]
        
        print(f"\n======Visiting BB({block.start}, {block.end}), instructions={instr_count}======")

        # For backtracking
        runtime_at_entry = path_runtime

        # --- Cost Calculation Part 1: Base Static Cost ---
        # Calculate the base execution time for this block (ALU, static costs)
        base_block_cost = instr_to_runtime(instructions, block.start, block.end)
        path_runtime += base_block_cost

        # Prepare local cache state (copy from parent)
        curr_cache = deque(list(cache_state), maxlen=16)

        last_branch_cond: Optional[BoolRef] = None

        # --- Cost Calculation Part 2: Memory Penalties ---
        sorted_pcs = sorted([pc for pc in instructions.keys() if block.start <= pc <= block.end])
        for i in sorted_pcs:
            current_idx = i
            instruction = instructions[current_idx]
 
            # 2. Symbolic Execution
            branch_cond, mem_addr = process_instruction(instruction, state, current_idx)

            # 3. Helper Call Cost Logic
            if hasattr(instruction, 'opcode') and instruction.opcode == 0x85:
                
                # Set R1-R5 to new values
                for reg_idx in range(1,6):
                    reg_val = fresh_gp_var(reg_idx, current_idx)
                    state.set_gp(reg_idx, reg_val)
                    # print(f"  [Helper Call] at I{current_idx}: R{reg_idx} value is set to {state.get_gp(reg_idx)}")
                
                if hasattr(instruction, 'imm') and instruction.imm in [1, 2, 3]:
                    print(f"  [Helper Call] ID {instruction.imm} at I{current_idx}: +{COST_MEM_MISS} cycles")
                    path_runtime += COST_MEM_MISS
                else:
                    print(f"  [Helper Call] ID {instruction.imm} at I{current_idx}: +100 cycles")
                    path_runtime += 100

            if branch_cond is not None:
                last_branch_cond = branch_cond

            if mem_addr is not None:
                if is_fpu_instr(instruction):
                    op_info = BPF_INFO_FPU.get(instruction.opcode)  # FADD / FNEG / JFEQ / JFOGT ...
                else:
                    op_info = BPF_INFO.get(instruction.opcode)      # ALU/MEM ... + FLDX & FSTX

                if op_info:
                    if "LD" in op_info.name:
                        dist = check_cache_hit(mem_addr, list(curr_cache), path_constraints, state)

                        # Check the distance from the most recent MEM/FMEM instruction
                        if dist == -1:
                            print(f"  [Cache MISS] Addr: {mem_addr} (+{COST_MEM_MISS} cycles)")
                            path_runtime += COST_MEM_MISS
                        elif len(list(curr_cache)) - dist < 8:
                            print(f"  [Cache HIT L1] Addr: {mem_addr} (+{COST_MEM_L1_HIT} cycles)")
                            path_runtime += COST_MEM_L1_HIT
                        elif len(list(curr_cache)) - dist < 16:
                            print(f"  [Cache HIT L2] Addr: {mem_addr} (+{COST_MEM_L2_HIT} cycles)")
                            path_runtime += COST_MEM_L2_HIT

                # Update cache with new access
                curr_cache.append(mem_addr)

        if not block.next:
            print(f"Reaching an exit point {block.end}, total path runtime is {path_runtime}")
            path_runtime_ub = max(path_runtime_ub, path_runtime)
        else:
            # Branching
            successors = block.next

            # Case A: Single Successor (Unconditional Jump or Fall-through)
            if len(successors) == 1:
                nxt = successors[0]
                if last_branch_cond is not None:
                    new_path_constraints = list(path_constraints)
                    vars_true = get_all_var_names(last_branch_cond)
                    new_path_constraints.append((last_branch_cond, vars_true))
                    dfs(nxt, state.fork(), curr_cache, new_path_constraints)
                else:
                    dfs(nxt, state.fork(), curr_cache, path_constraints)

            # Case B: Two Successors (Conditional Branch)
            # successors[0] is the Taken target, successors[1] is the Not-Taken target
            elif len(successors) == 2:
                if last_branch_cond is None:
                    print("Warning: Branch with 2 successors but no condition found! Exploring both blindly.")
                    for nxt in successors:
                        dfs(nxt, state.fork(), deque(list(curr_cache), maxlen=16), path_constraints)
                else:
                    # --- Condition is True (Taken) ---
                    nxt_true = successors[0]

                    new_path_constraints_taken = list(path_constraints)
                    vars_true = get_all_var_names(last_branch_cond)
                    new_path_constraints_taken.append((last_branch_cond, vars_true))
                    
                    solver = Solver()
                    solver.set("timeout", 1000) 
                    solver.set("smt.relevancy", 2)
                    solver.set("smt.arith.nl", True)
                    # Constraint Slicing (Minimization)
                    active_vars = get_all_var_names(state.gp) | \
                                get_all_var_names(state.fp) | \
                                get_all_var_names(state.memory)
                    for cond_expr, cond_vars in new_path_constraints_taken:
                        if cond_vars.issubset(active_vars):
                            solver.add(cond_expr)
                    
                    if solver.check() == sat or unknown:
                        dfs(nxt_true, state.fork(), deque(list(curr_cache), maxlen=16), new_path_constraints_taken)
                    else:
                        print(f"  [Pruned] Path to BB {nxt_true.start} is unreachable (UNSAT).")


                    # --- Condition is False (Not Taken) ---
                    nxt_false = successors[1]
                    new_path_constraints_nottaken = list(path_constraints)
                    vars_true = get_all_var_names(last_branch_cond)
                    new_path_constraints_nottaken.append((last_branch_cond, vars_true))
                    
                    solver = Solver()
                    solver.set("timeout", 1000) 
                    solver.set("smt.relevancy", 2)
                    solver.set("smt.arith.nl", True)
                    # Constraint Slicing (Minimization)
                    active_vars = get_all_var_names(state.gp) | \
                                get_all_var_names(state.fp) | \
                                get_all_var_names(state.memory)
                    for cond_expr, cond_vars in new_path_constraints_nottaken:
                        if cond_vars.issubset(active_vars):
                            solver.add(cond_expr)
                    
                    if solver.check() == sat or unknown:
                        dfs(nxt_false, state.fork(), deque(list(curr_cache), maxlen=16), new_path_constraints_nottaken)
                    else:
                        print(f"  [Pruned] Path to BB {nxt_false.start} is unreachable (UNSAT).")
                    

        # Backtrack (Restore Runtime)
        path_runtime = runtime_at_entry
        onpath.remove(block)

    # Initialize state
    initial_state = State()
    initial_cache: deque[BitVecRef] = deque([], maxlen=16)

    # Start DFS
    dfs(first_block, initial_state, initial_cache, [])

    return path_runtime_ub


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
    """
    sorted_loops = sorted(loop_list, key=lambda l: l.header.start, reverse=True)

    for loop in sorted_loops:
        if loop.max_iterations is None or loop.max_iterations <= 0:
            print(f"Warning: Loop at {loop.header.start} has no bound. Skipping unroll.")
            continue

        print(f"Unrolling loop at header {loop.header.start} for {loop.max_iterations} iterations.")

        # 1. Identify exit targets (blocks outside the loop)
        exit_targets = [exit_target for _, exit_target in loop.exit_edges]
        entry_sources = [entry_source for entry_source, _ in loop.entry_edges]
        
        # 2. Perform the unrolling
        prev_tails = None
        
        # We need to clone the loop body (members) N times
        for i in range(loop.max_iterations):
            block_map: dict[Block, Block] = {}
            
            # 1. Create clones with new suffix
            for member in loop.members:
                block_map[member] = member.copy_with_suffix(f".{i}")

            # 2. Re-establish connections within this iteration slice
            # , and exit edges
            for member in loop.members:
                new_member = block_map[member]
                for succ in member.next:
                    if succ in loop.members:
                        if succ == loop.header:
                            continue
                        # Internal link to new blocks, disconnect back edges
                        new_member.add(block_map[succ])
                        
                    # Exit link to blocks outside the loop
                    elif succ not in loop.members:
                        # if succ in exit_targets and i != loop.max_iterations - 1:
                        #     continue
                        new_member.add(succ)

            # Link the previous iteration's tail to this iteration's header
            if i == 0:
                for entry_source in entry_sources:
                    entry_source.next.remove(loop.header)
                    entry_source.add(block_map[loop.header])
                    prev_header = block_map[loop.tail]
                    
            elif i < loop.max_iterations:
                prev_header.add(block_map[loop.header])
                prev_header = block_map[loop.tail]

    return root_block
