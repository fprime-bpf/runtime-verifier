from block import Block
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from mem_access import process_instruction, State
from typing import Set, Optional
from z3 import Solver, If, ULT, ULE, sat, BitVecRef, BoolRef, Not, unknown
from collections import deque

CACHE_LINE_DIFF = 4
COST_MEM_L1_HIT = 0
COST_MEM_L2_HIT = 12
COST_MEM_MISS = 87
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


def instr_to_runtime(instructions:list, start:int, end:int) -> int:
    """
    Calculate runtime of the given instructions from `start` to `end` (inclusive).

    Parameters
    ----------
    instructions : list
        A list of decoded eBPF instructions.
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
    for idx in range(start, end+1):
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


def check_cache_hit(curr_addr, cache_list, solver) -> int:
    for i in reversed(range(len(cache_list))):
        if curr_addr.eq(cache_list[i]):
            return i
            
        solver.push()
        
        diff = If(ULT(curr_addr, cache_list[i]), 
                  cache_list[i] - curr_addr, 
                  curr_addr - cache_list[i])
        
        solver.add(ULE(diff, CACHE_LINE_DIFF)) 
        
        result = solver.check()
        solver.pop()

        if result == unknown:
            print(f"Warning: Z3 returned unknown at addr {curr_addr}")
        if result == sat:
            return i
            
    return -1
    
    
def dfs_blocks(first_block: 'Block | None', instructions: list) -> int:
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

    def dfs(block: 'Block', state: 'State', cache_state: deque[BitVecRef], solver: Solver):
        nonlocal path_runtime_ub, path_runtime

        # 1. Cycle detection (Back-edge)
        if block in onpath:
            # TODO: Plug a loop bound policy here.
            print(f"Back-edge hit at BB({block.start}, {block.end}); ignoring extra iteration for now.")
            return

        onpath.add(block)

        # Basic block information
        instr_count = block.end - block.start + 1
        block_instrs = instructions[block.start : block.end + 1]
        
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
        for i, instruction in enumerate(block_instrs):
            current_idx = block.start + i
 
            # 2. Symbolic Execution
            branch_cond, mem_addr = process_instruction(instruction, state, current_idx)

            # 3. Helper Call Cost Logic
            if hasattr(instruction, 'opcode') and instruction.opcode == 0x85:
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
                        dist = check_cache_hit(mem_addr, list(curr_cache), solver)

                        # Check the distance from the most recent MEM/FMEM instruction
                        if dist == -1:
                            print(f"  [Cache MISS] Addr: {mem_addr} (+{COST_MEM_MISS} cycles)")
                            path_runtime += COST_MEM_MISS
                        elif len(list(curr_cache)) - dist < 7:
                            print(f"  [Cache HIT L1] Addr: {mem_addr} (+{COST_MEM_L1_HIT} cycles)")
                            path_runtime += COST_MEM_L1_HIT
                        elif len(list(curr_cache)) - dist < 15:
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
                    solver.push()
                    solver.add(last_branch_cond)
                    dfs(nxt, state.fork(), curr_cache, solver)
                    solver.pop()
                else:
                    dfs(nxt, state.fork(), curr_cache, solver)

            # Case B: Two Successors (Conditional Branch)
            # successors[0] is the Taken target, successors[1] is the Not-Taken target
            elif len(successors) == 2:
                if last_branch_cond is None:
                    print("Warning: Branch with 2 successors but no condition found! Exploring both blindly.")
                    for nxt in successors:
                        dfs(nxt, state.fork(), deque(list(curr_cache), maxlen=16), solver)
                else:
                    # --- Condition is True (Taken) ---
                    nxt_true = successors[0]
                    solver.push()
                    solver.add(last_branch_cond)
                    
                    # Pruning: Only recurse if the path is satisfiable
                    if solver.check() == sat:
                        dfs(nxt_true, state.fork(), deque(list(curr_cache), maxlen=16), solver)
                    else:
                        print(f"  [Pruned] Path to BB {nxt_true.start} is unreachable (UNSAT).")

                    solver.pop()

                    # --- Condition is False (Not Taken) ---
                    nxt_false = successors[1]
                    solver.push()
                    solver.add(Not(last_branch_cond))
                    
                    if solver.check() == sat:
                        dfs(nxt_false, state.fork(), deque(list(curr_cache), maxlen=16), solver)
                    else:
                        print(f"  [Pruned] Path to BB {nxt_false.start} is unreachable (UNSAT).")
                    
                    solver.pop()

        # Backtrack (Restore Runtime)
        path_runtime = runtime_at_entry
        onpath.remove(block)

    # Initialize state
    initial_state = State()
    initial_cache: deque[BitVecRef] = deque([], maxlen=16)

    # Initialize Solver for path constraints and cache checks
    solver = Solver()

    # Start DFS
    dfs(first_block, initial_state, initial_cache, solver)

    return path_runtime_ub
