from __future__ import annotations
import argparse
import hashlib
import multiprocessing
import os
import sys
from collections import deque
from dataclasses import replace as replace_profile

from bpf import BpfInstruction, BpfClass, BpfCode, BpfS
from block import Block
from dfs import dfs_blocks, ExecutionTraceProfile, Loop, find_loops, unroll_loops_in_cfg, instr_counts_to_cycles, build_cycle_mapping, build_op_info_by_name, build_iter_value_map, save_trace, load_trace, check_trace_soundness, DEFAULT_MAX_UNROLLED_BLOCKS
from profiles import PROFILES


# get_blocks_tree recurses once per CFG edge; fully-unrolled programs (e.g.
# aberr's manually-unrolled 5-iteration convergence loop) produce far more
# sequential basic blocks than Python's default ~1000-frame limit allows.
sys.setrecursionlimit(100000)

parser = argparse.ArgumentParser(
    prog="bpf-runtime-verifier",
    description="Estimates the runtime of BPF-Prime programs",
)
parser.add_argument("filename", nargs="?", default=None,
                     help="Path to raw eBPF instructions (.o). Required unless --from-trace is given.")
parser.add_argument("--profile", choices=sorted(PROFILES), default="polarfire",
                     help="Target hardware profile (default: polarfire)")
parser.add_argument("--jobs", "-j", type=int, default=1,
                     help="Worker processes to split DFS exploration across (default: 1, i.e. no split)")
parser.add_argument("--split-depth", type=int, default=6,
                     help="2-successor branches to enumerate single-threaded before splitting into subtrees (default: 6)")
parser.add_argument("--emit-trace", metavar="PATH", default=None,
                     help="After computing path_results, also persist them as a YAML trace to PATH.")
parser.add_argument("--from-trace", metavar="PATH", default=None,
                     help="Skip file reading/CFG/DFS entirely; load path_results from a YAML trace "
                          "previously written by --emit-trace and cost it against --profile.")
parser.add_argument("--max-unrolled-blocks", type=int, default=DEFAULT_MAX_UNROLLED_BLOCKS,
                     metavar="N",
                     help=f"Refuse to unroll a CFG projected to exceed N basic blocks "
                          f"(default: {DEFAULT_MAX_UNROLLED_BLOCKS}). Guards against a deeply "
                          f"nested loop silently starting a multi-hour, multi-GB run.")
parser.add_argument("--print-cfg", action="store_true",
                     help="Dump the full basic-block CFG and mermaid graph. Suppressed by default "
                          "for unrolled CFGs, which can run to hundreds of thousands of blocks.")


# Set once per forked worker process (via _init_worker, before any tasks run) so
# workers share the CFG/instructions/profile through fork()'s copy-on-write instead
# of repickling them per task -- only the (tiny) leaf itself crosses the task queue.
_worker_ctx: dict = {}


def _init_worker(unrolled_block, instructions, profile, iter_value_by_call_site):
    _worker_ctx["unrolled_block"] = unrolled_block
    _worker_ctx["instructions"] = instructions
    _worker_ctx["profile"] = profile
    _worker_ctx["iter_value_by_call_site"] = iter_value_by_call_site


def _explore_leaf(leaf: list[bool]) -> list[ExecutionTraceProfile]:
    path_results, _ = dfs_blocks(
        _worker_ctx["unrolled_block"], _worker_ctx["instructions"],
        _worker_ctx["profile"], _worker_ctx["iter_value_by_call_site"],
        forced_decisions=leaf,
    )
    return path_results


def solve_in_parallel(unrolled_block, instructions, profile, iter_value_by_call_site,
                       collect_leaves_at: int, jobs: int) -> list[ExecutionTraceProfile]:
    """
    Single-threaded shallow pass down to collect_leaves_at 2-successor branches to
    enumerate independent subtrees (dfs_blocks's collect_leaves_at), then explores
    each subtree in its own worker process (forced_decisions replays the same
    prefix rather than resuming a saved Z3 state, which isn't picklable), merging
    every worker's completed paths with whatever the shallow pass itself completed.
    """
    initial_results, leaves = dfs_blocks(
        unrolled_block, instructions, profile, iter_value_by_call_site,
        collect_leaves_at=collect_leaves_at,
    )
    if not leaves or jobs <= 1:
        return initial_results

    print(f"\n======Splitting into {len(leaves)} subtree(s) across up to {jobs} worker process(es)======")
    with multiprocessing.Pool(
        processes=min(jobs, len(leaves)),
        initializer=_init_worker,
        initargs=(unrolled_block, instructions, profile, iter_value_by_call_site),
    ) as pool:
        for worker_results in pool.imap_unordered(_explore_leaf, leaves):
            initial_results.extend(worker_results)
    return initial_results


def read_bpf_file(filename: str) -> dict[int, BpfInstruction]:
    # TODO: this is not always the case,
    # some instructions are 16 bytes, and they're not that rare
    inst_size = 8
    instructions = {}
    current_pc = 0
    with open(filename, "rb") as file:
        while True:
            ins = file.read(inst_size)
            # EOF, program is done
            if ins == b"":
                break

            bpf_ins = BpfInstruction(ins)
            if bpf_ins.is_wide_instruction():
                more = file.read(inst_size)
                assert more != b""
                bpf_ins.widen_instruction(more)
                instructions[current_pc] = bpf_ins
                current_pc += 2
            else:
                instructions[current_pc] = bpf_ins
                current_pc += 1

    return instructions


def get_blocks_tree(
    instructions: dict[int, BpfInstruction], start_idx=0, all_blocks: dict[int, Block] | None = None, leaders = None
) -> Block:
    """Processes instruction set into a CFG using Leader-based partitioning.""" 

    # Pre-scan phase: Identify entry points (Leaders) to avoid block overlaps
    if all_blocks is None:
        all_blocks = {}
        leaders = {0}
        for idx in sorted(instructions.keys()):
            ins = instructions[idx]
            print(f"idx={idx}: instruction={str(ins)}")
            if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                # Target of a jump is a leader
                # BPF CALL
                if ins.opcode == (BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP):
                    if ins.src == 1:   # Calling normal function
                        leaders.add(idx + ins.imm + 1)
                        # print(f"Jumping to {idx + ins.imm + 1}")
                elif ins.opcode != (BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP):
                    target = idx + ins.off + 1 if hasattr(ins, 'off') else idx + ins.imm + 1
                    leaders.add(target)
                    # print(f"Jumping to {target}")
                
                # Instruction following a jump is a leader
                if idx + 1 < max(instructions.keys()):
                    leaders.add(idx + 1)
        
        leaders = sorted([l for l in leaders if l < max(instructions.keys())])
        # print(f"\nLeaders: {leaders}\n")
        
    # Cycle detection: reuse existing block and terminate recursion.
    if start_idx in all_blocks:
        return all_blocks[start_idx]

    # Determine current block boundary based on the next leader
    next_leader = next((l for l in leaders if l > start_idx), max(instructions.keys()))
    
    # Find the basic block
    curr_block_end = start_idx
    for idx in (pc for pc in sorted(instructions.keys()) if start_idx <= pc < next_leader):
        curr_block_end = idx
        ins = instructions[idx]
        if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
            # Helper calls don't end a block; other jumps do
            if not (ins.opcode == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP and ins.src in [0, 2]):
                # print(f"Block end: {idx}, instruction {ins}")
                break
            
    block = Block(start_idx, curr_block_end)
    all_blocks[start_idx] = block
    
    last_ins = instructions[curr_block_end]
    idx = curr_block_end 

    # Handle Fall-through: if block ends without a terminating jump
    if last_ins.get_class() not in [BpfClass.JMP, BpfClass.JMP32] or \
       (last_ins.opcode == BpfCode.JMP.CALL | BpfClass.JMP and last_ins.src in [0, 2]):
        next_step = 2 if last_ins.is_wide_instruction() else 1
        if curr_block_end + next_step < max(instructions.keys()):
            next_sequential_pc = curr_block_end + next_step
            next_b = get_blocks_tree(instructions, next_sequential_pc, all_blocks, leaders)
            block.add(next_b)
        return block

    # Connect edges
    match last_ins.opcode:
        case x if x == BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:
            return block

        case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP:
            jump_to = idx + last_ins.off + 1
            block.add(get_blocks_tree(instructions, jump_to, all_blocks, leaders))
            return block

        case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP32:
            jump_to = idx + last_ins.imm + 1
            block.add(get_blocks_tree(instructions, jump_to, all_blocks, leaders))
            return block

        case x if x == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:
            if last_ins.src == 1:
                jump_to = idx + last_ins.imm + 1
                block.add(get_blocks_tree(instructions, jump_to, all_blocks, leaders))
            else:
                # Fall-through for helper calls
                block.add(get_blocks_tree(instructions, idx + 1, all_blocks, leaders))
            return block

            # conditional jumps, these jump to two blocks
        case x if x in [
            BpfCode.JMP.JEQ | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JEQ | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JEQ | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JEQ | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JGT | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JGT | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JGT | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JGT | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JGE | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JGE | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JGE | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JGE | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JNE | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JNE | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JNE | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JNE | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JLT | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JLT | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JLT | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JLT | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JLE | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JLE | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JLE | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JLE | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32,
            BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP,
            BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32,
            BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP,
            BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32,
        ]:
            jump_if = idx + last_ins.off + 1
            jump_else = idx + 1
            block.add(get_blocks_tree(instructions, jump_if, all_blocks, leaders))
            block.add(get_blocks_tree(instructions, jump_else, all_blocks, leaders))
            return block

        case _:
            if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                raise Exception(f"idx={idx}: couldn't catch opcode: {ins.opcode}")

    raise Exception(f"unreachable")


def print_cfg_from_root(root: Block):
    """
    Traverses the CFG from the root block using Breadth-First Search (BFS) 
    and prints the blocks with their successors.
    
    It supports unrolled loops by differentiating blocks with suffixes,
    and outputs both a text-based list and a Mermaid graph.
    """
    # Blocks with the same start/end but different suffixes are treated as 
    # distinct objects thanks to the custom __hash__ and __eq__ methods.
    visited_blocks = set()
    queue = deque([root])

    while queue:
        curr = queue.popleft()
        if curr in visited_blocks:
            continue
        
        visited_blocks.add(curr)
        for n in curr.next:
            if n not in visited_blocks:
                queue.append(n)

    # Sort blocks by start index and then the suffix.
    sorted_blocks = sorted(list(visited_blocks), key=lambda b: (b.start, b.suffix))

    print("\n" + "="*60)
    print(f"{'BASIC BLOCK CFG LIST':^60}")
    print("="*60)

    for block in sorted_blocks:
        if not block.next:
            successors_str = "TERMINATE (EXIT)"
        else:
            formatted_succs = []
            for n in block.next:
                # Format each successor with its iteration suffix
                s_str = f"Block [{n.start:3} - {n.end:3}]{n.suffix}"
                
                # Mark true back-edges. 
                # In an unrolled CFG, a jump to a lower PC is only a back-edge 
                # if it remains within the exact same iteration level (same suffix).
                if n.start <= block.start and n.suffix == block.suffix:
                    s_str += " (LOOP BACK)"
                
                formatted_succs.append(s_str)
            
            successors_str = ", ".join(formatted_succs)

        print(f"Block [{block.start:3} - {block.end:3}]{block.suffix}")
        print(f"  └── Successors: {successors_str}")
        
    print("="*60 + "\n")
    
    
    print("\n" + "="*60)
    print(f"{'MERMAID GRAPH CODE':^60}")
    print("="*60)
    print("```mermaid")
    print("graph TD")
    print("    classDef exitNode fill:#f96,stroke:#333,stroke-width:2px;")
    
    def get_safe_id(b: Block) -> str:
        """
        Helper function to generate syntactically safe Mermaid Node IDs.
        Replaces periods or spaces in the suffix with underscores.
        e.g., Block 10 suffix '.1' -> 'B10_1'
        """
        safe_suffix = b.suffix.replace(".", "_").replace("@", "_").replace(" ", "_")
        return f"B{b.start}{safe_suffix}"

    for block in sorted_blocks:
        node_id = get_safe_id(block)
        
        # Include the suffix in the label and wrap it in quotes 
        # to prevent Mermaid from throwing parsing errors.
        node_label = f"\"Block [{block.start} - {block.end}]{block.suffix}\""
        
        # Declare node shapes: standard box for normal blocks, circle for exit nodes
        if not block.next:
            print(f"    {node_id}(({node_label})):::exitNode")
        else:
            print(f"    {node_id}[{node_label}]")

        # Declare directed edges between nodes
        for n in block.next:
            target_id = get_safe_id(n)
            print(f"    {node_id} --> {target_id}")
                
    print("```")
    print("="*60 + "\n")


def main():
    args = parser.parse_args()
    profile = PROFILES[args.profile]

    if args.filename is None and args.from_trace is None:
        parser.error("filename is required unless --from-trace is given")
    if args.filename is not None and args.from_trace is not None:
        parser.error("filename and --from-trace are mutually exclusive")
    if args.from_trace is not None and args.emit_trace is not None:
        parser.error("--from-trace and --emit-trace are mutually exclusive (re-emitting a trace "
                      "you just loaded, with no new DFS work done, is a no-op)")

    if args.from_trace is not None:
        path_results, metadata = load_trace(args.from_trace)
        try:
            check_trace_soundness(metadata, profile)
        except ValueError as e:
            parser.error(str(e))

        trace_program_path = metadata.get("program_path")
        trace_sha256 = metadata.get("program_sha256")
        if trace_program_path and trace_sha256 and os.path.isfile(trace_program_path):
            with open(trace_program_path, "rb") as pf:
                current_sha256 = hashlib.sha256(pf.read()).hexdigest()
            if current_sha256 != trace_sha256:
                print(f"WARNING: trace was generated from {trace_program_path!r} but that file's "
                      f"contents have since changed (sha256 mismatch) -- trace may be stale.",
                      file=sys.stderr)
    else:
        instructions = read_bpf_file(args.filename)  # dict[int, BpfInstruction]
        first_block = get_blocks_tree(instructions)

        if args.print_cfg:
            print_cfg_from_root(first_block)
        loop_list = find_loops(first_block, instructions)
        for loop in loop_list:
            print(f"Loop: {loop}\n Header: {loop.header}\n Tail: {loop.tail}\n Iteration count: {loop.max_iterations}\n "
                  f"Depth: {loop.depth}\n Call0x5_pc: {loop.call_5_pc}\n w2_pc: {loop.w2_pc}\n w3_pc: {loop.w3_pc}\n\n")

        # Duplicate loop contents in cycle
        try:
            unrolled_block = unroll_loops_in_cfg(first_block, loop_list,
                                                  max_unrolled_blocks=args.max_unrolled_blocks)
        except ValueError as e:
            parser.error(str(e))
        if args.print_cfg:
            print_cfg_from_root(unrolled_block)

        dfs_cache_size = max(p.cache_size for p in PROFILES.values())
        dfs_profile = replace_profile(profile, cache_size=dfs_cache_size) if profile.cache_size != dfs_cache_size else profile

        iter_value_by_call_site = build_iter_value_map(loop_list, instructions)
        if args.jobs > 1:
            path_results = solve_in_parallel(unrolled_block, instructions, dfs_profile, iter_value_by_call_site,
                                              collect_leaves_at=args.split_depth, jobs=args.jobs)
        else:
            path_results, _ = dfs_blocks(unrolled_block, instructions, dfs_profile, iter_value_by_call_site)

        if args.emit_trace is not None:
            save_trace(path_results, args.emit_trace, program_path=args.filename, dfs_cache_size=dfs_cache_size)
            print(f"Trace written to {args.emit_trace}")

    op_info_by_name = build_op_info_by_name(profile)
    cycle_mapping = build_cycle_mapping(op_info_by_name)
    runtime_cycle_ub = max(
        (instr_counts_to_cycles(trace, cycle_mapping, op_info_by_name, profile)
         for trace in path_results),
        default=0,
    )
    print(f"runtime_cycle_ub: {runtime_cycle_ub}")
    runtime_ub = runtime_cycle_ub / profile.cpu_freq_hz * 1000
    print(f"runtime_ub: {runtime_ub} ms")


if __name__ == "__main__":
    main()
