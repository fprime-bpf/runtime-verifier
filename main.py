from __future__ import annotations
import argparse

from bpf import BpfInstruction, BpfClass, BpfCode, BpfS
from block import Block
from dfs import dfs_blocks


parser = argparse.ArgumentParser(
    prog="bpf-runtime-verifier",
    description="Estimates the runtime of BPF-Prime programs",
)
parser.add_argument("filename")


def read_bpf_file(filename: str) -> list[BpfInstruction]:
    # TODO: this is not always the case,
    # some instructions are 16 bytes, and they're not that rare
    inst_size = 8
    instructions = []
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

            instructions.append(bpf_ins)

    return instructions


def get_blocks_tree(
    instructions: list[BpfInstruction], start_idx=0, all_blocks: dict[int, Block] | None = None
) -> Block:
    """Processes instruction set into a CFG using Leader-based partitioning."""

    # Pre-scan phase: Identify entry points (Leaders) to avoid block overlaps
    if all_blocks is None:
        all_blocks = {}
        leaders = {0}
        for i, ins in enumerate(instructions):
            if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                # Target of a jump is a leader
                if ins.opcode == (BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP):
                    if ins.src == 1: 
                        leaders.add(i + ins.imm + 1)
                elif ins.opcode != (BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP):
                    target = i + ins.off + 1 if hasattr(ins, 'off') else i + ins.imm + 1
                    leaders.add(target)
                
                # Instruction following a jump is a leader
                if i + 1 < len(instructions):
                    leaders.add(i + 1)
        
        all_blocks['_leaders'] = sorted([l for l in leaders if l < len(instructions)])

    if start_idx in all_blocks:
        return all_blocks[start_idx]

    # Determine current block boundary based on the next leader
    leaders = all_blocks['_leaders']
    next_leader = next((l for l in leaders if l > start_idx), len(instructions))
    
    curr_block_end = start_idx
    for idx in range(start_idx, next_leader):
        curr_block_end = idx
        ins = instructions[idx]
        if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
            # Helper calls don't end a block; other jumps do
            if not (ins.opcode == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP and ins.src in [0, 2]):
                break
            
    block = Block(start_idx, curr_block_end)
    all_blocks[start_idx] = block
    
    last_ins = instructions[curr_block_end]
    idx = curr_block_end 

    # Handle Fall-through: if block ends without a terminating jump
    if last_ins.get_class() not in [BpfClass.JMP, BpfClass.JMP32] or \
       (last_ins.opcode == BpfCode.JMP.CALL | BpfClass.JMP and last_ins.src in [0, 2]):
        if curr_block_end + 1 < len(instructions):
            next_b = get_blocks_tree(instructions, curr_block_end + 1, all_blocks)
            block.add(next_b)
        return block

    # Connect edges
    match last_ins.opcode:
        case x if x == BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:
            return block

        case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP:
            jump_to = idx + last_ins.off + 1
            block.add(get_blocks_tree(instructions, jump_to, all_blocks))
            return block

        case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP32:
            jump_to = idx + last_ins.imm + 1
            block.add(get_blocks_tree(instructions, jump_to, all_blocks))
            return block

        case x if x == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:
            if last_ins.src == 1:
                jump_to = idx + last_ins.imm + 1
                block.add(get_blocks_tree(instructions, jump_to, all_blocks))
            else:
                # Fall-through for helper calls
                block.add(get_blocks_tree(instructions, idx + 1, all_blocks))
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
            block.add(get_blocks_tree(instructions, jump_if, all_blocks))
            block.add(get_blocks_tree(instructions, jump_else, all_blocks))
            return block

        case _:
            if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                raise Exception(f"idx={idx}: couldn't catch opcode: {ins.opcode}")

    raise Exception(f"unreachable")


def print_cfg_from_root(root: Block):
    """
    Traverses the CFG from root and prints blocks with their 
    successors formatted as 'Block [start - end]'.
    """
    all_blocks = {}
    queue = [root]
    
    while queue:
        curr = queue.pop(0)
        if curr.start in all_blocks:
            continue
        
        all_blocks[curr.start] = curr
        for n in curr.next:
            if n.start not in all_blocks:
                queue.append(n)

    print("\n" + "="*60)
    print(f"{'BASIC BLOCK CFG LIST':^60}")
    print("="*60)

    for start_idx in sorted(all_blocks.keys()):
        block = all_blocks[start_idx]
        
        if not block.next:
            successors_str = "TERMINATE (EXIT)"
        else:
            formatted_succs = []
            for n in block.next:
                # Format each successor as Block [start - end]
                s_str = f"Block [{n.start:3} - {n.end:3}]"
                
                # Mark back-edges (loops) for easier debugging
                if n.start <= block.start:
                    s_str += " (LOOP BACK)"
                
                formatted_succs.append(s_str)
            
            successors_str = ", ".join(formatted_succs)

        print(f"Block [{block.start:3} - {block.end:3}]")
        print(f"  └── Successors: {successors_str}")
        
    print("="*60 + "\n")


def main():
    args = parser.parse_args()

    instructions = read_bpf_file(args.filename)
    first_block = get_blocks_tree(instructions)

    print_cfg_from_root(first_block)
    runtime_cycle_ub: float = dfs_blocks(first_block, instructions)
    print(f"runtime_cycle_ub: {runtime_cycle_ub}")
    runtime_ub = runtime_cycle_ub / (6.67e8) * 1000
    print(f"runtime_ub: {runtime_ub} ms")


if __name__ == "__main__":
    main()
