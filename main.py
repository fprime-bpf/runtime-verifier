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
    instructions: list[BpfInstruction], start_idx=0, seen: set | None = None
) -> Block:
    """Processes instruction set into a Control Flow Graph (CFG).

    Returns a Block class, resembling a Basic Block,
    which includes a start and end index, as well as a list of children blocks.
    All basic blocks have exactly one entry (first instruction)
    and one exit (last instruction).
    All basic blocks have either no following blocks (program end),
    one following block (usually function call)
    or two following blocks (branch condition)."""

    if seen is None:
        seen = set()

    if start_idx in seen:
        raise Exception(f"detected loop: block at idx={start_idx} loops")

    seen.add(start_idx)

    for idx in range(start_idx, len(instructions)):
        ins = instructions[idx]
        print(f"idx={idx}: instruction={str(ins)}")

        # python match case expressions are structural by default,
        # meaning they match structure (e.g. are you of type int?),
        # not values (e.g. are you 221?)
        # we go around this with our `x if x == (value)`
        match ins.opcode:
            # unconditional jumps
            case x if x == BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:
                print(f"idx={idx}: EXIT")
                return Block(start_idx, idx)

            case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP:  # offset jump
                block = Block(start_idx, idx)
                jump_to = idx + ins.off + 1
                print(f"idx={idx}: jump_to={jump_to}")

                next = get_blocks_tree(instructions, jump_to, seen.copy())
                block.add(next)
                return block

            case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP32:  # imm jump
                block = Block(start_idx, idx)
                jump_to = idx + ins.imm + 1
                print(f"idx={idx}: jump_to={jump_to}")

                next = get_blocks_tree(instructions, jump_to, seen.copy())
                block.add(next)
                return block

            case x if x == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:
                block = Block(start_idx, idx)
                # start.add(idx + 1)
                match ins.src:
                    case 0:
                        print("calling helper function by static id")
                        continue
                    case 1:
                        print(f"calling normal function")
                        jump_to = idx + ins.imm + 1
                        next = get_blocks_tree(instructions, jump_to, seen.copy())
                        block.add(next)
                        return block
                    case 2:
                        print("calling helper function by BTF id")
                        continue

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
                block = Block(start_idx, idx)
                jump_if = idx + ins.off + 1
                jump_else = idx + 1
                print(f"idx={idx}: jump_if={jump_if}, jump_else={jump_else}")

                next_if = get_blocks_tree(instructions, jump_if, seen.copy())
                next_else = get_blocks_tree(instructions, jump_else, seen.copy())
                block.add(next_if)
                block.add(next_else)
                return block

            case _:
                if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                    raise Exception(f"idx={idx}: couldn't catch opcode: {ins.opcode}")

    raise Exception(f"unreachable")


def main():
    args = parser.parse_args()

    instructions = read_bpf_file(args.filename)
    first_block = get_blocks_tree(instructions)

    print(f"blocks: {first_block}")
    runtime_ub: float = dfs_blocks(first_block, instructions)
    print(f"runtime_ub: {runtime_ub}")


if __name__ == "__main__":
    main()
