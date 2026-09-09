# For a eBPF program along with a trace, determine what instructions will be executed after sometimes.
"""Intended Usage
`python3 determine.py [program] [trace] [splits] [output]`
`program`: path to eBPF program. For example, "/home/cw3723/bpf-prime/tests/aberr/a.o".
`trace`: trace of that eBPF program. Using same example as above, would be "/home/cw3723/bpf-prime/tests/aberr/trace.yml".
`splits`: how many equal parts will the execution trace be split into. Suppose a program runs for a total 100 cycles, and `splits=4`, then 
we would output the instruction executed at cycle 20,40,60,80. It's not always to get equal cycle counts (total cycle count might not be
divisible by the split, and instructions take varying amount of cycles) for each part in the 
trace, just make them as "equal" as possible. Use the longest execution trace of the program (starting from entry).
`output`: path to a yaml file used as output. when it already exits, clear existing contents.
"""
from __future__ import annotations

"""Output Format (yaml)
- meta:
    - dir: "aberr" #bottom 2 level paths containing the eBPF program. For "/home/cw3723/bpf-prime/tests/aberr/a.o", it would be "tests/aberr".
    - split: 3 #A number containing the value of `splits`.
    - max: 100 #cycle count of longest execution path.
- data:
    - 40 #Only output PC if instruction isn't in a loop. We don't care whether it's inside a eBPF function or not.
    - 20 #Doesn't have to be sorted according to PC.
    - 60: #When it's in a loop, we need to describe which iteration.
        - offset: value #offset of the location that stores `struct bpf_iter_num it` relative to r10. value of `bpf_iter_num::curr`.
    - 80: #Possible that it's nested in many loops.
        - offset1: value1
        - offset2: value2
"""
"""Output Format Explanation
Element in the list can be either a plain number to represent index of eBPF instruction or a key-value pair also describing 
at which iteration do we aim for.

PC should match how trace files or "pc_gap.py" uses them. 

Both `offset` and `value` are numbers.

eBPF programs in "/home/cw3723/bpf-prime/tests/" will use iteration helper functions in "/home/cw3723/bpf-prime/Components/BpfSequencer/iter_bpf_helpers.cpp"
to perform iterations. The first argument is a pointer to a `struct bpf_iter_num it` defined in "/home/cw3723/bpf-prime/tests/bpf_shim.h". In eBPF, 
the first argument is stored in r1. All eBPF programs will put this struct in the stack, therefore the pointer is a fixed offset to r10. You can work 
backward from a call to these external iteration helpers and find the last modification to r1 to verify this. `offset` refers to this offset to r10l,
we can use this to find out where the loop counter lives in stack. For nested loops, there would be multiple loop counter struct, see "/home/cw3723/bpf-prime/tests/nccscore/program.bpf.c".
`bpf_iter_num::curr` is the current value of the loop counter. We wish to know at what iterations do the expected cycle count reaches some number. We can 
insert conditional branching on the value of `curr` to determine whether we reached this point when actually running the programs. A pair of (offset,value) 
describes a particular iteration in 1 loop. Multiple such pairs can describe iteration in nested loops.
"""

"""Implementation Guides
Longest path: "pc_gap.py" uses the trace files to find the longest cycle count gap between 2 eBPF instructions marked by 2 PCs. This 
might help you find the longest path in an eBPF program.

Loop Iterations: The "steps" or path used in "pc_gap.py" has the loops unrolled. You can use this to find out what iterations each 
loop is at when we reach the desired cycle count. 

"pc_gap.py": this file may serve as a reference, but if you find a better way to do the job here, feel free to do so.

Even splitting: Equal splitting isn't always possible. A simple way would to be keep following the execution trace until 
we path some threshold, and record the PC and iterations that we reached the threshold. Suppose max cycle count is 100 and split=4,
then thresholds would be 20,40,60,80. We would then walk the trace until the time at this point reaches cycle=20, and so on so fourth.
Not sure if there are more efficient ways to achieve similar things.

Finding offsets: it should be possible to go backward from each call to iteration helper functions and find the last changes to
r1 (the first argument). Existing code in this repo should already do something like this when reasoning about loops.

Finding iteration value: existing code in this repo already unroll loops. In fact, I think the "graph" in "pc_gap.py" already have
loops unrolled. Existing code may also track values of loop counter already. Note that we don't care about which function is the 
cycle count reached in (ignoring call stack context).
"""

import argparse
from pathlib import Path

import yaml

from bpf import BpfClass, BpfCode, BpfMode, BpfS, BpfSize
from dfs import (
    DEFAULT_MAX_UNROLLED_BLOCKS,
    build_cycle_mapping,
    build_helper_call_costs,
    build_op_info_by_name,
    check_trace_soundness,
    find_loops,
    load_trace,
    unroll_loops_in_cfg,
)
from main import get_blocks_tree, read_bpf_file
from profiles import PROFILES
from runtime_benchmark import replay_path


def find_stack_offset(instructions: dict, path_pcs: list[int], call_position: int) -> int:
    """Find the constant in r1 = r10 + constant before an iterator call."""
    register: int | None = 1
    stack_slot: int | None = None
    offset = 0

    for pc in reversed(path_pcs[:call_position]):
        instruction = instructions[pc]
        cls = instruction.get_class()

        if stack_slot is not None:
            if (cls in (BpfClass.ST, BpfClass.STX)
                    and instruction.dst == 10
                    and instruction.get_mode() in (BpfMode.MEM, BpfMode.ATOMIC)):
                width = {
                    BpfSize.B: 1, BpfSize.H: 2,
                    BpfSize.W: 4, BpfSize.DW: 8,
                }[instruction.opcode & 0x18]
                overlaps = (instruction.off < stack_slot + 8
                            and stack_slot < instruction.off + width)
                if overlaps:
                    if (cls == BpfClass.STX and width == 8
                            and instruction.off == stack_slot):
                        register = instruction.src
                        stack_slot = None
                        if register == 10:
                            return offset
                        continue
                    break
            continue

        if cls == BpfClass.JMP and instruction.opcode == 0x85:
            assert register is not None
            if register <= 5:
                break
            continue
        if instruction.dst != register:
            continue
        if (cls == BpfClass.LDX and instruction.src == 10
                and instruction.get_mode() == BpfMode.MEM
                and instruction.opcode & 0x18 == BpfSize.DW):
            stack_slot = instruction.off
            register = None
            continue
        if cls == BpfClass.ALU64:
            code = instruction.opcode & 0xF0
            source_is_register = bool(instruction.opcode & BpfS.X)
            if code == BpfCode.ALU.ADD and not source_is_register:
                offset += instruction.imm
                continue
            if code == BpfCode.ALU.SUB and not source_is_register:
                offset -= instruction.imm
                continue
            if code == BpfCode.ALU.MOV and source_is_register:
                register = instruction.src
                if register == 10:
                    return offset
                continue
        if cls in (BpfClass.ALU, BpfClass.ALU64, BpfClass.LD, BpfClass.LDX):
            break

    call_pc = path_pcs[call_position]
    raise ValueError(f"cannot find a fixed r10-relative iterator address before pc={call_pc}")


def loop_stack_offsets(loop_list: list, instructions: dict, steps: list[tuple]) -> dict:
    path_pcs = [step[0] for step in steps]
    offsets = {}
    for loop in loop_list:
        if loop.call_5_pc is None:
            continue
        try:
            call_position = path_pcs.index(loop.call_5_pc)
        except ValueError:
            continue
        offsets[loop] = find_stack_offset(instructions, path_pcs, call_position)
    return offsets


def checkpoint_steps(steps: list[tuple], splits: int) -> tuple[int, list[tuple]]:
    total = steps[-1][3] if steps else 0
    checkpoints = []
    position = 0

    for part in range(1, splits + 1):
        while (position < len(steps) - 1
               and steps[position][3] * (splits + 1) < total * part):
            position += 1
        if steps:
            checkpoints.append(steps[position])
    return total, checkpoints


def loops_at_pc(loop_list: list, pc: int, iteration: tuple[int, ...]) -> list:
    active = [
        loop for loop in loop_list
        if any(block.start <= pc <= block.end for block in loop.original_members)
    ]
    active.sort(key=lambda loop: loop.depth)
    if len(active) != len(iteration):
        raise ValueError(
            f"cannot match loop indexes {iteration} to enclosing loops at pc={pc}"
        )
    return active


def format_checkpoint(pc: int, iteration: tuple[int, ...] | None,
                      loop_list: list, offsets: dict):
    if iteration is None:
        return pc

    values = []
    for loop, index in zip(loops_at_pc(loop_list, pc, iteration), iteration):
        if loop not in offsets or loop.start_value is None:
            raise ValueError(f"loop at pc={loop.header.start} has incomplete iterator data")
        values.append({offsets[loop]: loop.start_value + index})
    return {pc: values}


def program_dir(program: str) -> str:
    parts = Path(program).resolve().parent.parts
    return "/".join(parts[-2:])


def determine(program: str, trace_path: str, splits: int, profile_name: str,
              max_unrolled_blocks: int = DEFAULT_MAX_UNROLLED_BLOCKS) -> dict:
    if splits <= 0:
        raise ValueError("splits must be greater than zero")

    profile = PROFILES[profile_name]
    traces, metadata = load_trace(trace_path)
    check_trace_soundness(metadata, profile)
    instructions = read_bpf_file(program)
    first_block = get_blocks_tree(instructions)
    loop_list = find_loops(first_block, instructions)
    unrolled_block = unroll_loops_in_cfg(
        first_block, loop_list, max_unrolled_blocks=max_unrolled_blocks
    )

    op_info = build_op_info_by_name(profile)
    cycle_mapping = build_cycle_mapping(op_info)
    helper_costs = build_helper_call_costs(profile)
    longest = None
    longest_total = -1

    for path_index, trace in enumerate(traces):
        if trace.decision_path is None:
            raise ValueError(
                f"path {path_index} has no decision_path; regenerate the trace"
            )
        steps = replay_path(
            unrolled_block, instructions, trace, cycle_mapping,
            helper_costs, op_info, profile,
        )
        total = steps[-1][3] if steps else 0
        if total > longest_total:
            longest = steps
            longest_total = total

    if longest is None:
        raise ValueError("trace has no execution paths")

    total, checkpoints = checkpoint_steps(longest, splits)
    offsets = loop_stack_offsets(loop_list, instructions, longest)
    data = [
        format_checkpoint(pc, iteration, loop_list, offsets)
        for pc, _name, _cost, _cumulative, iteration in checkpoints
    ]
    return {
        "meta": {"dir": program_dir(program), "split": splits, "max": total},
        "data": data,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", help="Path to the raw eBPF program")
    parser.add_argument("trace", help="Path to the execution trace")
    parser.add_argument("splits", type=int, help="Number of checkpoints")
    parser.add_argument("output", help="Path to the output YAML file")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="polarfire")
    parser.add_argument(
        "--max-unrolled-blocks", type=int, default=DEFAULT_MAX_UNROLLED_BLOCKS
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = determine(
            args.program, args.trace, args.splits, args.profile,
            args.max_unrolled_blocks,
        )
    except ValueError as error:
        parser.error(str(error))

    with open(args.output, "w") as output:
        yaml.safe_dump(result, output, sort_keys=False)


if __name__ == "__main__":
    main()

"""Problem
The current `find_stack_offset` doesn't handle cases like this:
`
  59: r1 = r10
  60: r1 += -1232
  61: *(u64 *)(r10 - 1296) = r1    # spill iterator address
  62: call 7                       # clobbers argument registers
  63: r1 = *(u64 *)(r10 - 1296)    # reload iterator address
  ...
  66: call 5
`
. This happens in "/home/cw3723/bpf-prime/tests/matmul" and "/home/cw3723/bpf-prime/tests/nccscore/". Existing 
symbolic executor implementation in "mem_access.py" doesn't have this problem; you may find inspiration on how 
to solve this problem.
"""
