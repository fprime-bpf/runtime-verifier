from z3 import Solver, Int, IntVal, Abs, Not, sat, simplify, ArithRef, BoolRef, ExprRef
from block import Block
from dfs import is_fpu_instr, BPF_INFO, BPF_INFO_FPU
from dataclasses import dataclass, field
from copy import deepcopy
from bpf import BpfInstruction, BpfClass
from typing import List, Optional, Dict
from enum import Enum, auto


@dataclass
class State:
    gp: List[ExprRef]          # len 11, R0..R10
    fp: List[ExprRef]          # len 11, F0..F10
    memory: Dict[int, ExprRef]

    def fork(self) -> "State":
        return State(
            gp=deepcopy(self.gp),
            fp=deepcopy(self.fp),
            memory=deepcopy(self.memory)
        )

    def get_gp(self, i): return self.gp[i]
    def set_gp(self, i, e): self.gp[i] = e

    def get_fp(self, i): return self.fp[i]
    def set_fp(self, i, e): self.fp[i] = e


class InstrClass(Enum):
    OP = auto()          # ALU / FPU operation（整数 or 浮点）
    LOAD_STORE = auto()  # load / store
    BRANCH = auto()      # branch / call / exit
    OTHER = auto()


@dataclass
class DecodedInstr:
    # Same as OpInfo.name
    name: str

    # True = floating, False = integer
    is_float: bool
    
    instr_class: InstrClass

    dst: int
    src: int
    imm: int
    offset: int


def _decode_instruction(instr: BpfInstruction) -> DecodedInstr:
    
    if is_fpu_instr(instr):
        op_info = BPF_INFO_FPU.get(instr.opcode)  # FADD / FNEG / JFEQ / JFOGT ...
    else:
        op_info = BPF_INFO.get(instr.opcode)      # ALU/MEM ... + FLDX & FSTX

    if not op_info:
        raise ValueError("Cannot identify instruction name")
    
    cls_ = instr.get_class()
    if cls_ in (BpfClass.ALU, BpfClass.ALU64):
        instr_class = InstrClass.OP

    elif cls_ in (BpfClass.LD, BpfClass.LDX, BpfClass.ST, BpfClass.STX):
        instr_class = InstrClass.LOAD_STORE

    elif cls_ in (BpfClass.JMP, BpfClass.JMP32):
        instr_class = InstrClass.BRANCH
    else:
        instr_class = InstrClass.OTHER

    return DecodedInstr(
        name=op_info.name,
        is_float=is_fpu_instr(instr),
        instr_class=instr_class,
        dst=instr.dst,
        src=instr.src,
        imm=instr.imm,
        offset=instr.off
    )

def _process_instruction(instr: BpfInstruction, state: State) -> None:
    decoded_instr = _decode_instruction(instr)
    match decoded_instr.instr_class:
        case InstrClass.OP:
            # Distinguish here or in another function
            if decoded_instr.is_float:
                pass
            else:
                pass

        case InstrClass.LOAD_STORE:
            pass

        case InstrClass.BRANCH:
            pass

        case InstrClass.OTHER:
            pass