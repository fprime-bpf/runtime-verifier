from z3 import (ArithRef, BoolRef, ExprRef, If, BitVecVal,Extract, ZeroExt, SignExt, UDiv, 
                URem, SRem, LShR, If, And, Real, BitVecRef, BitVec, RealVal, BV2Int,
                UGT, UGE, ULT, ULE, BoolVal)

from block import Block
from dataclasses import dataclass, field
from copy import deepcopy
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from typing import List, Optional, Dict, cast, Tuple
from enum import Enum, auto

NUM_REGS = 11

def _init_gp() -> List[BitVecRef]:
    return [BitVec(f"R{i}_0", WORD) for i in range(NUM_REGS)]

def _init_fp() -> List[ArithRef]:
    return [Real(F"f{i}_0") for i in range(NUM_REGS)]

@dataclass
class State:
    gp: List[BitVecRef] = field(default_factory=_init_gp)
    fp: List[ArithRef] = field(default_factory=_init_fp)
    memory: Dict[ExprRef, ExprRef] = field(default_factory=dict)

    def fork(self) -> "State":
        return State(
            gp=deepcopy(self.gp),
            fp=deepcopy(self.fp),
            memory=deepcopy(self.memory),
        )

    def get_gp(self, i): return self.gp[i]
    def set_gp(self, i, e): self.gp[i] = e

    def get_fp(self, i): return self.fp[i]
    def set_fp(self, i, e): self.fp[i] = e


class InstrClass(Enum):
    OP = auto()          # ALU / FPU operation
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


def _is_fpu_instr(instr: BpfInstruction) -> bool:
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


def _decode_instruction(instr: BpfInstruction) -> DecodedInstr:
    
    if _is_fpu_instr(instr):
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
        is_float=_is_fpu_instr(instr),
        instr_class=instr_class,
        dst=instr.dst,
        src=instr.src,
        imm=instr.imm,
        offset=instr.off
    )

WORD = 64

def _zext32(x: ExprRef) -> ExprRef:
    return ZeroExt(WORD - 32, Extract(31, 0, x))

def _is_alu32(decoded_instr: DecodedInstr) -> bool:
    return decoded_instr.instr_class == BpfClass.ALU    # 32-bit
    # ALU64: decoded_instr.instr_class == BpfClass.ALU64

def _update_state_op(decoded_instr: DecodedInstr, state: State) -> None:
    op_name = decoded_instr.name
    dst_idx = decoded_instr.dst

    if decoded_instr.is_float:
        dst_idx = decoded_instr.dst
        op_name = decoded_instr.name

        dst_fp: ArithRef = state.get_fp(dst_idx)

        if op_name.endswith("X"):
            src_fp: ArithRef = state.get_fp(decoded_instr.src)
        else:
            src_fp: ArithRef = RealVal(decoded_instr.imm)

        zero = RealVal(0)

        if op_name.startswith("FADD"):
            new_fp: ArithRef = dst_fp + src_fp
        elif op_name.startswith("FSUB"):
            new_fp = dst_fp - src_fp
        elif op_name.startswith("FMUL"):
            new_fp = cast(ArithRef, dst_fp * src_fp)
        elif op_name.startswith("FDIV"):
            new_fp = cast(ArithRef, If(src_fp == zero, zero, dst_fp / src_fp))
        elif op_name.startswith("FNEG"):
            new_fp = -dst_fp
        elif op_name.startswith("FMOV"):
            if decoded_instr.offset == 0:
                new_fp = src_fp
            else:
                if op_name.endswith("X"):
                    gp_src: BitVecRef = state.get_gp(decoded_instr.src)
                    new_fp = BV2Int(gp_src, False)
                else:
                    new_fp = RealVal(decoded_instr.imm)
        else:
            raise ValueError(f"Unsupported FPU op name: {op_name}")

        state.set_fp(dst_idx, new_fp)
        return
    
    else:
        dst_val: BitVecRef = cast(BitVecRef, state.get_gp(dst_idx))

        if op_name.endswith("X"):
            src_val: ExprRef = state.get_gp(decoded_instr.src)
        else:
            src_val = BitVecVal(decoded_instr.imm, WORD)

        is_32 = _is_alu32(decoded_instr)

        dst32 = cast(BitVecRef, Extract(31, 0, dst_val))
        src32 = cast(BitVecRef, Extract(31, 0, src_val))

        if op_name.startswith("ADD"):
            if is_32:
                res32 = dst32 + src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val + src_val

        elif op_name.startswith("SUB"):
            if is_32:
                res32 = dst32 - src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val - src_val

        elif op_name.startswith("MUL"):
            if is_32:
                res32 = dst32 * src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val * src_val

        elif op_name.startswith("DIV"):
            if is_32:
                res32 = If(src32 == BitVecVal(0, 32),
                        BitVecVal(0, 32),
                        UDiv(dst32, src32))
                new_val = _zext32(cast(BitVecRef, res32))
            else:
                res = If(src_val == BitVecVal(0, WORD),
                        BitVecVal(0, WORD),
                        UDiv(dst_val, src_val))
                new_val = res

        elif op_name.startswith("SDIV"):
            if is_32:
                INT_MIN32 = BitVecVal(1, 32) << 31
                res32 = If(
                    src32 == BitVecVal(0, 32),
                    BitVecVal(0, 32),
                    If(
                        And(src32 == BitVecVal(-1, 32), dst32 == INT_MIN32),
                        INT_MIN32,
                        dst32 / src32,
                    ),
                )
                new_val = _zext32(cast(BitVecRef, res32))
            else:
                LLONG_MIN = BitVecVal(1, WORD) << (WORD - 1)
                res = If(
                    src_val == BitVecVal(0, WORD),
                    BitVecVal(0, WORD),
                    If(
                        And(src_val == BitVecVal(-1, WORD), dst_val == LLONG_MIN),
                        LLONG_MIN,
                        dst_val / src_val,
                    ),
                )
                new_val = res

        elif op_name.startswith("OR"):
            if is_32:
                res32 = dst32 | src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val | src_val

        elif op_name.startswith("AND"):
            if is_32:
                res32 = dst32 & src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val & src_val

        elif op_name.startswith("XOR"):
            if is_32:
                res32 = dst32 ^ src32
                new_val = _zext32(res32)
            else:
                new_val = dst_val ^ src_val

        elif op_name.startswith("LSH"):
            if is_32:
                sh = src32 & BitVecVal(31, 32)
                res32 = dst32 << sh
                new_val = _zext32(res32)
            else:
                sh = src_val & BitVecVal(63, WORD)
                new_val = dst_val << sh

        elif op_name.startswith("RSH"):
            if is_32:
                sh = src32 & BitVecVal(31, 32)
                res32 = LShR(dst32, sh)
                new_val = _zext32(res32)
            else:
                sh = src_val & BitVecVal(63, WORD)
                new_val = LShR(dst_val, sh)

        elif op_name.startswith("ARSH"):
            if is_32:
                sh = src32 & BitVecVal(31, 32)
                res32 = dst32 >> sh
                new_val = _zext32(res32)
            else:
                sh = src_val & BitVecVal(63, WORD)
                new_val = dst_val >> sh

        elif op_name.startswith("NEG"):
            if is_32:
                res32 = -dst32
                new_val = _zext32(res32)
            else:
                new_val = -dst_val

        elif op_name.startswith("MOD"):
            if is_32:
                res32 = If(src32 == BitVecVal(0, 32),
                        dst32,
                        URem(dst32, src32))
                new_val = _zext32(cast(BitVecRef, res32))
            else:
                res = If(src_val == BitVecVal(0, WORD),
                        dst_val,
                        URem(dst_val, src_val))
                new_val = res

        elif op_name.startswith("SMOD"):
            if is_32:
                INT_MIN32 = BitVecVal(1, 32) << 31
                res32 = If(
                    src32 == BitVecVal(0, 32),
                    dst32,
                    If(
                        And(src32 == BitVecVal(-1, 32), dst32 == INT_MIN32),
                        BitVecVal(0, 32),
                        SRem(dst32, src32),
                    ),
                )
                new_val = _zext32(cast(BitVecRef, res32))
            else:
                LLONG_MIN = BitVecVal(1, WORD) << (WORD - 1)
                res = If(
                    src_val == BitVecVal(0, WORD),
                    dst_val,
                    If(
                        And(src_val == BitVecVal(-1, WORD), dst_val == LLONG_MIN),
                        BitVecVal(0, WORD),
                        SRem(dst_val, src_val),
                    ),
                )
                new_val = res

        elif op_name.startswith("MOVSX"):
            width = decoded_instr.imm   # 8 / 16 / 32
            if width == 8:
                res = SignExt(WORD - 8, Extract(7, 0, src_val))
            elif width == 16:
                res = SignExt(WORD - 16, Extract(15, 0, src_val))
            elif width == 32:
                res = SignExt(WORD - 32, Extract(31, 0, src_val))
            else:
                raise ValueError(f"Unsupported MOVSX width: {width}")
            new_val = res

        elif op_name.startswith("MOV"):
            # 32-bit MOV：zero-extend
            if is_32:
                new_val = _zext32(src32)
            else:
                new_val = src_val

        elif op_name.startswith("END"):
            size = decoded_instr.imm
            if size == 16:
                low16: BitVecRef = cast(BitVecRef, Extract(15, 0, dst_val))
                b0: BitVecRef = cast(BitVecRef, Extract(7, 0, low16))
                b1: BitVecRef = cast(BitVecRef, Extract(15, 8, low16))
                res16 = (b0 << 8) | b1
                new_val = ZeroExt(WORD - 16, res16)
            elif size == 32:
                low32: BitVecRef = cast(BitVecRef, Extract(31, 0, dst_val))
                b0: BitVecRef = cast(BitVecRef, Extract(7, 0, low32))
                b1: BitVecRef = cast(BitVecRef, Extract(15, 8, low32))
                b2: BitVecRef = cast(BitVecRef, Extract(23, 16, low32))
                b3: BitVecRef = cast(BitVecRef, Extract(31, 24, low32))
                res32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                new_val = ZeroExt(WORD - 32, res32)
            elif size == 64:
                dst_bv: BitVecRef = cast(BitVecRef, dst_val)
                b0: BitVecRef = cast(BitVecRef, Extract(7, 0, dst_bv))
                b1: BitVecRef = cast(BitVecRef, Extract(15, 8, dst_bv))
                b2: BitVecRef = cast(BitVecRef, Extract(23, 16, dst_bv))
                b3: BitVecRef = cast(BitVecRef, Extract(31, 24, dst_bv))
                b4: BitVecRef = cast(BitVecRef, Extract(39, 32, dst_bv))
                b5: BitVecRef = cast(BitVecRef, Extract(47, 40, dst_bv))
                b6: BitVecRef = cast(BitVecRef, Extract(55, 48, dst_bv))
                b7: BitVecRef = cast(BitVecRef, Extract(63, 56, dst_bv))
                new_val = (
                    (b0 << 56) | (b1 << 48) | (b2 << 40) | (b3 << 32) |
                    (b4 << 24) | (b5 << 16) | (b6 << 8)  | b7
                )
            else:
                raise ValueError(f"Unsupported END size: {size}")

        else:
            raise ValueError(f"Unsupported ALU op name: {op_name}")

        state.set_gp(dst_idx, new_val)


def fresh_gp_var(reg_idx: int, step_idx: int) -> BitVecRef:
    """Create a fresh 64-bit GP register variable R{reg}_I{step}."""
    return BitVec(f"R{reg_idx}_I{step_idx}", WORD)

def fresh_fp_var(reg_idx: int, step_idx: int) -> ArithRef:
    """Create a fresh FP register variable F{reg}_I{step} (modeled as Real)."""
    return Real(f"F{reg_idx}_I{step_idx}")


PKT_BASE = BitVec("pkt_base", WORD)  # abstract packet base pointer
def _mem_addr(decoded_instr: DecodedInstr, state: State) -> BitVecRef:
    """
    Compute an effective address for load/store-like instructions.
    """
    name = decoded_instr.name

    # ---------- Packet ABS/IND forms ----------
    if "_ABS_" in name:
        # Absolute offset into packet: pkt_base + imm
        off = BitVecVal(decoded_instr.imm, WORD)
        return PKT_BASE + off

    if "_IND_" in name:
        # Indexed packet access: pkt_base + src_reg + imm
        idx = state.get_gp(decoded_instr.src)      # BitVecRef
        off = BitVecVal(decoded_instr.imm, WORD)
        return PKT_BASE + idx + off

    # ---------- Register-based memory (stack / map / etc.) ----------
    # Loads: base in src
    if (
        name.startswith("LD_MEM_")
        or name.startswith("LD_MEMSX_")
        or name.startswith("FLD_")
        or name.startswith("LDX_")
        or name.startswith("FLDX_")
    ):
        base_idx = decoded_instr.src

    # Stores: base in dst
    elif (
        name.startswith("ST_")
        or name.startswith("ST_MEMSX_")
        or name.startswith("FST_")
        or name.startswith("STX_")
        or name.startswith("STX_MEMSX_")
        or name.startswith("FSTX_")
    ):
        base_idx = decoded_instr.dst

    else:
        raise ValueError(f"Unsupported load/store opcode for _mem_addr: {name}")

    base: BitVecRef = state.get_gp(base_idx)
    off = BitVecVal(decoded_instr.offset, WORD)
    return base + off


def _fresh_mem_val(is_float: bool, idx: int) -> ExprRef:
    """
    Create a fresh symbolic value for a memory cell.
    Integer loads use a BitVec; FP loads use a Real.
    """
    if is_float:
        return Real(f"mem_f_{idx}")        # Real for FP memory cell
    else:
        return BitVec(f"mem_{idx}", WORD)  # BitVec for integer memory cell


# classify by opcode name
_LOAD_PREFIXES  = ("LD_", "LDX_", "FLD_", "FLDX_")
_STORE_PREFIXES = ("ST_", "STX_", "FST_", "FSTX_")

def _exec_mem(decoded_instr: DecodedInstr, state: State) -> Optional[BitVecRef]:
    """
    Execute a memory-related instruction symbolically.

    Responsibilities:
      - Handle LD_IMM_*/LDDW: update dst register, no memory, return None.
      - Handle ST_IMM_*/STX_IMM_*: write imm into [dst + off], return addr.
      - For real loads/stores (LD*/LDX*/ST*/STX*/FLD*/FST*):
          * compute addr = _mem_addr(...)
          * update state.memory[addr]
          * for loads, also update dst register.

    Returns:
        addr (BitVecRef) if this instruction touches memory,
        or None if it only updates registers (e.g., LD_IMM/LDDW).
    """
    name = decoded_instr.name
    dst  = decoded_instr.dst
    src  = decoded_instr.src

    # ----- 1) Immediate-only loads: LD_IMM_*, LDX_IMM_*, LDDW -----
    if name.startswith("LD_IMM_") or name.startswith("LDX_IMM_") or name == "LDDW":
        imm_val = BitVecVal(decoded_instr.imm, WORD)
        state.set_gp(dst, imm_val)
        return None

    # ----- 2) Immediate stores: ST_IMM_* / STX_IMM_* -----
    if name.startswith("ST_IMM_") or name.startswith("STX_IMM_"):
        base = state.get_gp(dst)
        off  = BitVecVal(decoded_instr.offset, WORD)
        addr = base + off

        imm_val = BitVecVal(decoded_instr.imm, WORD)
        state.memory[addr] = imm_val
        return addr

    # ----- 3) All other real memory accesses go via _mem_addr -----
    addr = _mem_addr(decoded_instr, state)

    # 3a) Loads (LD_*, LDX_*, FLD_*, FLDX_*, and the LD_MEMSX_* variants)
    if name.startswith(_LOAD_PREFIXES):
        # lazily initialize memory cell if we haven't seen this address before
        if addr not in state.memory:
            fresh_idx = len(state.memory)
            state.memory[addr] = _fresh_mem_val(decoded_instr.is_float, fresh_idx)

        cell_val: ExprRef = state.memory[addr]

        if decoded_instr.is_float:
            state.set_fp(dst, cell_val)
        else:
            state.set_gp(dst, cell_val)

        return addr

    # 3b) Stores (ST_*, STX_*, FST_*, FSTX_* and MEMSX variants)
    if name.startswith(_STORE_PREFIXES):
        if decoded_instr.is_float:
            val: ExprRef = state.get_fp(src)
        else:
            val = state.get_gp(src)

        state.memory[addr] = val
        return addr

    raise ValueError(f"_exec_mem called on unsupported opcode: {name}")


def _branch_condition(decoded_instr: DecodedInstr, state: State) -> BoolRef:
    """
    Compute the Z3 condition under which this jump is taken.
    For integer jumps we use BitVec semantics (unsigned vs signed as per spec).
    For floating jumps we use Reals (no NaN modeling; ordered/unordered
    variants are approximated as simple comparisons).
    """
    op_name = decoded_instr.name
    dst_idx = decoded_instr.dst

    # ---------- floating-point jumps ----------
    if decoded_instr.is_float:
        dst_fp: ArithRef = state.get_fp(dst_idx)

        if op_name.endswith("X"):
            src_fp: ArithRef = state.get_fp(decoded_instr.src)
        else:
            src_fp: ArithRef = RealVal(decoded_instr.imm)

        # JFEQ:   PC += off if dst == src
        if op_name.startswith("JFEQ"):
            return cast(BoolRef, dst_fp == src_fp)

        # JFNE:   PC += off if dst != src
        elif op_name.startswith("JFNE"):
            return cast(BoolRef, dst_fp != src_fp)

        # Ordered >, >=, <, <=  (JFOGT / JFOGE / JFOLT / JFOLE)
        elif op_name.startswith("JFOGT"):
            return dst_fp > src_fp
        elif op_name.startswith("JFOGE"):
            return dst_fp >= src_fp
        elif op_name.startswith("JFOLT"):
            return dst_fp < src_fp
        elif op_name.startswith("JFOLE"):
            return dst_fp <= src_fp

        # Unordered >, >=, <, <= (JFUGT / JFUGE / JFULT / JFULE)
        elif op_name.startswith("JFUGT"):
            return dst_fp > src_fp
        elif op_name.startswith("JFUGE"):
            return dst_fp >= src_fp
        elif op_name.startswith("JFULT"):
            return dst_fp < src_fp
        elif op_name.startswith("JFULE"):
            return dst_fp <= src_fp

        else:
            raise ValueError(f"Unsupported FP branch opcode: {op_name}")

    # ---------- integer jumps ----------
    dst_gp: BitVecRef = state.get_gp(dst_idx)

    if op_name.endswith("X"):
        src_gp: BitVecRef = state.get_gp(decoded_instr.src)
    else:
        src_gp: BitVecRef = BitVecVal(decoded_instr.imm, WORD)

    # Unconditional jump: always taken
    if op_name.startswith("JA"):
        return BoolVal(True)

    # Equality / inequality
    if op_name.startswith("JEQ"):
        return cast(BoolRef, dst_gp == src_gp)
    if op_name.startswith("JNE"):
        return cast(BoolRef, dst_gp != src_gp)

    # Unsigned comparisons (JGT/JGE/JLT/JLE)
    if op_name.startswith("JGT"):
        return UGT(dst_gp, src_gp)          # dst > src (unsigned)
    if op_name.startswith("JGE"):
        return UGE(dst_gp, src_gp)          # dst >= src (unsigned)
    if op_name.startswith("JLT"):
        return ULT(dst_gp, src_gp)          # dst < src (unsigned)
    if op_name.startswith("JLE"):
        return ULE(dst_gp, src_gp)          # dst <= src (unsigned)

    # Signed comparisons (JSGT/JSGE/JSLT/JSLE)
    if op_name.startswith("JSGT"):
        return dst_gp > src_gp              # signed >
    if op_name.startswith("JSGE"):
        return dst_gp >= src_gp             # signed >=
    if op_name.startswith("JSLT"):
        return dst_gp < src_gp              # signed <
    if op_name.startswith("JSLE"):
        return dst_gp <= src_gp             # signed <=

    # Bit-test jump: dst & src != 0
    if op_name.startswith("JSET"):
        return cast(BoolRef, (dst_gp & src_gp) != BitVecVal(0, WORD))

    raise ValueError(f"Unsupported integer branch opcode: {op_name}")


def process_instruction(instr: BpfInstruction, state: State, instr_idx: int) -> Tuple[Optional[BoolRef], Optional[BitVecRef]]:
    """    
    Symbolically evaluates a single eBPF instruction.
    Added 'instr_idx' to support deterministic naming of symbolic variables.
    """
    decoded_instr = _decode_instruction(instr)
    
    branch_cond: Optional[BoolRef] = None
    addr: Optional[BitVecRef] = None

    match decoded_instr.instr_class:
        case InstrClass.OP:
            _update_state_op(decoded_instr, state)

        case InstrClass.LOAD_STORE:
            addr = _exec_mem(decoded_instr, state)

        case InstrClass.BRANCH:
            if decoded_instr.name == "EXIT":
                branch_cond = None
                addr = None

            elif decoded_instr.name == "CALL":
                func_id = decoded_instr.imm
                
                if func_id == 1:
                    new_r0 = fresh_gp_var(0, instr_idx)
                    state.set_gp(0, new_r0)
                # Both addr and branch_cond are None
 
            else:
                branch_cond = _branch_condition(decoded_instr, state)

        case InstrClass.OTHER:
            pass
        
    return (branch_cond, addr)