from z3 import (ArithRef, BoolRef, ExprRef, If, BitVecVal,Extract, ZeroExt, SignExt, UDiv, 
                URem, SRem, LShR, If, And, Real, BitVecRef, BitVec, RealVal, BV2Int,
                UGT, UGE, ULT, ULE, BoolVal, is_bv, is_arith, is_bool, Int2BV, ToInt, ToReal, BV2Int,
                is_true, is_false, simplify, is_bv_value, is_app, Z3_OP_UNINTERPRETED)

from dataclasses import dataclass, field
from bpf import BpfClass, BpfCode, BpfInstruction, Mask, Shift, BPF_INFO, BPF_INFO_FPU
from typing import List, Optional, Dict, cast, Tuple
from enum import Enum, auto

NUM_REGS = 11
WORD = 64

def to_bv64(expr):
    """
    Safely coerces any Z3 expression into a 64-bit BitVector.
    """
    if is_bv(expr):
        return expr
    if is_arith(expr):
        # Convert Arithmetic/Real expressions to Integer then to 64-bit BitVec
        return Int2BV(ToInt(expr), WORD)
    if is_bool(expr):
        # Map boolean results to 1 or 0
        return If(expr, BitVecVal(1, WORD), BitVecVal(0, WORD))
    if isinstance(expr, int):
        return BitVecVal(expr, WORD)
    return expr

def to_arith(expr):
    """
    Safely coerces any Z3 expression into an Arithmetic/Real expression.
    """
    if is_arith(expr):
        return expr
    if is_bv(expr):
        # Interpret the BitVector as an integer and convert to Real
        return ToReal(BV2Int(expr))
    if isinstance(expr, (int, float)):
        return RealVal(expr)
    return expr


def normalize_huge_bv(expr):
    if expr is None:
        return None
    
    if is_bv_value(expr):
        val = expr.as_long()
        if val >= (1 << 63):
            signed_val = val - (1 << 64)
            return BitVecVal(signed_val, 64)
        return expr

    if is_app(expr):
        children = [normalize_huge_bv(c) for c in expr.children()]
        return expr.decl()(*children)
        
    return expr


@dataclass
class State:
    gp: List[BitVecRef] = field(default_factory=list)
    fp: List[ArithRef] = field(default_factory=list)
    memory: Dict[ExprRef, ExprRef] = field(default_factory=dict)
    _is_initial: bool = field(default=True, repr=False)
    
    def __post_init__(self):
        if not self._is_initial:
            return
        
        self.gp = [None] * NUM_REGS
        self.fp = [None] * NUM_REGS
        for i in range(NUM_REGS):
            self.gp[i] = BitVecVal(0, WORD)
            
        for i in range(NUM_REGS):
            self.fp[i] = RealVal(0)
            
        self.set_gp(10, BitVec("R10_FP", WORD))
        self.set_gp(1, BitVec("R1_CTX", WORD))
        self.set_gp(0, BitVec("R0_RET", WORD))

    def fork(self) -> "State":
        return State(
            gp=self.gp[:],
            fp=self.fp[:],
            memory=self.memory.copy(),
            _is_initial=False,
        )

    def get_gp(self, i): return self.gp[i]
    def set_gp(self, i, e):
        val = to_bv64(e)
        self.gp[i] = simplify(val, som=True)

    def get_fp(self, i): return self.fp[i]
    def set_fp(self, i, e):
        val = to_arith(e)
        self.fp[i] = simplify(val, som=True)


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

    bpf_class: BpfClass


def _is_fpu_instr(instr: BpfInstruction) -> bool:
    """
    Determines if an instruction belongs to the BPF_INFO_FPU lookup table.
    
    Returns:
        True: For FP arithmetic (ALU) or FP branch (JMP) instructions.
        False: For FP memory access (stored in BPF_INFO/FMEM) or any integer instructions.
    
    Note: Due to design specificities, FMEM instructions (e.g., FLDX, FSTX) are 
    handled as non-FPU class in this context.
    """
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
        is_float=op_info.name.startswith('F') or op_info.name.startswith('JF') ,
        instr_class=instr_class,
        dst=instr.dst,
        src=instr.src,
        imm=instr.imm,
        offset=instr.off,
        bpf_class=cls_
    )


def _zext32(x: ExprRef) -> ExprRef:
    return ZeroExt(WORD - 32, Extract(31, 0, x))

def _is_alu32(decoded_instr: DecodedInstr) -> bool:
    return decoded_instr.bpf_class == BpfClass.ALU

def _is_concrete(e) -> bool:
    """
    Safely checks if a Z3 expression is a concrete value (numeral/constant) 
    rather than a symbolic variable. Supports BitVec, Int, Real, and Bool.
    """
    if not hasattr(e, 'decl'):
        return isinstance(e, (int, float, bool))
        
    return e.decl().kind() != Z3_OP_UNINTERPRETED

def _safe_div(dst, src, size, signed=False):
    if _is_concrete(dst) and _is_concrete(src):
        d, s = dst.as_long(), src.as_long()
        if signed:
            mask = 1 << (size - 1)
            d = d if d < mask else d - (1 << size)
            s = s if s < mask else s - (1 << size)
            
        if s == 0: return BitVecVal(0, size)
        
        if signed and s == -1 and d == -(1 << (size - 1)):
            return BitVecVal(d, size)
            
        res = int(d / s) if signed else (d // s)
        return BitVecVal(res, size)

    if not signed:
        return If(src == 0, BitVecVal(0, size), UDiv(dst, src))
    else:
        min_val = 1 << (size - 1)
        return If(src == 0, BitVecVal(0, size),
                  If(And(src == -1, dst == min_val), BitVecVal(min_val, size), dst / src))

def _safe_mod(dst, src, size, signed=False):
    if _is_concrete(dst) and _is_concrete(src):
        d, s = dst.as_long(), src.as_long()
        if signed:
            mask = 1 << (size - 1)
            d = d if d < mask else d - (1 << size)
            s = s if s < mask else s - (1 << size)

        if s == 0: return BitVecVal(d if not signed else d, size)
        
        if signed and s == -1 and d == -(1 << (size - 1)):
            return BitVecVal(0, size)
            
        res = d % s
        return BitVecVal(res, size)

    if not signed:
        return If(src == 0, dst, URem(dst, src))
    else:
        min_val = 1 << (size - 1)
        return If(src == 0, dst,
                  If(And(src == -1, dst == min_val), BitVecVal(0, size), SRem(dst, src)))

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
        if dst_val is not None:
            dst32 = cast(BitVecRef, Extract(31, 0, dst_val))
        if src_val is not None:
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
                new_val = _zext32(cast(BitVecRef, _safe_div(dst32, src32, 32, signed=False)))
            else:
                new_val = _safe_div(dst_val, src_val, WORD, signed=False)

        elif op_name.startswith("SDIV"):
            if is_32:
                new_val = _zext32(cast(BitVecRef, _safe_div(dst32, src32, 32, signed=True)))
            else:
                new_val = _safe_div(dst_val, src_val, WORD, signed=True)

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
                new_val = _zext32(cast(BitVecRef, _safe_mod(dst32, src32, 32, signed=False)))
            else:
                new_val = _safe_mod(dst_val, src_val, WORD, signed=False)

        elif op_name.startswith("SMOD"):
            if is_32:
                new_val = _zext32(cast(BitVecRef, _safe_mod(dst32, src32, 32, signed=True)))
            else:
                new_val = _safe_mod(dst_val, src_val, WORD, signed=True)

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


def fresh_gp_var(reg_idx: int, unique_id: str) -> BitVecRef:
    """Create a fresh 64-bit GP register variable R{reg}_{unique_id}."""
    safe_id = unique_id.replace('.', '_').replace('@', '_')
    return BitVec(f"R{reg_idx}_{safe_id}", WORD)

def fresh_fp_var(reg_idx: int, unique_id: str) -> ArithRef:
    """Create a fresh FP register variable F{reg}_{unique_id} (modeled as Real)."""
    safe_id = unique_id.replace('.', '_').replace('@', '_')
    return Real(f"F{reg_idx}_{safe_id}")


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


def _fresh_mem_val(is_float: bool, reg: int, unique_id: str) -> ExprRef:
    """
    Create a fresh symbolic value for a memory cell.
    Integer loads use a BitVec; FP loads use a Real.
    The unique_id ensures variable names are distinct across unrolled loop iterations.
    """
    safe_id = unique_id.replace('.', '_').replace('@', '_')
    if is_float:
        return Real(f"mem_f{reg}_{safe_id}")        # Real for FP memory cell
    else:
        return BitVec(f"mem_g{reg}_{safe_id}", WORD)  # BitVec for integer memory cell


# classify by opcode name
_LOAD_PREFIXES  = ("LD_", "LDX_", "FLD_", "FLDX_")
_STORE_PREFIXES = ("ST_", "STX_", "FST_", "FSTX_")

def _exec_mem(decoded_instr: DecodedInstr, state: State, unique_instr_id: str) -> Optional[BitVecRef]:
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
            state.memory[addr] = _fresh_mem_val(decoded_instr.is_float, dst, unique_instr_id)

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


def process_instruction(instr: BpfInstruction, state: State, unique_instr_id: str) -> Tuple[Optional[BoolRef], Optional[BitVecRef]]:
    """    
    Symbolically evaluates a single eBPF instruction.
    'unique_instr_id' is used for deterministic naming of symbolic variables.
    """
    decoded_instr = _decode_instruction(instr)
    
    branch_cond: Optional[BoolRef] = None
    addr: Optional[BitVecRef] = None

    match decoded_instr.instr_class:
        case InstrClass.OP:
            _update_state_op(decoded_instr, state)

        case InstrClass.LOAD_STORE:
            addr = _exec_mem(decoded_instr, state, unique_instr_id)

        case InstrClass.BRANCH:
            if decoded_instr.name == "EXIT":
                branch_cond = None
                addr = None

            elif decoded_instr.name == "CALL":
                # Per the eBPF calling convention, helper calls can modify
                # registers R0-R5. We model this by creating new, unconstrained
                # symbolic variables for each of them. R0 holds the return value.
                for reg_idx in range(6): # Clobber R0 through R5
                    new_reg_val = fresh_gp_var(reg_idx, unique_instr_id)
                    state.set_gp(reg_idx, new_reg_val)
                # Both addr and branch_cond are None
 
            else:
                branch_cond = _branch_condition(decoded_instr, state)

        case InstrClass.OTHER:
            pass
        
    return (branch_cond, addr)


def get_vars_from_expr(expr: ExprRef) -> set:
    if not hasattr(expr, 'children'):
        return set()
    
    variables = set()
    if expr.num_args() == 0:
        if not _is_concrete(expr): 
            variables.add(str(expr))
    else:
        for child in expr.children():
            variables.update(get_vars_from_expr(child))
    return variables


def get_all_var_names(data) -> set:
    """
    - Single Z3 exprs (BoolRef, BitVecRef, ArithRef)
    - Sequences (list, tuple)
    - Mappings (dict)
    """
    names = set()
    
    if isinstance(data, (list, tuple)):
        for item in data:
            names.update(get_all_var_names(item))
            
    elif isinstance(data, dict):
        for k, v in data.items():
            names.update(get_all_var_names(k))
            names.update(get_all_var_names(v))
            
    # z3 expression
    elif hasattr(data, 'children'):
        names.update(collect_vars(data))
        
    return names


def collect_vars(e) -> set:
    res = set()
    stack = [e]
    visited = set()
    while stack:
        node = stack.pop()
        node_id = node.get_id()
        if node_id in visited:
            continue
        visited.add(node_id)
        if node.num_args() == 0:
            if not _is_concrete(node) and not is_true(node) and not is_false(node):
                res.add(str(node))
        else:
            stack.extend(node.children())
    return res