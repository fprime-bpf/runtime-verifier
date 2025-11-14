from dataclasses import dataclass, field
from copy import deepcopy
from math import ceil
from typing import List, Tuple, Optional, Dict, cast

# Z3xx
from z3 import Solver, Int, IntVal, Abs, Not, sat, simplify, ArithRef, BoolRef

from block import Block
from dfs import OpInfo, instr_to_runtime, is_fpu_instr, BPF_INFO, BPF_INFO_FPU


# ---- Platform constants (from your notes) ----
CPU_MHZ = 667
DRAM_MHZ = 100
DRAM_EXTRA_CYCLES = int(ceil(86.71))  # ~= 87 cycles

PEEP_WINDOW = 5   # N
NEAR_DELTA = 4    # K (bytes)

MEMORY_TYPES   = {"ld", "st", "fldx", "fstx", "map"}
LOCALITY_TYPES = {"ld", "st", "fldx", "fstx"}

# Map helpers
BPF_FUNC_map_lookup_elem = 1
BPF_FUNC_map_update_elem = 2
BPF_FUNC_map_delete_elem = 3
MAP_HELPERS = {
    BPF_FUNC_map_lookup_elem: "map_lookup",
    BPF_FUNC_map_update_elem: "map_update",
    BPF_FUNC_map_delete_elem: "map_delete",
}

# ---------- Symbolic types ----------
@dataclass
class SymbolicAddr:
    base: str
    offset: int

@dataclass
class SymbolicVal:
    type: str                       # "ptr" | "const" | "unknown"
    addr: Optional[SymbolicAddr] = None
    const: Optional[int] = None

def make_unknown() -> SymbolicVal: return SymbolicVal(type="unknown")
def make_const(v: int) -> SymbolicVal: return SymbolicVal(type="const", const=v)
def make_ptr(base: str, offset: int = 0) -> SymbolicVal:
    return SymbolicVal(type="ptr", addr=SymbolicAddr(base=base, offset=offset))

@dataclass
class MemoryAccess:
    idx: int
    type: str                # "ld" | "st" | "fldx" | "fstx" | "map"
    addr: Optional[SymbolicAddr]
    size: int
    base_latency: int
    dram_added: int = 0
    # Z3 address expression (e.g., Int('addr_12345') + 3)
    z3_addr: Optional[ArithRef] = None

@dataclass
class RegisterState:
    regs: Dict[int, SymbolicVal] = field(default_factory=lambda: {i: make_unknown() for i in range(11)})
    def clone(self) -> "RegisterState": return RegisterState(regs=deepcopy(self.regs))
    def get(self, r: int) -> SymbolicVal: return self.regs.get(r, make_unknown())
    def set(self, r: int, v: SymbolicVal) -> None: self.regs[r] = v

def _init_state() -> RegisterState:
    st = RegisterState()
    st.set(10, make_ptr("fp", 0))  # r10 = frame pointer
    return st

# ---- BpfInstruction access helpers  ----
def _require(label: str, v: Optional[int], instr) -> int:
    if v is None:
        raise ValueError(f"{label} missing in {instr!r}")
    return v


# ---- OpInfo dispatch ----
def _opinfo_for(instr) -> Optional[OpInfo]:
    return BPF_INFO_FPU.get(instr.opcode) if is_fpu_instr(instr) else BPF_INFO.get(instr.opcode)

def _is_load_mem(name: str) -> bool:
    if name.startswith("LDX_") and not any(t in name for t in ("IMM","ABS","IND")): return True
    if name.startswith("LD_MEM") or name.startswith("LDX_MEM"): return True
    return False

def _is_store_mem(name: str) -> bool:
    if name.startswith("STX_") and not any(t in name for t in ("IMM","ABS","IND")): return True
    if name.startswith("ST_")  and not any(t in name for t in ("IMM","ABS","IND")): return True
    if "MEMSX" in name and (name.startswith("STX_") or name.startswith("ST_")): return True
    return False

def _is_fpu_mem(name: str) -> bool:
    return name.startswith(("FLDX_","FSTX_","FLD_","FST_"))

def _guess_size_from_name(name: str) -> int:
    if name.endswith("_DW"): return 8
    if name.endswith("_W"):  return 4
    if name.endswith("_H"):  return 2
    if name.endswith("_B"):  return 1
    return 4


def _reg_z3(z3_regs: Dict[int, ArithRef], reg: int, idx: int) -> ArithRef:
    """Return the latest Z3 var for reg, or fall back to R{reg}_I{idx-1}."""
    v = z3_regs.get(reg)
    return v if v is not None else _z3_reg_var(reg, idx-1)


def _branch_cond_z3(idx: int, instr, opinfo: OpInfo, z3_regs: Dict[int, ArithRef]) -> Optional[BoolRef]:
    """
    Build a Z3 BoolRef for a conditional branch at instruction `idx`.
    Supports integer and (approximate) floating branches whose op names look like:
      JEQ_K, JEQ_X, JNE_K, JGT_X, JGE_K, JLT_X, JLE_K, JSGT_K, JSGE_X, JSLT_K, JSLE_X, ...
      JFEQ_X, JFOGT_K, JFOGE_X, JFNE_K, JFULT_X, JFULE_K, ...  (FPU variants)
    Returns None for non-conditional (JA/CALL/EXIT) or unhandled forms.
    """
    if opinfo is None:
        return None

    name = opinfo.name  # e.g., "JEQ_K", "JNE_X", "JLT32_X", "JFEQ_X", "JFOGT32_K", "JA", "CALL", "EXIT"
    # Exclude non-conditional jumps
    if name in ("JA", "CALL", "EXIT"):
        return None

    # Find comparator kind (prefix up to first underscore) and operand kind (last suffix _K/_X)
    # Examples:
    #   "JEQ_K"     -> cmp="JEQ",  kind="K"
    #   "JGE32_X"   -> cmp="JGE32", kind="X"
    #   "JFEQ_X"    -> cmp="JFEQ", kind="X"
    parts = name.split("_")
    if len(parts) < 2:
        return None

    cmp_tag = parts[0]  # e.g., JEQ, JGE32, JFEQ, JFOGT32, JSGT, ...
    kind    = parts[-1] # "K" or "X"

    # Left operand is always dst register version at idx-1
    lhs = _reg_z3(z3_regs, instr.dst, idx)

    # Right operand: imm (K) or src reg (X)
    if kind == "K":
        rhs = IntVal(instr.imm)
    elif kind == "X":
        rhs = _reg_z3(z3_regs, instr.src, idx)
    else:
        return None

    # Normalize comparator (strip trailing "32" for now; we’re using Int semantics)
    cmp_core = cmp_tag.replace("32", "")

    # Integer
    if   cmp_core == "JEQ":  return lhs == rhs # type: ignore
    elif cmp_core == "JNE":  return lhs != rhs # type: ignore
    elif cmp_core == "JGT":  return lhs >  rhs
    elif cmp_core == "JGE":  return lhs >= rhs
    elif cmp_core == "JLT":  return lhs <  rhs
    elif cmp_core == "JLE":  return lhs <= rhs
    elif cmp_core == "JSGT": return lhs >  rhs  # signed vs unsigned not distinguished with Int
    elif cmp_core == "JSGE": return lhs >= rhs
    elif cmp_core == "JSLT": return lhs <  rhs
    elif cmp_core == "JSLE": return lhs <= rhs
    # Bit tests (JSET) need bitwise &, which is easier with BitVec; omit here:
    elif cmp_core == "JSET":
        return None

    # Floating
    elif cmp_core == "JFEQ":  return lhs == rhs # type: ignore
    elif cmp_core == "JFNE":  return lhs != rhs # type: ignore
    elif cmp_core == "JFOGT": return lhs >  rhs
    elif cmp_core == "JFOGE": return lhs >= rhs
    elif cmp_core == "JFOLT": return lhs <  rhs
    elif cmp_core == "JFOLE": return lhs <= rhs
    elif cmp_core == "JFUGT": return lhs >  rhs
    elif cmp_core == "JFUGE": return lhs >= rhs
    elif cmp_core == "JFULT": return lhs <  rhs
    elif cmp_core == "JFULE": return lhs <= rhs

    return None


# ---------- ALU updates to RegisterState (pointer/const light SE) ----------
def _apply_alu_update(instr, opinfo: OpInfo, st: RegisterState):
    if opinfo is None: return
    name = opinfo.name
    dst, src, imm = instr.dst, instr.src, instr.imm

    if name in ("MOV_K","MOV64_K"):
        st.set(dst, make_const(imm)); return
    if name in ("MOV_X","MOV64_X"):
        st.set(dst, deepcopy(st.get(src))); return

    if name in ("ADD_K","ADD64_K"):
        v = st.get(dst)
        if v.type == "ptr" and v.addr: st.set(dst, make_ptr(v.addr.base, v.addr.offset + imm))
        elif v.type == "const" and v.const is not None: st.set(dst, make_const(v.const + imm))
        else: st.set(dst, make_unknown())
        return

    if name in ("SUB_K","SUB64_K"):
        v = st.get(dst)
        if v.type == "ptr" and v.addr: st.set(dst, make_ptr(v.addr.base, v.addr.offset - imm))
        elif v.type == "const" and v.const is not None: st.set(dst, make_const(v.const - imm))
        else: st.set(dst, make_unknown())
        return

    if name in ("ADD_X","ADD64_X","SUB_X","SUB64_X"):
        vdst, vsrc = st.get(dst), st.get(src)
        delta = vsrc.const if vsrc.type == "const" and vsrc.const is not None else None
        if delta is None: st.set(dst, make_unknown()); return
        if name.startswith("ADD"):
            if vdst.type == "ptr" and vdst.addr: st.set(dst, make_ptr(vdst.addr.base, vdst.addr.offset + delta))
            elif vdst.type == "const" and vdst.const is not None: st.set(dst, make_const(vdst.const + delta))
            else: st.set(dst, make_unknown())
        else: # SUB_X
            if vdst.type == "ptr" and vdst.addr: st.set(dst, make_ptr(vdst.addr.base, vdst.addr.offset - delta))
            elif vdst.type == "const" and vdst.const is not None: st.set(dst, make_const(vdst.const - delta))
            else: st.set(dst, make_unknown()); 
        return

    if name.startswith(("AND","OR","XOR","ARSH","RSH","LSH","NEG","MOD","DIV","MUL")):
        st.set(dst, make_unknown())

# ---------- Z3 helpers ----------
def _z3_base_symbol(name: str, base_syms: Dict[str, ArithRef]) -> ArithRef:
    if name not in base_syms:
        base_syms[name] = Int(name)  # e.g., Int('fp'), Int('addr_12345'), Int('map:?')
    return base_syms[name]

def _z3_reg_var(reg: int, idx: int) -> ArithRef:
    return Int(f"R{reg}_I{idx}")

def _z3_imm_addr_symbol(imm: int, base_syms: Dict[str, ArithRef]) -> ArithRef:
    return _z3_base_symbol(f"addr_{imm:x}", base_syms)

# ---------- Build MemoryAccess (SymbolicAddr + Z3 addr expr) ----------
def _mem_access_from_instr(idx: int, instr, opinfo: OpInfo, st: RegisterState,
                           z3_regs: Dict[int, ArithRef], base_syms: Dict[str, ArithRef]) -> Tuple[Optional[MemoryAccess], Optional[ArithRef]]:
    if opinfo is None: return None, None
    name = opinfo.name
    base_latency = 0 if opinfo.latency is None else opinfo.latency
    size = _guess_size_from_name(name)

    # Normal memory
    if _is_load_mem(name):
        base_reg, off = instr.src, instr.off
        v = st.get(base_reg)
        addr = None
        z3_addr = None
        if v.type == "ptr" and v.addr:
            addr = SymbolicAddr(v.addr.base, v.addr.offset + off)
            z3_base = _z3_base_symbol(v.addr.base, base_syms)
            z3_addr = z3_regs.get(base_reg, _z3_reg_var(base_reg, idx-1)) + off
            # If base is 'fp', we often model Rbase == fp; keep path constraints elsewhere.
        return MemoryAccess(idx, "ld", addr, size, base_latency, 0, z3_addr), z3_addr

    if _is_store_mem(name):
        base_reg, off = instr.dst, instr.off
        v = st.get(base_reg)
        addr = None
        z3_addr = None
        if v.type == "ptr" and v.addr:
            addr = SymbolicAddr(v.addr.base, v.addr.offset + off)
            z3_base = _z3_base_symbol(v.addr.base, base_syms)
            z3_addr = z3_regs.get(base_reg, _z3_reg_var(base_reg, idx-1)) + off
        return MemoryAccess(idx, "st", addr, size, base_latency, 0, z3_addr), z3_addr

    # FPU memory
    if _is_fpu_mem(name):
        base_reg = instr.src if name.startswith(("FLDX_","FLD_")) else instr.dst
        off = instr.off
        v = st.get(base_reg)
        addr = None
        z3_addr = None
        if v.type == "ptr" and v.addr:
            addr = SymbolicAddr(v.addr.base, v.addr.offset + off)
            _ = _z3_base_symbol(v.addr.base, base_syms)
            z3_addr = z3_regs.get(base_reg, _z3_reg_var(base_reg, idx-1)) + off
        typ = "fldx" if name.startswith(("FLDX_","FLD_")) else "fstx"
        return MemoryAccess(idx, typ, addr, size, base_latency, 0, z3_addr), z3_addr

    # Map helper treated as load/stores
    if name == "CALL":
        helper_id = instr.imm
        if helper_id == BPF_FUNC_map_lookup_elem:
            r1 = st.get(1)
            base_name = f"map:{r1.addr.base}" if (r1.type == "ptr" and r1.addr) else "map:?"
            addr = SymbolicAddr(base_name, 0)
            z3_addr = _z3_base_symbol(base_name, base_syms)

            mem = MemoryAccess(idx, "map", addr, 8, base_latency, 0, z3_addr)

            # Renew R0
            st.set(0, make_ptr(base_name, 0))
            z3_regs[0] = z3_addr  # 让随后的 fldx/fstx 能拿到 z3_addr

            return mem, z3_addr

        elif helper_id in (BPF_FUNC_map_update_elem, BPF_FUNC_map_delete_elem):
            r1 = st.get(1)
            base_name = f"map:{r1.addr.base}" if (r1.type == "ptr" and r1.addr) else "map:?"
            addr = SymbolicAddr(base_name, 0)
            z3_addr = _z3_base_symbol(base_name, base_syms)
            mem = MemoryAccess(idx, "map", addr, 8, base_latency, 0, z3_addr)

            st.set(0, make_unknown())
            z3_regs[0] = _z3_reg_var(0, idx)
            return mem, z3_addr

    return None, None

# ---------- Z3-aware ALU constraints ----------
def _apply_alu_update_z3(idx: int, instr, opinfo: OpInfo,
                         z3_regs: Dict[int, ArithRef], solver: Solver, base_syms: Dict[str, ArithRef]) -> None:

    """Emit Z3 constraints for one eBPF ALU/IMM instruction and advance the
     Z3 register mapping.

    Notes:
      - This routine only handles ALU/IMM-style semantics; memory accesses are
        collected elsewhere.

    Args:
        idx: Instruction index used as the SSA version tag.
        instr: Decoded instruction (must expose ``dst``, ``src``, ``imm``).
        opinfo: Operation metadata; if ``None`` the function returns immediately.
        z3_regs: Current path map ``reg_id -> ArithRef``; updated in-place.
        solver: Z3 solver to which new constraints are appended.
        base_syms: Pool of base symbols for addresses; may be extended.

    Returns:
        None. Side-effects on ``solver`` and ``z3_regs``.
    """
    if opinfo is None:
        return

    raw = opinfo.name
    dst, src, imm = instr.dst, instr.src, instr.imm
    dst_var = _z3_reg_var(dst, idx)

    # ---- Helpers ----
    def _prev(reg: int) -> ArithRef:
        return z3_regs.get(reg, _z3_reg_var(reg, idx - 1))

    # Memory-like opcode families (keep original names; don't strip 'F')
    def _is_mem_like(n: str) -> bool:
        if _is_fpu_mem(n):
            return True
        if _is_load_mem(n) or _is_store_mem(n):
            return True
        return False

    # ---- Normalize FPU ALU names ----
    if raw.startswith('F') and not _is_mem_like(raw):
        name = raw[1:]            # e.g., FADD64_K -> ADD64_K, FMOV_X -> MOV_X
    else:
        name = raw

    # ================= Exact constraints we support =================
    # MOV_K / MOV64_K / FMOV_K / FMOV64_K
    if name in ("MOV_K", "MOV64_K"):
        solver.add(dst_var == IntVal(imm))
        z3_regs[dst] = dst_var
        return

    # MOV_X / MOV64_X / FMOV_X / FMOV64_X
    if name in ("MOV_X", "MOV64_X"):
        solver.add(dst_var == _prev(src))
        z3_regs[dst] = dst_var
        return

    # ADD_K / ADD64_K / FADD*_K
    if name in ("ADD_K", "ADD64_K"):
        solver.add(dst_var == _prev(dst) + IntVal(imm))
        z3_regs[dst] = dst_var
        return

    # SUB_K / SUB64_K / FSUB*_K
    if name in ("SUB_K", "SUB64_K"):
        solver.add(dst_var == _prev(dst) - IntVal(imm))
        z3_regs[dst] = dst_var
        return

    # ADD_X / ADD64_X / FADD*_X   and   SUB_X / SUB64_X / FSUB*_X
    if name in ("ADD_X", "ADD64_X", "SUB_X", "SUB64_X"):
        lhs = _prev(dst)
        rhs = _prev(src)
        if name.startswith("ADD"):
            solver.add(dst_var == lhs + rhs)
        else:
            solver.add(dst_var == lhs - rhs)
        z3_regs[dst] = dst_var
        return

    # NEG / NEG64 / FNEG
    if name in ("NEG", "NEG64"):
        solver.add(dst_var == -_prev(dst))
        z3_regs[dst] = dst_var
        return

    # MUL_K / MUL64_K / FMUL*_K   (safe Int semantics)
    if name in ("MUL_K", "MUL64_K"):
        solver.add(dst_var == _prev(dst) * IntVal(imm))
        z3_regs[dst] = dst_var
        return

    # MUL_X / MUL64_X / FMUL*_X   (safe Int semantics)
    if name in ("MUL_X", "MUL64_X"):
        solver.add(dst_var == _prev(dst) * _prev(src))
        z3_regs[dst] = dst_var
        return

    # ================= Address/immediate loads we model =================
    if name in ("LD_IMM_W", "LD_IMM_H", "LD_IMM_B", "LDDW",
                "LDX_IMM_W", "LDX_IMM_H", "LDX_IMM_B", "LDX_IMM_DW"):
        sym = _z3_imm_addr_symbol(imm, base_syms)
        solver.add(dst_var == sym)
        z3_regs[dst] = dst_var
        return

    # ================= Everything else =================
    # Bitwise (AND/OR/XOR), shifts (LSH/RSH/ARSH), DIV/MOD, etc. are
    # left unconstrained under Int semantics to avoid incorrect models.
    # If later needed, switch to BitVec and add precise rules.
    z3_regs[dst] = dst_var  # havoc


def _scan_block(
    instructions: list,                 # Full list of eBPF instructions (each is an instruction object)
    start: int,                         # Start index of the current basic block
    end: int,                           # End index (inclusive) of the current basic block
    st_in: RegisterState,               # Register state at block entry (maps reg_id → SymbolicVal)
    z3_regs_in: Dict[int, ArithRef],    # Z3 symbolic registers (maps reg_id → Z3 expression)
    solver: Solver,                     # Global Z3 solver for constraint management
    base_syms: Dict[str, ArithRef]      # Base symbols (e.g., frame pointer, map base addresses)
) -> Tuple[
    RegisterState,                      # Updated register state at block exit
    List[MemoryAccess],                 # List of memory accesses (ld/st/fldx/fstx) within the block
    Dict[int, SymbolicAddr],            # Map: instruction index → SymbolicAddr(base, offset)
    Dict[int, ArithRef],                 # Map: instruction index → Z3 address expression
    Dict[int, ArithRef]
]:
    """
    Scan a basic block and collect memory-access information (symbolic + Z3).
    Constraints for this block are added to ``solver``

    The function performs lightweight symbolic execution across instructions
    ``[start, end]``:
      1) updates the ``RegisterState`` (``SymbolicVal`` per register),
      2) add Z3 constraints for ALU/IMM ops and updates the map ``z3_regs``,
      3) for load/store-like instructions produces a ``MemoryAccess`` plus both
         a symbolic address (``SymbolicAddr(base, offset)``) and a Z3 address
         expression (``ArithRef``).

    Args:
        instructions: Full program instruction list.
        start: Inclusive start index of the basic block.
        end: Inclusive end index of the basic block.
        st_in: Register state at block entry; cloned internally.
        z3_regs_in: Z3 register map at block entry; deep-copied internally.
        solver: Z3 solver used to accumulate constraints for this block.
        base_syms: Pool of base symbols used when constructing Z3 addresses.

    Returns:
        Tuple containing:
            RegisterState: state at block exit (post-scan).
            List[MemoryAccess]: all memory accesses found within the block.
            Dict[int, SymbolicAddr]: instruction index → (base, offset).
            Dict[int, ArithRef]: instruction index → Z3 address expression.
    """
    # Clone incoming register state and Z3 symbolic register map.
    # This ensures changes inside this block do not mutate the caller’s state.
    st = st_in.clone()
    z3_regs = deepcopy(z3_regs_in)

    # Containers for results collected during the scan.
    block_mem_acc: List[MemoryAccess] = []   # All memory access instructions in this block
    addr_map: Dict[int, SymbolicAddr] = {}   # Symbolic (base + offset) addresses
    z3_addr_map: Dict[int, ArithRef] = {}    # Z3 address expressions for symbolic checking

    # Iterate through all instructions in the basic block.
    for idx in range(start, end + 1):
        instr = instructions[idx]
        opinfo = _opinfo_for(instr)          # Retrieve operation metadata (type, category, etc.)
        if opinfo is None:
            continue                         # Skip unknown or unhandled opcodes

        # Step 1️
        # Update register state. (z3 not involved)
        _apply_alu_update(instr, opinfo, st)

        # Step 2
        # Update Z3-level constraints.
        _apply_alu_update_z3(idx, instr, opinfo, z3_regs, solver, base_syms)

        # Step 3: If this is a load/store instruction, extract its memory access pattern.
        #   - `mem`  → MemoryAccess object
        #   - `z3a`  → Z3 address expression for solver-based analysis
        mem, z3a = _mem_access_from_instr(idx, instr, opinfo, st, z3_regs, base_syms)

        # If an actual memory access was found, record it.
        if mem:
            block_mem_acc.append(mem)

            # Only record symbolic addresses for valid memory operations.
            if mem.type in ("ld", "st", "fldx", "fstx") and mem.addr:
                addr_map[idx] = mem.addr        # Save SymbolicAddr(base, offset)
                if z3a is not None:
                    z3_addr_map[idx] = z3a      # Save Z3 arithmetic expression

    # Return updated state and all access mappings for this basic block.
    return st, block_mem_acc, addr_map, z3_addr_map, z3_regs


def _est_cache_latency_z3(path_mem_accesses: List[MemoryAccess],
                          solver: Solver,
                          window: int = PEEP_WINDOW,
                          near: int = NEAR_DELTA) -> int:
    """
    Estimate extra DRAM cycles for one path.
    Start by assuming every memory access hits DRAM, then use Z3 to
    reduce accesses proven to be near a prior access (|addr_i-addr_j|<=near).
    """
    # 1) Initialization
    for m in path_mem_accesses:
        m.dram_added = DRAM_EXTRA_CYCLES if m.type in MEMORY_TYPES else 0

    near_z3 = IntVal(near)

    for i, mi in enumerate(path_mem_accesses):
        if mi.z3_addr is None or mi.type not in LOCALITY_TYPES:
            continue
        ai = cast(ArithRef, mi.z3_addr)

        for j in range(max(0, i - window), i):
            mj = path_mem_accesses[j]
            if mj.z3_addr is None or mj.type not in LOCALITY_TYPES:
                continue
            aj = cast(ArithRef, mj.z3_addr)

            solver.push()

            solver.add(Not(Abs(ai - aj) <= near_z3))
            res = solver.check()
            solver.pop()

            if res != sat:        # unsat => they are near
                mi.dram_added = 0 # Second access is L1
                print(f"    L1 reuse: [{mj.idx}] -> [{mi.idx}]  | {aj} ~ {ai}")
                break

    return sum(m.dram_added for m in path_mem_accesses)


def dfs_blocks_with_mem(first_block: Block | None,
                        instructions: list,
                        peephole_window: int = PEEP_WINDOW,
                        near_delta: int = NEAR_DELTA
                       ) -> Tuple[int, Dict[int, SymbolicAddr], Dict[int, ArithRef]]:
    """
    Returns:
      (upper_bound_cycles_with_memory,
       {instr_idx -> SymbolicAddr},         # LD(X)/ST(X)/FLDX/FSTX only
       {instr_idx -> Z3 address expression} # corresponding Z3 expressions
    """
    print("\n======DFS+MEM (Z3) Start======")
    if first_block is None:
        return 0, {}, {}

    solver = Solver()
    base_syms: Dict[str, ArithRef] = {}

    # Program-level (final) summaries, merged at leaves only
    prog_addr_map: Dict[int, SymbolicAddr] = {}
    prog_z3_addr_map: Dict[int, ArithRef] = {}

    # Z3 regs for current path: r10 = fp
    z3_regs_init: Dict[int, ArithRef] = {10: _z3_base_symbol("fp", base_syms)}

    runtime_ub = 0  # global upper bound across all paths

    def dfs(block: Block,
            st_in: RegisterState,
            z3_regs_in: Dict[int, ArithRef],
            path_mem_accesses: List[MemoryAccess],
            path_addr_map: Dict[int, SymbolicAddr],
            path_z3_addr_map: Dict[int, ArithRef],
            path_base_runtime: int) -> None:
        nonlocal runtime_ub

        solver.push()  # constraints for this block
        print(f"\n======Visiting BB({block.start}, {block.end})======")

        # If you want ALU/FPU base cost per block, compute it here:
        base_rt = instr_to_runtime(instructions, block.start, block.end)
        path_rt_next = path_base_runtime + base_rt        
        print(f"Path ty: {path_rt_next}")

        try:
            # Scan this block to update symbolic state and collect memory accesses.
            st_out, blk_mem_acc, blk_addr_map, blk_z3_addr_map, z3_regs_out = _scan_block(
                instructions, block.start, block.end, st_in, z3_regs_in, solver, base_syms
            )

            # Per-branch views
            mem_next = deepcopy(path_mem_accesses + blk_mem_acc)   # independent list
            addr_next = {**path_addr_map, **blk_addr_map}          # merged dict
            z3_next   = {**path_z3_addr_map, **blk_z3_addr_map}    # merged dict

            if not block.next:
                # Leaf: compute DRAM penalty for this path
                dram_pen = _est_cache_latency_z3(mem_next, solver, peephole_window, near_delta)
                total_rt = path_rt_next + dram_pen    # not path_base_runtime
                print(f"  Path base={path_rt_next}, DRAM={dram_pen}, total={total_rt}")

                # Merge per-path summaries into program-level summaries
                for k, v in addr_next.items():   prog_addr_map[k] = v
                for k, v in z3_next.items():     prog_z3_addr_map[k] = v

                runtime_ub = max(runtime_ub, total_rt)

                # Optional debug
                if mem_next:
                    print("  -- Path memory summary --")
                    for m in mem_next:
                        loc = f"{m.addr.base}+{m.addr.offset}" if m.addr else "unknown"
                        print(f"    [{m.idx}] {m.type} @ {loc}: base={m.base_latency} + DRAM={m.dram_added}")
                    print(f"  Path base={path_base_runtime}, DRAM={dram_pen}, total={total_rt}")

            else:
                # Terminator: build condition if any
                term_instr = instructions[block.end]
                term_info  = _opinfo_for(term_instr)
                if term_info is None:
                    raise ValueError(f"Unknown terminator at {block.end}: {term_instr!r}")

                cond = _branch_cond_z3(block.end, term_instr, term_info, z3_regs_out)

                if cond is None:
                    # Unconditional / unparsed: if there is exactly one successor, just follow it.
                    if term_info.name in ("JA", "CALL") or len(block.next) == 1:
                        nxt = block.next[0]
                        dfs(nxt,
                            st_out.clone(),
                            deepcopy(z3_regs_out),
                            deepcopy(mem_next),
                            deepcopy(addr_next),
                            deepcopy(z3_next),
                            path_rt_next)
                    # Fallback: if two successors but no cond parsed, explore both without adding constraints.
                    elif len(block.next) == 2:
                        for nxt in block.next:
                            dfs(nxt,
                                st_out.clone(),
                                deepcopy(z3_regs_out),
                                deepcopy(mem_next),
                                deepcopy(addr_next),
                                deepcopy(z3_next),
                                path_rt_next)
                    else:
                        raise ValueError(f"Unsupported or non-conditional branch at {block.end}: {term_info.name}")
                else:
                    # Conditional: expect two successors—taken (true) and fallthrough (false).
                    true_succ, false_succ = block.next[0], block.next[1]

                    # True branch
                    solver.push()
                    solver.add(cond)
                    dfs(true_succ,
                        st_out.clone(),
                        deepcopy(z3_regs_out),
                        deepcopy(mem_next),
                        deepcopy(addr_next),
                        deepcopy(z3_next),
                        path_rt_next)
                    solver.pop()

                    # False branch
                    solver.push()
                    solver.add(Not(cond))
                    dfs(false_succ,
                        st_out.clone(),
                        deepcopy(z3_regs_out),
                        deepcopy(mem_next),
                        deepcopy(addr_next),
                        deepcopy(z3_next),
                        path_rt_next)
                    solver.pop()
        finally:
            solver.pop()

    # Kick off DFS with empty path-level containers
    dfs(first_block,
        _init_state(),
        z3_regs_init,
        path_mem_accesses=[],        # path-local containers start empty
        path_addr_map={},
        path_z3_addr_map={},
        path_base_runtime=0)

    return runtime_ub, prog_addr_map, prog_z3_addr_map