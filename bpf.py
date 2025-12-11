import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Dict

class Shift:
    IMM = 32
    OFFSET = 16
    SRC = 12
    DST = 8
    OPCODE = CLASS = 0
    S = SZ = 3
    CODE = 4
    MODE = 5

    # for 16-byte instructions
    RESERVED = 32
    NEXT_IMM = 0


class Mask:
    IMM = 0xFFFFFFFF << Shift.IMM
    OFFSET = 0xFFFF << Shift.OFFSET
    DST = 0b1111 << Shift.DST
    SRC = 0b1111 << Shift.SRC
    OPCODE = 0xFF << Shift.OPCODE

    # opcode specific
    CLASS = 0b111 << Shift.CLASS
    # - ALU and JMP
    S = 0b1 << Shift.S
    CODE = 0b1111 << Shift.CODE
    # - LD and ST
    SZ = 0b11 << Shift.SZ
    MODE = 0b111 << Shift.MODE

    # for 16-byte instructions
    RESERVED = 0xFFFFFFFF << Shift.RESERVED
    NEXT_IMM = 0xFFFFFFFF << Shift.NEXT_IMM


class_in_opcode_shift = Shift.CLASS - Shift.OPCODE
code_in_opcode_shift = Shift.CODE - Shift.OPCODE
s_in_opcode_shift = Shift.S - Shift.OPCODE
mode_in_opcode_shift = Shift.MODE - Shift.OPCODE


class BpfClass(IntEnum):
    # shift is zero, but let's keep it consistant
    shift = class_in_opcode_shift
    LD = 0x0 << shift
    LDX = 0x1 << shift
    ST = 0x2 << shift
    STX = 0x3 << shift
    ALU = 0x4 << shift
    JMP = 0x5 << shift
    JMP32 = 0x6 << shift
    ALU64 = 0x7 << shift


# for Arithmetic and Jump instructions
class BpfS:
    shift = s_in_opcode_shift
    K = 0x0 << shift  # imm is source
    X = 0x1 << shift  # src is source


# for Load and Store instructions
class BpfSize:
    W = 0x00 << Shift.SZ  # 32
    H = 0x01 << Shift.SZ  # 16
    B = 0x02 << Shift.SZ  # 8
    DW = 0x03 << Shift.SZ  # 64


# for Arithmetic and Jump instructions
class BpfCode:
    # arithmetic
    class ALU:
        shift = code_in_opcode_shift
        ADD = 0x0 << shift
        SUB = 0x1 << shift
        MUL = 0x2 << shift
        DIV = SDIV = 0x3 << shift
        OR = 0x4 << shift
        AND = 0x5 << shift
        LSH = 0x6 << shift
        RSH = 0x7 << shift
        NEG = 0x8 << shift
        MOD = SMOD = 0x9 << shift
        XOR = 0xA << shift
        MOV = MOVSX = 0xB << shift
        ARSH = 0xC << shift
        END = 0xD << shift

    # jump
    class JMP:
        shift = code_in_opcode_shift
        JA = 0x0 << shift
        JEQ = 0x1 << shift
        JGT = 0x2 << shift
        JGE = 0x3 << shift
        JSET = 0x4 << shift
        JNE = 0x5 << shift
        JSGT = 0x6 << shift
        JSGE = 0x7 << shift
        CALL = 0x8 << shift
        EXIT = 0x9 << shift
        JLT = 0xA << shift
        JLE = 0xB << shift
        JSLT = 0xC << shift
        JSLE = 0xD << shift


class BpfMode(IntEnum):
    shift = mode_in_opcode_shift
    IMM = 0x0 << shift
    ABS = 0x1 << shift
    IND = 0x2 << shift
    MEM = 0x3 << shift
    FMEM = 0x5 << shift
    MEMSX = 0x4 << shift
    ATOMIC = 0x6 << shift

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, int):
            val = value >> Shift.MODE
            raise ValueError(f"couldn't find BpfMode for 0b{val:03b} = {val}")


class BpfInstruction:
    def __init__(self, instruction: bytes) -> None:
        self.instruction = instruction

        self.imm = self._get_imm()
        self.off = self._get_off()
        self.src = self._get_src()
        self.dst = self._get_dst()
        self.opcode = self._get_opcode()

        # for the occasional 16-byte instruction
        self.next_instruction: bytes | None = None
        self.reserved: int | None = None
        self.next_imm: int | None = None

    def _to_int(self, instruction: bytes) -> int:
        (val,) = struct.unpack(
            # little endian = "<"
            # unsigned = "Q"
            "<Q",
            instruction,
        )

        return val

    def _get_imm(self) -> int:
        # unsigned 32 bit int
        org_imm = (self._to_int(self.instruction) & Mask.IMM) >> Shift.IMM

        # make it signed
        if org_imm > 0x7FFFFFFF:
            return org_imm - 0xFFFFFFFF - 1

        return org_imm

    def _get_off(self) -> int:
        # unsigned 16 bit int
        org_off = (self._to_int(self.instruction) & Mask.OFFSET) >> Shift.OFFSET

        # make it signed
        if org_off > 0x7FFF:
            return org_off - 0xFFFF - 1

        return org_off

    def _get_src(self) -> int:
        return (self._to_int(self.instruction) & Mask.SRC) >> Shift.SRC

    def _get_dst(self) -> int:
        return (self._to_int(self.instruction) & Mask.DST) >> Shift.DST

    def _get_opcode(self) -> int:
        return (self._to_int(self.instruction) & Mask.OPCODE) >> Shift.OPCODE

    def _get_reserved(self) -> int:
        if self.next_instruction is None:
            raise Exception(f"tried getting reserved on 8-byte instruction")
        return self._to_int(self.next_instruction) & Mask.RESERVED >> Shift.RESERVED

    def _get_next_imm(self) -> int:
        if self.next_instruction is None:
            raise Exception(f"tried getting next_imm on 8-byte instruction")
        return self._to_int(self.next_instruction) & Mask.NEXT_IMM >> Shift.NEXT_IMM

    def get_class(self) -> BpfClass:
        return BpfClass(self.opcode & Mask.CLASS)

    def get_mode(self) -> BpfMode:
        return BpfMode(self.opcode & Mask.MODE)

    def __str__(self) -> str:
        def bytes_to_str(bb: bytes) -> str:
            return " ".join([f"{b:02x}" for b in bb])

        out = bytes_to_str(self.instruction)
        if self.next_instruction is not None:
            out += " " + bytes_to_str(self.next_instruction)

        return out

    def __repr__(self) -> str:
        return str(self)

    def class_is_ld_st(self) -> bool:
        return self.get_class() in [
            BpfClass.LD,
            BpfClass.LDX,
            BpfClass.ST,
            BpfClass.STX,
        ]

    def class_is_alu_jmp(self) -> bool:
        return self.get_class() in [
            BpfClass.ALU,
            BpfClass.JMP,
            BpfClass.JMP32,
            BpfClass.ALU64,
        ]

    def is_wide_instruction(self) -> bool:
        """As defined in https://docs.kernel.org/bpf/standardization/instruction-set.html#wide-instruction-encoding"""

        # https://docs.kernel.org/bpf/standardization/instruction-set.html#bit-immediate-instructions
        if self.class_is_ld_st() and self.get_mode() == BpfMode.IMM:
            return True

        return False

    def widen_instruction(self, more: bytes):
        self.next_instruction = more
        self.reserved = self._get_reserved()
        self.next_imm = self._get_next_imm()


@dataclass(frozen=True)
class OpInfo:
    name: str
    latency: Optional[int]  # None as default


BPF_ATOMIC_OP_MASK = 0x0F
BPF_FETCH          = 0x10

ATOMIC_ADD     = 0x0
ATOMIC_AND     = 0x1
ATOMIC_OR      = 0x2
ATOMIC_XOR     = 0x3
ATOMIC_XCHG    = 0xE
ATOMIC_CMPXCHG = 0xF


BPF_INFO: Dict[int, OpInfo] = {
    # ===== ALU (32-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   OpInfo("ADD_K",   5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   OpInfo("ADD_X",   1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   OpInfo("SUB_K",   5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   OpInfo("SUB_X",   1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   OpInfo("MUL_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   OpInfo("MUL_X",   10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   OpInfo("DIV_K",   38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   OpInfo("DIV_X",   34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU:   OpInfo("MOD_K",   38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU:   OpInfo("MOD_X",   34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU:   OpInfo("OR_K",    5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU:   OpInfo("OR_X",    1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU:   OpInfo("AND_K",   5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU:   OpInfo("AND_X",   1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU:   OpInfo("LSH_K",   1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU:   OpInfo("LSH_X",   1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU:   OpInfo("RSH_K",   1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU:   OpInfo("RSH_X",   1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   OpInfo("NEG_K",   0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   OpInfo("NEG_X",   0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU:   OpInfo("XOR_K",   5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU:   OpInfo("XOR_X",   1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   OpInfo("MOV_K",   4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   OpInfo("MOV_X",   4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU:   OpInfo("ARSH_K",  1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU:   OpInfo("ARSH_X",  1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU:   OpInfo("END",     None),

    # ===== ALU64 (64-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64: OpInfo("ADD64_K", 5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64: OpInfo("ADD64_X", 1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64: OpInfo("SUB64_K", 5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64: OpInfo("SUB64_X", 1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64: OpInfo("MUL64_K", 14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64: OpInfo("MUL64_X", 10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64: OpInfo("DIV64_K", 38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64: OpInfo("DIV64_X", 34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU64: OpInfo("MOD64_K", 38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU64: OpInfo("MOD64_X", 34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU64: OpInfo("OR64_K",  5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU64: OpInfo("OR64_X",  1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU64: OpInfo("AND64_K", 5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU64: OpInfo("AND64_X", 1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU64: OpInfo("LSH64_K", 1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU64: OpInfo("LSH64_X", 1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU64: OpInfo("RSH64_K", 1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU64: OpInfo("RSH64_X", 1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64: OpInfo("NEG64_K", 0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64: OpInfo("NEG64_X", 0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU64: OpInfo("XOR64_K", 5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU64: OpInfo("XOR64_X", 1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64: OpInfo("MOV64_K", 4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64: OpInfo("MOV64_X", 4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU64: OpInfo("ARSH64_K",1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU64: OpInfo("ARSH64_X",1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU64: OpInfo("END64",   None),

    # ===== JMP (64-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP:   OpInfo("JA",      2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   OpInfo("JEQ_K",   7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   OpInfo("JEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   OpInfo("JGT_K",   7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   OpInfo("JGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   OpInfo("JGE_K",   7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   OpInfo("JGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   OpInfo("JNE_K",   7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   OpInfo("JNE_X",   3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP:   OpInfo("JSET_K",  8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP:   OpInfo("JSET_X",  4),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   OpInfo("JSGT_K",  7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   OpInfo("JSGT_X",  3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   OpInfo("JSGE_K",  7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   OpInfo("JSGE_X",  3),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   OpInfo("JLT_K",   7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   OpInfo("JLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   OpInfo("JLE_K",   7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   OpInfo("JLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   OpInfo("JSLT_K",  7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   OpInfo("JSLT_X",  3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   OpInfo("JSLE_K",  7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   OpInfo("JSLE_X",  3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:   OpInfo("CALL",    11 + 87),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP:   OpInfo("CALL",    11 + 87),
    BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:   OpInfo("EXIT",    2),

    # ===== JMP32 (32-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP32: OpInfo("JA", 2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32: OpInfo("JEQ32_K", 7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32: OpInfo("JEQ32_X", 3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32: OpInfo("JNE32_K", 7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32: OpInfo("JNE32_X", 3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32: OpInfo("JGT32_K", 7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32: OpInfo("JGT32_X", 3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32: OpInfo("JGE32_K", 7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32: OpInfo("JGE32_X", 3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP32: OpInfo("JSET32_K", 8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP32: OpInfo("JSET32_X", 4),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32: OpInfo("JLT32_K", 7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32: OpInfo("JLT32_X", 3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32: OpInfo("JLE32_K", 7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32: OpInfo("JLE32_X", 3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32: OpInfo("JSGT32_K", 7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32: OpInfo("JSGT32_X", 3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32: OpInfo("JSGE32_K", 7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32: OpInfo("JSGE32_X", 3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32: OpInfo("JSLT32_K", 7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32: OpInfo("JSLT32_X", 3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32: OpInfo("JSLE32_K", 7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32: OpInfo("JSLE32_X", 3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP32: OpInfo("CALL",     11 + 87),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP32: OpInfo("CALL",     11 + 87),
    
    # ===== LD =====
    BpfMode.IMM | BpfSize.W  | BpfClass.LD:  OpInfo("LD_IMM_W",  4 + 87),
    BpfMode.IMM | BpfSize.H  | BpfClass.LD:  OpInfo("LD_IMM_H",  4 + 87),
    BpfMode.IMM | BpfSize.B  | BpfClass.LD:  OpInfo("LD_IMM_B",  4 + 87),
    BpfMode.IMM | BpfSize.DW | BpfClass.LD:  OpInfo("LDDW",  4 + 87),   # 

    BpfMode.ABS | BpfSize.W  | BpfClass.LD:  OpInfo("LD_ABS_W",  None),
    BpfMode.ABS | BpfSize.H  | BpfClass.LD:  OpInfo("LD_ABS_H",  None),
    BpfMode.ABS | BpfSize.B  | BpfClass.LD:  OpInfo("LD_ABS_B",  None),
    BpfMode.ABS | BpfSize.DW | BpfClass.LD:  OpInfo("LD_ABS_DW", None),

    BpfMode.IND | BpfSize.W  | BpfClass.LD:  OpInfo("LD_IND_W",  None),
    BpfMode.IND | BpfSize.H  | BpfClass.LD:  OpInfo("LD_IND_H",  None),
    BpfMode.IND | BpfSize.B  | BpfClass.LD:  OpInfo("LD_IND_B",  None),
    BpfMode.IND | BpfSize.DW | BpfClass.LD:  OpInfo("LD_IND_DW", None),

    BpfMode.MEM   | BpfSize.W  | BpfClass.LD: OpInfo("LD_MEM_W",  None),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LD: OpInfo("LD_MEM_H",  None),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LD: OpInfo("LD_MEM_B",  None),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LD: OpInfo("LD_MEM_DW", None),

    BpfMode.FMEM  | BpfSize.W  | BpfClass.LD: OpInfo("FLD_W",  3 + 87),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LD: OpInfo("FLD_H",  3 + 87),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LD: OpInfo("FLD_B",  3 + 87),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LD: OpInfo("FLD_DW",  3 + 87),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LD: OpInfo("LD_MEMSX_W",  None),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LD: OpInfo("LD_MEMSX_H",  None),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LD: OpInfo("LD_MEMSX_B",  None),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LD: OpInfo("LD_MEMSX_DW", None),
    
    # ===== LDX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_ABS_W",  None),
    BpfMode.ABS   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_ABS_H",  None),
    BpfMode.ABS   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_ABS_B",  None),
    BpfMode.ABS   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_ABS_DW", None),

    BpfMode.IND   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_IND_W",  None),
    BpfMode.IND   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_IND_H",  None),
    BpfMode.IND   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_IND_B",  None),
    BpfMode.IND   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_IND_DW", None),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_W",  11 + 87),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_H",  11 + 87),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_B",  11 + 87),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_DW", 11 + 87),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.LDX: OpInfo("FLDX_W",  3 + 87),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LDX: OpInfo("FLDX_H",  3 + 87),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LDX: OpInfo("FLDX_B",  3 + 87),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LDX: OpInfo("FLDX_DW",  3 + 87),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LDX: OpInfo("LDX_MEMSX_W", 11 + 87),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LDX: OpInfo("LDX_MEMSX_H", 11 + 87),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LDX: OpInfo("LDX_MEMSX_B", 11 + 87),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LDX: OpInfo("LDX_MEMSX_DW", 11 + 87),
    
    # ===== ST =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_ABS_W",  0),
    BpfMode.ABS   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_ABS_H",  0),
    BpfMode.ABS   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_ABS_B",  0),
    BpfMode.ABS   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_ABS_DW", 0),

    BpfMode.IND   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_IND_W",  0),
    BpfMode.IND   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_IND_H",  0),
    BpfMode.IND   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_IND_B",  0),
    BpfMode.IND   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_IND_DW", 0),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.ST:  OpInfo("ST_W",  11 + 87),
    BpfMode.MEM   | BpfSize.H  | BpfClass.ST:  OpInfo("ST_H",  11 + 87),
    BpfMode.MEM   | BpfSize.B  | BpfClass.ST:  OpInfo("ST_B",  11 + 87),
    BpfMode.MEM   | BpfSize.DW | BpfClass.ST:  OpInfo("ST_DW", 11 + 87),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.ST: OpInfo("FST_W",  1 + 87),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.ST: OpInfo("FST_H",  1 + 87),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.ST: OpInfo("FST_B",  1 + 87),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.ST: OpInfo("FST_DW",  1 + 87),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.ST:  OpInfo("ST_MEMSX_W",  11 + 87),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.ST:  OpInfo("ST_MEMSX_H",  11 + 87),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.ST:  OpInfo("ST_MEMSX_B",  11 + 87),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.ST:  OpInfo("ST_MEMSX_DW", 11 + 87),
    
    # ===== STX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.STX: OpInfo("STX_IMM_W",  None),
    BpfMode.IMM   | BpfSize.H  | BpfClass.STX: OpInfo("STX_IMM_H",  None),
    BpfMode.IMM   | BpfSize.B  | BpfClass.STX: OpInfo("STX_IMM_B",  None),
    BpfMode.IMM   | BpfSize.DW | BpfClass.STX: OpInfo("STX_IMM_DW", None),

    BpfMode.ABS   | BpfSize.W  | BpfClass.STX: OpInfo("STX_ABS_W",  None),
    BpfMode.ABS   | BpfSize.H  | BpfClass.STX: OpInfo("STX_ABS_H",  None),
    BpfMode.ABS   | BpfSize.B  | BpfClass.STX: OpInfo("STX_ABS_B",  None),
    BpfMode.ABS   | BpfSize.DW | BpfClass.STX: OpInfo("STX_ABS_DW", None),

    BpfMode.IND   | BpfSize.W  | BpfClass.STX: OpInfo("STX_IND_W",  None),
    BpfMode.IND   | BpfSize.H  | BpfClass.STX: OpInfo("STX_IND_H",  None),
    BpfMode.IND   | BpfSize.B  | BpfClass.STX: OpInfo("STX_IND_B",  None),
    BpfMode.IND   | BpfSize.DW | BpfClass.STX: OpInfo("STX_IND_DW", None),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.STX: OpInfo("STX_W",  7 + 87),
    BpfMode.MEM   | BpfSize.H  | BpfClass.STX: OpInfo("STX_H",  7 + 87),
    BpfMode.MEM   | BpfSize.B  | BpfClass.STX: OpInfo("STX_B",  7 + 87),
    BpfMode.MEM   | BpfSize.DW | BpfClass.STX: OpInfo("STX_DW", 7 + 87),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.STX: OpInfo("FSTX_W",  1 + 87),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.STX: OpInfo("FSTX_H",  1 + 87),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.STX: OpInfo("FSTX_B",  1 + 87),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.STX: OpInfo("FSTX_DW",  1 + 87),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.STX: OpInfo("STX_MEMSX_W",  7 + 87),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.STX: OpInfo("STX_MEMSX_H",  7 + 87),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.STX: OpInfo("STX_MEMSX_B",  7 + 87),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.STX: OpInfo("STX_MEMSX_DW", 7 + 87),
    
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD) << 8): OpInfo("ATOMIC_ADD_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): OpInfo("ATOMIC_ADD_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND) << 8): OpInfo("ATOMIC_AND_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): OpInfo("ATOMIC_AND_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR) << 8): OpInfo("ATOMIC_OR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): OpInfo("ATOMIC_OR_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR) << 8): OpInfo("ATOMIC_XOR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): OpInfo("ATOMIC_XOR_FETCH_W", 8),

    # XCHG / CMPXCHG
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XCHG) << 8): OpInfo("ATOMIC_XCHG_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_CMPXCHG) << 8): OpInfo("ATOMIC_CMPXCHG_W", 8),

    # === STX | ATOMIC | DW（64-bit）===
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD          ) << 8): OpInfo("ATOMIC_ADD_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): OpInfo("ATOMIC_ADD_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND          ) << 8): OpInfo("ATOMIC_AND_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): OpInfo("ATOMIC_AND_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR           ) << 8): OpInfo("ATOMIC_OR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): OpInfo("ATOMIC_OR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR          ) << 8): OpInfo("ATOMIC_XOR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): OpInfo("ATOMIC_XOR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XCHG         ) << 8): OpInfo("ATOMIC_XCHG_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_CMPXCHG      ) << 8): OpInfo("ATOMIC_CMPXCHG_DW", 8),
}


BPF_INFO_FPU: Dict[int, OpInfo] = {
    # ===== FPU32 (Single Precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   OpInfo("FADD_K",   12),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   OpInfo("FADD_X",   5),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   OpInfo("FSUB_K",   12),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   OpInfo("FSUB_X",   5),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   OpInfo("FMUL_K",   12),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   OpInfo("FMUL_X",   5),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   OpInfo("FDIV_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   OpInfo("FDIV_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   OpInfo("FNEG_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   OpInfo("FNEG_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   OpInfo("FMOV_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   OpInfo("FMOV_X",   7),
    
    # ===== FPU64 (Double precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64:   OpInfo("FADD64_K",   14),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64:   OpInfo("FADD64_X",   7),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64:   OpInfo("FSUB64_K",   14),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64:   OpInfo("FSUB64_X",   7),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64:   OpInfo("FMUL64_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64:   OpInfo("FMUL64_X",   7),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64:   OpInfo("FDIV64_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64:   OpInfo("FDIV64_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64:   OpInfo("FNEG64_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64:   OpInfo("FNEG64_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64:   OpInfo("FMOV64_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64:   OpInfo("FMOV64_X",   7),
    
    ## Only register-register comparisons are supported!
    # ===== FJMP (64-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   OpInfo("JFEQ_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   OpInfo("JFEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   OpInfo("JFOGT_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   OpInfo("JFOGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   OpInfo("JFOGE_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   OpInfo("JFOGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   OpInfo("JFNE_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   OpInfo("JFNE_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   OpInfo("JFUGT_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   OpInfo("JFUGT_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   OpInfo("JFUGE_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   OpInfo("JFUGE_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   OpInfo("JFOLT_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   OpInfo("JFOLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   OpInfo("JFOLE_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   OpInfo("JFOLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   OpInfo("JFULT_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   OpInfo("JFULT_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   OpInfo("JFULE_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   OpInfo("JFULE_X",  8),

    # ===== FJMP32 (32-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32:   OpInfo("JFEQ32_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32:   OpInfo("JFEQ32_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOGT32_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOGT32_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOGE32_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOGE32_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFNE32_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFNE32_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32:   OpInfo("JFUGT32_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32:   OpInfo("JFUGT32_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32:   OpInfo("JFUGE32_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32:   OpInfo("JFUGE32_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOLT32_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOLT32_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32:   OpInfo("JFOLE32_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32:   OpInfo("JFOLE32_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32:   OpInfo("JFULT32_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32:   OpInfo("JFULT32_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32:   OpInfo("JFULE32_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32:   OpInfo("JFULE_32X",  8)
}
