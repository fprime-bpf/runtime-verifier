import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Dict


@dataclass(frozen=True)
class InstrInfo:
    name: str
    latency: Optional[int]

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




BPF_ATOMIC_OP_MASK = 0x0F
BPF_FETCH          = 0x10

ATOMIC_ADD     = 0x0
ATOMIC_AND     = 0x1
ATOMIC_OR      = 0x2
ATOMIC_XOR     = 0x3
ATOMIC_XCHG    = 0xE
ATOMIC_CMPXCHG = 0xF


BPF_INFO: Dict[int, InstrInfo] = {
    # ===== ALU (32-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   InstrInfo("ADD_K",   5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   InstrInfo("ADD_X",   1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   InstrInfo("SUB_K",   5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   InstrInfo("SUB_X",   1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   InstrInfo("MUL_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   InstrInfo("MUL_X",   10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   InstrInfo("DIV_K",   38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   InstrInfo("DIV_X",   34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU:   InstrInfo("MOD_K",   38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU:   InstrInfo("MOD_X",   34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU:   InstrInfo("OR_K",    5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU:   InstrInfo("OR_X",    1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU:   InstrInfo("AND_K",   5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU:   InstrInfo("AND_X",   1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU:   InstrInfo("LSH_K",   1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU:   InstrInfo("LSH_X",   1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU:   InstrInfo("RSH_K",   1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU:   InstrInfo("RSH_X",   1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   InstrInfo("NEG_K",   0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   InstrInfo("NEG_X",   0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU:   InstrInfo("XOR_K",   5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU:   InstrInfo("XOR_X",   1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   InstrInfo("MOV_K",   4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   InstrInfo("MOV_X",   4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU:   InstrInfo("ARSH_K",  1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU:   InstrInfo("ARSH_X",  1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU:   InstrInfo("END",     None),

    # ===== ALU64 (64-bit) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64: InstrInfo("ADD64_K", 5),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64: InstrInfo("ADD64_X", 1),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64: InstrInfo("SUB64_K", 5),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64: InstrInfo("SUB64_X", 1),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64: InstrInfo("MUL64_K", 14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64: InstrInfo("MUL64_X", 10),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64: InstrInfo("DIV64_K", 38),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64: InstrInfo("DIV64_X", 34),
    BpfCode.ALU.MOD  | BpfS.K | BpfClass.ALU64: InstrInfo("MOD64_K", 38),
    BpfCode.ALU.MOD  | BpfS.X | BpfClass.ALU64: InstrInfo("MOD64_X", 34),
    BpfCode.ALU.OR   | BpfS.K | BpfClass.ALU64: InstrInfo("OR64_K",  5),
    BpfCode.ALU.OR   | BpfS.X | BpfClass.ALU64: InstrInfo("OR64_X",  1),
    BpfCode.ALU.AND  | BpfS.K | BpfClass.ALU64: InstrInfo("AND64_K", 5),
    BpfCode.ALU.AND  | BpfS.X | BpfClass.ALU64: InstrInfo("AND64_X", 1),
    BpfCode.ALU.LSH  | BpfS.K | BpfClass.ALU64: InstrInfo("LSH64_K", 1),
    BpfCode.ALU.LSH  | BpfS.X | BpfClass.ALU64: InstrInfo("LSH64_X", 1),
    BpfCode.ALU.RSH  | BpfS.K | BpfClass.ALU64: InstrInfo("RSH64_K", 1),
    BpfCode.ALU.RSH  | BpfS.X | BpfClass.ALU64: InstrInfo("RSH64_X", 1),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64: InstrInfo("NEG64_K", 0),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64: InstrInfo("NEG64_X", 0),
    BpfCode.ALU.XOR  | BpfS.K | BpfClass.ALU64: InstrInfo("XOR64_K", 5),
    BpfCode.ALU.XOR  | BpfS.X | BpfClass.ALU64: InstrInfo("XOR64_X", 1),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64: InstrInfo("MOV64_K", 4),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64: InstrInfo("MOV64_X", 4),
    BpfCode.ALU.ARSH | BpfS.K | BpfClass.ALU64: InstrInfo("ARSH64_K",1),
    BpfCode.ALU.ARSH | BpfS.X | BpfClass.ALU64: InstrInfo("ARSH64_X",1),
    BpfCode.ALU.END  | BpfS.K | BpfClass.ALU64: InstrInfo("END64",   None),

    # ===== JMP (64-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP:   InstrInfo("JA",      2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   InstrInfo("JEQ_K",   7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   InstrInfo("JEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   InstrInfo("JGT_K",   7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   InstrInfo("JGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   InstrInfo("JGE_K",   7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   InstrInfo("JGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   InstrInfo("JNE_K",   7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   InstrInfo("JNE_X",   3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP:   InstrInfo("JSET_K",  8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP:   InstrInfo("JSET_X",  4),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   InstrInfo("JSGT_K",  7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   InstrInfo("JSGT_X",  3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   InstrInfo("JSGE_K",  7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   InstrInfo("JSGE_X",  3),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   InstrInfo("JLT_K",   7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   InstrInfo("JLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   InstrInfo("JLE_K",   7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   InstrInfo("JLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   InstrInfo("JSLT_K",  7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   InstrInfo("JSLT_X",  3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   InstrInfo("JSLE_K",  7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   InstrInfo("JSLE_X",  3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:   InstrInfo("CALL",    None),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP:   InstrInfo("CALL",    None),
    BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:   InstrInfo("EXIT",    2),

    # ===== JMP32 (32-bit compare) =====
    BpfCode.JMP.JA   | BpfS.K | BpfClass.JMP32: InstrInfo("JA", 2),
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32: InstrInfo("JEQ32_K", 7),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32: InstrInfo("JEQ32_X", 3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32: InstrInfo("JNE32_K", 7),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32: InstrInfo("JNE32_X", 3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32: InstrInfo("JGT32_K", 7),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32: InstrInfo("JGT32_X", 3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32: InstrInfo("JGE32_K", 7),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32: InstrInfo("JGE32_X", 3),
    BpfCode.JMP.JSET | BpfS.K | BpfClass.JMP32: InstrInfo("JSET32_K", 8),
    BpfCode.JMP.JSET | BpfS.X | BpfClass.JMP32: InstrInfo("JSET32_X", 4),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32: InstrInfo("JLT32_K", 7),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32: InstrInfo("JLT32_X", 3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32: InstrInfo("JLE32_K", 7),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32: InstrInfo("JLE32_X", 3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32: InstrInfo("JSGT32_K", 7),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32: InstrInfo("JSGT32_X", 3),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32: InstrInfo("JSGE32_K", 7),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32: InstrInfo("JSGE32_X", 3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32: InstrInfo("JSLT32_K", 7),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32: InstrInfo("JSLT32_X", 3),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32: InstrInfo("JSLE32_K", 7),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32: InstrInfo("JSLE32_X", 3),
    BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP32: InstrInfo("CALL",     None),
    BpfCode.JMP.CALL | BpfS.X | BpfClass.JMP32: InstrInfo("CALL",     None),
    
    # ===== LD =====
    BpfMode.IMM | BpfSize.W  | BpfClass.LD:  InstrInfo("LD_IMM_W",  11),
    BpfMode.IMM | BpfSize.H  | BpfClass.LD:  InstrInfo("LD_IMM_H",  11),
    BpfMode.IMM | BpfSize.B  | BpfClass.LD:  InstrInfo("LD_IMM_B",  11),
    BpfMode.IMM | BpfSize.DW | BpfClass.LD:  InstrInfo("LDDW",  11),   # 

    BpfMode.ABS | BpfSize.W  | BpfClass.LD:  InstrInfo("LD_ABS_W",  11),
    BpfMode.ABS | BpfSize.H  | BpfClass.LD:  InstrInfo("LD_ABS_H",  11),
    BpfMode.ABS | BpfSize.B  | BpfClass.LD:  InstrInfo("LD_ABS_B",  11),
    BpfMode.ABS | BpfSize.DW | BpfClass.LD:  InstrInfo("LD_ABS_DW", 11),

    BpfMode.IND | BpfSize.W  | BpfClass.LD:  InstrInfo("LD_IND_W",  11),
    BpfMode.IND | BpfSize.H  | BpfClass.LD:  InstrInfo("LD_IND_H",  11),
    BpfMode.IND | BpfSize.B  | BpfClass.LD:  InstrInfo("LD_IND_B",  11),
    BpfMode.IND | BpfSize.DW | BpfClass.LD:  InstrInfo("LD_IND_DW", 11),

    BpfMode.MEM   | BpfSize.W  | BpfClass.LD: InstrInfo("LD_MEM_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LD: InstrInfo("LD_MEM_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LD: InstrInfo("LD_MEM_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LD: InstrInfo("LD_MEM_DW", 11),

    BpfMode.FMEM  | BpfSize.W  | BpfClass.LD: InstrInfo("FLD_W",  11),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LD: InstrInfo("FLD_H",  11),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LD: InstrInfo("FLD_B",  11),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LD: InstrInfo("FLD_DW", 11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LD: InstrInfo("LD_MEMSX_W",  11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LD: InstrInfo("LD_MEMSX_H",  11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LD: InstrInfo("LD_MEMSX_B",  11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LD: InstrInfo("LD_MEMSX_DW", 11),
    
    # ===== LDX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.LDX: InstrInfo("LDX_IMM_W",  11),
    BpfMode.IMM   | BpfSize.H  | BpfClass.LDX: InstrInfo("LDX_IMM_H",  11),
    BpfMode.IMM   | BpfSize.B  | BpfClass.LDX: InstrInfo("LDX_IMM_B",  11),
    BpfMode.IMM   | BpfSize.DW | BpfClass.LDX: InstrInfo("LDX_IMM_DW", 11),

    BpfMode.ABS   | BpfSize.W  | BpfClass.LDX: InstrInfo("LDX_ABS_W",  11),
    BpfMode.ABS   | BpfSize.H  | BpfClass.LDX: InstrInfo("LDX_ABS_H",  11),
    BpfMode.ABS   | BpfSize.B  | BpfClass.LDX: InstrInfo("LDX_ABS_B",  11),
    BpfMode.ABS   | BpfSize.DW | BpfClass.LDX: InstrInfo("LDX_ABS_DW", 11),

    BpfMode.IND   | BpfSize.W  | BpfClass.LDX: InstrInfo("LDX_IND_W",  11),
    BpfMode.IND   | BpfSize.H  | BpfClass.LDX: InstrInfo("LDX_IND_H",  11),
    BpfMode.IND   | BpfSize.B  | BpfClass.LDX: InstrInfo("LDX_IND_B",  11),
    BpfMode.IND   | BpfSize.DW | BpfClass.LDX: InstrInfo("LDX_IND_DW", 11),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.LDX: InstrInfo("LDX_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.LDX: InstrInfo("LDX_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.LDX: InstrInfo("LDX_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.LDX: InstrInfo("LDX_DW", 11),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.LDX: InstrInfo("FLDX_W",  11),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.LDX: InstrInfo("FLDX_H",  11),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.LDX: InstrInfo("FLDX_B",  11),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.LDX: InstrInfo("FLDX_DW",  11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.LDX: InstrInfo("LDX_MEMSX_W", 11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.LDX: InstrInfo("LDX_MEMSX_H", 11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.LDX: InstrInfo("LDX_MEMSX_B", 11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.LDX: InstrInfo("LDX_MEMSX_DW", 11),
    
    # ===== ST =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.ST:  InstrInfo("ST_IMM_W",  11),
    BpfMode.IMM   | BpfSize.H  | BpfClass.ST:  InstrInfo("ST_IMM_H",  11),
    BpfMode.IMM   | BpfSize.B  | BpfClass.ST:  InstrInfo("ST_IMM_B",  11),
    BpfMode.IMM   | BpfSize.DW | BpfClass.ST:  InstrInfo("ST_IMM_DW", 11),

    BpfMode.ABS   | BpfSize.W  | BpfClass.ST:  InstrInfo("ST_ABS_W",  11),
    BpfMode.ABS   | BpfSize.H  | BpfClass.ST:  InstrInfo("ST_ABS_H",  11),
    BpfMode.ABS   | BpfSize.B  | BpfClass.ST:  InstrInfo("ST_ABS_B",  11),
    BpfMode.ABS   | BpfSize.DW | BpfClass.ST:  InstrInfo("ST_ABS_DW", 11),

    BpfMode.IND   | BpfSize.W  | BpfClass.ST:  InstrInfo("ST_IND_W",  11),
    BpfMode.IND   | BpfSize.H  | BpfClass.ST:  InstrInfo("ST_IND_H",  11),
    BpfMode.IND   | BpfSize.B  | BpfClass.ST:  InstrInfo("ST_IND_B",  11),
    BpfMode.IND   | BpfSize.DW | BpfClass.ST:  InstrInfo("ST_IND_DW", 11),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.ST:  InstrInfo("ST_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.ST:  InstrInfo("ST_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.ST:  InstrInfo("ST_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.ST:  InstrInfo("ST_DW", 11),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.ST: InstrInfo("FST_W",  11),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.ST: InstrInfo("FST_H",  11),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.ST: InstrInfo("FST_B",  11),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.ST: InstrInfo("FST_DW",  11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.ST:  InstrInfo("ST_MEMSX_W",  11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.ST:  InstrInfo("ST_MEMSX_H",  11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.ST:  InstrInfo("ST_MEMSX_B",  11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.ST:  InstrInfo("ST_MEMSX_DW", 11),
    
    # ===== STX =====
    BpfMode.IMM   | BpfSize.W  | BpfClass.STX: InstrInfo("STX_IMM_W",  11),
    BpfMode.IMM   | BpfSize.H  | BpfClass.STX: InstrInfo("STX_IMM_H",  11),
    BpfMode.IMM   | BpfSize.B  | BpfClass.STX: InstrInfo("STX_IMM_B",  11),
    BpfMode.IMM   | BpfSize.DW | BpfClass.STX: InstrInfo("STX_IMM_DW", 11),

    BpfMode.ABS   | BpfSize.W  | BpfClass.STX: InstrInfo("STX_ABS_W",  11),
    BpfMode.ABS   | BpfSize.H  | BpfClass.STX: InstrInfo("STX_ABS_H",  11),
    BpfMode.ABS   | BpfSize.B  | BpfClass.STX: InstrInfo("STX_ABS_B",  11),
    BpfMode.ABS   | BpfSize.DW | BpfClass.STX: InstrInfo("STX_ABS_DW", 11),

    BpfMode.IND   | BpfSize.W  | BpfClass.STX: InstrInfo("STX_IND_W",  11),
    BpfMode.IND   | BpfSize.H  | BpfClass.STX: InstrInfo("STX_IND_H",  11),
    BpfMode.IND   | BpfSize.B  | BpfClass.STX: InstrInfo("STX_IND_B",  11),
    BpfMode.IND   | BpfSize.DW | BpfClass.STX: InstrInfo("STX_IND_DW", 11),
    
    BpfMode.MEM   | BpfSize.W  | BpfClass.STX: InstrInfo("STX_W",  11),
    BpfMode.MEM   | BpfSize.H  | BpfClass.STX: InstrInfo("STX_H",  11),
    BpfMode.MEM   | BpfSize.B  | BpfClass.STX: InstrInfo("STX_B",  11),
    BpfMode.MEM   | BpfSize.DW | BpfClass.STX: InstrInfo("STX_DW", 11),
    
    BpfMode.FMEM  | BpfSize.W  | BpfClass.STX: InstrInfo("FSTX_W",  11),
    BpfMode.FMEM  | BpfSize.H  | BpfClass.STX: InstrInfo("FSTX_H",  11),
    BpfMode.FMEM  | BpfSize.B  | BpfClass.STX: InstrInfo("FSTX_B",  11),
    BpfMode.FMEM  | BpfSize.DW | BpfClass.STX: InstrInfo("FSTX_DW", 11),

    BpfMode.MEMSX | BpfSize.W  | BpfClass.STX: InstrInfo("STX_MEMSX_W",  11),
    BpfMode.MEMSX | BpfSize.H  | BpfClass.STX: InstrInfo("STX_MEMSX_H",  11),
    BpfMode.MEMSX | BpfSize.B  | BpfClass.STX: InstrInfo("STX_MEMSX_B",  11),
    BpfMode.MEMSX | BpfSize.DW | BpfClass.STX: InstrInfo("STX_MEMSX_DW", 11),
    
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD) << 8): InstrInfo("ATOMIC_ADD_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): InstrInfo("ATOMIC_ADD_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND) << 8): InstrInfo("ATOMIC_AND_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): InstrInfo("ATOMIC_AND_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR) << 8): InstrInfo("ATOMIC_OR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): InstrInfo("ATOMIC_OR_FETCH_W", 8),

    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR) << 8): InstrInfo("ATOMIC_XOR_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): InstrInfo("ATOMIC_XOR_FETCH_W", 8),

    # XCHG / CMPXCHG
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_XCHG) << 8): InstrInfo("ATOMIC_XCHG_W", 8),
    (BpfMode.ATOMIC | BpfSize.W  | BpfClass.STX) | ((ATOMIC_CMPXCHG) << 8): InstrInfo("ATOMIC_CMPXCHG_W", 8),

    # === STX | ATOMIC | DW（64-bit）===
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD          ) << 8): InstrInfo("ATOMIC_ADD_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_ADD|BPF_FETCH) << 8): InstrInfo("ATOMIC_ADD_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND          ) << 8): InstrInfo("ATOMIC_AND_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_AND|BPF_FETCH) << 8): InstrInfo("ATOMIC_AND_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR           ) << 8): InstrInfo("ATOMIC_OR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_OR |BPF_FETCH) << 8): InstrInfo("ATOMIC_OR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR          ) << 8): InstrInfo("ATOMIC_XOR_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XOR|BPF_FETCH) << 8): InstrInfo("ATOMIC_XOR_FETCH_DW", 8),

    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_XCHG         ) << 8): InstrInfo("ATOMIC_XCHG_DW", 8),
    (BpfMode.ATOMIC | BpfSize.DW | BpfClass.STX) | ((ATOMIC_CMPXCHG      ) << 8): InstrInfo("ATOMIC_CMPXCHG_DW", 8),
}


BPF_INFO_FPU: Dict[int, InstrInfo] = {
    # ===== FPU32 (Single Precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU:   InstrInfo("FADD_K",   12),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU:   InstrInfo("FADD_X",   5),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU:   InstrInfo("FSUB_K",   12),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU:   InstrInfo("FSUB_X",   5),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU:   InstrInfo("FMUL_K",   12),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU:   InstrInfo("FMUL_X",   5),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU:   InstrInfo("FDIV_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU:   InstrInfo("FDIV_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU:   InstrInfo("FNEG_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU:   InstrInfo("FNEG_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU:   InstrInfo("FMOV_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU:   InstrInfo("FMOV_X",   7),
    
    # ===== FPU64 (Double precision) =====
    BpfCode.ALU.ADD  | BpfS.K | BpfClass.ALU64:   InstrInfo("FADD64_K",   14),
    BpfCode.ALU.ADD  | BpfS.X | BpfClass.ALU64:   InstrInfo("FADD64_X",   7),
    BpfCode.ALU.SUB  | BpfS.K | BpfClass.ALU64:   InstrInfo("FSUB64_K",   14),
    BpfCode.ALU.SUB  | BpfS.X | BpfClass.ALU64:   InstrInfo("FSUB64_X",   7),
    BpfCode.ALU.MUL  | BpfS.K | BpfClass.ALU64:   InstrInfo("FMUL64_K",   14),
    BpfCode.ALU.MUL  | BpfS.X | BpfClass.ALU64:   InstrInfo("FMUL64_X",   7),
    BpfCode.ALU.DIV  | BpfS.K | BpfClass.ALU64:   InstrInfo("FDIV64_K",   27),
    BpfCode.ALU.DIV  | BpfS.X | BpfClass.ALU64:   InstrInfo("FDIV64_X",   20),
    BpfCode.ALU.NEG  | BpfS.K | BpfClass.ALU64:   InstrInfo("FNEG64_K",   3),
    BpfCode.ALU.NEG  | BpfS.X | BpfClass.ALU64:   InstrInfo("FNEG64_X",   3),
    BpfCode.ALU.MOV  | BpfS.K | BpfClass.ALU64:   InstrInfo("FMOV64_K",   7),
    BpfCode.ALU.MOV  | BpfS.X | BpfClass.ALU64:   InstrInfo("FMOV64_X",   7),
    
    ## Only register-register comparisons are supported!
    # ===== FJMP (64-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP:   InstrInfo("JFEQ_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP:   InstrInfo("JFEQ_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP:   InstrInfo("JFOGT_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP:   InstrInfo("JFOGT_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP:   InstrInfo("JFOGE_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP:   InstrInfo("JFOGE_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP:   InstrInfo("JFNE_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP:   InstrInfo("JFNE_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP:   InstrInfo("JFUGT_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP:   InstrInfo("JFUGT_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP:   InstrInfo("JFUGE_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP:   InstrInfo("JFUGE_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP:   InstrInfo("JFOLT_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP:   InstrInfo("JFOLT_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP:   InstrInfo("JFOLE_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP:   InstrInfo("JFOLE_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP:   InstrInfo("JFULT_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP:   InstrInfo("JFULT_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP:   InstrInfo("JFULE_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:   InstrInfo("JFULE_X",  8),

    # ===== FJMP32 (32-bit compare) =====
    BpfCode.JMP.JEQ  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFEQ32_K",   10),
    BpfCode.JMP.JEQ  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFEQ32_X",   3),
    BpfCode.JMP.JGT  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFOGT32_K",   10),
    BpfCode.JMP.JGT  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFOGT32_X",   3),
    BpfCode.JMP.JGE  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFOGE32_K",   10),
    BpfCode.JMP.JGE  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFOGE32_X",   3),
    BpfCode.JMP.JNE  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFNE32_K",   10),
    BpfCode.JMP.JNE  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFNE32_X",   3),
    BpfCode.JMP.JSGT | BpfS.K | BpfClass.JMP32:   InstrInfo("JFUGT32_K",  15),
    BpfCode.JMP.JSGT | BpfS.X | BpfClass.JMP32:   InstrInfo("JFUGT32_X",  8),
    BpfCode.JMP.JSGE | BpfS.K | BpfClass.JMP32:   InstrInfo("JFUGE32_K",  15),
    BpfCode.JMP.JSGE | BpfS.X | BpfClass.JMP32:   InstrInfo("JFUGE32_X",  8),
    BpfCode.JMP.JLT  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFOLT32_K",   10),
    BpfCode.JMP.JLT  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFOLT32_X",   3),
    BpfCode.JMP.JLE  | BpfS.K | BpfClass.JMP32:   InstrInfo("JFOLE32_K",   10),
    BpfCode.JMP.JLE  | BpfS.X | BpfClass.JMP32:   InstrInfo("JFOLE32_X",   3),
    BpfCode.JMP.JSLT | BpfS.K | BpfClass.JMP32:   InstrInfo("JFULT32_K",  15),
    BpfCode.JMP.JSLT | BpfS.X | BpfClass.JMP32:   InstrInfo("JFULT32_X",  8),
    BpfCode.JMP.JSLE | BpfS.K | BpfClass.JMP32:   InstrInfo("JFULE32_K",  15),
    BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP32:   InstrInfo("JFULE_32X",  8)
}
