import struct
from enum import IntEnum


class BpfClass(IntEnum):
    LD = 0x0
    LDX = 0x1
    ST = 0x2
    STX = 0x3
    ALU = 0x4
    JMP = 0x5
    JMP32 = 0x6
    ALU64 = 0x7


class Shift:
    IMM = 32
    OFFSET = 16
    SRC = 12
    DST = 8
    OPCODE = CLASS = 0
    S = SZ = 3
    CODE = 4
    MODE = 5


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


code_in_opcode_shift = Shift.CODE - Shift.OPCODE
s_in_opcode_shift = Shift.S - Shift.OPCODE


# for Arithmetic and Jump instructions
class BpfS:
    shift = s_in_opcode_shift
    K = 0x0 << shift  # imm is source
    X = 0x1 << shift  # src is source

# for Load and Store instructions
class BpfSize:
    W  = 0x00 << Shift.SZ   # 32
    H  = 0x01 << Shift.SZ   # 16
    B  = 0x02 << Shift.SZ   # 8
    DW = 0x03 << Shift.SZ   # 64

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
        
    class LOAD_STORE:
        shift = code_in_opcode_shift
        IMM = 0x0 << shift
        ABS = 0x1 << shift
        IND = 0x2 << shift
        MEM = 0x3 << shift
        MEMSX = 0x4 << shift
        ATOMIC = 0x6 << shift


class BpfInstruction:
    def __init__(self, instruction: bytes) -> None:
        self.instruction = instruction

        self.imm = self._get_imm()
        self.off = self._get_off()
        self.src = self._get_src()
        self.dst = self._get_dst()
        self.opcode = self._get_opcode()

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

    def get_class(self) -> BpfClass:
        return BpfClass(self.opcode & (Mask.CLASS >> Shift.CLASS))

    def __str__(self) -> str:
        return " ".join([f"{b:02x}" for b in self.instruction])

    def __repr__(self) -> str:
        return str(self)
