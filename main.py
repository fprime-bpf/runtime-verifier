import sys
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


class Instruction:
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
        return (self._to_int(self.instruction) & Mask.IMM) >> Shift.IMM

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
        return str(self.instruction)


def read_file(filename: str) -> list[Instruction]:
    inst_size = 8
    instructions = []
    with open(filename, "rb") as file:
        while True:
            ins = file.read(inst_size)
            if ins == b"":
                break

            instructions.append(Instruction(ins))

    return instructions


def get_blocks(instructions: list[Instruction]):
    start = set([0])
    ends = set([])

    for idx in range(1, len(instructions)):
        ins = instructions[idx]
        print(f"instruction: {str(ins)}")

        print(f"opcode: {ins.opcode}")
        # print(f"last: {BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP}")

        # python match case expressions are structural,
        # meaning they match structure (e.g. are you of type int?),
        # not values (e.g. are you 221?)
        # we go around this with our `x if x == (value)`
        match (ins.opcode):
            # unconditional jumps
            case x if x == BpfCode.JMP.EXIT | BpfS.K | BpfClass.JMP:
                print(f"idx={idx}: EXIT")
                ends.add(idx)

            case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP:  # offset jump
                ends.add(idx)
                jump_to = idx + ins.off + 1
                print(f"idx={idx}: jump_to={jump_to}")
                start.add(jump_to)

            case x if x == BpfCode.JMP.JA | BpfS.K | BpfClass.JMP32:  # imm jump
                ends.add(idx)
                jump_to = idx + ins.imm + 1
                print(f"idx={idx}: jump_to={jump_to}")
                start.add(jump_to)

            case x if x == BpfCode.JMP.CALL | BpfS.K | BpfClass.JMP:
                ends.add(idx)
                start.add(idx + 1)
                match (ins.src):
                    case 0:
                        print("calling helper function by static id")
                        raise Exception(f"idx={idx}: not implemented")
                    case 1:
                        print(f"calling normal function")
                        jump_to = idx + ins.imm + 1
                        start.add(jump_to)
                    case 2:
                        print("calling helper function by BTF id")
                        raise Exception(f"idx={idx}: not implemented")

                pass

            # conditional jumps
            case x if x == BpfCode.JMP.JSLE | BpfS.X | BpfClass.JMP:
                ends.add(idx)
                jump_if = idx + ins.off + 1
                jump_else = idx + 1
                print(f"idx={idx}: jump_if={jump_if}, jump_else={jump_else}")
                start.add(jump_if)
                start.add(jump_else)

            case _:
                if ins.get_class() in [BpfClass.JMP, BpfClass.JMP32]:
                    raise Exception(f"idx={idx}: couldn't catch opcode: {ins.opcode}")
                print(f"got {ins.get_class().name}")

    blocks = [(s, e) for s, e in zip(start, ends)]
    return blocks


def main():
    args = sys.argv
    if len(args) != 2:
        raise Exception(f"usage: {args[0]} <filename>")
    filename = args[1]

    instructions = read_file(filename)
    basic_blocks = get_blocks(instructions)

    print(basic_blocks)


if __name__ == "__main__":
    main()
