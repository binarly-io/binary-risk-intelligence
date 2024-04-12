# Copyright 2024 Binarly REsearch
#
# https://github.com/binarly-io/binary-risk-intelligence/xz-backdoor

# This script is used to create InsnOpcodes enum
# which contains the values for the insn_t.opcode

import ida_enum
import idaapi
import idc

# http://ref.x86asm.net/coder32.html
# bd_opcode = opcode + 0x80
BD_OPCODES = {
    "INSN_CALL": 0x168,
    "INSN_CALL_JMP": 0x17F,
    "INSN_CMP0": 0xBB,
    "INSN_CMP1": 0x103,
    "INSN_JMP1": 0x169,
    "INSN_JMP2": 0x16A,
    "INSN_JMP3": 0x16B,
    "INSN_MOV0": 0x109,
    "INSN_MOV1": 0x10B,
    "INSN_MOV2": 0x147,
    "INSN_MOVZX": 0x1036,
    "INSN_LEA0": 0x10D,
    "INSN_LEA1": 0x10E,
    "INSN_XOR": 0xB1,
    "INSN_NOP": 0xF9F,
}


def main():
    enum_name = "InsnOpcodes"
    eid = idc.add_enum(-1, enum_name, idaapi.hex_flag())
    if eid & 0xFF == ida_enum.MAX_ENUM_SERIAL:
        print(f"[I] enum {enum_name} is already exist")
        return False

    for name, value in BD_OPCODES.items():
        idc.add_enum_member(enum_id=eid, name=name, value=value, bmask=-1)

    print(f"[I] enum {enum_name} is created")


if __name__ == "__main__":
    main()
