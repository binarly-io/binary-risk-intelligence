# Copyright 2024 Binarly REsearch
#
# https://github.com/binarly-io/binary-risk-intelligence/xz-backdoor

# This script is used to simplify xz backdoor strings navigation in IDA

import string

import ida_allins
import ida_enum
import ida_funcs
import ida_kernwin
import ida_ua
import idaapi
import idautils
import idc

import xzbd_strings

g_strings = {
    xzbd_strings.h(bytes(r)): bytes(r).decode(errors="ignore")
    for r in xzbd_strings.invert()
}


class MappingItem:
    def __init__(
        self, addr: int, string_id: int, string_value: str, func_name: str
    ) -> None:
        self.addr = f"0x{addr:08x}"
        self.string_id = f"0x{string_id:04x}"
        self.string_value = string_value
        self.func_name = func_name


def _enum_name(input: str) -> str:
    allowed = string.ascii_letters + string.digits
    return "STR_" + "".join([c if c in allowed else "_" for c in input])


def _sanitize(input: str) -> str:
    denied = "\n\x00"
    return "".join([c if c not in denied else "_" for c in input])


def create_enum() -> bool:
    name = "BackdoorStrings"
    eid = idc.add_enum(-1, name, idaapi.hex_flag())
    if eid & 0xFF == ida_enum.MAX_ENUM_SERIAL:
        print(f"[I] enum {name} is already exist")
        return False

    for sid, svalue in g_strings.items():
        idc.add_enum_member(enum_id=eid, name=_enum_name(svalue), value=sid, bmask=-1)

    print(f"[I] enum {name} is created")

    return True


def get_code_addrs() -> dict:
    mapping = dict()
    for addr in idautils.Functions():
        f = ida_funcs.get_func(addr)
        ea = f.start_ea
        while ea <= f.end_ea:
            ea = idc.next_head(ea)  # first instruction does not matter
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, ea)
            if insn.itype not in (ida_allins.NN_cmp, ida_allins.NN_mov):
                continue
            if insn.ops[0].type != ida_ua.o_reg:
                continue
            op = insn.ops[1]
            if op.type != ida_ua.o_imm or op.value not in g_strings:
                continue
            print(
                f"[I] {_sanitize(g_strings[op.value])} ({op.value:#x}) usage detected at {ea:#x}"
            )
            mapping[ea] = MappingItem(
                addr=ea,
                string_id=op.value,
                string_value=g_strings[op.value],
                func_name=ida_funcs.get_func_name(ea),
            )

    return mapping


class bd_strings_t(ida_kernwin.Choose):
    def __init__(self, title, mapping) -> None:
        self._mapping = mapping
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
                ["Function", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["String", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Enum name", 30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["ID", 6 | ida_kernwin.Choose.CHCOL_HEX],
            ],
        )
        self.items = list()

    def _get_item(m: MappingItem):
        return [
            m.addr,
            m.func_name,
            _sanitize(m.string_value),
            _enum_name(m.string_value),
            m.string_id,
        ]

    def OnInit(self):
        self.items = [bd_strings_t._get_item(m) for _ea, m in self._mapping.items()]
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        return (ida_kernwin.Choose.ALL_CHANGED, n)

    def OnGetEA(self, n):
        return int(self.items[n][0], 16)

    def OnRefresh(self, n):
        self.OnInit()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        print("closed ", self.title)


if __name__ == "__main__":
    create_enum()
    c = bd_strings_t("xz backdoor strings list", get_code_addrs())
    c.Show(modal=False)
