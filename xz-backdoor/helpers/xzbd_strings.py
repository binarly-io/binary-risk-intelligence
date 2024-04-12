# Created by @q3k:
# https://gist.github.com/q3k/3fadc5ce7b8001d550cf553cfdc09752

# Used as part of xzbd_chooser.py

import struct

import ida_bytes

tbl_1_mem = ida_bytes.get_bytes(0xAEE0, 0xC340 - 0xAEE0)
tbl_2_mem = ida_bytes.get_bytes(0xC340, 0xCAB0 - 0xC340)


def popcount(v):
    return bin(v).count("1")


def tbl_1_entry(offs):
    tbl_1_entry = tbl_1_mem[offs : offs + 4]
    a, b = struct.unpack("<HH", tbl_1_entry)
    return a, b


def tbl_2_entry(offs):
    tbl_2 = struct.unpack("<QQ", tbl_2_mem[offs : offs + 16])
    return tbl_2


def tbl_2_lookup(tbl_2, c):
    if c > 127:
        return None

    ix = 0
    lookup = tbl_2[0]
    if c < 0x40:
        if (lookup >> (c & 0x3F)) & 1 == 0:
            return None
    else:
        lookup = tbl_2[1]
        c -= 0x40
        if (lookup >> (c & 0x3F)) & 1 == 0:
            return None
        ix = popcount(tbl_2[0])

    # find the actually responsible bit
    while True:
        zeroes = 0
        if lookup != 0:
            while ((lookup >> zeroes) & 1) == 0:
                zeroes += 1
        if zeroes == c:
            break
        ix += 1
        lookup = lookup & (lookup - 1)
    return ix


def h(data):
    tbl_1_offs = 0x13E8
    tbl_2_offs = 0x760

    for c in data:
        # print(tbl_1_offs, tbl_2_offs)
        tbl_2 = tbl_2_entry(tbl_2_offs)

        # c = ord(c)
        ix = tbl_2_lookup(tbl_2, c)
        if ix is None:
            return 0

        _tbl_1_ix = tbl_1_offs + ix * 4
        a, b = tbl_1_entry(tbl_1_offs + ix * 4)

        if (a & 4) != 0:
            return b
        elif (a & 2) == 0:
            b = -b
        else:
            a &= 0xFFFD

        add_tbl2 = a & 0xFFFE
        if (a & 1) == 0:
            add_tbl2 = -a

        add_tbl1 = b - 4
        add_tbl2 = add_tbl2 - 0x10
        tbl_1_offs += add_tbl1
        tbl_2_offs += add_tbl2
    return 0


def invert(tbl_1_offs=0x13E8, tbl_2_offs=0x760):
    tbl_2 = tbl_2_entry(tbl_2_offs)

    res = []
    for i in range(128):
        ix = tbl_2_lookup(tbl_2, i)
        # invalid
        if ix is None:
            continue
        _tbl_1_ix = tbl_1_offs + ix * 4
        a, b = tbl_1_entry(tbl_1_offs + ix * 4)

        if (a & 4) != 0:
            # end of string
            res.append([i])
            continue

        # string continues
        if (a & 2) == 0:
            b = -b
        else:
            a &= 0xFFFD

        add_tbl2 = a & 0xFFFE
        if (a & 1) == 0:
            add_tbl2 = -a

        add_tbl1 = b - 4
        add_tbl2 = add_tbl2 - 0x10

        _followup = [i]
        for extra in invert(tbl_1_offs + add_tbl1, tbl_2_offs + add_tbl2):
            res.append([i] + extra)

    return res


if __name__ == "__main__":
    res = invert()
    for r in res:
        print("{:#04x}".format(h(bytes(r))), bytes(r))
