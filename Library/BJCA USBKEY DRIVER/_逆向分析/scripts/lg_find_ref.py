"""在 PE 中定位字符串（GBK/ASCII/UTF-16）并反查引用它的代码位置。

用法:
    python lg_find_ref.py find <exe> "初始化USB-Key失败"
    python lg_find_ref.py refs <exe> 0x452abc
"""
import re
import sys
import struct

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

SECTIONS = [
    # (name, vma, size, file_off)
    ('.text', 0x401000, 0x50949, 0x400),
    ('.rdata', 0x452000, 0x15cfc, 0x50e00),
    ('.data', 0x468000, 0xba00, 0x66c00),
    ('.rsrc', 0x478000, 0xace10, 0x72600),
]


def off2va(off):
    for _, vma, size, foff in SECTIONS:
        if foff <= off < foff + size:
            return vma + (off - foff)
    return None


def va2off(va):
    for _, vma, size, foff in SECTIONS:
        if vma <= va < vma + size:
            return foff + (va - vma)
    return None


def find(path, text):
    data = open(path, 'rb').read()
    cands = []
    for enc in ('gbk', 'utf-16-le', 'ascii'):
        try:
            needle = text.encode(enc)
        except Exception:
            continue
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            cands.append((i, off2va(i), enc))
            start = i + 1
    for off, va, enc in cands:
        print(f'file=0x{off:06x} va=0x{va:08x} enc={enc}')
    if not cands:
        print('not found')
    return cands


def refs(path, va):
    data = open(path, 'rb').read()
    text = data[0x400:0x400 + 0x50949]
    base = 0x401000
    out = []
    pat = struct.pack('<I', va)
    start = 0
    while True:
        i = text.find(pat, start)
        if i < 0:
            break
        out.append(base + i)
        start = i + 1
    # 同时找 push imm32 (0x68) / mov reg,imm32 (0xB8+r)
    for pc in out:
        off = pc - 4  # 立即数前 4 字节是 opcode
        if off >= 0:
            op = text[off - 0x400]
            print(f'ref@0x{pc:08x} (imm at 0x{pc:08x}), prev_op=0x{op:02x}')
    if not out:
        print('no direct reference found')
    return out


def main():
    mode = sys.argv[1]
    path = sys.argv[2]
    if mode == 'find':
        find(path, sys.argv[3])
    else:
        refs(path, int(sys.argv[3], 16))


if __name__ == '__main__':
    main()
