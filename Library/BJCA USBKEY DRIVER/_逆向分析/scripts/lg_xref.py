"""搜索 PE .text 中对 VA/IAT 的调用与引用（用于定位关键代码）。

用法:
    python lg_xref.py calliat <exe> 0x45223c      # 找 call DWORD PTR ds:[VA] (FF 15 xx)
    python lg_xref.py push <exe> 0x454078         # 找 push imm32 (68 xx)
    python lg_xref.py any <exe> 0x454078          # 找任意 4 字节立即数引用
"""
import struct
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

SECTIONS = [
    ('.text', 0x401000, 0x50949, 0x400),
    ('.rdata', 0x452000, 0x15cfc, 0x50e00),
    ('.data', 0x468000, 0xba00, 0x66c00),
    ('.rsrc', 0x478000, 0xace10, 0x72600),
]


def va2off(va):
    for _, vma, size, foff in SECTIONS:
        if vma <= va < vma + size:
            return foff + (va - vma)
    return None


def main():
    mode, path, va = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    data = open(path, 'rb').read()
    text_vma, text_size, text_off = 0x401000, 0x50949, 0x400
    text = data[text_off:text_off + text_size]
    imm = struct.pack('<I', va)
    hits = []
    if mode in ('calliat', 'any'):
        hits += [m for m in range(5, len(text) - 4) if text[m:m + 4] == imm]
    else:
        hits += [m for m in range(1, len(text) - 4) if text[m:m + 4] == imm]
    seen = set()
    for i in hits:
        if i in seen:
            continue
        seen.add(i)
        va_pc = text_vma + i
        # 判断前置 opcode
        prev = text[i - 1] if i >= 1 else 0
        prev2 = text[i - 2] if i >= 2 else 0
        tag = ''
        if prev == 0x68:
            tag = 'push imm32'
        elif prev == 0xA1:
            tag = 'mov eax,[imm32]'
        elif prev == 0x15 and prev2 == 0xFF:
            tag = 'call ds:[imm32]'
        elif prev == 0x35 and prev2 == 0xFF:
            tag = 'push ds:[imm32]'
        elif prev == 0xB8:
            tag = 'mov eax,imm32'
        else:
            tag = f'raw (prev=0x{prev:02x})'
        print(f'code@0x{va_pc:08x}  {tag}')
    if not hits:
        print('no hit')
    print(f'total={len(seen)}')


if __name__ == '__main__':
    main()
