"""十六进制 + 字符串双视图转储（用于分析 SDK 回填的结构体）。

用法:
    python gm_hexdump.py <file> [最大字节数]
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def main():
    path = sys.argv[1]
    limit = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x200
    offset = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
    d = open(path, 'rb').read()
    end = min(offset + limit, len(d))
    print(f'{path}  文件长度={len(d)}  显示 0x{offset:X}..0x{end:X}')
    for off in range(offset, end, 16):
        chunk = d[off:min(off + 16, end)]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        txt = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        print(f'{off:04X}  {hexs:<47}  {txt}')
    print('--- 可打印串（>=3）---')
    for m in re.finditer(rb'[\x20-\x7e]{3,}', d[offset:end]):
        print(f'{offset + m.start():04X}: {m.group().decode("latin1")}')
    print('--- 32 位小端整数视图 ---')
    for off in range(offset, end - 3, 4):
        v = int.from_bytes(d[off:off + 4], 'little')
        if v:
            print(f'{off:04X}: {v} (0x{v:X})')


if __name__ == '__main__':
    main()
