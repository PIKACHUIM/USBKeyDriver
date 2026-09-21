"""PE 头部调试：打印可选头关键字段与数据目录原始字节。"""
import struct
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def main():
    path = sys.argv[1]
    d = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    coff = e_lfanew + 4
    machine, nsect, ts = struct.unpack_from('<HHI', d, coff)
    opt_size = struct.unpack_from('<H', d, coff + 16)[0]
    characteristics = struct.unpack_from('<H', d, coff + 18)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', d, opt)[0]
    num_dd = struct.unpack_from('<I', d, opt + 92)[0]
    print(f'path={path}')
    print(f'e_lfanew=0x{e_lfanew:X} coff=0x{coff:X} machine=0x{machine:04X} '
          f'nsect={nsect} opt_size=0x{opt_size:X} characteristics=0x{characteristics:04X}')
    print(f'opt_off=0x{opt:X} magic=0x{magic:X} NumberOfRvaAndSizes@92={num_dd}')
    print(f'SizeOfImage@56={struct.unpack_from("<I", d, opt + 56)[0]:#x} '
          f'SizeOfHeaders@60={struct.unpack_from("<I", d, opt + 60)[0]:#x} '
          f'AddrOfEntry@16={struct.unpack_from("<I", d, opt + 16)[0]:#x}')
    print('--- 可选头尾部 160 字节 (opt+64) ---')
    base = opt + 64
    for row in range(0, 160, 16):
        chunk = d[base + row:base + row + 16]
        print(f'  +0x{64 + row:03X}  ' + ' '.join(f'{b:02X}' for b in chunk))
    print('--- DataDirectory (opt+96) ---')
    for i in range(min(num_dd, 16)):
        rva, size = struct.unpack_from('<II', d, opt + 96 + i * 8)
        print(f'  DIR[{i:>2}] rva=0x{rva:08X} size=0x{size:X}')
    # 节区表位置
    print(f'--- section table @ opt+opt_size = 0x{opt + opt_size:X} ---')
    for i in range(nsect):
        o = opt + opt_size + i * 40
        name = d[o:o + 8].rstrip(b'\0')
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, o + 8)
        print(f'  {name.decode("latin1"):<9} va=0x{vaddr:08X} vsize=0x{vsize:08X} '
              f'raw=0x{raddr:08X} rsize=0x{rsize:08X}')


if __name__ == '__main__':
    main()
