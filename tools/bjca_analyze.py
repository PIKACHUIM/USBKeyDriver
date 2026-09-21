#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BJCA USB Key 驱动逆向辅助工具（PE 静态分析）

用法:
    python bjca_analyze.py exports <dll> [过滤关键字]
    python bjca_analyze.py rva <dll> <rva-hex> [长度]        # 按 RVA 转文件偏移并打印十六进制 + 字符串
    python bjca_analyze.py strings <dll> [过滤关键字] [最小长度]
    python bjca_analyze.py guids <dll>                       # 扫描所有 GUID 常量
    python bjca_analyze.py findguid <dll> <guid>             # 定位指定 GUID 并打印邻近 GUID
    python bjca_analyze.py imports <dll>                     # 打印导入 DLL 列表
    python bjca_analyze.py info <dll>                        # 节表 / 镜像基址 / 位数
"""
import re
import struct
import sys


class PE:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        d = self.data
        pe = struct.unpack_from('<I', d, 0x3C)[0]
        assert struct.unpack_from('<I', d, pe)[0] == 0x00004550, 'not a PE file'
        coff = pe + 4
        self.machine = struct.unpack_from('<H', d, coff)[0]
        self.is64 = self.machine == 0x8664
        num_sections = struct.unpack_from('<H', d, coff + 2)[0]
        opt_size = struct.unpack_from('<H', d, coff + 16)[0]
        opt = coff + 20
        self.magic = struct.unpack_from('<H', d, opt)[0]
        # PE32: ImageBase @ opt+28; PE32+: ImageBase @ opt+24
        self.image_base = struct.unpack_from('<Q' if self.is64 else '<I', d,
                                            opt + (24 if self.is64 else 28))[0]
        ddir = opt + (112 if self.is64 else 96)
        self.export_rva, self.export_size = struct.unpack_from('<II', d, ddir)
        self.import_rva, _ = struct.unpack_from('<II', d, ddir + 8)
        self.sections = []
        sec = opt + opt_size
        for i in range(num_sections):
            o = sec + i * 40
            name = d[o:o + 8].rstrip(b'\0').decode('latin1')
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, o + 8)
            # PE 头里存的本就是 RVA（objdump 显示时会加上 ImageBase）
            self.sections.append((name, vaddr, vsize, raddr, rsize))

    def rva2off(self, rva):
        for name, vaddr, vsize, raddr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rva - vaddr + raddr
        return -1

    def off2rva(self, off):
        for name, vaddr, vsize, raddr, rsize in self.sections:
            if raddr <= off < raddr + rsize:
                return off - raddr + vaddr
        return -1

    def exports(self):
        out = []
        if not self.export_rva:
            return out
        o = self.rva2off(self.export_rva)
        name_rva, ord_base, n_funcs, n_names, funcs_rva, names_rva, ords_rva = \
            struct.unpack_from('<IIIIIII', self.data, o + 12)
        fo, no, oo = self.rva2off(funcs_rva), self.rva2off(names_rva), self.rva2off(ords_rva)
        for i in range(n_names):
            nr = struct.unpack_from('<I', self.data, no + i * 4)[0]
            p = self.rva2off(nr)
            end = self.data.index(b'\0', p)
            nm = self.data[p:end].decode('latin1')
            ordv = struct.unpack_from('<H', self.data, oo + i * 2)[0]
            rva = struct.unpack_from('<I', self.data, fo + ordv * 4)[0]
            fwd = None
            if self.export_rva <= rva < self.export_rva + self.export_size:
                fp = self.rva2off(rva)
                fe = self.data.index(b'\0', fp)
                fwd = self.data[fp:fe].decode('latin1')
            out.append((ordv + ord_base, nm, rva, fwd))
        return sorted(out, key=lambda x: x[1].lower())

    def imports(self):
        res = []
        if not self.import_rva:
            return res
        o = self.rva2off(self.import_rva)
        while True:
            if self.data[o:o + 20] == b'\0' * 20:
                break
            nr = struct.unpack_from('<I', self.data, o + 12)[0]
            p = self.rva2off(nr)
            end = self.data.index(b'\0', p)
            res.append(self.data[p:end].decode('latin1'))
            o += 20
        return res


def show_exports(pe, filt=''):
    ex = pe.exports()
    print('%s  64=%s  exports=%d' % (pe.path, pe.is64, len(ex)))
    for ordv, nm, rva, fwd in ex:
        if filt and not re.search(filt, nm, re.I):
            continue
        if fwd:
            print('%4d  0x%08X  %-40s -> %s' % (ordv, rva, nm, fwd))
        else:
            print('%4d  0x%08X  %s' % (ordv, rva, nm))


def hexdump(data, base):
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = ' '.join('%02X' % b for b in chunk)
        tx = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print('%08X  %-47s  %s' % (base + i, hx, tx))


def safe(s):
    """把不可编码字符转义，避免 GBK 控制台报错。"""
    return s.encode('ascii', 'backslashreplace').decode('ascii')


def show_rva(pe, rva, length=256):
    off = pe.rva2off(rva)
    if off < 0:
        print('RVA 0x%X 无法解析到文件偏移' % rva)
        return
    print('RVA 0x%X -> offset 0x%X' % (rva, off))
    hexdump(pe.data[off:off + length], rva)
    print()
    print('as utf-16le:', safe(repr(pe.data[off:off + length].decode('utf-16le', 'ignore')[:120])))
    print('as ascii   :', safe(repr(pe.data[off:off + length].decode('latin1', 'ignore')[:120])))


def show_strings(pe, filt='', minlen=6):
    d = pe.data
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, d):
        s = m.group().decode('latin1')
        if filt and not re.search(filt, s, re.I):
            continue
        print('0x%08X  %s' % (pe.off2rva(m.start()), s))
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % minlen, d):
        s = m.group().decode('utf-16le', 'ignore')
        if filt and not re.search(filt, s, re.I):
            continue
        print('0x%08X  [w] %s' % (pe.off2rva(m.start()), s))


def parse_guid(data, o):
    a, b, c = struct.unpack_from('<IHH', data, o)
    e1 = struct.unpack_from('>H', data, o + 8)[0]
    e2 = struct.unpack_from('>I', data, o + 10)[0]
    e3 = struct.unpack_from('>I', data, o + 14)[0]
    return '{%08X-%04X-%04X-%04X-%04X%08X}' % (a, b, c, e1, e2, e3)


def guid_bytes(s):
    s = s.strip('{}')
    a, b, c, e1, e2 = s.split('-')
    return struct.pack('<IHH', int(a, 16), int(b, 16), int(c, 16)) + bytes.fromhex(e1 + e2)


def show_guids(pe):
    d = pe.data
    seen = set()
    pat = re.compile(rb'.{4}\x00\x00.{6}\x00\x00.{6}\x00\x00.{6}(?:\x00|.)', re.S)
    # 更可靠的方式: 扫描 16 字节窗口, 校验 Data3 高字节为 0x00/0x40/0x80 (版本位)
    for i in range(0, len(d) - 16):
        c = struct.unpack_from('<H', d, i + 6)[0]
        if (c & 0xF000) not in (0x0000, 0x4000, 0x8000, 0xA000, 0xB000, 0xC000):
            continue
        if d[i + 8] == d[i + 9] == 0:
            continue
        g = parse_guid(d, i)
        if g in seen:
            continue
        seen.add(g)
        print('0x%08X  %s' % (pe.off2rva(i), g))


def find_guid(pe, gs):
    target = guid_bytes(gs)
    d = pe.data
    for m in re.finditer(re.escape(target), d):
        o = m.start()
        print('found at 0x%08X (RVA 0x%08X)' % (o, pe.off2rva(o)))
        start = max(0, (o - 0x40) & ~0xF)
        for off in range(start, o + 0x50, 0x10):
            print('  0x%08X  %s' % (pe.off2rva(off), parse_guid(d, off)))


def arg_counts(pe, objdump=r'C:\msys64\mingw64\bin\objdump.exe', only=''):
    """
    对每个导出函数，反汇编后取「第一条 ret imm16」推算 __stdcall 参数个数。
    这是判定 COM/x86 接口真实 ABI 最可靠的方法（比 IDL 更可信）。
    输出: 名称  RVA  参数个数  字节数
    """
    import subprocess
    ex = sorted(pe.exports(), key=lambda x: x[2])
    proc = subprocess.run([objdump, '-d', pe.path], capture_output=True, text=True, errors='replace')
    instr = {}
    for line in proc.stdout.splitlines():
        m = re.match(r'^\s*([0-9a-f]{6,})\s*:\s*(?:[0-9a-f]{2} )+\s*\t?([a-z].*)$', line)
        if not m:
            m = re.match(r'^\s*([0-9a-f]{6,}):\t[0-9a-f ]+\t(.+)$', line)
        if m:
            instr[int(m.group(1), 16)] = m.group(2).strip()
    # objdump 反汇编里的地址 = 镜像基址 + RVA
    base = pe.image_base
    addrs = [a for _, _, a, _ in ex]
    for i, (ordv, name, rva, fwd) in enumerate(ex):
        if only and not re.search(only, name, re.I):
            continue
        if fwd:
            print('%4d  0x%08X  %-34s (转发导出 -> %s)' % (ordv, rva, name, fwd))
            continue
        limit = addrs[i + 1] if i + 1 < len(addrs) else rva + 0x2000
        # 函数体内可能混入 SEH 脚手架里的裸 ret（如 mov $addr,%eax; ret），
        # 因此取「带 imm 的 ret」中出现次数最多的那个作为真实栈清理值。
        tally = {}
        bare = 0
        for a in sorted(k for k in instr if base + rva <= k < base + limit):
            t = instr[a]
            if t in ('ret', 'retq'):
                bare += 1
            elif t.startswith('ret ') or t.startswith('retq '):
                v = t.split()[1].strip().lstrip('$')
                try:
                    imm = int(v, 16) if v.startswith('0x') else int(v)
                except ValueError:
                    continue
                tally[imm] = tally.get(imm, 0) + 1
        if tally:
            imm = max(tally.items(), key=lambda kv: (kv[1], kv[0]))[0]
            print('%4d  0x%08X  %-34s args=%d  (ret $0x%X, 裸ret=%d)' % (ordv, rva, name, imm // 4, imm, bare))
        else:
            print('%4d  0x%08X  %-34s args=%d  (仅裸 ret)' % (ordv, rva, name, 0 if bare else 0))


def show_info(pe):
    print('file      :', pe.path)
    print('is64      :', pe.is64)
    print('imagebase : 0x%X' % pe.image_base)
    print('sections  :')
    for name, vaddr, vsize, raddr, rsize in pe.sections:
        print('  %-8s VA=0x%08X VS=%9d RAW=0x%08X RS=%9d' % (name, vaddr, vsize, raddr, rsize))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    cmd, path = sys.argv[1], sys.argv[2]
    pe = PE(path)
    if cmd == 'exports':
        show_exports(pe, sys.argv[3] if len(sys.argv) > 3 else '')
    elif cmd == 'rva':
        show_rva(pe, int(sys.argv[3], 16), int(sys.argv[4]) if len(sys.argv) > 4 else 256)
    elif cmd == 'strings':
        show_strings(pe, sys.argv[3] if len(sys.argv) > 3 else '',
                     int(sys.argv[4]) if len(sys.argv) > 4 else 6)
    elif cmd == 'guids':
        show_guids(pe)
    elif cmd == 'findguid':
        find_guid(pe, sys.argv[3])
    elif cmd == 'argcounts':
        arg_counts(pe, only=sys.argv[3] if len(sys.argv) > 3 else '')
    elif cmd == 'imports':
        for n in pe.imports():
            print(n)
    elif cmd == 'info':
        show_info(pe)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
