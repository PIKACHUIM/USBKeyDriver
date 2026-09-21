"""GM3000（龙脉 Longmai）PE 分析工具（纯 Python，无第三方依赖）。

用法:
    python gm_pe.py info    <pe>            # 头部/节区/位数
    python gm_pe.py exports <pe>            # 导出表（序号 + 名字 + RVA）
    python gm_pe.py imports <pe>            # 导入表（DLL + 函数）
    python gm_pe.py strings <pe> [正则] [--out f]
    python gm_pe.py findva  <pe> <十六进制VA>   # VA -> 文件偏移 / 节区
    python gm_pe.py xref    <pe> <十六进制VA> [--kind data|call]
    python gm_pe.py delphi  <pe>            # Delphi/BCB 特征探测

设计说明：为规避 PowerShell 对 `$` 的转义问题，所有分析一律通过脚本落盘，
避免在命令行里使用管道与变量。
"""
import os
import re
import struct
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


# ---------------------------------------------------------------- PE 基础

class Pe:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError('不是 PE 文件')
        e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            raise ValueError('缺少 PE 签名')
        self.nt = e_lfanew
        coff = e_lfanew + 4
        self.machine, self.nsections, self.timestamp = struct.unpack_from('<HHI', d, coff)
        opt_size = struct.unpack_from('<H', d, coff + 16)[0]
        self.opt_off = coff + 20
        self.magic = struct.unpack_from('<H', d, self.opt_off)[0]
        self.is64 = self.magic == 0x20B
        self.is_rom = self.magic == 0x107
        if self.is64:
            self.image_base = struct.unpack_from('<Q', d, self.opt_off + 24)[0]
            ndd_off = self.opt_off + 112
        else:
            self.image_base = struct.unpack_from('<I', d, self.opt_off + 28)[0]
            ndd_off = self.opt_off + 96
        self.subsystem = struct.unpack_from('<H', d, self.opt_off + 68)[0]
        # 目录数量字段紧随其后（PE32 @+92，PE32+ @+108），数据目录起始即 ndd_off
        self.ndir = struct.unpack_from('<I', d, ndd_off - 4)[0]
        # 节区
        sec_off = self.opt_off + opt_size
        self.sections = []
        for i in range(self.nsections):
            o = sec_off + i * 40
            name = d[o:o + 8].rstrip(b'\0').decode('latin1')
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, o + 8)
            self.sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                                      rsize=rsize, raddr=raddr))
        # 数据目录（按文件偏移读取，注意不是 RVA）
        self.dirs = []
        for i in range(16):
            rva, size = struct.unpack_from('<II', d, ndd_off + i * 8)
            self.dirs.append((rva, size))

    def rva_to_off(self, rva):
        for s in self.sections:
            span = max(s['vsize'], s['rsize'])
            if s['vaddr'] <= rva < s['vaddr'] + span:
                return s['raddr'] + (rva - s['vaddr'])
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s['raddr'] <= off < s['raddr'] + s['rsize']:
                return s['vaddr'] + (off - s['raddr'])
        return None

    def rva_to_va(self, rva):
        return self.image_base + rva

    def va_to_rva(self, va):
        return va - self.image_base

    def read(self, rva, n):
        off = self.rva_to_off(rva)
        if off is None:
            return b''
        return self.data[off:off + n]

    def cstr(self, rva, limit=512):
        off = self.rva_to_off(rva)
        if off is None:
            return ''
        end = self.data.find(b'\0', off, off + limit)
        if end < 0:
            end = off + limit
        return self.data[off:end].decode('latin1')

    # ---- 导出表 ----
    def exports(self):
        if not self.dirs[0][0]:
            return []
        rva, _size = self.dirs[0]
        raw = self.read(rva, 40)
        if len(raw) < 40:
            return []
        base, nfunc, nname = struct.unpack_from('<III', raw, 16)
        addr_funcs, addr_names, addr_ords = struct.unpack_from('<III', raw, 28)
        # 函数地址表（按序号）——先建索引，便于补全无名字导出
        fn = self.read(addr_funcs, nfunc * 4)
        rva_by_index = {}
        for i in range(nfunc):
            if len(fn) >= (i + 1) * 4:
                rva_by_index[i] = struct.unpack_from('<I', fn, i * 4)[0]

        names = self.read(addr_names, nname * 4)
        ords = self.read(addr_ords, nname * 2)
        out = []
        used_index = set()
        for i in range(nname):
            if len(names) < (i + 1) * 4 or len(ords) < (i + 1) * 2:
                break
            name_rva = struct.unpack_from('<I', names, i * 4)[0]
            # AddressOfNameOrdinals[i] 保存的是「导出地址表下标」，真实序号 = base + 下标。
            # （早期版本在这里多减了 base，导致反汇编目标整体错位一个函数。）
            eat_index = struct.unpack_from('<H', ords, i * 2)[0]
            used_index.add(eat_index)
            out.append((base + eat_index, self.cstr(name_rva), rva_by_index.get(eat_index)))
        for idx in sorted(rva_by_index):
            if idx not in used_index:
                out.append((idx + base, f'#{idx + base}', rva_by_index[idx]))
        return sorted(out, key=lambda x: x[0])

    # ---- 导入表 ----
    def imports(self):
        if not self.dirs[1][0]:
            return []
        rva = self.dirs[1][0]
        out = []
        i = 0
        while i < 4096:
            ent = self.read(rva + i * 20, 20)
            if len(ent) < 20:
                break
            oft, _t, _fc, name_rva, first_thunk = struct.unpack_from('<IIIII', ent, 0)
            if name_rva == 0 and first_thunk == 0:
                break
            dll = self.cstr(name_rva)
            thunk_rva = oft or first_thunk
            funcs = []
            j = 0
            while True:
                size = 8 if self.is64 else 4
                buf = self.read(thunk_rva + j * size, size)
                if len(buf) < size:
                    break
                t = struct.unpack_from('<Q' if self.is64 else '<I', buf, 0)[0]
                if not t:
                    break
                if t & (1 << (63 if self.is64 else 31)):
                    funcs.append(f'<ordinal {t & 0xFFFF}>')
                else:
                    # Hint(2) + Name
                    funcs.append(self.cstr(t + 2))
                j += 1
            out.append((dll, funcs))
            i += 1
        return out


# ---------------------------------------------------------------- 字符串

ASCII_PAT = re.compile(rb'[\x20-\x7e]{4,}')
GBK_PAT = re.compile(rb'(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){4,}')
UTF16_PAT = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def extract_strings(pe):
    d = pe.data
    out = []
    for m in ASCII_PAT.finditer(d):
        out.append((m.start(), m.group().decode('ascii', 'ignore')))
    for m in GBK_PAT.finditer(d):
        raw = m.group()
        if not any(b >= 0x81 for b in raw):
            continue
        try:
            s = raw.decode('gbk')
        except Exception:
            continue
        if any('\u4e00' <= ch <= '\u9fff' for ch in s):
            out.append((m.start(), s))
    for m in UTF16_PAT.finditer(d):
        out.append((m.start(), m.group().decode('utf-16-le', 'ignore')))
    seen = set()
    uniq = []
    for off, s in out:
        if s in seen:
            continue
        seen.add(s)
        uniq.append((off, s))
    return uniq


# ---------------------------------------------------------------- 反汇编辅助

def objdump_path():
    for c in (r'C:\msys64\mingw64\bin\objdump.exe', r'C:\msys64\usr\bin\objdump.exe'):
        if os.path.exists(c):
            return c
    return 'objdump'


def run_objdump(pe, start=None, stop=None):
    import subprocess
    cmd = [objdump_path(), '-d', '-M', 'intel']
    if start is not None:
        cmd.append(f'--start-address=0x{start:x}')
    if stop is not None:
        cmd.append(f'--stop-address=0x{stop:x}')
    cmd.append(pe.path)
    p = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
    return p.stdout


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    mode = sys.argv[1]
    path = sys.argv[2]
    pe = Pe(path)
    rest = sys.argv[3:]

    out = None
    if '--out' in rest:
        i = rest.index('--out')
        out = rest[i + 1]
        del rest[i:i + 2]
    kw = rest[0] if rest else None

    lines = []
    if mode == 'info':
        lines.append(f'== {path}')
        lines.append(f'machine=0x{pe.machine:04X} magic=0x{pe.magic:X} '
                     f'{"x64" if pe.is64 else "x86"} image_base=0x{pe.image_base:X} '
                     f'sections={pe.nsections} subsystem={pe.subsystem}')
        for s in pe.sections:
            lines.append(f'  {s["name"]:<9} va=0x{s["vaddr"]:08X} vsize=0x{s["vsize"]:08X} '
                         f'raw=0x{s["raddr"]:08X} rsize=0x{s["rsize"]:08X}')
        labels = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Reloc',
                  'Debug', 'Arch', 'Global', 'TLS', 'LoadCfg', 'BoundImp', 'IAT',
                  'DelayImp', 'CLR', '<15>']
        for idx, (rva, size) in enumerate(pe.dirs):
            if rva or size:
                lines.append(f'  DIR[{idx:>2}] {labels[idx]:<9} rva=0x{rva:08X} size=0x{size:X}')
        lines.append(f'  NumberOfRvaAndSizes={pe.ndir}')
    elif mode == 'exports':
        exp = pe.exports()
        lines.append(f'# {path} 导出数量={len(exp)}')
        for ordinal, name, rva in exp:
            if rva is None:
                lines.append(f'[{ordinal:>4}] {name}')
            else:
                lines.append(f'[{ordinal:>4}] {name:<40} rva=0x{rva:08X}')
    elif mode == 'imports':
        for dll, funcs in pe.imports():
            lines.append(f'== {dll} ({len(funcs)})')
            for f in funcs:
                lines.append(f'   {f}')
    elif mode == 'strings':
        pat = re.compile(kw, re.I) if kw else None
        for off, s in extract_strings(pe):
            if pat is not None and not pat.search(s):
                continue
            rva = pe.off_to_rva(off)
            if rva is None:
                continue
            lines.append(f'0x{pe.rva_to_va(rva):08X}\t0x{off:08X}\t{s}')
    elif mode == 'findva':
        va = int(rest[0], 16)
        rva = pe.va_to_rva(va)
        off = pe.rva_to_off(rva)
        sec = next((s['name'] for s in pe.sections
                    if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsize'])), '?')
        lines.append(f'VA=0x{va:X} RVA=0x{rva:X} off=0x{off:X} section={sec}')
    elif mode == 'xref':
        va = int(rest[0], 16)
        raw = struct.pack('<I', va)
        hits = []
        for m in re.finditer(re.escape(raw), pe.data):
            rva = pe.off_to_rva(m.start())
            if rva is None:
                continue
            if pe.rva_to_off(rva) is None:
                continue
            hits.append((m.start(), rva))
        lines.append(f'# 立即数 0x{va:X} 出现 {len(hits)} 次')
        for off, rva in hits[:400]:
            lines.append(f'0x{pe.rva_to_va(rva):08X}\t(file 0x{off:X})')
    elif mode == 'delphi':
        d = pe.data
        marks = {
            'Borland/Delphi RTTI  "TForm"': b'TForm',
            'Delphi "System.pas"': b'System.pas',
            'Delphi "SysUtils"': b'SysUtils',
            'BCB "VCL"': b'Borland.Vcl',
            'MFC (VC)': b'MFC',
            'MSVC CRT': b'MSVCR',
            'Delphi __turboFloat': b'__turboFloat',
        }
        for k, v in marks.items():
            lines.append(f'{k:<32} {"YES" if v in d else "-"}')
    else:
        print(__doc__)
        return

    text = '\n'.join(lines)
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'written {len(lines)} lines -> {out}')
    else:
        print(text)


if __name__ == '__main__':
    main()
