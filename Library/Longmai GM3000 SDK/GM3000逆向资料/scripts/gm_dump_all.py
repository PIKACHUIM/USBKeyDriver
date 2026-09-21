"""批量落盘 GM3000 全部二进制的情报（导出/导入/特征/关键字符串）。

产物目录: <本目录>/../disasm/
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm_pe  # noqa: E402

SDK = r'g:\Codes\USBKeyDriver\Library\Longmai GM3000 SDK'
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'disasm')

TARGETS = [
    ('admin',      os.path.join(SDK, r'GM3000_2.2.19\GM3000Admin.exe')),
    ('pkcs11_2219', os.path.join(SDK, r'GM3000_2.2.19\gm3000_pkcs11.dll')),
    ('skf_2219',   os.path.join(SDK, r'GM3000_2.2.19\mtoken_gm3000.dll.old')),
    ('skf_2016',   os.path.join(SDK, r'GM3000_2.2.19\mtoken_gm3000.dll')),
    ('tokenmgr_2219', os.path.join(SDK, r'GM3000_2.2.19\tokenmgr.dll')),
    ('pkcs11_2110', os.path.join(SDK, r'GM3000_2.1.1.0\gm3000_pkcs11.dll')),
    ('skf_2110',   os.path.join(SDK, r'GM3000_2.1.1.0\mtoken_GM.dll')),
    ('tokenmgr_2110', os.path.join(SDK, r'GM3000_2.1.1.0\TokenMgr.dll')),
    ('pkimgr',     os.path.join(SDK, r'GM3000_2.1.1.0\GM3000PKIMgr.exe')),
    ('mon',        os.path.join(SDK, r'GM3000_2.1.1.0\GM3000Mon.exe')),
]

# 关键线索关键词（覆盖 DLL 名 / 设备 / 驱动路径 / 命令）
KW = (r'GM3000|mtoken|tokenmgr|Longmai|longmai|GM\d|\.dll|\.sys|\\\\\.\\|'
      r'USBSTOR|CDROM|Longmai|SetupDi|CreateFile|DeviceIoControl|SCARD|winscard|'
      r'admin|Admin|PIN|PUK|init|Init|reset|Reset|unlock|Unlock|Change|%s|%d|%x')


def main():
    os.makedirs(OUT, exist_ok=True)
    summary = []
    for tag, path in TARGETS:
        if not os.path.exists(path):
            summary.append(f'{tag}: MISSING {path}')
            continue
        pe = gm_pe.Pe(path)
        size = os.path.getsize(path)
        summary.append(f'{tag}: {os.path.basename(path)} size={size} '
                       f'{"x64" if pe.is64 else "x86"} sections={[s["name"] for s in pe.sections]}')

        with open(os.path.join(OUT, f'{tag}.info.txt'), 'w', encoding='utf-8') as f:
            f.write(f'== {path}\nsize={size}\n')
            f.write(f'machine=0x{pe.machine:04X} magic=0x{pe.magic:X} '
                    f'{"x64" if pe.is64 else "x86"} image_base=0x{pe.image_base:X}\n')
            for s in pe.sections:
                f.write(f'  {s["name"]:<9} va=0x{s["vaddr"]:08X} vsize=0x{s["vsize"]:08X} '
                        f'raw=0x{s["raddr"]:08X} rsize=0x{s["rsize"]:08X}\n')

        with open(os.path.join(OUT, f'{tag}.exports.txt'), 'w', encoding='utf-8') as f:
            exp = pe.exports()
            f.write(f'# 导出数量={len(exp)}\n')
            for ordinal, name, rva in exp:
                f.write(f'[{ordinal:>4}] {name}' + (f'\trva=0x{rva:08X}' if rva else '') + '\n')

        with open(os.path.join(OUT, f'{tag}.imports.txt'), 'w', encoding='utf-8') as f:
            for dll, funcs in pe.imports():
                f.write(f'== {dll} ({len(funcs)})\n')
                for fn in funcs:
                    f.write(f'   {fn}\n')

        # 全量字符串（无过滤，供后续 grep）+ 关键字符串
        allstr = gm_pe.extract_strings(pe)
        with open(os.path.join(OUT, f'{tag}.strings.txt'), 'w', encoding='utf-8') as f:
            for off, s in allstr:
                rva = pe.off_to_rva(off)
                va = pe.rva_to_va(rva) if rva is not None else 0
                f.write(f'0x{va:08X}\t{s}\n')
        pat = re.compile(KW, re.I)
        with open(os.path.join(OUT, f'{tag}.kw.txt'), 'w', encoding='utf-8') as f:
            for off, s in allstr:
                if len(s) < 4:
                    continue
                if not pat.search(s):
                    continue
                rva = pe.off_to_rva(off)
                va = pe.rva_to_va(rva) if rva is not None else 0
                f.write(f'0x{va:08X}\t{s}\n')

        print(f'[ok] {tag} exports={len(pe.exports())} imports_dlls={len(pe.imports())} '
              f'strings={len(allstr)}')

    with open(os.path.join(OUT, 'summary.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(summary) + '\n')
    print('summary ->', os.path.join(OUT, 'summary.txt'))


if __name__ == '__main__':
    main()
