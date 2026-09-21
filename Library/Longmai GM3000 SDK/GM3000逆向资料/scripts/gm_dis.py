"""按导出名批量反汇编（objdump 窗口切片），产物落盘避免控制台编码问题。

用法:
    python gm_dis.py <dll> <tag> [name1,name2,...] [--win 0x300]
        # 不给 name 列表则只反汇编目录附近的全部导出（谨慎，量大）

产物: <本目录>/../disasm/<tag>.<export>.dis.txt
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm_pe  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'disasm')


def main():
    args = sys.argv[1:]
    win = 0x300
    if '--win' in args:
        i = args.index('--win')
        win = int(args[i + 1], 16)
        del args[i:i + 2]
    dll, tag = args[0], args[1]
    names = args[2].split(',') if len(args) > 2 and args[2] else None

    os.makedirs(OUT, exist_ok=True)
    pe = gm_pe.Pe(dll)
    exp = pe.exports()
    by_name = {n: r for _, n, r in exp if r}
    ordered = sorted([(r, n) for n, r in by_name.items()])

    if names is None:
        names = [n for _, n in ordered]

    for i, name in enumerate(names):
        rva = by_name.get(name)
        if rva is None:
            print(f'[skip] {name}: 无 RVA（可能是无名字导出）')
            continue
        va = pe.rva_to_va(rva)
        # 停止地址：下一个导出起始（最多 win）
        stop = va + win
        for r, _n in ordered:
            rva_next = r
            if va < pe.rva_to_va(rva_next) < stop:
                stop = pe.rva_to_va(rva_next)
        cmd = ['C:\\msys64\\mingw64\\bin\\objdump.exe', '-d', '-M', 'intel',
               f'--start-address=0x{va:x}', f'--stop-address=0x{stop:x}', dll]
        p = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
        path = os.path.join(OUT, f'{tag}.{name}.dis.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f';; {dll}\n;; {name} rva=0x{rva:X} va=0x{va:X} stop=0x{stop:X}\n')
            f.write(p.stdout)
        print(f'[ok] {name} -> {path} ({len(p.stdout.splitlines())} lines)')


if __name__ == '__main__':
    main()
