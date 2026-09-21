"""批量推断导出函数的调用约定与参数个数（依据函数末尾 `ret imm16`）。

用法:
    python gm_sig.py <dll> [正则过滤]
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm_pe  # noqa: E402

RET_PAT = re.compile(r'^\s*[0-9a-f]+:\s+c2\s+([0-9a-f]{2})\s+([0-9a-f]{2})\s+ret\s+0x([0-9a-f]+)',
                     re.M)


def main():
    dll = sys.argv[1]
    flt = re.compile(sys.argv[2], re.I) if len(sys.argv) > 2 else None
    pe = gm_pe.Pe(dll)
    exp = [(o, n, r) for o, n, r in pe.exports() if r]
    ordered = sorted(r for _o, _n, r in exp)

    print(f'# {dll}  导出={len(exp)} image_base=0x{pe.image_base:X}')
    for ordinal, name, rva in exp:
        if flt and not flt.search(name):
            continue
        va = pe.rva_to_va(rva)
        # 窗口：到下一个导出起点，最多 0x600
        stop = min([r for r in ordered if r > rva] + [rva + 0x600])
        if stop - rva > 0x600:
            stop = rva + 0x600
        cmd = ['C:\\msys64\\mingw64\\bin\\objdump.exe', '-d', '-M', 'intel',
               f'--start-address={pe.rva_to_va(rva):#x}',
               f'--stop-address={pe.rva_to_va(stop):#x}', dll]
        out = subprocess.run(cmd, capture_output=True, text=True, errors='ignore').stdout
        rets = [int(m.group(3), 16) for m in RET_PAT.finditer(out)]
        # 取窗口内最后一个 ret imm（函数尾部）
        if rets:
            n = rets[-1]
            cc = f'stdcall({n // 4} 参数)'
        else:
            # 无 ret imm：cdecl 或尾调用
            cdecl = len(re.findall(r'\bret\b', out))
            cc = f'cdecl/无清理 (ret 次数={cdecl})'
        print(f'[{ordinal:>4}] 0x{rva:06X} {name:<36} {cc}')


if __name__ == '__main__':
    main()
