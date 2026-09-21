"""按显式 RVA 反汇编（用于导出表信息不全或需要精确窗口的场景）。

用法:
    python gm_disraw.py <dll> <tag> <rva1:len1,rva2:len2,...>
示例:
    python gm_disraw.py x.dll t 0x5900:0x120
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm_pe  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gm_out')


def main():
    dll, tag, spec = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(OUT, exist_ok=True)
    pe = gm_pe.Pe(dll)
    for item in spec.split(','):
        rva_s, len_s = item.split(':')
        rva = int(rva_s, 16)
        length = int(len_s, 16)
        off = pe.rva_to_off(rva)
        if off is None:
            # 可能是文件偏移
            off = rva
            pe2 = None
        # objdump 的 --start/stop-address 使用 VA（image_base + RVA）
        base = pe.image_base
        cmd = ['C:\\msys64\\mingw64\\bin\\objdump.exe', '-d', '-M', 'intel',
               f'--start-address={base + rva:#x}', f'--stop-address={base + rva + length:#x}', dll]
        p = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
        path = os.path.join(OUT, f'{tag}.{rva:06X}.dis.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f';; {dll}\n;; rva=0x{rva:X} len=0x{length:X} file_off=0x{(off or 0):X}\n')
            f.write(p.stdout)
        print(f'[ok] 0x{rva:X} -> {path} ({len(p.stdout.splitlines())} lines)')


if __name__ == '__main__':
    main()
