"""检索 TokenMgr 中「通过扩展函数表调用」的调用点，用于确定 M_* 的参数约定。

做法：对 TokenMgr.dll 反汇编，找出形如 `mov reg,[reg+0xNN]`（NN = 扩展表偏移）
随后 `call reg` 的片段，并打印上下文（含 call 之后的 add esp,N）。

用法:
    python tm_find_ext_calls.py <tokenmgr.dll> [--out file]
"""
import os
import re
import subprocess
import sys

OBJDUMP = r'C:\msys64\mingw64\bin\objdump.exe'
# 扩展表函数指针偏移：0x04 + 4*index
IDX_TO_OFF = {i: 0x04 + 4 * i for i in range(20)}
OFF_TO_IDX = {v: k for k, v in IDX_TO_OFF.items()}
NAMES = {
    0: 'M_GetUserInfo', 1: 'M_GetExtFunctionList', 2: 'M_UnblockUserPin', 3: 'M_SetTokenLabel',
    4: 'M_FormatToken', 5: 'M_CreateContainer', 6: 'M_DeleteContainer', 7: 'M_EnumContainer',
    8: 'M_GetContainerInfo', 9: 'M_WriteSectors', 10: 'M_ReadSectors', 11: 'M_ReloadObjects',
    12: 'M_CreateFile', 13: 'M_DeleteFile', 14: 'M_WriteFile', 15: 'M_ReadFile',
    16: 'M_GetFileInfo', 17: 'M_GetApplicationInfo', 18: 'M_SetEnumString',
    19: 'M_ConstructMSCMapFiles',
}

LOAD_PAT = re.compile(r'mov\s+(e[a-z]{2}),DWORD PTR \[(e[a-z]{2})\+(0x[0-9a-f]+)\]')
CALL_PAT = re.compile(r'call\s+(e[a-z]{2})')
ADDESP_PAT = re.compile(r'add\s+esp,(0x[0-9a-f]+)')


def main():
    dll = sys.argv[1]
    out = None
    if '--out' in sys.argv:
        i = sys.argv.index('--out')
        out = sys.argv[i + 1]

    p = subprocess.run([OBJDUMP, '-d', '-M', 'intel', dll],
                       capture_output=True, text=True, errors='ignore')
    lines = p.stdout.splitlines()
    print(f'# {dll}  反汇编行数={len(lines)}')

    buf = []
    for i, line in enumerate(lines):
        m = LOAD_PAT.search(line)
        if not m:
            continue
        reg_dst, reg_src, off = m.group(1), m.group(2), int(m.group(3), 16)
        if off not in OFF_TO_IDX:
            continue
        # 在接下来 20 行内找 call <reg_dst>
        window = lines[i:i + 24]
        call_line = None
        add_line = None
        for k, w in enumerate(window[1:], 1):
            c = CALL_PAT.search(w)
            if c and c.group(1) == reg_dst:
                call_line = w
                # 再往后找 add esp,N
                for w2 in lines[i + k + 1:i + k + 8]:
                    a = ADDESP_PAT.search(w2)
                    if a:
                        add_line = a.group(1)
                        break
                break
        idx = OFF_TO_IDX[off]
        if call_line:
            buf.append(f'== slot[{idx}] {NAMES[idx]}  (extTable+0x{off:02X})  '
                       f'参数清理={add_line or "无(可能 cdecl/或非本处)"}')
            for w in window:
                buf.append('   ' + w.strip())
            buf.append('')
        else:
            buf.append(f'-- slot[{idx}] {NAMES[idx]}  (extTable+0x{off:02X})  '
                       f'未见紧邻 call {reg_dst}（可能仅加载未调用）')

    text = '\n'.join(buf)
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'written {len(buf)} lines -> {out}')
    else:
        print(text)


if __name__ == '__main__':
    main()
