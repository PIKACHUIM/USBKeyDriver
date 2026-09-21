"""在 TokenMgr 反汇编里查找「扩展表表项读取 → 寄存器间接调用」的代码序列。

TokenMgr 取回扩展表指针后，通常先
    mov  reg1, ds:<全局>
    mov  reg2, [reg1 + 0x04 + 4*index]
再 call reg2。
本脚本把「包含表项偏移读取」的行连同上下文一起打印出来，便于确认每个槽位
的真实调用点、压栈参数个数与出参寄存器。

用法:
    python tm_find_table.py <tokenmgr.full.dis.txt> [偏移十六进制,...]
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

DEFAULT_OFFS = ['0x04', '0x08', '0x0c', '0x10', '0x14', '0x18', '0x1c', '0x20',
                '0x24', '0x28', '0x2c', '0x30', '0x34', '0x38', '0x3c', '0x40',
                '0x44', '0x48', '0x4c', '0x50']
CALLREG = re.compile(r'\bcall\s+(?:eax|ebx|ecx|edx|esi|edi)\b')


def main():
    path = sys.argv[1]
    offs = sys.argv[2:] or DEFAULT_OFFS
    pat = re.compile(r'\+(' + '|'.join(re.escape(o) for o in offs) + r')\]')

    lines = open(path, 'r', encoding='utf-16', errors='ignore').read().splitlines()
    print(f'# {path} lines={len(lines)} offs={offs}')

    hits = [n for n, l in enumerate(lines) if pat.search(l)]
    print(f'# 命中 {len(hits)} 行')
    for n in hits:
        # 只看「紧随其后 8 行内有寄存器间接 call」的位置
        window = lines[n + 1:n + 9]
        if not any(CALLREG.search(w) for w in window):
            continue
        print(f'\n----- @行{n} -----')
        for k in range(max(0, n - 4), min(len(lines), n + 9)):
            mark = '>>' if k == n else '  '
            print(f'{mark} {lines[k].rstrip()}')


if __name__ == '__main__':
    main()
