"""定位 TokenMgr 中对「PKCS#11 扩展表」各槽位的直接调用点，并打印上下文。

背景：TokenMgr 从 gm3000_pkcs11.dll!M_GetExtFunctionList 取回扩展表后，
把表首地址缓存在某处，之后按 `call DWORD PTR [reg+offset]` 形式调用，
其中 offset = 0x04 + index*4。

用法:
    python tm_ext_sites.py <tokenmgr.full.dis.txt> <index1> <index2> ...
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

# TokenMgr 常用 eax/ebx/ecx/edx/esi/edi/ebp 间接调用（勿漏 esi/edi/ebp）
CALL = re.compile(r'call\s+DWORD PTR \[e(?:ax|bx|cx|dx|si|di|bp)\+0x([0-9a-f]{2})\]')
FUNC = re.compile(r'^([0-9a-f]{8}) <.*>:')


def load(path):
    for enc in ('utf-16', 'utf-8', 'latin1'):
        try:
            with open(path, 'r', encoding=enc, errors='ignore') as f:
                return f.read().splitlines()
        except Exception:
            continue
    return []


def main():
    path = sys.argv[1]
    wanted = [int(x, 0) for x in sys.argv[2:]]
    offs = {0x04 + i * 4: i for i in wanted}

    lines = load(path)
    print(f'# {path} lines={len(lines)} 关注下标={wanted}')

    # 记录每个地址所属的最近函数头
    cur_func = None
    for n, line in enumerate(lines):
        m = FUNC.match(line.strip())
        if m:
            cur_func = m.group(1)
        mm = CALL.search(line)
        if not mm:
            continue
        off = int(mm.group(1), 16)
        if off not in offs:
            continue
        idx = offs[off]
        print(f'\n===== slot[{idx}] off=+0x{off:02X} @{cur_func} 行{n} =====')
        lo = max(0, n - 26)
        hi = min(len(lines), n + 10)
        for k in range(lo, hi):
            mark = '>>' if k == n else '  '
            print(f'{mark} {lines[k].rstrip()}')


if __name__ == '__main__':
    main()
