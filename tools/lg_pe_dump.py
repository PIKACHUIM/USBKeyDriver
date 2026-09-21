"""Linguo PE 分析工具：从 objdump -p 输出中提取导出表 / 导入表。

用法:
    python lg_pe_dump.py exports <objdump.txt>
    python lg_pe_dump.py imports <objdump.txt>
"""
import re
import sys


def parse_exports(path):
    """解析导出名表。objdump 把「地址表」和「名字表」分别列出，
    名字表行形如:  [   0] +base[   1]  0000 CPAcquireContext
    """
    rows = []
    pat_name = re.compile(r'^\s*\[\s*(\d+)\]\s*\+base\[\s*(\d+)\]\s+([0-9a-fA-F]+)\s+(\S+)\s*$')
    pat_addr = re.compile(r'^\s*\[\s*(\d+)\]\s*\+base\[\s*(\d+)\]\s+([0-9a-fA-F]+)\s+(.*)$')
    for line in open(path, encoding='utf-8', errors='ignore'):
        if 'Export RVA' in line:
            continue
        m = pat_name.match(line)
        if m:
            ordinal = int(m.group(2))
            rows.append((ordinal, m.group(4)))
    return rows


def parse_imports(path):
    """解析导入表：DLL Name: xxx.dll 以及 每个函数的 ordinal/hint/name。

    objdump 行格式:  00052044  <none>  0049  CertGetNameStringA
    """
    dlls = []
    cur = None
    pat_dll = re.compile(r'^\s*DLL Name:\s*(\S+)\s*$', re.I)
    pat_imp = re.compile(r'^\s*([0-9a-fA-F]{6,8})\s+(<none>|[0-9a-fA-F]+)\s+(<none>|[0-9a-fA-F]+)\s*(.*)$')
    for line in open(path, encoding='utf-8', errors='ignore'):
        m = pat_dll.match(line)
        if m:
            cur = {'dll': m.group(1), 'funcs': []}
            dlls.append(cur)
            continue
        m = pat_imp.match(line)
        if m and cur is not None:
            name = m.group(4).strip()
            if not name:
                name = f'<ordinal {m.group(2)}>'
            cur['funcs'].append((name, m.group(1)))
    return dlls


def main():
    mode, path = sys.argv[1], sys.argv[2]
    if mode == 'exports':
        rows = parse_exports(path)
        print(f'# {path}  导出数量: {len(rows)}')
        for ordinal, name in rows:
            print(f'{ordinal}\t{name}')
    else:
        for d in parse_imports(path):
            print(f'== {d["dll"]}  ({len(d["funcs"])} 个)')
            for name, rva in d['funcs']:
                print(f'   {name or "<ordinal>"}\t{rva}')


if __name__ == '__main__':
    main()
