"""判定 Longmai SKF（mtoken_gm3000.dll）各导出所要求的「句柄类型」。

背景
----
本厂商的 SKF 会校验句柄种类：传错种类直接返回 SAR_INVALIDHANDLEERR = 0xA000005。
（报告 §九-5 已实测：SKF_GetPINInfo 传设备句柄即返回 0xA000005，必须传应用句柄。）

判定方法
--------
反汇编每个导出函数开头的若干字节，提取两类指纹：
  1) 句柄解析调用的类型标签常量（形如 0x100404xx / 0x100405xx）：
     同一标签 = 同一种句柄类型；
  2) ret N —— 参数个数。
再以两个已知事实为锚点校准：
  · SKF_GetDevInfo  —— 必须是设备句柄(HDEV)
  · SKF_GetPINInfo  —— 必须是应用句柄(HAPPLICATION)
其余函数按「与哪个锚点共用同一标签」归类。

用法:
    python skf_handles.py <mtoken_gm3000.dll>
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gm_pe  # noqa: E402

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

OBJDUMP = r'C:\msys64\mingw64\bin\objdump.exe'
TAG = re.compile(r'0x(100[0-9a-f]{5})')
RET = re.compile(r'\bret\s+0x([0-9a-f]+)')
CALL = re.compile(r'\bcall\s+0x([0-9a-f]+)')
HEAD = 0x140


def head_disasm(dll, base, rva):
    cmd = [OBJDUMP, '-d', '-M', 'intel',
           '--start-address=%#x' % (base + rva),
           '--stop-address=%#x' % (base + rva + HEAD), dll]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode('utf-8', 'ignore')
    except Exception:
        return []
    return [l.rstrip() for l in out.splitlines() if re.match(r'^\s*[0-9a-f]{8}:', l)]


def main():
    dll = sys.argv[1]
    pe = gm_pe.Pe(dll)
    base = pe.image_base

    exps = pe.exports()
    targets = [(o, n, r) for (o, n, r) in exps if n.startswith('SKF_') and r]
    print('# %s  image_base=0x%X  SKF exports=%d\n' % (dll, base, len(targets)))

    rows = []
    for ordinal, name, rva in targets:
        lines = head_disasm(dll, base, rva)
        if not lines:
            continue
        tags = []
        resolver = None
        nargs = None
        for l in lines:
            m = TAG.search(l)
            if m and m.group(1) not in tags:
                tags.append(m.group(1))
            c = CALL.search(l)
            if c and resolver is None:
                resolver = c.group(1)
            r = RET.search(l)
            if r and nargs is None:
                nargs = int(r.group(1), 16) // 4
        rows.append((name, ordinal, rva, nargs, tags, resolver))

    print('NAME'.ljust(36) + 'ORD'.rjust(5) + 'ARGS'.rjust(6) + '  '
          + 'TYPE-TAG(hint of handle kind)'.ljust(30) + 'FIRST-CALL')
    for name, ordinal, rva, nargs, tags, resolver in rows:
        tag_s = ','.join('0x' + t for t in tags[:2]) if tags else '-'
        print(name.ljust(36) + str(ordinal).rjust(5) + str(nargs).rjust(6) + '  '
              + tag_s.ljust(30) + (resolver or '-'))


if __name__ == '__main__':
    main()
