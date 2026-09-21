"""在二进制里按多种编码查找字符串，并打印邻近语境的字符串。

Borland/ANSI 程序里中文界面文本可能以 GBK 或 UTF-16LE 存放，
因此对同一关键词两种编码都试，并把命中处附近的可见字符串一并列出，
便于推断界面文案的状态映射（例如 "已锁定" / "未锁定" 的分支）。

用法:
    python gm_strfind.py <file> 关键词1 关键词2 ...
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

STRLIT = re.compile(rb'[\x20-\x7e\x80-\xff]{4,}')


def near_strings(data, pos, span=600):
    lo = max(0, pos - span)
    hi = min(len(data), pos + span)
    out = []
    for m in STRLIT.finditer(data, lo, hi):
        raw = m.group()
        for enc in ('gbk', 'latin1'):
            try:
                s = raw.decode(enc)
                break
            except Exception:
                s = None
        if s:
            out.append(s.strip())
    return out[:14]


def main():
    path = sys.argv[1]
    keys = sys.argv[2:]
    data = open(path, 'rb').read()
    print(f'# {path}  size={len(data)}')
    for k in keys:
        for enc, label in (('gbk', 'GBK'), ('utf-8', 'UTF8'),
                           ('utf-16-le', 'UTF16LE'), ('ascii', 'ASCII')):
            try:
                pat = k.encode(enc)
            except Exception:
                continue
            idxs = [m.start() for m in re.finditer(re.escape(pat), data)][:6]
            if not idxs:
                continue
            print(f'\n== "{k}" [{label}] 命中 {len(idxs)} 处: {[hex(i) for i in idxs]}')
            for i in idxs[:3]:
                print(f'   @0x{i:X} 邻近串: ' + ' | '.join(near_strings(data, i)))


if __name__ == '__main__':
    main()
