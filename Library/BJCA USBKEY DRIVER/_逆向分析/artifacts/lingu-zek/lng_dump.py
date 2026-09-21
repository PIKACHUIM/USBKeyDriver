"""导出 Longmai 语言文件（*.lng，UTF-16LE / INI 风格）的可读内容，便于定位界面文案。

用法:
    python lng_dump.py <file.lng> [过滤关键词...]
"""
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def main():
    path = sys.argv[1]
    keys = sys.argv[2:]

    raw = open(path, 'rb').read()
    txt = None
    for enc in ('utf-16-le', 'utf-16', 'gbk', 'utf-8'):
        try:
            cand = raw.decode(enc)
        except Exception:
            continue
        # 选择「中文可读比例高」的解码方式
        good = sum(1 for c in cand if '\u4e00' <= c <= '\u9fff' or '\u3000' <= c <= '\u30ff' or c.isalnum() or c in ' \r\n\t=[].,:_-')
        if txt is None or good > sum(1 for c in txt if c.isalnum() or c in ' \r\n\t=[].,:_-'):
            txt = cand
            best = enc
    print(f'# {path} size={len(raw)} decode={best}')

    lines = txt.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    n = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        if keys and not any(k in s for k in keys):
            continue
        print(f'{i:5d}: {s}')
        n += 1
    print(f'--- printed {n} / {len(lines)} lines ---')


if __name__ == '__main__':
    main()
