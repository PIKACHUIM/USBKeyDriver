"""从二进制文件中提取可读字符串（ASCII + GBK 中文），用于逆向线索分析。

用法:
    python lg_str.py <file> [关键词正则] [--cn-only]
"""
import re
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

ASCII_PAT = re.compile(rb'[\x20-\x7e]{4,}')
# GBK: 首字节 0x81-0xFE，次字节 0x40-0xFE（不含 0x7F）
GBK_PAT = re.compile(rb'(?:[\x81-\xfe][\x40-\xfe]|[\x20-\x7e]){4,}')
# UTF-16LE: 可打印 ASCII 字符 + 0x00（COM 类型库 / Unicode 字符串）
UTF16_PAT = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def extract(path):
    data = open(path, 'rb').read()
    out = []
    for m in ASCII_PAT.finditer(data):
        out.append(m.group().decode('ascii', 'ignore'))
    for m in GBK_PAT.finditer(data):
        raw = m.group()
        if not any(b >= 0x81 for b in raw):
            continue  # 纯 ASCII 已在上一轮处理
        try:
            s = raw.decode('gbk')
        except Exception:
            continue
        if any('\u4e00' <= ch <= '\u9fff' for ch in s):
            out.append(s)
    for m in UTF16_PAT.finditer(data):
        out.append(m.group().decode('utf-16-le', 'ignore'))
    # UTF-8 中文描述（MFC 自动化 "方法Xxx" / "属性Xxx"）
    try:
        text = data.decode('utf-8', 'ignore')
        for m in re.finditer(r'[\u4e00-\u9fff]{1,12}[A-Za-z_][A-Za-z0-9_]{2,}', text):
            out.append(m.group())
    except Exception:
        pass
    # 去重保持顺序
    seen = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def main():
    args = list(sys.argv[1:])
    out = None
    if '--out' in args:
        i = args.index('--out')
        out = args[i + 1]
        del args[i:i + 2]
    path = args[0]
    kw = args[1] if len(args) > 1 else None
    pat = re.compile(kw, re.I) if kw else None
    lines = [s for s in extract(path) if pat is None or pat.search(s)]
    text = '\n'.join(lines)
    if out:
        # 直接写文件，避免 PowerShell 管道的编码转换破坏中文
        with open(out, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'written {len(lines)} lines -> {out}')
    else:
        print(text)


if __name__ == '__main__':
    main()
