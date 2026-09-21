# -*- coding: utf-8 -*-
"""Raw string extractor for the HengBao UranuSafe binaries.
Extracts ASCII and UTF-16LE (incl. CJK) strings, and greps interesting keywords.
Usage: python hbstrings.py <out.txt> <file1> [file2 ...]
"""
import os
import sys

KW = [
    "reset", "restore", "erase", "clear", "format", "init", "unlock",
    "pin", "puk", "admin", "so", "password", "passwd", "verify",
    "hid", "usb", "scard", "winscard", "ccid", "cos", "apdu",
    "serial", "device", "slot", "token", "cmbc", "uranu", "hengbao",
    "尝试", "次数", "锁定", "解锁", "重置", "初始化", "清空", "擦除",
    "格式化", "密码", "口令", "用户", "管理", "错误", "失败", "成功",
    "请输入", "确认", "删除", "证书", "密钥",
]

PRINT_RANGES = [
    (0x20, 0x7E),
    (0xA0, 0xFF),
    (0x2000, 0x206F),
    (0x3000, 0x303F),
    (0x4E00, 0x9FFF),
    (0xFF00, 0xFFEF),
]


def ok(c):
    for a, b in PRINT_RANGES:
        if a <= c <= b:
            return True
    return False


def ascii_strings(data, minlen=5):
    res = []
    cur = 0
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if cur == 0:
                start = i
            cur += 1
        else:
            if cur >= minlen:
                res.append((start, data[start:start + cur].decode("latin-1")))
            cur = 0
    if cur >= minlen:
        res.append((start, data[start:start + cur].decode("latin-1")))
    return res


def utf16le_strings(data, minlen=3):
    res = []
    n = len(data) - 1
    i = 0
    while i < n:
        # try to start a run
        start = i
        chars = []
        j = i
        while j + 1 < n:
            c = data[j] | (data[j + 1] << 8)
            if ok(c) and c != 0:
                chars.append(chr(c))
                j += 2
                continue
            break
        if len(chars) >= minlen:
            # require at least one CJK char to avoid noise from 1-byte ascii
            if any(0x4E00 <= ord(ch) <= 0x9FFF for ch in chars):
                res.append((start, "".join(chars)))
                i = j
                continue
        i += 1
    return res


def main():
    out_path = sys.argv[1]
    files = sys.argv[2:]
    with open(out_path, "w", encoding="utf-8") as out:
        for f in files:
            if not os.path.isfile(f):
                continue
            data = open(f, "rb").read()
            out.write("\n" + "=" * 78 + "\n")
            out.write("FILE: %s  (%d bytes)\n" % (os.path.basename(f), len(data)))
            out.write("=" * 78 + "\n")
            a = ascii_strings(data, 5)
            u = utf16le_strings(data, 3)
            out.write("-- ASCII strings: %d, UTF16LE(CJK) strings: %d --\n" % (len(a), len(u)))
            out.write("\n--- KEYWORD MATCHES (ascii) ---\n")
            for off, s in a:
                low = s.lower()
                if any(k in low for k in KW):
                    out.write("%08X  %s\n" % (off, s))
            out.write("\n--- KEYWORD MATCHES (utf16) ---\n")
            for off, s in u:
                if any(k in s for k in KW):
                    out.write("%08X  %s\n" % (off, s))
            out.write("\n--- ALL UTF16 (CJK, first 800) ---\n")
            for off, s in u[:800]:
                out.write("%08X  %s\n" % (off, s))
            out.write("\n--- ALL ASCII (first 1500) ---\n")
            for off, s in a[:1500]:
                out.write("%08X  %s\n" % (off, s))


if __name__ == "__main__":
    main()
