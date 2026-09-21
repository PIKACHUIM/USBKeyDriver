#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LNCA DLL 静态反汇编辅助工具（capstone + pefile）。

用法:
    py -3 tools/disasm_lnca.py <dll> <导出名|RVA(0x..)> [maxBytes] [--full]

功能:
    - 按导出名或 RVA 反汇编指定函数（32 位 x86，__stdcall）；
    - 自动标注 call 目标对应的导出名（便于还原调用链）；
    - 默认在首个 `ret imm16` 处停止并打印推导出的参数总字节数；
      加 `--full` 则连续反汇编整个 maxBytes 区间（用于查看带分支的完整实现）。

依赖: pip install capstone pefile
"""
from __future__ import annotations

import sys

import capstone
import pefile


def build_maps(pe: pefile.PE) -> tuple[dict[int, str], dict[str, int]]:
    """返回 (rva -> 导出名, 导出名 -> rva)。"""
    rva2name: dict[int, str] = {}
    name2rva: dict[str, int] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return rva2name, name2rva
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode("ascii", "replace")
        rva2name.setdefault(exp.address, name)
        name2rva.setdefault(name, exp.address)
    return rva2name, name2rva


def read_func_bytes(pe: pefile.PE, rva: int, max_bytes: int) -> bytes:
    return pe.get_data(rva, max_bytes)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    argv = sys.argv[1:]
    full = "--full" in argv
    argv = [a for a in argv if a != "--full"]
    if len(argv) < 2:
        print(__doc__)
        return 1

    dll_path = argv[0]
    target = argv[1]

    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    rva2name, name2rva = build_maps(pe)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    if target == "--addrrefs":
        # --addrrefs <rva>：查找代码中以绝对地址引用该 RVA 的位置（mov reg,[ImageBase+rva]）
        import struct as _struct

        img = pe.get_memory_mapped_image()
        va = image_base + int(argv[2], 16)
        pat = _struct.pack("<I", va)
        hits = []
        i = 0
        while True:
            i = img.find(pat, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        print(f"=== {argv[0]} 引用 VA 0x{va:X}（RVA 0x{int(argv[2], 16):X}）→ {len(hits)} 处 ===")
        for h in hits[:40]:
            print(f"  0x{h:06X}")
        return 0

    if target == "--findpat":
        # --findpat <hexbytes>：在文件中搜索字节模式（例如传输密钥常量）
        pat = bytes.fromhex(argv[2].replace(" ", ""))
        with open(argv[0], "rb") as fh:
            blob = fh.read()
        hits = []
        i = 0
        while True:
            i = blob.find(pat, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        print(f"=== {argv[0]} 模式 {pat.hex(' ')} → {len(hits)} 处 ===")
        for h in hits[:40]:
            print(f"  0x{h:X}")
            # 打印上下文（前后各 32 字节），便于识别密钥表结构
            lo = max(0, h - 32)
            hi = min(len(blob), h + len(pat) + 48)
            seg = blob[lo:hi]
            for k in range(0, len(seg), 16):
                mark = ">>" if lo + k <= h < lo + k + 16 else "  "
                print(f"    {mark} 0x{lo + k:06X}  {seg[k:k + 16].hex(' ')}"
                      f"  |{''.join(chr(c) if 32 <= c < 127 else '.' for c in seg[k:k + 16])}|")
        return 0

    if target == "--wstrings":
        # 提取 UTF-16LE 宽字符串（C++ 工具的中文提示/默认口令通常是宽字符）
        filt = argv[2] if len(argv) > 2 else ""
        with open(argv[0], "rb") as fh:
            blob = fh.read()
        out = set()
        i = 0
        n = len(blob)
        while i + 8 <= n:
            if blob[i] != 0 and blob[i + 1] == 0:
                j = i
                while j + 1 < n and blob[j] != 0 and blob[j + 1] == 0:
                    j += 2
                if j - i >= 8:
                    s = blob[i:j].decode("utf-16-le", "ignore")
                    if not filt or filt.lower() in s.lower():
                        out.add(s)
                i = j
            else:
                i += 1
        for s in sorted(out):
            print(repr(s))
        print(f"=== 共 {len(out)} 条 ===")
        return 0

    if target == "--strings":
        filt = argv[2] if len(argv) > 2 else ""
        import re

        with open(argv[0], "rb") as fh:
            blob = fh.read()
        found = {
            m.group(0).decode("ascii", "replace")
            for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{2,40}", blob)
        }
        for s in sorted(found):
            if filt and filt.lower() not in s.lower():
                continue
            print(s)
        return 0

    if target == "--imports":
        pe2 = pefile.PE(argv[0], fast_load=False)
        for entry in getattr(pe2, "DIRECTORY_ENTRY_IMPORT", []) or []:
            print(f"--- {entry.dll.decode('ascii', 'replace')}")
            for imp in entry.imports:
                nm = imp.name.decode("ascii", "replace") if imp.name else f"ord#{imp.ordinal}"
                print(f"    0x{imp.address:X}  {nm}")
        return 0

    if target == "--xrefs":
        filt = argv[2] if len(argv) > 2 else ""
        img = pe.get_memory_mapped_image()
        import struct as _struct

        hits = 0
        for i in range(len(img) - 5):
            if img[i] != 0xE8:
                continue
            rel = _struct.unpack_from("<i", img, i + 1)[0]
            tgt = i + 5 + rel
            name = rva2name.get(tgt)
            if not name:
                continue
            if filt and filt.lower() not in name.lower():
                continue
            print(f"0x{i:08X}  call  {name}  (RVA 0x{tgt:X})")
            hits += 1
        print(f"=== 共 {hits} 处直接调用 ===")
        return 0

    if target == "--data":
        rva = int(argv[2], 16)
        length = int(argv[3], 0) if len(argv) > 3 else 16
        raw = pe.get_data(rva, length)
        print(f"=== {dll_path} @RVA 0x{rva:X} ({length} bytes) ===")
        for i in range(0, len(raw), 16):
            chunk = raw[i:i + 16]
            print(f"{rva + i:08X}  {chunk.hex(' ')}")
        return 0

    max_bytes = int(argv[2], 0) if len(argv) > 2 and not argv[2].startswith("--") else 0x200

    if target.lower().startswith("0x"):
        rva = int(target, 16)
        label = rva2name.get(rva, "?")
    else:
        if target not in name2rva:
            print(f"[!] 未找到导出: {target}")
            return 2
        rva = name2rva[target]
        label = target

    data = read_func_bytes(pe, rva, max_bytes)
    print(f"=== {dll_path}")
    print(f"=== {label}  RVA=0x{rva:X}  VA=0x{image_base + rva:X}  size<=0x{max_bytes:X}")
    print()

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    for ins in md.disasm(data, image_base + rva):
        text = f"{ins.address:08X}  {ins.mnemonic:<8}{ins.op_str}"
        note = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            tgt_rva = tgt - image_base
            if tgt_rva in rva2name:
                note = f"   ; -> {rva2name[tgt_rva]}"
        print(text + note)

        if ins.mnemonic in ("ret", "retn"):
            if ins.op_str:
                imm = int(ins.op_str, 16)
                print(f"        ; __stdcall 参数总字节 = {imm} → {imm // 4} 个参数")
            if not full:
                break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
