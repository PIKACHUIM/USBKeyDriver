# -*- coding: utf-8 -*-
"""Minimal PE resource walker (no pefile needed).

Dumps RT_STRING tables (with their string IDs) and RT_MENU command IDs, so that
resource-driven tool binaries (CMBCu.exe / CMBCC.dll) can be mapped back to code.

Usage: python rsrc_dump.py <out.txt> <pe> [keyword ...]
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


class PE:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        d = self.d
        self.e_lfanew = u32(d, 0x3C)
        coff = self.e_lfanew + 4
        self.nsec = u16(d, coff + 2)
        self.optsz = u16(d, coff + 16)
        opt = coff + 20
        self.magic = u16(d, opt)
        self.base = u32(d, opt + 28) if self.magic == 0x10B else struct.unpack_from("<Q", d, opt + 24)[0]
        dd = opt + (96 if self.magic == 0x10B else 112)
        self.dd = [(u32(d, dd + 8 * i), u32(d, dd + 8 * i + 4)) for i in range(16)]
        secoff = opt + self.optsz
        self.secs = []
        for i in range(self.nsec):
            s = secoff + i * 40
            name = d[s:s + 8].rstrip(b"\0").decode("latin-1")
            vsz, va, rsz, rptr = struct.unpack_from("<IIII", d, s + 8)
            self.secs.append((name, va, vsz, rptr, rsz))
        self.file_end = len(d)

    def rva2off(self, rva):
        for (name, va, vsz, rptr, rsz) in self.secs:
            if va <= rva < va + max(vsz, rsz):
                return rptr + (rva - va)
        return None

    def sec_of(self, rva):
        for (name, va, vsz, rptr, rsz) in self.secs:
            if va <= rva < va + max(vsz, rsz):
                return name
        return "OVERLAY/none"


def walk(pe, base, rva, depth, out, path=""):
    """Collect leaves. `rva` is an absolute RVA of a resource directory."""
    off = pe.rva2off(rva)
    if off is None:
        return
    nnamed, nid = u16(pe.d, off + 12), u16(pe.d, off + 14)
    total = nnamed + nid
    for i in range(total):
        e = off + 16 + i * 8
        nm = u32(pe.d, e)
        sub = u32(pe.d, e + 4)
        if sub & 0x80000000:
            walk(pe, base, base + (sub & 0x7FFFFFFF), depth + 1, out,
                 path + "/%s" % (nm if nm & 0x80000000 else nm))
        else:
            # leaf offsets are relative to the resource directory base
            o = pe.rva2off(base + sub)
            if o is None:
                continue
            drva, dsz = u32(pe.d, o), u32(pe.d, o + 4)
            out.append((depth, nm, drva, dsz, path))


def main():
    out_path = sys.argv[1]
    pe = PE(sys.argv[2])
    kws = sys.argv[3:]
    _kwf = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\rsrc_keywords.txt"
    import os
    if os.path.isfile(_kwf):
        kws = [ln.strip() for ln in open(_kwf, "r", encoding="utf-8") if ln.strip()]
    w = open(out_path, "w", encoding="utf-8").write

    w("FILE %s size=%d base=0x%X\n" % (pe.path, pe.file_end, pe.base))
    w("SECTIONS:\n")
    for (name, va, vsz, rptr, rsz) in pe.secs:
        w("  %-8s va=0x%08X vsz=0x%X rawptr=0x%X rawsz=0x%X  (file 0x%X..0x%X)\n" %
          (name, va, vsz, rptr, rsz, rptr, rptr + rsz))
    w("resource dir RVA=0x%X size=0x%X -> section %s\n" %
      (pe.dd[2][0], pe.dd[2][1], pe.sec_of(pe.dd[2][0])))

    # ---- RT_STRING (type 6) ----
    w("\n--- RT_STRING (id -> text) ---\n")
    hits = {}
    base = pe.dd[2][0]
    for tid, tname in [(6, "STRING"), (4, "MENU"), (3, "ICON"), (16, "VERSION")]:
        leaves = []
        off = pe.rva2off(base)
        if off is None:
            continue
        nnamed, nid = u16(pe.d, off + 12), u16(pe.d, off + 14)
        for i in range(nnamed + nid):
            e = off + 16 + i * 8
            nm = u32(pe.d, e)
            sub = u32(pe.d, e + 4)
            if nm != tid:
                continue
            if not (sub & 0x80000000):
                continue
            walk(pe, base, base + (sub & 0x7FFFFFFF), 1, leaves, "")
        if not leaves:
            continue
        w("  [type %d = %s] leaves=%d\n" % (tid, tname, len(leaves)))
        for (lvl, nm, drva, dsz, _p) in leaves:
            o = pe.rva2off(drva)
            if o is None:
                w("    block %s: data unmapped (rva 0x%X)\n" % (nm, drva))
                continue
            if tid != 6:
                w("    entry id=%s size=0x%X @file 0x%X\n" % (nm, dsz, o))
                continue
            # path looks like "/<blockid>" ; block id drives the base string id
            try:
                block = int(_p.strip("/").split("/")[0])
            except Exception:
                block = 0
            pos = o
            end = o + dsz
            idx = 0
            while pos + 2 <= end and idx < 16:
                n = u16(pe.d, pos)
                pos += 2
                s = pe.d[pos:pos + 2 * n].decode("utf-16-le", "replace") if n else ""
                pos += 2 * n
                sid = (block - 1) * 16 + idx + 1 if block else None
                if s:
                    w("    ID=%d  %s\n" % (sid, s))
                    for k in kws:
                        if k in s:
                            hits.setdefault(k, []).append((sid, s))
                idx += 1

    w("\n--- KEYWORD HITS ---\n")
    for k in kws:
        for sid, s in hits.get(k, []):
            w("  %-24s ID=%-6s %s\n" % (k, sid, s))
        if k not in hits:
            w("  %-24s (none)\n" % k)


main()
