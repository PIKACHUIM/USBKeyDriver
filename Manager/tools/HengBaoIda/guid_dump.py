"""从 PE 中定位设备接口 GUID 常量（不依赖 pefile）。"""
import struct
import sys


class PE:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        d = self.d
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE"
        coff = e_lfanew + 4
        nsec = struct.unpack_from("<H", d, coff + 2)[0]
        opt_size = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        self.imagebase = struct.unpack_from("<I", d, opt + 28)[0]
        self.sections = []
        so = opt + opt_size
        for i in range(nsec):
            e = so + i * 40
            name = d[e:e + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, e + 8)
            self.sections.append((name, va, vsize, raw, rsize))

    def rva2off(self, rva):
        for name, va, vsize, raw, rsize in self.sections:
            if va <= rva < va + max(vsize, rsize):
                if rva - va < rsize:
                    return raw + (rva - va)
        return None

    def read(self, va, n):
        o = self.rva2off(va - self.imagebase)
        if o is None:
            return None
        return self.d[o:o + n]

    def find_va(self, needle):
        i = self.d.find(needle)
        if i < 0:
            return None
        for name, va, vsize, raw, rsize in self.sections:
            if raw <= i < raw + rsize:
                return self.imagebase + va + (i - raw)
        return None


def fmt(blob):
    if not blob or len(blob) < 16:
        return "?"
    a, b, c = struct.unpack_from("<IHH", blob, 0)
    d4 = blob[8:16]
    return "{%08X-%04X-%04X-%s-%s}" % (a, b, c, d4[:2].hex().upper(), d4[2:].hex().upper())


KNOWN = {
    "GUID_DEVINTERFACE_CDROM": "0863F553BFB6D011 94F200A0C91EFB8B",
    "GUID_DEVINTERFACE_DISK": "0763F553BFB6D01194F200A0C91EFB8B",
    "GUID_DEVINTERFACE_USB_DEVICE": "10BFDCA53065D211901F00C04FB951ED",
    "GUID_DEVINTERFACE_USBSTOR": "2D63F553BFB6D01194F200A0C91EFB8B",
    "GUID_DEVINTERFACE_HID": "781D004DFC9E154E9E23956F5E4A8A6B",
    "GUID_CLASS_USB_DEVICE": "10BFDCA53065D211901F00C04FB951ED",
}


def main():
    path = sys.argv[1]
    out = sys.argv[2]
    pe = PE(path)
    w = open(out, "w", encoding="utf-8").write
    w("FILE: %s  imagebase=0x%X\n" % (path, pe.imagebase))
    w("\n=== sections ===\n")
    for name, va, vsize, raw, rsize in pe.sections:
        w("  %-9s va=%08X vsize=%08X raw=%08X rsize=%08X\n" %
          (name, pe.imagebase + va, vsize, raw, rsize))

    w("\n=== known interface GUIDs (searched as raw bytes) ===\n")
    for name, hx in KNOWN.items():
        hx = hx.replace(" ", "")
        # GUID memory layout: d1(4 LE) d2(2 LE) d3(2 LE) d4(8 BE)
        g = (hx[:8] + hx[8:12] + hx[12:16] + hx[16:]).lower()
        try:
            blob = bytes.fromhex(g)
            blob = blob[3::-1] + blob[5:3:-1] + blob[7:5:-1] + blob[8:]
        except Exception:
            continue
        va = pe.find_va(blob)
        w("  %-32s %s\n" % (name, ("va=0x%X" % va) if va else "absent"))

    w("\n=== 16-byte GUID structs around CTSPBot constants ===\n")
    for va in (0x10039508, 0x1003950C, 0x10039518, 0x100394F8, 0x100394E8,
               0x10039528, 0x10039538, 0x10039548, 0x10039558, 0x10039568):
        b = pe.read(va, 16)
        w("  0x%08X  %s\n" % (va, fmt(b)))

    w("\n=== all look-alike GUIDs in .rdata/.data (d1 has version-ish upper bits) ===\n")
    for name, va, vsize, raw, rsize in pe.sections:
        if rsize == 0:
            continue
        blob = pe.d[raw:raw + rsize]
        for off in range(0, len(blob) - 16, 4):
            a, b, c = struct.unpack_from("<IHH", blob, off)
            # 只挑像设备接口 GUID 的：d3 形如 11D0/11D2/11D1
            if c in (0x11D0, 0x11D1, 0x11D2, 0x11D3):
                w("  0x%08X  %s\n" % (pe.imagebase + va + off,
                                      fmt(blob[off:off + 16])))
    w("\ndone\n")


if __name__ == "__main__":
    main()
