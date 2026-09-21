"""Dump DES tables from CMBCC.dll and compare with standard DES tables."""
import struct
import sys


class PE:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        d = self.d
        e = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, e + 6)[0]
        opt_size = struct.unpack_from("<H", d, e + 20)[0]
        opt = e + 24
        self.imagebase = struct.unpack_from("<I", d, opt + 28)[0]
        self.secs = []
        so = opt + opt_size
        for i in range(nsec):
            b = so + i * 40
            name = d[b:b + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, b + 8)
            self.secs.append((name, va, vsize, raw, rsize))

    def rva2off(self, rva):
        for name, va, vsize, raw, rsize in self.secs:
            if va <= rva < va + max(vsize, rsize):
                if rva - va < rsize:
                    return raw + (rva - va)
        return None

    def read(self, va, n):
        o = self.rva2off(va - self.imagebase)
        return None if o is None else self.d[o:o + n]


def fmt(b, label):
    print("%-28s (%d) %s" % (label, len(b), " ".join("%02X" % x for x in b)))


def main():
    path = sys.argv[1]
    pe = PE(path)
    print("imagebase=0x%X" % pe.imagebase)
    print("sections:", [(s[0], hex(pe.imagebase + s[1])) for s in pe.secs])
    for va in (0x1002C690, 0x1002C6D0, 0x1002C9D8):
        b = pe.read(va, 256)
        print()
        if b is None:
            print("0x%08X: not mapped" % va)
            continue
        for i in range(0, 256, 64):
            fmt(b[i:i + 64], "0x%08X+%d" % (va, i))
    print()
    print("=== 标准 DES 参考 ===")
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    print("PC1  ", " ".join("%02X" % x for x in PC1))
    print("SHIFT", " ".join("%02X" % x for x in [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]))
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20,
           13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46,
           42, 50, 36, 29, 32]
    print("PC2  ", " ".join("%02X" % x for x in PC2))


if __name__ == "__main__":
    main()
