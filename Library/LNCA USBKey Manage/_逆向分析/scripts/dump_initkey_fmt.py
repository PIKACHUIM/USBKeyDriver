"""Dump the InitKey format string at 0x10028cac (and neighbours) via correct RVA mapping."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll"
data = open(DLL,'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
coff = e+4
ns = struct.unpack_from('<H', data, coff+2)[0]
so = struct.unpack_from('<H', data, coff+16)[0]
opt = coff+20
magic = struct.unpack_from('<H', data, opt)[0]
is64 = magic == 0x20b
dd = opt + (112 if is64 else 96)
er, es = struct.unpack_from('<II', data, dd)
imgbase = struct.unpack_from('<I', data, opt+28)[0]
secoff = opt + so
secs = []
for i in range(ns):
    s = secoff + i*40
    name = data[s:s+8].rstrip(b'\0')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s+8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))
def r2o(rva):
    for (n,va,vs,rp,rs) in secs:
        if va <= rva < va+max(vs,rs):
            return rp + (rva - va)
    return None
def cstr_rva(rva):
    o = r2o(rva)
    if o is None: return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('gbk','replace')

print("ImageBase = 0x%08X" % imgbase)
# The pushes in InitKey use immediate 0x10028cac etc = VA. RVA = VA - imgbase
for va in (0x10028cac, 0x10028c94):
    r = va - imgbase
    print("VA 0x%08X (RVA 0x%X): %r" % (va, r, cstr_rva(r)))
