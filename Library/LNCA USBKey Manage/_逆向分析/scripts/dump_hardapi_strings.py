"""Find LoadLibrary/GetProcAddress string args in HD_HardAPI.dll to map its downstream chain."""
import struct, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_HardAPI.dll"
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
def cstr(rva):
    o = r2o(rva)
    if o is None: return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('ascii','replace') if e2!=-1 else data[o:].decode('ascii','replace')

# Find all printable strings that look like DLL names or API names
strings = re.findall(rb'[\x20-\x7e]{4,}', data)
seen = set()
print("Suspicious DLL/API strings in HD_HardAPI.dll:")
for s in strings:
    t = s.decode('ascii')
    if ('HD' in t or 'HS' in t or '.dll' in t.lower() or 'COS' in t or 'IFD' in t or 'CIDC' in t) and t not in seen:
        seen.add(t)
        print("  " + t)
