import struct
import sys

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_HardAPI.dll'
data = open(DLL, 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
coff = e + 4
ns = struct.unpack_from('<H', data, coff + 2)[0]
so = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
dd = opt + (112 if magic == 0x20b else 96)
imgbase = struct.unpack_from('<I', data, opt + 28)[0]
secoff = opt + so
secs = []
for i in range(ns):
    s = secoff + i * 40
    name = data[s:s + 8].rstrip(b'\0')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s + 8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))

def r2o(rva):
    for (n, va, vs, rp, rs) in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# 导入表 (import directory) = data directory 索引 1
imp_rva, imp_size = struct.unpack_from('<II', data, dd + 1 * 8)
print(f"Import directory RVA=0x{imp_rva:X} size=0x{imp_size:X}")

off = r2o(imp_rva)
i = 0
while True:
    oft = struct.unpack_from('<I', data, off + i * 20 + 0)[0]      # OriginalFirstThunk
    name_rva = struct.unpack_from('<I', data, off + i * 20 + 12)[0]
    first_thunk = struct.unpack_from('<I', data, off + i * 20 + 16)[0]
    if oft == 0 and name_rva == 0 and first_thunk == 0:
        break
    no = r2o(name_rva)
    dllname = data[no:data.find(b'\0', no)].decode('ascii', 'replace')
    print(f"\n=== DLL: {dllname} (OFT=0x{oft:X}, FirstThunk=0x{first_thunk:X}) ===")
    # enumerate thunks
    j = 0
    to = r2o(oft) if oft else r2o(first_thunk)
    ft = r2o(first_thunk)
    while True:
        th = struct.unpack_from('<I', data, to + j * 4)[0]
        if th == 0:
            break
        if th & 0x80000000:
            # ordinal
            ordv = th & 0xffff
            print(f"  [{j}] ord #{ordv}  -> thunk VA 0x{first_thunk + j*4:X} (IAT slot 0x{imgbase + first_thunk + j*4:X})")
        else:
            # name
            hn_rva = th & 0x7fffffff
            hno = r2o(hn_rva)
            hint = struct.unpack_from('<H', data, hno)[0]
            fname = data[hno+2:data.find(b'\0', hno+2)].decode('ascii', 'replace')
            print(f"  [{j}] {fname}  (hint {hint})  -> IAT slot 0x{imgbase + first_thunk + j*4:X}")
        j += 1
    i += 1
