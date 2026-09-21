import struct

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_SortDev.dll'
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

def dump_exports():
    er, es = struct.unpack_from('<II', data, dd)
    o = r2o(er)
    numNames = struct.unpack_from('<I', data, o + 24)[0]
    addrNames = struct.unpack_from('<I', data, o + 32)[0]
    addrOrds = struct.unpack_from('<I', data, o + 36)[0]
    addrFuncs = struct.unpack_from('<I', data, o + 28)[0]
    names_off = r2o(addrNames)
    ords_off = r2o(addrOrds)
    funcs_off = r2o(addrFuncs)
    exports = {}
    for i in range(numNames):
        n_rva = struct.unpack_from('<I', data, names_off + i * 4)[0]
        no = r2o(n_rva)
        name = data[no:data.find(b'\0', no)].decode('ascii', 'replace')
        ordinal = struct.unpack_from('<H', data, ords_off + i * 2)[0]
        func_rva = struct.unpack_from('<I', data, funcs_off + ordinal * 4)[0]
        exports[name] = func_rva
    return exports

exports = dump_exports()
print("=== HD_SortDev.dll 全部导出 ===")
for k in sorted(exports):
    print(f"  {k:<30s} RVA 0x{exports[k]:X}")
