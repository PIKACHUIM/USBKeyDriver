import struct, sys
sys.stdout.reconfigure(encoding='utf-8')

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HDCOS_LNCA.dll'
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
        if va <= rva < va + vs:
            return rp + (rva - va)
    return None

def cstr(rva):
    o = r2o(rva)
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('ascii', 'replace')

exp_rva, exp_size = struct.unpack_from('<II', data, dd + 96)
eo = r2o(exp_rva)
# IMAGE_EXPORT_DIRECTORY 正确偏移
nfuncs  = struct.unpack_from('<I', data, eo + 20)[0]   # 0x14 NumberOfFunctions
nnames  = struct.unpack_from('<I', data, eo + 24)[0]   # 0x18 NumberOfNames
addr_funcs = struct.unpack_from('<I', data, eo + 28)[0]  # 0x1C AddressOfFunctions
addr_names = struct.unpack_from('<I', data, eo + 32)[0]  # 0x20 AddressOfNames
addr_ord   = struct.unpack_from('<I', data, eo + 36)[0]  # 0x24 AddressOfNameOrdinals

print('=== HDCOS_LNCA.dll export names ===')
print('nfuncs=%d nnames=%d' % (nfuncs, nnames))
items = []
for i in range(nnames):
    name_rva = struct.unpack_from('<I', data, r2o(addr_names) + i * 4)[0]
    ord_idx = struct.unpack_from('<H', data, r2o(addr_ord) + i * 2)[0]
    func_rva = struct.unpack_from('<I', data, r2o(addr_funcs) + ord_idx * 4)[0]
    nm = cstr(name_rva)
    items.append((nm, func_rva))

for nm, rva in sorted(items, key=lambda x: x[1]):
    print('  %-34s RVA 0x%X' % (nm, rva))
