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
print('--- sections ---')
for i in range(ns):
    s = secoff + i * 40
    name = data[s:s + 8].rstrip(b'\0')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s + 8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))
    print('  %-10s vaddr=0x%X vsize=0x%X rawptr=0x%X rawsize=0x%X' % (name.decode(), vaddr, vsize, rawptr, rawsize))

exp_rva, exp_size = struct.unpack_from('<II', data, dd + 96)
print('exp_rva=0x%X exp_size=0x%X' % (exp_rva, exp_size))
eo = None
for (n, va, vs, rp, rs) in secs:
    if va <= exp_rva < va + vs:
        eo = rp + (exp_rva - va)
        break
print('eo=0x%X' % eo)

nnames = struct.unpack_from('<I', data, eo + 24)[0]
nfuncs = struct.unpack_from('<I', data, eo + 20)[0]
addr_names = struct.unpack_from('<I', data, eo + 32)[0]
addr_ord = struct.unpack_from('<I', data, eo + 36)[0]
addr_funcs = struct.unpack_from('<I', data, eo + 28)[0]
print('nnames=%d nfuncs=%d' % (nnames, nfuncs))
print('addr_names=0x%X addr_ord=0x%X addr_funcs=0x%X' % (addr_names, addr_ord, addr_funcs))

def r2o(rva):
    for (n, va, vs, rp, rs) in secs:
        if va <= rva < va + vs:
            return rp + (rva - va)
    return None

print('r2o(addr_names)=0x%X r2o(addr_ord)=0x%X r2o(addr_funcs)=0x%X' % (
    r2o(addr_names) or 0, r2o(addr_ord) or 0, r2o(addr_funcs) or 0))
