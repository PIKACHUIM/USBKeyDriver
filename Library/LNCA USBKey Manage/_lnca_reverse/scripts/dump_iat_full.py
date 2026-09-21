import struct, sys
sys.stdout.reconfigure(encoding='utf-8')

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll'
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

imp_rva, imp_size = struct.unpack_from('<II', data, dd + 8)
io = r2o(imp_rva)
results = []
idx = 0
while True:
    desc = io + idx * 20
    oft = struct.unpack_from('<I', data, desc + 0)[0]
    name_rva = struct.unpack_from('<I', data, desc + 12)[0]
    ft_rva = struct.unpack_from('<I', data, desc + 16)[0]
    if oft == 0 and name_rva == 0 and ft_rva == 0:
        break
    no = r2o(name_rva)
    e2 = data.find(b'\0', no)
    dllname = data[no:e2].decode('ascii', 'replace')
    th = oft if oft else ft_rva
    to = r2o(th)
    j = 0
    while True:
        val = struct.unpack_from('<I', data, to + j * 4)[0]
        if val == 0:
            break
        if val & 0x80000000:
            j += 1
            continue
        hn = r2o(val)
        name = data[hn + 2:data.find(b'\0', hn)].decode('ascii', 'replace')
        iat_addr = imgbase + ft_rva + j * 4
        results.append((iat_addr, dllname, name))
        j += 1
    idx += 1

for addr, dll, nm in sorted(results):
    print('  0x%08X  <- %s!%s' % (addr, dll, nm))
