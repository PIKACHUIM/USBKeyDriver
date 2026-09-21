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

# 密钥地址 0x10019050（RVA = 0x19050）
rva = 0x19050
off = r2o(rva)
print('密钥 @ RVA 0x19050，文件偏移 0x%X' % off)
raw = data[off:off+64]
print('hex:', raw.hex(' '))
print('ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw))

# 也看 0x100190ec / 0x10019290（HDJIT_ReloadPin 里引用的其他数据）
for r in [0x190EC, 0x19290]:
    o = r2o(r)
    if o is not None:
        raw2 = data[o:o+32]
        print('\n数据 @ RVA 0x%X:' % r, raw2.hex(' '))
        print('  ascii:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw2))
