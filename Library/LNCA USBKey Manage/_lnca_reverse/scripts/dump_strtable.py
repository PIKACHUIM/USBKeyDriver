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

# 0x27180 附近的字符串表：连续 ASCII 字符串，以 \0 分隔
# 打印 0x27180 到 0x27380 之间所有可见字符串
base = 0x27180
end = 0x27400
off = r2o(base)
print('=== 字符串表 0x27180-0x27400 ===')
cur = base
while cur < end:
    o = r2o(cur)
    if data[o] == 0:
        cur += 1
        continue
    e2 = data.find(b'\0', o)
    s = data[o:e2]
    # 只打印可打印的
    if all(32 <= c < 127 for c in s) and len(s) >= 3:
        print('  0x%X: "%s"' % (cur, s.decode('ascii')))
    cur += (e2 - o) + 1
