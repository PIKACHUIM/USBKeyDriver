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

# 导入目录是第 2 个数据目录（索引 1），偏移 dd + 8
imp_rva, imp_size = struct.unpack_from('<II', data, dd + 8)
print('import dir rva=0x%X size=0x%X' % (imp_rva, imp_size))

io = r2o(imp_rva)
# 遍历 IMAGE_IMPORT_DESCRIPTOR
results = []
idx = 0
while True:
    desc = io + idx * 20
    oft = struct.unpack_from('<I', data, desc + 0)[0]   # OriginalFirstThunk (RVA)
    name_rva = struct.unpack_from('<I', data, desc + 12)[0]
    ft_rva = struct.unpack_from('<I', data, desc + 16)[0]  # FirstThunk (RVA)
    if oft == 0 and name_rva == 0 and ft_rva == 0:
        break
    # dll name
    no = r2o(name_rva)
    e2 = data.find(b'\0', no)
    dllname = data[no:e2].decode('ascii', 'replace')

    # 遍历 thunk
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
        # 名字在 hint/name 表，val 是 RVA
        hn = r2o(val)
        name = data[hn + 2:data.find(b'\0', hn)].decode('ascii', 'replace')
        # IAT 地址 = imgbase + ft_rva + j*4
        iat_addr = imgbase + ft_rva + j * 4
        results.append((iat_addr, dllname, name))
        j += 1
    idx += 1

# 打印目标地址
targets = [0x10021068, 0x1002106c, 0x10021078, 0x1002105c, 0x10021074, 0x10021070]
print('\n=== 关键 IAT 地址映射 ===')
for addr, dll, nm in results:
    if addr in targets:
        print('  0x%08X  <- %s!%s' % (addr, dll, nm))

print('\n=== 全部 IAT (含 init/verify/reset 相关) ===')
for addr, dll, nm in sorted(results):
    if any(k in nm.lower() for k in ['init', 'reset', 'verify', 'pin', 'erase', 'format', 'clear', 'restore', 'delete', 'admin', 'so']):
        print('  0x%08X  <- %s!%s' % (addr, dll, nm))
