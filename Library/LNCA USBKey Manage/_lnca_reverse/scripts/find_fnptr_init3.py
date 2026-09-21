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

def o2rva(off):
    for (n, va, vs, rp, rs) in secs:
        if rp <= off < rp + max(vs, rs):
            return va + (off - rp)
    return None

# 1) 找函数名字符串 RVA
targets = [b'HD_VerifyPin', b'HDJIT_VerifyAdminPin', b'HD_ChangePin', b'HD_InitKey',
           b'HDJIT_InitKey', b'HD_Reset', b'HDJIT_Reset', b'HD_Erase', b'HD_Format',
           b'HDJIT_DeleteContainer', b'HD_DeleteContainer', b'HDJIT_VerifyUserPin',
           b'HDJIT_VerifyAdminPin', b'HD_GetChallenge', b'HD_VerifySOPin']

print('=== 函数名字符串定位 ===')
str_rvas = {}
for t in targets:
    # 找所有出现位置
    pos = 0
    found = []
    while True:
        idx = data.find(t, pos)
        if idx == -1:
            break
        rva = o2rva(idx)
        found.append(rva)
        pos = idx + 1
    if found:
        str_rvas[t.decode()] = found
        print('  %-28s RVA %s' % (t.decode(), [hex(f) for f in found]))

# 2) 搜索 mov [disp32], reg 写入这些全局变量（机器码 89 05 / 89 0D / 89 15 / A3 等）
print('\n=== 写入全局函数指针变量的指令 ===')
gvars = [0x1002105c, 0x10021068, 0x1002106c, 0x10021070, 0x10021074, 0x10021078,
         0x10021054, 0x10021058, 0x10021060, 0x10021064, 0x1002104c, 0x10021050]
for g in gvars:
    # mov [disp32], eax = 89 05 <disp32 little-endian>
    pat = b'\x89\x05' + struct.pack('<I', g)
    pos = 0
    while True:
        idx = data.find(pat, pos)
        if idx == -1:
            break
        print('  mov [0x%X], eax @ file_off=0x%X' % (g, idx))
        pos = idx + 1
    # mov [disp32], ecx = 89 0D
    pat = b'\x89\x0d' + struct.pack('<I', g)
    pos = 0
    while True:
        idx = data.find(pat, pos)
        if idx == -1:
            break
        print('  mov [0x%X], ecx @ file_off=0x%X' % (g, idx))
        pos = idx + 1
