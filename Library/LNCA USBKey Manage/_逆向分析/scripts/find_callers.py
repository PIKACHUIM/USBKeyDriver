import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# 查找 JIT_USBKEY_HD.dll 中是否有调用 HD_DeleteCert / HD_DeleteContainer 的代码
# 通过 IAT 导入表检查 JIT 是否 import 了 HDCOS_LNCA 的删除函数

DLLS = [
    r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll',
    r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_HardAPI.dll',
    r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_SortDev.dll',
]

def parse_imports(path):
    data = open(path, 'rb').read()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e + 4
    ns = struct.unpack_from('<H', data, coff + 2)[0]
    so = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    dd = opt + (112 if magic == 0x20b else 96)
    imp_rva, imp_size = struct.unpack_from('<II', data, dd + 8)
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
    if imp_rva == 0:
        return []
    off = r2o(imp_rva)
    results = []
    i = 0
    while True:
        desc_off = off + i * 20
        of_originalFirstThunk = struct.unpack_from('<I', data, desc_off)[0]
        name_rva = struct.unpack_from('<I', data, desc_off + 12)[0]
        if name_rva == 0:
            break
        no = r2o(name_rva)
        dll_name = data[no:data.find(b'\0', no)].decode('ascii', 'replace')
        # iterate thunks
        if of_originalFirstThunk == 0:
            of_originalFirstThunk = struct.unpack_from('<I', data, desc_off + 16)[0]
        thunk_off = r2o(of_originalFirstThunk)
        funcs = []
        j = 0
        while True:
            thunk = struct.unpack_from('<I', data, thunk_off + j * 4)[0]
            if thunk == 0:
                break
            if not (thunk & 0x80000000):
                hint_off = r2o(thunk)
                name = data[hint_off + 2:data.find(b'\0', hint_off + 2)].decode('ascii', 'replace')
                funcs.append(name)
            j += 1
        results.append((dll_name, funcs))
        i += 1
    return results

for dll in DLLS:
    print('=' * 80)
    print(dll)
    print('=' * 80)
    try:
        for dll_name, funcs in parse_imports(dll):
            hits = [f for f in funcs if 'Delete' in f or 'Del' in f or 'Cert' in f or 'Container' in f]
            if hits:
                print(f'  imports from {dll_name}: {hits}')
    except Exception as ex:
        print(f'  ERROR: {ex}')
    print()
