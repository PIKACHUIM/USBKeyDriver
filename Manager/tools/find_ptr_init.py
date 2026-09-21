import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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

def cstr_rva(rva):
    o = r2o(rva)
    if o is None:
        return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('gbk', 'replace') if e2 != -1 else data[o:].decode('gbk', 'replace')

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

# 目标全局变量地址（函数指针槽）
targets = [0x10009e08, 0x10009e0c, 0x10009e40, 0x10009e44, 0x10009e48, 0x10009e50]

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 搜索整个 .text 段里对目标地址的写入 (mov [target], reg)
text_sec = None
for (n, va, vs, rp, rs) in secs:
    if n == b'.text':
        text_sec = (va, vs, rp, rs)
        break

va, vs, rp, rs = text_sec
print(f".text RVA 0x{va:X} size 0x{vs:X}")

code = data[rp:rp + vs]
for insn in md.disasm(code, va):
    if insn.mnemonic == 'mov' and '[' in insn.op_str:
        # 检查是否写入目标地址
        for t in targets:
            # 绝对地址形式：mov dword ptr [0x10009e0c], eax
            if f'[0x{imgbase + (t - imgbase):x}]' in insn.op_str or f'[{t:x}]' in insn.op_str or f'[0x{t:x}]' in insn.op_str:
                print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}  ; 写入 {hex(t)}")
    if insn.mnemonic == 'lea' and '[' in insn.op_str:
        for t in targets:
            if f'0x{t:x}' in insn.op_str.lower():
                print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}  ; lea 涉及 {hex(t)}")
