import struct, sys
sys.stdout.reconfigure(encoding='utf-8')
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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

def cstr_rva(rva):
    o = r2o(rva)
    if o is None:
        return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('ascii', 'replace') if e2 != -1 else None

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 找 .text 段
for (n, va, vs, rp, rs) in secs:
    if n == b'.text':
        text_va, text_vs, text_rp = va, vs, rp
        break

insns = list(md.disasm(data[text_rp:text_rp + text_vs], text_va))

# 找引用 "USBKey_UnlockPin Start..." (0x273E0) 和 "111111" (0x273D8) 的 push
def find_refs(str_rva):
    refs = []
    for i, insn in enumerate(insns):
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if va == imgbase + str_rva:
                    refs.append(insn.address)
            except:
                pass
    return refs

print('引用 "111111"(0x273D8) 的位置:', [hex(x) for x in find_refs(0x273D8)])
print('引用 "USBKey_UnlockPin Start"(0x273E0) 的位置:', [hex(x) for x in find_refs(0x273E0)])
print('引用 "HS_ReloadUserPin"(0x2737C) 的位置:', [hex(x) for x in find_refs(0x2737C)])
print('引用 "USBKey_UnlockPin Success"(0x27360) 的位置:', [hex(x) for x in find_refs(0x27360)])
