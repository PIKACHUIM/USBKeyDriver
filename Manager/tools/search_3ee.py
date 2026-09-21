import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# 搜索 mov eax, 0x3ee 或 cmp ... 0x3ee
md = Cs(CS_ARCH_X86, CS_MODE_32)
# 0x3EE = 1006, 0x3ee 即 1006
text = None
for (n, va, vs, rp, rs) in secs:
    if n == b'.text':
        text = (va, vs, rp, rs)
        break
va, vs, rp, rs = text
code = data[rp:rp + vs]
for insn in md.disasm(code, va):
    if insn.mnemonic in ('mov', 'cmp', 'add', 'sub', 'push') and '0x3ee' in insn.op_str:
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}")
    if insn.mnemonic == 'mov' and insn.op_str.startswith('eax, 0x'):
        v = int(insn.op_str.split(',')[1].strip(), 16)
        if 1000 <= v <= 1010:
            print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}  ; ={v}")
