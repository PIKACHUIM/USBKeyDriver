import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

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

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 搜索 .text 里 0x3ee (1006) 和 0xfffffc18 (-1000)
text = None
for (n, va, vs, rp, rs) in secs:
    if n == b'.text':
        text = (va, vs, rp, rs)
        break
va, vs, rp, rs = text
code = data[rp:rp + vs]
for insn in md.disasm(code, va):
    if insn.mnemonic in ('mov', 'cmp') and ('0x3ee' in insn.op_str.lower() or '0xfffffc18' in insn.op_str.lower()):
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}")
