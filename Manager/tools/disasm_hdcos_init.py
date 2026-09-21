"""Disassemble HDCOS_LNCA.dll real init functions: InitialCard, HD_IC_RESET, Clear_DF, HD_SPWD, HD_ClearDir."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HDCOS_LNCA.dll"
data = open(DLL,'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
coff = e+4
ns = struct.unpack_from('<H', data, coff+2)[0]
so = struct.unpack_from('<H', data, coff+16)[0]
opt = coff+20
magic = struct.unpack_from('<H', data, opt)[0]
is64 = magic == 0x20b
dd = opt + (112 if is64 else 96)
er, es = struct.unpack_from('<II', data, dd)
imgbase = struct.unpack_from('<I', data, opt+28)[0]
secoff = opt + so
secs = []
for i in range(ns):
    s = secoff + i*40
    name = data[s:s+8].rstrip(b'\0')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s+8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))
def r2o(rva):
    for (n,va,vs,rp,rs) in secs:
        if va <= rva < va+max(vs,rs):
            return rp + (rva - va)
    return None
def cstr_rva(rva):
    o = r2o(rva)
    if o is None: return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('gbk','replace') if e2!=-1 else data[o:].decode('gbk','replace')

md = Cs(CS_ARCH_X86, CS_MODE_32)
def disasm(rva, count=100):
    off = r2o(rva)
    return list(md.disasm(data[off:off+count*16], rva))[:count]

for name, rva in [("HD_IC_RESET",0x10C0), ("InitialCard",0x73F0), ("Clear_DF",0x19C0), ("HD_SPWD",0x2B00), ("HD_ClearDir",0x67D0)]:
    print("="*80)
    print(f"{name} (RVA 0x{rva:X})")
    print("="*80)
    for insn in disasm(rva, 55):
        # annotate string refs
        extra = ""
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase + 0x400000:
                    s = cstr_rva(va - imgbase)
                    if s and len(s) < 80 and all(32 <= ord(c) < 127 or ord(c) > 127 for c in s):
                        extra = f"  ; \"{s}\""
            except: pass
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<7} {insn.op_str}{extra}")
    print()
