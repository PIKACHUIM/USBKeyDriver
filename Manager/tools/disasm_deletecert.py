"""Determine exact signatures of HD_DeleteCert / HD_DeleteContainer via ret imm16 + prologue analysis."""
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

def disasm(rva, n=200):
    off = r2o(rva)
    return list(md.disasm(data[off:off+n*16], rva))

# Functions of interest (name -> RVA from export table)
targets = [
    ("HD_DeleteCert",      0x7210),
    ("HD_DeleteContainer", 0x6A10),
    ("HD_DelCertFrIE",     0x6FD0),
    ("HD_ClearDir",        0x67D0),
    ("HD_ImportCert",      0x0000),   # fill from export dump below
]

for name, rva in targets:
    if rva == 0: continue
    print("="*80)
    print(f"{name}  (RVA 0x{rva:X})")
    print("="*80)
    insns = disasm(rva, 260)
    # find first ret / ret imm16
    for insn in insns:
        extra = ""
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase+0x400000:
                    s = cstr_rva(va - imgbase)
                    if s and len(s) < 80:
                        extra = f'  ; "{s}"'
            except: pass
        if insn.mnemonic.startswith('call') and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase+0x400000:
                    extra += f"  ; ->RVA 0x{va-imgbase:X}"
            except: pass
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{extra}")
        if insn.mnemonic == 'ret':
            # decode ret imm16
            if insn.op_str:
                imm = insn.op_str
                print(f"  >>> ret {imm} => __stdcall, total param bytes = {imm}")
            else:
                print("  >>> ret (no imm) => cdecl or 0 params")
            break
    print()
