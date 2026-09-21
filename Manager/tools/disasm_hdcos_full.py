"""Full disassembly of HDCOS init-chain functions to recover exact signatures (ret imm16 = param count)."""
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
def disasm(rva, count=140):
    off = r2o(rva)
    return list(md.disasm(data[off:off+count*16], rva))[:count]

# Only show first ~50 insns of each + detect the ret imm16 (calling conv/param count)
for name, rva in [("HD_Open",0x1120), ("HD_Close",0x15B0), ("HD_IC_RESET",0x10C0),
                  ("HD_VerifyPin",0x2840), ("HD_ChangePin",0x2490), ("HD_SPWD",0x2B00),
                  ("Clear_DF",0x19C0), ("HD_ClearDir",0x67D0), ("Reload_Pin",0x1D70)]:
    insns = disasm(rva, 200)
    print("="*78)
    print(f"{name} (RVA 0x{rva:X})")
    print("="*78)
    # Find the first ret instruction to determine function boundary
    ret_idx = None
    for idx, insn in enumerate(insns):
        if insn.mnemonic == 'ret':
            ret_idx = idx
            break
    # Show up to ret + 2 more instructions (or 100 if no ret found)
    display_count = min(ret_idx + 3 if ret_idx else 100, len(insns))
    for insn in insns[:display_count]:
        extra = ""
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase+0x400000:
                    s = cstr_rva(va - imgbase)
                    if s and len(s) < 70:
                        extra = f"  ; \"{s}\""
            except: pass
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<7} {insn.op_str}{extra}")
    print()
