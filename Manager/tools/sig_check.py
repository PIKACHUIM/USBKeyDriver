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

md = Cs(CS_ARCH_X86, CS_MODE_32)

def sig(name, rva):
    off = r2o(rva)
    if off is None:
        print(f"{name:22s} RVA 0x{rva:04X}  (unresolvable)")
        return
    ins = list(md.disasm(data[off:off + 900], rva))
    for x in ins:
        if x.mnemonic == 'ret':
            imm = x.op_str or '0'
            params = int(imm) // 4 if imm.isdigit() else '?'
            print(f"{name:22s} RVA 0x{rva:04X}  ret {imm}  => param bytes={imm} (params={params} if stdcall)")
            return
    print(f"{name:22s} RVA 0x{rva:04X}  (no ret found)")

for n, r in [('HD_DeleteCert', 0x7210), ('HD_DeleteContainer', 0x6A10),
             ('HD_DelCertFrIE', 0x6FD0), ('HD_ClearDir', 0x67D0)]:
    sig(n, r)
