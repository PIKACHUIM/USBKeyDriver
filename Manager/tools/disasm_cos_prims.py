import struct, sys
sys.stdout.reconfigure(encoding='utf-8')
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HDCOS_LNCA.dll'
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

md = Cs(CS_ARCH_X86, CS_MODE_32)

def show(name, rva, count=30):
    print('=' * 80)
    print(f'{name} (RVA 0x{rva:X})')
    print('=' * 80)
    off = r2o(rva)
    for insn in md.disasm(data[off:off + count * 16], rva):
        print("  0x%08X  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))

show('Select_File', 0x1C40, 30)
show('Get_Challenge', 0x1B40, 30)
show('External_Authentication', 0x1FB0, 30)
