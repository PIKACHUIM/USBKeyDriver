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

def cstr_rva(rva):
    o = r2o(rva)
    if o is None:
        return None
    e2 = data.find(b'\0', o)
    return data[o:e2].decode('gbk', 'replace') if e2 != -1 else data[o:].decode('gbk', 'replace')

md = Cs(CS_ARCH_X86, CS_MODE_32)

def show(name, rva, count=60):
    print('=' * 80)
    print(f'{name} (RVA 0x{rva:X})')
    print('=' * 80)
    off = r2o(rva)
    for insn in md.disasm(data[off:off + count * 16], rva):
        extra = ''
        if insn.mnemonic == 'push' and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase + 0x400000:
                    s = cstr_rva(va - imgbase)
                    if s and len(s) < 80:
                        extra = f'  ; "{s}"'
            except:
                pass
        if insn.mnemonic.startswith('call') and insn.op_str.startswith('0x'):
            try:
                va = int(insn.op_str, 16)
                if imgbase <= va < imgbase + 0x400000:
                    extra += f'  ; ->RVA 0x{va-imgbase:X}'
            except:
                pass
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{extra}")

# HD_DeleteContainer 内部调用的 0x7d40（连接设备）
show('0x7d40 (DeleteContainer 内部连接)', 0x7d40, 50)
# HD_DeleteCert 内部调用的 0x8b60
show('0x8b60 (DeleteCert 内部)', 0x8b60, 50)
