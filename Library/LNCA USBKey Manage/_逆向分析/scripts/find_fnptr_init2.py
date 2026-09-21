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

# 反汇编整个 text
insns = list(md.disasm(data[text_rp:text_rp + text_vs], text_va))
print('总指令数:', len(insns))

# 目标全局函数指针变量地址
targets = {0x1002105c, 0x10021068, 0x1002106c, 0x10021070, 0x10021074, 0x10021078, 0x10021054, 0x10021058, 0x10021060, 0x10021064}

# 找 mov dword ptr [target], eax 模式，回溯 push 字符串
for i, insn in enumerate(insns):
    # 匹配 mov dword ptr [0x...], eax/ecx/edx
    if insn.mnemonic == 'mov' and insn.op_str.startswith('dword ptr [0x100210'):
        try:
            t = int(insn.op_str.split('0x', 1)[1].split(']')[0], 16)
        except:
            continue
        if t in targets:
            # 回溯找 push 字符串
            name_str = None
            for j in range(i-1, max(0, i-10), -1):
                p = insns[j]
                if p.mnemonic == 'push' and p.op_str.startswith('0x1002'):
                    nm = cstr_rva(int(p.op_str, 16) - imgbase)
                    if nm:
                        name_str = nm
                        break
            print('0x%08X: mov [0x%08X] <- "%s"' % (insn.address, t, name_str))
