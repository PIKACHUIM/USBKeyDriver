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

# 找写入全局函数指针变量的位置：mov [0x100210XX], eax 附近的 GetProcAddress 字符串
# 全局函数指针变量范围约 0x10021000-0x10021200
# 搜索整个 .text 段，找 push "xxx" 后面跟 GetProcAddress 再 mov [0x100210XX]
text = None
for (n, va, vs, rp, rs) in secs:
    if n == b'.text':
        text = (va, vs, rp)
        break

va, vs, rp = text
start = rp
end = rp + vs
off = start
print('=== 扫描 .text 中 GetProcAddress 绑定全局函数指针的模式 ===')
# 反汇编整个 text 段找 GetProcAddress call，回溯 push 字符串
insns = list(md.disasm(data[start:end], va))
for i, insn in enumerate(insns):
    # call [0x1002118c] = GetProcAddress (从之前 dump 得知 0x1002118c 是 GetProcAddress)
    if insn.mnemonic == 'call' and '1002118c' in insn.op_str:
        # 向前回溯找 push 的字符串（函数名）和后面的 mov [0x100210XX]
        name_str = None
        for j in range(i-1, max(0, i-8), -1):
            p = insns[j]
            if p.mnemonic == 'push' and p.op_str.startswith('0x1002'):
                name_str = cstr_rva(int(p.op_str, 16) - imgbase)
                break
        # 向后找 mov [0x100210XX], eax
        store_target = None
        for j in range(i+1, min(len(insns), i+6)):
            p = insns[j]
            if p.mnemonic == 'mov' and p.op_str.startswith('dword ptr [0x100210'):
                # 提取目标地址
                t = p.op_str.split('0x')[-1].split(']')[0]
                store_target = '0x' + t
                break
        if name_str and store_target:
            print('  %s  <- %s' % (store_target, name_str))
