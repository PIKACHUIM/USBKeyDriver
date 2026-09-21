"""Full disassembly of USBKey_Reset and USBKey_InitKey with register operand detail."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll"

def parse_pe(path):
    data = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = magic == 0x20b
    dd_off = opt + (112 if is64 else 96)
    exp_rva, _ = struct.unpack_from('<II', data, dd_off)
    sec_off = opt + size_opt
    sections = []
    for i in range(num_sections):
        s = sec_off + i*40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii','replace')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s+8)
        sections.append((name, vaddr, vsize, rawptr, rawsize))
    def rva2off(rva):
        for (n, va, vs, rp, rs) in sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None
    return data, rva2off

def disasm(data, rva2off, rva, count=120):
    off = rva2off(rva)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = data[off:off+count*15]
    return list(md.disasm(code, rva))[:count]

def show(name, rva, data, rva2off):
    print("="*90)
    print(f"{name}  (RVA 0x{rva:X})")
    print("="*90)
    for insn in disasm(data, rva2off, rva, 120):
        ops = []
        for op in insn.operands:
            if op.type == 1:  # reg
                ops.append(f"reg:{insn.reg_name(op.reg)}")
            elif op.type == 2:  # imm
                ops.append(f"imm:0x{op.imm:X}")
            elif op.type == 3:  # mem
                base = insn.reg_name(op.mem.base) if op.mem.base else ''
                idx = insn.reg_name(op.mem.index) if op.mem.index else ''
                scale = op.mem.scale if op.mem.scale > 1 else ''
                disp = op.mem.disp
                s = ''
                if base: s += base
                if idx: s += ('+' if s else '') + idx
                if scale: s += f"*{scale}"
                if disp: s += f"{'+' if disp>0 and s else ''}0x{disp:X}" if s else f"0x{disp:X}"
                ops.append(f"mem:[{s}]")
        line = f"  0x{insn.address:08X}  {insn.mnemonic:<7} {insn.op_str}"
        print(line)
    print()

data, rva2off = parse_pe(DLL)
show("USBKey_Reset",    0x4400, data, rva2off)
show("USBKey_InitKey",  0x42B0, data, rva2off)
show("USBKey_GetDevState", 0x4300, data, rva2off)
show("USBKey_VerifyPin", 0x4440, data, rva2off)
