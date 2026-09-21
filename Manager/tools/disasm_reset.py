"""Disassemble LNCA JIT_USBKEY_HD.dll exported functions to recover exact signatures.

Goal: determine the real signatures (calling convention, parameter count/types)
of USBKey_Reset (ord 69, RVA 0x4400), USBKey_InitKey (ord 63, RVA 0x42B0) and
their neighbours, by inspecting the x86 prologue/epilogue and how many bytes
they pop off the stack (ret imm16 => __stdcall) and which registers they read.

Author: analysis script
"""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll"

def parse_pe(path):
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = magic == 0x20b
    dd_off = opt + (112 if is64 else 96)
    exp_rva, exp_size = struct.unpack_from('<II', data, dd_off)
    sec_off = opt + size_opt
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', 'replace')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, s + 8)
        sections.append((name, vaddr, vsize, rawptr, rawsize))
    def rva2off(rva):
        for (name, vaddr, vsize, rawptr, rawsize) in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None
    # image base
    imgbase = struct.unpack_from('<I', data, opt + 28)[0]  # ImageBase (PE32)
    return data, sections, rva2off, imgbase, exp_rva, exp_size

def get_exports(data, sections, rva2off, exp_rva, exp_size):
    exp_off = rva2off(exp_rva)
    nfuncs, nnames, base = struct.unpack_from('<III', data, exp_off + 16)
    addr_rva = struct.unpack_from('<I', data, exp_off + 28)[0]
    name_rva = struct.unpack_from('<I', data, exp_off + 32)[0]
    ord_rva  = struct.unpack_from('<I', data, exp_off + 36)[0]
    eat_off = rva2off(addr_rva)
    ent_off = rva2off(name_rva)
    eot_off = rva2off(ord_rva)
    names_rva = [struct.unpack_from('<I', data, ent_off + i*4)[0] for i in range(nnames)]
    eot = [struct.unpack_from('<H', data, eot_off + i*2)[0] for i in range(nnames)]
    name_to_ord = {}
    for i in range(nnames):
        off = rva2off(names_rva[i])
        nm = data[off:data.find(b'\x00', off)].decode('ascii', 'replace')
        name_to_ord[base + eot[i]] = nm
    exports = {}
    for i in range(nfuncs):
        ordn = base + i
        rva = struct.unpack_from('<I', data, eat_off + i*4)[0]
        exports[ordn] = (name_to_ord.get(ordn), rva)
    return exports

def disasm(data, rva2off, rva, count=80):
    off = rva2off(rva)
    if off is None:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = data[off:off+count*15]
    out = []
    for insn in md.disasm(code, rva):
        out.append(insn)
        if len(out) >= count:
            break
    return out

def analyze_function(name, rva, data, rva2off):
    print("=" * 78)
    print(f"FUNCTION: {name}   (RVA 0x{rva:X})")
    print("=" * 78)
    insns = disasm(data, rva2off, rva, count=60)
    # print first ~45 instructions
    for insn in insns[:45]:
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}")
    print()

def main():
    data, sections, rva2off, imgbase, exp_rva, exp_size = parse_pe(DLL)
    exports = get_exports(data, sections, rva2off, exp_rva, exp_size)

    # print all named exports with rva for reference
    print("Named exports:")
    for ordn in sorted(exports):
        nm, rva = exports[ordn]
        if nm:
            print(f"  ord {ordn:3d}  {nm:<32} RVA=0x{rva:X}")
    print()

    # find the ones we care about
    targets = {}
    for ordn, (nm, rva) in exports.items():
        if nm in ("USBKey_Reset", "USBKey_InitKey", "USBKey_GetDevState",
                  "USBKey_GetKeySN", "USBKey_ListKey", "USBKey_EKeyCopy"):
            targets[nm] = rva

    for nm in ("USBKey_InitKey", "USBKey_GetDevState", "USBKey_Reset", "USBKey_GetKeySN"):
        if nm in targets:
            analyze_function(nm, targets[nm], data, rva2off)

if __name__ == '__main__':
    main()
