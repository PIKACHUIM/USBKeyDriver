"""Pure-Python PE export table parser (no dependencies).

Reads the export directory of a PE file and prints (ordinal, name, RVA)
for every exported symbol. This definitively answers whether a DLL exports
by name or by ordinal only.
"""
import struct
import sys

def parse_pe_exports(path):
    with open(path, 'rb') as f:
        data = f.read()

    # DOS header
    if data[:2] != b'MZ':
        print("Not a PE file (no MZ)")
        return
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]

    # PE header
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print("No PE signature")
        return
    coff = e_lfanew + 4
    machine = struct.unpack_from('<H', data, coff)[0]
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20

    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = (magic == 0x20b)
    # Data directories offset: PE32 -> opt+96, PE32+ -> opt+112
    dd_off = opt + (112 if is64 else 96)
    export_rva, export_size = struct.unpack_from('<II', data, dd_off)

    if export_rva == 0:
        print("No export directory (empty)")
        return

    # section table
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

    exp_off = rva2off(export_rva)
    if exp_off is None:
        print("Cannot map export RVA 0x%X" % export_rva)
        return

    nfuncs, nnames, base = struct.unpack_from('<III', data, exp_off + 16)
    addr_rva  = struct.unpack_from('<I', data, exp_off + 28)[0]  # EAT
    name_rva  = struct.unpack_from('<I', data, exp_off + 32)[0]  # ENT
    ord_rva   = struct.unpack_from('<I', data, exp_off + 36)[0]  # EOT
    dllname_rva = struct.unpack_from('<I', data, exp_off + 12)[0]

    dllname_off = rva2off(dllname_rva)
    dllname = data[dllname_off:data.find(b'\x00', dllname_off)].decode() if dllname_off else '?'

    print("DLL name        : %s" % dllname)
    print("Machine         : 0x%X (%s)" % (machine, 'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else '?'))
    print("NumberOfFunctions: %d" % nfuncs)
    print("NumberOfNames    : %d" % nnames)
    print("Ordinal base     : %d" % base)
    print("-" * 60)

    # EAT array (function RVAs indexed by ordinal-base)
    eat_off = rva2off(addr_rva)
    eat = [struct.unpack_from('<I', data, eat_off + i*4)[0] for i in range(nfuncs)]

    # ENT array (name RVAs)
    ent_off = rva2off(name_rva)
    names_rva = [struct.unpack_from('<I', data, ent_off + i*4)[0] for i in range(nnames)]

    # EOT array (ordinal indexes into EAT)
    eot_off = rva2off(ord_rva)
    eot = [struct.unpack_from('<H', data, eot_off + i*2)[0] for i in range(nnames)]

    # Build name -> ordinal map
    name_to_ord = {}
    for i in range(nnames):
        off = rva2off(names_rva[i])
        name = data[off:data.find(b'\x00', off)].decode('ascii', 'replace')
        ordinal = base + eot[i]
        name_to_ord[ordinal] = name

    print("Exported symbols (ordinal, name, RVA):")
    for i in range(nfuncs):
        ordinal = base + i
        rva = eat[i]
        name = name_to_ord.get(ordinal, '(NO NAME)')
        print("  ord %3d  %-40s RVA=0x%08X" % (ordinal, name, rva))

    no_name = sum(1 for i in range(nfuncs) if (base+i) not in name_to_ord)
    print("-" * 60)
    print("Total functions: %d, named: %d, ordinal-only (no name): %d" % (nfuncs, nnames, no_name))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python dump_exports_pure.py <dll>")
        sys.exit(1)
    parse_pe_exports(sys.argv[1])
