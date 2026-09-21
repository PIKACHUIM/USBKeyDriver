"""Dump import table of HD_HardAPI.dll to understand HSErase's downstream chain."""
import struct

def dump(path):
    data = open(path,'rb').read()
    e = struct.unpack_from('<I', data, 0x3C)[0]
    coff = e+4
    ns = struct.unpack_from('<H', data, coff+2)[0]
    so = struct.unpack_from('<H', data, coff+16)[0]
    opt = coff+20
    magic = struct.unpack_from('<H', data, opt)[0]
    is64 = magic == 0x20b
    dd = opt + (112 if is64 else 96)
    imp_rva, imp_size = struct.unpack_from('<II', data, dd + 8)
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
    print("="*70)
    print(path.split('\\')[-1])
    print("="*70)
    off = r2o(imp_rva)
    i = 0
    while off is not None and i < 50:
        oft, ts, fc, name_rva, ft = struct.unpack_from('<IIIII', data, off)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        no = r2o(name_rva)
        dll = data[no:data.find(b'\0', no)].decode('ascii')
        print(f"[{dll}]")
        to = r2o(oft if oft else ft)
        while to is not None:
            thunk = struct.unpack_from('<I', data, to)[0]
            if thunk == 0: break
            if thunk & 0x80000000:
                print(f"    ord #{thunk & 0xffff}")
            else:
                hno = r2o(thunk)
                nm = data[hno+2:data.find(b'\0', hno+2)].decode('ascii')
                print(f"    {nm}")
            to += 4
        off += 20
        i += 1

dump(r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\HD_HardAPI.dll")
