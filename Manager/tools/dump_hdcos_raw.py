"""Correct raw dump of HDCOS_LNCA.dll export directory."""
import struct

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

o = r2o(er)
ch, ts, major, minor, name_rva, base, nfuncs, nnames, af, an, ao = struct.unpack_from('<IIIIIIIIIII', data, o)
print("Name RVA=0x%X" % name_rva)
print("Ordinal base=%d" % base)
print("NumberOfFunctions=%d" % nfuncs)
print("NumberOfNames=%d" % nnames)
print("AddressOfFunctions RVA=0x%X" % af)
print("AddressOfNames RVA=0x%X" % an)
print("AddressOfNameOrdinals RVA=0x%X" % ao)

eat_off = r2o(af)
ent_off = r2o(an)
eot_off = r2o(ao)

print("\n--- Exports (ordinal, name, RVA) ---")
for i in range(nnames):
    nr = struct.unpack_from('<I', data, ent_off+i*4)[0]
    noff = r2o(nr)
    nm = data[noff:data.find(b'\0', noff)].decode('ascii','replace') if noff else '?'
    ordidx = struct.unpack_from('<H', data, eot_off+i*2)[0]
    rva = struct.unpack_from('<I', data, eat_off+ordidx*4)[0]
    print("  ord %3d  %-34s RVA=0x%08X" % (base+ordidx, nm, rva))
