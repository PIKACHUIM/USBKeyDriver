import idautils
import ida_segment
import ida_bytes
import ida_nalt
import idc

out = open(r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\dbg.txt", "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


w("file=%s" % ida_nalt.get_input_file_path())
w("base=0x%X" % ida_nalt.get_imagebase())
segs = list(idautils.Segments())
w("segments=%d" % len(segs))
for ea in segs:
    s = ida_segment.getseg(ea)
    name = ida_segment.get_segm_name(s)
    n = s.end_ea - s.start_ea
    b = ida_bytes.get_bytes(s.start_ea, min(16, n))
    w("%-10s %08X-%08X size=0x%X type=%d first=%s" % (name, s.start_ea, s.end_ea, n, s.type,
      " ".join("%02X" % x for x in b) if b else "None"))

w("")
w("qty via get_segm_qty=%d" % ida_segment.get_segm_qty())

# direct probe: where should 'CMBC' appear?
blob = ida_bytes.get_bytes(0x400000, 0x1000)
w("get_bytes(0x400000,0x1000)=%s" % ("None" if blob is None else "ok len=%d" % len(blob)))

# raw scan of the whole image
total = 0
for ea in segs:
    s = ida_segment.getseg(ea)
    n = s.end_ea - s.start_ea
    off = 0
    while off < n:
        sz = min(0x10000, n - off)
        b = ida_bytes.get_bytes(s.start_ea + off, sz)
        if b:
            total += b.count(b"CMBC")
        off += sz
w("raw count of b'CMBC' via get_bytes = %d" % total)

# try reading via ida_bytes.get_bytes on the .rdata/.data segment fully
for ea in segs:
    s = ida_segment.getseg(ea)
    name = ida_segment.get_segm_name(s)
    if name in (".rsrc", ".data", ".rdata"):
        b = ida_bytes.get_bytes(s.start_ea, s.end_ea - s.start_ea)
        w("full get_bytes(%s) -> %s, count CMBC=%s" % (
            name, "None" if b is None else len(b), "n/a" if b is None else b.count(b"CMBC")))

out.close()
idc.qexit(0)
