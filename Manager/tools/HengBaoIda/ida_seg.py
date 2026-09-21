import ida_segment
import ida_bytes
import idautils
import idc

out = open(r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\CMBCp_seg.txt", "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


w("=== SEGMENTS ===")
for seg in idautils.Segments():
    s = ida_segment.getseg(seg)
    w("%-8s start=%08X end=%08X perm=%X class=%s" % (ida_segment.get_segm_name(s), s.start_ea, s.end_ea, s.perm, s.type))

w("")
w("=== HEX 0x10001000-0x10001100 ===")
for ea in range(0x10001000, 0x10001100, 16):
    bs = ida_bytes.get_bytes(ea, 16) or b""
    w("%08X  %s" % (ea, " ".join("%02X" % b for b in bs)))

w("")
w("=== first bytes of each segment ===")
for seg in idautils.Segments():
    s = ida_segment.getseg(seg)
    bs = ida_bytes.get_bytes(s.start_ea, 32) or b""
    w("%-8s %08X %s" % (ida_segment.get_segm_name(s), s.start_ea, " ".join("%02X" % b for b in bs)))

out.close()
idc.qexit(0)
