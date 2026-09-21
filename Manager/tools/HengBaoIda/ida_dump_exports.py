# IDA batch script: dump exports + (optionally) decompile PKCS#11 entry points.
# Usage: idat.exe -A -c -S"ida_dump_exports.py <outfile>" CMBCp.dll
import sys
import ida_entry
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_typeinf
import idc

args = idc.ARGV if hasattr(idc, "ARGV") else []
out_path = args[1] if len(args) > 1 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\report.txt"

out = open(out_path, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


def gtype(ea):
    try:
        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, ea):
            return str(tif)
    except Exception:
        pass
    return "?"


w("FILE: %s" % ida_nalt.get_input_file_path())
w("IMAGEBASE: 0x%X" % ida_nalt.get_imagebase())
w("")

w("=== EXPORTS ===")
qty = ida_entry.get_entry_qty()
names = []
for i in range(qty):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    nm = ida_entry.get_entry_name(ordv)
    names.append((ea, nm))
    w("ord=%-6d ea=%08X name=%s" % (ordv, ea, nm))

w("")
w("=== PROTOTYPES / STD CALL CHECK ===")
for ea, nm in sorted(names, key=lambda x: x[0]):
    f = ida_funcs.get_func(ea)
    if not f:
        w("%-42s ea=%08X  (no function)" % (nm, ea))
        continue
    w("%-42s ea=%08X end=%08X proto=%s" % (nm, ea, f.end_ea, gtype(ea)))

w("")
w("=== DECOMPILED (C_*) ===")
for ea, nm in sorted(names, key=lambda x: x[0]):
    if not nm.startswith("C_"):
        continue
    w("\n" + "=" * 70)
    w("### %s  @ 0x%X" % (nm, ea))
    w("=" * 70)
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            w(str(cf))
        else:
            w("(decompile returned None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)
        cur = ea
        for _ in range(60):
            w("  0x%X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt

out.close()
idc.qexit(0)
