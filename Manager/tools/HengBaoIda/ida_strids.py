# IDA batch: find code that references known resource-string IDs (immediates),
# then decompile the enclosing functions.
# Target ids are read from strids.txt (one decimal or 0x-hex id per line).
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_segment
import idautils
import idc

OUT = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\CMBCu_strids.txt"
IDS_FILE = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\strids.txt"

targets = {}
for ln in open(IDS_FILE, "r", encoding="utf-8"):
    ln = ln.strip()
    if not ln or ln.startswith("#"):
        continue
    parts = ln.split()
    val = int(parts[0], 0)
    targets[val] = parts[1] if len(parts) > 1 else ""

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


w("file=%s" % ida_nalt.get_input_file_path())
for _seg in idautils.Segments():
    _s = ida_segment.getseg(_seg)
    if _s.type == ida_segment.SEG_CODE:
        ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
ida_auto.auto_wait()
w("analysis done")
w("targets: %s" % ", ".join("%d(%s)" % (k, v) for k, v in sorted(targets.items())))

# collect hits
hits = {}
for seg in idautils.Segments():
    s = ida_segment.getseg(seg)
    if s.type != ida_segment.SEG_CODE:
        continue
    ea = s.start_ea
    n = 0
    while ea < s.end_ea:
        n += 1
        if n % 200000 == 0:
            out.flush()
        for i in range(3):
            if idc.get_operand_type(ea, i) == idc.o_imm:
                v = idc.get_operand_value(ea, i)
                if v in targets:
                    f = ida_funcs.get_func(ea)
                    key = f.start_ea if f else ea
                    hits.setdefault((key, v), []).append(ea)
        nxt = idc.next_head(ea)
        ea = nxt if nxt > ea else ea + 1

w("hits: %d" % len(hits))
for (fea, v), sites in sorted(hits.items()):
    w("  func %08X  id=%d(%s)  sites=%s" % (
        fea, v, targets[v], ", ".join("%08X" % x for x in sites[:6])))

w("")
w("=== DECOMPILED ===")
done = set()
for (fea, v) in sorted(hits.keys()):
    if fea in done:
        continue
    done.add(fea)
    f = ida_funcs.get_func(fea)
    w("\n" + "=" * 74)
    w("### FUNC %08X (%s)" % (fea, idc.get_func_name(fea)))
    w("=" * 74)
    if not f:
        w("(no function)")
        continue
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)

out.close()
idc.qexit(0)
