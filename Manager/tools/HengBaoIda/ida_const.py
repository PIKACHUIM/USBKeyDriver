# IDA batch: find instructions that reference given immediates (hex, one per line in consts.txt),
# then decompile the enclosing functions (optionally the callees too).
import ida_auto
import ida_funcs
import ida_hexrays
import ida_segment
import idautils
import idc

CONSTS = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\consts.txt"
OUT = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\consts_out.txt"

targets = []
for ln in open(CONSTS, "r", encoding="utf-8"):
    ln = ln.strip()
    if ln and not ln.startswith("#"):
        targets.append(int(ln.split()[0], 0))

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


for _seg in idautils.Segments():
    _s = ida_segment.getseg(_seg)
    if _s.type == ida_segment.SEG_CODE:
        ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
ida_auto.auto_wait()

hits = {}
for seg in idautils.Segments():
    s = ida_segment.getseg(seg)
    if s.type != ida_segment.SEG_CODE:
        continue
    ea = s.start_ea
    while ea < s.end_ea:
        for i in range(3):
            if idc.get_operand_type(ea, i) == idc.o_imm:
                v = idc.get_operand_value(ea, i)
                if v in targets:
                    f = ida_funcs.get_func(ea)
                    hits.setdefault((f.start_ea if f else ea, v), []).append(ea)
        nxt = idc.next_head(ea)
        ea = nxt if nxt > ea else ea + 1

w("=== IMMEDIATE HITS ===")
for (fea, v), sites in sorted(hits.items()):
    w("  0x%X in func %08X (%s)  sites=%s" % (v, fea, idc.get_func_name(fea), ", ".join("%08X" % x for x in sites)))

w("")
w("=== CONTEXT DISASM ===")
for (fea, v), sites in sorted(hits.items()):
    for site in sites[:2]:
        w("\n--- 0x%X @ %08X (func %08X) ---" % (v, site, fea))
        cur = site
        for _ in range(6):
            prev = idc.prev_head(cur)
            if prev <= 0:
                break
            cur = prev
        for _ in range(14):
            mark = "  <<<" if cur == site else ""
            w("  %08X  %s%s" % (cur, idc.generate_disasm_line(cur, 0), mark))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt

w("")
w("=== DECOMPILED FUNCS ===")
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
        continue
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)

out.close()
idc.qexit(0)
