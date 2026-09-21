# IDA batch: decompile a list of function addresses (funcs.txt: one 0xADDR per line).
import ida_auto
import ida_funcs
import ida_hexrays
import ida_segment
import idautils
import idc

_args = list(idc.ARGV) if hasattr(idc, "ARGV") else []
OUT = _args[1] if len(_args) > 1 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\funcs_out.txt"
FUNCS = _args[2] if len(_args) > 2 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\funcs.txt"

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


for _seg in idautils.Segments():
    _s = ida_segment.getseg(_seg)
    if _s.type == ida_segment.SEG_CODE:
        ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
ida_auto.auto_wait()
w("analysis done")

for ln in open(FUNCS, "r", encoding="utf-8"):
    ln = ln.strip()
    if not ln or ln.startswith("#"):
        continue
    parts = ln.split()
    ea = int(parts[0], 0)
    note = parts[1] if len(parts) > 1 else ""
    # follow jmp thunks to the real body
    for _ in range(4):
        try:
            idc.create_insn(ea)
        except Exception:
            pass
        if idc.print_insn_mnem(ea) != "jmp":
            break
        t = None
        if idc.get_operand_type(ea, 0) == idc.o_near:
            t = idc.get_operand_value(ea, 0)
        elif idc.get_operand_type(ea, 0) == idc.o_mem:
            import ida_bytes as _ib
            t = _ib.get_dword(idc.get_operand_value(ea, 0))
        if not t or t == ea:
            break
        ea = t
    f = ida_funcs.get_func(ea)
    if not f:
        try:
            idc.create_insn(ea)
            ida_funcs.add_func(ea)
        except Exception:
            pass
        f = ida_funcs.get_func(ea)
    w("\n" + "=" * 74)
    w("### %08X %s  func=%s" % (ea, note, ("%08X-%08X" % (f.start_ea, f.end_ea)) if f else "None"))
    w("=" * 74)
    if not f:
        w("(no function)")
        continue
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)
        cur = f.start_ea
        for _ in range(120):
            w("  0x%X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt

out.close()
idc.qexit(0)
