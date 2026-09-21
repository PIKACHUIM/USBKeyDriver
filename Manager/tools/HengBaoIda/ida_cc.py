# IDA batch: report calling convention (ret imm) for every C_* export.
import ida_auto
import ida_entry
import ida_funcs
import ida_segment
import idautils
import idc

_args = list(idc.ARGV) if hasattr(idc, "ARGV") else []
OUT = _args[1] if len(_args) > 1 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\cc.txt"

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


for _seg in idautils.Segments():
    _s = ida_segment.getseg(_seg)
    if _s.type == ida_segment.SEG_CODE:
        ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
ida_auto.auto_wait()


def resolve(ea):
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
            import ida_bytes
            t = ida_bytes.get_dword(idc.get_operand_value(ea, 0))
        if not t or t == ea:
            break
        ea = t
    return ea


def ret_imm(f):
    if not f:
        return None
    ea = f.start_ea
    for _ in range(4000):
        if ea >= f.end_ea:
            break
        mn = idc.print_insn_mnem(ea)
        if mn in ("retn", "ret"):
            if idc.get_operand_type(ea, 0) == idc.o_void:
                return 0
            return idc.get_operand_value(ea, 0)
        nxt = idc.next_head(ea)
        if nxt <= ea:
            break
        ea = nxt
    return None


cnt = {"cdecl": 0, "stdcall": 0, "other": 0}
qty = ida_entry.get_entry_qty()
w("FILE %s" % idc.get_input_file_path())
for i in range(qty):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    nm = ida_entry.get_entry_name(ordv)
    if not nm.startswith("C_"):
        continue
    real = resolve(ea)
    if ida_funcs.get_func(real) is None:
        ida_funcs.add_func(real)
    ri = ret_imm(ida_funcs.get_func(real))
    kind = "?" if ri is None else ("cdecl" if ri == 0 else ("stdcall(%d args)" % (ri // 4) if ri % 4 == 0 else "other"))
    cnt["cdecl" if kind == "cdecl" else ("stdcall" if kind.startswith("stdcall") else "other")] += 1
    w("%-34s real=%08X ret=%s  %s" % (nm, real, ri, kind))
w("SUMMARY cdecl=%d stdcall=%d other=%d" % (cnt["cdecl"], cnt["stdcall"], cnt["other"]))
out.close()
idc.qexit(0)
