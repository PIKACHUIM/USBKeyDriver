# IDA batch script v2: resolve PKCS#11 export thunks, define functions, decompile.
import ida_entry
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_typeinf
import ida_bytes
import idautils
import idc

args = idc.ARGV if hasattr(idc, "ARGV") else []
out_path = args[1] if len(args) > 1 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\report2.txt"

out = open(out_path, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


def resolve_target(ea, depth=0):
    """Follow jmp thunks (direct or via pointer) to the real implementation."""
    seen = 0
    while seen < 4:
        seen += 1
        mn = idc.print_insn_mnem(ea)
        if mn != "jmp":
            break
        op_type = idc.get_operand_type(ea, 0)
        if op_type == idc.o_near:
            t = idc.get_operand_value(ea, 0)
        elif op_type == idc.o_mem:
            t = idc.get_wide_dword(idc.get_operand_value(ea, 0))
        elif op_type == idc.o_imm:
            t = idc.get_operand_value(ea, 0)
        else:
            break
        if not t or t == ea:
            break
        ea = t
    return ea


qty = ida_entry.get_entry_qty()
w("=== EXPORT THUNKS ===")
targets = {}
for i in range(qty):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    nm = ida_entry.get_entry_name(ordv)
    dis = " | ".join(
        idc.generate_disasm_line(h, 0)
        for h in idautils.Heads(ea, min(ea + 24, ea + 24))
    )
    real = resolve_target(ea)
    targets[nm] = (ea, real)
    w("%-30s stub=%08X real=%08X   %s" % (nm, ea, real, dis))

w("")
w("=== STRINGS (interesting) ===")
kw = [
    "pin", "pass", "reset", "erase", "clear", "init", "so", "admin", "puk",
    "cmd", "hid", "usb", "cos", "verify", "lock", "unlock", "retry", "counter",
    "cmbc", "hb", "uranu", "skf", "csp", "serial", "flash", "format", "key",
]
try:
    for s in idautils.Strings():
        txt = str(s)
        low = txt.lower()
        if any(k in low for k in kw) and 3 <= len(txt) <= 90:
            w("%08X  %s" % (s.ea, txt))
except Exception as ex:
    w("(strings failed: %s)" % ex)

out.flush()

w("")
w("=== DECOMPILED ===")
for nm in sorted(targets.keys()):
    stub, real = targets[nm]
    if not nm.startswith("C_"):
        continue
    f = ida_funcs.get_func(real)
    if f is None:
        try:
            idc.create_insn(real)
            ida_funcs.add_func(real)
        except Exception:
            pass
        f = ida_funcs.get_func(real)
    w("\n" + "=" * 72)
    w("### %s   stub=0x%X real=0x%X  func=%s" % (nm, stub, real, f))
    w("=" * 72)
    if f is None:
        cur = real
        for _ in range(40):
            w("  0x%X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt
        continue
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)
        cur = f.start_ea
        for _ in range(60):
            w("  0x%X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt

out.close()
idc.qexit(0)
