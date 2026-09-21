# IDA batch: 找到所有 DeviceIoControl 调用点并反编译，用于对比不同模块的 SCSI 透传参数。
import ida_auto
import ida_funcs
import ida_hexrays
import ida_segment
import idautils
import idc

_args = list(idc.ARGV) if hasattr(idc, "ARGV") else []
OUT = _args[1] if len(_args) > 1 else r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\ioctl_out.txt"

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


for _seg in idautils.Segments():
    _s = ida_segment.getseg(_seg)
    if _s.type == ida_segment.SEG_CODE:
        ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
ida_auto.auto_wait()

targets = []
for ea, name in idautils.Names():
    if "DeviceIoControl" in name:
        targets.append((ea, name))
w("found %d DeviceIoControl-ish symbols" % len(targets))
for ea, name in targets:
    w("  %08X  %s" % (ea, name))

callers = {}
for ea, name in targets:
    for xr in idautils.XrefsTo(ea):
        f = ida_funcs.get_func(xr.frm)
        if f:
            callers.setdefault(f.start_ea, []).append(xr.frm)
w("distinct caller functions: %d" % len(callers))
for c in sorted(callers):
    w("  %08X  (call sites: %s)" % (c, ", ".join("%08X" % x for x in callers[c])))

for c in sorted(callers):
    w("\n" + "=" * 74)
    w("### %08X" % c)
    w("=" * 74)
    try:
        cf = ida_hexrays.decompile(c)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)
    # 同时打印原始反汇编，便于确认 CDB 常量
    f = ida_funcs.get_func(c)
    ea = f.start_ea if f else c
    end = f.end_ea if f else c + 0x400
    n = 0
    while ea < end and n < 400:
        w("  %08X  %s" % (ea, idc.generate_disasm_line(ea, 0)))
        nxt = idc.next_head(ea)
        if nxt <= ea:
            break
        ea = nxt
        n += 1

out.close()
idc.qexit(0)
