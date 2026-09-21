# IDA batch: CMBCp.dll PKCS#11 analysis.
#   - full autoanalysis of .text
#   - resolve export jmp thunks to real implementations
#   - report calling convention (ret imm16)
#   - decompile the key entry points
import ida_auto
import ida_entry
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_typeinf
import idautils
import idc

OUT = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\CMBCp_p11.txt"

TEXT_START = 0x10001000
TEXT_END = 0x1002E000

KEY = [
    "C_Initialize", "C_Finalize", "C_GetFunctionList", "C_GetInfo",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo",
    "C_OpenSession", "C_CloseSession", "C_Login", "C_Logout",
    "C_SetPIN", "C_InitPIN", "C_InitToken",
    "C_GetAttributeValue", "C_SetAttributeValue",
    "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
    "C_CreateObject", "C_DestroyObject", "C_GenerateKeyPair",
    "C_SignInit", "C_Sign", "C_GetMechanismList",
]

out = open(OUT, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


w("file=%s" % ida_nalt.get_input_file_path())
w("base=0x%X" % ida_nalt.get_imagebase())
w("")

ida_auto.plan_and_wait(TEXT_START, TEXT_END)
w("plan_and_wait done")


def make_func(ea):
    f = ida_funcs.get_func(ea)
    if f is None:
        try:
            idc.create_insn(ea)
        except Exception:
            pass
        try:
            ida_funcs.add_func(ea)
        except Exception:
            pass
        f = ida_funcs.get_func(ea)
    return f


def ret_imm(f):
    """Scan the function body for the final 'ret' -> tells the calling convention.
    0 => plain 'ret' (cdecl) , N>0 => 'ret N' (stdcall, N bytes of args)."""
    if f is None:
        return None
    ea = f.start_ea
    guard = 0
    while ea < f.end_ea and guard < 4000:
        guard += 1
        mn = idc.print_insn_mnem(ea)
        if mn in ("retn", "ret"):
            if idc.get_operand_type(ea, 0) == idc.o_void:
                return 0
            return idc.get_operand_value(ea, 0)
        ea = idc.next_head(ea)
    return None


def jmp_target(ea):
    try:
        idc.create_insn(ea)
    except Exception:
        pass
    if idc.print_insn_mnem(ea) == "jmp":
        if idc.get_operand_type(ea, 0) == idc.o_near:
            return idc.get_operand_value(ea, 0)
        if idc.get_operand_type(ea, 0) == idc.o_mem:
            import ida_bytes
            p = idc.get_operand_value(ea, 0)
            t = ida_bytes.get_dword(p)
            if t:
                return t
    return None


w("")
w("=== EXPORT TABLE (stub -> real, calling convention) ===")
info = {}
qty = ida_entry.get_entry_qty()
for i in range(qty):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    nm = ida_entry.get_entry_name(ordv)
    tgt = jmp_target(ea)
    real = tgt if tgt else ea
    f = make_func(real)
    ri = ret_imm(f)
    info[nm] = (ea, real)
    w("%-28s stub=%08X real=%08X func=%s ret_imm=%s %s" % (
        nm, ea, real,
        ("%08X-%08X" % (f.start_ea, f.end_ea)) if f else "None",
        ri,
        ("cdECL" if ri == 0 else ("STDCALL(%d args)" % (ri // 4) if (ri and ri % 4 == 0) else "?%s" % ri)) if ri is not None else ""))

w("")
ida_auto.auto_wait()

w("=== DECOMPILED KEY FUNCTIONS ===")
for nm in KEY:
    if nm not in info:
        w("\n### %s : NOT EXPORTED" % nm)
        continue
    stub, real = info[nm]
    f = ida_funcs.get_func(real)
    w("\n" + "=" * 74)
    w("### %s  stub=0x%X real=0x%X" % (nm, stub, real))
    w("=" * 74)
    if f is None:
        w("(no function)")
        continue
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        w(str(cf) if cf else "(None)")
    except Exception as ex:
        w("(decompile failed: %s)" % ex)
        cur = f.start_ea
        for _ in range(50):
            w("  0x%X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
            nxt = idc.next_head(cur)
            if nxt <= cur:
                break
            cur = nxt

out.close()
idc.qexit(0)
