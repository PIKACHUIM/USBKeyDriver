# IDA batch: dump raw disassembly for address ranges listed in ranges.txt
#   ranges.txt lines: 0xSTART 0xEND  NAME
import idc
import ida_auto
import ida_funcs

RANGES = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\ranges.txt"
OUT = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\ranges_out.txt"

out = open(OUT, "w", encoding="utf-8")
out.write("file=%s\n" % idc.get_input_file_path())

# Force full autoanalysis of the code segment before disassembling.
try:
    ida_auto.plan_and_wait(0x10001000, 0x1002E000)
except Exception as ex:
    out.write("plan_and_wait failed: %s\n" % ex)

with open(RANGES, "r", encoding="utf-8") as f:
    for ln in f:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        start = int(parts[0], 16)
        end = int(parts[1], 16)
        name = parts[2] if len(parts) > 2 else ""
        out.write("\n" + "=" * 70 + "\n### %s  %08X-%08X\n" % (name, start, end) + "=" * 70 + "\n")
        try:
            ida_funcs.add_func(start, end)
        except Exception:
            pass
        ea = start
        while ea < end:
            if idc.print_insn_mnem(ea) == "":
                try:
                    idc.create_insn(ea)
                except Exception:
                    pass
            out.write("  %08X  %s\n" % (ea, idc.generate_disasm_line(ea, 0)))
            nxt = idc.next_head(ea)
            if nxt <= ea:
                ea += 1
            else:
                ea = nxt

out.close()
idc.qexit(0)
