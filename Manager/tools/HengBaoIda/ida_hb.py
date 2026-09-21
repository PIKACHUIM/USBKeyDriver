# IDA batch script: imports + exports(+thunk resolve) + locate strings and decompile their users.
# Usage: idat.exe -A -c -S"ida_hb.py <outfile> <kw1> <kw2> ..." target
import ida_entry
import idautils
import ida_segment
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_search
import ida_ua
import ida_xref
import idc

args = list(idc.ARGV) if hasattr(idc, "ARGV") else []
out_path = args[1] if len(args) > 1 else "hb_out.txt"
keywords = args[2:]
_kw_file = r"g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda\hb_keywords.txt"
import os as _os
if _os.path.isfile(_kw_file):
    with open(_kw_file, "r", encoding="utf-8") as _f:
        keywords = [ln.strip() for ln in _f if ln.strip()]

out = open(out_path, "w", encoding="utf-8")


def w(s=""):
    out.write(str(s) + "\n")


w("FILE: %s" % ida_nalt.get_input_file_path())
w("IMAGEBASE: 0x%X" % ida_nalt.get_imagebase())
w("")

w("=== WAITING FOR AUTOANALYSIS ===")
try:
    ida_auto.auto_wait()
    for _seg in idautils.Segments():
        _s = ida_segment.getseg(_seg)
        if _s.type == ida_segment.SEG_CODE:
            ida_auto.plan_and_wait(_s.start_ea, _s.end_ea)
except Exception as _ex:
    w("auto_wait failed: %s" % _ex)
w("done")

# ---------- imports ----------
w("=== IMPORTS ===")
nimps = ida_nalt.get_import_module_qty()
for i in range(nimps):
    mod = ida_nalt.get_import_module_name(i)

    def cb(ea, name, ordinal):
        w("  %-24s %08X %s" % (mod, ea, name if name else "#%d" % ordinal))
        return True

    ida_nalt.enum_import_names(i, cb)

w("")
w("=== EXPORTS ===")
qty = ida_entry.get_entry_qty()
for i in range(qty):
    ordv = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ordv)
    nm = ida_entry.get_entry_name(ordv)
    w("ord=%-6d ea=%08X name=%s" % (ordv, ea, nm))

w("")
w("=== NAMED FUNCTIONS (interesting) ===")
pat = ("Reset", "Init", "Verify", "Pin", "PIN", "Pass", "Auth", "Device",
       "Enum", "Open", "Close", "Send", "Apdu", "APDU", "Cmd", "Erase",
       "Clear", "Format", "Token", "Slot", "Comm")
for ea, name in idautils.Names():
    if any(p in name for p in pat):
        w("%08X  %s" % (ea, name))

w("")


def decode_at(ea, is16):
    if is16:
        bs = ida_bytes.get_bytes(ea, 400) or b""
        s = []
        for i in range(0, len(bs) - 1, 2):
            ch = bs[i] | (bs[i + 1] << 8)
            if ch == 0:
                break
            if 0x20 <= ch <= 0x7E or 0x3000 <= ch <= 0xFFEF or 0x4E00 <= ch <= 0x9FFF:
                s.append(chr(ch))
            else:
                break
        return "".join(s)
    else:
        bs = ida_bytes.get_bytes(ea, 300) or b""
        s = []
        for b in bs:
            if b == 0:
                break
            if 0x20 <= b <= 0x7E or b >= 0x80:
                s.append(chr(b))
            else:
                break
        return "".join(s)


_CHUNK = 0x10000
_ROLL = 64  # overlap between chunks so matches spanning a boundary are not lost


def _chunks():
    """Yield (start_ea, bytes) for all segments, tolerating uninitialized gaps."""
    for seg in idautils.Segments():
        s = ida_segment.getseg(seg)
        ea = s.start_ea
        while ea < s.end_ea:
            n = min(_CHUNK, s.end_ea - ea)
            blob = ida_bytes.get_bytes(ea, n)
            if blob is None:
                blob = bytes(ida_bytes.get_byte(ea + i) for i in range(n))
            yield ea, blob
            ea += n


def find_pattern(text):
    """Return list of (ea, is16) where the text occurs as ASCII or UTF-16LE."""
    res = []
    encodings = []
    if all(ord(c) < 128 for c in text):
        encodings.append((text.encode("latin-1"), False))
    encodings.append((text.encode("utf-16-le"), True))
    for data, is16 in encodings:
        for start, blob in _chunks():
            pos = blob.find(data)
            while pos >= 0:
                res.append((start + pos, is16))
                pos = blob.find(data, pos + 1)
    return res


def decompile_func(ea):
    f = ida_funcs.get_func(ea)
    if f is None:
        try:
            ida_ua.create_insn(ea)
            ida_funcs.add_func(ea)
        except Exception:
            pass
        f = ida_funcs.get_func(ea)
    if f is None:
        return None, None
    try:
        return f, ida_hexrays.decompile(f.start_ea)
    except Exception as ex:
        return f, "(decompile failed: %s)" % ex


w("=== KEYWORD HITS ===")
seen = set()
for kw in keywords:
    w("\n#### keyword: %s" % kw)
    hits = find_pattern(kw)
    w("   raw hits: %d" % len(hits))
    for ea, is16 in hits:
        txt = decode_at(ea, is16)
        w("   hit @%08X (utf16=%s) -> %s" % (ea, is16, txt[:60]))
        # data xrefs (string referenced by code via push offset)
        xr = list(idautils.DataRefsTo(ea))
        if not xr:
            # sometimes IDA needs a string item; create one
            try:
                if is16:
                    idc.create_strlit(ea, ea + 2 * (len(txt) + 1))
                else:
                    idc.create_strlit(ea, ea + len(txt) + 1)
            except Exception:
                pass
            xr = list(idautils.DataRefsTo(ea))
        w("      data xrefs: %s" % ", ".join("%08X" % x for x in xr))
        for x in xr:
            f, code = decompile_func(x)
            if f is None:
                w("      (xref %08X: no function)" % x)
                continue
            key = f.start_ea
            if key in seen:
                w("      (func %08X already dumped)" % key)
                continue
            seen.add(key)
            w("\n" + "=" * 70)
            w("### FUNC @%08X  (refs string %s)" % (key, kw))
            w("=" * 70)
            w(code)

out.close()
idc.qexit(0)
