param(
    [string]$Path = "c:\USBKey\Library\LNCA"
)

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

public static class PEDump2 {
    public static List<string> GetExports(string path) {
        var result = new List<string>();
        try {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 0x40 || Encoding.ASCII.GetString(bytes, 0, 2) != "MZ") return result;
            int peOff = BitConverter.ToInt32(bytes, 0x3C);
            if (bytes[peOff] != 'P' || bytes[peOff+1] != 'E') return result;
            int optOff = peOff + 24;
            long sects = BitConverter.ToUInt16(bytes, peOff + 6);
            int optSize = BitConverter.ToUInt16(bytes, peOff + 20);
            long sectOff = peOff + 24 + optSize;
            int exportRva = BitConverter.ToInt32(bytes, optOff + 96);
            int exportSize = BitConverter.ToInt32(bytes, optOff + 100);
            if (exportRva == 0) { result.Add("(no export dir)"); return result; }
            int fileOff = FileOff(bytes, exportRva, sectOff, sects);
            if (fileOff < 0) { result.Add("(unmapped export dir rva0x" + exportRva.ToString("X") + ")"); return result; }
            int numFuncs = BitConverter.ToInt32(bytes, fileOff + 20);
            int baseOrd = BitConverter.ToInt32(bytes, fileOff + 16);
            int funcRva = BitConverter.ToInt32(bytes, fileOff + 28);
            int namePtrRva = BitConverter.ToInt32(bytes, fileOff + 24);
            int funcOff = FileOff(bytes, funcRva, sectOff, sects);
            int namePtrOff = FileOff(bytes, namePtrRva, sectOff, sects);
            if (numFuncs == 0) { result.Add("(0 funcs, dirsz=" + exportSize + ")"); return result; }
            for (int i = 0; i < numFuncs; i++) {
                string nm = "";
                if (namePtrOff > 0 && namePtrOff + i * 4 + 4 <= bytes.Length) {
                    int np = BitConverter.ToInt32(bytes, namePtrOff + i*4);
                    int no = FileOff(bytes, np, sectOff, sects);
                    nm = ReadStr(bytes, no);
                }
                string rva = "?";
                if (funcOff > 0 && funcOff + i * 4 + 4 <= bytes.Length)
                    rva = "0x" + BitConverter.ToInt32(bytes, funcOff + i*4).ToString("X");
                result.Add((nm == "" ? ("ord#" + (baseOrd + i)) : nm) + " @rva" + rva);
            }
            result.Sort(StringComparer.OrdinalIgnoreCase);
        } catch (Exception e) { result.Add("ERR:" + e.GetType().Name + ":" + e.Message); }
        return result;
    }
    static int FileOff(byte[] b, int rva, long sectOff, long sects) {
        if (rva <= 0) return -1;
        for (int i = 0; i < sects; i++) {
            int vs = BitConverter.ToInt32(b, (int)sectOff + i*40 + 8);
            int vr = BitConverter.ToInt32(b, (int)sectOff + i*40 + 12);
            int rs = BitConverter.ToInt32(b, (int)sectOff + i*40 + 16);
            int rf = BitConverter.ToInt32(b, (int)sectOff + i*40 + 20);
            if (rva >= vr && rva < vr + Math.Max(vs, rs)) {
                int off = rva - vr + rf;
                if (off >= 0 && off < b.Length) return off;
            }
        }
        return -1;
    }
    static string ReadStr(byte[] b, int off) {
        if (off < 0 || off >= b.Length) return "";
        int end = off;
        try { while (end < b.Length && b[end] != 0 && end - off < 512) end++; } catch { }
        if (end == off) return "";
        try { return Encoding.ASCII.GetString(b, off, end - off).Trim(); } catch { return ""; }
    }
}
"@

Get-ChildItem -Path $Path -Filter "*.dll" | ForEach-Object {
    Write-Host "`n===== $($_.Name) ====="
    $exps = [PEDump2]::GetExports($_.FullName)
    Write-Host ("Count: " + $exps.Count)
    $exps | ForEach-Object { Write-Host "   $_" }
}
