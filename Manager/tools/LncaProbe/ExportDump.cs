using System;
using System.IO;
using System.Text;

/// <summary>
/// 轻量 PE 导出表 dump 工具（不依赖 dumpbin）。
/// 用法：ExportDump <dllPath> [filter]
/// </summary>
public static class ExportDump
{
    public static void Dump(string path, string filter)
    {
        var b = File.ReadAllBytes(path);
        int pe = BitConverter.ToInt32(b, 0x3C);
        int opt = pe + 24;
        ushort magic = BitConverter.ToUInt16(b, opt);
        bool is64 = magic == 0x20B;
        // 数据目录表在 Optional Header 内偏移 96（PE32）/112（PE32+）
        int ddStart = opt + (is64 ? 112 : 96);

        int expRva = BitConverter.ToInt32(b, ddStart);
        int nSec = BitConverter.ToUInt16(b, pe + 6);
        // Section Headers 紧跟 Optional Header，大小为 SizeOfOptionalHeader（COFF +16）
        int szOpt = BitConverter.ToUInt16(b, pe + 20);
        int secStart = opt + szOpt;

        int RvaToOff(int rva)
        {
            for (int i = 0; i < nSec; i++)
            {
                int s = secStart + i * 40;
                int va = BitConverter.ToInt32(b, s + 12);
                int vsz = BitConverter.ToInt32(b, s + 8);
                int rawSz = BitConverter.ToInt32(b, s + 16);
                int raw = BitConverter.ToInt32(b, s + 20);
                if (rva >= va && rva < va + Math.Max(vsz, rawSz)) return raw + (rva - va);
            }
            return -1;
        }

        int eoff = RvaToOff(expRva);
        if (eoff < 0) { Console.WriteLine("无导出表"); return; }
        int numNames = BitConverter.ToInt32(b, eoff + 24);
        int numFuncs = BitConverter.ToInt32(b, eoff + 20);
        int baseOrd = BitConverter.ToInt32(b, eoff + 16);
        int namesRva = BitConverter.ToInt32(b, eoff + 32);
        int ordRva = BitConverter.ToInt32(b, eoff + 36);
        int funcRva = BitConverter.ToInt32(b, eoff + 28); // EAT (Export Address Table)
        int namesOff = RvaToOff(namesRva);
        int ordOff = RvaToOff(ordRva);
        int funcOff = RvaToOff(funcRva);

        Console.WriteLine($"=== {Path.GetFileName(path)} : {numNames} 个具名导出 (共 {numFuncs} 个, base ordinal {baseOrd}) ===");
        for (int i = 0; i < numNames; i++)
        {
            int nrva = BitConverter.ToInt32(b, namesOff + i * 4);
            int noff = RvaToOff(nrva);
            int end = noff;
            while (b[end] != 0) end++;
            string name = Encoding.ASCII.GetString(b, noff, end - noff);
            ushort ord = BitConverter.ToUInt16(b, ordOff + i * 2);
            // ordinals 数组存的是相对序号（相对 base ordinal），EAT 索引直接用 ord
            int fRva = BitConverter.ToInt32(b, funcOff + ord * 4);
            if (string.IsNullOrEmpty(filter) || name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                Console.WriteLine($"{ord}\t0x{fRva:X8}\t{name}");
        }
    }
}
