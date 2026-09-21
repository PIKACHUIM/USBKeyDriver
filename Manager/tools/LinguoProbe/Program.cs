using System.Text;
using USBKey.Core.UsbKey;

namespace LinguoProbe;

/// <summary>
/// 凌国（Linguo）USB Key 实机校准探针。
/// <para>用法：
/// <code>
///   LinguoProbe                       # 全流程（枚举 → 各 LUN INQUIRY → APDU 两种模式）
///   LinguoProbe --inquiry-only        # 只做枚举与 INQUIRY
///   LinguoProbe --lun 1               # 指定 LUN 做 APDU 测试
///   LinguoProbe 8020008108313233343536 --lun 1
/// </code>
/// </para>
/// </summary>
internal static class Program
{
    private const string DefaultApdu = "8020008108313233343536"; // VERIFY PIN "123456"

    private static void Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        bool inquiryOnly = args.Contains("--inquiry-only");
        byte forcedLun = ParseArgByte(args, "--lun", 0xFF);
        bool lunForced = forcedLun != 0xFF;
        string apduHex = args.FirstOrDefault(a => !a.StartsWith("--")) ?? DefaultApdu;
        // 统计参数（形如 --candidate-index=2）不使用，保持简单

        Console.WriteLine("=== 凌国 USB Key 实机探针 ===");
        Console.WriteLine($"GUID={LinguoNative.DeviceInterfaceGuid}");
        Console.WriteLine();

        // ---------- [1] 枚举 ----------
        Console.WriteLine("[1] 枚举 CD-ROM 设备接口");
        List<string> paths;
        try { paths = LinguoNative.EnumerateDevicePaths(); }
        catch (Exception ex) { Console.WriteLine($"    ✗ {ex}"); return; }

        Console.WriteLine($"    共 {paths.Count} 个");
        foreach (var p in paths) Console.WriteLine($"      {p}");
        Console.WriteLine();
        if (paths.Count == 0) return;

        // ---------- [2] INQUIRY（完整 192B；覆盖 官方 PathId/TargetId=1 组合） ----------
        Console.WriteLine("[2] SCSI INQUIRY 全量扫描（192B，搜索 \"LGUSB\"）");
        var hits = new List<(string Path, LinguoNative.DeviceHandle Dev, byte Lun, string Vp)>();
        var combos = new (byte P, byte T, byte L)[] { (0, 0, 0), (1, 1, 0), (1, 1, 1), (0, 0, 1) };

        foreach (var path in paths)
        {
            Console.WriteLine($"  ── {ShortName(path)}");
            LinguoNative.DeviceHandle? dev;
            try { dev = LinguoNative.Open(path); }
            catch (Exception ex) { Console.WriteLine($"     ✗ 打开失败：{ex.Message}"); continue; }

            bool keep = false;
            foreach (var (p, t, l) in combos)
            {
                dev.PathId = p; dev.TargetId = t; dev.Lun = l;
                byte[] raw;
                try { raw = dev.Inquiry(192); }
                catch (Exception ex) { Console.WriteLine($"     P{p}T{t}L{l}: ✗ {ex.Message}"); continue; }

                if (raw.Length == 0) { Console.WriteLine($"     P{p}T{t}L{l}: (无数据)"); continue; }

                string ascii = Encoding.ASCII.GetString(raw);
                bool isLinguo = ascii.Contains("LGUSB", StringComparison.Ordinal);
                int addLen = raw.Length > 4 ? raw[4] : -1;

                Console.WriteLine($"     P{p}T{t}L{l}: {raw.Length,3}B  addLen=0x{addLen:X2}  " +
                                  $"vendor=\"{Safe(raw, 8, 8)}\" product=\"{Safe(raw, 16, Math.Min(16, raw.Length - 16))}\"" +
                                  (isLinguo ? "   ★★ LGUSB 命中" : ""));
                Console.WriteLine($"             ASCII: {Printable(raw)}");
                if (raw.Length > 36)
                    Console.WriteLine($"             扩展区(36..): {Printable(raw.AsSpan(36).ToArray())}");

                if (isLinguo)
                {
                    hits.Add((path, dev, l, Safe(raw, 8, 8) + " " + Safe(raw, 16, 16)));
                    keep = true;
                }
            }

            // 官方工具同款识别：IOCTL_SCSI_PASS_THROUGH(0x4D004) + DataBufferOffset=0x50
            try
            {
                var oRaw = dev.OfficialInquiry();
                string oAscii = Encoding.ASCII.GetString(oRaw);
                bool oHit = oAscii.Contains("LGUSB", StringComparison.Ordinal);
                Console.WriteLine($"     [官方同款 0x4D004] {oRaw.Length}B  vendor=\"{Safe(oRaw, 8, 8)}\" " +
                                  $"product=\"{Safe(oRaw, 16, 16)}\"{(oHit ? "   ★★ LGUSB 命中" : "")}");
                Console.WriteLine($"             ASCII: {Printable(oRaw)}");
                if (oHit)
                {
                    hits.Add((path, dev, 0, Safe(oRaw, 8, 8) + " " + Safe(oRaw, 16, 16)));
                    keep = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"     [官方同款 0x4D004] ✗ {ex.Message}");
            }

            if (!keep) dev.Dispose();
        }
        Console.WriteLine();

        if (inquiryOnly)
        {
            Console.WriteLine("（--inquiry-only，结束）");
            DisposeAll(hits);
            return;
        }

        // ---------- [3] APDU 传输 ----------
        Console.WriteLine("[3] APDU 传输测试");
        var candidates = hits.Count > 0
            ? hits
            : BuildFallback(paths, lunForced ? forcedLun : (byte)0);
        if (hits.Count == 0)
            Console.WriteLine("    ⚠ 没有 LGUSB 命中的设备，改为对「全部设备 × 指定 LUN」盲测（只发只读/校验类 APDU）");

        var apdu = ParseHex(apduHex);
        foreach (var (path, dev, lun, vp) in candidates)
        {
            dev.Lun = lun;
            Console.WriteLine($"  ── {ShortName(path)}  LUN{lun}  \"{vp}\"");
            foreach (var mode in new[] { LinguoNative.TransferMode.SingleShot, LinguoNative.TransferMode.SendThenRead })
            {
                Console.Write($"     [{mode,-12}] {apduHex} → ");
                try
                {
                    var data = dev.Transceive(apdu, mode, out ushort sw);
                    Console.WriteLine($"SW=0x{sw:X4}  data({data.Length}B)={Hex(data)}");
                }
                catch (Exception ex) { Console.WriteLine($"✗ {ex.Message}"); }
            }
            Console.WriteLine();
        }

        DisposeAll(candidates);
        Console.WriteLine("探针结束。");
    }

    /// <summary>没有命中时，按路径重建句柄做盲测。</summary>
    private static List<(string Path, LinguoNative.DeviceHandle Dev, byte Lun, string Vp)> BuildFallback(
        List<string> paths, byte lun)
    {
        var list = new List<(string, LinguoNative.DeviceHandle, byte, string)>();
        foreach (var p in paths)
        {
            try
            {
                var d = LinguoNative.Open(p);
                d.Lun = lun;
                list.Add((p, d, lun, ""));
            }
            catch { }
        }
        return list;
    }

    private static byte ParseArgByte(string[] args, string name, byte def)
    {
        int i = Array.IndexOf(args, name);
        if (i < 0 || i + 1 >= args.Length) return def;
        return byte.TryParse(args[i + 1], out var v) ? v : def;
    }

    private static string ShortName(string path)
    {
        int a = path.IndexOf("cdrom&", StringComparison.OrdinalIgnoreCase);
        int b = path.IndexOf('{', a < 0 ? 0 : a);
        if (a >= 0 && b > a) return path[a..b].TrimEnd('#');
        return Path.GetFileName(path);
    }

    private static void DisposeAll(List<(string Path, LinguoNative.DeviceHandle Dev, byte Lun, string Vp)> list)
    {
        foreach (var (_, dev, _, _) in list)
        {
            try { dev.Dispose(); } catch { }
        }
    }

    private static byte[] ParseHex(string hex)
    {
        var clean = hex.Replace(" ", "").Replace("-", "");
        if (clean.Length % 2 != 0) throw new ArgumentException("HEX 长度必须为偶数");
        return Convert.FromHexString(clean);
    }

    private static string Hex(byte[] data) => data.Length == 0 ? "(空)" : Convert.ToHexString(data);

    private static string Safe(byte[] data, int offset, int count)
    {
        if (data.Length <= offset) return "";
        int n = Math.Min(count, data.Length - offset);
        return Encoding.ASCII.GetString(data, offset, n).TrimEnd();
    }

    private static string Printable(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (var b in data) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
        return sb.ToString();
    }
}
