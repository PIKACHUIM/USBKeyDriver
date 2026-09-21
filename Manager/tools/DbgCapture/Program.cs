using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;

/// <summary>
/// OutputDebugString 捕获器（等价于轻量版 DebugView）。
///
/// 用途：恒宝 CMBCp.dll / CMBCC.dll / CMBCu.exe 内部有大量 OutputDebugStringA 埋点
/// （例如 "KOpenDevice In/Out"、"THidTSP::OpenDevice"、"CTSPBot::OpenDevice"、
///  "C_GetTokenInfo In/Out"、DeviceIoControl 返回值等），
/// 通过这些 trace 可以精确定位 PKCS#11 调用失败在设备层的那一步。
///
/// 用法：
///   DbgCapture.exe [秒数] [--filter 进程名子串] [--run 可执行文件 [参数...]]
///
/// 例：
///   DbgCapture.exe 20 --run "C:\...\HengBaoProbe.exe"
///   DbgCapture.exe 15 --filter CMBCu --run "C:\...\CMBCu.exe"
/// </summary>
internal static class Program
{
    private const string DBWIN_BUFFER = "DBWIN_BUFFER";
    private const string DBWIN_BUFFER_READY = "DBWIN_BUFFER_READY";
    private const string DBWIN_DATA_READY = "DBWIN_DATA_READY";
    private const int DBWIN_BUFFER_SIZE = 4096;

    private static int Main(string[] args)
    {
        int seconds = 15;
        string filter = null;
        string runExe = null;
        var runArgs = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--filter":
                    if (i + 1 < args.Length) filter = args[++i];
                    break;
                case "--run":
                    if (i + 1 < args.Length)
                    {
                        runExe = args[++i];
                        for (int j = i + 1; j < args.Length; j++) runArgs.Add(args[j]);
                        i = args.Length;
                    }
                    break;
                default:
                    if (int.TryParse(args[i], out var s)) seconds = s;
                    break;
            }
        }

        MemoryMappedFile mmf = null;
        MemoryMappedViewAccessor view = null;
        EventWaitHandle bufferReady = null, dataReady = null;
        try
        {
            mmf = MemoryMappedFile.CreateOrOpen(DBWIN_BUFFER, DBWIN_BUFFER_SIZE, MemoryMappedFileAccess.ReadWrite);
            view = mmf.CreateViewAccessor(0, DBWIN_BUFFER_SIZE, MemoryMappedFileAccess.ReadWrite);
            bufferReady = new EventWaitHandle(false, EventResetMode.AutoReset, DBWIN_BUFFER_READY);
            dataReady = new EventWaitHandle(false, EventResetMode.AutoReset, DBWIN_DATA_READY);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] 无法建立 DBWIN 共享对象：" + ex.Message);
            Console.WriteLine("    可能已有 DebugView 之类的调试器在捕获（同一会话只允许一个捕获者）。");
            return 1;
        }

        Console.WriteLine("[*] 开始捕获 OutputDebugString，持续 " + seconds + " 秒"
                          + (filter != null ? "，过滤进程名包含 \"" + filter + "\"" : "") + " …");

        var nameCache = new Dictionary<int, string>();
        using (mmf)
        using (view)
        using (bufferReady)
        using (dataReady)
        {
            Process child = null;
            if (runExe != null)
            {
                try
                {
                    var psi = new ProcessStartInfo(runExe)
                    {
                        UseShellExecute = false,
                        WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(runExe)) ?? ".",
                    };
                    foreach (var a in runArgs) psi.ArgumentList.Add(a);
                    child = Process.Start(psi);
                    Console.WriteLine("[*] 已启动：" + runExe + " (pid=" + child.Id + ")");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] 启动失败：" + ex.Message);
                }
            }

            var buf = new byte[DBWIN_BUFFER_SIZE - 4];
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < seconds)
            {
                bufferReady.Set();
                if (!dataReady.WaitOne(200))
                {
                    if (child != null && child.HasExited && sw.Elapsed.TotalSeconds > 1)
                    {
                        Console.WriteLine("[*] 子进程已退出。");
                        break;
                    }
                    continue;
                }

                int pid = view.ReadInt32(0);
                view.ReadArray(4, buf, 0, buf.Length);
                int zero = Array.IndexOf(buf, (byte)0);
                if (zero < 0) zero = buf.Length;
                if (zero == 0) continue;

                // .NET Core 默认不带 936(GBK) 代码页；trace 里关键信息（函数名/路径/错误码）都是 ASCII，
                // 用 Latin1 逐字节映射，避免因编码器缺失抛异常（中文部分会显示为乱码但不影响判读）。
                string text = Encoding.Latin1.GetString(buf, 0, zero).TrimEnd('\r', '\n');
                if (text.Length == 0) continue;

                if (!nameCache.TryGetValue(pid, out var pname))
                {
                    try { pname = Process.GetProcessById(pid).ProcessName; }
                    catch { pname = "pid" + pid; }
                    nameCache[pid] = pname;
                }
                if (filter != null && pname.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;

                Console.WriteLine("[" + pname + ":" + pid + "] " + text);
            }
            sw.Stop();

            if (child != null && !child.HasExited)
            {
                try { child.Kill(true); } catch { }
            }
        }

        Console.WriteLine("[*] 捕获结束。");
        return 0;
    }
}
