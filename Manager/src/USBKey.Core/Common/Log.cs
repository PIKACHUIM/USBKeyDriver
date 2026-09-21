namespace USBKey.Core.Common;

/// <summary>
/// 简单文本日志（写运行目录 logs 下）。
/// <para>
/// 同时通过 <see cref="Line"/> 事件把日志推给界面，便于在主界面内查看，
/// 不必再让用户去翻 logs 目录逐条扫。
/// </para>
/// </summary>
public static class Log
{
    private static readonly object LockObj = new();

    /// <summary>新日志行（已带时间戳前缀）。订阅方需自行保证快速返回，异常会被吞掉。</summary>
    public static event Action<string>? Line;

    /// <summary>是否写文件（默认开；批量枚举等高噪音场景可由调用方临时关闭）。</summary>
    public static bool WriteToFile { get; set; } = true;

    public static void Write(string message)
    {
        var text = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";

        // 先通知界面：即便是写文件失败也要让用户看到
        try { Line?.Invoke(text); } catch { }

        if (!WriteToFile) return;
        try
        {
            var dir = Path.Combine(AppPaths.BaseDir, "logs");
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, $"app_{DateTime.Now:yyyyMMdd}.log");
            lock (LockObj)
            {
                File.AppendAllText(file, text + Environment.NewLine);
            }
        }
        catch { }
    }

    public static void Error(Exception ex, string ctx = "") =>
        Write($"{ctx} [ERR] {ex.GetType().Name}: {ex.Message}{Environment.NewLine}{ex.StackTrace}");
}
