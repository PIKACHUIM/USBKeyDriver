using System.Text;
using System.Text.RegularExpressions;

namespace USBKey.Core.Common;

/// <summary>运行目录与路径定位。</summary>
public static class AppPaths
{
    /// <summary>可执行文件所在目录（发布时与 Library/、config/ 同处）。</summary>
    public static string BaseDir => AppContext.BaseDirectory;

    /// <summary>配置目录（优先 baseDir）；相对路径时回退到 baseDir。</summary>
    public static string ConfigDir
    {
        get
        {
            var dir = Path.Combine(BaseDir, "config");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string ConfigFile => Path.Combine(ConfigDir, "config.json");
    public static string LicenseFile => Path.Combine(ConfigDir, "license.key");
    public static string ApiMapFile(string platform) => Path.Combine(ConfigDir, $"api_map.{platform}.json");

    /// <summary>Library 目录（驱动 DLL 位置）。</summary>
    public static string LibraryDir
    {
        get
        {
            var d = Path.Combine(BaseDir, "Library");
            return Directory.Exists(d) ? d : BaseDir;
        }
    }
}

/// <summary>参数合法性校验。</summary>
public static class Validators
{
    public static readonly Regex PinRule = new(@"^.{6,}$", RegexOptions.Compiled);

    /// <summary>校验 PIN：6 位起。</summary>
    public static void EnsurePin(string pin, string what = "PIN")
    {
        if (string.IsNullOrEmpty(pin) || !PinRule.IsMatch(pin))
            throw new ArgumentException($"{what} 长度不能少于 6 位");
    }

    /// <summary>校验密码一致性。</summary>
    public static void EnsureSame(string a, string b, string what = "密码")
    {
        if (!string.Equals(a, b)) throw new ArgumentException($"两次输入的{what}不一致");
    }

    /// <summary>生成随机口令（默认随机 PIN/PUK/AdminKey，用于重置设备）。</summary>
    public static string RandomPassword(int length = 8, string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789")
    {
        var rnd = Random.Shared;
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.Append(chars[rnd.Next(chars.Length)]);
        return sb.ToString();
    }
}

/// <summary>简单文本日志（写运行目录 logs 下）。</summary>
public static class Log
{
    private static readonly object LockObj = new();

    public static void Write(string message)
    {
        try
        {
            var dir = Path.Combine(AppPaths.BaseDir, "logs");
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, $"app_{DateTime.Now:yyyyMMdd}.log");
            lock (LockObj)
            {
                File.AppendAllText(file, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
            }
        }
        catch { }
    }

    public static void Error(Exception ex, string ctx = "") =>
        Write($"{ctx} [ERR] {ex.GetType().Name}: {ex.Message}{Environment.NewLine}{ex.StackTrace}");
}
