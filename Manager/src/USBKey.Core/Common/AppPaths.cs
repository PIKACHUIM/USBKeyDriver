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

    /// <summary>证书注册记录（持久化私钥绑定信息，供下次启动自动补注册）。</summary>
    public static string CertRegistrationFile => Path.Combine(ConfigDir, "registered-certs.json");

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

