using System.Text.Json;
using System.Text.Json.Serialization;

namespace USBKey.Core.Configuration;

/// <summary>功能的可见性/可用性状态。</summary>
public enum FeatureState
{
    /// <summary>可用</summary>
    Enabled,
    /// <summary>隐藏（完全不可见）</summary>
    Hidden,
    /// <summary>可见但禁用（按钮置灰）</summary>
    Disabled,
}

/// <summary>按键/功能标识符，对应 config.json 中 features 的键。</summary>
public static class FeatureKeys
{
    public const string Login = "login";             // 登录解锁/登出加锁
    public const string CloudImport = "cloudimport"; // 云端导入(暂不实现)
    public const string ImportCert = "importcert";   // 本地导入PFX
    public const string ViewCert = "viewcert";       // 查看证书
    public const string ExportCert = "exportcert";   // 导出证书
    public const string DeleteCert = "delcert";      // 删除证书
    public const string RegisterCert = "regcert";    // 注册/注销证书
    public const string ChangePin = "changepin";     // 修改密码
    public const string UnlockDevice = "unlock";     // 解锁设备
    public const string ResetDevice = "reset";       // 重置设备
    public const string EnrollCert = "enrollcert";   // 证书登记（卡内生成密钥→导出P10→导回签发证书）
}

/// <summary>用户（非管理）模式的本地偏好设置。</summary>
public class UserSettings
{
    /// <summary>是否允许用户删除证书（默认否）。</summary>
    public bool AllowDeleteCert { get; set; } = false;

    /// <summary>是否允许用户修改密码（默认否）。</summary>
    public bool AllowChangePin { get; set; } = false;

    /// <summary>登录会话有效期（分钟，默认15）。</summary>
    public int LoginTimeoutMinutes { get; set; } = 15;

    /// <summary>云端证书导入地址（空表示未配置）。</summary>
    public string CloudEndpoint { get; set; } = "";

    /// <summary>是否开机自启动服务（默认是）。</summary>
    public bool AutoStart { get; set; } = true;

    /// <summary>证书是否自动注册到系统CSP证书库（默认是）。</summary>
    public bool AutoRegisterCert { get; set; } = true;
}

/// <summary>单个USB设备的VID/PID 定义。</summary>
public class UsbDeviceDef
{
    public string Name { get; set; } = "";
    /// <summary>十六进制VID，如 "16A0"。</summary>
    public string Vid { get; set; } = "";
    /// <summary>十六进制PID，如 "0D00"。</summary>
    public string Pid { get; set; } = "";

    /// <summary>
    /// SKF 平台（<c>skf</c>）专用：该设备对应的 SKF 中间件 DLL 文件名，
    /// 如 <c>lgu3073_p1514_gm.dll</c>（会在 Library 目录下递归查找）。
    /// </summary>
    public string Dll { get; set; } = "";

    [JsonIgnore] public int VidInt => ParseHex(Vid);
    [JsonIgnore] public int PidInt => ParseHex(Pid);
    private static int ParseHex(string s) =>
        int.TryParse(s.TrimStart('0', 'x', 'X'), System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : 0;
}

/// <summary>可编程注册的 REST API 配置（仅授权状态下可用）。</summary>
public class ApiConfig
{
    public bool Enabled { get; set; } = false;
    public int Port { get; set; } = 18443;
    public string Token { get; set; } = "";
}

/// <summary>应用整体配置，对应运行目录 config.json。</summary>
public class AppConfig
{
    /// <summary>管理模式：false=管理模式(检查授权)，true=用户模式(不检查授权)。</summary>
    public bool UserMode { get; set; } = true;

    /// <summary>当前可用的平台列表，如 ["lnca"]。</summary>
    public List<string> Platform { get; set; } = new() { "lnca" };

    /// <summary>
    /// 每个平台支持的 USB 设备 VID/PID 列表（含 SKF 平台的中间件 DLL 名）。
    /// <para>
    /// 必须显式标注 JSON 键：配置文件里是 <c>keyslist</c>，而 <see cref="JsonNamingPolicy.CamelCase"/>
    /// 会把 <c>KeyList</c> 推导成 <c>keyList</c>，两者不匹配（"keyslist" ≠ "keylist"），
    /// 缺省会静默反序列化成空字典——各平台的 VID/PID 白名单与 SKF 的 dll 名会全部丢失。
    /// </para>
    /// </summary>
    [JsonPropertyName("keyslist")]
    public Dictionary<string, List<UsbDeviceDef>> KeyList { get; set; } = new();

    /// <summary>功能按钮的可见性/可用性配置。</summary>
    public Dictionary<string, string> Features { get; set; } = new();

    /// <summary>用户模式偏好设置。</summary>
    public UserSettings Settings { get; set; } = new();

    /// <summary>可编程 REST API 配置。</summary>
    public ApiConfig Api { get; set; } = new();

    /// <summary>软件信息（管理设置页展示：名称/版权/构建日期/支持的平台）。</summary>
    [JsonIgnore] public static string SoftwareName => "USB Key 管理端";
    [JsonIgnore] public static string Copyright => "Copyright © 2026";
    [JsonIgnore] public static string BuildDate => Version;
    [JsonIgnore] public static string Version => "1.0.0.0";

    /// <summary>获取 features 中某个功能的实际状态。</summary>
    public FeatureState GetFeatureState(string key)
    {
        if (Features == null || !Features.TryGetValue(key, out var raw) || string.IsNullOrEmpty(raw))
            return FeatureState.Enabled; // 未配置默认可用
        return raw.Trim().ToLowerInvariant() switch
        {
            "hidden" => FeatureState.Hidden,
            "disable" or "disabled" => FeatureState.Disabled,
            "enable" or "enabled" => FeatureState.Enabled,
            _ => FeatureState.Enabled,
        };
    }

    /// <summary>仅在管理模式（管理员账号）下根据授权能力返回功能状态。</summary>
    public FeatureState GetFeatureStateForAdmin(string key, bool hasLicense)
    {
        var s = GetFeatureState(key);
        if (s == FeatureState.Hidden) return s;
        if (s == FeatureState.Enabled) return s; // 已显式启用
        // disabled(可见但禁用) 时，若已授权可提升? —— 需求:管理系统完全由features控制；此处保持原态。
        return s;
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static AppConfig Load(string path)
    {
        Console.WriteLine($"[AppConfig] 加载配置文件: {path}");
        Console.WriteLine($"[AppConfig] 文件存在: {File.Exists(path)}");
        
        if (!File.Exists(path))
        {
            Console.WriteLine("[AppConfig] 配置文件不存在，使用默认配置");
            return new AppConfig();
        }
        
        var json = File.ReadAllText(path);
        Console.WriteLine($"[AppConfig] 配置文件内容前100字符: {json.Substring(0, Math.Min(100, json.Length))}");
        
        var config = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts) ?? new AppConfig();
        Console.WriteLine($"[AppConfig] 反序列化结果: UserMode={config.UserMode}");
        
        return config;
    }

    public void Save(string path)
    {
        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(path, json);
    }
}
