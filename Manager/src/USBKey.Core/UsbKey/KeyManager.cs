using USBKey.Core.Common;
using USBKey.Core.Configuration;

namespace USBKey.Core.UsbKey;

/// <summary>
/// USB Key 平台/设备管理器：根据 config.json 的 platform 与 keyslist 注册 provider，
/// 汇总所有已连接设备，并承担 USB 热插拔监听（见 UsbWatcher）。
/// </summary>
public sealed class KeyManager : IDisposable
{
    private readonly Dictionary<string, IKeyProvider> _providers = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<IKeyProvider> _allProviders = new();
    private readonly AppConfig _config;

    /// <summary>设备变化事件（插入/拔出）。</summary>
    public event Action? DevicesChanged;

    public KeyManager(AppConfig config)
    {
        _config = config;
    }

    /// <summary>注册一个平台 provider。</summary>
    public void Register(IKeyProvider provider)
    {
        _providers[provider.PlatformName] = provider;
        _allProviders.Add(provider);
    }

    /// <summary>返回受 config.platform 启用的 providers。</summary>
    public IEnumerable<IKeyProvider> EnabledProviders()
    {
        var enabled = _config.Platform ?? new();
        foreach (var p in _allProviders)
            if (enabled.Contains(p.PlatformName, StringComparer.OrdinalIgnoreCase))
                yield return p;
    }

    /// <summary>按平台名获取 provider（不存在或未启用返回 null）。</summary>
    public IKeyProvider? GetProvider(string platformName) =>
        _providers.TryGetValue(platformName, out var p) && IsEnabled(platformName) ? p : null;

    public bool IsEnabled(string platformName) =>
        (_config.Platform ?? new()).Contains(platformName, StringComparer.OrdinalIgnoreCase);

    /// <summary>provider 是否可加载出驱动（未启用返回 false）。</summary>
    public bool IsPlatformAvailable(string platformName)
    {
        var p = GetProvider(platformName);
        if (p == null) return false;
        try { return p.IsAvailable; }
        catch { return false; }
    }

    /// <summary>初始化所有已启用且 DLL 可用的 provider（不可用的会记一条原因，便于界面展示）。</summary>
    public void InitializeAll()
    {
        foreach (var p in EnabledProviders())
        {
            if (!p.IsAvailable) continue;
            try
            {
                p.Initialize();
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"初始化 provider {p.PlatformName} 失败");
            }
        }
    }

    /// <summary>枚举所有已启用且可用 provider 下的设备。</summary>
    public List<UsbKeyDevice> EnumerateAll()
    {
        var result = new List<UsbKeyDevice>();
        foreach (var p in EnabledProviders())
        {
            if (!p.IsAvailable) continue;
            try { result.AddRange(p.Enumerate()); }
            catch (Exception ex) { Log.Error(ex, $"枚举 provider {p.PlatformName} 设备失败"); }
        }
        return result;
    }

    /// <summary>
    /// 只枚举指定平台的设备。
    /// <para>
    /// 界面必须走这个方法：早期实现用 <see cref="EnumerateAll"/> 填「按平台筛选」的列表，
    /// 结果选北京CA时会把龙脉等其它平台的设备一并列出来（设备归属错乱，
    /// 更严重的是后续按索引回查会拿到别的平台的设备，操作可能下发到错误设备）。
    /// </para>
    /// </summary>
    public List<UsbKeyDevice> EnumeratePlatform(string platformName)
    {
        var result = new List<UsbKeyDevice>();
        var p = GetProvider(platformName);
        if (p == null)
        {
            Log.Write($"[{platformName}] 未启用或未注册该平台，无法枚举设备。");
            return result;
        }
        try
        {
            if (!p.IsAvailable)
            {
                Log.Write($"[{platformName}] 驱动不可用（未找到厂商 DLL），跳过枚举。");
                return result;
            }
            p.Initialize();
            result.AddRange(p.Enumerate());
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"枚举平台 {platformName} 设备失败");
        }
        return result;
    }

    /// <summary>打开指定平台/序列号的设备。</summary>
    public UsbKeyDevice? Open(string platform, string serialOrHandle)
    {
        var p = GetProvider(platform);
        if (p == null) return null;
        try { return p.Open(int.TryParse(serialOrHandle, out var h) ? h : -1); }
        catch (Exception ex) { Log.Error(ex, $"打开设备失败 platform={platform} serialOrHandle={serialOrHandle}"); return null; }
    }

    /// <summary>触发设备变化通知。</summary>
    public void RaiseDevicesChanged() => DevicesChanged?.Invoke();

    public void Dispose()
    {
        foreach (var p in _allProviders) p.Dispose();
        _allProviders.Clear();
        _providers.Clear();
    }
}
