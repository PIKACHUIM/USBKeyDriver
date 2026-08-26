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

    /// <summary>初始化所有已启用且 DLL 可用的 provider。</summary>
    public void InitializeAll()
    {
        foreach (var p in EnabledProviders())
        {
            if (!p.IsAvailable) continue;
            try { p.Initialize(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[KeyManager] init {p.PlatformName}: {ex.Message}"); }
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
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[KeyManager] enum {p.PlatformName}: {ex.Message}"); }
        }
        return result;
    }

    /// <summary>打开指定平台/序列号的设备。</summary>
    public UsbKeyDevice? Open(string platform, string serialOrHandle)
    {
        var p = GetProvider(platform);
        if (p == null) return null;
        try { return p.Open(int.TryParse(serialOrHandle, out var h) ? h : -1); }
        catch { return null; }
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
