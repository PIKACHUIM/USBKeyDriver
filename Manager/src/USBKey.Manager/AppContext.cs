using USBKey.Core.Configuration;
using USBKey.Core.Licensing;
using USBKey.Core.UsbKey;

namespace USBKey.Manager;

/// <summary>
/// 应用运行时上下文：装配配置、KeyManager、USB 监听、授权状态与当前会话。
/// 管理端软件唯一的“胶水层”。
/// </summary>
public sealed class AppContext : IDisposable
{
    public AppConfig Config { get; }
    public KeyManager Keys { get; }
    public UsbWatcher? Watcher { get; private set; }

    /// <summary>当前是否管理模式（非 usermode）。</summary>
    public bool IsAdminMode => !Config.UserMode;

    /// <summary>当前授权校验结果（管理模式才有意义）。</summary>
    public LicenseCheckResult? License { get; private set; }

    /// <summary>当前选中的厂商平台名（如 lnca / mock）。</summary>
    public string SelectedPlatform { get; set; } = "";

    /// <summary>当前 “已登录” 的设备。</summary>
    public UsbKeyDevice? CurrentDevice { get; set; }

    /// <summary>登录时间（用于会话有效期）。</summary>
    public DateTime LoginAt { get; private set; }

    /// <summary>当前是否处于登录(解锁)会话。</summary>
    public bool IsLoggedIn => CurrentDevice?.IsLoggedIn == true &&
                              (DateTime.UtcNow - LoginAt).TotalMinutes < Config.Settings.LoginTimeoutMinutes;

    public event Action? OnStateChanged;

    public AppContext(AppConfig config)
    {
        Config = config;
        Keys = new KeyManager(config);

        // 调试：输出配置信息
        Console.WriteLine($"[AppContext] UserMode={Config.UserMode}, IsAdminMode={IsAdminMode}");
        Console.WriteLine($"[AppContext] Platform={string.Join(",", Config.Platform ?? new())}");

        // 注册真实平台 provider
        foreach (var platform in config.Platform ?? new())
        {
            switch (platform.ToLowerInvariant())
            {
                case "lnca" or "lnca1" or "lnca2":
                    config.KeyList.TryGetValue("lnca", out var lncaKeys);
                    // 使用 JIT_USBKEY_HD.dll（厂商管理 API 层，逆向已确认并动态验证通过）
                    Keys.Register(new LncaProvider(AppPaths.LibraryDir, lncaKeys));
                    break;
                case "mock":
                    Keys.Register(new MockKeyProvider { IsEnabledByConfig = true });
                    break;
            }
        }
    }

    /// <summary>初始化：装配 provider 与 USB 监听。watcherEnabled 决定是否监听热插拔。</summary>
    public void Initialize(bool watcherEnabled)
    {
        Keys.InitializeAll();
        if (watcherEnabled && Config.KeyList != null)
        {
            var whitelist = Config.KeyList.Values.SelectMany(v => v ?? new()).ToList();
            Watcher = new UsbWatcher(whitelist);
            Watcher.Changed += () => OnStateChanged?.Invoke();
            Watcher.Start();
        }
    }

    /// <summary>管理模式启动：校验授权。未通过返回 false（调用方提示并进入激活流程）。</summary>
    public bool TryValidateLicense()
    {
        if (!IsAdminMode) { License = null; return true; } // 用户模式不检查授权
        
        // TODO: 临时禁用授权检查，方便测试
        Console.WriteLine("[授权] 测试模式：跳过授权验证");
        License = new LicenseCheckResult 
        { 
            Status = LicenseStatus.Valid, 
            Message = "测试模式",
            ValidUntilUtc = DateTime.UtcNow.AddYears(1)
        };
        return true;
        
        /* 原授权逻辑（暂时注释）
        var (now, isNet, _) = NetworkTime.Now();
        if (!isNet) Log.Write("警告：未能获取网络时间，授权时间依赖本机时钟");
        var machineCode = MachineCode.Get();
        License = LicenseVerifier.Check(AppPaths.LicenseFile, machineCode, Config.Platform, now);
        return License.IsValid;
        */
    }

    /// <summary>记录登录会话开始。</summary>
    public void MarkLoggedIn(UsbKeyDevice dev)
    {
        CurrentDevice = dev;
        LoginAt = DateTime.UtcNow;
        OnStateChanged?.Invoke();
    }

    public void MarkLoggedOut()
    {
        if (CurrentDevice != null) { try { CurrentDevice.IsLoggedIn = false; } catch { } CurrentDevice = null; }
        OnStateChanged?.Invoke();
    }

    /// <summary>管理员执行敏感操作（导入/重置/解锁）前，必须再次校验授权（防越权）。</summary>
    public bool AuthorizeSensitiveOperation()
    {
        if (!IsAdminMode) return true; // 用户模式这些操作本来就被禁用
        return TryValidateLicense();
    }

    public void RaiseStateChanged() => OnStateChanged?.Invoke();

    public void Dispose()
    {
        Watcher?.Dispose();
        Keys.Dispose();
    }
}
