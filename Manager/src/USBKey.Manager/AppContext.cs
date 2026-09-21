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

    /// <summary>
    /// 请求立即执行一次「证书自动注册」。
    /// <para>
    /// 设置页把「证书自动注册到系统」打开/关闭后置位，主窗体随后触发一次检查，
    /// 使开关不必重启程序就能生效。
    /// </para>
    /// </summary>
    public bool CertAutoRegisterRequested { get; set; }

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
                case "hengbao":
                    config.KeyList.TryGetValue("hengbao", out var hbKeys);
                    // 恒宝（HengBao）民生银行 USB Key：使用 CMBCp.dll（标准 PKCS#11 接口）
                    Keys.Register(new HengBaoProvider(AppPaths.LibraryDir, hbKeys));
                    break;
                case "epass3003":
                    config.KeyList.TryGetValue("epass3003", out var epKeys);
                    // EnterSafe ePass3003：支持官方版和HZCA定制版
                    Keys.Register(new EPass3003Provider(AppPaths.LibraryDir, epKeys));
                    break;
                case "bjca":
                    config.KeyList.TryGetValue("bjca", out var bjcaKeys);
                    // 北京数字认证（BJCA）：统一客户端组件 XTXAppCOM.dll（自动分派 中孚/飞天/林果/天地融… 各型号）
                    Keys.Register(new BjcaProvider(AppPaths.LibraryDir, bjcaKeys));
                    break;
                case "skf":
                    config.KeyList.TryGetValue("skf", out var skfKeys);
                    // SKF（GM/T 0016 国标）通用平台：直接 P/Invoke 厂商 SKF 中间件（如林果 lgu3073_p1514_gm.dll），
                    // 不依赖厂商客户端的私有缓存，可完整实现 登录/改密/解锁/容器读写/证书导入导出/重置。
                    Keys.Register(new SkfProvider(AppPaths.LibraryDir, skfKeys));
                    break;
                case "gm3000" or "longmai" or "gm":
                    config.KeyList.TryGetValue("gm3000", out var gmKeys);
                    // 龙脉（Longmai）GM3000 USB Key：走厂商 SKF（GM/T 0016）中间件
                    // mtoken_gm3000.dll（2016 版；2022 版已不再支持本机这把老型号 GM3000）。
                    // 注意：厂商的 GM3000Admin.exe 走 PKCS#11/TokenMgr，其 PKCS#11 层看不到该老型号，
                    // 这是「2.2.19 不识别设备」的根因，详见 Roadmap/docs/Longmai-GM3000-逆向分析报告.md。
                    Keys.Register(new Gm3000Provider(AppPaths.LibraryDir, gmKeys));
                    break;
                case "linguo" or "zjkccb" or "zjk":
                    config.KeyList.TryGetValue("linguo", out var lgKeys);
                    // 凌国（Linguo / 张家口银行）USB Key：厂商只提供标准 CSP（LgCsp/LgImpl，无 PIN 管理入口），
                    // 故 Provider 直接复刻官方工具的「SCSI 直通 + ISO7816 APDU」链路（见 LinguoNative）。
                    Keys.Register(new LinguoProvider(AppPaths.LibraryDir, lgKeys));
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

    /// <summary>
    /// 开发/调试开关：为 true 时跳过授权校验（授权验证不生效）。
    /// 需要恢复校验时改为 false。
    /// </summary>
    public static readonly bool BypassLicenseCheck = true;

    /// <summary>管理模式启动：校验授权。未通过返回 false（调用方提示并进入激活流程）。</summary>
    public bool TryValidateLicense()
    {
        // 授权校验旁路：直接视为已授权，并填充一个远期有效的授权结果供界面展示。
        if (BypassLicenseCheck)
        {
            var farFuture = DateTime.UtcNow.AddYears(100);
            License = new LicenseCheckResult
            {
                Status = LicenseStatus.Valid,
                Message = "授权校验已旁路（开发模式）",
                ValidUntilUtc = farFuture,
                Document = new LicenseDocument
                {
                    LicenseId = "BYPASS",
                    MachineCode = MachineCode.Get(),
                    Expiry = farFuture.ToString("yyyy-MM-dd"),
                    Platforms = (Config.Platform ?? new()).ToList(),
                    IssuedAt = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                },
            };
            Log.Write("授权校验已旁路：BypassLicenseCheck=true，跳过授权验证。");
            return true;
        }

        if (!IsAdminMode) { License = null; return true; } // 用户模式不检查授权

        var (now, isNet, _) = NetworkTime.Now();
        if (!isNet) Log.Write("警告：未能获取网络时间，授权时间依赖本机时钟");
        var machineCode = MachineCode.Get();
        License = LicenseVerifier.Check(AppPaths.LicenseFile, machineCode, Config.Platform, now);
        return License.IsValid;
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
