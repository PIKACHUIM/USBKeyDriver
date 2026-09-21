using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Crypto;

namespace USBKey.Core.UsbKey;

/// <summary>一次自动注册的执行摘要。</summary>
public sealed class CertAutoRegisterResult
{
    /// <summary>扫描的设备数。</summary>
    public int DevicesScanned { get; set; }
    /// <summary>本次注册进系统的证书数。</summary>
    public int Registered { get; set; }
    /// <summary>已在系统证书库里、无需动作的证书数。</summary>
    public int AlreadyRegistered { get; set; }
    /// <summary>记录存在、但卡上已找不到对应证书的条数。</summary>
    public int Missing { get; set; }
    /// <summary>失败的条数。</summary>
    public int Failed { get; set; }
    /// <summary>被跳过的设备数（平台未启用/驱动不可用）。</summary>
    public int Skipped { get; set; }

    /// <summary>明细消息（写日志/状态栏用）。</summary>
    public List<string> Messages { get; } = new();

    /// <summary>是否发生了写入（决定要不要落盘）。</summary>
    public bool Changed => Registered > 0;

    /// <summary>一行摘要。</summary>
    public string Summary()
    {
        var parts = new List<string>();
        if (Registered > 0) parts.Add($"已注册 {Registered}");
        if (AlreadyRegistered > 0) parts.Add($"已在库中 {AlreadyRegistered}");
        if (Missing > 0) parts.Add($"卡上已无 {Missing}");
        if (Failed > 0) parts.Add($"失败 {Failed}");
        return parts.Count == 0 ? "无需处理" : string.Join("，", parts);
    }
}

/// <summary>
/// 证书自动注册器。
/// <para>
/// 两条业务规则：
/// <list type="number">
/// <item><b>新设备</b>（记录里没见过这台卡的 平台+序列号）：扫描卡上全部证书，自动注册到系统并持久化，
/// 下次启动就能按记录恢复；</item>
/// <item><b>已知设备</b>：只保证「记录里那几条证书」还在系统证书库里（缺了就重新注册）；
/// 用户手动注销过的证书会因为记录被删除而不会被自动加回来。</item>
/// </list>
/// 每次注册都会解析私钥容器（厂商 CSP/KSP），把 CERT_KEY_PROV_INFO 一并写进证书：
/// 卡上的证书必然带卡内私钥，注册就必须连私钥一起注册；解析不到提供程序时按失败上报，
/// 不写入"系统用不了"的证书。
/// </para>
/// </summary>
public sealed class CertAutoRegistrar
{
    private readonly AppConfig _config;
    private readonly Dictionary<string, CertKeyBinding?> _bindingCache = new(StringComparer.OrdinalIgnoreCase);

    public CertAutoRegistrar(AppConfig config, CertRegistrationStore store)
    {
        _config = config;
        Store = store;
    }

    /// <summary>注册记录仓库。</summary>
    public CertRegistrationStore Store { get; }

    /// <summary>自动注册开关（设置 → 证书自动注册到系统）。</summary>
    public bool Enabled => _config.Settings.AutoRegisterCert;

    /// <summary>对一批设备执行自动注册（同步、可能耗时；调用方应放在后台线程）。</summary>
    /// <param name="keys">平台/设备管理器。</param>
    /// <param name="devices">待检查的设备。</param>
    /// <param name="platformGate">
    /// 可选的"按平台串行"门（界面传自己的门进来，保证与手动操作不会并发读同一张卡）；
    /// 为 null 时直接执行。
    /// </param>
    public CertAutoRegisterResult Run(KeyManager keys, IEnumerable<UsbKeyDevice> devices,
        Action<string, Action>? platformGate = null)
    {
        var result = new CertAutoRegisterResult();
        if (!Enabled)
        {
            result.Messages.Add("自动注册已关闭，跳过。");
            return result;
        }

        _bindingCache.Clear();
        foreach (var dev in devices)
        {
            result.DevicesScanned++;
            try
            {
                if (platformGate != null) platformGate(dev.Platform, () => ProcessDevice(keys, dev, result));
                else ProcessDevice(keys, dev, result);
            }
            catch (Exception ex)
            {
                result.Failed++;
                result.Messages.Add($"{dev.TrayLabel}：{ex.Message}");
                Log.Error(ex, $"[自动注册] 处理设备 {dev.TrayLabel} 失败");
            }
        }

        if (result.Changed) Store.Save();
        return result;
    }

    private void ProcessDevice(KeyManager keys, UsbKeyDevice dev, CertAutoRegisterResult result)
    {
        var prov = keys.GetProvider(dev.Platform);
        if (prov == null || !prov.IsAvailable)
        {
            result.Skipped++;
            return;
        }

        var isNew = !Store.IsKnownDevice(dev.Platform, dev.SerialNumber);
        var recorded = Store.ForDevice(dev.Platform, dev.SerialNumber);

        List<KeyContainer> containers;
        try
        {
            containers = prov.ListContainers(dev).ToList();
        }
        catch (Exception ex)
        {
            result.Failed++;
            result.Messages.Add($"{dev.TrayLabel}：读取容器失败（{ex.Message}）");
            return;
        }

        if (isNew)
        {
            // ---- 新设备：卡上所有证书都注册一遍（带上卡内私钥容器） ----
            var targets = containers.Where(c => c.HasCertificate && !string.IsNullOrEmpty(c.Thumbprint)).ToList();
            if (targets.Count > 0) Log.Write($"[自动注册] 首次识别 {dev.TrayLabel}，发现 {targets.Count} 张证书");
            var failedBefore = result.Failed;
            foreach (var c in targets)
            {
                RegisterOne(prov, dev, c, result, rebind: true);
            }

            if (result.Failed > failedBefore)
            {
                // 有失败的（多半是厂商 CSP/KSP 没装）：不标记"已识别"，
                // 这样装上驱动后的下一次启动/插卡还会自动重试，而不是永远错过这台卡。
                Log.Write($"[自动注册] {dev.TrayLabel} 本次有注册失败，保留为新设备状态，下次扫描会重试");
                return;
            }

            // 标记已识别：即使用户之后全部注销，也不会被再次自动注册
            Store.MarkDeviceKnown(dev.Platform, dev.SerialNumber);
            Store.Save();
            return;
        }

        // ---- 已知设备：只维护记录里的那些证书 ----
        foreach (var rec in recorded)
        {
            var cert = containers.FirstOrDefault(c =>
                (!string.IsNullOrEmpty(rec.Thumbprint) &&
                 string.Equals(c.Thumbprint, rec.Thumbprint, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(rec.ContainerUuid) &&
                 string.Equals(c.ContainerUuid, rec.ContainerUuid, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(rec.ContainerName) &&
                 string.Equals(c.ContainerName, rec.ContainerName, StringComparison.OrdinalIgnoreCase)));

            if (cert == null || !cert.HasCertificate)
            {
                result.Missing++;
                result.Messages.Add($"{dev.TrayLabel}：记录中的「{rec.FriendlyName}」在卡上已不存在");
                continue;
            }

            // 记录里没写下私钥提供程序（早期版本注册留下的），这次重新注册把绑定补上
            RegisterOne(prov, dev, cert, result, rebind: !rec.HasKeyBinding, recorded: rec.ToKeyBinding());
        }
    }

    /// <summary>
    /// 把一张证书注册到系统证书库（连带卡内私钥容器）。
    /// </summary>
    /// <param name="rebind">为 true 时即使证书已在库中也重新注册（用于覆盖旧副本、补上私钥绑定）。</param>
    /// <param name="recorded">上次注册落盘的绑定（现场探测失败时的兜底，保证"下次启动还能注册回来"）。</param>
    private void RegisterOne(IKeyProvider prov, UsbKeyDevice dev, KeyContainer cert,
        CertAutoRegisterResult result, bool rebind, CertKeyBinding? recorded = null)
    {
        var thumb = cert.Thumbprint;
        if (string.IsNullOrEmpty(thumb)) return;

        if (!rebind && CertHelper.IsRegistered(thumb))
        {
            result.AlreadyRegistered++;
            return;
        }

        // 卡上的证书必然带卡内私钥：拿不到「提供程序 + 容器」说明厂商 CSP/KSP 没装好，
        // 这时宁可报错，也不能把一张系统用不了的证书塞进证书库。
        var binding = ResolveBinding(dev, cert);
        if (binding == null && recorded is { IsValid: true })
        {
            binding = recorded;
            Log.Write($"[私钥] 现场未匹配到容器，改用注册记录中的绑定：{binding.Describe()}");
        }
        if (binding == null)
        {
            result.Failed++;
            result.Messages.Add($"{dev.TrayLabel}：证书「{cert.Name}」未找到对应的厂商 CSP/KSP，已跳过");
            return;
        }

        try
        {
            prov.RegisterToCsp(cert, binding);
            result.Registered++;
            Store.Upsert(BuildRecord(dev, cert, binding));
            Log.Write($"[自动注册] {dev.TrayLabel} 证书「{cert.Name}」已注册（{binding.Describe()}）");
        }
        catch (Exception ex)
        {
            result.Failed++;
            result.Messages.Add($"{dev.TrayLabel}：注册「{cert.Name}」失败（{ex.Message}）");
            Log.Error(ex, $"[自动注册] 注册证书失败：{dev.TrayLabel} / {cert.Name}");
        }
    }

    private CertRegistrationRecord BuildRecord(UsbKeyDevice dev, KeyContainer cert, CertKeyBinding? binding) => new()
    {
        Platform = dev.Platform,
        SerialNumber = dev.SerialNumber,
        ContainerName = cert.ContainerName,
        ContainerUuid = cert.ContainerUuid,
        Thumbprint = cert.Thumbprint,
        FriendlyName = cert.Name,
        KeyProvider = binding?.ProviderName ?? "",
        KeyStoreKind = binding == null ? "" : (binding.Kind == KeyStoreKind.Cng ? "cng" : "capi"),
        KeyContainer = binding?.ContainerName ?? "",
        ProviderType = binding?.ProviderType ?? 0,
        KeySpec = binding?.KeySpec ?? 0,
        RegisteredAtUtc = DateTime.UtcNow,
        LastSeenUtc = DateTime.UtcNow,
        NotAfterUtc = cert.NotAfter?.ToUniversalTime(),
    };

    /// <summary>解析私钥容器（结果按 平台+容器 缓存，避免同一容器反复枚举系统 CSP）。</summary>
    private CertKeyBinding? ResolveBinding(UsbKeyDevice dev, KeyContainer cert)
    {
        var cacheKey = $"{dev.Platform}|{cert.ContainerName}|{cert.ContainerUuid}|{cert.Name}";
        if (_bindingCache.TryGetValue(cacheKey, out var cached)) return cached;

        var def = FindDeviceDef(dev);
        string? pinned = null;
        KeyStoreKind? pinnedKind = null;
        if (!string.IsNullOrWhiteSpace(def?.Ksp)) { pinned = def!.Ksp; pinnedKind = KeyStoreKind.Cng; }
        else if (!string.IsNullOrWhiteSpace(def?.Csp)) { pinned = def!.Csp; pinnedKind = KeyStoreKind.Capi; }

        var binding = CertKeyBinder.Resolve(
            new[] { cert.ContainerName, cert.ContainerUuid, cert.Name },
            pinned, pinnedKind, CertKeyBinder.KeySpecFromUsage(cert.KeyUsage));

        _bindingCache[cacheKey] = binding;
        return binding;
    }

    /// <summary>在 config.json 的 keyslist 里找该设备所属的型号定义（按 VID/PID 匹配）。</summary>
    private UsbDeviceDef? FindDeviceDef(UsbKeyDevice dev)
    {
        if (_config.KeyList == null) return null;
        if (!_config.KeyList.TryGetValue(dev.Platform, out var defs) || defs == null) return null;
        return defs.FirstOrDefault(d =>
                   (d.VidInt == 0 || d.VidInt == dev.Vid) &&
                   (d.PidInt == 0 || d.PidInt == dev.Pid))
               ?? defs.FirstOrDefault(d => string.IsNullOrEmpty(d.Vid) && string.IsNullOrEmpty(d.Pid));
    }
}
