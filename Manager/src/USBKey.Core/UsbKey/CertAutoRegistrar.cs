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
/// <item><b>新设备</b>（记录里没见过这台卡的 平台+序列号）：把卡上全部证书注册到系统证书库并持久化记录，
/// 下次启动就能按记录恢复；</item>
/// <item><b>已知设备</b>：只保证「记录里那几条证书」还在系统证书库里，缺了就重新注册。
/// 用户手动注销过的证书会因为记录被删除而不会被自动加回来。</item>
/// </list>
/// 只负责证书本体的注册/注销（走各平台既有的 RegisterToCsp），不涉及私钥容器。
/// </para>
/// </summary>
public sealed class CertAutoRegistrar
{
    private readonly AppConfig _config;

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
            // ---- 新设备：卡上所有证书都注册一遍 ----
            var targets = containers.Where(c => c.HasCertificate && !string.IsNullOrEmpty(c.Thumbprint)).ToList();
            if (targets.Count > 0) Log.Write($"[自动注册] 首次识别 {dev.TrayLabel}，发现 {targets.Count} 张证书");
            var failedBefore = result.Failed;
            foreach (var c in targets) RegisterOne(prov, dev, c, result);

            if (result.Failed > failedBefore)
            {
                // 有失败的：不标记"已识别"，下次扫描（或装了驱动后）还会重试，而不是永远错过这台卡
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

            RegisterOne(prov, dev, cert, result);
        }
    }

    /// <summary>把一张证书注册到系统证书库（已在库里则跳过）。</summary>
    private void RegisterOne(IKeyProvider prov, UsbKeyDevice dev, KeyContainer cert, CertAutoRegisterResult result)
    {
        var thumb = cert.Thumbprint;
        if (string.IsNullOrEmpty(thumb)) return;

        if (CertHelper.IsRegistered(thumb))
        {
            result.AlreadyRegistered++;
            return;
        }

        try
        {
            prov.RegisterToCsp(cert);
            result.Registered++;
            Store.Upsert(BuildRecord(dev, cert));
            Log.Write($"[自动注册] {dev.TrayLabel} 证书「{cert.Name}」已注册到系统证书库");
        }
        catch (Exception ex)
        {
            result.Failed++;
            result.Messages.Add($"{dev.TrayLabel}：注册「{cert.Name}」失败（{ex.Message}）");
            Log.Error(ex, $"[自动注册] 注册证书失败：{dev.TrayLabel} / {cert.Name}");
        }
    }

    private static CertRegistrationRecord BuildRecord(UsbKeyDevice dev, KeyContainer cert) => new()
    {
        Platform = dev.Platform,
        SerialNumber = dev.SerialNumber,
        ContainerName = cert.ContainerName,
        ContainerUuid = cert.ContainerUuid,
        Thumbprint = cert.Thumbprint,
        FriendlyName = cert.Name,
        RegisteredAtUtc = DateTime.UtcNow,
        LastSeenUtc = DateTime.UtcNow,
        NotAfterUtc = cert.NotAfter?.ToUniversalTime(),
    };
}
