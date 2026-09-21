using System.Text.Json;
using System.Text.Json.Serialization;
using USBKey.Core.Common;

namespace USBKey.Core.UsbKey;

/// <summary>一条证书注册记录（卡侧标识 + 系统侧私钥绑定），持久化到 config/registered-certs.json。</summary>
public sealed class CertRegistrationRecord
{
    /// <summary>平台名（如 skf / bjca）。</summary>
    public string Platform { get; set; } = "";
    /// <summary>设备序列号（同一平台下唯一标识一台卡）。</summary>
    public string SerialNumber { get; set; } = "";
    /// <summary>卡内容器名。</summary>
    public string ContainerName { get; set; } = "";
    /// <summary>卡内容器 UUID（部分平台与容器名相同）。</summary>
    public string ContainerUuid { get; set; } = "";
    /// <summary>证书指纹（SHA1，注册/注销都按它匹配）。</summary>
    public string Thumbprint { get; set; } = "";
    /// <summary>注册到系统时使用的友好名称。</summary>
    public string FriendlyName { get; set; } = "";
    /// <summary>首次注册时间（UTC）。</summary>
    public DateTime RegisteredAtUtc { get; set; }
    /// <summary>最近一次确认/补注册时间（UTC）。</summary>
    public DateTime LastSeenUtc { get; set; }
    /// <summary>证书有效期（UTC）。</summary>
    public DateTime? NotAfterUtc { get; set; }
}

/// <summary>
/// 已处理过「首次自动注册」的设备。
/// <para>
/// 有它才能区分「这台卡是新插上的」和「用户把证书全部注销过的旧卡」：
/// 前者自动注册，后者必须尊重用户的选择、不能又被自动加回去。
/// </para>
/// </summary>
public sealed class KnownDeviceRecord
{
    public string Platform { get; set; } = "";
    public string SerialNumber { get; set; } = "";
    /// <summary>首次识别时间（UTC）。</summary>
    public DateTime FirstSeenUtc { get; set; }
    /// <summary>完成首次自动注册的时间（UTC）。</summary>
    public DateTime AutoRegisteredUtc { get; set; }
}

/// <summary>
/// 证书注册记录仓库（config/registered-certs.json）。
/// <para>
/// 目的：注册动作本身写在证书库里，但"这条证书来自哪台卡、绑的是哪个容器"只有这里知道。
/// 有了它，程序下次启动可以对缺失的证书自动补注册（证书库被清理/换机器也能恢复）。
/// </para>
/// </summary>
public sealed class CertRegistrationStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly string _path;
    private readonly object _gate = new();

    public List<CertRegistrationRecord> Records { get; set; } = new();
    public List<KnownDeviceRecord> KnownDevices { get; set; } = new();

    private CertRegistrationStore(string path) => _path = path;

    /// <summary>记录文件路径。</summary>
    public string Path => _path;

    /// <summary>加载记录（文件不存在/损坏时返回空仓库，绝不让它挡住程序启动）。</summary>
    public static CertRegistrationStore Load(string path)
    {
        var store = new CertRegistrationStore(path);
        try
        {
            if (!File.Exists(path)) return store;
            var json = File.ReadAllText(path);
            var loaded = JsonSerializer.Deserialize<CertRegistrationStore>(json, JsonOpts);
            if (loaded != null)
            {
                store.Records = loaded.Records ?? new List<CertRegistrationRecord>();
                store.KnownDevices = loaded.KnownDevices ?? new List<KnownDeviceRecord>();
            }
            Log.Write($"[注册记录] 已加载 {store.Records.Count} 条证书注册记录、{store.KnownDevices.Count} 台已识别设备");
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[注册记录] 读取注册记录失败，按空记录继续");
        }
        return store;
    }

    /// <summary>保存（失败只记日志，不影响主流程）。</summary>
    public void Save()
    {
        try
        {
            lock (_gate)
            {
                var dir = System.IO.Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(_path, JsonSerializer.Serialize(this, JsonOpts));
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[注册记录] 写入注册记录失败");
        }
    }

    /// <summary>取某台设备的全部记录。</summary>
    public List<CertRegistrationRecord> ForDevice(string platform, string serial)
    {
        lock (_gate)
        {
            return Records.Where(r => SameDevice(r.Platform, r.SerialNumber, platform, serial)).ToList();
        }
    }

    /// <summary>查一条记录。</summary>
    public CertRegistrationRecord? Find(string platform, string serial, string thumbprint)
    {
        lock (_gate)
        {
            return Records.FirstOrDefault(r => SameDevice(r.Platform, r.SerialNumber, platform, serial)
                                            && string.Equals(r.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>新增或更新记录。</summary>
    public void Upsert(CertRegistrationRecord record)
    {
        lock (_gate)
        {
            var old = Records.FirstOrDefault(r => SameDevice(r.Platform, r.SerialNumber, record.Platform, record.SerialNumber)
                                               && string.Equals(r.Thumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase));
            if (old != null) Records.Remove(old);
            if (record.RegisteredAtUtc == default) record.RegisteredAtUtc = DateTime.UtcNow;
            record.LastSeenUtc = DateTime.UtcNow;
            Records.Add(record);
        }
    }

    /// <summary>
    /// 按证书指纹删除记录（注销证书 / 删除容器时调用）。
    /// <para>
    /// 用指纹而不是"平台+序列号"定位：同一张卡可能同时挂在 BJCA 与 SKF 两个通道下，
    /// 注册时记的平台未必是删除时用的平台，按指纹删才删得干净。
    /// </para>
    /// </summary>
    public int RemoveByThumbprint(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint)) return 0;
        lock (_gate)
        {
            return Records.RemoveAll(r =>
                string.Equals(r.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>删除整台设备的记录（重置/格式化设备后调用）。</summary>
    public int RemoveDevice(string platform, string serial)
    {
        lock (_gate) return Records.RemoveAll(r => SameDevice(r.Platform, r.SerialNumber, platform, serial));
    }

    /// <summary>该设备是否已被识别过（决定要不要做"首次自动注册"）。</summary>
    public bool IsKnownDevice(string platform, string serial)
    {
        lock (_gate)
        {
            return KnownDevices.Any(k => SameDevice(k.Platform, k.SerialNumber, platform, serial));
        }
    }

    /// <summary>标记设备已识别（首次自动注册完成后调用）。</summary>
    public void MarkDeviceKnown(string platform, string serial)
    {
        lock (_gate)
        {
            var hit = KnownDevices.FirstOrDefault(k => SameDevice(k.Platform, k.SerialNumber, platform, serial));
            if (hit == null)
            {
                KnownDevices.Add(new KnownDeviceRecord
                {
                    Platform = platform,
                    SerialNumber = serial,
                    FirstSeenUtc = DateTime.UtcNow,
                    AutoRegisteredUtc = DateTime.UtcNow,
                });
            }
            else
            {
                hit.AutoRegisteredUtc = DateTime.UtcNow;
            }
        }
    }

    private static bool SameDevice(string p1, string s1, string p2, string s2) =>
        string.Equals(p1, p2, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(s1, s2, StringComparison.OrdinalIgnoreCase);
}
