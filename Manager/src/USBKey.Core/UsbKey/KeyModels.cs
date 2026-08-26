namespace USBKey.Core.UsbKey;

/// <summary>加密算法/摘要摘要描述（如 RSA2048、SHA1withRSA、SM2 等）。</summary>
public class KeyAlgorithm
{
    public string PublicKey { get; init; } = "";
    public string SignAlgorithm { get; init; } = "";
    public int KeyBits { get; init; }
    public override string ToString() =>
        string.IsNullOrEmpty(PublicKey) ? SignAlgorithm : $"{PublicKey}/{SignAlgorithm} ({KeyBits})";
}

/// <summary>USB Key 上的一个证书/容器。</summary>
public class KeyContainer
{
    /// <summary>证书名称/CN。</summary>
    public string Name { get; set; } = "";
    /// <summary>容器名（CSP 用，可能为 UUID 形式）。</summary>
    public string ContainerName { get; set; } = "";
    /// <summary>密钥容器 UUID（若提供）。</summary>
    public string ContainerUuid { get; set; } = "";
    /// <summary>算法摘要（RSA 2048/SHA1 等）。</summary>
    public string Algorithm { get; set; } = "";
    /// <summary>证书主体（Subject DN 字符串）。</summary>
    public string Subject { get; set; } = "";
    /// <summary>签发者。</summary>
    public string Issuer { get; set; } = "";
    public DateTime? NotBefore { get; set; }
    public DateTime? NotAfter { get; set; }
    /// <summary>证书用途（如 数据加密/数字签名）。</summary>
    public string KeyUsage { get; set; } = "";
    /// <summary>扩展用途（如 客户端身份验证）。</summary>
    public string ExtendedKeyUsage { get; set; } = "";
    /// <summary>是否已注册到系统 CSP 证书库。</summary>
    public bool IsRegisteredInCsp { get; set; }
    /// <summary>证书序列号。</summary>
    public string SerialNumber { get; set; } = "";
    /// <summary>证书指纹(SHA1)。</summary>
    public string Thumbprint { get; set; } = "";
    /// <summary>底层证书字节（仅内存，不用于导出私钥）。</summary>
    [field: System.Text.Json.Serialization.JsonIgnore]
    public byte[]? CertRaw { get; set; }

    /// <summary>有效期显示。</summary>
    public string ValidityText =>
        (NotBefore?.ToString("yyyy-MM-dd") ?? "-") + " ~ " + (NotAfter?.ToString("yyyy-MM-dd") ?? "-");
}

/// <summary>一台 USB Key 设备的描述与传输句柄。</summary>
public class UsbKeyDevice
{
    /// <summary>平台名（如 lnca）。</summary>
    public string Platform { get; set; } = "";
    /// <summary>厂商显示名。</summary>
    public string VendorName { get; set; } = "";
    /// <summary>设备名/型号。</summary>
    public string Model { get; set; } = "";
    /// <summary>序列号。</summary>
    public string SerialNumber { get; set; } = "";
    /// <summary>设备句柄/索引，用于打开。</summary>
    public int Handle { get; set; } = -1;
    /// <summary>VID。</summary>
    public int Vid { get; set; }
    /// <summary>PID。</summary>
    public int Pid { get; set; }
    /// <summary>固件版本。</summary>
    public string FirmwareVersion { get; set; } = "";
    /// <summary>容量（KB）。</summary>
    public long CapacityKb { get; set; }
    /// <summary>当前是否已登录（解锁）。</summary>
    public bool IsLoggedIn { get; set; }
    /// <summary>备注。</summary>
    public string Notes { get; set; } = "";

    public override string ToString() =>
        string.IsNullOrEmpty(SerialNumber) ? Model : $"{Platform.ToUpperInvariant()}-{SerialNumber}";
    /// <summary>托盘显示的设备名：平台前缀+序列号。</summary>
    public string TrayLabel => string.IsNullOrEmpty(SerialNumber)
        ? $"{Platform.ToUpperInvariant()}-{Model}"
        : $"{Platform.ToUpperInvariant()}-{SerialNumber}";
}
