using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 模拟实现：在没有实体 USB Key / 驱动 DLL 的环境下，
/// 用于开发、演示与 UI 走查。通过本地自签名证书模拟一个“已插入的 Key”。
/// 生产环境不应启用（config 未启用此 provider 时不会加载）。
/// </summary>
public sealed class MockKeyProvider : IKeyProvider
{
    private const string MockPin = "123456";
    private const string MockPuk = "12345678";
    private bool _initialized;
    private readonly List<MockContainer> _containers = new();

    public string PlatformName => "mock";
    public bool IsAvailable => true;
    public bool IsEnabledByConfig { get; set; } = true; // UI 通过 config.platform 含 "mock" 时才启用

    private class MockContainer
    {
        public KeyContainer Info { get; set; } = new();
        public bool CspRegistered { get; set; }
    }

    public void Initialize()
    {
        if (_initialized) return;
        _initialized = true;
        // 预置2个模拟证书，方便 UI 展示
        _containers.Clear();
        try
        {
            _containers.Add(new MockContainer { Info = CreateCert("模拟-张三(示例)", "lnca", 2048) });
            _containers.Add(new MockContainer { Info = CreateCert("模拟-李四(示例)", "lnca", 4096) });
        }
        catch { /* 证书生成失败不影响框架 */ }
    }

    private static KeyContainer CreateCert(string cn, string issuerCn, int bits)
    {
        using var rsa = RSA.Create(bits);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature, false));
        var eku = new OidCollection();
        eku.Add(new Oid("1.3.6.1.5.5.7.3.2")); // 客户端身份验证
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
        var now = DateTime.Now;
        using var cert = req.CreateSelfSigned(now.AddDays(-30), now.AddYears(3));
        var raw = cert.Export(X509ContentType.Cert); // 仅公钥证书，无私钥
        return new KeyContainer
        {
            Name = cn,
            Subject = cert.Subject,
            Issuer = $"CN={issuerCn} Root",
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = $"RSA {bits}/SHA256",
            KeyUsage = "数据加密、数字签名",
            ExtendedKeyUsage = "客户端身份验证(1.3.6.1.5.5.7.3.2)",
            ContainerName = Guid.NewGuid().ToString("B"),
            ContainerUuid = Guid.NewGuid().ToString(),
            CertRaw = raw,
        };
    }

    private static ushort Reverse(ushort v) => (ushort)((v >> 8) | (v << 8));
    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        // 模拟检测到 1 台设备
        return new List<UsbKeyDevice>
        {
            new UsbKeyDevice
            {
                Platform = PlatformName,
                VendorName = "模拟厂商(Mock)",
                Model = "Serial-USBKey 演示设备",
                SerialNumber = "MOCK-8A3F-C001",
                Handle = 0,
                Vid = 0x16A0, Pid = 0x0D00,
                FirmwareVersion = "2.1.0",
                CapacityKb = 64 * 1024,
                IsLoggedIn = false,
            },
        };
    }

    public UsbKeyDevice Open(int handleOrSerial) =>
        Enumerate().FirstOrDefault(d => d.Handle == handleOrSerial) ?? Enumerate().First();

    public void Login(UsbKeyDevice device, string pin)
    {
        if (pin != MockPin)
        {
            device.IsLoggedIn = false;
            throw new InvalidOperationException("PIN 验证失败（模拟 PIN 为 123456）");
        }
        device.IsLoggedIn = true;
    }

    public void Logout(UsbKeyDevice device) => device.IsLoggedIn = false;

    public UsbKeyDevice GetDetail(UsbKeyDevice device) => device;

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        if (!device.IsLoggedIn) throw new InvalidOperationException("请先登录（解锁）设备");
        return _containers.Select(c => c.Info).ToList();
    }

    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        if (!device.IsLoggedIn) throw new InvalidOperationException("请先登录设备");
        var cert = new X509Certificate2(pfxPath, pfxPassword == null ? null : pfxPassword, X509KeyStorageFlags.Exportable);
        _containers.Add(new MockContainer
        {
            Info = new KeyContainer
            {
                Name = cert.Subject.Split(',')[0].Replace("CN=", ""),
                Subject = cert.Subject,
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
                SerialNumber = cert.SerialNumber,
                Thumbprint = cert.Thumbprint,
                Algorithm = "RSA/导入",
                KeyUsage = "数字签名",
                ExtendedKeyUsage = "—",
                ContainerName = Guid.NewGuid().ToString("B"),
                ContainerUuid = Guid.NewGuid().ToString(),
                CertRaw = cert.Export(X509ContentType.Cert),
            }
        });
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath) =>
        File.WriteAllBytes(outputPath, container.CertRaw ?? FallbackCert(container));

    public void ViewCertificate(KeyContainer container)
    {
        try
        {
            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
            File.WriteAllBytes(tmp, container.CertRaw ?? FallbackCert(container));
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmp) { UseShellExecute = true });
        }
        catch (Exception ex) { throw new InvalidOperationException("打开证书查看器失败: " + ex.Message); }
    }

    private static byte[] FallbackCert(KeyContainer c)
    {
        // 兜底：若无原始证书字节，根据描述信息重建一个占位证书用于查看
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={c.Name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTime.Now.AddDays(-1), DateTime.Now.AddYears(1));
        return cert.Export(X509ContentType.Cert);
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        if (!device.IsLoggedIn) throw new InvalidOperationException("请先登录设备");
        var m = _containers.FirstOrDefault(x => x.Info.ContainerUuid == container.ContainerUuid);
        if (m != null) { _containers.Remove(m); return; }
        var m2 = _containers.FirstOrDefault(x => x.Info.Name == container.Name);
        if (m2 != null) _containers.Remove(m2);
    }

    public void RegisterToCsp(KeyContainer container)
    {
        var m = Find(container);
        m.CspRegistered = true;
        m.Info.IsRegisteredInCsp = true;
        if (m.Info.CertRaw != null)
        {
            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Add(new X509Certificate2(RsaPublicCert(m.Info)));
                store.Close();
            }
            catch { /* 注册到当前用户证书库失败则忽略(演示) */ }
        }
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        var m = Find(container);
        m.CspRegistered = false;
        m.Info.IsRegisteredInCsp = false;
    }

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin) { /* 模拟 */ }

    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        if (method == UnlockMethod.Puk && credential != MockPuk)
            throw new InvalidOperationException("PUK 验证失败（模拟 PUK 为 12345678）");
        device.IsLoggedIn = true;
    }

    public string GenerateChallenge(UsbKeyDevice device) => "MOCK-" + Guid.NewGuid().ToString("N").Substring(0, 16);

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
    {
        if (response.Length < 8) throw new InvalidOperationException("挑战码响应无效");
        device.IsLoggedIn = true;
    }

    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null)
    {
        if (newPin.Length < 6) throw new InvalidOperationException("PIN 长度不能少于 6 位");
        device.IsLoggedIn = true;
    }

    private MockContainer Find(KeyContainer c) =>
        _containers.First(x => x.Info.ContainerUuid == c.ContainerUuid || x.Info.Name == c.Name);

    private static X509Certificate2 RsaPublicCert(KeyContainer c)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={c.Name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(c.NotBefore ?? DateTime.Now.AddDays(-1), c.NotAfter ?? DateTime.Now.AddYears(1));
    }

    public void Dispose() { }
}
