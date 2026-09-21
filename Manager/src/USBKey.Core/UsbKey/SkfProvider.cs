using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Common;
using USBKey.Core.Configuration;

namespace USBKey.Core.UsbKey;

/// <summary>
/// <b>SKF（GM/T 0016-2012）通用平台对接实现</b>。
///
/// <para><b>定位</b>：直接 P/Invoke 厂商 SKF 中间件（如林果 <c>lgu3073_p1514_gm.dll</c>），
/// 不依赖任何厂商客户端的私有缓存，因此能拿到
/// <b>枚举 / 登录 / 改密 / 解锁 / 容器 / 证书导入导出 / 重置</b> 的全套能力。</para>
///
/// <para><b>为什么需要它</b>：BJCA 的 <c>XTXAppCOM</c> 组件虽然能重置设备，
/// 但其登录/改密接口依赖 <c>SOF_GetUserList</c>（实测恒为空）拿 <c>CertID</c>，链路无法自举
/// （见 <c>Roadmap/07-BJCA逆向分析与对接.md</c> §8.3）。本 provider 走 SKF 层，绕开该限制。</para>
///
/// <para><b>实机实测（林果 LG3073 / <c>6588:1514</c>，2026-09-21）</b>：
/// <list type="bullet">
/// <item>设备名 = 序列号（如 <c>5303201812001784</c>）；</item>
/// <item>卡内应用名 = <c>BJCA-Application</c>（<c>SKF_EnumApplication</c>）；</item>
/// <item><b>PIN 类型：0 = 管理员（SO PIN），1 = 用户 PIN</b>
/// （<c>SKF_VerifyPIN(0,"111111")=成功</c>、<c>SKF_VerifyPIN(1,"123456")=成功</c>）；
/// 2 及以上返回 <c>SAR_INVALIDPARAMERR</c>；</item>
/// <item><c>SKF_GetDevInfo</c> 的 <c>DEVINFO</c> 是<b>厂商变体</b>（Version 为 2 字节、
/// 字段长度与国标不同），偏移见 <see cref="SkfSession.GetDevInfo"/>；</item>
/// <item>全部所用接口参数个数与国标签名一致（<c>tools/bjca_analyze.py argcounts</c> 核对）。</item>
/// </list>
/// </para>
///
/// <para><b>配置</b>：<c>config.json → keyslist.skf[]</c>，每项用 <c>dll</c> 指定 SKF 中间件文件名
/// （可再带 <c>vid</c>/<c>pid</c> 做过滤）。</para>
/// </summary>
public sealed class SkfProvider : IKeyProvider
{
    /// <summary>平台名。</summary>
    public const string Platform = "skf";

    /// <summary>默认应用名（BJCA 定制卡）。</summary>
    public const string DefaultAppName = "BJCA-Application";

    /// <summary>PIN 类型（实测）：0 = 管理员（SO PIN）。</summary>
    public const uint PinTypeAdmin = 0;

    /// <summary>PIN 类型（实测）：1 = 用户 PIN。</summary>
    public const uint PinTypeUser = 1;

    /// <summary>出厂默认管理口令（实测本卡为 111111，且 GetPINInfo 报"是否出厂=True"）。</summary>
    public const string DefaultAdminPin = "111111";

    /// <summary>出厂默认用户 PIN。</summary>
    public const string DefaultUserPin = "111111";

    private const uint MaxRetry = 10;
    private const uint FileRights = 0x02;   // 国标：0x02 = 允许读写

    private readonly string _libraryRoot;
    private readonly List<UsbDeviceDef> _defs;
    private readonly object _sync = new();

    private SkfSession? _session;
    private string _dllPath = "";

    // 当前已连接的会话状态
    private string _devName = "";
    private IntPtr _hDev = IntPtr.Zero;
    private IntPtr _hApp = IntPtr.Zero;
    private bool _userLoggedIn;

    /// <summary>最近一次重置报告，供 UI 展示。</summary>
    public string? LastResetReport { get; private set; }

    /// <summary>当前会话是否已通过用户 PIN 认证（SKF 安全状态）。</summary>
    public bool IsUserLoggedIn => _userLoggedIn;

    public string PlatformName => Platform;

    /// <summary>SKF 的清空动作是「删除应用」，必须有管理员权限，因此重置需要当前管理口令。</summary>
    public bool ResetRequiresCurrentPin => true;

    /// <summary>SKF 私钥在卡内生成、不可导出也不可导入，因此不支持导入外部 PFX。</summary>
    public bool SupportsImportPfx => false;

    /// <summary>支持「卡内生成密钥对 → 导出公钥/P10 → 导回签发证书」的建证流程。</summary>
    public bool SupportsKeyEnrollment => true;

    public SkfProvider(string libraryRoot, IEnumerable<UsbDeviceDef>? defs = null)
    {
        _libraryRoot = libraryRoot ?? "";
        _defs = defs?.ToList() ?? new List<UsbDeviceDef>();

        // 构造即报告可用性（与 GM3000/BJCA 的日志风格一致）：
        // KeyManager.InitializeAll 会静默跳过不可用的 provider，不打印就无法确认平台是否装配成功。
        var cfgDll = _defs.Select(d => d.Dll).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s)) ?? "(未配置)";
        var found = LocateDll();
        if (found != null)
            Log.Write($"[SKF] 中间件已就绪：{found}");
        else
            Log.Write($"[SKF] 未找到 SKF 中间件：keyslist.skf[].dll=\"{cfgDll}\" 设备定义数={_defs.Count} " +
                      $"宿主64位={Environment.Is64BitProcess} 查找根目录=\"{_libraryRoot}\"（该平台将不可用）");
    }

    /// <summary>已加载的 SKF 中间件路径。</summary>
    public string DllPath => _dllPath;

    // ============================================================ 定位与初始化

    public bool IsAvailable
    {
        get
        {
            if (_session != null) return true;
            return LocateDll() != null;
        }
    }

    /// <summary>按 keyslist.skf[].dll 指定的文件名，在 Library 下递归定位（优先 32 位目录）。</summary>
    public string? LocateDll()
    {
        if (_session != null) return _dllPath;
        lock (_sync)
        {
            if (_session != null) return _dllPath;
            var name = _defs.Select(d => d.Dll).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));
            if (string.IsNullOrWhiteSpace(name)) return null;

            // 64 位宿主优先取 _x64 版本（配置里通常写 32 位名）
            var want = Environment.Is64BitProcess
                ? (name!.Contains("_x64", StringComparison.OrdinalIgnoreCase)
                    ? name
                    : Path.GetFileNameWithoutExtension(name) + "_x64" + Path.GetExtension(name))
                : name!;

            foreach (var root in new[] { _libraryRoot, AppPaths.LibraryDir }.Where(Directory.Exists)
                         .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                FileInfo[] hits;
                try { hits = new DirectoryInfo(root).GetFiles(want, SearchOption.AllDirectories); }
                catch { continue; }
                var hit = hits.OrderByDescending(f => f.FullName.Contains(@"\x86\", StringComparison.OrdinalIgnoreCase))
                              .FirstOrDefault();
                if (hit != null) return hit.FullName;
            }
            return null;
        }
    }

    public void Initialize()
    {
        if (_session != null) return;
        var path = LocateDll()
            ?? throw new FileNotFoundException(
                "未找到 SKF 中间件。请在 config.json 的 keyslist.skf 中配置 dll 文件名，并把该 DLL 放到 Library 目录下" +
                "（例如 Library\\BJCA USBKEY DRIVER\\BJCAClient\\CertAppEnv*\\Driver\\x86\\lgu3073_p1514_gm.dll）。");

        var s = new SkfSession(path);
        if (!s.HasExport("SKF_EnumDev"))
        {
            s.Dispose();
            throw new InvalidOperationException($"{Path.GetFileName(path)} 未导出 SKF_EnumDev，不是标准 SKF 中间件");
        }
        _session = s;
        _dllPath = path;
        Log.Write($"[SKF] 中间件已加载：{path}");
    }

    private SkfSession Session
    {
        get
        {
            if (_session == null) Initialize();
            return _session!;
        }
    }

    /// <summary>取该设备对应的配置项（用于 VID/PID 过滤与显示名）。</summary>
    private UsbDeviceDef? DefFor(string serial)
        => _defs.FirstOrDefault(d => d.VidInt > 0 || d.PidInt > 0) == null ? null : _defs.FirstOrDefault();

    // ============================================================ 设备枚举 / 详情

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var result = new List<UsbKeyDevice>();
        var s = Session;
        var (rc, names) = s.EnumDev();
        if (rc != SkfNative.SAR_OK)
        {
            Log.Write($"[SKF] SKF_EnumDev 失败：{SkfNative.Describe(rc)}");
            return result;
        }

        for (int i = 0; i < names.Count; i++)
        {
            var dev = new UsbKeyDevice
            {
                Platform = Platform,
                VendorName = "SKF（GM/T 0016）",
                SerialNumber = names[i],
                Handle = i,
                Model = Path.GetFileNameWithoutExtension(_dllPath),
            };
            try
            {
                var (rcC, hDev) = s.ConnectDev(names[i]);
                if (rcC == SkfNative.SAR_OK)
                {
                    try
                    {
                        var (rcI, info) = s.GetDevInfo(hDev);
                        if (rcI == SkfNative.SAR_OK && info != null) Fill(dev, info);
                        var (_, state) = s.GetDevState(names[i]);
                        dev.Notes = state == 2 ? "设备已锁定" : "设备已插入";
                    }
                    finally { s.DisConnectDev(hDev); }
                }
                else
                {
                    dev.Notes = $"连接失败：{SkfNative.Describe(rcC)}";
                }
            }
            catch (Exception ex) { Log.Error(ex, $"[SKF] 读取设备 {names[i]} 信息失败"); }

            // VID/PID：配置里给了非零值时才回填（SKF 不提供 VID/PID）
            var def = _defs.FirstOrDefault(d => d.VidInt > 0 || d.PidInt > 0);
            if (def != null) { dev.Vid = def.VidInt; dev.Pid = def.PidInt; }

            result.Add(dev);
        }
        return result;
    }

    private static void Fill(UsbKeyDevice dev, SkfNative.SkfDevInfo info)
    {
        if (!string.IsNullOrWhiteSpace(info.SerialNumber)) dev.SerialNumber = info.SerialNumber;
        if (!string.IsNullOrWhiteSpace(info.Manufacturer)) dev.VendorName = info.Manufacturer;
        if (!string.IsNullOrWhiteSpace(info.Label)) dev.Model = info.Label;
        dev.FirmwareVersion = $"HW 0x{info.HwVersion:X} / FW 0x{info.FirmwareVersion:X}";
        var caps = new List<string>();
        if (info.AlgSymCap != 0) caps.Add($"对称 0x{info.AlgSymCap:X}");
        if (info.AlgAsymCap != 0) caps.Add($"非对称 0x{info.AlgAsymCap:X}");
        if (info.AlgHashCap != 0) caps.Add($"摘要 0x{info.AlgHashCap:X}");
        if (!string.IsNullOrWhiteSpace(info.Issuer)) caps.Add($"Issuer {info.Issuer}");
        if (caps.Count > 0) dev.Notes = string.Join("；", caps);
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        var devs = Enumerate();
        if (devs.Count == 0) throw new InvalidOperationException("未找到已连接的 SKF 设备");
        if (handleOrSerial >= 0 && handleOrSerial < devs.Count) return devs[handleOrSerial];
        return devs[0];
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        var s = Session;
        var (rcC, hDev) = s.ConnectDev(device.SerialNumber);
        if (rcC != SkfNative.SAR_OK) return device;
        try
        {
            var (rcI, info) = s.GetDevInfo(hDev);
            if (rcI == SkfNative.SAR_OK && info != null) Fill(device, info);
        }
        finally { s.DisConnectDev(hDev); }
        return device;
    }

    // ============================================================ 连接 / 应用

    /// <summary>连接设备并打开应用；重复调用复用同一会话。</summary>
    private (IntPtr Dev, IntPtr App) EnsureOpen(UsbKeyDevice device)
    {
        var s = Session;
        if (_hApp != IntPtr.Zero && string.Equals(_devName, device.SerialNumber, StringComparison.OrdinalIgnoreCase))
            return (_hDev, _hApp);

        CloseSession();

        var (rcC, hDev) = s.ConnectDev(device.SerialNumber);
        if (rcC != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_ConnectDev 失败：{SkfNative.Describe(rcC)}");

        var appName = string.IsNullOrWhiteSpace(_appName) ? DefaultAppName : _appName;
        var (rcO, hApp) = s.OpenApplication(hDev, appName);
        if (rcO != SkfNative.SAR_OK)
        {
            s.DisConnectDev(hDev);
            throw new InvalidOperationException(
                $"SKF_OpenApplication(\"{appName}\") 失败：{SkfNative.Describe(rcO)}");
        }

        _hDev = hDev;
        _hApp = hApp;
        _devName = device.SerialNumber;
        return (_hDev, _hApp);
    }

    private void CloseSession()
    {
        var s = _session;
        if (s == null) return;
        try { if (_hApp != IntPtr.Zero) s.CloseApplication(_hApp); } catch { }
        try { if (_hDev != IntPtr.Zero) s.DisConnectDev(_hDev); } catch { }
        _hApp = IntPtr.Zero;
        _hDev = IntPtr.Zero;
        _devName = "";
        _userLoggedIn = false;
    }

    /// <summary>可选：自定义应用名（默认 BJCA-Application）。</summary>
    private string _appName = "";

    // ============================================================ 登录 / 登出

    /// <summary>用户 PIN 登录（SKF_VerifyPIN，PIN 类型 1）。</summary>
    public void Login(UsbKeyDevice device, string pin)
    {
        Validators.EnsurePin(pin);
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rc, remain) = s.VerifyPin(hApp, PinTypeUser, pin);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException(
                $"用户 PIN 认证失败：{SkfNative.Describe(rc)}，剩余重试 {remain} 次");
        _userLoggedIn = true;
        device.IsLoggedIn = true;
        Log.Write($"[SKF] {device.SerialNumber} 用户 PIN 登录成功");
    }

    /// <summary>管理员口令认证（PIN 类型 0）。用于重置等管理操作。</summary>
    public void VerifyAdminPin(UsbKeyDevice device, string adminPin)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rc, remain) = s.VerifyPin(hApp, PinTypeAdmin, adminPin);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException(
                $"管理口令认证失败：{SkfNative.Describe(rc)}，剩余重试 {remain} 次");
    }

    public void Logout(UsbKeyDevice device)
    {
        if (_session != null && _hApp != IntPtr.Zero) { try { _session.ClearSecureState(_hApp); } catch { } }
        _userLoggedIn = false;
        device.IsLoggedIn = false;
    }

    // ============================================================ 容器 / 证书

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var result = new List<KeyContainer>();

        var (rc, names) = s.EnumContainer(hApp);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_EnumContainer 失败：{SkfNative.Describe(rc)}");

        foreach (var name in names)
        {
            var (rcO, hCon) = s.OpenContainer(hApp, name);
            if (rcO != SkfNative.SAR_OK)
            {
                result.Add(new KeyContainer
                {
                    Name = "",
                    ContainerName = name,
                    ContainerUuid = name,
                    Content = KeyContainerContent.Unreadable,
                    Algorithm = $"打开失败：{SkfNative.Describe(rcO)}",
                });
                continue;
            }
            try
            {
                // 容器里可能同时有签名证书与加密证书，这里以「签名证书」为主
                var (rcSign, certSign) = s.ExportCertificate(hCon, true);
                var (rcEnc, certEnc) = s.ExportCertificate(hCon, false);
                var cert = (rcSign == SkfNative.SAR_OK && certSign.Length > 0) ? certSign
                         : (rcEnc == SkfNative.SAR_OK && certEnc.Length > 0) ? certEnc
                         : null;

                KeyContainer c;
                if (cert != null)
                {
                    c = BuildContainer(cert, name);
                    c.Content = KeyContainerContent.Certificate;
                    if (cert == certEnc && cert != certSign)
                        c.KeyUsage = "数据加密";
                }
                else
                {
                    /* 无证书：用「公钥能否导出」判定容器里到底有没有密钥对。
                       不能依赖 SKF_GetContainerType —— 实测本卡 UserKey 有完整密钥对且已导入证书，
                       该接口仍返回 1（未定），故只借它取算法名，不作有无密钥的判据。
                       名称留空：「名称」列表达证书 CN，容器名归「容器 UUID」列；
                       容器名仍保留在 ContainerName，用于打开/删除。 */
                    var (rcPubSign, pubSign) = s.ExportPublicKey(hCon, true);
                    var (rcPubEnc, pubEnc) = s.ExportPublicKey(hCon, false);
                    bool hasKey = (rcPubSign == SkfNative.SAR_OK && pubSign.Length > 0)
                               || (rcPubEnc == SkfNative.SAR_OK && pubEnc.Length > 0);

                    var (_, type) = s.GetContainerType(hCon);
                    var alg = type switch { 2 => "RSA", 3 => "ECC/SM2", _ => "" };
                    c = new KeyContainer
                    {
                        Name = "",
                        ContainerName = name,
                        ContainerUuid = name,
                        Content = hasKey ? KeyContainerContent.KeyOnly : KeyContainerContent.Empty,
                        Algorithm = hasKey
                            ? (alg.Length > 0 ? $"{alg} 密钥（无证书）" : "密钥（无证书）")
                            : "空容器（无密钥、无证书）",
                    };
                }
                result.Add(c);
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"[SKF] 读取容器 {name} 失败");
                result.Add(new KeyContainer
                {
                    Name = "",
                    ContainerName = name,
                    ContainerUuid = name,
                    Content = KeyContainerContent.Unreadable,
                });
            }
            finally { s.CloseContainer(hCon); }
        }

        foreach (var c in result)
            if (!string.IsNullOrEmpty(c.Thumbprint))
                c.IsRegisteredInCsp = Crypto.CertHelper.IsRegistered(c.Thumbprint);
        return result;
    }

    private static KeyContainer BuildContainer(byte[] certDer, string containerName)
    {
        using var cert = new X509Certificate2(certDer);
        return new KeyContainer
        {
            Name = cert.GetNameInfo(X509NameType.SimpleName, false),
            ContainerName = containerName,
            ContainerUuid = containerName,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "未知算法",
            KeyUsage = "数字签名",
            ExtendedKeyUsage = "—",
            CertRaw = certDer,
        };
    }

    /// <summary>
    /// SKF 不提供「导入外部私钥（PFX）」的能力：私钥只在卡内生成、不可导出也不可导入。
    /// 正确做法见 <see cref="CreateContainer"/> / <see cref="ImportCertificate"/>。
    /// </summary>
    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
        => throw new NotSupportedException(
            "SKF（GM/T 0016）设备不支持导入外部 PFX（含私钥）——私钥在卡内生成、不可导出也不可导入。" +
            Environment.NewLine + "正确流程：① 在卡内生成密钥对（本软件「重置设备」可完成设备初始化）；" +
            "② 导出公钥/PKCS#10 提交 CA；③ 用 ImportCertificate 把签发结果导入容器。");

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        var der = container.CertRaw ?? ReadCert(device, container.ContainerName);
        if (der == null) throw new InvalidOperationException("无法从容器读取证书");
        File.WriteAllBytes(outputPath, der);
    }

    private byte[]? ReadCert(UsbKeyDevice device, string containerName)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rcO, hCon) = s.OpenContainer(hApp, containerName);
        if (rcO != SkfNative.SAR_OK) return null;
        try
        {
            var (rc, cert) = s.ExportCertificate(hCon, true);
            if (rc == SkfNative.SAR_OK && cert.Length > 0) return cert;
            var (rc2, cert2) = s.ExportCertificate(hCon, false);
            return rc2 == SkfNative.SAR_OK && cert2.Length > 0 ? cert2 : null;
        }
        finally { s.CloseContainer(hCon); }
    }

    public void ViewCertificate(KeyContainer container)
    {
        var der = container.CertRaw;
        if (der == null) throw new InvalidOperationException("证书数据不可用");
        var tmp = Path.Combine(Path.GetTempPath(), $"skf_{Guid.NewGuid():N}.cer");
        File.WriteAllBytes(tmp, der);
        Crypto.CertHelper.ViewCertificateFile(tmp);
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var rc = s.DeleteContainer(hApp, container.ContainerName);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_DeleteContainer 失败：{SkfNative.Describe(rc)}");
        Log.Write($"[SKF] 已删除容器 {container.ContainerName}");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        Crypto.CertHelper.Register(container.CertRaw, container.Name);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            Crypto.CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    // ============================================================ SKF 专属：容器 / 密钥 / 证书导入

    /// <summary>新建容器（SKF_CreateContainer）。</summary>
    public void CreateContainer(UsbKeyDevice device, string containerName)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rc, hCon) = s.CreateContainer(hApp, containerName);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_CreateContainer 失败：{SkfNative.Describe(rc)}");
        s.CloseContainer(hCon);
        Log.Write($"[SKF] 已创建容器 {containerName}");
    }

    /// <summary>在容器内生成密钥对。<paramref name="ecc"/> 为 true 时生成 ECC/SM2，否则 RSA。</summary>
    public void GenerateKeyPair(UsbKeyDevice device, string containerName, bool ecc = false, uint bitsOrAlg = 2048)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rcO, hCon) = s.OpenContainer(hApp, containerName);
        if (rcO != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_OpenContainer 失败：{SkfNative.Describe(rcO)}");
        try
        {
            var (rc, blob) = ecc ? s.GenEccKeyPair(hCon, bitsOrAlg) : s.GenRsaKeyPair(hCon, bitsOrAlg);
            if (rc != SkfNative.SAR_OK)
                throw new InvalidOperationException(
                    $"{(ecc ? "SKF_GenECCKeyPair" : "SKF_GenRSAKeyPair")} 失败：{SkfNative.Describe(rc)}");
            Log.Write($"[SKF] 容器 {containerName} 已生成密钥对（{(ecc ? $"ECC alg={bitsOrAlg}" : $"RSA {bitsOrAlg}")}，返回 {blob.Length}B）");
        }
        finally { s.CloseContainer(hCon); }
    }

    /// <summary>导入证书（SKF_ImportCertificate）。证书公钥必须与容器内密钥匹配。</summary>
    public void ImportCertificate(UsbKeyDevice device, string containerName, byte[] certDer, bool sign = true)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rcO, hCon) = s.OpenContainer(hApp, containerName);
        if (rcO != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_OpenContainer 失败：{SkfNative.Describe(rcO)}");
        try
        {
            var rc = s.ImportCertificate(hCon, sign, certDer);
            if (rc != SkfNative.SAR_OK)
                throw new InvalidOperationException(
                    $"SKF_ImportCertificate 失败：{SkfNative.Describe(rc)}（证书公钥需与容器内密钥匹配）");
            Log.Write($"[SKF] 已导入证书 → 容器 {containerName}（sign={sign}）");
        }
        finally { s.CloseContainer(hCon); }
    }

    /// <summary>导出容器内公钥（原始 SKF blob）。</summary>
    /// <summary>
    /// 【只读探测】评估国标「导入密钥对」（<c>SKF_ImportRSAKeyPair</c>）在本设备上的可行性。
    ///
    /// <para>不创建容器、不写入任何数据，只回答三件事：</para>
    /// <list type="number">
    /// <item>设备的算法能力位图（决定 <c>ulSymAlgId</c> 可用取值）与设备认证算法 <c>DevAuthAlgId</c>；</item>
    /// <item>各容器的<b>公钥能否导出</b> —— 国标导入流程要用「容器的密钥加密公钥」保护会话密钥，
    /// 若本中间件在空容器上导不出公钥，则说明导入必须先有密钥来源，路径需要重新设计；</item>
    /// <item>容器枚举结果，作为对照基线。</item>
    /// </list>
    ///
    /// <para>之所以要先做这一步：07/08 文档中关于「导入密钥」的结论都缺少参数层面的实证，
    /// 而 <c>SKF_ImportRSAKeyPair</c> 的 <c>pbEncryptedKey</c> 必须由设备侧公钥加密而来 ——
    /// 这个前提不落实，写再多调用代码都是盲猜。</para>
    /// </summary>
    public string ProbeImportCapability(UsbKeyDevice device)
    {
        var s = Session;
        var lines = new List<string>();
        var (rcC, hDev) = s.ConnectDev(device.SerialNumber);
        if (rcC != SkfNative.SAR_OK)
            return $"SKF_ConnectDev 失败：{SkfNative.Describe(rcC)}";

        try
        {
            var (rcI, info) = s.GetDevInfo(hDev);
            if (rcI == SkfNative.SAR_OK && info != null)
            {
                lines.Add($"DEVINFO        : {info}");
                lines.Add($"  AlgSymCap      = 0x{info.AlgSymCap:X8}  （对称算法能力位图）");
                lines.Add($"  AlgAsymCap     = 0x{info.AlgAsymCap:X8}  （非对称算法能力位图）");
                lines.Add($"  AlgHashCap     = 0x{info.AlgHashCap:X8}  （摘要算法能力位图）");
                lines.Add($"  DevAuthAlgId   = 0x{info.DevAuthAlgId:X8}  （设备认证算法，SKF_DevAuth 使用）");
                lines.Add($"  ChannelMaxBufLen = {info.ChannelMaxBufLen}");
            }
            else
            {
                lines.Add($"SKF_GetDevInfo 失败：{SkfNative.Describe(rcI)}");
            }

            var appName = string.IsNullOrWhiteSpace(_appName) ? DefaultAppName : _appName;
            var (rcO, hApp) = s.OpenApplication(hDev, appName);
            if (rcO != SkfNative.SAR_OK)
            {
                lines.Add($"SKF_OpenApplication({appName}) 失败：{SkfNative.Describe(rcO)}");
                return string.Join(Environment.NewLine, lines);
            }

            try
            {
                var (rcE, names) = s.EnumContainer(hApp);
                lines.Add($"容器枚举       : {SkfNative.Describe(rcE)}，共 {names.Count} 个" +
                          (names.Count > 0 ? $" [{string.Join(", ", names)}]" : ""));

                foreach (var cn in names)
                {
                    var (rcOc, hCon) = s.OpenContainer(hApp, cn);
                    if (rcOc != SkfNative.SAR_OK)
                    {
                        lines.Add($"  容器 {cn}：打开失败 {SkfNative.Describe(rcOc)}");
                        continue;
                    }
                    try
                    {
                        var (rcS, signKey) = s.ExportPublicKey(hCon, true);
                        var (rcN, encKey) = s.ExportPublicKey(hCon, false);
                        lines.Add($"  容器 {cn}：");
                        lines.Add($"      签名公钥  {SkfNative.Describe(rcS)}  len={signKey.Length}");
                        lines.Add($"      加密公钥  {SkfNative.Describe(rcN)}  len={encKey.Length}");
                    }
                    finally { s.CloseContainer(hCon); }
                }
            }
            finally { s.CloseApplication(hApp); }
        }
        finally { s.DisConnectDev(hDev); }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// 【探测】真实调用一次 <c>SKF_ImportRSAKeyPair</c>，用<b>最小负载</b>观察中间件的反应，
    /// 以此判定该接口在本设备上是否可用、以及它期望的参数形态。
    ///
    /// <para><b>这是写操作</b>：会创建并以 <c>SKF_DeleteContainer</c> 清理一个临时容器
    /// （默认名 <c>ZZIMPORTTEST</c>）；除此之外不触碰卡上任何既有数据。</para>
    ///
    /// <para>之所以要实际调用：国标 <c>SKF_ImportRSAKeyPair</c> 的 <c>pbEncryptedKey</c>
    /// 要求「用设备密钥加密公钥保护的对称密钥」，而实测本卡容器的<b>加密公钥不存在</b>
    /// （<c>SKF_ExportPublicKey(sign=false)</c> 返回 <c>0x0A000031 文件不存在</c>）。
    /// 因此必须先看清中间件在参数不足时给什么错误码，才能判断这条路是否走得通，
    /// 而不是照着国标把参数猜一遍。</para>
    /// </summary>
    public string ProbeImportKeyPairCall(UsbKeyDevice device, string adminPin, string probeContainer = "ZZIMPORTTEST")
    {
        var s = Session;
        var lines = new List<string>();
        var (_, hApp) = EnsureOpen(device);

        var (rcAuth, remain) = s.VerifyPin(hApp, PinTypeAdmin, adminPin);
        lines.Add($"管理口令认证：{SkfNative.Describe(rcAuth)}（剩余重试 {remain}）");
        if (rcAuth != SkfNative.SAR_OK)
            return string.Join(Environment.NewLine, lines);

        // 建一个临时容器承载导入动作
        var (rcC, hCon) = s.CreateContainer(hApp, probeContainer);
        lines.Add($"SKF_CreateContainer({probeContainer})：{SkfNative.Describe(rcC)}");
        if (rcC != SkfNative.SAR_OK)
        {
            // 已存在则尝试打开
            var (rcO2, hCon2) = s.OpenContainer(hApp, probeContainer);
            lines.Add($"  改尝试打开：{SkfNative.Describe(rcO2)}");
            if (rcO2 != SkfNative.SAR_OK) return string.Join(Environment.NewLine, lines);
            hCon = hCon2;
        }

        try
        {
            // 依次用「空对称算法 + 空负载」调用，只观察参数校验反应，不送入真实密钥材料。
            (uint Alg, string Name)[] algs =
            {
                (0x00000000, "0（未指定）"),
                (0x00000101, "SGD_SM1_ECB?"),
                (0x00000401, "SGD_SM4_ECB?"),
                (0x00000801, "SGD_AES128_ECB?"),
            };

            lines.Add("SKF_ImportRSAKeyPair 空负载调用（仅探测参数校验，不送真实密钥）：");
            foreach (var (alg, name) in algs)
            {
                try
                {
                    var rc = s.ImportRsaKeyPair(hCon, alg, Array.Empty<byte>(), Array.Empty<byte>());
                    lines.Add($"  symAlgId=0x{alg:X8} {name,-18} → {SkfNative.Describe(rc)}");
                }
                catch (Exception ex)
                {
                    lines.Add($"  symAlgId=0x{alg:X8} {name,-18} → 调用异常：{ex.Message}");
                }
            }

            // ---- 分水岭实验：容器内先有一对密钥后，0x0A000031 是否消失？----
            // 若消失 ⇒ 该接口依赖"容器内已存在加密密钥对"，属可绕过的前置条件；
            // 若依旧 ⇒ 它找的是设备级文件，本中间件在纯导入场景下不给这条路。
            lines.Add("");
            lines.Add("【分水岭】先在容器内生成一对 RSA 密钥，再复查：");
            var (rcG, _) = s.GenRsaKeyPair(hCon, 1024);
            lines.Add($"  SKF_GenRSAKeyPair(1024) → {SkfNative.Describe(rcG)}");

            var (rcP1, pk1) = s.ExportPublicKey(hCon, true);
            var (rcP2, pk2) = s.ExportPublicKey(hCon, false);
            lines.Add($"  生成后 签名公钥 → {SkfNative.Describe(rcP1)} len={pk1.Length}");
            lines.Add($"  生成后 加密公钥 → {SkfNative.Describe(rcP2)} len={pk2.Length}");

            try
            {
                var rc2 = s.ImportRsaKeyPair(hCon, 0x00000401, Array.Empty<byte>(), Array.Empty<byte>());
                lines.Add($"  生成后再调 ImportRSAKeyPair → {SkfNative.Describe(rc2)}");
                lines.Add(rc2 == SkfNative.SAR_OK
                    ? "  ⇒ 结论：前置条件仅为「容器内已有密钥对」，导入路径【可行】。"
                    : (rc2 == 0x0A000031
                        ? "  ⇒ 结论：仍报「文件不存在」，说明它找的是设备级文件，本中间件不支持该导入路径。"
                        : "  ⇒ 结论：错误码已改变，说明进入更深的校验阶段，路径需要继续细化参数。"));
            }
            catch (Exception ex)
            {
                lines.Add($"  生成后再调 ImportRSAKeyPair → 异常：{ex.Message}");
            }
        }
        finally
        {
            s.CloseContainer(hCon);
            var rcD = s.DeleteContainer(hApp, probeContainer);
            lines.Add($"清理：SKF_DeleteContainer({probeContainer}) → {SkfNative.Describe(rcD)}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// 【方案A 实测·第二步】按国标语义构造<b>真实参数</b>，尝试用 <c>SKF_ImportRSAKeyPair</c>
    /// 把一对外部 RSA 密钥导入卡内。
    ///
    /// <para><b>国标参数关系</b>：</para>
    /// <code>
    /// pbWrappedKey   = 用对称算法 ulSymAlgId 加密后的 RSA 私钥密文
    /// pbEncryptedKey = 用「容器公钥」加密的对称密钥密文
    /// 中间件侧顺序：容器私钥解 pbEncryptedKey → 得对称密钥 → 解 pbWrappedKey → 得 RSA 私钥
    /// </code>
    ///
    /// <para><b>前置事实</b>（均由本探针实测得到，非文档推断）：</para>
    /// <list type="bullet">
    /// <item>空负载调用返回 <c>0x0A000031 文件不存在</c> —— 容器内必须先有密钥对；</item>
    /// <item>容器内生成密钥对后，同样的空负载调用改报 <c>0x0A000019 RSA解密错误</c> ——
    /// 说明中间件确实在用容器私钥解 <c>pbEncryptedKey</c>，参数方向与国标一致；</item>
    /// <item>本卡 <c>AlgSymCap = 0x00030700</c>，按 GM/T 0016 附录的 <c>SGD_</c> 位图解码为
    /// SM4(ECB/CBC/CFB) 与 AES128(ECB/CBC)。</item>
    /// </list>
    ///
    /// <para><b>这是写操作</b>：会建临时容器（默认 <c>ZZIMPKEY</c>）并在结束时删除。</para>
    /// </summary>
    public string ProbeImportRealKeyPair(UsbKeyDevice device, string adminPin, string probeContainer = "ZZIMPKEY")
    {
        var s = Session;
        var lines = new List<string>();
        var (_, hApp) = EnsureOpen(device);

        var (rcAuth, _) = s.VerifyPin(hApp, PinTypeAdmin, adminPin);
        lines.Add($"管理口令认证：{SkfNative.Describe(rcAuth)}");
        if (rcAuth != SkfNative.SAR_OK) return string.Join(Environment.NewLine, lines);

        var (rcC, hCon) = s.CreateContainer(hApp, probeContainer);
        lines.Add($"SKF_CreateContainer({probeContainer})：{SkfNative.Describe(rcC)}");
        if (rcC != SkfNative.SAR_OK)
        {
            var (rcO2, hCon2) = s.OpenContainer(hApp, probeContainer);
            if (rcO2 != SkfNative.SAR_OK)
            {
                lines.Add($"  打开也失败：{SkfNative.Describe(rcO2)}");
                return string.Join(Environment.NewLine, lines);
            }
            hCon = hCon2;
        }

        try
        {
            // 1) 先让容器具备解密能力
            var (rcG, _) = s.GenRsaKeyPair(hCon, 1024);
            lines.Add($"SKF_GenRSAKeyPair(1024)：{SkfNative.Describe(rcG)}");
            if (rcG != SkfNative.SAR_OK) return string.Join(Environment.NewLine, lines);

            // 2) 取容器公钥（268 字节厂商 blob，布局见 Roadmap/08 §4）
            var (rcP, blob) = s.ExportPublicKey(hCon, true);
            lines.Add($"SKF_ExportPublicKey(sign=true)：{SkfNative.Describe(rcP)} len={blob.Length}");

            // 3) 造一对"待导入"的 RSA 密钥
            using var rsaToImport = System.Security.Cryptography.RSA.Create(1024);
            var pkcs1 = rsaToImport.ExportRSAPrivateKey();       // PKCS#1 RSAPrivateKey DER
            lines.Add($"待导入私钥：PKCS#1 DER {pkcs1.Length} 字节");

            // 4) 对称密钥 + 加密（AlgSymCap 表明支持 SM4/AES128；此处用 .NET 内置的 AES-128-ECB）
            var symKey = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(symKey);
            byte[] wrapped;
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = symKey;
                aes.Mode = System.Security.Cryptography.CipherMode.ECB;
                aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                wrapped = aes.CreateEncryptor().TransformFinalBlock(pkcs1, 0, pkcs1.Length);
            }
            lines.Add($"pbWrappedKey={wrapped.Length} 字节");

            // 5) 逐一遍历「字节序 × padding × 对称算法」三种不确定性，直到找到中间件接受的那组。
            //    之所以要扫：厂商 blob 的 Modulus 字节序、以及它期望的 RSA padding 都没有文档，
            //    而 0x0A000019「RSA解密错误」恰好说明它确实在做容器私钥解密，只是解不开我们的密文。
            (bool ReverseMod, string OrdName)[] orders = { (false, "大端"), (true, "小端") };
            (System.Security.Cryptography.RSAEncryptionPadding Pad, string PadName)[] pads =
            {
                (System.Security.Cryptography.RSAEncryptionPadding.Pkcs1, "PKCS#1v1.5"),
                (System.Security.Cryptography.RSAEncryptionPadding.OaepSHA1, "OAEP-SHA1"),
            };
            (uint Alg, string Name)[] algs =
            {
                (0x00010000, "SGD_AES128_ECB"),
                (0x00020000, "SGD_AES128_CBC"),
                (0x00000100, "SGD_SM4_ECB"),
                (0x00000200, "SGD_SM4_CBC"),
            };

            lines.Add("");
            lines.Add("SKF_ImportRSAKeyPair 参数扫描：");
            bool anyOk = false;
            foreach (var (reverse, ordName) in orders)
            {
                var pub = TryParsePubKeyBlob(blob, reverse);
                if (pub == null) { lines.Add($"  公钥解析失败（{ordName}），跳过。"); continue; }
                using var _ = pub;
                lines.Add($"  ── 公钥字节序：{ordName}（{pub.KeySize} 位）──");

                foreach (var (pad, padName) in pads)
                {
                    byte[] encKey;
                    try { encKey = pub.Encrypt(symKey, pad); }
                    catch (Exception ex) { lines.Add($"    {padName}：加密失败 {ex.Message}"); continue; }

                    foreach (var (alg, name) in algs)
                    {
                        try
                        {
                            var rc = s.ImportRsaKeyPair(hCon, alg, wrapped, encKey);
                            lines.Add($"    {padName,-11} {name,-16} → {SkfNative.Describe(rc)}");
                            if (rc == SkfNative.SAR_OK)
                            {
                                anyOk = true;
                                var (rcChk, pk) = s.ExportPublicKey(hCon, true);
                                lines.Add($"     导入后容器公钥：{SkfNative.Describe(rcChk)} len={pk.Length}");
                                lines.Add($"     ⇒ 方案 A 成功！可用组合：字节序={ordName}, padding={padName}, ulSymAlgId=0x{alg:X8}({name})");
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            lines.Add($"    {padName,-11} {name,-16} → 异常：{ex.Message}");
                        }
                    }
                    if (anyOk) break;
                }
                if (anyOk) break;
            }

            if (!anyOk)
                lines.Add("  ⇒ 上述组合全部失败，需要继续排查（对称算法标识或密钥包装格式可能另有约定）。");
        }
        finally
        {
            s.CloseContainer(hCon);
            var rcD = s.DeleteContainer(hApp, probeContainer);
            lines.Add($"清理：SKF_DeleteContainer({probeContainer}) → {SkfNative.Describe(rcD)}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// 解析 <c>SKF_ExportPublicKey</c> 返回的厂商公钥 blob（实测 268 字节，RSA）。
    /// <para>布局（Roadmap/08 §4 实测）：<c>[0..3]</c> 头、<c>[4..7]</c> 位长(小端)、
    /// <c>[8..263]</c> Modulus[256]（小密钥右对齐）、<c>[264..267]</c> Exponent（大端）。</para>
    /// </summary>
    private static System.Security.Cryptography.RSA? TryParsePubKeyBlob(byte[] blob, bool reverseModulus = false)
    {
        try
        {
            if (blob.Length < 268) return null;
            var bits = BitConverter.ToUInt32(blob, 4);
            if (bits == 0 || bits % 8 != 0) bits = 1024;
            var modLen = (int)(bits / 8);

            var modulus = new byte[modLen];
            // Modulus 区固定 256 字节、小密钥右对齐，取其末尾 modLen 字节
            Array.Copy(blob, 8 + 256 - modLen, modulus, 0, modLen);
            // 厂商 blob 的字节序没有文档：先按标准大端尝试，失败再试反转（由调用方遍历）。
            if (reverseModulus) Array.Reverse(modulus);

            var exponent = new byte[4];
            Array.Copy(blob, 264, exponent, 0, 4);        // 大端，如 00 01 00 01

            var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportParameters(new System.Security.Cryptography.RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent,
            });
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    public byte[] ExportPublicKey(UsbKeyDevice device, string containerName, bool sign = true)
    {
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rcO, hCon) = s.OpenContainer(hApp, containerName);
        if (rcO != SkfNative.SAR_OK)
            throw new InvalidOperationException($"SKF_OpenContainer 失败：{SkfNative.Describe(rcO)}");
        try
        {
            var (rc, blob) = s.ExportPublicKey(hCon, sign);
            if (rc != SkfNative.SAR_OK)
                throw new InvalidOperationException($"SKF_ExportPublicKey 失败：{SkfNative.Describe(rc)}");
            return blob;
        }
        finally { s.CloseContainer(hCon); }
    }

    // ============================================================ 口令 / 解锁 / 重置

    /// <summary>修改用户 PIN（SKF_ChangePIN，PIN 类型 1）。</summary>
    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        Validators.EnsurePin(newPin);
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rc, remain) = s.ChangePin(hApp, PinTypeUser, oldPin, newPin);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException(
                $"修改用户 PIN 失败：{SkfNative.Describe(rc)}，剩余重试 {remain} 次");
        _userLoggedIn = true;
        Log.Write($"[SKF] {device.SerialNumber} 用户 PIN 已修改");
    }

    /// <summary>修改管理口令（SKF_ChangePIN，PIN 类型 0）。</summary>
    public void ChangeAdminPin(UsbKeyDevice device, string oldPin, string newPin)
    {
        Validators.EnsurePin(newPin);
        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var (rc, remain) = s.ChangePin(hApp, PinTypeAdmin, oldPin, newPin);
        if (rc != SkfNative.SAR_OK)
            throw new InvalidOperationException(
                $"修改管理口令失败：{SkfNative.Describe(rc)}，剩余重试 {remain} 次");
        Log.Write($"[SKF] {device.SerialNumber} 管理口令已修改");
    }

    /// <summary>
    /// 解锁：用管理口令把「已锁定的用户 PIN」重设为 <paramref name="newPin"/>
    /// （<c>SKF_UnblockPIN(hApp, szAdminPIN, szNewUserPIN, &amp;retry)</c>）。
    /// </summary>
    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        Validators.EnsurePin(newPin);
        switch (method)
        {
            case UnlockMethod.AdminKey:
            case UnlockMethod.Puk:
                {
                    var s = Session;
                    var (_, hApp) = EnsureOpen(device);
                    var (rc, remain) = s.UnblockPin(hApp, credential, newPin);
                    if (rc != SkfNative.SAR_OK)
                        throw new InvalidOperationException(
                            $"解锁失败：{SkfNative.Describe(rc)}，剩余重试 {remain} 次（管理口令不正确或用户 PIN 未锁定）");
                    _userLoggedIn = true;
                    device.IsLoggedIn = true;
                    Log.Write($"[SKF] {device.SerialNumber} 用户 PIN 已通过管理口令重设");
                    return;
                }
            case UnlockMethod.Challenge:
                throw new NotSupportedException("SKF（GM/T 0016）不提供挑战码解锁通道，请使用管理口令解锁。");
            default:
                throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    public string GenerateChallenge(UsbKeyDevice device)
    {
        var s = Session;
        var (hDev, _) = EnsureOpen(device);
        var (rc, data) = s.GenRandom(hDev, 16);
        if (rc != SkfNative.SAR_OK) throw new InvalidOperationException($"SKF_GenRandom 失败：{SkfNative.Describe(rc)}");
        return Convert.ToHexString(data);
    }

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
        => throw new NotSupportedException("SKF（GM/T 0016）不提供挑战码解锁通道。");

    /// <summary>
    /// 重置（清空内容 + 重设两套口令）。
    ///
    /// <para><b>为什么不用 <c>SKF_DeleteApplication</c></b>：实测该接口在本中间件上恒定返回
    /// <c>0x0A00002D「用户没有登录」</c>，且 <c>SKF_VerifyPIN(设备句柄,…)</c> 会直接崩溃 ——
    /// 说明删除应用依赖的是 <b>设备认证（SKF_DevAuth，厂商密钥）</b>而非 PIN，属厂商私有通道。</para>
    ///
    /// <para><b>因此改用等价且已实测可行的组合</b>（全部为 SKF 标准接口）：
    /// <list type="number">
    /// <item><c>SKF_VerifyPIN(type=0)</c> 认证当前管理口令；</item>
    /// <item><c>SKF_EnumContainer</c> + <c>SKF_DeleteContainer</c> 删除全部容器（连同密钥与证书）；</item>
    /// <item><c>SKF_EnumFiles</c> + <c>SKF_DeleteFile</c> 删除应用下全部文件；</item>
    /// <item><c>SKF_ChangePIN(type=0)</c> 把管理口令改成新值；</item>
    /// <item><c>SKF_UnblockPIN(新管理口令, 新用户PIN)</c> 把用户 PIN 强制重设为新值（<b>不需要旧用户 PIN</b>）；</item>
    /// <item>用新口令复验。</item>
    /// </list>
    /// </para>
    ///
    /// <para><b>入参映射</b>：<paramref name="currentPin"/> = 当前管理口令（认证用，缺省用出厂值 111111）；
    /// <paramref name="adminKey"/> = 新管理口令（缺省与当前相同）；<paramref name="newPin"/> = 新用户 PIN；
    /// <paramref name="puk"/> 不使用（SKF 无独立 PUK，解锁由管理口令承担）。</para>
    /// </summary>
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        Validators.EnsurePin(newPin);
        var currentAdmin = !string.IsNullOrWhiteSpace(currentPin) ? currentPin!.Trim()
                         : !string.IsNullOrWhiteSpace(adminKey) ? adminKey!.Trim()
                         : DefaultAdminPin;
        var newAdmin = !string.IsNullOrWhiteSpace(adminKey) ? adminKey!.Trim() : currentAdmin;

        var s = Session;
        var (_, hApp) = EnsureOpen(device);
        var report = new List<string>
        {
            $"设备序列号 : {device.SerialNumber}",
            $"应用名     : {(_appName.Length > 0 ? _appName : DefaultAppName)}",
            $"当前管理口令: {Mask(currentAdmin)}（认证用）",
            $"新管理口令 : {Mask(newAdmin)}",
            $"新用户 PIN : {Mask(newPin)}",
        };

        // 1) 认证当前管理口令
        var (rcAdmin, remainAdmin) = s.VerifyPin(hApp, PinTypeAdmin, currentAdmin);
        report.Add($"1) 认证管理口令 → {SkfNative.Describe(rcAdmin)}（剩余重试 {remainAdmin}）");
        if (rcAdmin != SkfNative.SAR_OK)
        {
            LastResetReport = string.Join(Environment.NewLine, report);
            throw new InvalidOperationException(
                "重置失败：当前管理口令不正确。" + Environment.NewLine +
                "请在重置对话框中填入该 USBKey 的当前管理口令（出厂值为 111111）。" + Environment.NewLine +
                string.Join(Environment.NewLine, report));
        }
        s.ClearSecureState(hApp);

        // 2) 删除全部容器
        var (_, cons) = s.EnumContainer(hApp);
        report.Add($"2) 重置前容器数 {cons.Count}" + (cons.Count > 0 ? $"（{string.Join(",", cons)}）" : ""));
        int deleted = 0;
        foreach (var c in cons)
        {
            var rc = s.DeleteContainer(hApp, c);
            report.Add($"   删除容器 {c} → {SkfNative.Describe(rc)}");
            if (rc == SkfNative.SAR_OK) deleted++;
        }
        report.Add($"   容器删除结果：{deleted}/{cons.Count}");

        // 3) 删除全部文件
        var (rcEnumF, files) = s.EnumFiles(hApp);
        report.Add($"3) 应用内文件数 {files.Count}（枚举 {SkfNative.Describe(rcEnumF)}）");
        foreach (var f in files)
            report.Add($"   删除文件 {f} → {SkfNative.Describe(s.DeleteFile(hApp, f))}");

        // 4) 改管理口令（需要旧口令）
        if (!string.Equals(newAdmin, currentAdmin, StringComparison.Ordinal))
        {
            var (rcA, rA) = s.ChangePin(hApp, PinTypeAdmin, currentAdmin, newAdmin);
            report.Add($"4) SKF_ChangePIN(管理口令 → 新值) → {SkfNative.Describe(rcA)}（剩余重试 {rA}）");
            if (rcA != SkfNative.SAR_OK)
            {
                LastResetReport = string.Join(Environment.NewLine, report);
                throw new InvalidOperationException("重置部分失败：管理口令修改未成功。" + Environment.NewLine +
                                                    string.Join(Environment.NewLine, report));
            }
        }
        else
        {
            report.Add("4) 管理口令不变，跳过修改");
        }

        // 5) 用管理口令把用户 PIN 强制重设为新值（不需要旧用户 PIN）
        var (rcU, rU) = s.UnblockPin(hApp, newAdmin, newPin);
        report.Add($"5) SKF_UnblockPIN(新管理口令, 新用户PIN) → {SkfNative.Describe(rcU)}（剩余重试 {rU}）");

        // 6) 复验
        s.ClearSecureState(hApp);
        var (rcV1, _) = s.VerifyPin(hApp, PinTypeAdmin, newAdmin);
        report.Add($"6) 复验新管理口令 → {SkfNative.Describe(rcV1)}");
        s.ClearSecureState(hApp);
        var (rcV2, _) = s.VerifyPin(hApp, PinTypeUser, newPin);
        report.Add($"   复验新用户 PIN → {SkfNative.Describe(rcV2)}");
        s.ClearSecureState(hApp);
        var (_, consAfter) = s.EnumContainer(hApp);
        report.Add($"   重置后容器数: {consAfter.Count}");

        LastResetReport = string.Join(Environment.NewLine, report);
        Log.Write("[SKF] 重置完成：" + Environment.NewLine + LastResetReport);

        if (rcU != SkfNative.SAR_OK || rcV2 != SkfNative.SAR_OK)
            throw new InvalidOperationException("重置未完全成功（用户 PIN 重设或复验失败）。" +
                                                Environment.NewLine + string.Join(Environment.NewLine, report));

        device.IsLoggedIn = true;
    }

    private static string Mask(string secret) => new string('*', Math.Max(1, secret.Length));

    public void Dispose()
    {
        CloseSession();
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
