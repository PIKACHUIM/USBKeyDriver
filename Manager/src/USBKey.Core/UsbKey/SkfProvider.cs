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
        Crypto.CertHelper.Register(container.CertRaw, container.Name, container.KeyBinding);
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
