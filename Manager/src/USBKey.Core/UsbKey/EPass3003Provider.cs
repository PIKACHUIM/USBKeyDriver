using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Configuration;
using USBKey.Core.Crypto;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// ePass3003 (HZCA 杭州银行) USB Key 驱动对接实现。
/// <para>
/// 对接目标：<c>HCCBCSP11.dll</c>（32 位标准 PKCS#11 / Cryptoki 实现，完全遵循 PKCS#11 v2.x 标准）。
/// </para>
/// <para>
/// 该 DLL 与恒宝的 CMBCp.dll 相同，都是标准 PKCS#11 接口，因此本 Provider 直接复用 
/// HengBaoProvider 的实现逻辑，按 PKCS#11 规范对接所有功能。
/// </para>
/// <para>
/// 关键约束：HCCBCSP11.dll 为 32 位，宿主进程必须以 x86 运行（见 csproj 的 PlatformTarget）。
/// </para>
/// <para>
/// <b>槽位号 ≠ 设备索引</b>：<c>C_GetSlotList</c> 返回的槽位号是不透明数值，必须原样回传给
/// C_OpenSession / C_GetTokenInfo / C_InitToken；界面用的「设备索引」只用于给设备列表排序，
/// 混用会得到 <c>CKR_SLOT_ID_INVALID</c>（"槽位句柄无效"）——见 <see cref="ResolveSlot"/>。
/// </para>
/// </summary>
public sealed class EPass3003Provider : IKeyProvider, IDisposable
{
    public string PlatformName => "epass3003";

    /// <summary>界面显示的型号名（与厂商工具写法一致）。</summary>
    private const string ModelHzca = "ePass 3003 (HZCA)";
    private const string ModelGeneric = "ePass 3003";

    private string _libraryRoot = "";
    /// <summary>实际加载的中间件路径（用于判定是 HZCA/HCCB 定制版还是官方通用版）。</summary>
    private string _dllPath = "";
    private NativeDll.Module? _dll;

    // PKCS#11 导出函数委托（与 HengBaoProvider 完全相同）
    private CkmNative.C_InitializeFn? _initialize;
    private CkmNative.C_FinalizeFn? _finalize;
    private CkmNative.C_GetSlotListFn? _getSlotList;
    private CkmNative.C_GetTokenInfoFn? _getTokenInfo;
    private CkmNative.C_GetSlotInfoFn? _getSlotInfo;
    private CkmNative.C_OpenSessionFn? _openSession;
    private CkmNative.C_CloseSessionFn? _closeSession;
    private CkmNative.C_LoginFn? _login;
    private CkmNative.C_LogoutFn? _logout;
    private CkmNative.C_SetPINFn? _setPin;
    private CkmNative.C_InitPINFn? _initPin;
    private CkmNative.C_InitTokenFn? _initToken;
    private CkmNative.C_GetAttributeValueFn? _getAttr;
    private CkmNative.C_FindObjectsInitFn? _findInit;
    private CkmNative.C_FindObjectsFn? _find;
    private CkmNative.C_FindObjectsFinalFn? _findFinal;
    private CkmNative.C_CreateObjectFn? _createObject;
    private CkmNative.C_DestroyObjectFn? _destroyObject;
    private CkmNative.C_SignInitFn? _signInit;
    private CkmNative.C_SignFn? _sign;

    // 会话缓存：设备索引 -> (slotId, session)
    private readonly Dictionary<int, (uint Slot, uint Session)> _sessions = new();
    private int _currentIndex = -1;

    private readonly List<(int Vid, int Pid)> _whitelist = new();

    public EPass3003Provider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
    {
        _libraryRoot = libraryRoot;
        if (whitelist != null)
            foreach (var d in whitelist)
                if (d.VidInt > 0 || d.PidInt > 0)
                    _whitelist.Add((d.VidInt, d.PidInt));
    }

    public bool IsAvailable
    {
        get
        {
            if (_dll != null) return true;
            return File.Exists(FindDllPath(_libraryRoot));
        }
    }

    public void Initialize()
    {
        if (_dll != null) return;
        
        var dllPath = FindDllPath(_libraryRoot);
        Console.WriteLine($"[ePass3003] 尝试加载 DLL: {dllPath}");
        _dll = NativeDll.Load(dllPath);
        if (_dll == null)
            throw new InvalidOperationException("无法加载 HCCBCSP11.dll（请确认 ePass3003 HZCA SDK 目录存在且为 32 位进程）");
        _dllPath = dllPath;
        Console.WriteLine("[ePass3003] DLL 加载成功");

        // 先检测 DLL 是否导出 PKCS#11 函数
        if (!_dll.HasExport("C_Initialize") && !_dll.HasExport("C_GetFunctionList"))
        {
            _dll.Dispose();
            _dll = null;
            throw new InvalidOperationException(
                "HCCBCSP11.dll 不是标准 PKCS#11 库（未导出 C_Initialize 或 C_GetFunctionList）。\n" +
                "该 DLL 是 Windows CSP，需要使用 CryptoAPI 访问，暂不支持。");
        }

        _initialize = _dll.GetDelegate<CkmNative.C_InitializeFn>("C_Initialize");
        _finalize = _dll.GetDelegate<CkmNative.C_FinalizeFn>("C_Finalize");
        _getSlotList = _dll.GetDelegate<CkmNative.C_GetSlotListFn>("C_GetSlotList");
        _getTokenInfo = _dll.GetDelegate<CkmNative.C_GetTokenInfoFn>("C_GetTokenInfo");
        _getSlotInfo = _dll.GetDelegate<CkmNative.C_GetSlotInfoFn>("C_GetSlotInfo");
        _openSession = _dll.GetDelegate<CkmNative.C_OpenSessionFn>("C_OpenSession");
        _closeSession = _dll.GetDelegate<CkmNative.C_CloseSessionFn>("C_CloseSession");
        _login = _dll.GetDelegate<CkmNative.C_LoginFn>("C_Login");
        _logout = _dll.GetDelegate<CkmNative.C_LogoutFn>("C_Logout");
        _setPin = _dll.GetDelegate<CkmNative.C_SetPINFn>("C_SetPIN");
        _initPin = _dll.GetDelegate<CkmNative.C_InitPINFn>("C_InitPIN");
        _initToken = _dll.GetDelegate<CkmNative.C_InitTokenFn>("C_InitToken");
        _getAttr = _dll.GetDelegate<CkmNative.C_GetAttributeValueFn>("C_GetAttributeValue");
        _findInit = _dll.GetDelegate<CkmNative.C_FindObjectsInitFn>("C_FindObjectsInit");
        _find = _dll.GetDelegate<CkmNative.C_FindObjectsFn>("C_FindObjects");
        _findFinal = _dll.GetDelegate<CkmNative.C_FindObjectsFinalFn>("C_FindObjectsFinal");
        _createObject = _dll.GetDelegate<CkmNative.C_CreateObjectFn>("C_CreateObject");
        _destroyObject = _dll.GetDelegate<CkmNative.C_DestroyObjectFn>("C_DestroyObject");
        _signInit = _dll.GetDelegate<CkmNative.C_SignInitFn>("C_SignInit");
        _sign = _dll.GetDelegate<CkmNative.C_SignFn>("C_Sign");

        if (_getSlotList == null)
            throw new InvalidOperationException("HCCBCSP11.dll 导出解析失败（C_GetSlotList 不存在）");

        // 初始化 PKCS#11 运行时
        var rc = _initialize!.Invoke(IntPtr.Zero);
        if (rc != CkmNative.CKR_OK && rc != 0x00000191 /* CKR_CRYPTOKI_ALREADY_INITIALIZED */)
            throw new InvalidOperationException($"PKCS#11 初始化失败 ({CkmNative.ErrorString(rc)})");
        
        Console.WriteLine("[ePass3003] PKCS#11 初始化成功");
    }

    private static string FindDllPath(string root)
    {
        // HCCBCSP11.dll 是 32 位 DLL，必须从 SysWOW64 加载
        var sys = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        var sysDll = Path.Combine(sys, "HCCBCSP11.dll");
        if (File.Exists(sysDll)) return sysDll;

        // 备用路径：从 SDK 目录加载
        if (string.IsNullOrWhiteSpace(root))
            root = Path.Combine(AppContext.BaseDirectory, "Library", "ePass3003 HZCA SDK");
        
        var libDll = Path.Combine(root, "SysWOW64", "HCCBCSP11.dll");
        if (File.Exists(libDll)) return libDll;

        return sysDll;
    }

    /// <summary>
    /// 判定当前对接的是不是「HZCA（杭州银行 / HCCB）定制版」ePass3003。
    /// <para>
    /// 依据：本 Provider 只对接 <c>HCCBCSP11.dll</c>——HCCB（杭州银行）定制版的 PKCS#11 中间件；
    /// 卡片侧的 label/model/manufacturer 也可能带 HCCB/HZCA/HZBANK 标识。
    /// 官方通用版是另一套中间件（CSP 名 <c>EnterSafe ePass3003 CSP</c>、注册表 <c>EnterSafe\ePass3003</c>），
    /// 两者在界面上的名称必须区分，否则用户无法确认自己看到的和厂商工具是不是同一把卡。
    /// </para>
    /// </summary>
    private bool IsHzcaVariant(params string?[] parts)
    {
        if (_dllPath.Contains("HCCB", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var p in parts)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            if (p.Contains("HCCB", StringComparison.OrdinalIgnoreCase) ||
                p.Contains("HZCA", StringComparison.OrdinalIgnoreCase) ||
                p.Contains("HZBANK", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// 厂商名取短名，与其它平台（LNCA / HengBao / Longmai …）保持一致：
    /// 卡内 <c>manufacturerID</c> 实测为 "Feitian Technologies Co., Ltd."，
    /// 直接照抄会把界面「厂商 / 型号」列挤满，反而看不到型号。
    /// </summary>
    private static string ShortVendorName(string mfr)
    {
        if (string.IsNullOrWhiteSpace(mfr)) return "Feitian（飞天诚信）";
        if (mfr.Contains("Feitian", StringComparison.OrdinalIgnoreCase) ||
            mfr.Contains("EnterSafe", StringComparison.OrdinalIgnoreCase) ||
            mfr.Contains("飞天", StringComparison.Ordinal))
            return "Feitian（飞天诚信）";
        return mfr.Trim();
    }

    /// <summary>
    /// 把界面句柄（设备索引）解析为 PKCS#11 的真实槽位号。
    /// <para>
    /// 这两个值必须严格分开：<c>C_GetSlotList</c> 返回的槽位号对 HCCBCSP11.dll 是不透明数值
    /// （实测不是 0/1/2 顺序）。早期实现把「设备索引」直接当槽位号传给 C_OpenSession，
    /// 于是恒返回 <c>CKR_SLOT_ID_INVALID</c>（界面提示"打开会话失败：槽位句柄无效"），登录永远失败。
    /// </para>
    /// </summary>
    private uint ResolveSlot(UsbKeyDevice device)
    {
        // 首选：枚举时记下的映射
        if (_sessions.TryGetValue(device.Handle, out var cached) && cached.Slot != 0)
            return cached.Slot;

        // 兜底 1：设备对象来自上一次枚举（缓存被清过）→ 重新枚举一次
        Enumerate();
        if (_sessions.TryGetValue(device.Handle, out cached) && cached.Slot != 0)
            return cached.Slot;

        // 兜底 2：索引已失效（拔插后枚举顺序变化）→ 按序列号在真实槽位表中重新定位
        if (_getSlotList != null && _getTokenInfo != null && !string.IsNullOrWhiteSpace(device.SerialNumber))
        {
            uint count = 0;
            if (_getSlotList(1, null!, ref count) == CkmNative.CKR_OK && count > 0)
            {
                var slots = new uint[count];
                if (_getSlotList(1, slots, ref count) == CkmNative.CKR_OK)
                {
                    for (int i = 0; i < count; i++)
                    {
                        var ti = new CkmNative.CK_TOKEN_INFO();
                        if (_getTokenInfo(slots[i], ref ti) != CkmNative.CKR_OK) continue;
                        if (!string.Equals(CkmNative.PaddedToString(ti.serialNumber), device.SerialNumber, StringComparison.Ordinal))
                            continue;

                        var keep = _sessions.TryGetValue(i, out var e) && e.Slot == slots[i] ? e.Session : 0u;
                        _sessions[i] = (slots[i], keep);
                        return slots[i];
                    }
                }
            }
        }

        throw new InvalidOperationException(
            $"未找到设备对应的槽位（序列号 {device.SerialNumber}），请「刷新设备」后重试");
    }

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        if (_getSlotList == null || _getTokenInfo == null)
            throw new InvalidOperationException("Provider 未初始化");

        // 1. 获取插槽数量
        uint count = 0;
        var rc = _getSlotList(1, null!, ref count);
        if (rc != CkmNative.CKR_OK || count == 0)
            return Array.Empty<UsbKeyDevice>();

        // 2. 获取插槽列表
        var slots = new uint[count];
        rc = _getSlotList(1, slots, ref count);
        if (rc != CkmNative.CKR_OK)
            return Array.Empty<UsbKeyDevice>();

        // 3. 遍历插槽，读取 TokenInfo
        var devices = new List<UsbKeyDevice>();
        for (int i = 0; i < count; i++)
        {
            var slotId = slots[i];
            var tokenInfo = new CkmNative.CK_TOKEN_INFO();
            rc = _getTokenInfo(slotId, ref tokenInfo);
            if (rc != CkmNative.CKR_OK) continue;

            var sn = CkmNative.PaddedToString(tokenInfo.serialNumber).Trim();
            var label = CkmNative.PaddedToString(tokenInfo.label).Trim();
            var mfr = CkmNative.PaddedToString(tokenInfo.manufacturerID).Trim();
            var model = CkmNative.PaddedToString(tokenInfo.model).Trim();

            var dev = new UsbKeyDevice
            {
                Platform = PlatformName,
                SerialNumber = sn,
                Handle = i,
                VendorName = ShortVendorName(mfr),
                // 型号：与厂商工具的写法对齐（官方版与 HZCA 定制版是两个不同的中间件/名称，
                // 直接显示 token 里的原始 model 会让用户无法与厂商工具对照）。
                Model = IsHzcaVariant(label, model, mfr) ? ModelHzca : ModelGeneric,
                FirmwareVersion = $"硬件 {tokenInfo.hardwareVersion.major}.{tokenInfo.hardwareVersion.minor}" +
                                  $" / 固件 {tokenInfo.firmwareVersion.major}.{tokenInfo.firmwareVersion.minor}",
                // 注意：Notes 在界面上被当作「设备已发现但未就绪」的原因展示，
                // 这里没有异常，必须留空（硬件版本已并入 FirmwareVersion）。
                Notes = ""
            };

            // PKCS#11 不提供 VID/PID，用 config.keyslist.epass3003 的配置值回填，
            // 否则界面「VID:PID」列恒为空、无法与实际硬件核对。
            // 注意实机 PID 随型号/定制方不同：HCCB 定制版为 0703，标准版为 0303。
            var wl = _whitelist.FirstOrDefault(w => w.Vid > 0 || w.Pid > 0);
            if (wl.Vid > 0 || wl.Pid > 0) { dev.Vid = wl.Vid; dev.Pid = wl.Pid; }
            devices.Add(dev);

            // 记录槽位到会话缓存（未登录状态）。
            // key = 界面句柄（枚举序号），value = 真实 PKCS#11 槽位号 —— 二者不可混用。
            // 已存在且槽位号相同则【不得覆盖】：界面每次刷新都会重新枚举，覆盖会把已打开的
            // 会话句柄丢成 0，随后 ListContainers/Login 拿着 0 去调 C_* 必然报「会话句柄无效」，
            // 同时卡上仍然保持着登录态（登不出去也进不来）。
            if (!_sessions.TryGetValue(i, out var existing) || existing.Slot != slotId)
                _sessions[i] = (slotId, 0);
        }

        return devices;
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        // PKCS#11 不需要单独的 Open，枚举时已获取所有信息
        var devices = Enumerate();
        var device = devices.FirstOrDefault(d => d.Handle == handleOrSerial);
        if (device == null)
            throw new InvalidOperationException($"设备不存在: {handleOrSerial}");
        return device;
    }

    public void Login(UsbKeyDevice device, string pin)
    {
        if (_openSession == null || _login == null)
            throw new InvalidOperationException("Provider 未初始化");

        // 关键：必须用真实槽位号，不能用界面句柄（设备索引）——见 ResolveSlot 的注释。
        var slotId = ResolveSlot(device);

        // 已有会话：直接登录（Session == 0 表示只有槽位占位、还没真正开会话）
        if (_sessions.TryGetValue(device.Handle, out var cached) && cached.Session != 0)
        {
            var pinBytes = Encoding.UTF8.GetBytes(pin);
            var rc = _login(cached.Session, CkmNative.CKU_USER, pinBytes, (uint)pinBytes.Length);
            if (rc == CkmNative.CKR_OK || rc == CkmNative.CKR_USER_ALREADY_LOGGED_IN)
            {
                device.IsLoggedIn = true;
                _currentIndex = device.Handle;
                return;
            }

            // 会话句柄已失效（例如被 WPF/官方工具抢占后回收）：丢弃缓存，走下面重新开会话
            if (rc != CkmNative.CKR_SESSION_HANDLE_INVALID)
                throw new InvalidOperationException($"登录失败: {CkmNative.ErrorString(rc)}");

            _sessions[device.Handle] = (slotId, 0);
        }

        // 打开新会话
        uint session = 0;
        var openRc = _openSession(slotId, CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, ref session);
        if (openRc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"打开会话失败: {CkmNative.ErrorString(openRc)}（槽位 {slotId}）");

        // 登录
        var pinData = Encoding.UTF8.GetBytes(pin);
        var loginRc = _login(session, CkmNative.CKU_USER, pinData, (uint)pinData.Length);
        if (loginRc != CkmNative.CKR_OK && loginRc != CkmNative.CKR_USER_ALREADY_LOGGED_IN)
        {
            _closeSession?.Invoke(session);
            throw new InvalidOperationException($"登录失败: {CkmNative.ErrorString(loginRc)}");
        }

        _sessions[device.Handle] = (slotId, session);
        _currentIndex = device.Handle;
        device.IsLoggedIn = true;
    }

    /// <summary>
    /// 取该设备的会话句柄，必要时新建（<b>不</b>要求已登录——列证书/容器多数平台无需认证）。
    /// 早期实现直接用缓存里的 <c>Session</c>，而缓存里可能只是「未开会话」的槽位占位（0），
    /// 于是拿 0 当会话句柄调用 C_FindObjectsInit 必然报「会话句柄无效」。
    /// </summary>
    private uint EnsureSession(UsbKeyDevice device)
    {
        if (_openSession == null)
            throw new InvalidOperationException("Provider 未初始化");

        var slotId = ResolveSlot(device);
        if (_sessions.TryGetValue(device.Handle, out var cached) && cached.Session != 0)
            return cached.Session;

        uint session = 0;
        var rc = _openSession(slotId, CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION,
            IntPtr.Zero, IntPtr.Zero, ref session);
        if (rc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"打开会话失败: {CkmNative.ErrorString(rc)}（槽位 {slotId}）");

        _sessions[device.Handle] = (slotId, session);
        return session;
    }

    public void Logout(UsbKeyDevice device)
    {
        if (_logout == null || _closeSession == null) return;

        if (_sessions.TryGetValue(device.Handle, out var cached))
        {
            if (cached.Session != 0)
            {
                _logout(cached.Session);
                _closeSession(cached.Session);
            }
            _sessions.Remove(device.Handle);
            device.IsLoggedIn = false;
        }

        if (_currentIndex == device.Handle)
            _currentIndex = -1;
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        // 刷新设备信息
        if (_getTokenInfo == null)
            return device;

        var tokenInfo = new CkmNative.CK_TOKEN_INFO();
        var rc = _getTokenInfo(ResolveSlot(device), ref tokenInfo);
        if (rc != CkmNative.CKR_OK)
            return device;

        device.FirmwareVersion = $"硬件 {tokenInfo.hardwareVersion.major}.{tokenInfo.hardwareVersion.minor}" +
                                 $" / 固件 {tokenInfo.firmwareVersion.major}.{tokenInfo.firmwareVersion.minor}";
        return device;
    }

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        if (_findInit == null || _find == null || _findFinal == null || _getAttr == null)
            throw new InvalidOperationException("Provider 未初始化");

        var session = EnsureSession(device);

        // 查找所有证书对象
        var certClass = CkmNative.CKO_CERTIFICATE;
        var certType = CkmNative.CKC_X_509;
        
        var containers = new List<KeyContainer>();
        var classPtr = Marshal.AllocHGlobal(sizeof(uint));
        var typePtr = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            Marshal.WriteInt32(classPtr, (int)certClass);
            Marshal.WriteInt32(typePtr, (int)certType);
            
            var template = new[]
            {
                new CkmNative.CK_ATTRIBUTE { type = CkmNative.CKA_CLASS, pValue = classPtr, ulValueLen = 4 },
                new CkmNative.CK_ATTRIBUTE { type = CkmNative.CKA_CERTIFICATE_TYPE, pValue = typePtr, ulValueLen = 4 }
            };

            var rc = _findInit(session, template, (uint)template.Length);
            if (rc != CkmNative.CKR_OK)
                throw new InvalidOperationException($"查找初始化失败: {CkmNative.ErrorString(rc)}");

            try
            {
                var handles = new uint[32];
                uint foundCount = 0;
                while (true)
                {
                    rc = _find(session, handles, (uint)handles.Length, ref foundCount);
                    if (rc != CkmNative.CKR_OK || foundCount == 0) break;

                    for (uint i = 0; i < foundCount; i++)
                    {
                        try
                        {
                            var container = ReadContainer(session, handles[i]);
                            if (container != null)
                                containers.Add(container);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ePass3003] 读取容器失败 (handle={handles[i]}): {ex.Message}");
                        }
                    }
                }
            }
            finally
            {
                _findFinal(session);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(classPtr);
            Marshal.FreeHGlobal(typePtr);
        }

        return containers;
    }

    private KeyContainer? ReadContainer(uint session, uint certHandle)
    {
        if (_getAttr == null) return null;

        // 读取证书 DER 编码
        var certDer = ReadAttribute(session, certHandle, CkmNative.CKA_VALUE);
        if (certDer == null || certDer.Length == 0) return null;

        // 读取证书 ID（用于关联私钥）
        var certId = ReadAttribute(session, certHandle, CkmNative.CKA_ID);
        var label = ReadAttributeString(session, certHandle, CkmNative.CKA_LABEL);

        X509Certificate2? cert = null;
        try
        {
            cert = new X509Certificate2(certDer);
        }
        catch
        {
            return null;
        }

        return new KeyContainer
        {
            Name = label ?? cert.Subject,
            ContainerName = label ?? cert.Thumbprint,
            CertRaw = certDer,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            Algorithm = $"{cert.GetKeyAlgorithm()}/{cert.SignatureAlgorithm.FriendlyName ?? "Unknown"}",
            // 卡上取到的就是完整证书，别让界面显示成"未知"
            Content = KeyContainerContent.Certificate,
            KeyUsage = DescribeKeyUsage(cert),
            ExtendedKeyUsage = DescribeExtendedKeyUsage(cert),
            IsRegisteredInCsp = Crypto.CertHelper.IsRegistered(cert.Thumbprint),
        };
    }

    /// <summary>
    /// 读取对象属性。
    /// <para>
    /// PKCS#11 的标准做法是「先用 pValue=NULL 问长度，再按长度取数据」。但 HZCA ePass3003 的
    /// <c>HCCBCSP11.dll</c> <b>不实现长度查询</b>：pValue=NULL 时恒返回 <c>ulValueLen=0</c>；
    /// 给了缓冲区后成功也不回填实际长度，只用 <c>CKR_BUFFER_TOO_SMALL</c> 表示"不够装"。
    /// 旧实现只走标准两步法，于是每个属性都被读成"空"→ 每张证书都构造失败 →
    /// <b>卡上明明有证书，界面却一个都列不出来</b>（官方工具用 C++ 自己给缓冲区，所以看得到）。
    /// </para>
    /// <para>
    /// 兼容路径：先倍增找到"够用"的缓冲区尺寸，再二分求出<b>最小够用尺寸</b>（即实际长度）。
    /// </para>
    /// </summary>
    private byte[]? ReadAttribute(uint session, uint objHandle, uint attrType)
    {
        if (_getAttr == null) return null;

        // 1) 标准两步法（多数实现走这条）
        var probe = new CkmNative.CK_ATTRIBUTE { type = attrType, pValue = IntPtr.Zero, ulValueLen = 0 };
        if (_getAttr(session, objHandle, new[] { probe }, 1) == CkmNative.CKR_OK &&
            probe.ulValueLen is > 0 and not 0xFFFFFFFF)
        {
            var (rcDirect, direct) = ReadAttributeInto(session, objHandle, attrType, (int)probe.ulValueLen);
            return rcDirect == CkmNative.CKR_OK ? direct : null;
        }

        // 2) 兼容"不支持问长度"的实现
        const int maxCap = 64 * 1024;
        int cap = 256;
        while (true)
        {
            var (rc, _) = ReadAttributeInto(session, objHandle, attrType, cap);
            if (rc == CkmNative.CKR_OK) break;
            if (rc != CkmNative.CKR_BUFFER_TOO_SMALL || cap >= maxCap) return null;
            cap *= 2;
        }

        // 二分：lo 一定不够、hi 一定够 → 收敛到"刚好够"= 实际长度
        int lo = 0, hi = cap;
        while (hi - lo > 1)
        {
            int mid = lo + (hi - lo) / 2;
            var (rcMid, _) = ReadAttributeInto(session, objHandle, attrType, mid);
            if (rcMid == CkmNative.CKR_OK) hi = mid;
            else lo = mid;
        }

        var (rcFinal, final) = ReadAttributeInto(session, objHandle, attrType, hi);
        return rcFinal == CkmNative.CKR_OK ? final : null;
    }

    /// <summary>用指定大小的缓冲区读一个属性；返回返回码与缓冲区内容（长度取实际可用部分）。</summary>
    private (uint Rc, byte[]? Buffer) ReadAttributeInto(uint session, uint objHandle, uint attrType, int size)
    {
        if (size <= 0) return (CkmNative.CKR_BUFFER_TOO_SMALL, null);

        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            var attr = new CkmNative.CK_ATTRIBUTE { type = attrType, pValue = ptr, ulValueLen = (uint)size };
            var rc = _getAttr!(session, objHandle, new[] { attr }, 1);
            if (rc != CkmNative.CKR_OK) return (rc, null);

            // 有的实现会回填真实长度，有的不回填（保持传入值）——两种都按"最小可用"处理
            var len = attr.ulValueLen > 0 && attr.ulValueLen != 0xFFFFFFFF && attr.ulValueLen <= (uint)size
                ? (int)attr.ulValueLen
                : size;

            var buf = new byte[len];
            Marshal.Copy(ptr, buf, 0, len);
            return (CkmNative.CKR_OK, buf);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    private string? ReadAttributeString(uint session, uint objHandle, uint attrType)
    {
        var bytes = ReadAttribute(session, objHandle, attrType);
        return bytes != null ? Encoding.UTF8.GetString(bytes).Trim('\0', ' ') : null;
    }

    /// <summary>
    /// 导入 PFX（证书 + 私钥）到卡内。
    /// <para>
    /// 厂商工具（<c>HZBANK_certd3003.exe</c>）就有「导入…」功能，其语言文件里带着
    /// 「证书访问密码」「选择容器」「导入密钥对失败」「容器中的数据缺少与证书匹配的密钥对」
    /// 等条目，说明这套卡<b>支持把外部密钥对写进卡内</b>——因此这里按 PKCS#11 标准
    /// 用 <c>C_CreateObject</c> 写入「私钥对象 + 证书对象」，两者共享同一个 <c>CKA_ID</c>
    /// （即厂商工具所说的"容器"，也是 Windows 侧证书↔私钥的配对依据）。
    /// </para>
    /// </summary>
    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        if (_createObject == null || _destroyObject == null)
            throw new InvalidOperationException("Provider 未初始化");

        // 创建私有对象（私钥）必须在已认证的用户会话里做；界面已按 ImportRequiresLogin 保证这一点。
        if (!device.IsLoggedIn)
            throw new InvalidOperationException("导入证书需要先登录设备（把私钥写入卡内必须有用户 PIN 会话）");

        // 读 PFX 与取私钥参数统一交给 PfxKeyReader：它会自动处理 Windows 上
        // "CNG 只允许 AllowExport、不允许明文导出"导致的 NTE_NOT_SUPPORTED（= 界面"不支持请求的操作"）。
        RSAParameters p;
        using var cert = PfxKeyReader.Load(pfxPath, pfxPassword);
        try
        {
            p = PfxKeyReader.ReadRsaPrivateKey(cert);
        }
        catch (NotSupportedException ex)
        {
            throw new NotSupportedException(
                ex.Message + "\n" +
                "ePass3003 只支持 RSA 密钥对；若该 PFX 只有证书（无私钥）或使用 SM2/ECC，请让 CA 重新签发并导出含 RSA 私钥的 PFX。", ex);
        }

        var session = EnsureSession(device);

        // CKA_ID：证书与私钥必须取同一个值，卡与 Windows 才认得出它们是一对。
        // 用证书自身的 SHA-1 指纹，天然唯一且与厂商工具"容器"概念一致。
        var id = cert.GetCertHash();
        var label = CertLabel(cert);

        uint keyHandle = 0;
        uint certHandle = 0;
        try
        {
            keyHandle = CreateObjectChecked(session, PrivateKeyTemplate(p, id, label, cert), "写入私钥");
            certHandle = CreateObjectChecked(session, CertificateTemplate(id, label, cert), "写入证书");
        }
        catch
        {
            // 回滚：失败时不能留下"有私钥没证书"的半截容器（那会变成删不掉的空容器）。
            if (certHandle != 0) { try { _destroyObject(session, certHandle); } catch { /* 尽力而为 */ } }
            if (keyHandle != 0) { try { _destroyObject(session, keyHandle); } catch { /* 尽力而为 */ } }
            throw;
        }

        Console.WriteLine($"[ePass3003] 导入成功：{cert.Subject}");
    }

    /// <summary>证书显示名：CN 优先，其次整个主题。</summary>
    private static string CertLabel(X509Certificate2 cert)
    {
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        return string.IsNullOrWhiteSpace(cn) ? cert.Subject : cn;
    }

    private static byte[] U32(uint v) => BitConverter.GetBytes(v);
    private static readonly byte[] CkTrue = { 1 };
    private static readonly byte[] CkFalse = { 0 };

    /// <summary>RSA 私钥对象模板（PKCS#11 标准属性，导入式写入）。探针复用同一份模板做试写。</summary>
    internal static (uint, byte[])[] PrivateKeyTemplate(RSAParameters p, byte[] id, string label, X509Certificate2 cert) => new[]
    {
        (CkmNative.CKA_CLASS, U32(CkmNative.CKO_PRIVATE_KEY)),
        (CkmNative.CKA_KEY_TYPE, U32(CkmNative.CKK_RSA)),
        (CkmNative.CKA_TOKEN, CkTrue),
        (CkmNative.CKA_PRIVATE, CkTrue),
        (CkmNative.CKA_SENSITIVE, CkTrue),
        (CkmNative.CKA_EXTRACTABLE, CkFalse),   // 已入卡的私钥不可再导出
        (CkmNative.CKA_SIGN, CkTrue),
        (CkmNative.CKA_DECRYPT, CkTrue),
        (CkmNative.CKA_ID, id),
        (CkmNative.CKA_LABEL, Encoding.UTF8.GetBytes(label)),
        (CkmNative.CKA_SUBJECT, cert.SubjectName.RawData),
        (CkmNative.CKA_MODULUS, p.Modulus!),
        (CkmNative.CKA_PUBLIC_EXPONENT, p.Exponent!),
        (CkmNative.CKA_PRIVATE_EXPONENT, p.D!),
        (CkmNative.CKA_PRIME_1, p.P!),
        (CkmNative.CKA_PRIME_2, p.Q!),
        (CkmNative.CKA_EXPONENT_1, p.DP!),
        (CkmNative.CKA_EXPONENT_2, p.DQ!),
        (CkmNative.CKA_COEFFICIENT, p.InverseQ!),
    };

    /// <summary>
    /// X.509 证书对象模板。<c>CKA_PRIVATE=false</c>：用户证书是公开数据，
    /// 这样界面不登录也能列出容器（与其它平台一致）；私钥仍受 PIN 保护。
    /// </summary>
    internal static (uint, byte[])[] CertificateTemplate(byte[] id, string label, X509Certificate2 cert) => new[]
    {
        (CkmNative.CKA_CLASS, U32(CkmNative.CKO_CERTIFICATE)),
        (CkmNative.CKA_CERTIFICATE_TYPE, U32(CkmNative.CKC_X_509)),
        (CkmNative.CKA_TOKEN, CkTrue),
        (CkmNative.CKA_PRIVATE, CkFalse),
        (CkmNative.CKA_ID, id),
        (CkmNative.CKA_LABEL, Encoding.UTF8.GetBytes(label)),
        (CkmNative.CKA_SUBJECT, cert.SubjectName.RawData),
        (CkmNative.CKA_VALUE, cert.RawData),
    };

    /// <summary>把托管模板转成非托管 CK_ATTRIBUTE 数组并调用 C_CreateObject。</summary>
    private uint CreateObjectChecked(uint session, (uint Type, byte[] Value)[] template, string what)
    {
        var attrs = new CkmNative.CK_ATTRIBUTE[template.Length];
        var buffers = new IntPtr[template.Length];
        try
        {
            for (int i = 0; i < template.Length; i++)
            {
                buffers[i] = Marshal.AllocHGlobal(template[i].Value.Length);
                Marshal.Copy(template[i].Value, 0, buffers[i], template[i].Value.Length);
                attrs[i] = new CkmNative.CK_ATTRIBUTE
                {
                    type = template[i].Type,
                    pValue = buffers[i],
                    ulValueLen = (uint)template[i].Value.Length
                };
            }

            uint handle = 0;
            var rc = _createObject!(session, attrs, (uint)attrs.Length, ref handle);
            if (rc != CkmNative.CKR_OK)
                throw new InvalidOperationException(
                    $"{what}失败: {CkmNative.ErrorString(rc)}（0x{rc:X}）。\n" +
                    "若提示属性无效/模板不一致，说明本卡不接受该属性组合；\n" +
                    "若提示空间不足，请先删除无用容器。也可改用厂商工具 HZBANK_certd3003.exe 导入。");
            return handle;
        }
        finally
        {
            foreach (var b in buffers)
                if (b != IntPtr.Zero) Marshal.FreeHGlobal(b);
        }
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        if (container.CertRaw == null || container.CertRaw.Length == 0)
            throw new InvalidOperationException("证书数据不可用");
        
        File.WriteAllBytes(outputPath, container.CertRaw);
    }

    public void ViewCertificate(KeyContainer container)
    {
        if (container.CertRaw == null || container.CertRaw.Length == 0)
            throw new InvalidOperationException("证书数据不可用");

        var cert = new X509Certificate2(container.CertRaw);
        var tempFile = Path.GetTempFileName() + ".cer";
        File.WriteAllBytes(tempFile, container.CertRaw);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tempFile) { UseShellExecute = true });
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        if (_findInit == null || _find == null || _findFinal == null || _destroyObject == null || _getAttr == null)
            throw new InvalidOperationException("Provider 未初始化");

        var session = EnsureSession(device);

        // 通过 CKA_ID 关联证书与私钥：先用目标容器的指纹/CKA_LABEL 定位到证书对象，取其 CKA_ID，
        // 再分别删除私钥对象与证书对象。
        byte[]? targetId = null;

        // 第一步：枚举所有证书对象，匹配 thumbprint 或 label，取得 CKA_ID。
        uint certClass = CkmNative.CKO_CERTIFICATE;
        var classPtr = Marshal.AllocHGlobal(sizeof(uint));
        try
        {
            Marshal.WriteInt32(classPtr, (int)certClass);
            var template = new[] { new CkmNative.CK_ATTRIBUTE { type = CkmNative.CKA_CLASS, pValue = classPtr, ulValueLen = 4 } };
            var rc = _findInit(session, template, (uint)template.Length);
            if (rc != CkmNative.CKR_OK)
                throw new InvalidOperationException($"查找证书失败: {CkmNative.ErrorString(rc)}");

            try
            {
                var handles = new uint[32];
                uint found = 0;
                while (true)
                {
                    rc = _find(session, handles, (uint)handles.Length, ref found);
                    if (rc != CkmNative.CKR_OK || found == 0) break;

                    for (uint i = 0; i < found; i++)
                    {
                        var h = handles[i];
                        var id = ReadAttribute(session, h, CkmNative.CKA_ID);
                        var label = ReadAttributeString(session, h, CkmNative.CKA_LABEL);
                        var value = ReadAttribute(session, h, CkmNative.CKA_VALUE);

                        var match = false;
                        if (!string.IsNullOrEmpty(container.Thumbprint) && value != null)
                        {
                            try
                            {
                                using var cert = new X509Certificate2(value);
                                match = string.Equals(cert.Thumbprint, container.Thumbprint, StringComparison.OrdinalIgnoreCase);
                            }
                            catch { /* ignore */ }
                        }
                        if (!match && !string.IsNullOrEmpty(container.ContainerName) && label != null)
                            match = string.Equals(label, container.ContainerName, StringComparison.Ordinal);
                        if (!match && !string.IsNullOrEmpty(container.Name) && label != null)
                            match = string.Equals(label, container.Name, StringComparison.Ordinal);

                        if (match)
                        {
                            targetId = id;
                            break;
                        }
                    }
                    if (targetId != null) break;
                }
            }
            finally
            {
                _findFinal(session);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(classPtr);
        }

        if (targetId == null || targetId.Length == 0)
            throw new InvalidOperationException("未找到对应容器对象");

        // 第二步：按 CKA_ID 分别删除私钥对象与证书对象。
        int deleted = 0;
        foreach (var objClass in new[] { CkmNative.CKO_PRIVATE_KEY, CkmNative.CKO_CERTIFICATE })
        {
            var idPtr = Marshal.AllocHGlobal(targetId.Length);
            var clsPtr = Marshal.AllocHGlobal(sizeof(uint));
            try
            {
                Marshal.Copy(targetId, 0, idPtr, targetId.Length);
                Marshal.WriteInt32(clsPtr, (int)objClass);

                var tpl = new[]
                {
                    new CkmNative.CK_ATTRIBUTE { type = CkmNative.CKA_CLASS, pValue = clsPtr, ulValueLen = 4 },
                    new CkmNative.CK_ATTRIBUTE { type = CkmNative.CKA_ID, pValue = idPtr, ulValueLen = (uint)targetId.Length }
                };

                var rc = _findInit(session, tpl, (uint)tpl.Length);
                if (rc != CkmNative.CKR_OK) continue;

                try
                {
                    var handles = new uint[8];
                    uint found = 0;
                    rc = _find(session, handles, (uint)handles.Length, ref found);
                    for (uint i = 0; i < found; i++)
                    {
                        var drc = _destroyObject(session, handles[i]);
                        if (drc == CkmNative.CKR_OK)
                            deleted++;
                    }
                }
                finally
                {
                    _findFinal(session);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(idPtr);
                Marshal.FreeHGlobal(clsPtr);
            }
        }

        if (deleted == 0)
            throw new InvalidOperationException("删除失败：未找到可删除的对象");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null || container.CertRaw.Length == 0)
            throw new InvalidOperationException("证书数据不可用");
        Crypto.CertHelper.Register(container.CertRaw, container.Name);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            Crypto.CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    /// <summary>证书「密钥用途」的可读文本（界面列用）。</summary>
    private static string DescribeKeyUsage(X509Certificate2 cert)
    {
        var ext = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (ext == null) return "";

        var f = ext.KeyUsages;
        var parts = new List<string>();
        if ((f & X509KeyUsageFlags.DigitalSignature) != 0) parts.Add("数字签名");
        if ((f & X509KeyUsageFlags.NonRepudiation) != 0) parts.Add("不可否认");
        if ((f & X509KeyUsageFlags.KeyEncipherment) != 0) parts.Add("密钥加密");
        if ((f & X509KeyUsageFlags.DataEncipherment) != 0) parts.Add("数据加密");
        if ((f & X509KeyUsageFlags.KeyAgreement) != 0) parts.Add("密钥协商");
        if ((f & X509KeyUsageFlags.KeyCertSign) != 0) parts.Add("签发证书");
        return string.Join("/", parts);
    }

    /// <summary>证书「扩展密钥用途」的可读文本（界面列用）。</summary>
    private static string DescribeExtendedKeyUsage(X509Certificate2 cert)
    {
        var ext = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ext == null) return "";

        var parts = new List<string>();
        foreach (var oid in ext.EnhancedKeyUsages.Cast<Oid>())
        {
            parts.Add(oid.Value switch
            {
                "1.3.6.1.5.5.7.3.2" => "客户端身份验证",
                "1.3.6.1.5.5.7.3.3" => "代码签名",
                "1.3.6.1.5.5.7.3.4" => "邮件保护",
                "1.3.6.1.5.5.7.3.8" => "时间戳",
                "1.3.6.1.5.5.7.3.9" => "OCSP 签名",
                _ => oid.FriendlyName ?? oid.Value ?? "",
            });
        }
        return string.Join("/", parts);
    }

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        if (_setPin == null)
            throw new NotImplementedException("ChangePin 不支持");

        var session = EnsureSession(device);
        var oldBytes = Encoding.UTF8.GetBytes(oldPin);
        var newBytes = Encoding.UTF8.GetBytes(newPin);
        var rc = _setPin(session, oldBytes, (uint)oldBytes.Length, newBytes, (uint)newBytes.Length);
        if (rc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"修改 PIN 失败: {CkmNative.ErrorString(rc)}");
    }

    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        throw new NotImplementedException("Unlock 待实现");
    }

    public string GenerateChallenge(UsbKeyDevice device)
    {
        throw new NotSupportedException("ePass3003 不支持挑战响应解锁");
    }

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
    {
        throw new NotSupportedException("ePass3003 不支持挑战响应解锁");
    }

    /// <summary>ePass3003 支持 C_InitToken（SO PIN 初始化），不强制要求当前用户 PIN。</summary>
    public bool ResetRequiresCurrentPin => false;

    /// <summary>
    /// 支持导入 PFX（证书 + 私钥写入卡内，走 PKCS#11 C_CreateObject），
    /// 与厂商工具「导入…（证书访问密码／选择容器／用途）」等价。
    /// </summary>
    public bool SupportsImportPfx => true;

    /// <summary>把私钥写进卡内必须在用户 PIN 会话里做，界面会先要求登录。</summary>
    public bool ImportRequiresLogin => true;

    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        if (_initToken == null)
            throw new NotImplementedException("ResetDevice 不支持");

        // 注意：device.Handle 只是界面用的索引，真实槽位号必须从枚举缓存里取，
        // 否则会把 0/1/2 当成槽位号传给 C_InitToken（本机实测槽位号并非 0/1/2 顺序，
        // 传错会直接报 CKR_SLOT_ID_INVALID「槽位句柄无效」）。
        var slotId = ResolveSlot(device);

        var pinBytes = Encoding.UTF8.GetBytes(newPin);
        var label = Encoding.UTF8.GetBytes("ePass3003Token");
        
        // 初始化 Token（需要 SO PIN）
        var soPin = Encoding.UTF8.GetBytes(puk ?? "");
        var rc = _initToken(slotId, soPin, (uint)soPin.Length, label);
        if (rc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"重置设备失败: {CkmNative.ErrorString(rc)}");

        // 设置用户 PIN
        uint session = 0;
        rc = _openSession!(slotId, CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, ref session);
        if (rc == CkmNative.CKR_OK && _initPin != null)
        {
            _login!(session, CkmNative.CKU_SO, soPin, (uint)soPin.Length);
            _initPin(session, pinBytes, (uint)pinBytes.Length);
            _logout!(session);
            _closeSession!(session);
        }
    }

    public void Dispose()
    {
        foreach (var (_, session) in _sessions.Values)
        {
            if (session == 0) continue;   // 0 表示只有槽位占位、未真正开会话
            _logout?.Invoke(session);
            _closeSession?.Invoke(session);
        }
        _sessions.Clear();

        _finalize?.Invoke(IntPtr.Zero);
        _dll?.Dispose();
        _dll = null;
    }
}
