using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Configuration;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 龙脉（Longmai）GM3000 USB Key 对接实现，基于 <b>SKF（GM/T 0016）</b>接口。
/// <para>
/// 实测结论（2026-09，x86 探针 <c>tools/GM3000Probe</c> 在本机插入的 GM3000 上验证）：
/// <list type="bullet">
/// <item><c>SKF_EnumDev</c> → 1 台设备（名 = 序列号 <c>ED466583B8C689AB81DFA5573DF55AE</c>）；</item>
/// <item><c>SKF_GetDevInfo</c> → Longmai / Longmai / <c>GM3000</c> / 上述序列号；</item>
/// <item><c>SKF_EnumApplication</c> → <c>GM3000APP</c>；<c>SKF_OpenApplication</c> 成功；</item>
/// <item><c>SKF_GetPINInfo(hApp,0)</c> → 剩余 10 / 上限 10；<c>SKF_EnumContainer</c> → 0 个（全新未初始化）；</item>
/// <item><c>SKF_GenRandom(16B)</c> 成功 → 说明设备通信与口令状态均正常。</item>
/// </list>
/// </para>
/// <para>
/// <b>重要</b>：该 SKF 是「当前设备 + 当前应用」全局上下文模型，所有操作必须在
/// <see cref="EnsureReady"/> 建立的会话（ConnectDev → OpenApplication）内进行。
/// </para>
/// <para>
/// <b>已由反汇编确认参数、但本次未在实机上执行的写操作</b>（改 PIN / 解锁 / 重置 / 导入）：
/// 调用前请确认凭据，写错会真实消耗 PIN 重试次数。详见
/// <c>Roadmap/docs/Longmai-GM3000-逆向分析报告.md</c>。
/// </para>
/// </summary>
public sealed class Gm3000Provider : IKeyProvider
{
    public string PlatformName => "gm3000";

    private readonly string _libraryRoot;
    private readonly List<(int Vid, int Pid)> _whitelist = new();

    private string? _modulePath;
    private NativeDll.Module? _mod;

    // SKF 导出
    private Gm3000Native.EnumDevFn? _enumDev;
    private Gm3000Native.ConnectDevFn? _connectDev;
    private Gm3000Native.DisConnectDevFn? _disconnectDev;
    private Gm3000Native.GetDevInfoFn? _getDevInfo;
    private Gm3000Native.GetDevStateFn? _getDevState;
    private Gm3000Native.EnumApplicationFn? _enumApp;
    private Gm3000Native.OpenApplicationFn? _openApp;
    private Gm3000Native.CloseApplicationFn? _closeApp;
    private Gm3000Native.EnumContainerFn? _enumContainer;
    private Gm3000Native.OpenContainerFn? _openContainer;
    private Gm3000Native.CloseContainerFn? _closeContainer;
    private Gm3000Native.CreateContainerFn? _createContainer;
    private Gm3000Native.DeleteContainerFn? _deleteContainer;
    private Gm3000Native.GetContainerTypeFn? _getContainerType;
    private Gm3000Native.ImportCertificateFn? _importCert;
    private Gm3000Native.ExportCertificateFn? _exportCert;
    private Gm3000Native.ExportPublicKeyFn? _exportPubKey;
    private Gm3000Native.ImportRSAKeyPairFn? _importRsaKeyPair;
    private Gm3000Native.GenRandomFn? _genRandom;
    private Gm3000Native.VerifyPinFn? _verifyPin;
    private Gm3000Native.ChangePinFn? _changePin;
    private Gm3000Native.UnblockPinFn? _unblockPin;
    private Gm3000Native.ClearSecureStateFn? _clearSecureState;
    private Gm3000Native.SetLabelFn? _setLabel;
    private Gm3000Native.GetPinInfoFn? _getPinInfo;
    private Gm3000Native.TransmitFn? _transmit;

    // 会话状态（SKF 为全局上下文，同进程只能有一个活动设备/应用）
    private readonly object _sync = new();
    private IntPtr _hDev = IntPtr.Zero;
    private IntPtr _hApp = IntPtr.Zero;
    private string _currentDevName = "";
    private string _currentAppName = "";

    /// <summary>最近一次「重置设备」的逐步报告（供界面/日志展示）。</summary>
    public string? LastResetReport { get; private set; }

    /// <summary>最近一次导入的补充说明（例如私钥导入未落地时的原因）。</summary>
    public string? LastImportNote { get; private set; }

    public Gm3000Provider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
    {
        _libraryRoot = libraryRoot;
        if (whitelist != null)
            foreach (var d in whitelist)
                if (d.VidInt > 0 || d.PidInt > 0)
                    _whitelist.Add((d.VidInt, d.PidInt));
    }

    // ================= 初始化 =================

    public bool IsAvailable => _mod != null || Gm3000Native.FindModulePath(_libraryRoot) != null;

    public void Initialize()
    {
        if (_mod != null) return;

        _modulePath = Gm3000Native.FindModulePath(_libraryRoot)
            ?? throw new InvalidOperationException(
                "未找到 GM3000 的 SKF 模块（mtoken_gm3000.dll）。请确认 Library/GM3000/ 目录存在，且宿主为 32 位进程。");

        _mod = NativeDll.Load(_modulePath)
            ?? throw new InvalidOperationException($"加载 {_modulePath} 失败（请确认 DLL 为 32 位且依赖完整）");

        _enumDev = _mod.GetDelegate<Gm3000Native.EnumDevFn>("SKF_EnumDev");
        _connectDev = _mod.GetDelegate<Gm3000Native.ConnectDevFn>("SKF_ConnectDev");
        _disconnectDev = _mod.GetDelegate<Gm3000Native.DisConnectDevFn>("SKF_DisConnectDev");
        _getDevInfo = _mod.GetDelegate<Gm3000Native.GetDevInfoFn>("SKF_GetDevInfo");
        _getDevState = _mod.GetDelegate<Gm3000Native.GetDevStateFn>("SKF_GetDevState");
        _enumApp = _mod.GetDelegate<Gm3000Native.EnumApplicationFn>("SKF_EnumApplication");
        _openApp = _mod.GetDelegate<Gm3000Native.OpenApplicationFn>("SKF_OpenApplication");
        _closeApp = _mod.GetDelegate<Gm3000Native.CloseApplicationFn>("SKF_CloseApplication");
        _enumContainer = _mod.GetDelegate<Gm3000Native.EnumContainerFn>("SKF_EnumContainer");
        _openContainer = _mod.GetDelegate<Gm3000Native.OpenContainerFn>("SKF_OpenContainer");
        _closeContainer = _mod.GetDelegate<Gm3000Native.CloseContainerFn>("SKF_CloseContainer");
        _createContainer = _mod.GetDelegate<Gm3000Native.CreateContainerFn>("SKF_CreateContainer");
        _deleteContainer = _mod.GetDelegate<Gm3000Native.DeleteContainerFn>("SKF_DeleteContainer");
        _getContainerType = _mod.GetDelegate<Gm3000Native.GetContainerTypeFn>("SKF_GetContainerType");
        _importCert = _mod.GetDelegate<Gm3000Native.ImportCertificateFn>("SKF_ImportCertificate");
        _exportCert = _mod.GetDelegate<Gm3000Native.ExportCertificateFn>("SKF_ExportCertificate");
        _exportPubKey = _mod.GetDelegate<Gm3000Native.ExportPublicKeyFn>("SKF_ExportPublicKey");
        _importRsaKeyPair = _mod.GetDelegate<Gm3000Native.ImportRSAKeyPairFn>("SKF_ImportRSAKeyPair");
        _genRandom = _mod.GetDelegate<Gm3000Native.GenRandomFn>("SKF_GenRandom");
        _verifyPin = _mod.GetDelegate<Gm3000Native.VerifyPinFn>("SKF_VerifyPIN");
        _changePin = _mod.GetDelegate<Gm3000Native.ChangePinFn>("SKF_ChangePIN");
        _unblockPin = _mod.GetDelegate<Gm3000Native.UnblockPinFn>("SKF_UnblockPIN");
        _clearSecureState = _mod.GetDelegate<Gm3000Native.ClearSecureStateFn>("SKF_ClearSecureState");
        _setLabel = _mod.GetDelegate<Gm3000Native.SetLabelFn>("SKF_SetLabel");
        _getPinInfo = _mod.GetDelegate<Gm3000Native.GetPinInfoFn>("SKF_GetPINInfo");
        _transmit = _mod.GetDelegate<Gm3000Native.TransmitFn>("SKF_Transmit");

        if (_enumDev == null || _connectDev == null || _disconnectDev == null)
            throw new InvalidOperationException(
                $"{Path.GetFileName(_modulePath)} 不是可用的 GM3000 SKF 模块（缺少 SKF_EnumDev/SKF_ConnectDev）。" +
                "注意：GM3000_2.2.19 目录内的 mtoken_gm3000.dll.old（2022 版）已不支持老型号 GM3000。");

        Common.Log.Write($"[GM3000] SKF 模块已加载：{_modulePath}");
    }

    // ================= 设备枚举 / 打开 =================

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        if (_mod == null) Initialize();
        lock (_sync)
        {
            var names = EnumDeviceNames();
            var result = new List<UsbKeyDevice>();
            for (var i = 0; i < names.Count; i++)
            {
                var name = names[i];
                var dev = new UsbKeyDevice
                {
                    Platform = PlatformName,
                    VendorName = "Longmai",
                    Model = "GM3000",
                    SerialNumber = name,   // SKF 设备名即序列号（实机验证）
                    Handle = i,
                    Notes = "",
                };

                // SKF 不提供 VID/PID，用 config.keyslist.gm3000 的配置值回填，
                // 否则界面「VID:PID」列恒为空、无法与实际硬件核对。
                var wl = _whitelist.FirstOrDefault(w => w.Vid > 0 || w.Pid > 0);
                if (wl.Vid > 0 || wl.Pid > 0) { dev.Vid = wl.Vid; dev.Pid = wl.Pid; }

                // 逐个临时连接读取详细信息（SKF 无「只读设备信息」入口）
                var rc = _connectDev!(name, out var hDev);
                if (rc != Gm3000Native.SAR_OK)
                {
                    dev.Notes = $"连接失败：{Gm3000Native.ErrorText((uint)rc)}";
                    result.Add(dev);
                    continue;
                }
                try
                {
                    FillDetail(hDev, dev);
                }
                finally
                {
                    try { _disconnectDev!(hDev); } catch { /* 断开失败不影响枚举结果 */ }
                }
                result.Add(dev);
            }
            return result;
        }
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        var devs = Enumerate();
        if (devs.Count == 0)
            throw new InvalidOperationException("未检测到 GM3000 USB Key（请确认设备已插入且已安装 32 位 SKF 模块）");
        if (handleOrSerial >= 0 && handleOrSerial < devs.Count) return devs[handleOrSerial];
        return devs[0];
    }

    /// <summary>读取 <c>SKF_EnumDev</c> 的多字符串设备名列表。</summary>
    private List<string> EnumDeviceNames()
    {
        var capacity = 0x400;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buf = new byte[capacity];
            var pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                var size = (uint)capacity;
                var rc = (uint)_enumDev!(true, pin.AddrOfPinnedObject(), ref size);
                if (rc == Gm3000Native.SAR_BUFFER_TOO_SMALL)
                {
                    capacity = (int)Math.Max(size, 0x400);
                    continue;
                }
                if (rc != Gm3000Native.SAR_OK)
                {
                    Common.Log.Write($"[GM3000] SKF_EnumDev 失败：{Gm3000Native.ErrorText(rc)}");
                    return new List<string>();
                }
                return SplitMultiString(buf, (int)Math.Min(size, (uint)capacity));
            }
            finally { pin.Free(); }
        }
        return new List<string>();
    }

    /// <summary>按 ANSI 多字符串（双 0 结尾）拆分。</summary>
    private static List<string> SplitMultiString(byte[] buf, int len)
    {
        var res = new List<string>();
        var start = -1;
        for (var i = 0; i < len && i < buf.Length; i++)
        {
            if (buf[i] != 0)
            {
                if (start < 0) start = i;
                continue;
            }
            if (start < 0) break;                       // 双 0 结束
            res.Add(Encoding.ASCII.GetString(buf, start, i - start));
            start = -1;
        }
        return res;
    }

    private void FillDetail(IntPtr hDev, UsbKeyDevice dev)
    {
        try
        {
            var parts = new List<string>();
            var info = new Gm3000Native.SkfDevInfo { Extra = new byte[100] };
            if (_getDevInfo != null)
            {
                var rc = _getDevInfo(hDev, ref info);
                if (rc == Gm3000Native.SAR_OK)
                {
                    if (!string.IsNullOrWhiteSpace(info.Vendor)) dev.VendorName = info.Vendor.Trim();
                    if (!string.IsNullOrWhiteSpace(info.Model)) dev.Model = info.Model.Trim();
                    if (!string.IsNullOrWhiteSpace(info.SerialNumber)) dev.SerialNumber = info.SerialNumber.Trim();
                    dev.FirmwareVersion = $"DEVINFO v{info.Version}";
                    if (!string.IsNullOrWhiteSpace(info.Manufacturer))
                        parts.Add($"制造商 {info.Manufacturer.Trim()}");
                }
                else
                {
                    parts.Add($"读取设备信息失败：{Gm3000Native.ErrorText((uint)rc)}");
                }
            }

            if (_getDevState != null && _getDevState(dev.SerialNumber, out var state) == Gm3000Native.SAR_OK)
                parts.Add($"设备状态 {state}");

            // 每次重新计算，避免重复调用时无限追加
            dev.Notes = string.Join("；", parts);
        }
        catch (Exception ex)
        {
            Common.Log.Write($"[GM3000] 读取设备详情失败：{ex.Message}");
        }
    }

    // ================= 会话管理 =================

    /// <summary>
    /// 确保会话就绪：<c>ConnectDev</c> → <c>EnumApplication/OpenApplication</c>。
    /// <para>
    /// 反汇编与实测均表明：PIN 校验、容器枚举等操作读取的是 **全局当前应用上下文**，
    /// 因此必须先连接设备并打开应用，否则统一返回 <c>SAR_INVALIDHANDLEERR (0xA000005)</c>。
    /// </para>
    /// </summary>
    private void EnsureReady(UsbKeyDevice device)
    {
        if (_mod == null) Initialize();
        lock (_sync)
        {
            var name = string.IsNullOrWhiteSpace(device.SerialNumber) ? _currentDevName : device.SerialNumber;
            if (string.IsNullOrWhiteSpace(name))
                throw new InvalidOperationException("设备序列号（SKF 设备名）为空，无法连接");

            if (_hDev != IntPtr.Zero && _currentDevName == name && _hApp != IntPtr.Zero) return;

            DisconnectLocked();

            var rc = (uint)_connectDev!(name, out var hDev);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException(
                    $"连接 GM3000 设备失败：{Gm3000Native.ErrorText(rc)}（设备名 {name}）");
            _hDev = hDev;
            _currentDevName = name;

            OpenApplicationLocked();
        }
    }

    /// <summary>选择并打开应用（优先 <c>GM3000APP</c>，否则取枚举到的第一个）。</summary>
    private void OpenApplicationLocked()
    {
        if (_hApp != IntPtr.Zero || _openApp == null) return;

        var apps = new List<string>();
        if (_enumApp != null)
        {
            var capacity = 0x400;
            var buf = new byte[capacity];
            var pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                var size = (uint)capacity;
                var rc = _enumApp(_hDev, pin.AddrOfPinnedObject(), ref size);
                if (rc == Gm3000Native.SAR_OK)
                    apps = SplitMultiString(buf, (int)Math.Min(size, (uint)capacity));
            }
            finally { pin.Free(); }
        }

        var target = apps.FirstOrDefault(a =>
                         string.Equals(a, Gm3000Native.DefaultAppName, StringComparison.OrdinalIgnoreCase))
                     ?? apps.FirstOrDefault()
                     ?? Gm3000Native.DefaultAppName;

        var orc = (uint)_openApp(_hDev, target, out var hApp);
        if (orc != Gm3000Native.SAR_OK)
            throw new InvalidOperationException(
                $"打开 GM3000 应用『{target}』失败：{Gm3000Native.ErrorText(orc)}");

        _hApp = hApp;
        _currentAppName = target;
    }

    private void DisconnectLocked()
    {
        if (_hApp != IntPtr.Zero)
        {
            try { _closeApp?.Invoke(_hApp); } catch { /* 关闭失败忽略 */ }
            _hApp = IntPtr.Zero;
        }
        if (_hDev != IntPtr.Zero)
        {
            try { _disconnectDev?.Invoke(_hDev); } catch { /* 断开失败忽略 */ }
            _hDev = IntPtr.Zero;
        }
        _currentDevName = "";
        _currentAppName = "";
    }

    public void Login(UsbKeyDevice device, string pin)
    {
        if (string.IsNullOrEmpty(pin)) throw new ArgumentException("PIN 不能为空", nameof(pin));
        EnsureReady(device);
        lock (_sync)
        {
            var retry = 0u;
            // 注意：SKF_VerifyPIN 的首参必须是**应用句柄**（传设备句柄 → 0xA000005，
            // 且不消耗重试次数，表现为「口令验证不正确」）。
            var rc = (uint)_verifyPin!(_hApp, Gm3000Native.PinTypeUser, pin, ref retry);
            if (rc == Gm3000Native.SAR_OK || rc == Gm3000Native.SAR_USER_ALREADY_LOGGED_IN)
            {
                device.IsLoggedIn = true;
                return;
            }
            if (rc == Gm3000Native.SAR_PIN_INCORRECT || rc == Gm3000Native.SAR_PIN_LOCKED)
                throw new InvalidOperationException(
                    $"PIN 校验失败：{Gm3000Native.ErrorText(rc)}（剩余重试 {retry} 次）");
            throw new InvalidOperationException($"PIN 校验失败：{Gm3000Native.ErrorText(rc)}");
        }
    }

    public void Logout(UsbKeyDevice device)
    {
        lock (_sync)
        {
            if (_hDev != IntPtr.Zero && _clearSecureState != null)
            {
                try { _clearSecureState(_hApp); } catch { /* 忽略：登出是尽力而为 */ }
            }
            DisconnectLocked();
        }
        device.IsLoggedIn = false;
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        EnsureReady(device);
        lock (_sync)
        {
            FillDetail(_hDev, device);
            // PIN 状态（GM3000 扩展；实测需传应用句柄）
            if (_getPinInfo != null && _hApp != IntPtr.Zero)
            {
                var parts = new List<string>();
                foreach (var (type, label) in new[] { (Gm3000Native.PinTypeUser, "用户PIN"), (Gm3000Native.PinTypeSO, "管理员PIN") })
                {
                    // 实测出参顺序是「上限在前、剩余在后」
                    var rc = _getPinInfo(_hApp, type, out var max, out var remain, out _);
                    parts.Add(rc == Gm3000Native.SAR_OK
                        ? $"{label} {remain}/{max}"
                        : $"{label} {Gm3000Native.ErrorText((uint)rc)}");
                }
                device.Notes = string.IsNullOrEmpty(device.Notes)
                    ? string.Join("，", parts)
                    : $"{device.Notes}；{string.Join("，", parts)}";
            }
        }
        return device;
    }

    // ================= 容器 / 证书 =================

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        EnsureReady(device);
        lock (_sync)
        {
            var result = new List<KeyContainer>();
            foreach (var name in EnumContainerNamesLocked())
            {
                var c = ReadContainerLocked(name);
                if (c != null) result.Add(c);
            }
            return result;
        }
    }

    private List<string> EnumContainerNamesLocked()
    {
        if (_enumContainer == null || _hApp == IntPtr.Zero) return new List<string>();
        var capacity = 0x1000;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buf = new byte[capacity];
            var pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                var size = (uint)capacity;
                var rc = (uint)_enumContainer(_hApp, pin.AddrOfPinnedObject(), ref size);
                if (rc == Gm3000Native.SAR_BUFFER_TOO_SMALL)
                {
                    capacity = (int)Math.Max(size, 0x1000);
                    continue;
                }
                if (rc != Gm3000Native.SAR_OK)
                {
                    if (rc != Gm3000Native.SAR_INVALIDHANDLEERR)
                        Common.Log.Write($"[GM3000] SKF_EnumContainer 失败：{Gm3000Native.ErrorText(rc)}");
                    return new List<string>();
                }
                return SplitMultiString(buf, (int)Math.Min(size, (uint)capacity));
            }
            finally { pin.Free(); }
        }
        return new List<string>();
    }

    private KeyContainer? ReadContainerLocked(string containerName)
    {
        if (_openContainer == null) return null;
        var rc = (uint)_openContainer(_hApp, containerName, out var hCont);
        if (rc != Gm3000Native.SAR_OK || hCont == IntPtr.Zero)
        {
            Common.Log.Write($"[GM3000] 打开容器『{containerName}』失败：{Gm3000Native.ErrorText(rc)}");
            return null;
        }

        try
        {
            uint type = 0;
            _getContainerType?.Invoke(hCont, out type);

            // 签名证书（bSignFlag = true）与加密证书（false）分别尝试，取到即用
            var signDer = ExportCertLocked(hCont, true);
            var encDer = ExportCertLocked(hCont, false);
            var der = signDer ?? encDer;

            var kc = new KeyContainer
            {
                /* 真实标识用于「打开/删除容器」，必须保留 */
                ContainerName = containerName,
                ContainerUuid = containerName,
                /* 名称（证书 CN）默认留空：空容器（只有容器壳、卡内还没有证书）在设备上
                   只有 UUID 形式的容器名，若直接拿它当「名称」显示，会让人误以为那就是证书名。
                   有证书时下面会用证书主体名覆盖；无证书就保持为空。 */
                Name = "",
                CertRaw = der,
                Algorithm = type == 0 ? "RSA" : $"RSA (容器类型 {type})",
                KeyUsage = signDer != null ? "数字签名" : "数据加密",
                ExtendedKeyUsage = signDer != null && encDer != null ? "签名 + 加密" : "—",
            };

            if (der != null)
            {
                try
                {
                    using var cert = new X509Certificate2(der);
                    kc.Name = cert.GetNameInfo(X509NameType.SimpleName, false);
                    kc.Subject = cert.Subject;
                    kc.Issuer = cert.Issuer;
                    kc.NotBefore = cert.NotBefore;
                    kc.NotAfter = cert.NotAfter;
                    kc.SerialNumber = cert.SerialNumber;
                    kc.Thumbprint = cert.Thumbprint;
                }
                catch (Exception ex)
                {
                    Common.Log.Write($"[GM3000] 容器『{containerName}』证书解析失败：{ex.Message}");
                }
            }
            return kc;
        }
        finally
        {
            try { _closeContainer?.Invoke(hCont); } catch { /* 关闭失败忽略 */ }
        }
    }

    private byte[]? ExportCertLocked(IntPtr hCont, bool signFlag)
    {
        if (_exportCert == null) return null;
        var buf = new byte[Gm3000Native.CertBufferSize];
        var len = (uint)buf.Length;
        var rc = (uint)_exportCert(hCont, signFlag, buf, ref len);
        if (rc == Gm3000Native.SAR_BUFFER_TOO_SMALL)
        {
            buf = new byte[Math.Max(len, (uint)Gm3000Native.CertBufferSize)];
            len = (uint)buf.Length;
            rc = (uint)_exportCert(hCont, signFlag, buf, ref len);
        }
        if (rc != Gm3000Native.SAR_OK || len == 0) return null;
        return buf.AsSpan(0, (int)Math.Min(len, (uint)buf.Length)).ToArray();
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        var der = container.CertRaw;
        if (der == null || der.Length == 0)
        {
            // 缓存缺失时重新读取
            EnsureReady(device);
            lock (_sync) { der = ReadContainerLocked(container.ContainerName)?.CertRaw; }
        }
        if (der == null || der.Length == 0)
            throw new InvalidOperationException("证书数据不可用（该容器可能只有私钥而无证书）");
        File.WriteAllBytes(outputPath, der);
    }

    public void ViewCertificate(KeyContainer container)
    {
        var der = container.CertRaw;
        if (der == null || der.Length == 0) throw new InvalidOperationException("证书数据不可用");
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(tmp, der);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmp) { UseShellExecute = true });
    }

    /// <summary>
    /// 从 PFX 导入：创建/复用容器 → 导入证书 → 尝试导入私钥。
    /// <para>
    /// <b>私钥导入的限制（如实告知）</b>：<c>SKF_ImportRSAKeyPair</c> 要求把私钥按厂商约定
    /// 「包裹/加密」后传入（GM/T 0016 语义为先加密成 wrappedKey），该包裹格式尚未逆向确认。
    /// 因此本方法：证书一定导入；私钥以「PKCS#1 DER 明文 + 空加密数据」尝试一次，
    /// 无论成功与否都把真实返回码写入 <see cref="LastImportNote"/>，绝不假装成功。
    /// </para>
    /// </summary>
    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        LastImportNote = null;
        EnsureReady(device);

        using var pfx = new X509Certificate2(pfxPath,
            string.IsNullOrEmpty(pfxPassword) ? null : pfxPassword,
            X509KeyStorageFlags.Exportable);
        var certDer = pfx.Export(X509ContentType.Cert);
        var containerName = BuildContainerName(pfx);

        lock (_sync)
        {
            IntPtr hCont;
            var existing = EnumContainerNamesLocked()
                .FirstOrDefault(n => string.Equals(n, containerName, StringComparison.OrdinalIgnoreCase));

            if (existing != null)
            {
                var orc = (uint)_openContainer!(_hApp, existing, out hCont);
                if (orc != Gm3000Native.SAR_OK)
                    throw new InvalidOperationException($"打开已存在的容器『{existing}』失败：{Gm3000Native.ErrorText(orc)}");
                containerName = existing;
            }
            else
            {
                if (_createContainer == null)
                    throw new NotSupportedException("SKF 模块未导出 SKF_CreateContainer，无法新建容器");
                var crc = (uint)_createContainer(_hApp, containerName, out hCont);
                if (crc != Gm3000Native.SAR_OK)
                    throw new InvalidOperationException(
                        $"创建容器『{containerName}』失败：{Gm3000Native.ErrorText(crc)}" +
                        "（若提示未登录，请先用 PIN 登录后再导入）");
            }

            try
            {
                // 1) 导入证书（签名位）
                if (_importCert == null)
                    throw new NotSupportedException("SKF 模块未导出 SKF_ImportCertificate，无法导入证书");
                var irc = (uint)_importCert(hCont, true, certDer, (uint)certDer.Length);
                if (irc != Gm3000Native.SAR_OK)
                    throw new InvalidOperationException($"导入证书失败：{Gm3000Native.ErrorText(irc)}");

                // 2) 尝试导入私钥（格式待厂商确认，如实回报）
                if (!pfx.HasPrivateKey)
                {
                    LastImportNote = "PFX 不含私钥，仅导入证书。";
                }
                else if (_importRsaKeyPair == null)
                {
                    LastImportNote = "SKF 模块未导出 SKF_ImportRSAKeyPair，私钥未导入（仅证书已导入）。";
                }
                else
                {
                    using var rsa = pfx.GetRSAPrivateKey();
                    if (rsa == null)
                    {
                        LastImportNote = "PFX 私钥不是 RSA（可能为 SM2/ECC），当前未对接，仅导入证书。";
                    }
                    else
                    {
                        var pkcs1 = rsa.ExportRSAPrivateKey();
                        var krc = (uint)_importRsaKeyPair(hCont, 0, pkcs1, (uint)pkcs1.Length, Array.Empty<byte>(), 0);
                        LastImportNote = krc == Gm3000Native.SAR_OK
                            ? "证书与私钥均已导入。"
                            : $"证书已导入；私钥未导入（SKF_ImportRSAKeyPair → {Gm3000Native.ErrorText(krc)}）。" +
                              "私钥包裹格式尚未逆向确认，见逆向报告「待实机确认」清单。";
                        Common.Log.Write($"[GM3000] {LastImportNote}");
                    }
                }
            }
            finally
            {
                try { _closeContainer?.Invoke(hCont); } catch { /* 忽略 */ }
            }
        }

        if (LastImportNote != null) Common.Log.Write($"[GM3000] 导入结果：{LastImportNote}");
    }

    /// <summary>用证书主体 CN 生成容器名（长度受限 39 字符，超长退化为指纹前 32 位）。</summary>
    private static string BuildContainerName(X509Certificate2 cert)
    {
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        if (!string.IsNullOrWhiteSpace(cn))
        {
            cn = cn.Trim();
            if (cn.Length <= Gm3000Native.MaxContainerNameLen) return cn;
            return cn[..Gm3000Native.MaxContainerNameLen];
        }
        return cert.Thumbprint[..32];
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        EnsureReady(device);
        lock (_sync)
        {
            if (_deleteContainer == null)
                throw new NotSupportedException("SKF 模块未导出 SKF_DeleteContainer");
            var rc = (uint)_deleteContainer(_hApp, container.ContainerName);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException($"删除容器『{container.ContainerName}』失败：{Gm3000Native.ErrorText(rc)}");
        }
    }

    // ================= CSP 注册 =================

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

    // ================= PIN / 解锁 / 重置 =================

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        Common.Validators.EnsurePin(newPin, "新 PIN");
        EnsureReady(device);
        lock (_sync)
        {
            if (_changePin == null) throw new NotSupportedException("SKF 模块未导出 SKF_ChangePIN");
            var retry = 0u;
            var rc = (uint)_changePin(_hApp, Gm3000Native.PinTypeUser, oldPin, newPin, ref retry);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException(
                    $"修改用户 PIN 失败：{Gm3000Native.ErrorText(rc)}" +
                    (rc == Gm3000Native.SAR_PIN_INCORRECT || rc == Gm3000Native.SAR_PIN_LOCKED
                        ? $"（剩余重试 {retry} 次）" : ""));
        }
    }

    /// <summary>
    /// 解锁并重设用户 PIN。
    /// <para>
    /// GM3000 的 SKF 没有独立 PUK：<see cref="UnlockMethod.Puk"/> 与
    /// <see cref="UnlockMethod.AdminKey"/> 都走 <c>SKF_UnblockPIN(hDev, szAdminPin, szNewUserPin, &amp;retry)</c>
    /// （反汇编确认 <c>ret 0x10</c>=4 参数、PIN 类型仅接受 0/1）。出厂管理员口令见 SDK 的
    /// <c>Initconfig.ini</c>（<c>default_sopin=admin</c>），用户 PIN 出厂值 <c>12345678</c>。
    /// </para>
    /// </summary>
    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        Common.Validators.EnsurePin(newPin, "新 PIN");
        if (method == UnlockMethod.Challenge)
            throw new NotSupportedException(
                "GM3000 的挑战码/远程解锁（SKF_GenRemoteUnblockRequest / SKF_RemoteUnblockPIN）已定位，" +
                "但参数语义待实机确认；请使用管理员口令解锁。");

        EnsureReady(device);
        lock (_sync)
        {
            if (_unblockPin == null) throw new NotSupportedException("SKF 模块未导出 SKF_UnblockPIN");
            var retry = 0u;
            var rc = (uint)_unblockPin(_hDev, credential, newPin, ref retry);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException(
                    $"解锁失败：{Gm3000Native.ErrorText(rc)}" +
                    (rc == Gm3000Native.SAR_PIN_INCORRECT || rc == Gm3000Native.SAR_PIN_LOCKED
                        ? $"（剩余重试 {retry} 次）" : ""));
            device.IsLoggedIn = true;
        }
    }

    public string GenerateChallenge(UsbKeyDevice device) =>
        throw new NotSupportedException(
            "GM3000 远程解锁请求（SKF_GenRemoteUnblockRequest）已定位，但参数语义待实机确认。");

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin) =>
        throw new NotSupportedException(
            "GM3000 远程解锁（SKF_RemoteUnblockPIN）已定位，但参数语义待实机确认。");

    /// <summary>GM3000 有管理员(SO)口令，重置可用 SO 口令解锁用户 PIN，不强制要求当前用户 PIN。</summary>
    public bool ResetRequiresCurrentPin => false;

    /// <summary>
    /// 重置设备（把口令恢复为出厂态并清空全部容器/证书）。
    /// <para>
    /// <b>能力边界（如实说明）</b>：GM3000 的「真·令牌初始化」在厂商工具里是 PKCS#11
    /// <c>M_FormatToken</c>；而本机该 PKCS#11 层看不到这把老型号 Key（只有空槽位），
    /// 因此 SKF 侧没有等价的格式化入口。本实现采取与 LNCA 一致的「可靠性分级 + 诚实反馈」：
    /// </para>
    /// <list type="number">
    /// <item>用 <paramref name="adminKey"/>（SO 口令）走 <c>SKF_UnblockPIN</c> 重设用户 PIN；
    /// 若只给了 <paramref name="currentPin"/> 则走 <c>SKF_ChangePIN</c>；</item>
    /// <item>逐个删除设备上所有容器（<c>SKF_DeleteContainer</c>），失败项全部写入报告，绝不静默忽略；</item>
    /// <item>最后用新 PIN 重新 <c>SKF_VerifyPIN</c> 认证，只有通过才判定成功。</item>
    /// </list>
    /// </summary>
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        Common.Validators.EnsurePin(newPin, "新 PIN");
        LastResetReport = null;

        var report = new List<string>();
        var ok = false;

        EnsureReady(device);
        lock (_sync)
        {
            // ---- 阶段 1：重设用户 PIN ----
            var credential = adminKey ?? puk;
            var retry = 0u;
            if (!string.IsNullOrEmpty(credential) && _unblockPin != null)
            {
                // 首参必须是应用句柄（`credential` 为管理员/SO 口令，编号 0）
                var rc = (uint)_unblockPin(_hApp, credential, newPin, ref retry);
                report.Add($"SKF_UnblockPIN(管理员口令 → 新用户 PIN) → {Gm3000Native.ErrorText(rc)}" +
                           (rc != Gm3000Native.SAR_OK ? $"（剩余重试 {retry}）" : ""));
            }
            else if (!string.IsNullOrEmpty(currentPin) && _changePin != null)
            {
                var rc = (uint)_changePin(_hApp, Gm3000Native.PinTypeUser, currentPin, newPin, ref retry);
                report.Add($"SKF_ChangePIN(当前 PIN → 新 PIN) → {Gm3000Native.ErrorText(rc)}" +
                           (rc != Gm3000Native.SAR_OK ? $"（剩余重试 {retry}）" : ""));
            }
            else
            {
                report.Add("跳过重设用户 PIN：未提供管理员(SO)口令，也未提供当前用户 PIN。");
            }

            // ---- 阶段 2：清空容器 ----
            var containers = EnumContainerNamesLocked();
            if (containers.Count == 0)
            {
                report.Add("设备上没有容器需要清除。");
            }
            else
            {
                foreach (var name in containers)
                {
                    if (_deleteContainer == null)
                    {
                        report.Add($"容器『{name}』未删除：SKF_DeleteContainer 不可用");
                        continue;
                    }
                    var rc = (uint)_deleteContainer(_hApp, name);
                    report.Add($"删除容器『{name}』 → {Gm3000Native.ErrorText(rc)}");
                }
            }

            // ---- 阶段 3：用新 PIN 认证（唯一成功判据） ----
            if (_verifyPin != null)
            {
                var vRetry = 0u;
                var vrc = (uint)_verifyPin(_hApp, Gm3000Native.PinTypeUser, newPin, ref vRetry);
                ok = vrc == Gm3000Native.SAR_OK;
                report.Add($"SKF_VerifyPIN(新 PIN) → {Gm3000Native.ErrorText(vrc)}" +
                           (ok ? "（通过）" : $"（未通过，剩余重试 {vRetry}）"));
                if (ok) device.IsLoggedIn = true;
            }
        }

        LastResetReport = string.Join(Environment.NewLine, report);
        foreach (var line in report) Common.Log.Write($"[GM3000 重置] {line}");

        if (!ok)
            throw new InvalidOperationException(
                "GM3000 重置未完成：新 PIN 未能通过设备认证。" + Environment.NewLine + LastResetReport);
    }

    // ================= 工具 =================

    /// <summary>读取随机数（<c>SKF_GenRandom</c>，实机验证可用）。</summary>
    public byte[] GetRandom(int length)
    {
        if (_mod == null) Initialize();
        lock (_sync)
        {
            if (_hDev == IntPtr.Zero)
                throw new InvalidOperationException("未连接设备，无法读取随机数");
            var buf = new byte[length];
            var rc = (uint)_genRandom!(_hDev, buf, (uint)length);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException($"读取随机数失败：{Gm3000Native.ErrorText(rc)}");
            return buf;
        }
    }

    /// <summary>设置设备标签（<c>SKF_SetLabel</c>）。</summary>
    public void SetLabel(UsbKeyDevice device, string label)
    {
        EnsureReady(device);
        lock (_sync)
        {
            if (_setLabel == null) throw new NotSupportedException("SKF 模块未导出 SKF_SetLabel");
            // 待实测：首参该用设备句柄还是应用句柄尚未确认（GM/T 0016 标准写作 HAPPLICATION）。
            // 传错种类时本厂商通常返回 0xA000005，但也有直接崩溃的先例（SKF_GenRandom），
            // 故在实测确认前保留设备句柄，不盲试。实测结果请回填此处与逆向报告。
            var rc = (uint)_setLabel(_hDev, label);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException($"设置标签失败：{Gm3000Native.ErrorText(rc)}");
        }
    }

    /// <summary>直接透传 APDU（协议校准 / 诊断用）。</summary>
    public byte[] Transmit(UsbKeyDevice device, byte[] apdu)
    {
        EnsureReady(device);
        lock (_sync)
        {
            if (_transmit == null) throw new NotSupportedException("SKF 模块未导出 SKF_Transmit");
            var data = new byte[Gm3000Native.CertBufferSize];
            var len = (uint)data.Length;
            var rc = (uint)_transmit(_hDev, apdu, (uint)apdu.Length, data, ref len);
            if (rc != Gm3000Native.SAR_OK)
                throw new InvalidOperationException($"透传 APDU 失败：{Gm3000Native.ErrorText(rc)}");
            return data.AsSpan(0, (int)Math.Min(len, (uint)data.Length)).ToArray();
        }
    }

    public void Dispose()
    {
        lock (_sync) { DisconnectLocked(); }
        _mod?.Dispose();
        _mod = null;
    }
}
