using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Configuration;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// LNCA 平台 USB Key 驱动对接实现。
/// <para>
/// 对接目标：厂商管理 API 层 <c>JIT_USBKEY_HD.dll</c>（32 位，__stdcall，返回 int）。
/// 该 DLL 内部自行完成 COS/IFD/驱动层的调用（HDCOS_LNCA.dll → GP_IFD_LNCA.dll →
/// CIDCUSB.sys），因此管理端只需按名字解析 <c>USBKey_*</c> 导出即可完成全部管理操作。
/// </para>
/// <para>
/// 关键约束：驱动 DLL 为 32 位，宿主进程必须以 x86 运行（见 csproj 的 PlatformTarget）。
/// </para>
/// </summary>
public sealed class LncaProvider : IKeyProvider
{
    /// <summary>PIN 类型常量（USBKey_VerifyPin 的 type 参数）。</summary>
    private const uint PinTypeUser = 0;   // 用户 PIN
    private const uint PinTypeAdmin = 1;  // 管理员 PIN（SO PIN）

    /// <summary>证书类型常量（USBKey_WriteCert/ReadCert 的 dwCertType）。</summary>
    private const uint CertTypeSign = 0;    // 签名证书
    private const uint CertTypeEncrypt = 1; // 加密证书

    /// <summary>读取证书时预分配的缓冲大小（X.509 证书通常 &lt; 8KB）。</summary>
    private const int CertBufferSize = 8192;

    private const uint DefaultBaudRate = 0; // USB Key 走 USB，波特率参数实际被忽略

    public string PlatformName => "lnca";

    private string _libraryRoot = "";
    private NativeDll.Module? _jit;
    private NativeDll.Module? _hardApi;

    private IntPtr _hKey = IntPtr.Zero;
    private int _connectedIndex = -1;

    /// <summary>保护 _hKey / _connectedIndex 共享连接状态的锁，避免并发竞态。</summary>
    private readonly object _sync = new();

    // 委托
    private LncaNative.ConnectFn? _connect;
    private LncaNative.DisconnectFn? _disconnect;
    private LncaNative.UserLoginFn? _userLogin;
    private LncaNative.UserExitFn? _userExit;
    private LncaNative.ChangePinFn? _changePin;
    private LncaNative.UnlockPinFn? _unlockPin;
    private LncaNative.UserUnlockPinFn? _userUnlockPin;
    private LncaNative.VerifyPinFn? _verifyPin;
    private LncaNative.InitKeyFn? _initKey;
    private LncaNative.GetDevStateFn? _getDevState;
    private LncaNative.GetKeySNFn? _getKeySN;
    private LncaNative.ResetFn? _reset;
    private LncaNative.WriteCertFn? _writeCert;
    private LncaNative.ReadCertFn? _readCert;
    private LncaNative.RegisterCertFn? _registerCert;
    private LncaNative.ListKeyFn? _listKey;
    private LncaNative.CreatFileFn? _creatFile;
    private LncaNative.WriteFileFn? _writeFile;
    private LncaNative.ReadFileFn? _readFile;
    private LncaNative.DelFileFn? _delFile;
    private LncaNative.RFileLenFn? _rFileLen;
    private LncaNative.GetRandomFn? _getRandom;
    private LncaNative.GenRSAKeyPairFn? _genRSAKeyPair;
    private LncaNative.SignDataFn? _signData;
    private LncaNative.WritePubPriKeyFn? _writePubPriKey;
    private LncaNative.RegisterNotificationFn? _registerNotification;
    private LncaNative.UnRegisterNotificationFn? _unRegisterNotification;

    // HD_HardAPI.dll 委托（存储层：擦除 / PIN 校验 / 重写 PIN，见 LncaHardApiNative）
    private LncaHardApiNative.ConnectDevFn? _hsConnectDev;
    private LncaHardApiNative.DisconnectDevFn? _hsDisconnectDev;
    private LncaHardApiNative.EraseFn? _hsErase;
    private LncaHardApiNative.VerifyUserPinFn? _hsVerifyUserPin;
    private LncaHardApiNative.VerifySOPinFn? _hsVerifySOPin;
    private LncaHardApiNative.ChangeUserPinFn? _hsChangeUserPin;
    private LncaHardApiNative.ReWriteUserPinFn? _hsReWriteUserPin;
    private LncaHardApiNative.CheckStructureFn? _hsCheckStructure;

    // HDCOS_LNCA.dll 委托（COS 层：完全格式化 / 重设 PIN，见 LncaHdcosNative）
    private NativeDll.Module? _hdcos;
    private LncaHdcosNative.HdOpenFn? _hdOpen;
    private LncaHdcosNative.HdCloseFn? _hdClose;
    private LncaHdcosNative.HdIcResetFn? _hdIcReset;
    private LncaHdcosNative.HdClearDirFn? _hdClearDir;
    private LncaHdcosNative.ReloadPinFn? _hdReloadPin;
    private LncaHdcosNative.HdChangePinFn? _hdChangePin;
    private LncaHdcosNative.HdVerifyPinFn? _hdVerifyPin;
    private LncaHdcosNative.HdGetBcdSnFn? _hdGetBcdSn;
    private LncaHdcosNative.HdGetSnFn? _hdGetSn;
    private LncaHdcosNative.GetChallengeFn? _hdGetChallenge;
    private LncaHdcosNative.ExternalAuthFn? _hdExternalAuth;
    private LncaHdcosNative.ClearDfFn? _hdClearDf;
    private LncaHdcosNative.SelectFileFn? _hdSelectFile;
    private LncaHdcosNative.VerifyAdminPinFn? _hdVerifyAdminPin;
    private LncaHdcosNative.JitReloadPinFn? _hdJitReloadPin;

    /// <summary>
    /// 最近一次「初始化（完全格式化 + 重设 PIN）」的逐步执行报告，供 UI/日志展示。
    /// 未执行过或已清空时为 null。
    /// </summary>
    public string? LastResetReport { get; private set; }

    private readonly List<(int Vid, int Pid)> _whitelist = new();

    /// <summary>
    /// 创建 LNCA provider。
    /// </summary>
    /// <param name="libraryRoot">驱动 DLL 根目录（Library 或 Library/LNCA）。</param>
    /// <param name="whitelist">config.keyslist.lnca 的 VID/PID 白名单（为空则不按 VID/PID 过滤）。</param>
    public LncaProvider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
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
            if (_jit != null) return true;
            var path = Path.Combine(FindLibraryRoot(_libraryRoot), "JIT_USBKEY_HD.dll");
            return File.Exists(path);
        }
    }

    public void Initialize()
    {
        if (_jit != null) return;
        _libraryRoot = FindLibraryRoot(_libraryRoot);
        Console.WriteLine($"[LNCA] 尝试加载 DLL: {Path.Combine(_libraryRoot, "JIT_USBKEY_HD.dll")}");
        _jit = NativeDll.Load(Path.Combine(_libraryRoot, "JIT_USBKEY_HD.dll"));
        if (_jit == null)
            throw new InvalidOperationException("无法加载 JIT_USBKEY_HD.dll（请确认 Library/LNCA 目录存在且为 32 位进程）");
        Console.WriteLine("[LNCA] DLL 加载成功");

        _connect = _jit.GetDelegate<LncaNative.ConnectFn>("USBKey_Connect");
        _disconnect = _jit.GetDelegate<LncaNative.DisconnectFn>("USBKey_Disconnect");
        _userLogin = _jit.GetDelegate<LncaNative.UserLoginFn>("USBKey_UserLogin");
        _userExit = _jit.GetDelegate<LncaNative.UserExitFn>("User_Exit");
        _changePin = _jit.GetDelegate<LncaNative.ChangePinFn>("USBKey_ChangePin");
        _unlockPin = _jit.GetDelegate<LncaNative.UnlockPinFn>("USBKey_UnlockPin");
        _userUnlockPin = _jit.GetDelegate<LncaNative.UserUnlockPinFn>("USBKey_UserUnlockPin");
        _verifyPin = _jit.GetDelegate<LncaNative.VerifyPinFn>("USBKey_VerifyPin");
        _initKey = _jit.GetDelegate<LncaNative.InitKeyFn>("USBKey_InitKey");
        _getDevState = _jit.GetDelegate<LncaNative.GetDevStateFn>("USBKey_GetDevState");
        _getKeySN = _jit.GetDelegate<LncaNative.GetKeySNFn>("USBKey_GetKeySN");
        _reset = _jit.GetDelegate<LncaNative.ResetFn>("USBKey_Reset");
        _writeCert = _jit.GetDelegate<LncaNative.WriteCertFn>("USBKey_WriteCert");
        _readCert = _jit.GetDelegate<LncaNative.ReadCertFn>("USBKey_ReadCert");
        _registerCert = _jit.GetDelegate<LncaNative.RegisterCertFn>("USBKey_RegisterCert");
        _listKey = _jit.GetDelegate<LncaNative.ListKeyFn>("USBKey_ListKey");
        _creatFile = _jit.GetDelegate<LncaNative.CreatFileFn>("USBKey_CreatFile");
        _writeFile = _jit.GetDelegate<LncaNative.WriteFileFn>("USBKey_WriteFile");
        _readFile = _jit.GetDelegate<LncaNative.ReadFileFn>("USBKey_ReadFile");
        _delFile = _jit.GetDelegate<LncaNative.DelFileFn>("USBKey_DelFile");
        _rFileLen = _jit.GetDelegate<LncaNative.RFileLenFn>("USBKey_RFileLen");
        _getRandom = _jit.GetDelegate<LncaNative.GetRandomFn>("USBKey_GetRandom");
        _genRSAKeyPair = _jit.GetDelegate<LncaNative.GenRSAKeyPairFn>("USBKey_GenRSAKeyPair");
        _signData = _jit.GetDelegate<LncaNative.SignDataFn>("USBKey_SignData");
        _writePubPriKey = _jit.GetDelegate<LncaNative.WritePubPriKeyFn>("USBKey_WritePubPriKey");
        _registerNotification = _jit.GetDelegate<LncaNative.RegisterNotificationFn>("USBKey_RegisterNotification");
        _unRegisterNotification = _jit.GetDelegate<LncaNative.UnRegisterNotificationFn>("USBKey_UnRegisterNotification");

        if (_connect == null || _disconnect == null)
            throw new InvalidOperationException("JIT_USBKEY_HD.dll 导出解析失败（USBKey_Connect/Disconnect 不存在）");

        // 加载 HD_HardAPI.dll（真实设备初始化/擦除能力）。
        // 注意：JIT_USBKEY_HD.dll 的 USBKey_InitKey/Reset 为空壳（仅打印日志返回 0），
        // 因此「重置设备初始化」必须走 HD_HardAPI.dll 的 HSErase 链路。
        LoadHardApi();
    }

    /// <summary>
    /// 加载 HD_HardAPI.dll 并解析初始化相关导出。失败不抛异常（非关键路径），
    /// 由 ResetDevice 在使用时检测并给出明确错误。
    /// </summary>
    private void LoadHardApi()
    {
        if (_hardApi != null) return;
        var path = Path.Combine(_libraryRoot, "HD_HardAPI.dll");
        if (!File.Exists(path))
        {
            Console.WriteLine($"[LNCA] 未找到 HD_HardAPI.dll：{path}（设备初始化/擦除将不可用）");
            return;
        }

        _hardApi = NativeDll.Load(path);
        if (_hardApi == null)
        {
            Console.WriteLine($"[LNCA] HD_HardAPI.dll 加载失败：{path}");
            return;
        }

        _hsConnectDev = _hardApi.GetDelegate<LncaHardApiNative.ConnectDevFn>("HSConnectDev");
        _hsDisconnectDev = _hardApi.GetDelegate<LncaHardApiNative.DisconnectDevFn>("HSDisconnectDev");
        _hsErase = _hardApi.GetDelegate<LncaHardApiNative.EraseFn>("HSErase");
        _hsVerifyUserPin = _hardApi.GetDelegate<LncaHardApiNative.VerifyUserPinFn>("HSVerifyUserPin");
        _hsVerifySOPin = _hardApi.GetDelegate<LncaHardApiNative.VerifySOPinFn>("HSVerifySOPin");
        _hsChangeUserPin = _hardApi.GetDelegate<LncaHardApiNative.ChangeUserPinFn>("HSChangeUserPin");
        _hsReWriteUserPin = _hardApi.GetDelegate<LncaHardApiNative.ReWriteUserPinFn>("HSReWriteUserPin");
        _hsCheckStructure = _hardApi.GetDelegate<LncaHardApiNative.CheckStructureFn>("HSCheckStructure");

        Console.WriteLine($"[LNCA] HD_HardAPI.dll 加载成功（HSErase 可用 = {_hsErase != null}）");
    }

    /// <summary>
    /// 加载 <c>HDCOS_LNCA.dll</c> 并解析「完全格式化 / 重设 PIN」相关导出。
    /// <para>
    /// 该模块是 JIT 层（JIT_USBKEY_HD.dll）实际动态加载的 COS 层（字符串证据：DLL 内出现
    /// "HDCOS_LNCA" 与 HD_ChangePin/HD_VerifyPin/HD_OpenJITDevice 等导入名），因此与其调用
    /// 同一模块可保证句柄语义一致。失败时抛异常（调用方按需捕获）。
    /// </para>
    /// </summary>
    private void LoadHdcos()
    {
        if (_hdcos != null) return;

        var path = Path.Combine(_libraryRoot, "HDCOS_LNCA.dll");
        if (!File.Exists(path))
            throw new InvalidOperationException($"未找到 HDCOS_LNCA.dll：{path}（COS 层完全格式化不可用）");

        _hdcos = NativeDll.Load(path)
                 ?? throw new InvalidOperationException($"HDCOS_LNCA.dll 加载失败：{path}");

        _hdOpen = _hdcos.GetDelegate<LncaHdcosNative.HdOpenFn>("HD_Open");
        _hdClose = _hdcos.GetDelegate<LncaHdcosNative.HdCloseFn>("HD_Close");
        _hdIcReset = _hdcos.GetDelegate<LncaHdcosNative.HdIcResetFn>("HD_IC_RESET");
        _hdClearDir = _hdcos.GetDelegate<LncaHdcosNative.HdClearDirFn>("HD_ClearDir");
        _hdReloadPin = _hdcos.GetDelegate<LncaHdcosNative.ReloadPinFn>("Reload_Pin");
        _hdChangePin = _hdcos.GetDelegate<LncaHdcosNative.HdChangePinFn>("HD_ChangePin");
        _hdVerifyPin = _hdcos.GetDelegate<LncaHdcosNative.HdVerifyPinFn>("HD_VerifyPin");
        _hdGetBcdSn = _hdcos.GetDelegate<LncaHdcosNative.HdGetBcdSnFn>("HD_GET_BCDSN");
        _hdGetSn = _hdcos.GetDelegate<LncaHdcosNative.HdGetSnFn>("HD_GET_SN");
        _hdGetChallenge = _hdcos.GetDelegate<LncaHdcosNative.GetChallengeFn>("Get_Challenge");
        _hdExternalAuth = _hdcos.GetDelegate<LncaHdcosNative.ExternalAuthFn>("External_Authentication");
        _hdClearDf = _hdcos.GetDelegate<LncaHdcosNative.ClearDfFn>("Clear_DF");
        _hdSelectFile = _hdcos.GetDelegate<LncaHdcosNative.SelectFileFn>("Select_File");
        _hdVerifyAdminPin = _hdcos.GetDelegate<LncaHdcosNative.VerifyAdminPinFn>("HDJIT_VerifyAdminPin");
        _hdJitReloadPin = _hdcos.GetDelegate<LncaHdcosNative.JitReloadPinFn>("HDJIT_ReloadPin");

        Console.WriteLine($"[LNCA] HDCOS_LNCA.dll 加载成功（HD_ClearDir 可用 = {_hdClearDir != null}，" +
                          $"Reload_Pin = {_hdReloadPin != null}，HD_ChangePin = {_hdChangePin != null}，" +
                          $"HD_VerifyPin = {_hdVerifyPin != null}）");
    }

    private static string FindLibraryRoot(string root)
    {
        if (Directory.Exists(root) && File.Exists(Path.Combine(root, "JIT_USBKEY_HD.dll"))) return root;
        var candidates = new[]
        {
            Path.Combine(root, "Library"),
            Path.Combine(root, "Library", "LNCA"),
            Path.Combine(AppContext.BaseDirectory, "Library"),
            Path.Combine(AppContext.BaseDirectory, "Library", "LNCA"),
        };
        foreach (var c in candidates)
            if (Directory.Exists(c) && File.Exists(Path.Combine(c, "JIT_USBKEY_HD.dll")))
                return c;
        return root;
    }

    // ================= 设备枚举 / 打开 =================

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var result = new List<UsbKeyDevice>();
        try
        {
            if (_jit == null) Initialize();

            // 用 DLL 的 USBKey_ListKey 获取设备数量（不依赖 WMI/VID/PID ——
            // LNCA 设备可能通过 usbip/VMware 虚拟化或厂商私有驱动接入，标准 PNP 枚举不到）。
            if (_listKey == null)
            {
                var msg = $"[LNCA] Enumerate: ListKey 函数不可用";
                System.Diagnostics.Debug.WriteLine(msg);
                Console.WriteLine(msg);
                return result;
            }

            var listKeyRc = _listKey(out uint count);
            if (listKeyRc != 0)
            {
                var msg = $"[LNCA] Enumerate: ListKey 调用失败 (rc=0x{listKeyRc:X})";
                System.Diagnostics.Debug.WriteLine(msg);
                Console.WriteLine(msg);
                return result;
            }

            var countMsg = $"[LNCA] Enumerate: ListKey count={count}";
            System.Diagnostics.Debug.WriteLine(countMsg);
            Console.WriteLine(countMsg);

            // 逐个临时连接获取序列号/状态（ListKey 返回设备数量，上限 4）
            for (uint i = 0; i < count && i < 4; i++)
            {
                var dev = new UsbKeyDevice
                {
                    Platform = PlatformName,
                    VendorName = "LNCA",
                    Model = "LNCA USB Key",
                    SerialNumber = $"设备 {i}",  // 默认显示设备索引，即使后续操作失败
                    Handle = (int)i,
                };

                try
                {
                    if (_connect != null)
                    {
                        var connectRc = _connect(i, DefaultBaudRate, out var hKey);
                        var connectMsg = $"[LNCA] Connect({i}): rc=0x{connectRc:X} hKey=0x{hKey:X}";
                        System.Diagnostics.Debug.WriteLine(connectMsg);
                        Console.WriteLine(connectMsg);

                        if (connectRc == 0 && hKey != IntPtr.Zero)
                        {
                            try
                            {
                                var sb = new StringBuilder(64);
                                uint snLen = 64;
                                if (_getKeySN != null && _getKeySN(hKey, sb, ref snLen) == 0 && sb.Length > 0)
                                {
                                    dev.SerialNumber = sb.ToString();
                                    var snMsg = $"[LNCA]   序列号: {sb}";
                                    System.Diagnostics.Debug.WriteLine(snMsg);
                                    Console.WriteLine(snMsg);
                                }

                                if (_getDevState != null && _getDevState(hKey, out uint state) == 0)
                                    dev.Notes = $"状态 0x{state:X}";
                            }
                            finally
                            {
                                if (_disconnect != null)
                                {
                                    var h = hKey;
                                    try { _disconnect(ref h); } catch { }
                                }
                            }
                        }
                        else
                        {
                            dev.Notes = $"连接失败 (rc=0x{connectRc:X})";
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[LNCA] 设备 {i} 枚举异常: {ex.Message}");
                    dev.Notes = "枚举异常";
                }

                result.Add(dev);
            }
        }
        catch (Exception ex)
        {
            var errMsg = $"[LNCA] Enumerate 失败: {ex}";
            System.Diagnostics.Debug.WriteLine(errMsg);
            Console.WriteLine(errMsg);
        }

        var finalMsg = $"[LNCA] Enumerate 返回 {result.Count} 台设备";
        System.Diagnostics.Debug.WriteLine(finalMsg);
        Console.WriteLine(finalMsg);
        return result;
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        var devs = Enumerate();
        if (handleOrSerial >= 0 && handleOrSerial < devs.Count) return devs[handleOrSerial];
        if (devs.Count > 0) return devs[0];
        throw new InvalidOperationException("未检测到 LNCA USB Key 设备");
    }

    // ================= 会话 / 认证 =================

    /// <summary>确保已与指定设备建立物理连接（Connect）。</summary>
    private void EnsureConnected(UsbKeyDevice device)
    {
        if (_jit == null) Initialize();
        lock (_sync)
        {
            if (_hKey != IntPtr.Zero && _connectedIndex == device.Handle) return;

            // 先断开旧连接
            DisconnectCoreLocked();

            var rc = _connect!((uint)Math.Max(0, device.Handle), DefaultBaudRate, out var hKey);
            if (rc != 0) throw new InvalidOperationException($"连接 LNCA 设备失败 (错误码 0x{rc:X})");
            _hKey = hKey;
            _connectedIndex = device.Handle;
        }
    }

    private void DisconnectCore()
    {
        lock (_sync)
        {
            DisconnectCoreLocked();
        }
    }

    /// <summary>断开连接（调用方需已持有 _sync 锁）。</summary>
    private void DisconnectCoreLocked()
    {
        if (_hKey == IntPtr.Zero) return;
        try { _userExit?.Invoke(_hKey); } catch { }
        try { _disconnect?.Invoke(ref _hKey); } catch { }
        _hKey = IntPtr.Zero;
        _connectedIndex = -1;
    }

    public void Login(UsbKeyDevice device, string pin)
    {
        EnsureConnected(device);
        var rc = _userLogin!(_hKey, pin, (uint)pin.Length);
        if (rc != 0) throw new InvalidOperationException($"PIN 登录失败 (错误码 0x{rc:X})");
        device.IsLoggedIn = true;
    }

    public void Logout(UsbKeyDevice device)
    {
        DisconnectCore();
        device.IsLoggedIn = false;
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        try
        {
            EnsureConnected(device);

            var sb = new StringBuilder(64);
            uint snLen = 64;
            if (_getKeySN!(_hKey, sb, ref snLen) == 0 && sb.Length > 0)
                device.SerialNumber = sb.ToString();

            if (_getDevState!(_hKey, out uint state) == 0)
                device.Notes = $"状态 0x{state:X}";
        }
        catch (Exception ex)
        {
            // 设备信息获取失败不影响已枚举的基本信息，但记录日志便于排查。
            USBKey.Core.Common.Log.Write($"LNCA 获取设备详情失败：{ex.Message}");
        }
        return device;
    }

    // ================= 证书 / 容器 =================

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        EnsureConnected(device);

        // JIT 层为单设备证书模型：读取签名证书（type 0）与加密证书（type 1）。
        // 多容器场景需扩展 HD_ReadContainerListInfo（待实体设备确认）。
        var result = new List<KeyContainer>();
        for (uint type = CertTypeSign; type <= CertTypeEncrypt; type++)
        {
            var cert = TryReadCert(device, type);
            if (cert != null) result.Add(cert);
        }
        return result;
    }

    private KeyContainer? TryReadCert(UsbKeyDevice device, uint certType)
    {
        try
        {
            var buf = new byte[CertBufferSize];
            uint len = (uint)buf.Length;
            if (_readCert!(_hKey, certType, buf, ref len) != 0 || len == 0) return null;
            var der = buf.AsSpan(0, (int)Math.Min(len, buf.Length)).ToArray();
            return BuildContainer(der);
        }
        catch (Exception ex)
        {
            USBKey.Core.Common.Log.Write($"LNCA 读取证书(type={certType})失败：{ex.Message}");
            return null;
        }
    }

    private static KeyContainer BuildContainer(byte[] certDer)
    {
        using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certDer);
        return new KeyContainer
        {
            Name = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false),
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = "RSA/证书",
            KeyUsage = "数字签名",
            ExtendedKeyUsage = "—",
            ContainerName = cert.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false),
            ContainerUuid = cert.Thumbprint,
            CertRaw = certDer,
        };
    }

    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        EnsureConnected(device);

        var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
            pfxPath, string.IsNullOrEmpty(pfxPassword) ? null : pfxPassword,
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);

        // 1) 写入证书（签名证书）
        var der = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
        var rc = _writeCert!(_hKey, CertTypeSign, der, (uint)der.Length);
        if (rc != 0) throw new InvalidOperationException($"写入证书失败 (错误码 0x{rc:X})");

        // 2) 注册证书
        _registerCert?.Invoke(_hKey, CertTypeSign);

        // 3) 导入私钥（若 PFX 含私钥）
        if (cert.HasPrivateKey)
        {
            try
            {
                ImportPrivateKey(cert);
            }
            catch (Exception ex)
            {
                // 私钥导入失败不阻断证书导入，但提示
                USBKey.Core.Common.Log.Write($"LNCA 私钥导入失败：{ex.Message}");
            }
        }
    }

    /// <summary>
    /// 导入 RSA 私钥到设备。
    /// <para>
    /// 正确链路为 <c>USBKey_WritePubPriKey</c>（而非 GenRSAKeyPair —— 后者会在设备内
    /// 生成一对全新密钥，导致「导入证书」与「设备内私钥」不匹配，导入后无法签名）。
    /// 签名：<c>WritePubPriKey(hKey, dEnKeyIndex, pri, priLen, pubEncKey, pubEncKeyLen, algID)</c>。
    /// </para>
    /// <para>
    /// 关键未决项：<c>pubEncKey</c> 需为「用设备加密公钥对私钥加密」的结果
    /// （协议见 <c>HDJIT_ImportRsaPrivateKey</c> 链路，尚未逆向完成）。
    /// 因此在协议确认前，这里不猜测加密细节，而是：
    /// 1) 先尝试从设备读取加密证书提取加密公钥（设备公钥）；
    /// 2) 若可用，用该公钥对私钥做 PKCS#1 v1.5 加密后调用 WritePubPriKey；
    /// 3) 若任何一步不确定或失败，明确抛出异常并记录日志，绝不静默「假成功」。
    /// </para>
    /// </summary>
    private void ImportPrivateKey(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        if (cert.GetRSAPrivateKey() is not { } rsa)
            return; // 无 RSA 私钥，仅证书导入，合法。

        if (_writePubPriKey == null)
            throw new InvalidOperationException(
                "设备驱动缺少 USBKey_WritePubPriKey 导出，无法导入私钥（仅证书已导入）");

        // 导出 PKCS#1 DER 私钥（明文，仅用于计算，不落盘）
        var priKey = rsa.ExportRSAPrivateKey();

        // 读取设备加密证书，提取加密公钥（作为 WritePubPriKey 的加密公钥）
        byte[] encPub;
        try
        {
            var encCertBuf = new byte[CertBufferSize];
            uint encLen = (uint)encCertBuf.Length;
            if (_readCert!(_hKey, CertTypeEncrypt, encCertBuf, ref encLen) != 0 || encLen == 0)
                throw new InvalidOperationException("无法读取设备加密证书（certType=1），无法获取加密公钥");
            using var encCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                encCertBuf.AsSpan(0, (int)Math.Min(encLen, encCertBuf.Length)).ToArray());
            var encPubKey = encCert.GetRSAPublicKey()
                ?? throw new InvalidOperationException("设备加密证书不含 RSA 公钥");
            encPub = encPubKey.ExportRSAPublicKey();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"获取设备加密公钥失败，私钥导入中止（避免证书与私钥不匹配）：{ex.Message}");
        }

        // 用设备加密公钥对私钥做 PKCS#1 v1.5 加密（协议假设，待实体设备确认）
        byte[] encryptedPri;
        try
        {
            using var pubRsa = RSA.Create();
            pubRsa.ImportRSAPublicKey(encPub, out _);
            encryptedPri = pubRsa.Encrypt(priKey, RSAEncryptionPadding.Pkcs1);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"私钥加密失败：{ex.Message}");
        }

        // dEnKeyIndex：0=签名密钥、1=加密密钥（与 certType 约定一致）
        var rc = _writePubPriKey(_hKey, CertTypeSign, priKey, (uint)priKey.Length,
            encryptedPri, (uint)encryptedPri.Length, 0 /* algID，RSA 默认 */);

        if (rc != 0)
        {
            USBKey.Core.Common.Log.Write($"LNCA WritePubPriKey 失败 rc=0x{rc:X}（加密协议或参数待实体设备确认）");
            throw new InvalidOperationException($"导入私钥失败 (错误码 0x{rc:X})");
        }
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        var der = container.CertRaw ?? ReadCertRaw(device);
        System.IO.File.WriteAllBytes(outputPath, der);
    }

    public void ViewCertificate(KeyContainer container)
    {
        var der = container.CertRaw;
        if (der == null) throw new InvalidOperationException("证书数据不可用");
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        System.IO.File.WriteAllBytes(tmp, der);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmp) { UseShellExecute = true });
    }

    private byte[] ReadCertRaw(UsbKeyDevice device)
    {
        EnsureConnected(device);
        var buf = new byte[CertBufferSize];
        uint len = (uint)buf.Length;
        if (_readCert!(_hKey, CertTypeSign, buf, ref len) != 0 || len == 0)
            throw new InvalidOperationException("读取证书失败");
        return buf.AsSpan(0, (int)Math.Min(len, buf.Length)).ToArray();
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        EnsureConnected(device);

        // LNCA JIT 层证书按 certType（0=签名/1=加密）索引存储，无「按文件名删除证书」的语义；
        // DelFile/CreatFile/WriteFile 操作的是 Key 内数据文件，与证书容器无关。
        // 因此不能用 container.ContainerName（实为证书 CN，如人名）去 DelFile —— 那样删不掉证书，
        // 还可能误删同名数据文件。
        //
        // 删除证书的正确入口已逆向确认（见 Roadmap/05-LNCA逆向分析案例.md 第十一章）：
        //   - HD_DeleteCert(const char* A, const char* B)         // 内部拼 A \x00ff B，且会弹 MessageBox
        //   - HD_DeleteContainer(int hDev, WORD containerId)      // 按容器索引删除，无弹窗
        // 二者均为 __stdcall、ret 8，位于 HDCOS_LNCA.dll。
        //
        // containerId 语义（反汇编确认）：低字节 = 容器索引（1/2/3），高字节 = 证书类型（0=签名/1=加密）；
        // 删除 APDU 的 P1 = 低字节 + 0x10。容器枚举入口为 HD_ReadContainerInfoEx（ret 0x10，4 参数）。
        //
        // 仍待实机确认：containerId 低字节与 KeyContainer 的精确映射（JIT 层仅暴露 type 0/1 两个槽位，
        // 推测低字节固定为 1）。当前环境无真实 LNCA 设备（仅插入 Feitian ePass3003），
        // 故暂不落地实现，避免猜测性误删。
        throw new NotSupportedException(
            "LNCA 平台删除证书能力尚未对接（HD_DeleteCert/HD_DeleteContainer 签名已确认，" +
            "但容器索引映射需实机验证），为安全起见不执行猜测性删除。");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        // 通过标准 CryptoAPI 将证书注册到当前用户证书库
        USBKey.Core.Crypto.CertHelper.Register(container.CertRaw, container.Name, container.KeyBinding);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            USBKey.Core.Crypto.CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    // ================= PIN / 解锁 / 重置 =================

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        EnsureConnected(device);
        var rc = _changePin!(_hKey, oldPin, (uint)oldPin.Length, newPin, (uint)newPin.Length);
        if (rc != 0) throw new InvalidOperationException($"修改密码失败 (错误码 0x{rc:X})");
    }

    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        EnsureConnected(device);
        int rc = -1;
        switch (method)
        {
            case UnlockMethod.Puk:
                // PUK 解锁并重设用户 PIN
                rc = _userUnlockPin!(_hKey, credential, (uint)credential.Length, newPin, (uint)newPin.Length);
                if (rc != 0) rc = _unlockPin!(_hKey, credential, (uint)credential.Length);
                break;
            case UnlockMethod.AdminKey:
                // 管理员密钥解锁（SO PIN）
                rc = _unlockPin!(_hKey, credential, (uint)credential.Length);
                break;
            case UnlockMethod.Challenge:
                throw new NotSupportedException("挑战码解锁需实体设备确认后对接");
            default:
                throw new ArgumentOutOfRangeException(nameof(method));
        }
        if (rc != 0) throw new InvalidOperationException($"解锁失败 (错误码 0x{rc:X})");
        device.IsLoggedIn = true;
    }

    public string GenerateChallenge(UsbKeyDevice device)
    {
        EnsureConnected(device);
        var buf = new byte[16];
        if (_getRandom!(_hKey, 16, buf) != 0)
            throw new InvalidOperationException("生成挑战码失败");
        return Convert.ToHexString(buf);
    }

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
    {
        throw new NotSupportedException("挑战码解锁需实体设备确认后对接");
    }

    /// <summary>
    /// 设备初始化（出厂重置）：<b>COS 层完全格式化</b> + <b>重设用户 PIN</b>，并逐步验证结果。
    /// <para>
    /// 逆向结论（2026-09，静态反汇编验证；工具 <c>tools/disasm_lnca.py</c>）：
    /// <list type="number">
    /// <item>JIT 层 <c>USBKey_InitKey</c>/<c>USBKey_Reset</c> 为调试空壳；
    /// HDCOS 层 <c>InitialCard</c> 为空 stub（<c>or eax,-1; ret 0x10</c>），二者均不可用。</item>
    /// <item><b>完全格式化</b>唯一入口 = <c>HDCOS_LNCA.dll!HD_ClearDir(hCard)</c>：
    /// <c>Get_Challenge</c>(CLA 0x84, 8B) → 用 DLL 数据段内置传输密钥（RVA 0x19050）做挑战应答 →
    /// <c>External_Authentication</c>(CLA 0x82, P1=0) → <c>Clear_DF</c>(私有 APDU <c>BF CE 00 00 00</c>)。
    /// 它<b>不需要用户 PIN</b>（传输密钥内置于 DLL），因此适用于「忘记 PIN 后恢复出厂」。</item>
    /// <item><b>重设 PIN</b>入口：<c>Reload_Pin</c>（ISO7816-4 INS 0x5E RESET RETRY COUNTER）、
    /// 或 <c>HD_ChangePin</c>（缓冲区格式 <c>旧PIN + 0xFF + 新PIN</c>）、
    /// 或存储层 <c>HSReWriteUserPin</c>（需旧 PIN）。</item>
    /// <item>存储层 <c>HSErase</c>（HD_SortDev）只擦除「存储层文件系统」，不重置 COS PIN，
    /// 因此必须与 <c>HD_ClearDir</c> 叠加才是真正的「完全格式化」（含证书/容器/密钥数据区）。</item>
    /// </list>
    /// </para>
    /// <para>
    /// 诚实原则：每一步真实返回码都写入 <see cref="LastResetReport"/> 与日志；
    /// 只有最终用新 PIN 通过 <c>HD_VerifyPin</c> 认证成功才判定为成功，否则抛出带完整报告的异常。
    /// </para>
    /// </summary>
    /// <param name="device">目标设备（<c>Handle</c> 作为设备端口索引 0~3）。</param>
    /// <param name="newPin">新用户 PIN（6~16 位）。</param>
    /// <param name="puk">可选：解锁码/PUK。提供时会按 ISO7816 语义以「PUK + 新PIN」作为 INS 0x5E 的数据。</param>
    /// <param name="adminKey">可选：管理员密钥，作为 <c>HD_ChangePin</c>/<c>HSReWriteUserPin</c> 的旧 PIN。</param>
    /// <summary>LNCA 有 SO 口令/传输密钥路径，重置不强制要求当前用户 PIN。</summary>
    public bool ResetRequiresCurrentPin => false;

    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        USBKey.Core.Common.Validators.EnsurePin(newPin, "新 PIN");
        if (newPin.Length > 16)
            throw new ArgumentException("LNCA 平台的 PIN 长度上限为 16 位");

        LoadHdcos();
        if (_hdClearDir == null || _hdOpen == null)
            throw new InvalidOperationException("HDCOS_LNCA.dll 缺少 HD_ClearDir/HD_Open 导出，无法执行完全格式化");

        var report = new List<string>();
        LastResetReport = null;

        // 关闭 JIT 会话，避免与「COS 直连 + 存储层」两条通路争抢同一张卡。
        DisconnectCore();

        var port = (uint)Math.Max(0, device.Handle);

        // ---------- 阶段 1：存储层擦除（释放数据区文件） ----------
        // 失败不致命（COS 层格式化才是关键），但必须如实记录，绝不吞掉。
        try
        {
            report.Add(EraseStorageLayer(device));
        }
        catch (Exception ex)
        {
            report.Add($"存储层擦除异常（忽略，不阻断后续格式化）：{ex.Message}");
        }

        // ---------- 阶段 2：COS 层完全格式化 + 重设 PIN（同一卡片会话内顺序执行） ----------
        IntPtr hCard = IntPtr.Zero;
        var verified = false;
        try
        {
            hCard = _hdOpen(port);
            report.Add($"HD_Open(port={port}) → hCard=0x{hCard.ToInt64():X}");
            if (hCard == IntPtr.Zero)
                throw new InvalidOperationException("打开 LNCA 设备失败（HD_Open 返回 0）");

            if (_hdGetBcdSn != null)
            {
                var snBuf = new byte[64];
                if (_hdGetBcdSn(hCard, snBuf) == 0)
                    report.Add($"设备序列号(BCD)：{ToAscii(snBuf)}");
            }

            // 与厂商 HD_OpenJITDevice 的打开流程一致：先复位卡片，确保后续 APDU 会话干净。
            if (_hdIcReset != null)
            {
                var atr = new byte[64];
                report.Add($"HD_IC_RESET → 0x{_hdIcReset(hCard, atr):X}");
            }

            // ===== 关键步骤 1：COS 层完全格式化（首选：内置默认传输密钥） =====
            var rcClear = _hdClearDir(hCard);
            report.Add($"HD_ClearDir(完全格式化：内置传输密钥外部认证 → Clear_DF) → 0x{rcClear:X}");
            var formatted = rcClear == 0;

            if (!formatted)
            {
                // 失败几乎总是「本卡的管理员/传输密钥已非 SDK 内置默认值」。
                // 逐层诊断把 SW 记入报告（可比对不同设备/批次），便于定位与售后分析。
                DiagnoseAuthStack(hCard, report);

                // ===== 关键步骤 2：备用链路 —— 调用方提供 SO 口令 → 管理员认证 → 直接 Clear_DF =====
                if (!string.IsNullOrEmpty(adminKey) && _hdVerifyAdminPin != null && _hdClearDf != null)
                {
                    var keyBytes = Encoding.ASCII.GetBytes(adminKey);
                    var authRc = _hdVerifyAdminPin(hCard, keyBytes, (uint)keyBytes.Length);
                    report.Add($"HDJIT_VerifyAdminPin(调用方提供的 SO 口令) → {authRc}" +
                               (authRc == 0 ? "（管理员认证通过）" : "（口令不匹配）"));

                    if (authRc == 0)
                    {
                        var dfRc = _hdClearDf(hCard, out var dfSw);
                        report.Add($"Clear_DF(管理员会话内直接格式化) → rc=0x{dfRc:X}  sw=0x{dfSw:X4}");
                        formatted = dfRc >= 0 && dfSw == 0x9000;
                    }
                }
                else if (string.IsNullOrEmpty(adminKey))
                {
                    report.Add("备用格式化链路跳过：未提供 SO 口令（本卡内置默认传输密钥已不适用时，必须提供 SO 口令）");
                }
            }

            if (!formatted)
                throw new InvalidOperationException(
                    "COS 层完全格式化失败：本卡的传输密钥/管理员口令与 SDK 内置默认值不一致。" +
                    Environment.NewLine + LastResetReportPreview(report));

            // ===== 重设用户 PIN =====
            SetUserPin(hCard, device, newPin, puk, adminKey, report);

            // ===== 验证新 PIN（唯一判定依据） =====
            if (_hdVerifyPin != null)
            {
                var vrc = _hdVerifyPin(hCard, Encoding.ASCII.GetBytes(newPin), (uint)newPin.Length);
                verified = vrc == 0;
                report.Add($"HD_VerifyPin(新 PIN) → {DescribeVerify(vrc)}");
            }
            else
            {
                report.Add("HD_VerifyPin 不可用，改用存储层 HSVerifyUserPin 验证");
            }
        }
        finally
        {
            if (hCard != IntPtr.Zero)
            {
                try { _hdClose?.Invoke(hCard); } catch { /* 关闭失败不影响结果判定 */ }
                report.Add("HD_Close");
            }
        }

        // COS 层不可用时，退化为「存储层 HSVerifyUserPin 验证」，避免漏判。
        if (!verified && _hsVerifyUserPin != null && _hsConnectDev != null && _hsDisconnectDev != null)
        {
            var rc = _hsConnectDev(Math.Max(0, device.Handle), out var hDev);
            if (rc == 0 && hDev != IntPtr.Zero)
            {
                try
                {
                    var vrc = _hsVerifyUserPin(hDev, newPin, (uint)newPin.Length);
                    verified = vrc == 0;
                    report.Add($"HSVerifyUserPin(新 PIN, 存储层) → 0x{vrc:X}（{(vrc == 0 ? "通过" : "未通过")}）");
                }
                finally { try { _hsDisconnectDev(hDev); } catch { } }
            }
        }

        LastResetReport = string.Join(Environment.NewLine, report);
        foreach (var line in report) USBKey.Core.Common.Log.Write($"[LNCA 初始化] {line}");

        if (!verified)
        {
            // 格式化可能已成功、但新 PIN 未生效：如实报错并给出完整报告，绝不假装成功。
            throw new InvalidOperationException(
                "LNCA 设备初始化未完成：完全格式化已执行，但新 PIN 未能通过设备认证。" +
                Environment.NewLine + LastResetReport);
        }

        device.IsLoggedIn = true;
    }

    /// <summary>
    /// 存储层擦除（HD_HardAPI.dll：HSConnectDev → HSErase → HSDisconnectDev），返回可读报告。
    /// <para>该层只擦除存储层文件系统（HD_SortDev 的 <c>HS_Erase</c>，内部为 DD/AD 系列的
    /// 文件系统 APDU），不触及 COS 层 PIN；成功与否都如实回报。</para>
    /// </summary>
    private string EraseStorageLayer(UsbKeyDevice device)
    {
        if (_hsErase == null || _hsConnectDev == null || _hsDisconnectDev == null)
            return "存储层擦除跳过：HD_HardAPI.dll 或 HSErase 导出不可用";

        var devIndex = Math.Max(0, device.Handle);
        var rc = _hsConnectDev(devIndex, out var hDev);
        if (rc != 0 || hDev == IntPtr.Zero)
            return $"存储层擦除跳过：HSConnectDev({devIndex}) → 0x{rc:X}";

        try
        {
            var eraseRc = _hsErase(hDev);
            var text = $"HSErase(存储层擦除) → 0x{eraseRc:X}";
            if (eraseRc == 0 && _hsCheckStructure != null)
                text += $"；HSCheckStructure → 0x{_hsCheckStructure(hDev):X}";
            return text;
        }
        finally
        {
            try { _hsDisconnectDev(hDev); } catch { }
        }
    }

    /// <summary>
    /// 在已认证的卡片会话内重设用户 PIN：按「成功概率 + 风险」由低到高依次尝试，
    /// 每步的返回码都写入 <paramref name="report"/>（失败不抛出，交由最终验证判定）。
    /// </summary>
    private void SetUserPin(IntPtr hCard, UsbKeyDevice device, string newPin,
        string? puk, string? adminKey, List<string> report)
    {
        var newPinBytes = Encoding.ASCII.GetBytes(newPin);

        // 0) 提供 SO 口令时优先走「厂商工具路径」：管理员认证(P1=2) → HDJIT_ReloadPin
        if (!string.IsNullOrEmpty(adminKey) && _hdVerifyAdminPin != null && _hdJitReloadPin != null)
        {
            var keyBytes = Encoding.ASCII.GetBytes(adminKey);
            if (_hdVerifyAdminPin(hCard, keyBytes, (uint)keyBytes.Length) == 0)
            {
                var jrc = _hdJitReloadPin(hCard, keyBytes, (uint)keyBytes.Length,
                    newPinBytes, (uint)newPinBytes.Length);
                report.Add($"HDJIT_ReloadPin(SO 口令认证后写入新 PIN 记录) → {jrc}");
                if (jrc == 0) return;
            }
            else
            {
                report.Add("HDJIT_ReloadPin 跳过：SO 口令未通过管理员认证（P1=2）");
            }
        }

        // 1) Reload_Pin（INS 0x5E RESET RETRY COUNTER）
        //    标准语义：数据域 = 「解锁码(PUK) + 新 PIN」；未提供 PUK 时退化为仅新 PIN 再试一次。
        if (_hdReloadPin != null)
        {
            if (!string.IsNullOrEmpty(puk))
            {
                var data = Encoding.ASCII.GetBytes(puk + newPin);
                var rc = _hdReloadPin(hCard, (uint)data.Length, data, IntPtr.Zero);
                report.Add($"Reload_Pin(PUK+新PIN, {data.Length}B) → 0x{rc:X}");
                if (rc == 0) return;
            }

            var rc2 = _hdReloadPin(hCard, (uint)newPinBytes.Length, newPinBytes, IntPtr.Zero);
            report.Add($"Reload_Pin(仅新PIN, {newPinBytes.Length}B) → 0x{rc2:X}");
            if (rc2 == 0) return;
        }

        // 2) HD_ChangePin（数据缓冲区格式：旧PIN + 0xFF + 新PIN）
        //    旧 PIN 取值优先级：调用方明确提供的 adminKey/PUK → 出厂默认 123456。
        if (_hdChangePin != null)
        {
            var oldCandidates = new List<string>();
            if (!string.IsNullOrEmpty(adminKey)) oldCandidates.Add(adminKey);
            if (!string.IsNullOrEmpty(puk) && puk != adminKey) oldCandidates.Add(puk);
            oldCandidates.Add("123456"); // LNCA 出厂默认用户 PIN（多数固件）

            foreach (var oldPin in oldCandidates)
            {
                var buf = BuildChangePinBuffer(oldPin, newPin);
                var rc = _hdChangePin(hCard, buf, (uint)buf.Length);
                report.Add($"HD_ChangePin(旧=\"{Mask(oldPin)}\" + 0xFF + 新) → 0x{rc:X}");
                if (rc == 0) return;
            }
        }

        // 3) 存储层 HSReWriteUserPin（需旧 PIN；仅在调用方提供凭据时才尝试）
        var oldPinForHs = !string.IsNullOrEmpty(adminKey) ? adminKey : puk;
        if (!string.IsNullOrEmpty(oldPinForHs) && _hsReWriteUserPin != null &&
            _hsConnectDev != null && _hsDisconnectDev != null)
        {
            var rc = _hsConnectDev(Math.Max(0, device.Handle), out var hDev);
            if (rc == 0 && hDev != IntPtr.Zero)
            {
                try
                {
                    var rc2 = _hsReWriteUserPin(hDev, oldPinForHs, newPin);
                    report.Add($"HSReWriteUserPin(存储层, 旧=\"{Mask(oldPinForHs)}\") → 0x{rc2:X}");
                }
                finally { try { _hsDisconnectDev(hDev); } catch { } }
            }
            else
            {
                report.Add($"HSReWriteUserPin 跳过：HSConnectDev → 0x{rc:X}");
            }
        }
        else
        {
            report.Add("HSReWriteUserPin 跳过：未提供旧 PIN/PUK（该接口必须先验证旧 PIN）");
        }
    }

    /// <summary>
    /// 完全格式化失败时的逐层诊断：把每一步的真实返回码与状态字(SW)写入报告。
    /// <para>实测语义（2026-09-20 真机 LNCA Key，SN 01102001519176）：
    /// <c>Get_Challenge</c> 成功返回字节数(8) 且 SW=0x9000；<c>External_Authentication</c> 失败时
    /// SW=0x63Cx（x = 剩余重试次数，0 即已锁定）。因此本诊断可判断「密钥不匹配」还是「计数耗尽」。</para>
    /// </summary>
    private void DiagnoseAuthStack(IntPtr hCard, List<string> report)
    {
        if (_hdGetChallenge != null)
        {
            var ch = new byte[16];
            var rc = _hdGetChallenge(hCard, 8, ch, out var sw);
            report.Add($"  · 诊断 Get_Challenge → rc=0x{rc:X} sw=0x{sw:X4} challenge={Convert.ToHexString(ch, 0, 8)}");
        }
        if (_hdSelectFile != null)
        {
            var rc = _hdSelectFile(hCard, 0, 0, 0, 0, out var sw);
            report.Add($"  · 诊断 Select_File → rc=0x{rc:X} sw=0x{sw:X4}");
        }
        if (_hdExternalAuth != null)
        {
            // 全 0 响应必然失配，仅用于读取认证状态字（0x63Cx 的末位 = 剩余重试次数）。
            var rc = _hdExternalAuth(hCard, 0, new byte[8], out var sw);
            report.Add($"  · 诊断 External_Authentication(P1=0, 试探响应) → rc=0x{rc:X} sw=0x{sw:X4}" +
                       "（0x63Cx 末位 = 传输密钥剩余重试次数，0 表示已锁定）");
        }
    }

    /// <summary>把执行报告拼成文本（用于异常消息）。</summary>
    private static string LastResetReportPreview(List<string> report) =>
        string.Join(Environment.NewLine, report);

    /// <summary>构造 HD_ChangePin 的入参缓冲区：旧 PIN + 0xFF + 新 PIN（DLL 内部以 0xFF 分隔）。</summary>
    private static byte[] BuildChangePinBuffer(string oldPin, string newPin)
    {
        var oldBytes = Encoding.ASCII.GetBytes(oldPin);
        var newBytes = Encoding.ASCII.GetBytes(newPin);
        var buf = new byte[oldBytes.Length + 1 + newBytes.Length];
        Array.Copy(oldBytes, 0, buf, 0, oldBytes.Length);
        buf[oldBytes.Length] = 0xFF;
        Array.Copy(newBytes, 0, buf, oldBytes.Length + 1, newBytes.Length);
        return buf;
    }

    /// <summary>把 HD_VerifyPin 的返回码翻译为可读结论（0=通过，正数=剩余重试次数，-1=锁定/被拒）。</summary>
    private static string DescribeVerify(int rc) => rc switch
    {
        0 => "通过（PIN 已生效）",
        -1 => "被拒（PIN 错误计数已耗尽或已被锁定）",
        _ => $"不匹配（剩余重试 {rc} 次）"
    };

    /// <summary>日志脱敏：仅保留长度信息，避免明文口令落盘。</summary>
    private static string Mask(string secret) => new string('*', Math.Max(1, secret.Length));

    /// <summary>把 DLL 回填的定长 ANSI 缓冲区转为字符串（截断首个 0）。</summary>
    private static string ToAscii(byte[] buf)
    {
        var end = Array.IndexOf(buf, (byte)0);
        if (end < 0) end = buf.Length;
        return Encoding.ASCII.GetString(buf, 0, end).Trim();
    }

    public void Dispose()
    {
        DisconnectCore();
        _jit?.Dispose();
        _jit = null;
        _hardApi?.Dispose();
        _hardApi = null;
        _hdcos?.Dispose();
        _hdcos = null;
    }
}
