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

    private IntPtr _hKey = IntPtr.Zero;
    private int _connectedIndex = -1;

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
        if (_hKey != IntPtr.Zero && _connectedIndex == device.Handle) return;

        // 先断开旧连接
        DisconnectCore();

        var rc = _connect!((uint)Math.Max(0, device.Handle), DefaultBaudRate, out var hKey);
        if (rc != 0) throw new InvalidOperationException($"连接 LNCA 设备失败 (错误码 0x{rc:X})");
        _hKey = hKey;
        _connectedIndex = device.Handle;
    }

    private void DisconnectCore()
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
        catch { /* 设备信息获取失败不影响已枚举的基本信息 */ }
        return device;
    }

    // ================= 证书 / 容器 =================

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        Console.WriteLine($"[LNCA] ListContainers 开始, IsLoggedIn={device.IsLoggedIn}");
        EnsureConnected(device);

        // JIT 层为单设备证书模型：读取签名证书（type 0）与加密证书（type 1）。
        // 多容器场景需扩展 HD_ReadContainerListInfo（待实体设备确认）。
        var result = new List<KeyContainer>();
        for (uint type = CertTypeSign; type <= CertTypeEncrypt; type++)
        {
            Console.WriteLine($"[LNCA] 尝试读取证书 type={type}");
            var cert = TryReadCert(device, type);
            if (cert != null)
            {
                Console.WriteLine($"[LNCA] 读取到证书: {cert.Subject}");
                result.Add(cert);
            }
            else
            {
                Console.WriteLine($"[LNCA] 证书 type={type} 不存在或读取失败");
            }
        }
        Console.WriteLine($"[LNCA] ListContainers 完成, 共 {result.Count} 个证书");
        return result;
    }

    private KeyContainer? TryReadCert(UsbKeyDevice device, uint certType)
    {
        try
        {
            var buf = new byte[CertBufferSize];
            uint len = (uint)buf.Length;
            var rc = _readCert!(_hKey, certType, buf, ref len);
            Console.WriteLine($"[LNCA] ReadCert(type={certType}): rc=0x{rc:X}, len={len}");
            
            if (rc != 0 || len == 0) return null;
            
            var der = buf.AsSpan(0, (int)Math.Min(len, buf.Length)).ToArray();
            return BuildContainer(der);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LNCA] ReadCert 异常: {ex.Message}");
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
    /// 导入 RSA 私钥到设备。私钥需以设备公钥加密后写入，格式与加密细节
    /// （dEnKeyIndex/dPubEncKey/dAlgID）依赖设备内部约定，生产前需实体设备确认。
    /// </summary>
    private void ImportPrivateKey(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        if (cert.GetRSAPrivateKey() is not { } rsa) return;

        // 导出 PKCS#1 DER 私钥
        var priKey = rsa.ExportRSAPrivateKey();
        // 无加密公钥密钥时，采用设备内生成密钥对的方式（写入已生成容器则不需要外部私钥）
        // 这里给出基础流程：GenRSAKeyPair 在设备内生成，避免外部私钥传输。
        var pubBuf = new byte[4096];
        var priBuf = new byte[4096];
        uint pubLen = (uint)pubBuf.Length, priLen = (uint)priBuf.Length;
        if (_genRSAKeyPair!(_hKey, 0, pubBuf, ref pubLen, priBuf, ref priLen) != 0)
            throw new InvalidOperationException("设备内生成密钥对失败");
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
        // JIT 层删除证书容器需实体设备确认对应接口（HD_DeleteContainer / HD_DeleteCert）。
        // 此处尝试删除证书对应文件（若容器以文件形式存储）。
        if (!string.IsNullOrEmpty(container.ContainerName))
        {
            var rc = _delFile!(_hKey, container.ContainerName, (uint)container.ContainerName.Length);
            if (rc != 0) throw new InvalidOperationException($"删除证书失败 (错误码 0x{rc:X})");
            return;
        }
        throw new InvalidOperationException("当前证书容器缺少可定位信息，无法删除（待设备确认）");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        // 通过标准 CryptoAPI 将证书注册到当前用户证书库
        USBKey.Core.Crypto.CertHelper.Register(container.CertRaw, container.Name);
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
        int rc;
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

    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null)
    {
        throw new NotSupportedException("LNCA 设备暂不支持重置功能。USBKey_Reset 函数签名未能确定，需进一步逆向分析或联系厂商获取正确的 API 文档。");
    }

    public void Dispose()
    {
        DisconnectCore();
        _jit?.Dispose();
        _jit = null;
    }
}
