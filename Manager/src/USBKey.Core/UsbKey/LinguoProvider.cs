using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Configuration;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 凌国（Linguo / 张家口银行 ZJKCCB）USB Key 驱动对接实现。
/// <para>
/// 对接方式：<b>不依赖厂商 DLL</b>，而是复刻官方管理工具 <c>ZJK_LgKit.exe</c> 的
/// 「SCSI 直通 + ISO7816 APDU」通信链路（见 <see cref="LinguoNative"/>）。
/// 之所以不能像 LNCA/恒宝那样直接调用厂商 DLL：凌国的公开 DLL 只有
/// <c>LgCsp.dll</c>/<c>LgImpl.dll</c>（标准 Windows CSP，仅导出 25 个 <c>CP*</c>
/// 函数），其 <c>CPSetProvParam</c> 只接受 <c>PP_KEYEXCHANGE_PIN(0x20)</c> 与
/// <c>PP_SIGNATURE_PIN(0x21)</c>（反汇编 0x10012360 确认），<b>既无
/// <c>PP_CHANGE_PASSWORD</c> 也无任何「重置/清空」入口</b>；<c>LgZjkUKeyCtrl.ocx</c>
/// 仅暴露设备枚举方法（<c>GetLinguoKeyCount(W/WWW)</c>、<c>GetLinguoKeyId(W)</c>）。
/// 因此「重置 + 清空 + 重设密码」只能走底层 APDU。
/// </para>
/// <para>
/// ⚠️ 本实现基于 2026-09 的静态逆向（无实机）。所有 APDU 参数均已在代码中
/// 标注逆向证据；标 <c>【待实机校准】</c> 的部分需在真实设备上验证后才能启用。
/// </para>
/// </summary>
public sealed class LinguoProvider : IKeyProvider
{
    // ========================= 协议常量（逆向自 ZJK_LgKit.exe）=========================

    private const byte ClaPin = 0x80;   // PIN / 管理指令类
    private const byte ClaFile = 0x84;  // 文件 / 证书指令类

    private const byte InsVerify = 0x20;      // 校验 PIN（ISO7816 VERIFY）
    private const byte InsChangePin = 0x24;   // 修改 PIN（ISO7816 CHANGE REFERENCE DATA）
    private const byte InsUnblock = 0x2C;     // 解锁 / 重置重试计数（ISO7816 RESET RETRY COUNTER）
    private const byte InsReadBinary = 0xB0;  // 读二进制（读证书 / 公钥）
    private const byte InsWriteBinary = 0xD0; // 写二进制
    private const byte InsCreateFile = 0xE0;  // 创建文件
    private const byte InsAppendRecord = 0xE2;// 追加记录（写证书）
    private const byte InsGetInfo = 0xAA;     // 私有：设备/容器信息
    private const byte InsKeyOp = 0xE7;       // 私有：密钥运算（生成 / 签名）

    /// <summary>P2：用户 PIN。</summary>
    private const byte PinRefUser = 0x81;
    /// <summary>P2：管理（SO）PIN。</summary>
    private const byte PinRefAdmin = 0x80;

    /// <summary>Linguo PIN 在 APDU 中的定长（逆向：改 PIN 的 Lc = 0x10 = 旧8 + 新8）。</summary>
    private const int PinLength = 8;

    /// <summary>SW1SW2 = 0x9000 表示成功（逆向 0x40557D 处校验该值）。</summary>
    private const ushort SwOk = 0x9000;

    private const int CertBufferSize = 16384;

    public string PlatformName => "linguo";

    private string _libraryRoot = "";
    private readonly List<LinguoNative.DeviceHandle> _opened = new();
    private LinguoNative.DeviceHandle? _session;
    private int _sessionIndex = -1;
    private readonly object _sync = new();
    private readonly List<(int Vid, int Pid)> _whitelist = new();

    public LinguoProvider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
    {
        _libraryRoot = libraryRoot;
        if (whitelist != null)
            foreach (var d in whitelist)
                if (d.VidInt > 0 || d.PidInt > 0)
                    _whitelist.Add((d.VidInt, d.PidInt));
    }

    /// <summary>本平台纯 P/Invoke 实现，永远可用（真正可用与否取决于设备是否插入）。</summary>
    public bool IsAvailable => true;

    /// <summary>
    /// 凌国 Key 具备 PUK/管理 PIN 概念（ISO7816 <c>80 2C</c> / <c>80 24</c>），
    /// 因此重置不强制要求「当前用户 PIN」——凭据优先级为 currentPin → puk → adminKey。
    /// </summary>
    public bool ResetRequiresCurrentPin => false;

    public void Initialize()
    {
        // 无 DLL 需要加载；此处做一次探测，便于日志定位问题。
        try
        {
            var paths = LinguoNative.EnumerateDevicePaths();
            Console.WriteLine($"[Linguo] 设备接口枚举到 {paths.Count} 个候选（GUID {LinguoNative.DeviceInterfaceGuid}）");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Linguo] 初始化探测失败：{ex.Message}");
        }
    }

    // ========================= 设备枚举 / 打开 =========================

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var result = new List<UsbKeyDevice>();
        List<string> paths;
        try { paths = LinguoNative.EnumerateDevicePaths(); }
        catch (Exception ex)
        {
            USBKey.Core.Common.Log.Error(ex, "Linguo 枚举设备接口失败");
            return result;
        }

        int index = 0;
        foreach (var path in paths)
        {
            LinguoNative.DeviceHandle? dev = null;
            try
            {
                dev = LinguoNative.Open(path);
                if (!LinguoNative.Probe(dev, out var vendorProduct))
                    continue; // 不是凌国 Key（同接口下可能有其它 CD-ROM 设备）

                result.Add(new UsbKeyDevice
                {
                    Platform = PlatformName,
                    VendorName = "Linguo",
                    Model = string.IsNullOrWhiteSpace(vendorProduct) ? "Linguo USB Key" : vendorProduct,
                    SerialNumber = dev.SerialNumber,
                    Handle = index,
                    Notes = path,
                });
                index++;
            }
            catch (Exception ex)
            {
                USBKey.Core.Common.Log.Write($"Linguo 探测设备 {path} 失败：{ex.Message}");
            }
            finally
            {
                dev?.Dispose();
            }
        }
        return result;
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        var devs = Enumerate();
        if (devs.Count == 0) throw new InvalidOperationException("未检测到凌国（Linguo）USB Key 设备");
        if (handleOrSerial >= 0 && handleOrSerial < devs.Count) return devs[handleOrSerial];
        return devs[0];
    }

    /// <summary>建立与指定设备的会话（打开物理句柄）。</summary>
    private void EnsureConnected(UsbKeyDevice device)
    {
        lock (_sync)
        {
            if (_session != null && _sessionIndex == device.Handle) return;
            CloseSessionLocked();

            var paths = LinguoNative.EnumerateDevicePaths();
            var candidates = new List<(string Path, LinguoNative.DeviceHandle Dev)>();
            foreach (var p in paths)
            {
                try
                {
                    var h = LinguoNative.Open(p);
                    if (LinguoNative.Probe(h, out _)) candidates.Add((p, h));
                    else h.Dispose();
                }
                catch { /* 忽略单个设备失败 */ }
            }

            if (candidates.Count == 0)
                throw new InvalidOperationException("未检测到凌国（Linguo）USB Key 设备");

            int idx = device.Handle >= 0 && device.Handle < candidates.Count ? device.Handle : 0;
            _session = candidates[idx].Dev;
            _sessionIndex = idx;
            // 释放其余句柄
            for (int i = 0; i < candidates.Count; i++)
                if (i != idx) candidates[i].Dev.Dispose();
        }
    }

    private void CloseSessionLocked()
    {
        if (_session != null)
        {
            try { _session.Dispose(); } catch { }
            _session = null;
            _sessionIndex = -1;
        }
    }

    private void CloseSession()
    {
        lock (_sync) CloseSessionLocked();
    }

    // ========================= 会话 / 认证 =========================

    public void Login(UsbKeyDevice device, string pin)
    {
        EnsureConnected(device);
        var rc = VerifyPin(PinRefUser, pin);
        if (rc != SwOk) throw new InvalidOperationException($"PIN 校验失败（SW={rc:X4}）");
        device.IsLoggedIn = true;
    }

    public void Logout(UsbKeyDevice device)
    {
        CloseSession();
        device.IsLoggedIn = false;
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        try
        {
            EnsureConnected(device);
            if (_session != null)
            {
                var resp = _session.Inquiry();
                if (resp.Length >= 32)
                {
                    device.Model = Encoding.ASCII.GetString(resp, 16, 16).TrimEnd();
                    device.FirmwareVersion = Encoding.ASCII.GetString(resp, 32, Math.Min(4, resp.Length - 32)).Trim();
                }
            }
        }
        catch (Exception ex)
        {
            USBKey.Core.Common.Log.Write($"Linguo 获取设备详情失败：{ex.Message}");
        }
        return device;
    }

    // ========================= 证书 / 容器 =========================

    /// <summary>
    /// 读取设备内的证书。
    /// <para>
    /// 【待实机校准】凌国把证书作为卡片文件系统上的记录保存（逆向可见 <c>84 E2</c>
    /// 追加记录、<c>84 B0</c> 读二进制），但文件 ID 的取值需要在真机上确认。
    /// 当前实现按「按顺序读取文件 0..N，凡是能被解析为 X.509 的即视为证书」的策略，
    /// 不做任何猜测性写入，读不到就返回空列表并记录日志。
    /// </para>
    /// </summary>
    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        EnsureConnected(device);
        var list = new List<KeyContainer>();
        // 以常见的证书文件槽位尝试读取
        foreach (byte fileId in new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08 })
        {
            var der = TryReadBinary(fileId);
            if (der == null || der.Length < 64) continue;
            try
            {
                var c = BuildContainer(der);
                c.ContainerName = $"file-{fileId:X2}";
                c.ContainerUuid = $"{fileId:X2}";
                list.Add(c);
            }
            catch
            {
                // 不是证书，跳过
            }
        }
        return list;
    }

    private static KeyContainer BuildContainer(byte[] certDer)
    {
        using var cert = new X509Certificate2(certDer);
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        return new KeyContainer
        {
            Name = cn,
            ContainerName = cn,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = cert.PublicKey.Oid.FriendlyName + "/" + cert.SignatureAlgorithm.FriendlyName,
            CertRaw = certDer,
        };
    }

    private byte[]? TryReadBinary(byte fileId)
    {
        try
        {
            var apdu = new byte[] { ClaFile, InsReadBinary, 0x00, fileId, 0x00 };
            var resp = Send(apdu);
            return resp.Length > 0 ? resp : null;
        }
        catch
        {
            return null;
        }
    }

    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        EnsureConnected(device);

        using var cert = new X509Certificate2(
            pfxPath, string.IsNullOrEmpty(pfxPassword) ? null : pfxPassword,
            X509KeyStorageFlags.Exportable);

        var der = cert.Export(X509ContentType.Cert);

        // 写入证书（追加记录）。逆向证据：84 E2 为写记录指令（0x405B0D/0x405CF0 出现 84 E2）。
        var apdu = new byte[5 + der.Length];
        apdu[0] = ClaFile; apdu[1] = InsAppendRecord; apdu[2] = 0x00; apdu[3] = 0x00;
        apdu[4] = (byte)Math.Min(der.Length, 255);
        Array.Copy(der, 0, apdu, 5, apdu[4]);
        var sw = SendSw(apdu);
        if (sw != SwOk)
            throw new InvalidOperationException(
                $"写入证书失败（SW={sw:X4}）。凌国证书写入的文件 ID / P1P2 语义【待实机校准】，" +
                $"请先用 ReadRawApdu/SendRawApdu 在真机上确认。");

        if (cert.HasPrivateKey)
            USBKey.Core.Common.Log.Write(
                "Linguo 私钥导入尚未对接：凌国私钥需以设备公钥加密后经私有指令（0xE7 系列）写入，" +
                "协议待实机确认，本次仅导入证书。");
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        var der = container.CertRaw ?? throw new InvalidOperationException("证书数据不可用");
        File.WriteAllBytes(outputPath, der);
    }

    public void ViewCertificate(KeyContainer container)
    {
        var der = container.CertRaw ?? throw new InvalidOperationException("证书数据不可用");
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(tmp, der);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmp) { UseShellExecute = true });
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        EnsureConnected(device);

        // 只删除能定位到明确文件槽位的证书，避免误删。
        if (!byte.TryParse(container.ContainerUuid, System.Globalization.NumberStyles.HexNumber, null, out var fileId))
            throw new NotSupportedException(
                "该容器缺少可定位的文件槽位（fileId），为安全起见不执行删除。" +
                "凌国的删除证书指令（私有 INS）需实机确认后再开放。");

        // 【待实机校准】凌国的删除记录指令未在静态逆向中确认，这里先用「写零长度」的方式试探性清除，
        // 失败则明确报错，绝不静默成功。
        var apdu = new byte[] { ClaFile, InsWriteBinary, 0x00, fileId, 0x00 };
        var sw = SendSw(apdu);
        if (sw != SwOk)
            throw new InvalidOperationException($"删除证书失败（SW={sw:X4}），删除指令语义【待实机校准】");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        USBKey.Core.Crypto.CertHelper.Register(container.CertRaw, container.Name, container.KeyBinding);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            USBKey.Core.Crypto.CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    // ========================= PIN / 解锁 / 重置 =========================

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        EnsureConnected(device);
        var data = new byte[PinLength * 2];
        FillPin(oldPin, data, 0);
        FillPin(newPin, data, PinLength);

        // 逆向确认（0x405FF0）：CLA=0x80，INS=0x24，数据长度 clamp 到 0x10（= 旧8+新8）
        var apdu = new byte[5 + data.Length];
        apdu[0] = ClaPin; apdu[1] = InsChangePin; apdu[2] = 0x00; apdu[3] = PinRefUser;
        apdu[4] = (byte)data.Length;
        Array.Copy(data, 0, apdu, 5, data.Length);

        var sw = SendSw(apdu);
        if (sw != SwOk) throw new InvalidOperationException($"修改密码失败（SW={sw:X4}）");
    }

    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        EnsureConnected(device);
        switch (method)
        {
            case UnlockMethod.Puk:
            {
                // ISO7816 RESET RETRY COUNTER：P1=0x00，P2=0x81，Lc=0x10（PUK 8 + 新 PIN 8）
                var data = new byte[PinLength * 2];
                FillPin(credential, data, 0);
                FillPin(newPin, data, PinLength);
                var apdu = new byte[5 + data.Length];
                apdu[0] = ClaPin; apdu[1] = InsUnblock; apdu[2] = 0x00; apdu[3] = PinRefUser;
                apdu[4] = (byte)data.Length;
                Array.Copy(data, 0, apdu, 5, data.Length);
                var sw = SendSw(apdu);
                if (sw != SwOk) throw new InvalidOperationException($"PUK 解锁失败（SW={sw:X4}）");
                break;
            }
            case UnlockMethod.AdminKey:
            {
                var sw = VerifyPin(PinRefAdmin, credential);
                if (sw != SwOk) throw new InvalidOperationException($"管理员 PIN 校验失败（SW={sw:X4}）");
                break;
            }
            default:
                throw new NotSupportedException("凌国平台暂不支持挑战码解锁");
        }
        device.IsLoggedIn = true;
    }

    public string GenerateChallenge(UsbKeyDevice device)
    {
        EnsureConnected(device);
        // 逆向：0x406B9C 处 80 AA .. 10（取随机数/挑战码）
        var apdu = new byte[] { ClaPin, InsGetInfo, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00 };
        var resp = Send(apdu);
        if (resp.Length < 16)
            throw new InvalidOperationException("生成挑战码失败（设备未返回 16 字节数据）");
        return Convert.ToHexString(resp.AsSpan(0, 16));
    }

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
        => throw new NotSupportedException("凌国平台暂不支持挑战码解锁");

    /// <summary>
    /// 重置 / 初始化设备：清空内容并重设密码。
    /// <para>
    /// 逆向依据（<c>ZJK_LgKit.exe</c> 的「初始化 USB-Key」功能，函数 0x4090F0 → 回调 0x401000）：
    /// 官方初始化是一段**多命令序列**：创建/选择文件 → 写入密钥文件槽（3/5）→
    /// 分别设置签名 PIN 与加密 PIN（<c>0x405C60</c>）→ 私有指令 <c>0x6001</c> 取容器信息 →
    /// 写用户数据 → 私有指令 <c>0x6002</c> → 再写数据。
    /// 其中「设置 PIN」与「文件写入」的 P1/P2 需要真机才能逐字节确认。
    /// </para>
    /// <para>
    /// 因此本方法按<b>可靠性分级</b>执行，绝不假装成功：
    /// <list type="number">
    /// <item>若调用方给出<b>当前 PIN 或 PUK</b>：走标准 APDU（<c>80 24</c> 改 PIN / <c>80 2C</c> PUK 解锁），
    /// 这是逆向已确认的可靠路径，可稳定完成「重设密码」；</item>
    /// <item>随后逐个尝试清除已知证书文件槽，清除失败的槽位会被如实记录并在结果中抛出，
    /// 不会静默忽略；</item>
    /// <item>若既无当前 PIN 也无 PUK，则公开接口不存在「无需认证的重置」入口
    /// （官方工具的完整初始化依赖厂商传输密钥），此时抛出明确异常而非返回假成功。</item>
    /// </list>
    /// </para>
    /// </summary>
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        EnsureConnected(device);
        if (_session == null) throw new InvalidOperationException("设备会话不可用");

        if (string.IsNullOrEmpty(newPin) || newPin.Length < 6)
            throw new ArgumentException("新密码至少 6 位", nameof(newPin));

        // 步骤 1：重设用户 PIN（凭据优先级：当前 PIN → PUK → 管理员 PIN）
        bool pinReset = false;
        if (!string.IsNullOrEmpty(currentPin))
        {
            // 已知当前 PIN：标准 CHANGE REFERENCE DATA（80 24 00 81 10 <旧8><新8>）
            ChangePin(device, currentPin, newPin);
            pinReset = true;
            USBKey.Core.Common.Log.Write("[Linguo] 已用当前 PIN 重设用户 PIN");
        }
        else if (!string.IsNullOrEmpty(puk))
        {
            Unlock(device, UnlockMethod.Puk, puk, newPin);
            pinReset = true;
            USBKey.Core.Common.Log.Write("[Linguo] 已通过 PUK 重置用户 PIN");
        }
        else if (!string.IsNullOrEmpty(adminKey))
        {
            // 管理员 PIN → 直接改用户 PIN（旧 PIN 由管理会话提供时的标准做法）
            ChangePin(device, adminKey, newPin);
            pinReset = true;
            USBKey.Core.Common.Log.Write("[Linguo] 已通过管理员 PIN 重置用户 PIN");
        }
        else
        {
            throw new InvalidOperationException(
                "凌国 USB Key 的重置必须提供凭据（当前 PIN / PUK / 管理员 PIN）：" +
                "公开接口不提供「免认证重置」（官方工具的完整初始化依赖厂商传输密钥，" +
                "静态逆向已确认其第一步即为私有指令链路，无法在无授权情况下复刻）。");
        }

        if (!pinReset)
            throw new InvalidOperationException("重置设备失败：密码未成功重设");

        // 步骤 2：清空证书/文件内容（尽力而为，逐项如实反馈）
        var failures = new List<string>();
        foreach (byte fileId in new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08 })
        {
            try
            {
                var apdu = new byte[] { ClaFile, InsWriteBinary, 0x00, fileId, 0x00 };
                var sw = SendSw(apdu);
                if (sw != SwOk) failures.Add($"file-{fileId:X2}(SW={sw:X4})");
            }
            catch (Exception ex)
            {
                failures.Add($"file-{fileId:X2}({ex.Message})");
            }
        }

        if (failures.Count > 0)
        {
            USBKey.Core.Common.Log.Write(
                "[Linguo] 重置后清空内容存在未完成项：" + string.Join("、", failures) +
                "。【待实机校准】凌国的「删除记录」私有指令未在静态逆向中确认，当前用写零长度试探，失败项未做静默处理。");
            throw new InvalidOperationException(
                "密码已重设，但内容清空未全部完成：" + string.Join("、", failures) +
                "。请在真机上校准凌国的删除指令后重试。");
        }

        device.IsLoggedIn = true;
        USBKey.Core.Common.Log.Write("[Linguo] 设备重置完成（密码已重设，证书槽位已清空）");
    }

    // ========================= 底层 APDU 助手 =========================

    /// <summary>发送 APDU，返回响应数据（校验 SW=0x9000，失败抛异常）。</summary>
    private byte[] Send(byte[] apdu)
    {
        var sw = SendSw(apdu, out var data);
        if (sw != SwOk) throw new InvalidOperationException($"APDU 执行失败（SW={sw:X4}）");
        return data;
    }

    /// <summary>发送 APDU，返回 SW1SW2。</summary>
    private ushort SendSw(byte[] apdu) => SendSw(apdu, out _);

    private ushort SendSw(byte[] apdu, out byte[] data)
    {
        lock (_sync)
        {
            if (_session == null) { data = Array.Empty<byte>(); return 0; }
            data = _session.Transceive(apdu, TransferMode, out ushort sw);
            return sw;
        }
    }

    /// <summary>
    /// APDU 传输模式。默认 <see cref="LinguoNative.TransferMode.SendThenRead"/>
    /// （与官方工具 DataIn=0 的发送行为一致）。若实机表现为「一次调用即需回读响应」，
    /// 改为 <see cref="LinguoNative.TransferMode.SingleShot"/>。
    /// </summary>
    internal LinguoNative.TransferMode TransferMode { get; set; } = LinguoNative.TransferMode.SendThenRead;

    private ushort VerifyPin(byte pinRef, string pin)
    {
        var data = new byte[PinLength];
        FillPin(pin, data, 0);
        var apdu = new byte[5 + PinLength];
        apdu[0] = ClaPin; apdu[1] = InsVerify; apdu[2] = 0x00; apdu[3] = pinRef;
        apdu[4] = PinLength;
        Array.Copy(data, 0, apdu, 5, PinLength);
        return SendSw(apdu);
    }

    /// <summary>把 PIN 写入定长缓冲（不足右补 0x00，超长截断）。</summary>
    private static void FillPin(string pin, byte[] dst, int offset)
    {
        var bytes = Encoding.ASCII.GetBytes(pin ?? "");
        int n = Math.Min(bytes.Length, PinLength);
        Array.Clear(dst, offset, PinLength);
        Array.Copy(bytes, 0, dst, offset, n);
    }

    /// <summary>
    /// 发送原始 APDU（调试/实机校准入用）。返回 (SW, 响应数据)。
    /// 用法示例（PowerShell / 控制台）：<c>provider.SendRawApdu("8020008108313233343536")</c>
    /// </summary>
    public (ushort Sw, byte[] Data) SendRawApdu(string hexApdu)
    {
        var apdu = Convert.FromHexString(hexApdu.Replace(" ", "").Replace("-", ""));
        var sw = SendSw(apdu, out var data);
        return (sw, data);
    }

    /// <summary>打开设备并建立会话（供实机校准脚本直接使用）。</summary>
    public void ConnectForDebug(int index = 0)
    {
        var dev = new UsbKeyDevice { Platform = PlatformName, Handle = index };
        EnsureConnected(dev);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            CloseSessionLocked();
            foreach (var h in _opened)
            {
                try { h.Dispose(); } catch { }
            }
            _opened.Clear();
        }
    }
}
