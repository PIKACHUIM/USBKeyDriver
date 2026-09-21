using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Crypto;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 恒宝（HengBao）民生银行 U 宝驱动对接实现。
///
/// <para><b>逆向结论（2026-09-20，IDA Pro 8.3 静态分析 + 官方工具对照）</b></para>
/// <list type="bullet">
/// <item>对接目标 <c>CMBCp.dll</c>（32 位）是 UranuSafe 5.0 的标准 PKCS#11 实现
/// （源码路径 <c>Src\Pkcs11\Windows\pkcs11</c>：uZJPKCS11.cpp / implglue.cpp / token_comm.cpp）。</item>
/// <item>全部 68 个 <c>C_*</c> 导出均为 <c>__cdecl</c>（函数尾为裸 <c>retn</c>）。</item>
/// <item><c>C_InitToken</c> / <c>C_InitPIN</c> / <c>C_GetObjectSize</c> / <c>C_CopyObject</c> /
/// <c>C_GetFunctionStatus</c> 均为 <c>mov eax,54h; retn</c> 的桩函数，恒返回
/// CKR_FUNCTION_NOT_SUPPORTED —— <b>本设备不能通过 PKCS#11 做令牌初始化</b>。</item>
/// <item><c>C_Login</c> 只接受 <c>CKU_USER</c>（其它 userType 直接返回 CKR_USER_TYPE_INVALID），
/// 即<b>没有 SO PIN / PUK 概念</b>。</item>
/// <item><c>C_GetSlotList</c> 返回的槽位是「设备路径字符串指针」（不透明句柄），必须原样回传；
/// <c>C_GetSlotInfo</c> 返回硬编码信息；<c>C_GetTokenInfo</c> 才会真正打开设备（失败返回
/// CKR_FUNCTION_FAILED），因此枚举时必须用 C_GetTokenInfo 过滤真实在线设备。</item>
/// <item>厂商把 <c>CK_TOKEN_INFO.ulSessionCount</c>（偏移 104）复用为「PIN 剩余尝试次数」。</item>
/// <item>硬件出厂口令为 <c>111111</c>（6 位；逆向自官方工具资源串 ID=1094
/// “U宝硬件初始口令为"111111"”）；口令长度 6–15 位。</item>
/// <item>真正的「初始化 U 宝」（清空并恢复出厂态）只存在于厂商层
/// （官方工具 CMBCu.exe 的 UserTool/Device 模块与 CSP CMBCC.dll），走自研 HID / SCSI-BOT /
/// ISO7816 APDU 链路，且需要 U 宝按键确认，未导出任何可调用的 API。</item>
/// </list>
///
/// <para><b>因此本 Provider 的重置语义</b>：用当前 PIN 登录 →
/// 删除设备上全部 PKCS#11 对象（证书 / 私钥 / 公钥 / 数据，即「清空内容」）→
/// 用 <c>C_SetPIN</c> 把口令重设为新口令。</para>
/// </summary>
public sealed class HengBaoProvider : IKeyProvider
{
    /// <summary>厂商硬件出厂口令（官方工具资源串 ID=1094）。</summary>
    public const string DefaultFactoryPin = "111111";

    private const int MaxCertSize = 32768;
    private const int EnumCacheMs = 1200;   // 枚举结果缓存，避免 UI 刷新时反复走 HID 枚举

    public string PlatformName => "hengbao";

    /// <summary>恒宝 U 宝无 SO PIN/PUK，重置必须先用当前口令登录才能清空并改密。</summary>
    public bool ResetRequiresCurrentPin => true;

    /// <summary>最近一次重置/清空的摘要（供界面与日志展示）。</summary>
    public string LastResetSummary { get; private set; } = "";

    /// <summary>
    /// 最近一次枚举的诊断信息（用于界面提示「枚举到设备但打不开」这类驱动/模式问题）。
    /// 典型场景：U 宝只以 CD-ROM/U 盘形态出现、未安装厂商 HID 驱动时，
    /// C_GetSlotList 能返回槽位（设备接口路径），但 C_GetTokenInfo 返回
    /// CKR_FUNCTION_FAILED(6)，此时界面会展示本提示而不是「未检测到设备」。
    /// </summary>
    public string LastEnumerationDiagnostic { get; private set; } = "";

    /// <summary>上次已写入日志的诊断内容（用于抑制枚举期重复打印）。</summary>
    private string _lastDiagLogged = "";

    private string _libraryRoot;
    private NativeDll.Module? _dll;

    // ---- PKCS#11 导出 ----
    private CkmNative.C_InitializeFn? _initialize;
    private CkmNative.C_FinalizeFn? _finalize;
    private CkmNative.C_GetInfoFn? _getInfo;
    private CkmNative.C_GetSlotListFn? _getSlotList;
    private CkmNative.C_GetSlotInfoFn? _getSlotInfo;
    private CkmNative.C_GetTokenInfoFn? _getTokenInfo;
    private CkmNative.C_OpenSessionFn? _openSession;
    private CkmNative.C_CloseSessionFn? _closeSession;
    private CkmNative.C_LoginFn? _login;
    private CkmNative.C_LogoutFn? _logout;
    private CkmNative.C_SetPINFn? _setPin;
    private CkmNative.C_InitPINFn? _initPin;
    private CkmNative.C_InitTokenFn? _initToken;
    private CkmNative.C_GetAttributeValueFn? _getAttr;
    private CkmNative.C_SetAttributeValueFn? _setAttr;
    private CkmNative.C_FindObjectsInitFn? _findInit;
    private CkmNative.C_FindObjectsFn? _find;
    private CkmNative.C_FindObjectsFinalFn? _findFinal;
    private CkmNative.C_CreateObjectFn? _createObject;
    private CkmNative.C_DestroyObjectFn? _destroyObject;
    private CkmNative.C_SignInitFn? _signInit;
    private CkmNative.C_SignFn? _sign;

    // ---- 槽位与会话 ----
    private readonly List<uint> _slots = new();         // 不透明槽位句柄（32 位设备名字符串指针）
    private readonly List<string> _slotNames = new();   // 槽位对应的设备路径（仅用于展示/解析 VID-PID）
    private readonly List<bool> _slotReady = new();     // 对应槽位是否能被 C_GetTokenInfo 打开（未就绪也会列出，仅用于界面提示）
    private DateTime _enumAt = DateTime.MinValue;
    private readonly Dictionary<int, (uint Slot, uint Session)> _sessions = new();

    private readonly List<(int Vid, int Pid)> _whitelist = new();

    public HengBaoProvider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
    {
        _libraryRoot = libraryRoot;
        if (whitelist != null)
            foreach (var d in whitelist)
                if (d.VidInt > 0 || d.PidInt > 0)
                    _whitelist.Add((d.VidInt, d.PidInt));
    }

    // ================= 加载 / 初始化 =================

    public bool IsAvailable
    {
        get
        {
            if (_dll != null) return true;
            return File.Exists(Path.Combine(FindLibraryRoot(_libraryRoot), "CMBCp.dll"));
        }
    }

    public void Initialize()
    {
        if (_dll != null) return;
        _libraryRoot = FindLibraryRoot(_libraryRoot);
        var dllPath = Path.Combine(_libraryRoot, "CMBCp.dll");
        _dll = NativeDll.Load(dllPath);
        if (_dll == null)
            throw new InvalidOperationException(
                "无法加载 CMBCp.dll（请确认 Library/HengBao 目录存在，且宿主为 32 位进程）");

        _initialize = _dll.GetDelegate<CkmNative.C_InitializeFn>("C_Initialize");
        _finalize = _dll.GetDelegate<CkmNative.C_FinalizeFn>("C_Finalize");
        _getInfo = _dll.GetDelegate<CkmNative.C_GetInfoFn>("C_GetInfo");
        _getSlotList = _dll.GetDelegate<CkmNative.C_GetSlotListFn>("C_GetSlotList");
        _getSlotInfo = _dll.GetDelegate<CkmNative.C_GetSlotInfoFn>("C_GetSlotInfo");
        _getTokenInfo = _dll.GetDelegate<CkmNative.C_GetTokenInfoFn>("C_GetTokenInfo");
        _openSession = _dll.GetDelegate<CkmNative.C_OpenSessionFn>("C_OpenSession");
        _closeSession = _dll.GetDelegate<CkmNative.C_CloseSessionFn>("C_CloseSession");
        _login = _dll.GetDelegate<CkmNative.C_LoginFn>("C_Login");
        _logout = _dll.GetDelegate<CkmNative.C_LogoutFn>("C_Logout");
        _setPin = _dll.GetDelegate<CkmNative.C_SetPINFn>("C_SetPIN");
        _initPin = _dll.GetDelegate<CkmNative.C_InitPINFn>("C_InitPIN");
        _initToken = _dll.GetDelegate<CkmNative.C_InitTokenFn>("C_InitToken");
        _getAttr = _dll.GetDelegate<CkmNative.C_GetAttributeValueFn>("C_GetAttributeValue");
        _setAttr = _dll.GetDelegate<CkmNative.C_SetAttributeValueFn>("C_SetAttributeValue");
        _findInit = _dll.GetDelegate<CkmNative.C_FindObjectsInitFn>("C_FindObjectsInit");
        _find = _dll.GetDelegate<CkmNative.C_FindObjectsFn>("C_FindObjects");
        _findFinal = _dll.GetDelegate<CkmNative.C_FindObjectsFinalFn>("C_FindObjectsFinal");
        _createObject = _dll.GetDelegate<CkmNative.C_CreateObjectFn>("C_CreateObject");
        _destroyObject = _dll.GetDelegate<CkmNative.C_DestroyObjectFn>("C_DestroyObject");
        _signInit = _dll.GetDelegate<CkmNative.C_SignInitFn>("C_SignInit");
        _sign = _dll.GetDelegate<CkmNative.C_SignFn>("C_Sign");

        if (_getSlotList == null)
            throw new InvalidOperationException("CMBCp.dll 导出解析失败（未找到 C_GetSlotList）");

        var rc = _initialize!(IntPtr.Zero);
        if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_CRYPTOKI_ALREADY_INITIALIZED)
            throw new InvalidOperationException($"PKCS#11 初始化失败（{CkmNative.ErrorString(rc)}）");
    }

    private static string FindLibraryRoot(string root)
    {
        if (Directory.Exists(root) && File.Exists(Path.Combine(root, "CMBCp.dll"))) return root;
        var candidates = new[]
        {
            Path.Combine(root, "Library"),
            Path.Combine(root, "Library", "HengBao"),
            Path.Combine(root, "Library", "HengBao USB Manage"),
            Path.Combine(AppContext.BaseDirectory, "Library"),
            Path.Combine(AppContext.BaseDirectory, "Library", "HengBao"),
            Path.Combine(AppContext.BaseDirectory, "Library", "HengBao USB Manage"),
        };
        foreach (var c in candidates)
            if (Directory.Exists(c) && File.Exists(Path.Combine(c, "CMBCp.dll")))
                return c;
        return root;
    }

    // ================= 设备枚举 =================

    /// <summary>
    /// 刷新槽位表。<c>C_GetSlotList</c> 会返回厂家自研 HID/SCSI 传输枚举到的设备名，
    /// 但不保证设备真的可访问；必须再用 <c>C_GetTokenInfo</c> 过滤，
    /// 只有真的能打开的设备才计入 <see cref="_slots"/>。
    /// </summary>
    private void RefreshSlots(bool force)
    {
        if (!force && _slots.Count > 0 && (DateTime.UtcNow - _enumAt).TotalMilliseconds < EnumCacheMs)
            return;

        _slots.Clear();
        _slotNames.Clear();
        _slotReady.Clear();
        _enumAt = DateTime.UtcNow;
        LastEnumerationDiagnostic = "";

        if (_dll == null) Initialize();

        uint count = 0;
        var rcEnum = _getSlotList!(1, null, ref count);
        if (rcEnum != CkmNative.CKR_OK)
        {
            SetDiagnostic($"C_GetSlotList 失败：{CkmNative.ErrorString(rcEnum)}");
            return;
        }
        if (count == 0)
        {
            // CMBCp.dll 自己的两条通道（HID + CD-ROM/SCSI）都没枚举到槽位。
            // 用 WMI 独立确认系统里到底有没有恒宝设备，以区分「设备不在」与「设备在、但驱动枚举不到」。
            var pnp = DetectHengBaoPnpDevices();
            if (pnp.Count > 0)
                SetDiagnostic($"系统检测到 {pnp.Count} 个恒宝设备（{pnp[0]}），但 CMBCp.dll 未枚举到任何槽位；" +
                              "请确认 U 宝是否已开机/唤醒、光盘卷是否挂载，或换 USB 口直插后重插。" +
                              "详见 Roadmap/07-HengBao-U宝逆向分析.md");
            return;
        }

        var raw = new uint[count];
        if (_getSlotList!(1, raw, ref count) != CkmNative.CKR_OK)
            return;

        for (int i = 0; i < (int)count && i < raw.Length; i++)
        {
            var slot = raw[i];
            if (slot == 0) continue;

            var name = ReadSlotName(slot);
            if (!PassesWhitelist(name)) continue;

            // 注意：这里不再因为 C_GetTokenInfo 失败就丢弃槽位。
            // 恒宝 U 宝「未进入令牌模式」时的表现是：C_GetSlotList 能给出槽位、
            // C_GetSlotInfo 返回硬编码信息，但 C_GetTokenInfo 返回 CKR_FUNCTION_FAILED(6)
            // （设备层日志显示卡片对 SELECT ADF1 回 SW=6E00）。
            // 此时必须仍把设备列出来（标记「未就绪」），否则界面会误报「未检测到设备」。
            var ready = false;
            try
            {
                var info = new CkmNative.CK_TOKEN_INFO();
                ready = _getTokenInfo!(slot, ref info) == CkmNative.CKR_OK;
            }
            catch { ready = false; }

            _slots.Add(slot);
            _slotNames.Add(name);
            _slotReady.Add(ready);
        }

        if (count > 0 && !_slotReady.Any(r => r))
        {
            SetDiagnostic(
                $"发现 {count} 个设备接口，但均无法打开（C_GetTokenInfo → CKR_FUNCTION_FAILED）：" +
                "该 U 宝要求先完成厂商 MSP 安全报文握手（80F2030001 → 80F4020000 → " +
                "80F4000087 → 80F4010080），而 CMBCp.dll 不做此握手，" +
                "因此卡片对裸 APDU 一律回 SW=6E00。这【不是】设备故障 —— " +
                "厂商工具 CMBCu.exe 在同一只 U 宝上可正常读写卡片。" +
                "详见 Roadmap/07-HengBao-U宝逆向分析.md §2.2");

                // 该诊断每次枚举都会命中（设备一直打不开），逐条打印会把日志刷爆。
                // 只在内容变化时记录一次；界面通过 LastEnumerationDiagnostic 展示提示。
                if (LastEnumerationDiagnostic != _lastDiagLogged)
                {
                _lastDiagLogged = LastEnumerationDiagnostic;
                Log.Write("[HengBao] " + LastEnumerationDiagnostic);
                }
                }
    }

    /// <summary>把槽位句柄当作设备路径字符串指针读取（仅用于展示与解析 VID/PID）。</summary>
    private static string ReadSlotName(uint slot)
    {
        try
        {
            var s = Marshal.PtrToStringAnsi(new IntPtr(unchecked((int)slot)));
            return s ?? "";
        }
        catch { return ""; }
    }

    private bool PassesWhitelist(string devicePath)
    {
        if (_whitelist.Count == 0) return true;
        var (vid, pid) = ParseVidPid(devicePath);
        if (vid == 0 && pid == 0) return true;   // 无法解析时不拦，交由驱动决定
        return _whitelist.Any(w => (w.Vid == 0 || w.Vid == vid) && (w.Pid == 0 || w.Pid == pid));
    }

    /// <summary>记录枚举诊断（内容变化时才写日志，避免每次枚举刷屏）。</summary>
    private void SetDiagnostic(string message)
    {
        LastEnumerationDiagnostic = message;
        if (message != _lastDiagLogged)
        {
            _lastDiagLogged = message;
            Log.Write("[HengBao] " + message);
        }
    }

    /// <summary>
    /// 用 WMI 独立探测系统里是否存在恒宝 USB 设备（不依赖 CMBCp.dll 能否枚举/打开）。
    /// 恒宝的 USB VID 为 <c>0x14D6</c>；设备名里带 HENGBAO / UranuSafe。
    /// 用途：当 DLL 返回 0 个槽位时，区分「设备根本没插」与「插了但驱动枚举不到」。
    /// </summary>
    private static List<string> DetectHengBaoPnpDevices()
    {
        var found = new List<string>();
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT PNPDeviceID, Name FROM Win32_PnPEntity WHERE " +
                "PNPDeviceID LIKE '%HENGBAO%' OR PNPDeviceID LIKE '%VID_14D6%' OR Name LIKE '%UranuSafe%'");
            foreach (System.Management.ManagementBaseObject o in searcher.Get())
            {
                var id = o["PNPDeviceID"]?.ToString() ?? "";
                if (id.Length == 0) continue;
                found.Add(id);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "HengBao WMI 设备探测失败");
        }
        return found;
    }

    private static (int Vid, int Pid) ParseVidPid(string devicePath)
    {
        if (string.IsNullOrEmpty(devicePath)) return (0, 0);
        int vid = 0, pid = 0;
        var mv = Regex.Match(devicePath, @"vid_([0-9a-fA-F]{4})", RegexOptions.IgnoreCase);
        var mp = Regex.Match(devicePath, @"pid_([0-9a-fA-F]{4})", RegexOptions.IgnoreCase);
        if (mv.Success) vid = Convert.ToInt32(mv.Groups[1].Value, 16);
        if (mp.Success) pid = Convert.ToInt32(mp.Groups[1].Value, 16);
        return (vid, pid);
    }

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var result = new List<UsbKeyDevice>();
        try
        {
            RefreshSlots(force: false);

            for (int i = 0; i < _slots.Count; i++)
            {
                var isReady = i < _slotReady.Count && _slotReady[i];
                var dev = new UsbKeyDevice
                {
                    Platform = PlatformName,
                    VendorName = "HengBao（恒宝）",
                    Model = isReady ? "民生银行 U 宝" : "民生银行 U 宝（未就绪）",
                    Handle = i,
                };

                try
                {
                    if (isReady)
                    {
                        var info = new CkmNative.CK_TOKEN_INFO();
                        if (_getTokenInfo!(_slots[i], ref info) == CkmNative.CKR_OK)
                            FillDeviceInfo(dev, info);
                    }
                    else
                    {
                        // 设备接口在，但令牌打不开：仍然列出来，并说明原因（否则界面会误报"未检测到设备"）
                        var slotName = i < _slotNames.Count ? _slotNames[i] : "";
                        dev.SerialNumber = "";
                        dev.Notes = "设备接口已枚举到，但令牌无法打开（C_GetTokenInfo → CKR_FUNCTION_FAILED）：" +
                                    "该 U 宝要求先完成厂商 MSP 安全报文握手，而 CMBCp.dll 不做此握手，" +
                                    "因此卡片对裸 APDU 一律回 SW=6E00。这【不是】设备故障" +
                                    "（厂商工具 CMBCu.exe 在同一设备上工作正常）。" +
                                    "详见 Roadmap/07-HengBao-U宝逆向分析.md §2.2";
                        if (!string.IsNullOrEmpty(slotName))
                            dev.FirmwareVersion = "—";
                    }
                }
                catch (Exception ex)
                {
                    dev.Notes = "读取设备信息失败：" + ex.Message;
                }

                var (vid, pid) = ParseVidPid(i < _slotNames.Count ? _slotNames[i] : "");
                dev.Vid = vid;
                dev.Pid = pid;
                result.Add(dev);
            }

            // 兜底：DLL 一个槽位都没给，但 WMI 确认系统里确实有恒宝设备 —— 也要让界面能看见它
            if (result.Count == 0)
            {
                var pnp = DetectHengBaoPnpDevices();
                if (pnp.Count > 0)
                {
                    result.Add(new UsbKeyDevice
                    {
                        Platform = PlatformName,
                        VendorName = "HengBao（恒宝）",
                        Model = "民生银行 U 宝（驱动未枚举到）",
                        Handle = -1,
                        Notes = $"系统检测到 {pnp.Count} 个恒宝设备（{pnp[0]}），但 CMBCp.dll 未返回可用槽位：" +
                                "通常是 U 宝未进入令牌模式/未开机，或光盘卷未挂载。详见 Roadmap/07-HengBao-U宝逆向分析.md",
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "HengBao Enumerate 失败");
        }
        return result;
    }

    private static void FillDeviceInfo(UsbKeyDevice dev, CkmNative.CK_TOKEN_INFO info)
    {
        var label = CkmNative.PaddedToString(info.label);
        var model = CkmNative.PaddedToString(info.model);
        var modelCode = CkmNative.PaddedToString(info.manufacturerID);
        var serial = CkmNative.PaddedToString(info.serialNumber);

        dev.Model = string.IsNullOrWhiteSpace(model) ? (string.IsNullOrWhiteSpace(label) ? "民生银行 U 宝" : label) : model;
        if (!string.IsNullOrWhiteSpace(label) && !string.Equals(label, dev.Model, StringComparison.Ordinal))
            dev.Model += $"（{label}）";
        dev.SerialNumber = string.IsNullOrWhiteSpace(serial) ? "未知" : serial;
        dev.FirmwareVersion = $"{info.firmwareVersion.major}.{info.firmwareVersion.minor}";

        var notes = new List<string>();
        if (!string.IsNullOrWhiteSpace(modelCode)) notes.Add("厂商代码:" + modelCode);
        notes.Add($"硬件版本 {info.hardwareVersion.major}.{info.hardwareVersion.minor}");
        if (info.ulMinPinLen > 0 || info.ulMaxPinLen > 0)
            notes.Add($"口令长度 {info.ulMinPinLen}-{info.ulMaxPinLen}");
        var retry = info.ulSessionCount;   // 厂商把该字段复用为 PIN 剩余尝试次数
        if (retry <= 50) notes.Add($"PIN 剩余尝试次数 {retry}");
        if ((info.flags & CkmNative.CKF_USER_PIN_LOCKED) != 0) notes.Add("PIN 已锁定");
        else if ((info.flags & CkmNative.CKF_USER_PIN_FINAL_TRY) != 0) notes.Add("PIN 仅剩最后一次机会");
        dev.Notes = string.Join(" · ", notes);
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        RefreshSlots(force: false);
        if (handleOrSerial >= 0 && handleOrSerial < _slots.Count)
        {
            var devs = Enumerate();
            if (handleOrSerial < devs.Count) return devs[handleOrSerial];
        }
        var list = Enumerate();
        if (list.Count > 0) return list[0];
        throw new InvalidOperationException("未检测到恒宝 U 宝设备（请确认已插入且驱动已安装）");
    }

    // ================= 会话 =================

    private uint EnsureSession(UsbKeyDevice device)
    {
        if (_dll == null) Initialize();
        RefreshSlots(force: false);

        if (device.Handle < 0)
            throw new InvalidOperationException(
                "该设备当前无法打开（未就绪）：CMBCp.dll 未枚举到可用槽位。\n" +
                "请确认 U 宝已开机/唤醒（二代带屏机型需按开机键）、换 USB 口直插后重插；" +
                "排查步骤见 Roadmap/07-HengBao-U宝逆向分析.md。");
        if (device.Handle >= _slots.Count)
            throw new InvalidOperationException("设备句柄已失效，请点击「刷新」后重试");

        var slot = _slots[device.Handle];
        var ready = device.Handle < _slotReady.Count && _slotReady[device.Handle];

        if (_sessions.TryGetValue(device.Handle, out var cached))
        {
            if (cached.Slot != slot)
            {
                // 设备集合变化导致同一索引指向了不同设备：关闭旧会话
                try { if (cached.Session != 0) _closeSession?.Invoke(cached.Session); } catch { }
                _sessions.Remove(device.Handle);
            }
            else if (cached.Session != 0)
            {
                return cached.Session;
            }
        }

        uint session = 0;
        var flags = CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION;
        var rc = _openSession!(slot, flags, IntPtr.Zero, IntPtr.Zero, ref session);
        if (rc != CkmNative.CKR_OK || session == 0)
        {
            if (!ready)
                throw new InvalidOperationException(
                    "设备接口存在但令牌无法打开：该 U 宝要求先完成厂商 MSP 安全报文握手" +
                    "（80F2030001 → 80F4020000 → 80F4000087 → 80F4010080），" +
                    "而 CMBCp.dll 不做此握手，未握手时卡片对裸 APDU 一律回 SW=6E00。\n" +
                    "这【不是】设备故障：厂商工具 CMBCu.exe 在同一只 U 宝上可正常读写卡片。\n" +
                    "本工程需先实现该握手（见 Roadmap/07-HengBao-U宝逆向分析.md §2.2）；" +
                    "在此之前请使用厂商工具 CMBCu.exe 完成证书管理与「初始化 U 宝」。");
            throw new InvalidOperationException($"打开会话失败（{CkmNative.ErrorString(rc)}）");
        }

        _sessions[device.Handle] = (slot, session);
        return session;
    }

    private void CloseSession(int index)
    {
        if (_sessions.TryGetValue(index, out var pair))
        {
            try { if (pair.Session != 0) _closeSession?.Invoke(pair.Session); } catch { }
            _sessions.Remove(index);
        }
    }

    public void Login(UsbKeyDevice device, string pin)
    {
        var session = EnsureSession(device);
        var pinBytes = Encoding.UTF8.GetBytes(pin);
        var rc = _login!(session, CkmNative.CKU_USER, pinBytes, (uint)pinBytes.Length);
        if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_USER_ALREADY_LOGGED_IN)
            throw new InvalidOperationException(ErrorMessage(rc));
        device.IsLoggedIn = true;
    }

    private static string ErrorMessage(uint rc) => rc switch
    {
        CkmNative.CKR_PIN_INCORRECT => "PIN 错误（口令不正确）",
        CkmNative.CKR_PIN_LOCKED => "PIN 已锁定（需到银行柜台/厂商工具初始化后重新申请证书）",
        CkmNative.CKR_PIN_LEN_RANGE => "PIN 长度不合法（本设备为 6-15 位）",
        CkmNative.CKR_PIN_EXPIRED => "PIN 已过期",
        CkmNative.CKR_USER_TYPE_INVALID => "用户类型无效（本设备仅支持用户口令，无管理员/ SO 口令）",
        CkmNative.CKR_FUNCTION_FAILED => "设备通信失败（请重新插拔后重试，或使用厂商工具修复）",
        CkmNative.CKR_FUNCTION_NOT_SUPPORTED => "该设备不支持此功能",
        _ => $"登录失败（{CkmNative.ErrorString(rc)}）",
    };

    public void Logout(UsbKeyDevice device)
    {
        if (_sessions.TryGetValue(device.Handle, out var pair) && pair.Session != 0)
            try { _logout?.Invoke(pair.Session); } catch { }
        device.IsLoggedIn = false;
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        try
        {
            RefreshSlots(force: true);
            if (device.Handle >= 0 && device.Handle < _slots.Count)
            {
                var info = new CkmNative.CK_TOKEN_INFO();
                if (_getTokenInfo!(_slots[device.Handle], ref info) == CkmNative.CKR_OK)
                    FillDeviceInfo(device, info);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "HengBao GetDetail 失败");
        }
        return device;
    }

    // ================= 证书 / 容器 =================

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        var session = EnsureSession(device);
        var result = new List<KeyContainer>();

        var certHandles = FindObjects(session, CkmNative.CKO_CERTIFICATE);
        if (certHandles.Count == 0) return result;

        // 收集私钥及其 CKA_ID，便于判断证书是否有对应私钥
        var keyIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kh in FindObjects(session, CkmNative.CKO_PRIVATE_KEY))
        {
            var id = ReadBytes(session, kh, CkmNative.CKA_ID);
            if (id is { Length: > 0 }) keyIds.Add(Convert.ToHexString(id));
        }

        foreach (var handle in certHandles)
        {
            try
            {
                var der = ReadBytes(session, handle, CkmNative.CKA_VALUE);
                if (der is not { Length: > 0 } || der.Length > MaxCertSize) continue;

                var id = ReadBytes(session, handle, CkmNative.CKA_ID);
                var label = ReadString(session, handle, CkmNative.CKA_LABEL);
                var container = BuildContainer(der, handle, label, id, keyIds);
                if (container != null) result.Add(container);
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"HengBao 读取证书对象 0x{handle:X} 失败");
            }
        }
        return result;
    }

    private static KeyContainer? BuildContainer(byte[] der, uint handle, string label, byte[]? id, HashSet<string> keyIds)
    {
        X509Certificate2 cert;
        try { cert = new X509Certificate2(der); }
        catch { return null; }

        using (cert)
        {
            string name;
            try
            {
                name = cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch { name = ""; }
            if (string.IsNullOrWhiteSpace(name)) name = cert.GetNameInfo(X509NameType.SimpleName, true);
            if (string.IsNullOrWhiteSpace(name)) name = label;
            if (string.IsNullOrWhiteSpace(name)) name = "证书";

            var hasKey = id is { Length: > 0 } && keyIds.Contains(Convert.ToHexString(id));
            var bits = 0;
            var keyAlg = "—";
            try
            {
                using var rsa = cert.GetRSAPublicKey();
                if (rsa != null)
                {
                    bits = rsa.KeySize;
                    keyAlg = $"RSA {bits}";
                }
                else
                {
                    using var ecdsa = cert.GetECDsaPublicKey();
                    if (ecdsa != null)
                    {
                        bits = ecdsa.KeySize;
                        keyAlg = $"ECDSA P{bits}";
                    }
                }
            }
            catch { }

            return new KeyContainer
            {
                Name = name,
                ContainerName = string.IsNullOrWhiteSpace(label) ? name : label,
                ContainerUuid = handle.ToString(),         // PKCS#11 对象句柄
                Algorithm = hasKey ? $"{keyAlg}/设备内私钥" : $"{keyAlg}/无匹配私钥",
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
                SerialNumber = cert.SerialNumber,
                Thumbprint = cert.Thumbprint,
                KeyUsage = DescribeKeyUsage(cert),
                ExtendedKeyUsage = hasKey ? "可用于签名/解密" : "仅有证书（无私钥）",
                IsRegisteredInCsp = CertHelper.IsRegistered(cert.Thumbprint),
                CertRaw = der,
            };
        }
    }

    private static string DescribeKeyUsage(X509Certificate2 cert)
    {
        try
        {
            var ku = cert.Extensions
                .OfType<X509KeyUsageExtension>()
                .FirstOrDefault();
            if (ku == null) return "—";
            var flags = ku.KeyUsages;
            var parts = new List<string>();
            if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature)) parts.Add("数字签名");
            if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation)) parts.Add("不可否认");
            if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment)) parts.Add("密钥加密");
            if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment)) parts.Add("数据加密");
            if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement)) parts.Add("密钥协商");
            if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign)) parts.Add("签发证书");
            return parts.Count > 0 ? string.Join("/", parts) : "—";
        }
        catch { return "—"; }
    }

    /// <summary>导入 PFX：先尝试写入设备内私钥对象，再写入证书对象（两步骤均失败则整体回滚报错）。</summary>
    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        var session = EnsureSession(device);
        if (_createObject == null) throw new InvalidOperationException("Provider 未初始化");

        using var cert = new X509Certificate2(pfxPath,
            string.IsNullOrEmpty(pfxPassword) ? null : pfxPassword,
            X509KeyStorageFlags.Exportable);

        var der = cert.Export(X509ContentType.Cert);
        var id = System.Security.Cryptography.SHA1.HashData(der);   // CKA_ID 用证书指纹，便于与私钥配对

        // 1) 私钥：本设备为「卡片内生成密钥」型 U 宝，外部私钥导入通常不被支持。
        if (cert.HasPrivateKey)
        {
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa != null)
            {
                // 经 PfxKeyReader 取参数：直接 ExportParameters(true) 在 Windows 上会因 CNG
                // 只给 AllowExport、不给 AllowPlaintextExport 而报"不支持请求的操作"（0x80090029）。
                var p = Crypto.PfxKeyReader.ExportRsaPrivateKey(rsa);
                var rcKey = CreateRsaPrivateKey(session, id, p, cert.GetNameInfo(X509NameType.SimpleName, false));
                if (rcKey != CkmNative.CKR_OK)
                    throw new NotSupportedException(
                        "该设备不支持导入外部私钥（C_CreateObject/CKO_PRIVATE_KEY 返回 " +
                        $"{CkmNative.ErrorString(rcKey)}）。\n" +
                        "恒宝 U 宝的密钥必须由设备内部产生、证书由银行柜台/网银下载，\n" +
                        "因此「导入 PFX」在本设备上不可用；请改用「下载证书」或厂商工具。");
            }
        }

        // 2) 证书对象
        var rc = CreateCertificate(session, der, id, cert.GetNameInfo(X509NameType.SimpleName, false),
            cert.Subject, cert.Issuer, cert.GetSerialNumber());
        if (rc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"导入证书失败（{CkmNative.ErrorString(rc)}）");
    }

    private uint CreateRsaPrivateKey(uint session, byte[] id, System.Security.Cryptography.RSAParameters p, string label)
    {
        using var attrs = new AttrSet();
        attrs.AddUInt(CkmNative.CKA_CLASS, CkmNative.CKO_PRIVATE_KEY);
        attrs.AddUInt(CkmNative.CKA_KEY_TYPE, CkmNative.CKK_RSA);
        attrs.AddUInt(CkmNative.CKA_TOKEN, 1);
        attrs.AddUInt(CkmNative.CKA_PRIVATE, 1);
        attrs.AddBytes(CkmNative.CKA_ID, id);
        attrs.AddString(CkmNative.CKA_LABEL, label);
        if (p.Modulus != null) attrs.AddBytes(CkmNative.CKA_MODULUS, p.Modulus);
        if (p.Exponent != null) attrs.AddBytes(CkmNative.CKA_PUBLIC_EXPONENT, p.Exponent);
        if (p.D != null) attrs.AddBytes(CkmNative.CKA_PRIVATE_EXPONENT, p.D);
        if (p.P != null) attrs.AddBytes(CkmNative.CKA_PRIME_1, p.P);
        if (p.Q != null) attrs.AddBytes(CkmNative.CKA_PRIME_2, p.Q);
        if (p.DP != null) attrs.AddBytes(CkmNative.CKA_EXPONENT_1, p.DP);
        if (p.DQ != null) attrs.AddBytes(CkmNative.CKA_EXPONENT_2, p.DQ);
        if (p.InverseQ != null) attrs.AddBytes(CkmNative.CKA_COEFFICIENT, p.InverseQ);

        uint handle = 0;
        return _createObject!(session, attrs.Template!, (uint)attrs.Count, ref handle);
    }

    private uint CreateCertificate(uint session, byte[] der, byte[] id, string label, string subject, string issuer, byte[] serial)
    {
        using var attrs = new AttrSet();
        attrs.AddUInt(CkmNative.CKA_CLASS, CkmNative.CKO_CERTIFICATE);
        attrs.AddUInt(CkmNative.CKA_CERTIFICATE_TYPE, CkmNative.CKC_X_509);
        attrs.AddUInt(CkmNative.CKA_TOKEN, 1);
        attrs.AddBytes(CkmNative.CKA_VALUE, der);
        attrs.AddBytes(CkmNative.CKA_ID, id);
        attrs.AddString(CkmNative.CKA_LABEL, label);

        uint handle = 0;
        return _createObject!(session, attrs.Template!, (uint)attrs.Count, ref handle);
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        if (container.CertRaw == null || container.CertRaw.Length == 0)
            throw new InvalidOperationException("证书数据不可用");
        // 只导出公钥证书部分
        using var cert = new X509Certificate2(container.CertRaw);
        File.WriteAllBytes(outputPath, cert.Export(X509ContentType.Cert));
    }

    public void ViewCertificate(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
        File.WriteAllBytes(tmp, container.CertRaw);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmp) { UseShellExecute = true });
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        var session = EnsureSession(device);
        if (!uint.TryParse(container.ContainerUuid, out var handle) || handle == 0)
            throw new InvalidOperationException("容器缺少对象句柄，无法删除");

        var rc = _destroyObject!(session, handle);
        if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_OBJECT_HANDLE_INVALID)
            throw new InvalidOperationException($"删除证书失败（{CkmNative.ErrorString(rc)}）");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        CertHelper.Register(container.CertRaw, container.Name);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    // ================= PIN / 解锁 / 重置 =================

    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        var session = EnsureSession(device);
        var oldBytes = Encoding.UTF8.GetBytes(oldPin);
        var newBytes = Encoding.UTF8.GetBytes(newPin);
        var rc = _setPin!(session, oldBytes, (uint)oldBytes.Length, newBytes, (uint)newBytes.Length);
        if (rc != CkmNative.CKR_OK)
            throw new InvalidOperationException($"修改口令失败（{CkmNative.ErrorString(rc)}）");
    }

    /// <summary>
    /// 本设备无 SO 口令 / PUK：PKCS#11 的 C_Login 仅接受 CKU_USER，
    /// C_InitToken / C_InitPIN 为未实现桩函数，故无法「解锁」也不存在管理员重置通道。
    /// </summary>
    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
        => throw new NotSupportedException(
            "恒宝 U 宝不支持口令解锁：PKCS#11 层只实现了用户口令（C_Login 仅接受 CKU_USER），" +
            "没有 SO 口令 / PUK，C_InitToken、C_InitPIN 均为未实现（返回 CKR_FUNCTION_NOT_SUPPORTED）。\n" +
            "口令锁定后只能携带 U 宝到银行柜台处理，或使用厂商工具 CMBCu.exe。");

    public string GenerateChallenge(UsbKeyDevice device)
        => throw new NotSupportedException("恒宝 U 宝不支持挑战码解锁。");

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
        => throw new NotSupportedException("恒宝 U 宝不支持挑战码解锁。");

    /// <summary>
    /// 重置设备 = <b>清空设备内容 + 重设口令</b>。
    /// <list type="number">
    /// <item>用当前口令登录（本设备无 SO/PUK，这是唯一可行的授权方式）。</item>
    /// <item>删除设备上全部 PKCS#11 对象（证书 / 私钥 / 公钥 / 数据）。</item>
    /// <item>调用 C_SetPIN 把用户口令改为新口令，并用新口令重新登录。</item>
    /// </list>
    /// 注意：这不等同于厂商工具的「初始化 U 宝」（后者会连卡片文件系统一起恢复出厂态、
    /// 并把口令恢复为 111111，只能由 CMBCu.exe / 银行柜台完成）。
    /// </summary>
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        if (string.IsNullOrEmpty(currentPin))
            throw new InvalidOperationException("请提供当前口令：恒宝 U 宝没有 SO/PUK，必须先通过用户口令认证才能清空设备并重设口令。");
        if (_destroyObject == null || _setPin == null || _findInit == null || _find == null || _findFinal == null)
            throw new InvalidOperationException("CMBCp.dll 缺少必需导出（C_DestroyObject / C_SetPIN / C_FindObjects*），无法重置。");

        var session = EnsureSession(device);

        // 1) 认证
        var oldBytes = Encoding.UTF8.GetBytes(currentPin);
        var rcLogin = _login!(session, CkmNative.CKU_USER, oldBytes, (uint)oldBytes.Length);
        if (rcLogin != CkmNative.CKR_OK && rcLogin != CkmNative.CKR_USER_ALREADY_LOGGED_IN)
            throw new InvalidOperationException(ErrorMessage(rcLogin));
        device.IsLoggedIn = true;

        // 2) 清空内容
        var erased = EraseAllObjects(session);

        // 3) 重设口令
        var newBytes = Encoding.UTF8.GetBytes(newPin);
        var rcSet = _setPin!(session, oldBytes, (uint)oldBytes.Length, newBytes, (uint)newBytes.Length);
        if (rcSet != CkmNative.CKR_OK)
            throw new InvalidOperationException(
                $"已清空 {erased} 个对象，但重设口令失败（{CkmNative.ErrorString(rcSet)}）；请重新插拔设备后重试。");

        LastResetSummary = $"已删除 {erased} 个对象，口令已重设。";

        // 4) 重新登录，保持会话可用
        try
        {
            CloseSession(device.Handle);
            var s2 = EnsureSession(device);
            var rc2 = _login!(s2, CkmNative.CKU_USER, newBytes, (uint)newBytes.Length);
            device.IsLoggedIn = rc2 == CkmNative.CKR_OK || rc2 == CkmNative.CKR_USER_ALREADY_LOGGED_IN;
        }
        catch
        {
            device.IsLoggedIn = false;
        }

        var info = new CkmNative.CK_TOKEN_INFO();
        if (_getTokenInfo != null && device.Handle >= 0 && device.Handle < _slots.Count &&
            _getTokenInfo(_slots[device.Handle], ref info) == CkmNative.CKR_OK)
            FillDeviceInfo(device, info);
    }

    /// <summary>
    /// 删除设备上的全部对象（不区分类别）。返回成功删除的数量；失败项记录在
    /// <see cref="LastResetSummary"/>。
    /// <para>注意：<c>C_DestroyObject</c> 对「卡片内对象」会同步删除卡片上的文件；
    /// 对句柄已失效的对象返回 CKR_OBJECT_HANDLE_INVALID，属正常（例如删除证书后其公钥已被联动删除）。</para>
    /// </summary>
    public int EraseAllObjects(UsbKeyDevice device, string? currentPin = null)
    {
        if (!string.IsNullOrEmpty(currentPin))
        {
            var session0 = EnsureSession(device);
            var b = Encoding.UTF8.GetBytes(currentPin!);
            var rc = _login!(session0, CkmNative.CKU_USER, b, (uint)b.Length);
            if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_USER_ALREADY_LOGGED_IN)
                throw new InvalidOperationException(ErrorMessage(rc));
            device.IsLoggedIn = true;
        }
        return EraseAllObjects(EnsureSession(device));
    }

    private int EraseAllObjects(uint session)
    {
        var handles = new List<uint>();
        foreach (var cls in new[]
                 {
                     CkmNative.CKO_CERTIFICATE, CkmNative.CKO_PRIVATE_KEY,
                     CkmNative.CKO_PUBLIC_KEY, CkmNative.CKO_DATA
                 })
            handles.AddRange(FindObjects(session, cls));

        // 去重（同一对象可能被多次命中）
        var unique = handles.Distinct().ToList();

        int ok = 0;
        var failures = new List<string>();
        foreach (var h in unique)
        {
            var rc = _destroyObject!(session, h);
            if (rc == CkmNative.CKR_OK) ok++;
            else if (rc != CkmNative.CKR_OBJECT_HANDLE_INVALID)
                failures.Add($"0x{h:X}:{CkmNative.ErrorString(rc)}");
        }

        LastResetSummary = failures.Count == 0
            ? $"共发现 {unique.Count} 个对象，已全部删除。"
            : $"共发现 {unique.Count} 个对象，删除 {ok} 个，失败 {failures.Count} 个（{string.Join(", ", failures.Take(3))}）";
        return ok;
    }

    // ================= 签名 =================

    /// <summary>使用设备内私钥签名（先试 SHA256withRSA，失败回退 SHA1withRSA）。</summary>
    public byte[] Sign(UsbKeyDevice device, KeyContainer container, byte[] data)
    {
        var session = EnsureSession(device);

        uint certHandle = uint.TryParse(container.ContainerUuid, out var h) ? h : 0;
        var keyHandle = FindPrivateKey(session, certHandle);
        if (keyHandle == 0)
            throw new InvalidOperationException("未找到与证书匹配的设备内私钥");

        foreach (var mechanism in new[] { CkmNative.CKM_SHA256_RSA_PKCS, CkmNative.CKM_SHA1_RSA_PKCS })
        {
            var mech = new CkmNative.CK_MECHANISM { mechanism = mechanism, pParameter = IntPtr.Zero, ulParameterLen = 0 };
            if (_signInit!(session, ref mech, keyHandle) != CkmNative.CKR_OK) continue;

            uint sigLen = 0;
            var rc = _sign!(session, data, (uint)data.Length, null, ref sigLen);
            if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_BUFFER_TOO_SMALL)
                continue;

            var sig = new byte[sigLen];
            rc = _sign!(session, data, (uint)data.Length, sig, ref sigLen);
            if (rc == CkmNative.CKR_OK) return sig;
        }
        throw new InvalidOperationException("签名失败：设备不支持 SHA256withRSA / SHA1withRSA 机制");
    }

    private uint FindPrivateKey(uint session, uint certHandle)
    {
        var keys = FindObjects(session, CkmNative.CKO_PRIVATE_KEY);
        if (keys.Count == 0) return 0;
        if (certHandle == 0) return keys[0];

        // 用证书的 CKA_ID 匹配私钥
        var certId = ReadBytes(session, certHandle, CkmNative.CKA_ID);
        if (certId is not { Length: > 0 }) return keys[0];

        foreach (var k in keys)
        {
            var kid = ReadBytes(session, k, CkmNative.CKA_ID);
            if (kid != null && kid.AsSpan().SequenceEqual(certId)) return k;
        }
        return keys[0];
    }

    // ================= PKCS#11 通用工具 =================

    private List<uint> FindObjects(uint session, uint objClass)
    {
        var result = new List<uint>();
        if (_findInit == null || _find == null || _findFinal == null) return result;

        using var attrs = new AttrSet();
        attrs.AddUInt(CkmNative.CKA_CLASS, objClass);

        var rc = _findInit(session, attrs.Template!, (uint)attrs.Count);
        if (rc != CkmNative.CKR_OK) return result;
        try
        {
            var buf = new uint[16];
            while (true)
            {
                uint got = 0;
                if (_find(session, buf, (uint)buf.Length, ref got) != CkmNative.CKR_OK || got == 0) break;
                for (int i = 0; i < (int)got; i++) result.Add(buf[i]);
                if (got < buf.Length) break;
            }
        }
        finally
        {
            try { _findFinal(session); } catch { }
        }
        return result;
    }

    /// <summary>读取单字节数组属性（两次调用：先取长度再取值）。不支持时返回 null。</summary>
    private byte[]? ReadBytes(uint session, uint obj, uint attrType)
    {
        if (_getAttr == null) return null;
        try
        {
            var probe = new[]
            {
                new CkmNative.CK_ATTRIBUTE { type = attrType, pValue = IntPtr.Zero, ulValueLen = 0 }
            };
            var rc = _getAttr(session, obj, probe, 1);
            if (rc == CkmNative.CKR_ATTRIBUTE_TYPE_INVALID || rc == CkmNative.CKR_ATTRIBUTE_SENSITIVE) return null;
            var len = (int)probe[0].ulValueLen;
            if (len <= 0 || len > MaxCertSize * 4) return null;

            var buf = new byte[len];
            var ptr = Marshal.AllocHGlobal(len);
            try
            {
                var read = new[]
                {
                    new CkmNative.CK_ATTRIBUTE { type = attrType, pValue = ptr, ulValueLen = (uint)len }
                };
                if (_getAttr(session, obj, read, 1) != CkmNative.CKR_OK) return null;
                Marshal.Copy(ptr, buf, 0, len);
                return buf;
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        catch { return null; }
    }

    private string ReadString(uint session, uint obj, uint attrType)
    {
        var b = ReadBytes(session, obj, attrType);
        if (b == null) return "";
        return Encoding.UTF8.GetString(b).TrimEnd('\0', ' ').Trim();
    }

    /// <summary>CK_ATTRIBUTE 模板构造器：负责托管非托管缓冲区的生命周期。</summary>
    private sealed class AttrSet : IDisposable
    {
        private readonly List<CkmNative.CK_ATTRIBUTE> _attrs = new();
        private readonly List<IntPtr> _buffers = new();

        public uint Count => (uint)_attrs.Count;
        public CkmNative.CK_ATTRIBUTE[]? Template => _attrs.Count == 0 ? null : _attrs.ToArray();

        public void AddUInt(uint type, uint value)
        {
            var ptr = Marshal.AllocHGlobal(sizeof(uint));
            Marshal.WriteInt32(ptr, (int)value);
            _buffers.Add(ptr);
            _attrs.Add(new CkmNative.CK_ATTRIBUTE { type = type, pValue = ptr, ulValueLen = sizeof(uint) });
        }

        public void AddBytes(uint type, byte[] value)
        {
            var ptr = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, ptr, value.Length);
            _buffers.Add(ptr);
            _attrs.Add(new CkmNative.CK_ATTRIBUTE { type = type, pValue = ptr, ulValueLen = (uint)value.Length });
        }

        public void AddString(uint type, string value) => AddBytes(type, Encoding.UTF8.GetBytes(value));

        public void Dispose()
        {
            foreach (var b in _buffers)
                try { Marshal.FreeHGlobal(b); } catch { }
            _buffers.Clear();
            _attrs.Clear();
        }
    }

    public void Dispose()
    {
        foreach (var idx in _sessions.Keys.ToList())
            CloseSession(idx);
        try { _finalize?.Invoke(IntPtr.Zero); } catch { }
        _dll?.Dispose();
        _dll = null;
    }
}
