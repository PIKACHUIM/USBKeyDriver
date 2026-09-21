using System.Runtime.InteropServices;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 龙脉（Longmai）GM3000 USB Key 底层互操作层：<b>SKF（GM/T 0016）</b>接口封装。
/// <para>
/// 逆向来源（2026-09，静态反汇编 + x86 实机探针 <c>tools/GM3000Probe</c>）：
/// <c>Library/Longmai GM3000 SDK/GM3000_2.1.1.0/mtoken_GM.dll</c>
/// （内部 PDB 路径为 <c>mtoken_gm3000.pdb</c>，即模块真名为 mtoken_gm3000）。
/// </para>
/// <para>
/// <b>关键版本结论（已实测）</b>：本机插入的是一把 **老型号 GM3000**
/// （USB <c>VID_055C&amp;PID_DB08</c>，以 USBSTOR/CD-ROM 形态暴露，固件 <c>REV 2.00</c>）。
/// <list type="bullet">
/// <item>2016 版 SKF（292,352B，SHA256 <c>5E8E5725…</c>）→ <c>SKF_EnumDev</c> 能枚举到该设备；</item>
/// <item>2022 版 SKF（<c>GM3000_2.2.19\mtoken_gm3000.dll.old</c>，427,008B）→ 枚举数为 <b>0</b>，
/// 新中间件已不再支持该老型号；</item>
/// <item>两个版本的 <c>gm3000_pkcs11.dll</c> 都只有 4 个「无令牌」槽位，
/// 这正是 <c>GM3000Admin.exe</c>（经 <c>TokenMgr.dll</c> → PKCS#11）报「不识别设备」的根因。</item>
/// </list>
/// 因此本 Provider 只依赖 <b>SKF</b>，不依赖 PKCS#11 / TokenMgr / mTokenIOSvr 服务。
/// </para>
/// <para>
/// <b>调用约定</b>：全部导出为 <c>__stdcall</c>，参数个数已由反汇编 <c>ret imm16</c> 逐一确认：
/// <c>EnumDev(3) ConnectDev(2) DisConnectDev(1) GetDevInfo(2) GetDevState(2)
/// EnumApplication(3) OpenApplication(3) CloseApplication(1) EnumContainer(3) OpenContainer(3)
/// CloseContainer(1) CreateContainer(3) DeleteContainer(2) GetContainerType(2)
/// ImportCertificate(4) ExportCertificate(4) ExportPublicKey(4) ImportRSAKeyPair(6)
/// GenRandom(3) VerifyPIN(4) ChangePIN(5) UnblockPIN(4) ClearSecureState(1) SetLabel(2)
/// GetPINInfo(5) Transmit(5)</c>。
/// </para>
/// <para>
/// <b>上下文语义（重要）</b>：该 SKF 实现是「当前设备/当前应用」全局上下文模型——
/// <c>SKF_ConnectDev</c> 选定当前设备、<c>SKF_OpenApplication</c> 选定当前应用；
/// 之后 <c>VerifyPIN</c>/<c>GetPINInfo</c>/<c>EnumContainer</c> 等函数的首个句柄参数
/// 在反汇编中并未参与查找（读取的是全局上下文）。因此调用顺序必须是
/// <c>ConnectDev → OpenApplication → 其余操作</c>。
/// </para>
/// <para>本类不做 DLL 位数判断；宿主必须以 x86 运行（见 csproj 的 PlatformTarget）。</para>
/// </summary>
internal static class Gm3000Native
{
    // ======================= 错误码（GM/T 0016 SAR_*）=======================

    internal const uint SAR_OK = 0x00000000;
    internal const uint SAR_FAIL = 0x0A000001;
    internal const uint SAR_NOTSUPPORTYETERR = 0x0A000003;
    internal const uint SAR_FILEERR = 0x0A000004;
    internal const uint SAR_INVALIDHANDLEERR = 0x0A000005;
    internal const uint SAR_INVALIDPARAMERR = 0x0A000006;
    internal const uint SAR_NOTINITIALIZEERR = 0x0A00000C;
    internal const uint SAR_OBJERR = 0x0A00000D;
    internal const uint SAR_BUFFER_TOO_SMALL = 0x0A000020;
    internal const uint SAR_DEVICE_REMOVED = 0x0A000023;
    internal const uint SAR_PIN_INCORRECT = 0x0A000024;
    internal const uint SAR_PIN_LOCKED = 0x0A000025;
    internal const uint SAR_PIN_INVALID = 0x0A000026;
    internal const uint SAR_PIN_LEN_RANGE = 0x0A000027;
    internal const uint SAR_USER_ALREADY_LOGGED_IN = 0x0A000028;
    internal const uint SAR_USER_PIN_NOT_INITIALIZED = 0x0A000029;
    internal const uint SAR_USER_TYPE_INVALID = 0x0A00002A;
    internal const uint SAR_APPLICATION_NAME_INVALID = 0x0A00002B;
    internal const uint SAR_APPLICATION_EXISTS = 0x0A00002C;
    internal const uint SAR_USER_NOT_LOGGED_IN = 0x0A00002D;
    internal const uint SAR_APPLICATION_NOT_EXISTS = 0x0A00002E;
    internal const uint SAR_FILE_ALREADY_EXIST = 0x0A00002F;
    internal const uint SAR_NO_ROOM = 0x0A000030;
    internal const uint SAR_FILE_NOT_EXIST = 0x0A000031;
    internal const uint SAR_REACH_MAX_CONTAINER_COUNT = 0x0A000032;

    /// <summary>PIN 类型：管理员（SO）PIN。
    /// <para>实机实测（<c>tools\GM3000Probe skfpin</c>）：本 SKF 的 <c>ulPINType</c>
    /// <b>0 = 管理员(SO)、1 = 用户</b>，与 <c>SKF_GetPINInfo</c> / 厂商 PKCS#11
    /// <c>M_GetUserInfo(handle, pinType, ...)</c> 的编号一致。出厂口令：
    /// SO = <c>admin</c>（<c>Initconfig.ini</c> 的 <c>default_sopin</c>）、用户 = <c>12345678</c>。</para></summary>
    internal const uint PinTypeSO = 0;
    /// <summary>PIN 类型：用户 PIN（详见 <see cref="PinTypeSO"/> 的实测说明）。</summary>
    internal const uint PinTypeUser = 1;

    /// <summary>设备默认应用名（<c>SKF_EnumApplication</c> 实测返回 <c>GM3000APP</c>）。</summary>
    internal const string DefaultAppName = "GM3000APP";

    /// <summary>容器名长度上限（反汇编 <c>SKF_CreateContainer</c>：<c>cmp eax,0x27</c>，即 39 字符）。</summary>
    internal const int MaxContainerNameLen = 0x27;

    /// <summary>证书读取缓冲上限（反汇编 <c>SKF_ExportCertificate</c> 内部为 0x4000）。</summary>
    internal const int CertBufferSize = 0x4000;

    /// <summary>把 SKF 返回码翻译成可读文本。</summary>
    internal static string ErrorText(uint rc) => rc switch
    {
        SAR_OK => "成功",
        SAR_FAIL => "通用失败",
        SAR_NOTSUPPORTYETERR => "暂不支持该操作",
        SAR_FILEERR => "文件错误",
        SAR_INVALIDHANDLEERR => "句柄无效（设备/应用未连接或已拔出）",
        SAR_INVALIDPARAMERR => "参数无效",
        SAR_NOTINITIALIZEERR => "未初始化",
        SAR_OBJERR => "对象错误",
        SAR_BUFFER_TOO_SMALL => "缓冲区太小",
        SAR_DEVICE_REMOVED => "设备已被拔出",
        SAR_PIN_INCORRECT => "PIN 不正确",
        SAR_PIN_LOCKED => "PIN 已锁定",
        SAR_PIN_INVALID => "PIN 无效",
        SAR_PIN_LEN_RANGE => "PIN 长度超范围",
        SAR_USER_ALREADY_LOGGED_IN => "用户已登录",
        SAR_USER_PIN_NOT_INITIALIZED => "用户 PIN 未初始化",
        SAR_USER_TYPE_INVALID => "PIN 类型无效",
        SAR_APPLICATION_NAME_INVALID => "应用名无效",
        SAR_APPLICATION_EXISTS => "应用已存在",
        SAR_USER_NOT_LOGGED_IN => "用户未登录（需先验证 PIN）",
        SAR_APPLICATION_NOT_EXISTS => "应用不存在",
        SAR_FILE_ALREADY_EXIST => "文件已存在",
        SAR_NO_ROOM => "空间不足",
        SAR_FILE_NOT_EXIST => "文件不存在",
        SAR_REACH_MAX_CONTAINER_COUNT => "容器数量已达上限",
        _ => $"未知错误 0x{rc:X8}",
    };

    // ======================= 结构 =======================

    /// <summary>
    /// DEVINFO（<c>SKF_GetDevInfo</c> 输出）。布局由实机探针回填的 294 字节数据逐偏移确认：
    /// <c>+0x00</c> 2 字节版本号，随后 64/64/32/32 字节的 4 个定长 ANSI 串，其后为设备能力数据区。
    /// 实机值：Vendor=<c>Longmai</c>、Manufacturer=<c>Longmai</c>、Model=<c>GM3000</c>、
    /// Serial=<c>ED466583B8C689AB81DFA5573DF55AE</c>。
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal struct SkfDevInfo
    {
        /// <summary>+0x00：结构版本（实机 = 1）。</summary>
        public ushort Version;
        /// <summary>+0x02：厂商名（64 字节）。</summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string Vendor;
        /// <summary>+0x42：制造商（64 字节）。</summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string Manufacturer;
        /// <summary>+0x82：型号（32 字节）。</summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string Model;
        /// <summary>+0xA2：序列号（32 字节）。</summary>
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string SerialNumber;
        /// <summary>+0xC2：能力/版本数据区（100 字节，调用方无需解析）。</summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)]
        public byte[] Extra;
    }

    // ======================= 委托定义 =======================

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int EnumDevFn([MarshalAs(UnmanagedType.Bool)] bool present, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int ConnectDevFn(string devName, out IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int DisConnectDevFn(IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetDevInfoFn(IntPtr hDev, ref SkfDevInfo info);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int GetDevStateFn(string devName, out uint state);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int EnumApplicationFn(IntPtr hDev, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int OpenApplicationFn(IntPtr hDev, string appName, out IntPtr hApp);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int CloseApplicationFn(IntPtr hApp);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int EnumContainerFn(IntPtr hApp, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int OpenContainerFn(IntPtr hApp, string contName, out IntPtr hContainer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int CloseContainerFn(IntPtr hContainer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int CreateContainerFn(IntPtr hApp, string contName, out IntPtr hContainer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int DeleteContainerFn(IntPtr hApp, string contName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetContainerTypeFn(IntPtr hContainer, out uint type);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ImportCertificateFn(IntPtr hContainer, [MarshalAs(UnmanagedType.Bool)] bool signFlag,
        byte[] cert, uint certLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ExportCertificateFn(IntPtr hContainer, [MarshalAs(UnmanagedType.Bool)] bool signFlag,
        byte[] cert, ref uint certLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ExportPublicKeyFn(IntPtr hContainer, [MarshalAs(UnmanagedType.Bool)] bool signFlag,
        byte[] blob, ref uint blobLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ImportRSAKeyPairFn(IntPtr hContainer, uint algId, byte[] wrappedKey, uint wrappedKeyLen,
        byte[] encryptedData, uint encryptedDataLen);

    /// <summary>取随机数。首参是<b>设备句柄</b>（实测：传应用句柄会直接崩溃 0xC0000005）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GenRandomFn(IntPtr hDev, byte[] buf, uint len);

    /// <summary>验证 PIN。首参必须是<b>应用句柄</b>：传设备句柄返回
    /// <c>SAR_INVALIDHANDLEERR(0xA000005)</c>，且**不消耗重试次数**（口令根本没送到设备）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int VerifyPinFn(IntPtr hApp, uint pinType, string pin, ref uint retryCount);

    /// <summary>修改 PIN。首参必须是<b>应用句柄</b>（同 <see cref="VerifyPinFn"/>）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int ChangePinFn(IntPtr hApp, uint pinType, string oldPin, string newPin, ref uint retryCount);

    /// <summary>用管理员口令解锁并重设用户 PIN。首参必须是<b>应用句柄</b>（同 <see cref="VerifyPinFn"/>）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int UnblockPinFn(IntPtr hApp, string adminPin, string newUserPin, ref uint retryCount);

    /// <summary>清空安全状态（登出：清除已认证会话）。首参必须是<b>应用句柄</b>（实测传设备句柄返回 0xA000005）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ClearSecureStateFn(IntPtr hApp);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    internal delegate int SetLabelFn(IntPtr hDev, string label);

    /// <summary>
    /// GM3000 扩展：读取 PIN 状态。<c>hApp</c> 需为已打开的应用句柄（实测：传设备句柄返回
    /// <c>0xA000005</c>，传应用句柄返回成功）。
    /// </summary>
    /// <param name="hApp">应用句柄（实测：传设备句柄返回 0xA000005）。</param>
    /// <param name="pinType">0=管理员(SO) PIN，1=用户 PIN（仅接受 0/1，否则 0xA000006）。</param>
    /// <param name="maxRetry">输出：最大重试次数。实测出参顺序是「**上限在前、剩余在后**」。</param>
    /// <param name="remainRetry">输出：剩余重试次数。</param>
    /// <param name="flags">输出：是否为出厂默认口令（实机 = 1），并非「PIN 是否已初始化」。</param>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetPinInfoFn(IntPtr hApp, uint pinType, out uint maxRetry, out uint remainRetry, out uint flags);

    /// <summary>直接透传 APDU（调试/校准用）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int TransmitFn(IntPtr hDev, byte[] command, uint commandLen, byte[] data, ref uint dataLen);

    // ======================= 模块加载 =======================

    /// <summary>候选 DLL 文件名（该模块真名为 mtoken_gm3000；2016 版在 2.1.1.0 目录里叫 mtoken_GM.dll）。</summary>
    private static readonly string[] FileNames = { "mtoken_gm3000.dll", "mtoken_GM.dll" };

    /// <summary>
    /// 查找可用的 SKF 模块。优先级：
    /// ① <paramref name="libraryRoot"/>\GM3000\；
    /// ② <paramref name="libraryRoot"/>；
    /// ③ 进程目录\Library\GM3000；
    /// ④ 系统 SysWOW64（厂商安装版）。
    /// </summary>
    internal static string? FindModulePath(string libraryRoot)
    {
        var roots = new List<string>();
        if (!string.IsNullOrWhiteSpace(libraryRoot))
        {
            roots.Add(Path.Combine(libraryRoot, "GM3000"));
            roots.Add(libraryRoot);
        }
        roots.Add(Path.Combine(AppContext.BaseDirectory, "Library", "GM3000"));
        roots.Add(Path.Combine(AppContext.BaseDirectory, "Library"));

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var name in FileNames)
            {
                var p = Path.Combine(root, name);
                if (File.Exists(p)) return p;
            }
        }

        // 厂商安装版（32 位进程下 SysWOW64 即系统目录）
        try
        {
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            foreach (var name in FileNames)
            {
                var p = Path.Combine(sys, name);
                if (File.Exists(p)) return p;
            }
        }
        catch
        {
            // 忽略：仅作为兜底
        }
        return null;
    }

    /// <summary>加载模块（<paramref name="libraryRoot"/> 为 Library 根目录）。</summary>
    internal static NativeDll.Module? Load(string libraryRoot)
    {
        var path = FindModulePath(libraryRoot);
        return path == null ? null : NativeDll.Load(path);
    }
}
