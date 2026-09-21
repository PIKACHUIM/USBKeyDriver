using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// SKF（<b>GM/T 0016-2012 智能密码钥匙密码应用接口规范</b>）原生封装。
///
/// <para><b>为什么需要它：</b>BJCA 的 <c>XTXAppCOM</c> 组件虽然能重置设备，
/// 但它的「登录 / 改密 / 导出证书」依赖一个由客户端维护的证书缓存（<c>SOF_GetUserList</c> 恒为空，
/// 拿不到 <c>CertID</c>，见 <c>Roadmap/07-BJCA逆向分析与对接.md</c> §8.3）。
/// 而 <c>Driver\driver.ini</c> 显示设备（如林果 LG3073，<c>6588:1514</c>）的 <c>type = SKF</c>，
/// 组件内部同样走 <c>SKF_OpenApplication / SKF_VerifyPIN / SKF_CreateApplication …</c>。
/// 因此<b>直接 P/Invoke 厂商 SKF 中间件</b>即可拿到「登录/改密/解锁/容器/证书」全套能力，
/// 且不依赖任何 BJCA 缓存。</para>
///
/// <para><b>实测结论（林果 <c>lgu3073_p1514_gm.dll</c>，x86）：</b>
/// 全部 40 余个所用接口的参数个数与 GM/T 0016 国标签名<b>完全一致</b>
/// （已用 <c>tools/bjca_analyze.py argcounts</c> 的 <c>ret imm16</c> 逐条核对），
/// 故此处直接按国标签名声明。</para>
/// </summary>
internal static class SkfNative
{
    /// <summary>SKF 成功返回码。</summary>
    internal const uint SAR_OK = 0x00000000;

    /// <summary>PIN 类型：管理员（SO PIN）。国标取值见 <see cref="PinTypeAdmin"/>。</summary>
    internal const uint PinTypeAdmin = 1;

    /// <summary>PIN 类型：用户。</summary>
    internal const uint PinTypeUser = 2;

    /// <summary>SKF 返回码文案（回退表；优先用 <see cref="LoadErrorMap"/> 读厂商 errorinfo.json）。</summary>
    private static readonly Dictionary<uint, string> FallbackErrors = new()
    {
        [0x00000000] = "成功",
        [0x0A000001] = "操作失败",
        [0x0A000002] = "未知错误",
        [0x0A000003] = "暂不支持的接口",
        [0x0A000004] = "文件操作错误",
        [0x0A000005] = "无效的句柄",
        [0x0A000006] = "无效的参数",
        [0x0A000007] = "读文件错误",
        [0x0A000008] = "写文件错误",
        [0x0A000009] = "名称长度错误",
        [0x0A00000A] = "密钥用途错误",
        [0x0A00000B] = "模长度错误",
        [0x0A00000C] = "未初始化",
        [0x0A00000D] = "对象错误",
        [0x0A00000E] = "内存错误",
        [0x0A00000F] = "超时",
        [0x0A000010] = "输入数据长度错误",
        [0x0A000011] = "输入数据错误",
        [0x0A000012] = "产生随机数错误",
        [0x0A000013] = "哈希对象错误",
        [0x0A000014] = "哈希运算错误",
        [0x0A000015] = "产生 RSA 密钥错误",
        [0x0A00001B] = "密钥未找到",
        [0x0A00001C] = "证书未找到",
        [0x0A000024] = "认证失败",
        [0x0A000025] = "签名错误",
        [0x0A000026] = "验签错误",
        [0x0A000027] = "文件格式错误",
        [0x0A000030] = "PIN 长度错误",
        [0x0A000031] = "PIN 错误",
        [0x0A000032] = "PIN 已锁定",
        [0x0A000033] = "已经初始化",
    };

    private static Dictionary<uint, string>? _vendorErrors;

    /// <summary>
    /// 尝试从厂商客户端目录加载 <c>errorinfo.json</c>（GBK 编码）作为错误码文案表。
    /// 目录按「SKF DLL 所在目录 → 其上级若干层」搜索；找不到则返回 null（使用内置回退表）。
    /// </summary>
    internal static void TryLoadVendorErrorMap(string skfDllPath)
    {
        if (_vendorErrors != null) return;
        try
        {
            var encoding = GetChineseEncoding();
            var dir = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(skfDllPath))!);
            for (int depth = 0; depth < 4 && dir != null; depth++, dir = dir.Parent)
            {
                var hit = dir.GetFiles("errorinfo.json", SearchOption.AllDirectories).FirstOrDefault();
                if (hit == null) continue;
                var json = File.ReadAllText(hit.FullName, encoding);
                var map = new Dictionary<uint, string>();
                foreach (var item in System.Text.Json.JsonDocument.Parse(json).RootElement.EnumerateObject())
                {
                    if (!item.Name.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!uint.TryParse(item.Name.AsSpan(2), System.Globalization.NumberStyles.HexNumber,
                            null, out var code)) continue;
                    if (item.Value.TryGetProperty("info", out var info))
                        map[code] = info.GetString() ?? "";
                }
                if (map.Count > 0) { _vendorErrors = map; return; }
            }
        }
        catch { /* 忽略，使用回退表 */ }
    }

    private static Encoding GetChineseEncoding()
    {
        try
        {
            Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(936);   // GBK
        }
        catch { return Encoding.Latin1; }
    }

    /// <summary>把 SKF 返回码转成可读文案。</summary>
    internal static string Describe(uint rc)
    {
        if (rc == SAR_OK) return "成功";
        if (_vendorErrors != null && _vendorErrors.TryGetValue(rc, out var s) && !string.IsNullOrWhiteSpace(s))
            return $"{s}（0x{rc:X8}）";
        if (FallbackErrors.TryGetValue(rc, out var f))
            return $"{f}（0x{rc:X8}）";
        return $"SKF 错误 0x{rc:X8}";
    }

    // ------------------------------------------------------------ 委托（x86 __stdcall）
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint EnumDevFn(int bPresent, IntPtr pszNameList, ref uint pulSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint ConnectDevFn(IntPtr szName, out IntPtr phDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint HandleFn(IntPtr h);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint HandleUintFn(IntPtr h, ref uint value);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GetDevStateFn(IntPtr szDevName, ref uint pulDevState);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GetDevInfoFn(IntPtr hDev, IntPtr pDevInfo);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint Str2Fn(IntPtr h, IntPtr sz);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint HandleUint2Fn(IntPtr h, uint a, ref uint b);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint TransmitFn(IntPtr hDev, byte[] pbCommand, uint ulCommandLen, byte[]? pbData, ref uint pulDataLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint VerifyPinFn(IntPtr hApp, uint ulPinType, IntPtr szPin, ref uint pulRetryCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint ChangePinFn(IntPtr hApp, uint ulPinType, IntPtr szOldPin, IntPtr szNewPin, ref uint pulRetryCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint UnblockPinFn(IntPtr hApp, IntPtr szAdminPin, IntPtr szNewUserPin, ref uint pulRetryCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GetPinInfoFn(IntPtr hApp, uint ulPinType, ref uint pulMaxRetry,
                                        ref uint pulRemainRetry, ref int pbDefaultPin);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint Enum3Fn(IntPtr h, IntPtr szList, ref uint pulSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint OpenContainerFn(IntPtr hApp, IntPtr szName, out IntPtr phContainer);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint CreateApplicationFn(IntPtr hDev, IntPtr szAppName, IntPtr szAdminPin,
        uint dwAdminPinRetryCount, IntPtr szUserPin, uint dwUserPinRetryCount,
        uint dwCreateFileRights, out IntPtr phApplication);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint ImportCertFn(IntPtr hContainer, int bSignFlag, byte[] pbCert, uint ulCertLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint ExportCertFn(IntPtr hContainer, int bSignFlag, byte[] pbCert, ref uint pulCertLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint ExportPubKeyFn(IntPtr hContainer, int bSignFlag, byte[] pbBlob, ref uint pulBlobLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GenRsaKeyPairFn(IntPtr hContainer, uint ulBitsLen, byte[] pbBlob);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GenEccKeyPairFn(IntPtr hContainer, uint ulAlgID, byte[] pbBlob);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate uint GenRandomFn(IntPtr hDev, byte[] pbRandom, uint ulRandomLen);

    /// <summary>设备信息（GM/T 0016 SKF_DEVINFO）。为避免尾部字段差异，按标准偏移解析。</summary>
    internal sealed class SkfDevInfo
    {
        public uint Version { get; init; }
        public string Label { get; init; } = "";
        public string Manufacturer { get; init; } = "";
        public string Issuer { get; init; } = "";
        public string SerialNumber { get; init; } = "";
        public uint HwVersion { get; init; }
        public uint FirmwareVersion { get; init; }
        public uint AlgSymCap { get; init; }
        public uint AlgAsymCap { get; init; }
        public uint AlgHashCap { get; init; }
        public uint DevAuthAlgId { get; init; }
        public uint ChannelMaxBufLen { get; init; }

        public override string ToString() =>
            $"Label={Label} 厂商={Manufacturer} 序列号={SerialNumber} " +
            $"HW=0x{HwVersion:X} FW=0x{FirmwareVersion:X} 对称={AlgSymCap:X} 非对称={AlgAsymCap:X} 摘要={AlgHashCap:X}";
    }
}

/// <summary>
/// SKF 会话：加载厂商 SKF 中间件（如 <c>lgu3073_p1514_gm.dll</c>）并提供国标接口的强类型封装。
/// 非线程安全；调用方需自行串行化（<see cref="SkfProvider"/> 内部有锁）。
/// </summary>
internal sealed class SkfSession : IDisposable
{
    private readonly NativeDll.Module _module;
    private readonly ConcurrentDictionary<string, Delegate> _cache = new();
    private readonly Encoding _ansi;
    private bool _disposed;

    /// <summary>SKF 中间件完整路径。</summary>
    public string DllPath { get; }

    public SkfSession(string dllPath)
    {
        DllPath = dllPath;
        _module = NativeDll.Load(dllPath)
            ?? throw new InvalidOperationException($"无法加载 SKF 中间件 {dllPath}（请确认位数与宿主一致）");
        SkfNative.TryLoadVendorErrorMap(dllPath);
        _ansi = GetAnsiEncoding();
    }

    private static Encoding GetAnsiEncoding()
    {
        try
        {
            Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding(936);
        }
        catch { return Encoding.Latin1; }
    }

    /// <summary>该 DLL 是否导出了 SKF 接口（用于 IsAvailable 判定）。</summary>
    public bool HasExport(string name) => _module.HasExport(name);

    private T Fn<T>(string name) where T : Delegate
        => (T)_cache.GetOrAdd(name, n => _module.GetDelegate<T>(n)
            ?? throw new MissingMethodException($"SKF 中间件未导出 {n}"));

    // ---------------- 字符串/缓冲辅助 ----------------
    private IntPtr AllocAnsi(string? s, int padBytes = 0)
    {
        var bytes = _ansi.GetBytes(s ?? "");
        var buf = Marshal.AllocHGlobal(bytes.Length + 1 + padBytes);
        Marshal.Copy(bytes, 0, buf, bytes.Length);
        Marshal.WriteByte(buf, bytes.Length, 0);
        for (int i = 1; i <= padBytes; i++) Marshal.WriteByte(buf, bytes.Length + i, 0);
        return buf;
    }

    private string ReadAnsi(IntPtr p)
    {
        if (p == IntPtr.Zero) return "";
        int len = 0;
        while (Marshal.ReadByte(p, len) != 0) len++;
        var bytes = new byte[len];
        Marshal.Copy(p, bytes, 0, len);
        return _ansi.GetString(bytes);
    }

    // ============================================================ 设备

    /// <summary>SKF_EnumDev(bPresent, pszNameList, pulSize) —— 返回以 '\0' 分隔的设备名列表。</summary>
    public (uint Rc, List<string> Names) EnumDev(bool present = true)
    {
        uint size = 0;
        var rc = Fn<SkfNative.EnumDevFn>("SKF_EnumDev")(present ? 1 : 0, IntPtr.Zero, ref size);
        if (rc != SkfNative.SAR_OK || size == 0) return (rc, new List<string>());

        var buf = Marshal.AllocHGlobal((int)size + 2);
        try
        {
            for (int i = 0; i < (int)size + 2; i++) Marshal.WriteByte(buf, i, 0);
            rc = Fn<SkfNative.EnumDevFn>("SKF_EnumDev")(present ? 1 : 0, buf, ref size);
            if (rc != SkfNative.SAR_OK) return (rc, new List<string>());

            var names = new List<string>();
            int off = 0;
            while (off < size)
            {
                int len = 0;
                while (off + len < size && Marshal.ReadByte(buf, off + len) != 0) len++;
                if (len == 0) break;
                var bytes = new byte[len];
                Marshal.Copy(buf + off, bytes, 0, len);
                names.Add(_ansi.GetString(bytes));
                off += len + 1;
            }
            return (rc, names);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public (uint Rc, IntPtr Dev) ConnectDev(string name)
    {
        var p = AllocAnsi(name);
        try
        {
            var rc = Fn<SkfNative.ConnectDevFn>("SKF_ConnectDev")(p, out var h);
            return (rc, h);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    public uint DisConnectDev(IntPtr hDev) => Fn<SkfNative.HandleFn>("SKF_DisConnectDev")(hDev);

    public (uint Rc, string Name) GetDevNameByState(bool present = true)
    {
        var (rc, names) = EnumDev(present);
        return (rc, names.FirstOrDefault() ?? "");
    }

    /// <summary>SKF_GetDevState(szDevName, pulDevState)：0=不存在 1=已插入 2=已锁定。</summary>
    public (uint Rc, uint State) GetDevState(string devName)
    {
        var p = AllocAnsi(devName);
        try
        {
            uint st = 0;
            var rc = Fn<SkfNative.GetDevStateFn>("SKF_GetDevState")(p, ref st);
            return (rc, st);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    /// <summary>SKF_GetDevInfo 原始字节（用于核对厂商结构体偏移）。给足余量避免厂商结构体偏大时越界写。</summary>
    public (uint Rc, byte[] Raw) GetDevInfoRaw(IntPtr hDev, int size = 4096)
    {
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
            var rc = Fn<SkfNative.GetDevInfoFn>("SKF_GetDevInfo")(hDev, buf);
            var raw = new byte[size];
            Marshal.Copy(buf, raw, 0, size);
            return (rc, raw);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>SKF_GetDevInfo(hDev, DEVINFO*) —— 按国标偏移解析。</summary>
    public (uint Rc, SkfNative.SkfDevInfo? Info) GetDevInfo(IntPtr hDev)
    {
        const int size = 4096;  // 国标约 224 字节；本厂商结构体明显更大（256 字节会越界写），给足余量
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
            var rc = Fn<SkfNative.GetDevInfoFn>("SKF_GetDevInfo")(hDev, buf);
            if (rc != SkfNative.SAR_OK) return (rc, null);

            string Str(int off, int max)
            {
                int len = 0;
                while (len < max && Marshal.ReadByte(buf, off + len) != 0) len++;
                var b = new byte[len];
                Marshal.Copy(buf + off, b, 0, len);
                return _ansi.GetString(b);
            }

            // ⚠️ 偏移按「实测转储」而定，非国标：
            //   0x00 USHORT Version；0x02 Label[64]；0x42 Manufacturer[64]；
            //   0x82 Issuer[32]；0xA2 SerialNumber[32]；0xC2 起为数值区。
            //   （国标为 ULONG Version + Label[32]+Manufacturer[64]+Issuer[64]+SerialNumber[32]，
            //     本厂商中间件是它的变体；256 字节缓冲区会被越界写，故必须给足余量。）
            var info = new SkfNative.SkfDevInfo
            {
                Version = (uint)Marshal.ReadInt16(buf, 0x00),
                Label = Str(0x02, 64),
                Manufacturer = Str(0x42, 64),
                Issuer = Str(0x82, 32),
                SerialNumber = Str(0xA2, 32),
                HwVersion = (uint)Marshal.ReadInt32(buf, 0xC2),
                FirmwareVersion = (uint)Marshal.ReadInt32(buf, 0xC6),
                AlgSymCap = (uint)Marshal.ReadInt32(buf, 0xCA),
                AlgAsymCap = (uint)Marshal.ReadInt32(buf, 0xCE),
                AlgHashCap = (uint)Marshal.ReadInt32(buf, 0xD2),
                DevAuthAlgId = (uint)Marshal.ReadInt32(buf, 0xD6),
                ChannelMaxBufLen = (uint)Marshal.ReadInt32(buf, 0xDA),
            };
            return (rc, info);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>SKF_SetLabel(hDev, szLabel)。</summary>
    public uint SetLabel(IntPtr hDev, string label)
    {
        var p = AllocAnsi(label);
        try { return Fn<SkfNative.Str2Fn>("SKF_SetLabel")(hDev, p); }
        finally { Marshal.FreeHGlobal(p); }
    }

    /// <summary>SKF_GenRandom(hDev, pbRandom, len)。</summary>
    public (uint Rc, byte[] Data) GenRandom(IntPtr hDev, int len)
    {
        var buf = new byte[len];
        var rc = Fn<SkfNative.GenRandomFn>("SKF_GenRandom")(hDev, buf, (uint)len);
        return (rc, buf);
    }

    /// <summary>SKF_Transmit —— 透传 APDU。</summary>
    public (uint Rc, byte[] Data) Transmit(IntPtr hDev, byte[] command, uint maxOut = 4096)
    {
        var outp = new byte[maxOut];
        uint len = maxOut;
        var rc = Fn<SkfNative.TransmitFn>("SKF_Transmit")(hDev, command, (uint)command.Length, outp, ref len);
        if (len > outp.Length) len = (uint)outp.Length;
        return (rc, outp.AsSpan(0, (int)len).ToArray());
    }

    // ============================================================ 应用

    /// <summary>SKF_OpenApplication(hDev, szAppName, phApplication)。</summary>
    public (uint Rc, IntPtr App) OpenApplication(IntPtr hDev, string appName)
    {
        var p = AllocAnsi(appName);
        try
        {
            var rc = Fn<SkfNative.OpenContainerFn>("SKF_OpenApplication")(hDev, p, out var h);
            return (rc, h);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    public uint CloseApplication(IntPtr hApp) => Fn<SkfNative.HandleFn>("SKF_CloseApplication")(hApp);

    /// <summary>SKF_EnumApplication(hDev, szAppNameList, pulSize)。</summary>
    public (uint Rc, List<string> Names) EnumApplication(IntPtr hDev) => EnumList("SKF_EnumApplication", hDev);

    /// <summary>SKF_DeleteApplication(hDev, szAppName)：删除应用 = 清空该应用下全部容器/文件/证书。</summary>
    public uint DeleteApplication(IntPtr hDev, string appName)
    {
        var p = AllocAnsi(appName);
        try { return Fn<SkfNative.Str2Fn>("SKF_DeleteApplication")(hDev, p); }
        finally { Marshal.FreeHGlobal(p); }
    }

    /// <summary>SKF_CreateApplication(hDev, app, adminPin, adminRetry, userPin, userRetry, fileRights, phApp)。</summary>
    public (uint Rc, IntPtr App) CreateApplication(IntPtr hDev, string appName, string adminPin,
        uint adminRetry, string userPin, uint userRetry, uint fileRights = 0x02)
    {
        var pa = AllocAnsi(appName);
        var padm = AllocAnsi(adminPin);
        var pusr = AllocAnsi(userPin);
        try
        {
            var rc = Fn<SkfNative.CreateApplicationFn>("SKF_CreateApplication")(
                hDev, pa, padm, adminRetry, pusr, userRetry, fileRights, out var h);
            return (rc, h);
        }
        finally
        {
            Marshal.FreeHGlobal(pa);
            Marshal.FreeHGlobal(padm);
            Marshal.FreeHGlobal(pusr);
        }
    }

    // ============================================================ PIN / 权限

    /// <summary>SKF_VerifyPIN(hApp, ulPinType, szPIN, pulRetryCount)。</summary>
    public (uint Rc, uint RemainRetry) VerifyPin(IntPtr hApp, uint pinType, string pin)
    {
        var p = AllocAnsi(pin);
        try
        {
            uint retry = 0;
            var rc = Fn<SkfNative.VerifyPinFn>("SKF_VerifyPIN")(hApp, pinType, p, ref retry);
            return (rc, retry);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    /// <summary>SKF_ChangePIN(hApp, ulPinType, szOldPin, szNewPin, pulRetryCount)。</summary>
    public (uint Rc, uint RemainRetry) ChangePin(IntPtr hApp, uint pinType, string oldPin, string newPin)
    {
        var po = AllocAnsi(oldPin);
        var pn = AllocAnsi(newPin);
        try
        {
            uint retry = 0;
            var rc = Fn<SkfNative.ChangePinFn>("SKF_ChangePIN")(hApp, pinType, po, pn, ref retry);
            return (rc, retry);
        }
        finally
        {
            Marshal.FreeHGlobal(po);
            Marshal.FreeHGlobal(pn);
        }
    }

    /// <summary>SKF_UnblockPIN(hApp, szAdminPIN, szNewUserPIN, pulRetryCount) —— 用管理 PIN 解锁并重设用户 PIN。</summary>
    public (uint Rc, uint RemainRetry) UnblockPin(IntPtr hApp, string adminPin, string newUserPin)
    {
        var pa = AllocAnsi(adminPin);
        var pn = AllocAnsi(newUserPin);
        try
        {
            uint retry = 0;
            var rc = Fn<SkfNative.UnblockPinFn>("SKF_UnblockPIN")(hApp, pa, pn, ref retry);
            return (rc, retry);
        }
        finally
        {
            Marshal.FreeHGlobal(pa);
            Marshal.FreeHGlobal(pn);
        }
    }

    /// <summary>SKF_GetPINInfo(hApp, ulPinType, maxRetry, remainRetry, bDefaultPin)。</summary>
    public (uint Rc, uint MaxRetry, uint RemainRetry, bool IsDefault) GetPinInfo(IntPtr hApp, uint pinType)
    {
        uint max = 0, remain = 0;
        int def = 0;
        var rc = Fn<SkfNative.GetPinInfoFn>("SKF_GetPINInfo")(hApp, pinType, ref max, ref remain, ref def);
        return (rc, max, remain, def != 0);
    }

    /// <summary>SKF_ClearSecureState(hApp)。</summary>
    public uint ClearSecureState(IntPtr hApp) => Fn<SkfNative.HandleFn>("SKF_ClearSecureState")(hApp);

    // ============================================================ 容器 / 证书

    /// <summary>SKF_EnumContainer(hApp, szNameList, pulSize)。</summary>
    public (uint Rc, List<string> Names) EnumContainer(IntPtr hApp) => EnumList("SKF_EnumContainer", hApp);

    /// <summary>SKF_EnumFiles(hApp, szFileList, pulSize)。</summary>
    public (uint Rc, List<string> Names) EnumFiles(IntPtr hApp) => EnumList("SKF_EnumFiles", hApp);

    /// <summary>SKF_DeleteFile(hApp, szFileName)。</summary>
    public uint DeleteFile(IntPtr hApp, string fileName)
    {
        var p = AllocAnsi(fileName);
        try { return Fn<SkfNative.Str2Fn>("SKF_DeleteFile")(hApp, p); }
        finally { Marshal.FreeHGlobal(p); }
    }

    public (uint Rc, IntPtr Container) CreateContainer(IntPtr hApp, string name)
    {
        var p = AllocAnsi(name);
        try
        {
            var rc = Fn<SkfNative.OpenContainerFn>("SKF_CreateContainer")(hApp, p, out var h);
            return (rc, h);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    public uint DeleteContainer(IntPtr hApp, string name)
    {
        var p = AllocAnsi(name);
        try { return Fn<SkfNative.Str2Fn>("SKF_DeleteContainer")(hApp, p); }
        finally { Marshal.FreeHGlobal(p); }
    }

    public (uint Rc, IntPtr Container) OpenContainer(IntPtr hApp, string name)
    {
        var p = AllocAnsi(name);
        try
        {
            var rc = Fn<SkfNative.OpenContainerFn>("SKF_OpenContainer")(hApp, p, out var h);
            return (rc, h);
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    public uint CloseContainer(IntPtr hContainer) => Fn<SkfNative.HandleFn>("SKF_CloseContainer")(hContainer);

    /// <summary>SKF_GetContainerType(hContainer, pulContainerType)：1=未定 2=RSA 3=ECC。</summary>
    public (uint Rc, uint Type) GetContainerType(IntPtr hContainer)
    {
        uint t = 0;
        var rc = Fn<SkfNative.HandleUintFn>("SKF_GetContainerType")(hContainer, ref t);
        return (rc, t);
    }

    /// <summary>SKF_ImportCertificate(hContainer, bSignFlag, pbCert, ulCertLen)。</summary>
    public uint ImportCertificate(IntPtr hContainer, bool sign, byte[] certDer) =>
        Fn<SkfNative.ImportCertFn>("SKF_ImportCertificate")(hContainer, sign ? 1 : 0, certDer, (uint)certDer.Length);

    /// <summary>SKF_ExportCertificate(hContainer, bSignFlag, pbCert, pulCertLen)。</summary>
    public (uint Rc, byte[] Data) ExportCertificate(IntPtr hContainer, bool sign)
    {
        uint len = 8192;
        var buf = new byte[len];
        var rc = Fn<SkfNative.ExportCertFn>("SKF_ExportCertificate")(hContainer, sign ? 1 : 0, buf, ref len);
        if (len > buf.Length) len = (uint)buf.Length;
        return (rc, buf.AsSpan(0, (int)len).ToArray());
    }

    /// <summary>SKF_ExportPublicKey(hContainer, bSignFlag, pbBlob, pulBlobLen)。</summary>
    public (uint Rc, byte[] Data) ExportPublicKey(IntPtr hContainer, bool sign)
    {
        uint len = 8192;
        var buf = new byte[len];
        var rc = Fn<SkfNative.ExportPubKeyFn>("SKF_ExportPublicKey")(hContainer, sign ? 1 : 0, buf, ref len);
        if (len > buf.Length) len = (uint)buf.Length;
        return (rc, buf.AsSpan(0, (int)len).ToArray());
    }

    /// <summary>SKF_GenRSAKeyPair(hContainer, ulBitsLen, pBlob)。</summary>
    public (uint Rc, byte[] Blob) GenRsaKeyPair(IntPtr hContainer, uint bits)
    {
        var buf = new byte[2048];
        var rc = Fn<SkfNative.GenRsaKeyPairFn>("SKF_GenRSAKeyPair")(hContainer, bits, buf);
        return (rc, buf);
    }

    /// <summary>SKF_GenECCKeyPair(hContainer, ulAlgID, pBlob)。</summary>
    public (uint Rc, byte[] Blob) GenEccKeyPair(IntPtr hContainer, uint algId)
    {
        var buf = new byte[2048];
        var rc = Fn<SkfNative.GenEccKeyPairFn>("SKF_GenECCKeyPair")(hContainer, algId, buf);
        return (rc, buf);
    }

    // ---------------- 通用列表枚举（EnumApplication / EnumContainer / EnumFiles 同构） ----------------
    private (uint Rc, List<string> Names) EnumList(string fnName, IntPtr h)
    {
        uint size = 0;
        var rc = Fn<SkfNative.Enum3Fn>(fnName)(h, IntPtr.Zero, ref size);
        if (rc != SkfNative.SAR_OK || size == 0) return (rc, new List<string>());

        var buf = Marshal.AllocHGlobal((int)size + 2);
        try
        {
            for (int i = 0; i < (int)size + 2; i++) Marshal.WriteByte(buf, i, 0);
            rc = Fn<SkfNative.Enum3Fn>(fnName)(h, buf, ref size);
            if (rc != SkfNative.SAR_OK) return (rc, new List<string>());

            var names = new List<string>();
            int off = 0;
            while (off < size)
            {
                int len = 0;
                while (off + len < size && Marshal.ReadByte(buf, off + len) != 0) len++;
                if (len == 0) break;
                var bytes = new byte[len];
                Marshal.Copy(buf + off, bytes, 0, len);
                names.Add(_ansi.GetString(bytes));
                off += len + 1;
            }
            return (rc, names);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cache.Clear();
        _module.Dispose();
    }
}
