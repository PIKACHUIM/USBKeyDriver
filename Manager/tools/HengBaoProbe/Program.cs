using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// 恒宝（HengBao）CMBC U 宝 / PKCS#11 探针。
///
/// 逆向要点（2026-09-20，IDA Pro 8.3 静态分析）：
///  · CMBCp.dll 的 68 个 C_* 导出全部是 __cdecl（函数尾为裸 retn），
///    用 StdCall 委托会栈失衡并得到随机错误码 —— 本探针统一使用 Cdecl。
///  · C_GetSlotList 返回的“槽位”其实是设备路径字符串指针（Win32 下 4 字节），
///    必须原样回传，不能当索引重建。C_GetSlotInfo 是硬编码信息；
///    C_GetTokenInfo / C_OpenSession 才会真正打开设备（失败返回 6=CKR_FUNCTION_FAILED）。
///  · C_InitToken / C_InitPIN 是 mov eax,54h; retn 的桩函数（CKR_FUNCTION_NOT_SUPPORTED），
///    因此本设备不能用 PKCS#11 做令牌初始化；重置只能「删除全部对象 + C_SetPIN 改口令」。
///  · C_Login 仅接受 CKU_USER(1)，没有 SO/PUK 概念。
///  · 官方出厂口令为 111111（6 位）。
///
/// 用法：
///   HengBaoProbe.exe [dllPath] [pin] [选项]
/// 选项：
///   --list            只枚举/读信息（默认行为，不写入）
///   --changepin  新PIN 执行 C_SetPIN（会真的改口令）
///   --erase-all      删除设备上全部对象（清空内容，会真的写入）
///   --reset 新PIN     等价于 --erase-all + --changepin 新PIN（清空 + 重设口令）
///   --sign           用设备内私钥做一次 SHA1/SHA256 RSA 签名自检
///   --probe-init     探测 C_InitToken/C_InitPIN（危险：非桩实现上会清空令牌，默认关闭）
///   --scan           只做设备接口扫描：复刻 CMBCp.dll 的 THidTSP/CTSPBot 枚举逻辑，
///                    打印所有 HID / CD-ROM 设备接口与 VID/PID，判断令牌通道是否存在
///   --import-pfx <file> [--pfx-pwd <pwd>] [--cert-only]
///                    导入 PKCS#12：写证书对象 + 尝试写私钥对象（最小/完整模板各试一次并打印返回码）
///   --pfx-info <file> [--pfx-pwd <pwd>]
///                    仅本地解析 PKCS#12（不访问设备），校验口令并打印证书/CKA_ID/私钥信息
///   --yes            删除对象（--erase-all / --reset）时不再交互确认，用于无人值守脚本
///   --raw [--apdu HEX]
///                    绕开 CMBCp.dll，直接复刻其设备层（SCSI-BOT 透传）与设备对话：
///                    ① 枚举 GUID_DEVINTERFACE_CDROM/DISK 并按 "HENGBAO" 过滤（与 DLL 一致）；
///                    ② 用 SCSI INQUIRY 验证直通通道是否可用；
///                    ③ 用厂商命令 FA3A(写)/FA08(读) 发送 --apdu 指定的 APDU 并打印原始响应与 SW。
///                    用途：判定 SW=6E00 是「透传没通」还是「卡片真的回 6E00」，
///                    也是后续实现厂商「初始化 U 宝」（恢复出厂态）的前置能力。需要管理员权限。
///   --brute [--cla 0080]
///                    遍历 CLA(默认 00/80/84/90/FF) × INS(00..FF)，打印所有 SW != 6E00 的组合，
///                    用于找出卡片真正识别哪些指令（6E00 是本 COS 的通用「不识别」码）。
///   --cdb-scan       扫描 TargetId/Lun 与 CDB[1] 子命令（找复位/上电类命令）。
///                    注意：会给设备发 254 种未定义 CDB，实测会触发超时并把设备短暂卡住
///                    （随后自动恢复），不要在正常业务过程中运行。
///   --msp-open [--apdu HEX]
///                    复刻厂商 MSP 安全报文：明文握手（80F2/80F4）→ RSA 交换 16 字节会话密钥
///                    （EM=00 02||01×109||00||K，c=EM^65537 mod n）→ 用 3DES-ECB(0x80 位填充)
///                    封装 APDU 并解密响应。这是 PKCS#11 打不开令牌的真正缺口。需管理员权限。
/// </summary>
internal static class Program
{
    // ---------------- PKCS#11 常量 ----------------
    private const uint CKA_CLASS = 0x00000000;
    private const uint CKA_TOKEN = 0x00000001;
    private const uint CKA_PRIVATE = 0x00000002;
    private const uint CKA_LABEL = 0x00000003;
    private const uint CKA_VALUE = 0x00000011;
    private const uint CKA_CERTIFICATE_TYPE = 0x00000080;
    private const uint CKA_KEY_TYPE = 0x00000100;
    private const uint CKA_ID = 0x00000102;
    private const uint CKA_MODULUS = 0x00000120;
    private const uint CKA_PUBLIC_EXPONENT = 0x00000122;
    private const uint CKA_PRIVATE_EXPONENT = 0x00000123;
    private const uint CKA_PRIME_1 = 0x00000124;
    private const uint CKA_PRIME_2 = 0x00000125;
    private const uint CKA_EXPONENT_1 = 0x00000126;
    private const uint CKA_EXPONENT_2 = 0x00000127;
    private const uint CKA_COEFFICIENT = 0x00000128;
    private const uint CKC_X_509 = 0x00000000;
    private const uint CKK_RSA = 0x00000000;
    private const uint CKO_DATA = 0x00000000;
    private const uint CKO_CERTIFICATE = 0x00000001;
    private const uint CKO_PUBLIC_KEY = 0x00000002;
    private const uint CKO_PRIVATE_KEY = 0x00000003;
    private const uint CKU_USER = 1;
    private const uint CKF_SERIAL_SESSION = 0x00000004;
    private const uint CKF_RW_SESSION = 0x00000002;
    private const uint CKM_SHA1_RSA_PKCS = 0x00000006;
    private const uint CKM_SHA256_RSA_PKCS = 0x00000040;
    private const uint CKR_OK = 0x00000000;
    private const uint CKR_USER_ALREADY_LOGGED_IN = 0x00000100;
    private const uint CKR_BUFFER_TOO_SMALL = 0x00000150;
    private const uint CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012;
    private const uint CKR_ATTRIBUTE_SENSITIVE = 0x00000011;
    private const uint CKR_OBJECT_HANDLE_INVALID = 0x00000082;

    // ---------------- 结构体 ----------------
    [StructLayout(LayoutKind.Sequential)]
    private struct CK_ATTRIBUTE { public uint type; public IntPtr pValue; public uint ulValueLen; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CK_MECHANISM { public uint mechanism; public IntPtr pParameter; public uint ulParameterLen; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CK_VERSION { public byte major; public byte minor; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CK_SLOT_INFO
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)] public byte[] slotDescription;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] manufacturerID;
        public uint flags;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CK_TOKEN_INFO
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] label;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] manufacturerID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] model;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] serialNumber;
        public uint flags;
        public uint ulMaxSessionCount;
        public uint ulSessionCount;
        public uint ulMaxRwSessionCount;
        public uint ulRwSessionCount;
        public uint ulMaxPinLen;
        public uint ulMinPinLen;
        public uint ulTotalPublicMemory;
        public uint ulFreePublicMemory;
        public uint ulTotalPrivateMemory;
        public uint ulFreePrivateMemory;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] utcTime;
    }

    // ---------------- 委托（全部 __cdecl！） ----------------
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_InitializeFn(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_FinalizeFn(IntPtr p);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_GetSlotListFn(byte present, uint[] slots, ref uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_GetSlotInfoFn(uint slot, ref CK_SLOT_INFO info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_GetTokenInfoFn(uint slot, ref CK_TOKEN_INFO info);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_OpenSessionFn(uint slot, uint flags, IntPtr app, IntPtr notify, ref uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_CloseSessionFn(uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_LoginFn(uint session, uint userType, byte[] pin, uint pinLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_LogoutFn(uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_SetPINFn(uint session, byte[] oldPin, uint oldLen, byte[] newPin, uint newLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_InitTokenFn(uint slot, byte[] pin, uint pinLen, byte[] label);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_InitPINFn(uint session, byte[] pin, uint pinLen);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_GetAttributeValueFn(uint session, uint obj, CK_ATTRIBUTE[] tmpl, uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_FindObjectsInitFn(uint session, CK_ATTRIBUTE[] tmpl, uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_FindObjectsFn(uint session, uint[] objs, uint max, ref uint count);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_FindObjectsFinalFn(uint session);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_DestroyObjectFn(uint session, uint obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_CreateObjectFn(uint session, CK_ATTRIBUTE[] tmpl, uint count, ref uint obj);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_SignInitFn(uint session, ref CK_MECHANISM mech, uint key);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint C_SignFn(uint session, byte[] data, uint dataLen, byte[] sig, ref uint sigLen);

    // ---------------- kernel32 ----------------
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr h);

    // ---------------- setupapi / hid（用于 --scan 设备接口扫描） ----------------
    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HIDD_ATTRIBUTES
    {
        public int Size;
        public ushort VendorID;
        public ushort ProductID;
        public ushort VersionNumber;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(IntPtr deviceInfoSet, IntPtr deviceInfoData,
        ref Guid interfaceClassGuid, uint memberIndex, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr deviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData, IntPtr deviceInterfaceDetailData,
        uint deviceInterfaceDetailDataSize, ref uint requiredSize, IntPtr deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("hid.dll", SetLastError = true)]
    private static extern bool HidD_GetAttributes(IntPtr hidDeviceObject, ref HIDD_ATTRIBUTES attributes);

    private static readonly Guid GUID_DEVINTERFACE_HID =
        new Guid("4D1E55B2-F16F-11CF-88CB-001111000030");
    private static readonly Guid GUID_DEVINTERFACE_CDROM =
        new Guid("53F56308-B6BF-11D0-94F2-00A0C91EFB8B");

    private const uint DIGCF_PRESENT = 0x02;
    private const uint DIGCF_DEVICEINTERFACE = 0x10;
    private const ushort HENGBAO_VID = 0x14D6;   // 5334，与 THidTSP::EnumDevice 里的判断一致

    /// <summary>
    /// 复刻 CMBCp.dll 的设备枚举：
    ///   THidTSP::EnumDevice → SetupDiGetClassDevs(GUID_DEVINTERFACE_HID, DIGCF_PRESENT|DIGCF_DEVICEINTERFACE)
    ///                        → CreateFile → HidD_GetAttributes → 只接受 VendorID == 0x14D6
    ///   CTSPBot::EnumDevice → 枚举 GUID_DEVINTERFACE_CDROM
    /// 用于判断「令牌通道是否存在」，即在 PKCS#11 之外独立验证设备形态。
    /// </summary>
    private static int ScanDevices()
    {
        Console.WriteLine("=== 设备接口扫描（复刻 CMBCp.dll 的枚举逻辑） ===");
        Console.WriteLine("HID  需要：VendorID == 0x{0:X4}（{0}）", HENGBAO_VID);

        int hidTotal, hidMatch;
        ScanClass(GUID_DEVINTERFACE_HID, "HID", true, out hidTotal, out hidMatch);
        Console.WriteLine();
        int cdTotal, cdMatch;
        ScanClass(GUID_DEVINTERFACE_CDROM, "CD-ROM", false, out cdTotal, out cdMatch);

        Console.WriteLine();
        Console.WriteLine("=== 结论 ===");
        Console.WriteLine("HID  接口：共 {0} 个，其中 VID=0x{1:X4} 的令牌接口 {2} 个", hidTotal, HENGBAO_VID, hidMatch);
        Console.WriteLine("CD-ROM 接口：共 {0} 个，其中恒宝(HENGBAO) {1} 个", cdTotal, cdMatch);
        if (hidMatch == 0)
        {
            Console.WriteLine("=> 未发现恒宝 HID 令牌接口，CMBCp.dll 的 THidTSP 通道不可用（它会返回 0 个槽位设备）。");
            Console.WriteLine("   PKCS#11 只能走 CTSPBot（SCSI 直通）通道；该通道本身是通的（--raw 的 INQUIRY 能成功）；");
            Console.WriteLine("   若 APDU 仍回 SW=6E00，是因为卡片要求先完成 MSP 握手（见 --seq / Roadmap 07 §2.2），");
            Console.WriteLine("   而不是设备故障 —— 官方工具 CMBCu.exe 在同一只 U 宝上工作正常。");
        }
        else
        {
            Console.WriteLine("=> 发现恒宝 HID 令牌接口，请直接运行不带 --scan 的探针做完整 PKCS#11 测试。");
        }
        return 0;
    }

    private static void ScanClass(Guid guid, string label, bool hidAttrs, out int total, out int match)
    {
        total = 0;
        match = 0;
        var set = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == IntPtr.Zero || set == new IntPtr(-1))
        {
            Console.WriteLine("[{0}] SetupDiGetClassDevs 失败", label);
            return;
        }
        try
        {
            uint idx = 0;
            while (true)
            {
                var ifData = new SP_DEVICE_INTERFACE_DATA { cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref guid, idx, ref ifData))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err != 259 /*ERROR_NO_MORE_ITEMS*/)
                        Console.WriteLine("[{0}] 枚举结束 err={1}", label, err);
                    break;
                }
                idx++;
                total++;

                uint need = 0;
                SetupDiGetDeviceInterfaceDetail(set, ref ifData, IntPtr.Zero, 0, ref need, IntPtr.Zero);
                if (need == 0) continue;
                var buf = Marshal.AllocHGlobal((int)need);
                try
                {
                    // 32 位进程下 SP_DEVICE_INTERFACE_DETAIL_DATA_A.cbSize = 4 + sizeof(char) = 5
                    Marshal.WriteInt32(buf, 5);
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref ifData, buf, need, ref need, IntPtr.Zero))
                        continue;
                    var path = Marshal.PtrToStringAnsi(new IntPtr(buf.ToInt32() + 4)) ?? "";

                    string extra = "";
                    bool isTarget = false;
                    if (hidAttrs)
                    {
                        var h = CreateFile(path, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                        if (h != new IntPtr(-1))
                        {
                            var attrs = new HIDD_ATTRIBUTES { Size = Marshal.SizeOf<HIDD_ATTRIBUTES>() };
                            if (HidD_GetAttributes(h, ref attrs))
                            {
                                extra = string.Format(" VID=0x{0:X4} PID=0x{1:X4} ver=0x{2:X4}",
                                    attrs.VendorID, attrs.ProductID, attrs.VersionNumber);
                                isTarget = attrs.VendorID == HENGBAO_VID;
                            }
                            else extra = " (HidD_GetAttributes 失败)";
                            CloseHandleSafe(h);
                        }
                        else extra = " (CreateFile 失败)";
                    }
                    else
                    {
                        isTarget = path.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0
                                   || path.IndexOf("UranuSafe", StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                    if (isTarget) match++;

                    Console.WriteLine("[{0}] #{1}{2}{3}", label, idx, isTarget ? " ★匹配" : "", extra);
                    Console.WriteLine("      " + path);
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    private static void CloseHandleSafe(IntPtr h)
    {
        try { CloseHandle(h); } catch { }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr hDevice, uint ioctl,
        IntPtr inBuffer, uint inSize, IntPtr outBuffer, uint outSize,
        ref uint bytesReturned, IntPtr overlapped);

    // ==================================================================================
    // SCSI-BOT 透传（--raw）：完全按 CMBCp.dll 的反汇编结果复刻
    //
    // 逆向依据（IDA Pro 8.3，2026-09-21）：
    //   · EnumDevicesByGuid (sub_10028FC1)：枚举 GUID_DEVINTERFACE_DISK 与 GUID_DEVINTERFACE_CDROM，
    //     设备路径 strupr 后必须包含 "HENGBAO" 才收下 —— 这就是恒宝未插时 C_GetSlotList 返回 0 的原因
    //     （本机虽有两个别家 CD-ROM，但都不含该串，故被过滤）。
    //   · CTSPBot::OpenDevice (sub_10028C60)：CreateFileA(path, 0xC0000000, 3, 0, 1, 0x80, 0)
    //   · BotReadWrite (sub_10028DE9)：DeviceIoControl(IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014)
    //         Length=44, TargetId=1, Lun=0, CdbLength=16, SenseInfoLength=16,
    //         DataTransferLength = 帧长|512, TimeOutValue=60, SenseInfoOffset=48,
    //         CDB[0]=0xFA, CDB[1]=0x3A(写)/0x08(读)，其余 14 字节为 0
    //   · SendCmd_BotU (sub_10028CFF)：写帧 = 43 <len_hi> <len_lo> <apdu…>；读回 512 字节
    //   · XSendAPDU (sub_100291A5)：响应去掉前 3 字节帧头后，末 2 字节即 SW1 SW2（大端）
    // ==================================================================================
    private const uint GENERIC_READ_WRITE = 0xC0000000;
    private const uint FILE_SHARE_RW = 0x3;
    private const uint OPEN_EXISTING = 3;
    /// <summary>
    /// 官方工具 CMBCu.exe 的 CTSPBot::OpenDevice 用的是 dwCreationDisposition = 1（CREATE_NEW），
    /// 而本探针默认用 OPEN_EXISTING。实测两者对后续 APDU 的结果有影响（见 --open-new 说明），
    /// 因此保留该开关以便复现官方行为。
    /// </summary>
    private static uint _createDisposition = OPEN_EXISTING;
    private const uint IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014;
    private const byte SCSI_IOCTL_DATA_OUT = 0;
    private const byte SCSI_IOCTL_DATA_IN = 1;

    private static readonly Guid GUID_DEVINTERFACE_DISK =
        new Guid("53F56307-B6BF-11D0-94F2-00A0C91EFB8B");

    /// <summary>枚举某个设备接口类的全部设备路径（与 DLL 用 SetupDiEnumDeviceInterfaces 的做法一致）。</summary>
    private static List<string> EnumDevicePaths(Guid guid)
    {
        var list = new List<string>();
        var set = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == IntPtr.Zero || set == new IntPtr(-1)) return list;
        try
        {
            uint idx = 0;
            while (true)
            {
                var ifData = new SP_DEVICE_INTERFACE_DATA { cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref guid, idx, ref ifData)) break;
                idx++;
                uint need = 0;
                SetupDiGetDeviceInterfaceDetail(set, ref ifData, IntPtr.Zero, 0, ref need, IntPtr.Zero);
                if (need == 0) continue;
                var buf = Marshal.AllocHGlobal((int)need);
                try
                {
                    Marshal.WriteInt32(buf, 5);   // 32 位下 SP_DEVICE_INTERFACE_DETAIL_DATA_A.cbSize = 4 + 1
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref ifData, buf, need, ref need, IntPtr.Zero)) continue;
                    list.Add(Marshal.PtrToStringAnsi(new IntPtr(buf.ToInt32() + 4)) ?? "");
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return list;
    }

    /// <summary>
    /// 发一条 SCSI 直通命令。结构与厂商完全一致（TargetId=1 / SenseInfoOffset=48 / TimeOutValue=60）。
    /// 返回 false 表示 DeviceIoControl 失败，err 为 Win32 错误码，sense 为请求感知数据。
    /// </summary>
    private static bool ScsiCmd(IntPtr h, byte[] cdb, byte dataIn, byte[] data,
        out byte[] sense, out int transferred, out int err, byte targetId = 1, byte lun = 0)
    {
        sense = new byte[16];
        transferred = 0;
        err = 0;
        var buf = Marshal.AllocHGlobal(80);
        var dataPtr = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
        try
        {
            for (int i = 0; i < 80; i++) Marshal.WriteByte(buf, i, 0);
            if (data.Length > 0) Marshal.Copy(data, 0, dataPtr, data.Length);

            Marshal.WriteInt16(buf, 0, 44);                       // SPTD.Length
            Marshal.WriteByte(buf, 4, targetId);                  // TargetId（厂商实现固定为 1）
            Marshal.WriteByte(buf, 5, lun);                       // Lun

            Marshal.WriteByte(buf, 6, (byte)cdb.Length);          // CdbLength
            Marshal.WriteByte(buf, 7, 16);                        // SenseInfoLength
            Marshal.WriteByte(buf, 8, dataIn);                    // DataIn
            Marshal.WriteInt32(buf, 12, data.Length);             // DataTransferLength
            Marshal.WriteInt32(buf, 16, 60);                      // TimeOutValue
            Marshal.WriteIntPtr(buf, 20, dataPtr);                // DataBuffer
            Marshal.WriteInt32(buf, 24, 48);                      // SenseInfoOffset
            Marshal.Copy(cdb, 0, new IntPtr(buf.ToInt32() + 28), Math.Min(cdb.Length, 16));

            uint ret = 0;
            bool ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT, buf, 80, buf, 80, ref ret, IntPtr.Zero);
            Marshal.Copy(new IntPtr(buf.ToInt32() + 48), sense, 0, 16);
            if (!ok) { err = Marshal.GetLastWin32Error(); return false; }

            var got = Marshal.ReadInt32(buf, 12);
            if (got < 0) got = 0;
            if (got > data.Length) got = data.Length;
            transferred = got;
            if (got > 0) Marshal.Copy(dataPtr, data, 0, got);
            return true;
        }
        finally { Marshal.FreeHGlobal(dataPtr); Marshal.FreeHGlobal(buf); }
    }

    private static string Hex(byte[] b, int len = -1)
    {
        if (b == null) return "";
        int n = len < 0 ? b.Length : Math.Min(len, b.Length);
        var sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) sb.Append(b[i].ToString("X2"));
        return sb.ToString();
    }

    private static string Ascii(byte[] b, int off, int len)
    {
        if (b == null || off >= b.Length) return "";
        var sb = new StringBuilder();
        for (int i = off; i < off + len && i < b.Length; i++)
            sb.Append(b[i] >= 0x20 && b[i] < 0x7F ? (char)b[i] : '.');
        return sb.ToString().Trim();
    }

    private static string SenseText(byte[] sense)
    {
        if (sense == null || sense.Length < 3) return "";
        if (sense[0] == 0 && sense[1] == 0 && sense[2] == 0) return "(无感知数据)";
        return string.Format("Sense=Key:0x{0:X2} ASC:0x{1:X2} ASCQ:0x{2:X2}", sense[2] & 0x0F, sense[12], sense[13]);
    }

    /// <summary>--raw：直接与设备做 SCSI-BOT 对话，用于判定 SW=6E00 的真实来源。</summary>
    private static int RawTransportSelfTest(string apduHex)
    {
        Console.WriteLine("=== SCSI-BOT 透传自检（--raw，复刻 CMBCp.dll 设备层） ===");
        Console.WriteLine("IOCTL : SCSI_PASS_THROUGH_DIRECT (0x{0:X})  CDB=FA3A(写)/FA08(读)  TargetId=1", IOCTL_SCSI_PASS_THROUGH_DIRECT);
        Console.WriteLine("过滤  : 设备路径（大写）必须包含 \"HENGBAO\"（与 EnumDevicesByGuid 一致）");
        Console.WriteLine();

        var paths = new List<string>();
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_CDROM));
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_DISK));
        Console.WriteLine("枚举到 CD-ROM / Disk 接口共 {0} 个：", paths.Count);
        foreach (var p in paths)
        {
            bool hit = p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0;
            Console.WriteLine("  {0}{1}", hit ? "[匹配] " : "       ", p);
        }
        Console.WriteLine();

        var targets = paths.FindAll(p => p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0);
        if (targets.Count == 0)
        {
            Console.WriteLine("[!] 没有任何设备路径包含 HENGBAO —— 与 CMBCp.dll 行为一致（此时 C_GetSlotList 返回 0）。");
            Console.WriteLine("    结论：当前根本没有恒宝 U 宝（或它未以磁盘/光盘形态出现），SW=6E00 无从复现。");
            return 2;
        }

        var apdu = ParseHex(apduHex);
        Console.WriteLine("待发送 APDU : " + Hex(apdu) + "（{0} 字节）", apdu.Length);
        Console.WriteLine();

        int okCount = 0;
        foreach (var path in targets)
        {
            Console.WriteLine("---- 打开 " + path);
            var h = CreateFile(path, GENERIC_READ_WRITE, FILE_SHARE_RW, IntPtr.Zero, _createDisposition, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1))
            {
                Console.WriteLine("  [x] CreateFile 失败 err={0}（多数情况是权限不足：请以管理员身份运行）",
                    Marshal.GetLastWin32Error());
                continue;
            }
            try
            {
                // [1] 标准 SCSI INQUIRY：验证直通通道本身是否可用
                byte[] sense; int got, err;
                var inq = new byte[36];
                var cdbInq = new byte[] { 0x12, 0, 0, 0, 36, 0 };
                if (ScsiCmd(h, cdbInq, SCSI_IOCTL_DATA_IN, inq, out sense, out got, out err))
                {
                    Console.WriteLine("  [1] SCSI INQUIRY 成功，返回 {0} 字节", got);
                    if (got >= 36)
                        Console.WriteLine("      Vendor=\"{0}\" Product=\"{1}\" Rev=\"{2}\"",
                            Ascii(inq, 8, 8), Ascii(inq, 16, 16), Ascii(inq, 32, 4));
                    Console.WriteLine("      => SCSI 直通通道可用（设备能正确响应标准命令）");
                }
                else
                {
                    Console.WriteLine("  [1] SCSI INQUIRY 失败 err={0} {1}", err, SenseText(sense));
                    Console.WriteLine("      => 直通通道不通；此时 DLL 的 6E00 属于「命令没送到卡片」");
                }

                // [2] 厂商命令：写 APDU 帧（43 len_hi len_lo <apdu>），CDB = FA 3A
                var cmd = new byte[apdu.Length + 3];
                cmd[0] = 0x43;
                cmd[1] = (byte)(apdu.Length >> 8);
                cmd[2] = (byte)(apdu.Length & 0xFF);
                Buffer.BlockCopy(apdu, 0, cmd, 3, apdu.Length);

                var cdbWrite = new byte[16]; cdbWrite[0] = 0xFA; cdbWrite[1] = 0x3A;
                var cdbRead = new byte[16]; cdbRead[0] = 0xFA; cdbRead[1] = 0x08;

                if (!ScsiCmd(h, cdbWrite, SCSI_IOCTL_DATA_OUT, cmd, out sense, out got, out err))
                {
                    Console.WriteLine("  [2] 写命令帧失败 err={0} {1}（数据长度 {2}）", err, SenseText(sense), got);
                    continue;
                }
                Console.WriteLine("  [2] 写命令帧成功: " + Hex(cmd));

                // [3] 读响应（最多 512 字节），CDB = FA 08
                var resp = new byte[512];
                if (!ScsiCmd(h, cdbRead, SCSI_IOCTL_DATA_IN, resp, out sense, out got, out err))
                {
                    Console.WriteLine("  [3] 读响应失败 err={0} {1}", err, SenseText(sense));
                    continue;
                }
                Console.WriteLine("  [3] 读响应 {0} 字节: {1}", got, Hex(resp, got));

                if (got < 3)
                {
                    Console.WriteLine("      => 响应不足 3 字节（无帧头），设备未按厂商协议应答");
                    continue;
                }
                var payloadLen = got - 3;
                Console.WriteLine("      帧头={0}  载荷={1} 字节", Hex(resp, 3), payloadLen);
                if (payloadLen < 2)
                {
                    Console.WriteLine("      => 载荷 {0} 字节：不足以构成 SW，卡片未返回状态字（通常=卡未上电/未就绪）",
                        payloadLen);
                    continue;
                }
                var sw = (uint)((resp[got - 2] << 8) | resp[got - 1]);
                Console.WriteLine("      载荷={0}", Hex(resp, got).Substring(6, payloadLen * 2));
                Console.WriteLine("      SW=0x{0:X4}  (XSendAPDU 取载荷末 2 字节：SW1={1:X2} SW2={2:X2})",
                    sw, resp[got - 2], resp[got - 1]);
                if (sw == 0x9000)
                {
                    okCount++;
                    Console.WriteLine("      => SW=0x9000：这条 APDU 被卡片接受！（DLL 的固定序列之外存在可用命令）");
                }
                else if (sw == 0x6E00)
                {
                    Console.WriteLine("      => SW=0x6E00：透传是通的，但卡片拒收裸 APDU。");
                    Console.WriteLine("         根因：该 U 宝要求先完成厂商 MSP 安全报文握手");
                    Console.WriteLine("         （--seq \"80F2030001,80F4020000,80F4000087,80F4010080<128B>\"），");
                    Console.WriteLine("         而 CMBCp.dll 不做此握手。官方工具 CMBCu.exe 可正常读卡，");
                    Console.WriteLine("         所以这不是设备故障（详见 Roadmap/07 §2.2）。");
                }
                else
                {
                    Console.WriteLine("      => 卡片回了非 6E00 的状态字，说明它对命令有反应，可据此继续探测。");
                }
            }
            finally { CloseHandle(h); }
            Console.WriteLine();
        }

        Console.WriteLine("=== 结论 ===");
        Console.WriteLine("收到 SW=0x9000 的设备数：" + okCount);
        Console.WriteLine("提示：可直接改写 APDU 做定向探测，例如");
        Console.WriteLine("      --raw --apdu 00A40000023F00   （SELECT MF 3F00）");
        Console.WriteLine("      --raw --apdu 00A4000002ADF1   （SELECT ADF1，DLL 的第一条命令）");
        Console.WriteLine("      --raw --apdu 80320000FF       （DLL 的第二条：取随机数/挑战）");
        return 0;
    }

    /// <summary>用厂商命令（FA3A 写 / FA08 读）发一条 APDU，返回 SW 与载荷。</summary>
    private static bool SendVendorApdu(IntPtr h, byte[] apdu, out uint sw, out byte[] payload, out string diag)
    {
        sw = 0xFFFFFFFF;
        payload = null;
        diag = "";
        var cmd = new byte[apdu.Length + 3];
        cmd[0] = 0x43;
        cmd[1] = (byte)(apdu.Length >> 8);
        cmd[2] = (byte)(apdu.Length & 0xFF);
        Buffer.BlockCopy(apdu, 0, cmd, 3, apdu.Length);

        var cdbWrite = new byte[16]; cdbWrite[0] = 0xFA; cdbWrite[1] = 0x3A;
        var cdbRead = new byte[16]; cdbRead[0] = 0xFA; cdbRead[1] = 0x08;

        byte[] sense; int got, err;
        if (!ScsiCmd(h, cdbWrite, SCSI_IOCTL_DATA_OUT, cmd, out sense, out got, out err))
        { diag = "写命令帧失败 err=" + err; return false; }

        var resp = new byte[512];
        if (!ScsiCmd(h, cdbRead, SCSI_IOCTL_DATA_IN, resp, out sense, out got, out err))
        { diag = "读响应失败 err=" + err; return false; }
        if (got < 3) { diag = "响应不足 3 字节（got=" + got + "）"; return false; }

        var n = got - 3;
        payload = new byte[n];
        Buffer.BlockCopy(resp, 3, payload, 0, n);
        if (n < 2) { sw = 0xFFFF; return true; }
        sw = (uint)((payload[n - 2] << 8) | payload[n - 1]);
        return true;
    }

    /// <summary>
    /// --brute：遍历 CLA/INS 空间，找出卡片真正「识别」的指令。
    /// 判据：本 COS 对不识别的 CLA/INS 统一回 6E00（ISO7816 里 6E00=CLA 不支持，
    /// 但实测同一 CLA 下 INS=00 会回 6700=长度错误，说明 6E00 被用作通用「不识别」码），
    /// 因此凡是回非 6E00 的，就是被识别到的指令。
    /// </summary>
    private static int BruteForceScan(byte[] clas)
    {
        Console.WriteLine("=== APDU 空间探测（--brute） ===");
        Console.WriteLine("方法：对每个 CLA 遍历 INS 0x00..0xFF，发 <CLA><INS>00 00（4 字节 Case-1）");
        Console.WriteLine("      只打印 SW != 6E00 的组合（6E00 = 本 COS 的通用「不识别」码）");
        Console.WriteLine();

        var paths = new List<string>();
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_CDROM));
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_DISK));
        var targets = paths.FindAll(p => p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0);
        if (targets.Count == 0) { Console.WriteLine("[!] 未发现恒宝设备（路径不含 HENGBAO）"); return 2; }

        foreach (var path in targets)
        {
            Console.WriteLine("---- " + path);
            var h = CreateFile(path, GENERIC_READ_WRITE, FILE_SHARE_RW, IntPtr.Zero, _createDisposition, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1))
            {
                Console.WriteLine("  [x] CreateFile 失败 err=" + Marshal.GetLastWin32Error() + "（请以管理员身份运行）");
                continue;
            }
            try
            {
                foreach (var cla in clas)
                {
                    Console.WriteLine("  ---- CLA=0x{0:X2} ----", cla);
                    int hits = 0;
                    for (int ins = 0; ins <= 0xFF; ins++)
                    {
                        var apdu = new byte[] { cla, (byte)ins, 0x00, 0x00 };
                        uint sw;
                        byte[] payload;
                        string diag;
                        if (!SendVendorApdu(h, apdu, out sw, out payload, out diag))
                        {
                            Console.WriteLine("    传输中断: " + diag);
                            break;
                        }
                        if (sw == 0x6E00) continue;
                        hits++;
                        Console.WriteLine("    INS=0x{0:X2}  SW=0x{1:X4}  载荷={2}", ins, sw, Hex(payload));
                    }
                    Console.WriteLine("    => 非 6E00 的 INS 共 " + hits + " 个");
                }
            }
            finally { CloseHandle(h); }
            Console.WriteLine();
        }

        Console.WriteLine("判读：");
        Console.WriteLine("  9000 / 6A82 / 6A80 / 6700 → 该 INS 有实现（6A82=文件不存在，6700=长度不对）");
        Console.WriteLine("  6D00 → CLA 被接受但 INS 不支持");
        Console.WriteLine("  若整片都是 6E00，则说明卡片 OS 未上线（命令被桥接芯片挡下），属设备状态问题。");
        return 0;
    }

    /// <summary>厂商命令往返：写帧（CDB 由 writeCdb 指定）→ 读响应（CDB = FA readSub）。</summary>
    private static bool VendorRoundTrip(IntPtr h, byte[] writeCdb, byte[] frame, byte readSub,
        out byte[] resp, out int got, out string diag, byte targetId = 1, byte lun = 0)
    {
        resp = new byte[512];
        got = 0;
        diag = "";
        byte[] sense; int err;
        if (!ScsiCmd(h, writeCdb, SCSI_IOCTL_DATA_OUT, frame, out sense, out got, out err, targetId, lun))
        { diag = "写失败 err=" + err + " " + SenseText(sense); return false; }
        var cdbRead = new byte[16]; cdbRead[0] = 0xFA; cdbRead[1] = readSub;
        if (!ScsiCmd(h, cdbRead, SCSI_IOCTL_DATA_IN, resp, out sense, out got, out err, targetId, lun))
        { diag = "读失败 err=" + err + " " + SenseText(sense); return false; }
        return true;
    }

    private static uint SwOf(byte[] resp, int got)
    {
        if (resp == null || got < 5) return 0xFFFF;
        return (uint)((resp[got - 2] << 8) | resp[got - 1]);
    }

    /// <summary>
    /// --cdb-scan：从传输层找「唤醒/复位卡片」的厂商命令。
    ///   ① TargetId/Lun 组合扫描（设备可能是多 LUN，令牌在别的 LUN 上）
    ///   ② 只发读命令（FA08）看是否有缓存的 ATR/状态
    ///   ③ CDB[1] 子命令扫描（FA00..FAFF）
    /// </summary>
    private static int CdbScan()
    {
        Console.WriteLine("=== 传输层扫描（--cdb-scan） ===");
        Console.WriteLine();

        var paths = new List<string>();
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_CDROM));
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_DISK));
        var targets = paths.FindAll(p => p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0);
        if (targets.Count == 0) { Console.WriteLine("[!] 未发现恒宝设备"); return 2; }

        var apdu = new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0xAD, 0xF1 };
        var frame = new byte[apdu.Length + 3];
        frame[0] = 0x43;
        frame[1] = (byte)(apdu.Length >> 8);
        frame[2] = (byte)(apdu.Length & 0xFF);
        Buffer.BlockCopy(apdu, 0, frame, 3, apdu.Length);

        foreach (var path in targets)
        {
            Console.WriteLine("---- " + path);
            var h = CreateFile(path, GENERIC_READ_WRITE, FILE_SHARE_RW, IntPtr.Zero, _createDisposition, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1))
            {
                Console.WriteLine("  [x] CreateFile 失败 err=" + Marshal.GetLastWin32Error() + "（请以管理员身份运行）");
                continue;
            }
            try
            {
                var cdbW = new byte[16]; cdbW[0] = 0xFA; cdbW[1] = 0x3A;

                // ① TargetId / Lun
                Console.WriteLine("  ① TargetId / Lun 扫描（CDB=FA3A 写 00A4000002ADF1）");
                var swSeen = new HashSet<uint>();
                for (byte tid = 0; tid <= 3; tid++)
                {
                    var line = new StringBuilder("     tid=" + tid + " :");
                    for (byte lun = 0; lun <= 3; lun++)
                    {
                        byte[] resp; int got; string diag;
                        if (!VendorRoundTrip(h, cdbW, frame, 0x08, out resp, out got, out diag, tid, lun))
                            line.Append(" L" + lun + "=<" + diag + ">");
                        else
                            line.Append(" L" + lun + "=0x" + SwOf(resp, got).ToString("X4"));
                    }
                    Console.WriteLine(line.ToString());
                }

                // ② 只读：不发写命令直接读，看是否有缓存/ATR
                {
                    var cdbR = new byte[16]; cdbR[0] = 0xFA; cdbR[1] = 0x08;
                    var resp = new byte[512];
                    byte[] sense; int got, err;
                    if (ScsiCmd(h, cdbR, SCSI_IOCTL_DATA_IN, resp, out sense, out got, out err))
                        Console.WriteLine("  ② 纯读(FA08) → " + got + " 字节: " + Hex(resp, got));
                    else
                        Console.WriteLine("  ② 纯读(FA08) → 失败 err=" + err + " " + SenseText(sense));
                }

                // ③ CDB[1] 子命令扫描
                Console.WriteLine("  ③ CDB[1] 子命令扫描（FA00..FAFF，每个先写 7 字节 APDU 帧再读）");
                var unusual = new List<string>();
                var hist = new Dictionary<string, int>();
                for (int sub = 0; sub <= 0xFF; sub++)
                {
                    var cdb = new byte[16]; cdb[0] = 0xFA; cdb[1] = (byte)sub;
                    byte[] resp; int got; string diag;
                    string key;
                    if (!VendorRoundTrip(h, cdb, frame, 0x08, out resp, out got, out diag))
                        key = "err:" + diag;
                    else
                        key = "SW=0x" + SwOf(resp, got).ToString("X4") + " len=" + got;
                    if (!hist.ContainsKey(key)) hist[key] = 0;
                    hist[key]++;
                    if (!key.StartsWith("SW=0x6E00") && !key.StartsWith("err:"))
                        unusual.Add("    sub=0x" + sub.ToString("X2") + "  " + key);
                }
                foreach (var kv in hist) Console.WriteLine("     " + kv.Key + "  ×" + kv.Value);
                if (unusual.Count > 0)
                {
                    Console.WriteLine("     ---- 非 6E00 的子命令 ----");
                    foreach (var u in unusual) Console.WriteLine(u);
                }
            }
            finally { CloseHandle(h); }
            Console.WriteLine();
        }
        Console.WriteLine("判读：如果某个 sub 返回不同结果，那就是厂商的其它控制命令（可能含复位/上电）；");
        Console.WriteLine("      若 0x00..0xFF 全是 6E00，说明桥接芯片只实现了 APDU 透传，");
        Console.WriteLine("      卡片不肯应答的原因在卡片侧（未上电 / 未进入令牌应用 / 需 U 宝按键或蓝牙配对）。");
        return 0;
    }

    /// <summary>
    /// --seq：在<b>同一个设备会话</b>里按序发送多条 APDU。
    /// 关键：卡片的状态不跨会话保留 —— 官方工具是在同一次打开里先发 80F2/80F4
    /// （厂商「激活卡/进入令牌模式」命令）再发 00A4000002ADF1，才拿到 0x6109；
    /// 单独发 SELECT 只会得到 0x6E00。
    /// </summary>
    private static int RunSequence(string spec)
    {
        Console.WriteLine("=== 单会话 APDU 序列（--seq） ===");
        Console.WriteLine("说明：卡片的激活状态不跨设备会话保留，因此前置命令必须与后续命令同一会话。");
        Console.WriteLine();

        var apdus = new List<byte[]>();
        foreach (var part in spec.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            apdus.Add(ParseHex(part));
        if (apdus.Count == 0) { Console.WriteLine("[!] 未解析出任何 APDU"); return 2; }

        var paths = new List<string>();
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_CDROM));
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_DISK));
        var targets = paths.FindAll(p => p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0);
        if (targets.Count == 0) { Console.WriteLine("[!] 未发现恒宝设备"); return 2; }

        foreach (var path in targets)
        {
            Console.WriteLine("---- " + path);
            var h = CreateFile(path, GENERIC_READ_WRITE, FILE_SHARE_RW, IntPtr.Zero, _createDisposition, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1))
            {
                Console.WriteLine("  [x] CreateFile 失败 err=" + Marshal.GetLastWin32Error() + "（请以管理员身份运行）");
                continue;
            }
            try
            {
                int n = 0;
                foreach (var apdu in apdus)
                {
                    n++;
                    uint sw;
                    byte[] payload;
                    string diag;
                    Console.Write("  [{0,2}] 发 {1,-24}", n, Hex(apdu));
                    if (!SendVendorApdu(h, apdu, out sw, out payload, out diag))
                    {
                        Console.WriteLine(" → 传输失败：" + diag);
                        continue;
                    }
                    var dataLen = payload.Length >= 2 ? payload.Length - 2 : 0;
                    Console.WriteLine(" → SW=0x{0:X4}  数据{1}字节  {2}", sw, dataLen, Hex(payload));
                }
            }
            finally { CloseHandle(h); }
            Console.WriteLine();
        }
        return 0;
    }

    // ==================================================================================
    // MSP 安全报文（--msp-open）：完全按 CMBCC.dll 反汇编结果复刻
    //
    //   Handshake  (sub_1001FDDE)
    //     80F2030001 → 要求 SW=0x9000 且应答第 2 字符为 '1'
    //     80F4020000 → 要求 SW=0x9000
    //     80F4000087 → 135 字节卡片密钥材料（hex）
    //     会话密钥 K = 16 字节随机；EM = 00 02 || 01×109 || 00 || K ；c = EM^65537 mod n
    //     80F40100%02X%s  (128 → "80") → 要求 SW=0x9000，此后 MSP 生效
    //
    //   RsaEngine  (sub_10021719)：PKCS#1 v1.5 type-2 外形，但填充串恒为 0x01（非随机）
    //   MspCipher  (sub_1001F02A)：hex→bin → 追加 0x80 并补 0 到 8 字节倍数 →
    //                              密钥 16 字节走 3DES(K3=K1)、8 字节走 DES，ECB → bin→hex
    //   MSP::XSendAPDU (sub_1001FA64)
    //     发送 = "01" + hex( 3DES_enc( bin( 长度4hex + APDU hex ) ) )
    //     接收 = 去掉前 2 字符 → 3DES_dec → hex 串 = 长度4hex + 数据hex + SW4hex
    //            （长度 = 数据字节数 + 2，SW = 末尾 4 个 hex 字符）
    // ==================================================================================

    /// <summary>3DES-ECB（两密钥，K3=K1），明文按 0x80 位填充补到 8 字节倍数。</summary>
    private static byte[] Des3Ecb(byte[] data, byte[] key16, bool encrypt)
    {
        byte[] input;
        if (encrypt)
        {
            // 厂商填充：追加 0x80 后补 0x00 到 8 字节倍数（ISO/IEC 9797-1 方法 2）
            var padded = new List<byte>(data);
            padded.Add(0x80);
            while (padded.Count % 8 != 0) padded.Add(0x00);
            input = padded.ToArray();
        }
        else
        {
            input = data;
            if (data.Length % 8 != 0) throw new InvalidOperationException("密文长度不是 8 的倍数: " + data.Length);
        }

        var tdes = System.Security.Cryptography.TripleDES.Create();
        try
        {
            tdes.Mode = System.Security.Cryptography.CipherMode.ECB;
            tdes.Padding = System.Security.Cryptography.PaddingMode.None;
            tdes.Key = key16;
            var xf = encrypt ? tdes.CreateEncryptor() : tdes.CreateDecryptor();
            return xf.TransformFinalBlock(input, 0, input.Length);
        }
        finally { tdes.Dispose(); }
    }

    /// <summary>裸 RSA 公钥运算（无 .NET 的随机填充，按厂商的确定性 0x01 填充）。</summary>
    private static byte[] RsaEncryptSessionKey(byte[] modulus128, byte[] sessionKey16)
    {
        const int k = 128;                       // 1024 位
        if (sessionKey16.Length + 11 > k) throw new InvalidOperationException("会话密钥过长");
        var em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x02;
        var padLen = k - sessionKey16.Length - 3;          // 109
        for (int i = 0; i < padLen; i++) em[2 + i] = 0x01;
        em[2 + padLen] = 0x00;
        Buffer.BlockCopy(sessionKey16, 0, em, 3 + padLen, sessionKey16.Length);

        var m = new System.Numerics.BigInteger(em, isUnsigned: true, isBigEndian: true);
        var n = new System.Numerics.BigInteger(modulus128, isUnsigned: true, isBigEndian: true);
        var e = new System.Numerics.BigInteger(65537);
        var c = System.Numerics.BigInteger.ModPow(m, e, n);
        var outBytes = c.ToByteArray(isUnsigned: true, isBigEndian: true);
        var res = new byte[k];
        if (outBytes.Length > k) throw new InvalidOperationException("RSA 结果超出模长");
        Buffer.BlockCopy(outBytes, 0, res, k - outBytes.Length, outBytes.Length);
        return res;
    }

    /// <summary>MSP 握手：成功返回 16 字节会话密钥。</summary>
    private static bool MspHandshake(IntPtr h, out byte[] sessionKey, out string diag)
    {
        sessionKey = null;
        diag = "";

        byte[] r1; int got1; string d1;
        if (!VendorRoundTrip(h, MakeCdb(0x3A), FrameApdu(ParseHex("80F2030001")), 0x08, out r1, out got1, out d1))
        { diag = "80F2030001 传输失败: " + d1; return false; }
        var p1 = PayloadOf(r1, got1);
        if (SwOf(p1) != 0x9000) { diag = "80F2030001 返回 0x" + SwOf(p1).ToString("X4"); return false; }

        byte[] r2; int got2; string d2;
        if (!VendorRoundTrip(h, MakeCdb(0x3A), FrameApdu(ParseHex("80F4020000")), 0x08, out r2, out got2, out d2))
        { diag = "80F4020000 传输失败: " + d2; return false; }
        var p2 = PayloadOf(r2, got2);
        if (SwOf(p2) != 0x9000) { diag = "80F4020000 返回 0x" + SwOf(p2).ToString("X4"); return false; }

        byte[] r3; int got3; string d3;
        if (!VendorRoundTrip(h, MakeCdb(0x3A), FrameApdu(ParseHex("80F4000087")), 0x08, out r3, out got3, out d3))
        { diag = "80F4000087 传输失败: " + d3; return false; }
        var p3 = PayloadOf(r3, got3);
        var sw3 = SwOf(p3);
        if (sw3 != 0x9000) { diag = "80F4000087 返回 0x" + sw3.ToString("X4"); return false; }

        // 载荷是二进制：数据 + 2 字节 SW（DLL 内部才把它转成 hex 字符串）
        var blob = new byte[p3.Length - 2];
        Buffer.BlockCopy(p3, 0, blob, 0, blob.Length);
        Console.WriteLine("      卡片密钥材料 {0} 字节: {1}", blob.Length, Convert.ToHexString(blob));
        if (blob.Length < 130) { diag = "卡片密钥材料长度异常"; return false; }

        // 厂商从 hex 串第 4 个字符起取 256 个 hex 字符 = 字节 2..129 作为模数
        var modulus = new byte[128];
        Buffer.BlockCopy(blob, 2, modulus, 0, 128);
        if (modulus[0] == 0) { diag = "模数首字节为 0，偏移可能不对"; return false; }

        var key = new byte[16];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(key);
        Console.WriteLine("      会话密钥 K = " + Convert.ToHexString(key));

        var cipher = RsaEncryptSessionKey(modulus, key);
        var apdu = "80F40100" + cipher.Length.ToString("X2") + Convert.ToHexString(cipher);
        Console.WriteLine("      发送 80F40100{0} + {1} 字节密文", cipher.Length.ToString("X2"), cipher.Length);

        byte[] r4; int got4; string d4;
        if (!VendorRoundTrip(h, MakeCdb(0x3A), FrameApdu(ParseHex(apdu)), 0x08, out r4, out got4, out d4))
        { diag = "80F4010080 传输失败: " + d4; return false; }
        var p4 = PayloadOf(r4, got4);
        var sw4 = SwOf(p4);
        if (sw4 != 0x9000) { diag = "80F4010080 返回 0x" + sw4.ToString("X4") + "（RSA 填充或模数偏移可能不对）"; return false; }

        sessionKey = key;
        return true;
    }

    private static byte[] MakeCdb(byte sub) { var c = new byte[16]; c[0] = 0xFA; c[1] = sub; return c; }

    private static byte[] PayloadOf(byte[] resp, int got)
    {
        if (resp == null || got < 3) return Array.Empty<byte>();
        var n = got - 3;
        var p = new byte[n];
        Buffer.BlockCopy(resp, 3, p, 0, n);
        return p;
    }

    private static uint SwOf(byte[] payload)
        => payload == null || payload.Length < 2 ? 0xFFFFu
           : (uint)((payload[payload.Length - 2] << 8) | payload[payload.Length - 1]);

    /// <summary>组厂商命令帧：43 len_hi len_lo + apdu。</summary>
    private static byte[] FrameApdu(byte[] apdu)
    {
        var f = new byte[apdu.Length + 3];
        f[0] = 0x43;
        f[1] = (byte)(apdu.Length >> 8);
        f[2] = (byte)(apdu.Length & 0xFF);
        Buffer.BlockCopy(apdu, 0, f, 3, apdu.Length);
        return f;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
        if (hex.Length % 2 != 0) hex = hex.Substring(0, hex.Length - 1);
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    /// <summary>用已建立的 MSP 会话加密发送一条 APDU，并解密响应。</summary>
    private static bool MspSend(IntPtr h, byte[] key, byte[] apdu, out uint sw, out byte[] data, out byte[] raw, out string diag)
    {
        sw = 0xFFFF; data = null; raw = null; diag = "";
        // 明文 hex = 长度(4 hex) + APDU hex
        var lenHex = (apdu.Length).ToString("X4");
        var plainHex = lenHex + Convert.ToHexString(apdu);
        var enc = Des3Ecb(HexToBytes(plainHex), key, true);
        // 线上报文 = 1 字节标记 0x01 + 密文（对应 DLL 里的 "01" + hex(密文)）
        var wire = new byte[enc.Length + 1];
        wire[0] = 0x01;
        Buffer.BlockCopy(enc, 0, wire, 1, enc.Length);

        var resp = new byte[512];
        byte[] sense; int got, err;
        var cdbW = MakeCdb(0x3A); var cdbR = MakeCdb(0x08);
        if (!ScsiCmd(h, cdbW, SCSI_IOCTL_DATA_OUT, FrameApdu(wire), out sense, out got, out err))
        { diag = "写失败 err=" + err; return false; }
        if (!ScsiCmd(h, cdbR, SCSI_IOCTL_DATA_IN, resp, out sense, out got, out err))
        { diag = "读失败 err=" + err; return false; }

        var payload = PayloadOf(resp, got);
        raw = payload;
        Console.WriteLine("      载荷 {0} 字节: {1}", payload.Length, Hex(payload));

        // 按 DLL 的分帧：载荷 = [1 字节前缀][8 字节密文]。
        // 注意 sub_1001F02A 的语义：输入是 hex 串（先 hex→bin 再解密），
        // 输出是「解密结果的 hex 串」——所以这里必须 Convert.ToHexString，不能再当 ASCII 读。
        string txt = null;
        for (int off = 0; off <= 1 && txt == null; off++)
        {
            var n = payload.Length - off;
            if (n <= 0 || n % 8 != 0) continue;
            var slice = new byte[n];
            Buffer.BlockCopy(payload, off, slice, 0, n);
            try
            {
                var plain = Des3Ecb(slice, key, false);
                var hexStr = Convert.ToHexString(plain);
                Console.WriteLine("      [3DES解密 off={0}] hex={1}", off, hexStr);
                if (hexStr.Length < 8) continue;
                var len0 = Convert.ToInt32(hexStr.Substring(0, 4), 16);
                if (len0 >= 2 && 4 + (len0 - 2) * 2 + 4 <= hexStr.Length) txt = hexStr;
            }
            catch (Exception ex) { Console.WriteLine("      [3DES解密 off={0}] 异常 {1}", off, ex.Message); }
        }
        if (txt == null)
        {
            MspKeySearch(key, payload);
            diag = "标准 3DES 解不出可读内容（载荷 " + Hex(payload) + "）";
            return false;
        }

        var total = Convert.ToInt32(txt.Substring(0, 4), 16);      // = 数据字节数 + 2
        var dataLen = total - 2;
        if (dataLen < 0 || 4 + dataLen * 2 + 4 > txt.Length) { diag = "长度字段异常: " + txt; return false; }

        data = HexToBytes(txt.Substring(4, dataLen * 2));
        sw = Convert.ToUInt32(txt.Substring(4 + dataLen * 2, 4), 16);
        return true;
    }

    /// <summary>--msp-open：完成 MSP 握手并用安全报文发一条 APDU（默认 SELECT ADF1）。</summary>
    private static int MspOpenTest(string apduHex)
    {
        Console.WriteLine("=== MSP 安全报文握手 + 受保护 APDU（--msp-open） ===");
        Console.WriteLine("复刻 CMBCC.dll: Handshake(sub_1001FDDE) / RsaEngine(sub_10021719) / MspCipher(sub_1001F02A)");
        Console.WriteLine();

        var paths = new List<string>();
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_CDROM));
        paths.AddRange(EnumDevicePaths(GUID_DEVINTERFACE_DISK));
        var targets = paths.FindAll(p => p.IndexOf("HENGBAO", StringComparison.OrdinalIgnoreCase) >= 0);
        if (targets.Count == 0) { Console.WriteLine("[!] 未发现恒宝设备"); return 2; }

        var apdus = new List<byte[]>();
        foreach (var p in (apduHex ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            apdus.Add(ParseHex(p));
        if (apdus.Count == 0) apdus.Add(ParseHex(null));

        foreach (var path in targets)
        {
            Console.WriteLine("---- " + path);
            var h = CreateFile(path, GENERIC_READ_WRITE, FILE_SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1))
            {
                Console.WriteLine("  [x] CreateFile 失败 err=" + Marshal.GetLastWin32Error() + "（请以管理员身份运行）");
                continue;
            }
            try
            {
                Console.WriteLine("  [1] 明文握手…");
                byte[] key; string diag;
                if (!MspHandshake(h, out key, out diag))
                {
                    Console.WriteLine("  [x] 握手失败: " + diag);
                    continue;
                }
                Console.WriteLine("  [2] 握手成功，MSP 已启用。");

                Console.WriteLine("  [3] 同一会话内用 MSP 连发 {0} 条 APDU：", apdus.Count);
                var raws = new List<string>();
                foreach (var apdu in apdus)
                {
                    uint sw; byte[] data, raw;
                    Console.WriteLine("    -> 发送 " + Hex(apdu));
                    if (!MspSend(h, key, apdu, out sw, out data, out raw, out diag))
                    {
                        Console.WriteLine("       [x] 失败: " + diag);
                        continue;
                    }
                    raws.Add(raw == null ? "" : Hex(raw));
                    Console.WriteLine("       => SW=0x{0:X4}  数据 {1} 字节  {2}", sw, data.Length, Hex(data));
                }

                Console.WriteLine("  [4] 原始应答密文对比（ECB 下：明文相同 ⇒ 密文必相同）：");
                for (int i = 0; i < raws.Count; i++)
                {
                    var cmp = i == 0 ? "" : (raws[i] == raws[0] ? "   ← 与 #0 完全相同" : "   ← 与 #0 不同");
                    Console.WriteLine("      #{0} {1}{2}", i, raws[i], cmp);
                }
            }
            finally { CloseHandle(h); }
            Console.WriteLine();
        }
        return 0;
    }

    /// <summary>
    /// 密钥派生搜索：卡片对 SELECT ADF1 应回 SW=0x6109，因此应答明文 hex 必为
    /// "0002"+"6109"（长度 2 = 数据 0 字节 + SW 2 字节），hex 解码后 = 00 02 61 09，
    /// 4 字节按厂商规则补 0x80 到 8 字节 → 解密结果应为 00 02 61 09 80 00 00 00。
    /// 用它当"已知明文"，逐一验证厂商 3DES 可能使用的密钥派生形式。
    /// </summary>
    private static void MspKeySearch(byte[] key, byte[] payload)
    {
        var target = HexToBytes("0002610980000000");
        // 密文 = 载荷跳过 1 字节前缀后的 8 字节
        if (payload.Length < 9) return;
        var cipher = new byte[8];
        Buffer.BlockCopy(payload, 1, cipher, 0, 8);

        var hexUp = Convert.ToHexString(key);            // BinToHex 输出大写
        var hexLo = hexUp.ToLowerInvariant();
        var cands = new List<Tuple<string, byte[]>>();
        void Add(string n, byte[] b) { if (b != null && (b.Length == 16 || b.Length == 24)) cands.Add(Tuple.Create(n, b)); }

        Add("K", key);
        Add("K反转", key.Reverse().ToArray());
        Add("K半交换", key.Skip(8).Concat(key.Take(8)).ToArray());
        Add("K半内反转", key.Take(8).Reverse().Concat(key.Skip(8).Reverse()).ToArray());
        Add("hexUp[:16]", Encoding.ASCII.GetBytes(hexUp.Substring(0, 16)));
        Add("hexUp[16:]", Encoding.ASCII.GetBytes(hexUp.Substring(16)));
        Add("hexLo[:16]", Encoding.ASCII.GetBytes(hexLo.Substring(0, 16)));
        Add("hexLo[16:]", Encoding.ASCII.GetBytes(hexLo.Substring(16)));
        try { Add("MD5(K)", System.Security.Cryptography.MD5.HashData(key)); } catch { }
        try { Add("MD5(hexUp)", System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes(hexUp))); } catch { }
        try { Add("MD5(hexLo)", System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes(hexLo))); } catch { }
        try { Add("SHA1(K)[:16]", System.Security.Cryptography.SHA1.HashData(key).Take(16).ToArray()); } catch { }
        try { Add("SHA256(K)[:16]", System.Security.Cryptography.SHA256.HashData(key).Take(16).ToArray()); } catch { }
        Add("K^FF", key.Select(b => (byte)(b ^ 0xFF)).ToArray());
        Add("K位反转", key.Select(BitReverse).ToArray());

        Console.WriteLine("      [密钥派生搜索] 目标明文 = 0002610980000000");
        foreach (var c in cands)
        {
            foreach (var dir in new[] { true, false })
            {
                byte[] p;
                try { p = Des3Ecb(cipher, c.Item2, dir); }
                catch { continue; }
                var tag = p.SequenceEqual(target) ? "  ★★★ 精确命中 ★★★" : "";
                var s = new string(p.Select(ch => ch >= 0x20 && ch < 0x7F ? (char)ch : '.').ToArray());
                if (tag.Length > 0)
                    Console.WriteLine("        {0} {1} → {2}{3}", c.Item1, dir ? "加密" : "解密", Hex(p), tag);
            }
        }
    }

    private static byte BitReverse(byte b)
    {
        byte r = 0;
        for (int i = 0; i < 8; i++) if ((b & (1 << i)) != 0) r |= (byte)(1 << (7 - i));
        return r;
    }

    private static byte[] ParseHex(string hex)    {
        if (string.IsNullOrWhiteSpace(hex)) return new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0xAD, 0xF1 };
        var s = new StringBuilder();
        foreach (var c in hex) if (Uri.IsHexDigit(c)) s.Append(c);
        if (s.Length % 2 != 0) s.Length--;
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.ToString(i * 2, 2), 16);
        return b;
    }

    private static string Err(uint rv)
    {
        switch (rv)
        {
            case CKR_OK: return "CKR_OK(0)";
            case 0x06: return "CKR_FUNCTION_FAILED(6)  ← 设备通信失败/设备未就绪";
            case 0x54: return "CKR_FUNCTION_NOT_SUPPORTED(0x54)";
            case 0xA0: return "CKR_PIN_INCORRECT(0xA0)";
            case 0xA1: return "CKR_PIN_INVALID(0xA1)";
            case 0xA2: return "CKR_PIN_LEN_RANGE(0xA2)";
            case 0xA3: return "CKR_PIN_EXPIRED(0xA3)";
            case 0xA4: return "CKR_PIN_LOCKED(0xA4)";
            case 0x100: return "CKR_USER_ALREADY_LOGGED_IN(0x100)";
            case 0x101: return "CKR_USER_NOT_LOGGED_IN(0x101)";
            case 0x102: return "CKR_USER_PIN_NOT_INITIALIZED(0x102)";
            case 0x103: return "CKR_USER_TYPE_INVALID(0x103)";
            case 0x150: return "CKR_BUFFER_TOO_SMALL(0x150)";
            case 0x180: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED(0x180)";
            case 0x190: return "CKR_CRYPTOKI_NOT_INITIALIZED(0x190)";
            case 0x191: return "CKR_CRYPTOKI_ALREADY_INITIALIZED(0x191)";
            case 0xE0: return "CKR_TOKEN_NOT_PRESENT(0xE0)";
            case 0x30: return "CKR_DEVICE_ERROR(0x30)";
            case 0x32: return "CKR_DEVICE_REMOVED(0x32)";
            case 0x03: return "CKR_SLOT_ID_INVALID(3)";
            case 0x82: return "CKR_OBJECT_HANDLE_INVALID(0x82)";
            default: return string.Format("0x{0:X}", rv);
        }
    }

    private static T Get<T>(IntPtr h, string name) where T : class
    {
        var addr = GetProcAddress(h, name);
        if (addr == IntPtr.Zero) { Console.WriteLine("  [!] 未找到导出 " + name); return null; }
        return Marshal.GetDelegateForFunctionPointer(addr, typeof(T)) as T;
    }

    private static string S(byte[] b)
    {
        if (b == null) return "";
        int end = b.Length;
        while (end > 0 && (b[end - 1] == 0 || b[end - 1] == 0x20)) end--;
        return end == 0 ? "" : Encoding.UTF8.GetString(b, 0, end).Trim();
    }

    private static byte[] ReadAttr(C_GetAttributeValueFn getAttr, uint session, uint obj, uint type)
    {
        if (getAttr == null) return null;
        var probe = new[] { new CK_ATTRIBUTE { type = type, pValue = IntPtr.Zero, ulValueLen = 0 } };
        var rc = getAttr(session, obj, probe, 1);
        if (rc == CKR_ATTRIBUTE_TYPE_INVALID || rc == CKR_ATTRIBUTE_SENSITIVE) return null;
        var len = (int)probe[0].ulValueLen;
        if (len <= 0 || len > 1024 * 1024) return null;
        var buf = new byte[len];
        var ptr = Marshal.AllocHGlobal(len);
        try
        {
            var read = new[] { new CK_ATTRIBUTE { type = type, pValue = ptr, ulValueLen = (uint)len } };
            if (getAttr(session, obj, read, 1) != CKR_OK) return null;
            Marshal.Copy(ptr, buf, 0, len);
            return buf;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static List<uint> Find(C_FindObjectsInitFn init, C_FindObjectsFn find, C_FindObjectsFinalFn final,
        uint session, uint objClass)
    {
        var res = new List<uint>();
        var clsPtr = Marshal.AllocHGlobal(4);
        Marshal.WriteInt32(clsPtr, (int)objClass);
        var tmpl = new[] { new CK_ATTRIBUTE { type = CKA_CLASS, pValue = clsPtr, ulValueLen = 4 } };
        try
        {
            if (init(session, tmpl, 1) != CKR_OK) return res;
            try
            {
                var buf = new uint[16];
                while (true)
                {
                    uint got = 0;
                    if (find(session, buf, (uint)buf.Length, ref got) != CKR_OK || got == 0) break;
                    for (int i = 0; i < got; i++) res.Add(buf[i]);
                    if (got < buf.Length) break;
                }
            }
            finally { final(session); }
        }
        finally { Marshal.FreeHGlobal(clsPtr); }
        return res;
    }

    private static int Main(string[] args)
    {
        string dllPath = @"G:\Codes\USBKeyDriver\Library\HengBao USB Manage\CMBCp.dll";
        string pin = "111111";
        string newPin = null, resetPin = null;
        string importPfx = null, pfxPwd = "", pfxInfo = null;
        bool eraseAll = false, doSign = false, probeInit = false, scanOnly = false, certOnly = false, assumeYes = false;
        bool rawMode = false, bruteMode = false, cdbScanMode = false, mspOpenMode = false;
        string apduHex = null, claHex = null, seqHex = null;

        var positional = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--scan": scanOnly = true; break;
                case "--list": break;
                case "--erase-all": eraseAll = true; break;
                case "--sign": doSign = true; break;
                case "--probe-init": probeInit = true; break;
                case "--cert-only": certOnly = true; break;
                case "--yes": assumeYes = true; break;
                case "--import-pfx": if (i + 1 < args.Length) importPfx = args[++i]; break;
                case "--pfx-pwd": if (i + 1 < args.Length) pfxPwd = args[++i]; break;
                case "--pfx-info": if (i + 1 < args.Length) pfxInfo = args[++i]; break;
                case "--changepin": if (i + 1 < args.Length) newPin = args[++i]; break;
                case "--reset": if (i + 1 < args.Length) resetPin = args[++i]; break;
                case "--raw": rawMode = true; break;
                case "--apdu": if (i + 1 < args.Length) apduHex = args[++i]; break;
                case "--brute": bruteMode = true; break;
                case "--cdb-scan": cdbScanMode = true; break;
                case "--msp-open": mspOpenMode = true; break;
                case "--cla": if (i + 1 < args.Length) claHex = args[++i]; break;
                case "--seq": if (i + 1 < args.Length) seqHex = args[++i]; break;
                case "--open-new": _createDisposition = 1; break;
                default: positional.Add(args[i]); break;
            }
        }
        if (positional.Count > 0) dllPath = positional[0];
        if (positional.Count > 1) pin = positional[1];

        Console.WriteLine("=== 恒宝 CMBC U 宝 PKCS#11 探针（__cdecl 版） ===");
        Console.WriteLine("DLL : " + dllPath);
        Console.WriteLine("PIN : " + pin);
        Console.WriteLine();

        if (scanOnly) return ScanDevices();
        if (bruteMode) return BruteForceScan(claHex == null
            ? new byte[] { 0x00, 0x80, 0x84, 0x90, 0xFF }
            : ParseHex(claHex));
        if (mspOpenMode) return MspOpenTest(apduHex);
        if (seqHex != null) return RunSequence(seqHex);
        if (cdbScanMode) return CdbScan();
        if (rawMode) return RawTransportSelfTest(apduHex);
        if (pfxInfo != null) return ShowPfxInfo(pfxInfo, pfxPwd);

        var h = LoadLibrary(dllPath);
        if (h == IntPtr.Zero)
        {
            Console.WriteLine("[!] LoadLibrary 失败 err=" + Marshal.GetLastWin32Error());
            Console.WriteLine("    请确认：路径存在、且本进程为 32 位（x86）。");
            return 1;
        }
        Console.WriteLine("[+] LoadLibrary 成功 handle=0x" + h.ToString("X"));

        var init = Get<C_InitializeFn>(h, "C_Initialize");
        var final = Get<C_FinalizeFn>(h, "C_Finalize");
        var getSlotList = Get<C_GetSlotListFn>(h, "C_GetSlotList");
        var getSlotInfo = Get<C_GetSlotInfoFn>(h, "C_GetSlotInfo");
        var getTokenInfo = Get<C_GetTokenInfoFn>(h, "C_GetTokenInfo");
        var openSession = Get<C_OpenSessionFn>(h, "C_OpenSession");
        var closeSession = Get<C_CloseSessionFn>(h, "C_CloseSession");
        var login = Get<C_LoginFn>(h, "C_Login");
        var logout = Get<C_LogoutFn>(h, "C_Logout");
        var setPin = Get<C_SetPINFn>(h, "C_SetPIN");
        var initToken = Get<C_InitTokenFn>(h, "C_InitToken");
        var initPin = Get<C_InitPINFn>(h, "C_InitPIN");
        var getAttr = Get<C_GetAttributeValueFn>(h, "C_GetAttributeValue");
        var findInit = Get<C_FindObjectsInitFn>(h, "C_FindObjectsInit");
        var find = Get<C_FindObjectsFn>(h, "C_FindObjects");
        var findFinal = Get<C_FindObjectsFinalFn>(h, "C_FindObjectsFinal");
        var destroyObj = Get<C_DestroyObjectFn>(h, "C_DestroyObject");
        var createObj = Get<C_CreateObjectFn>(h, "C_CreateObject");
        var signInit = Get<C_SignInitFn>(h, "C_SignInit");
        var sign = Get<C_SignFn>(h, "C_Sign");

        // 1) 初始化
        var rc = init(IntPtr.Zero);
        Console.WriteLine("[1] C_Initialize → " + Err(rc));
        if (rc != CKR_OK && rc != 0x191) { FreeLibrary(h); return 2; }

        // 2) 枚举槽位
        uint count = 0;
        rc = getSlotList(1, null, ref count);
        Console.WriteLine("[2] C_GetSlotList(TRUE,NULL) → " + Err(rc) + " count=" + count);
        if (rc != CKR_OK || count == 0)
        {
            Console.WriteLine("[!] 未检测到已插入的恒宝 U 宝。");
            Console.WriteLine("    提示：该设备通过自研 HID / SCSI-BOT 通道通信（不是 PCSC），");
            Console.WriteLine("    若设备只以 U 盘/CD-ROM 形态出现，驱动未切换到 HID 模式则无法访问。");
            final(IntPtr.Zero); FreeLibrary(h); return 0;
        }

        var slots = new uint[count];
        rc = getSlotList(1, slots, ref count);
        Console.WriteLine("[2b] C_GetSlotList(TRUE,[]) → " + Err(rc) + " count=" + count);

        int online = 0;
        for (int i = 0; i < count; i++)
        {
            Console.WriteLine();
            Console.WriteLine("----- 槽位[" + i + "] 句柄=0x" + slots[i].ToString("X8") + " -----");

            var slotName = "";
            try { slotName = Marshal.PtrToStringAnsi(new IntPtr(unchecked((int)slots[i]))) ?? ""; } catch { }
            Console.WriteLine("  设备路径字符串 : " + slotName);

            var si = new CK_SLOT_INFO();
            rc = getSlotInfo(slots[i], ref si);
            Console.WriteLine("  C_GetSlotInfo  → " + Err(rc)
                + (rc == CKR_OK ? "  描述=\"" + S(si.slotDescription) + "\" 厂商=\"" + S(si.manufacturerID) + "\" flags=0x" + si.flags.ToString("X") : ""));

            var ti = new CK_TOKEN_INFO();
            rc = getTokenInfo(slots[i], ref ti);
            Console.WriteLine("  C_GetTokenInfo → " + Err(rc));
            if (rc != CKR_OK)
            {
                Console.WriteLine("    ⚠ 槽位存在但设备打不开（C_GetTokenInfo 返回 CKR_FUNCTION_FAILED）。");
                Console.WriteLine("      根因（2026-09-21 实机确认，详见 Roadmap/07-HengBao-U宝逆向分析.md §2.2）：");
                Console.WriteLine("        · 该 U 宝要求先完成厂商「MSP 安全报文」握手，之后才接受 ISO7816 命令；");
                Console.WriteLine("          握手 = 80F2030001 → 80F4020000 → 80F4000087 → 80F4010080+128B 应答；");
                Console.WriteLine("        · 未握手时卡片对任何 APDU 一律回 SW=0x6E00（且 4 字节 APDU 回 0x6700）；");
                Console.WriteLine("        · CMBCp.dll 的 KOpenDevice 不做该握手，所以 C_GetTokenInfo 恒失败。");
                Console.WriteLine("      验证方法（本探针已内置）：--raw 直连 SCSI-BOT；--seq 发指定 APDU 序列。");
                Console.WriteLine("      注意：官方工具 CMBCu.exe 在同一只 U 宝上工作正常（可读出 HBKEY / CMBC_SKF），");
                Console.WriteLine("            因此这【不是】设备故障，而是 PKCS#11 模块缺少握手。");
                continue;
            }

            online++;
            Console.WriteLine("    label         = " + S(ti.label));
            Console.WriteLine("    model         = " + S(ti.model));
            Console.WriteLine("    serial        = " + S(ti.serialNumber));
            Console.WriteLine("    manufacturer  = " + S(ti.manufacturerID));
            Console.WriteLine("    flags         = 0x" + ti.flags.ToString("X"));
            Console.WriteLine("    版本          = hw " + ti.hardwareVersion.major + "." + ti.hardwareVersion.minor
                              + " / fw " + ti.firmwareVersion.major + "." + ti.firmwareVersion.minor);
            Console.WriteLine("    口径长度       = " + ti.ulMinPinLen + "-" + ti.ulMaxPinLen);
            Console.WriteLine("    PIN剩余次数    = " + ti.ulSessionCount + "  (厂商把 ulSessionCount 复用为剩余尝试次数)");

            // 3) 打开会话
            uint session = 0;
            rc = openSession(slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, ref session);
            Console.WriteLine("  C_OpenSession  → " + Err(rc) + " session=" + session);
            if (rc != CKR_OK || session == 0) continue;

            try
            {
                // 4) 登录
                var pinBytes = Encoding.UTF8.GetBytes(pin);
                rc = login(session, CKU_USER, pinBytes, (uint)pinBytes.Length);
                Console.WriteLine("  C_Login(USER)  → " + Err(rc));
                if (rc != CKR_OK && rc != CKR_USER_ALREADY_LOGGED_IN)
                {
                    Console.WriteLine("    ⚠ 登录失败，后续对象操作将不可用（出厂口令为 111111）。");
                }
                else
                {
                    // 5) 对象统计
                    var certs = Find(findInit, find, findFinal, session, CKO_CERTIFICATE);
                    var privs = Find(findInit, find, findFinal, session, CKO_PRIVATE_KEY);
                    var pubs = Find(findInit, find, findFinal, session, CKO_PUBLIC_KEY);
                    var datas = Find(findInit, find, findFinal, session, CKO_DATA);
                    Console.WriteLine("  对象统计       : 证书=" + certs.Count + " 私钥=" + privs.Count
                                      + " 公钥=" + pubs.Count + " 数据=" + datas.Count);

                    foreach (var c in certs)
                    {
                        var der = ReadAttr(getAttr, session, c, CKA_VALUE);
                        var id = ReadAttr(getAttr, session, c, CKA_ID);
                        var label = ReadAttr(getAttr, session, c, CKA_LABEL);
                        var line = "    证书句柄=0x" + c.ToString("X");
                        if (label != null) line += " label=\"" + Encoding.UTF8.GetString(label).TrimEnd('\0') + "\"";
                        if (id != null) line += " id=" + BitConverter.ToString(id).Replace("-", "");
                        Console.WriteLine(line);
                        if (der != null)
                        {
                            try
                            {
                                var x = new X509Certificate2(der);
                                Console.WriteLine("      Subject=" + x.Subject);
                                Console.WriteLine("      Issuer =" + x.Issuer);
                                Console.WriteLine("      有效期 =" + x.NotBefore.ToString("yyyy-MM-dd") + " ~ " + x.NotAfter.ToString("yyyy-MM-dd"));
                            }
                            catch (Exception ex) { Console.WriteLine("      X509 解析失败: " + ex.Message); }
                        }
                    }

                    // 6) 签名自检
                    if (doSign && privs.Count > 0)
                    {
                        foreach (var mechId in new[] { CKM_SHA256_RSA_PKCS, CKM_SHA1_RSA_PKCS })
                        {
                            var mech = new CK_MECHANISM { mechanism = mechId, pParameter = IntPtr.Zero, ulParameterLen = 0 };
                            rc = signInit(session, ref mech, privs[0]);
                            Console.WriteLine("  C_SignInit(0x" + mechId.ToString("X") + ") → " + Err(rc));
                            if (rc != CKR_OK) continue;
                            var data = Encoding.UTF8.GetBytes("HengBao U-Bao signature self-test");
                            uint sigLen = 0;
                            rc = sign(session, data, (uint)data.Length, null, ref sigLen);
                            if (rc == CKR_OK || rc == CKR_BUFFER_TOO_SMALL)
                            {
                                var sig = new byte[sigLen];
                                rc = sign(session, data, (uint)data.Length, sig, ref sigLen);
                                Console.WriteLine("  C_Sign → " + Err(rc) + " 签名长度=" + sigLen);
                            }
                            else Console.WriteLine("  C_Sign(len) → " + Err(rc));
                            break;
                        }
                    }

                    // 7) 清空内容 / 重置
                    if (eraseAll || resetPin != null)
                    {
                        var go = assumeYes;
                        if (!assumeYes)
                        {
                            Console.Write("即将删除设备上全部对象（" + certs.Count + " 证书 / " + privs.Count + " 私钥 / "
                                          + pubs.Count + " 公钥 / " + datas.Count + " 数据）。输入 YES 确认：");
                            var answer = Console.ReadLine();
                            go = string.Equals(answer, "YES", StringComparison.Ordinal);
                        }
                        else
                        {
                            Console.WriteLine("  （--yes 已开启，直接删除全部对象）");
                        }
                        if (!go)
                        {
                            Console.WriteLine("  已取消。");
                        }
                        else
                        {
                            int ok = 0;
                            foreach (var obj in AllObjects(certs, privs, pubs, datas))
                            {
                                var drc = destroyObj(session, obj);
                                if (drc == CKR_OK) ok++;
                                else if (drc != CKR_OBJECT_HANDLE_INVALID)
                                    Console.WriteLine("    删除 0x" + obj.ToString("X") + " 失败：" + Err(drc));
                            }
                            Console.WriteLine("  C_DestroyObject 成功删除 " + ok + " 个对象（清空内容完成）。");
                        }
                    }

                    // 8) 重设口令
                    var targetPin = resetPin ?? newPin;
                    if (targetPin != null)
                    {
                        var newBytes = Encoding.UTF8.GetBytes(targetPin);
                        rc = setPin(session, pinBytes, (uint)pinBytes.Length, newBytes, (uint)newBytes.Length);
                        Console.WriteLine("  C_SetPIN → " + Err(rc) + (rc == CKR_OK ? "  口令已改为 " + targetPin : ""));
                    }

                    // 8.5) 导入 PFX（证书对象 + 尝试私钥对象，逐步给出返回码）
                    if (importPfx != null)
                        ImportPkcs12(session, createObj, importPfx, pfxPwd, certOnly);

                    // 9) C_InitToken / C_InitPIN 探测
                    //    注意：这两个函数在 CMBCp.dll 中是返回 0x54 的桩函数（已用 IDA 验证），
                    //    但若把本探针指向别的 PKCS#11 库，它们会真的初始化令牌 / 改口令。
                    //    因此默认不调用，只有显式加 --probe-init 才探测。
                    if (probeInit && initToken != null && initPin != null)
                    {
                        Console.WriteLine("  ⚠ --probe-init 已开启：将调用 C_InitToken / C_InitPIN（在非桩实现上会清空令牌！）");
                        var dummy = Encoding.UTF8.GetBytes("000000");
                        var label = Encoding.UTF8.GetBytes("probe");
                        Console.WriteLine("  C_InitToken    → " + Err(initToken(slots[i], dummy, 6, label)));
                        Console.WriteLine("  C_InitPIN      → " + Err(initPin(session, dummy, 6)));
                    }
                    else
                    {
                        Console.WriteLine("  C_InitToken    → 未调用（CMBCp.dll 中为 0x54 桩函数，见 --probe-init 说明）");
                        Console.WriteLine("  C_InitPIN      → 未调用（同上）");
                    }
                }
            }
            finally
            {
                logout(session);
                closeSession(session);
            }
        }

        Console.WriteLine();
        Console.WriteLine("=== 结论 ===");
        Console.WriteLine("在线设备数：" + online);
        Console.WriteLine("说明：重置（清空内容 + 重设口令）= --reset 新PIN；");
        Console.WriteLine("      真正的「初始化 U 宝」（恢复出厂态、口令回到 111111）只能由厂商工具 CMBCu.exe 完成。");

        final(IntPtr.Zero);
        FreeLibrary(h);
        return 0;
    }

    private static IEnumerable<uint> AllObjects(params List<uint>[] lists)
    {
        var seen = new HashSet<uint>();
        foreach (var l in lists)
            foreach (var v in l)
                if (seen.Add(v)) yield return v;
    }

    /// <summary>
    /// 仅本地解析 PKCS#12（不访问设备）：用于在 U 宝不可用时先确认 PFX 口令是否正确、
    /// 里面是否含私钥、以及导入时将要使用的 CKA_ID。
    /// </summary>
    private static int ShowPfxInfo(string path, string password)
    {
        Console.WriteLine();
        Console.WriteLine("=== PFX 本地自检（不访问设备） ===");
        if (!System.IO.File.Exists(path)) { Console.WriteLine("[!] 文件不存在: " + path); return 2; }

        X509Certificate2 cert;
        try
        {
            cert = new X509Certificate2(path, string.IsNullOrEmpty(password) ? null : password,
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] 打开 PFX 失败： " + ex.Message);
            Console.WriteLine("    提示：请用 --pfx-pwd <口令> 传入正确口令（该文件已确认设有口令）。");
            return 1;
        }

        using (cert)
        {
            Console.WriteLine("  文件        : " + path);
            Console.WriteLine("  Subject     : " + cert.Subject);
            Console.WriteLine("  Issuer      : " + cert.Issuer);
            Console.WriteLine("  有效期      : " + cert.NotBefore.ToString("yyyy-MM-dd") + " ~ " + cert.NotAfter.ToString("yyyy-MM-dd"));
            Console.WriteLine("  序列号      : " + cert.SerialNumber);
            Console.WriteLine("  指纹(SHA1)  : " + cert.Thumbprint);
            Console.WriteLine("  含私钥      : " + cert.HasPrivateKey);

            var der = cert.Export(X509ContentType.Cert);
            var id = SHA1.HashData(der);
            Console.WriteLine("  证书DER长度 : " + der.Length + " 字节");
            Console.WriteLine("  将用作CKA_ID: " + Convert.ToHexString(id));

            if (cert.HasPrivateKey)
            {
                using (var rsa = cert.GetRSAPrivateKey())
                {
                    if (rsa != null)
                    {
                        var p = rsa.ExportParameters(true);
                        Console.WriteLine("  私钥        : RSA " + rsa.KeySize + " bit（模长 " + p.Modulus.Length
                                          + " 字节，含 D/P/Q/DP/DQ/InverseQ → 可尝试 C_CreateObject 导入）");
                    }
                    else
                    {
                        using (var ec = cert.GetECDsaPrivateKey())
                            Console.WriteLine("  私钥        : " + (ec != null ? "ECDSA " + ec.KeySize + " bit（恒宝 PKCS#11 主要支持 RSA 导入）" : "无法识别"));
                    }
                }
            }
            Console.WriteLine("  => PFX 口令与内容校验通过。设备可用后可执行：--import-pfx");
            Console.WriteLine("     注意：恒宝 U 宝的私钥由卡内生成，外部私钥导入大概率不被接受；");
            Console.WriteLine("           届时请关注 [A]（证书对象）与 [B1]/[B2]（私钥对象）的返回码。");
        }
        return 0;
    }

    /// <summary>CK_ATTRIBUTE 模板构造器（负责非托管缓冲区生命周期）。</summary>
    private sealed class AttrBuilder : IDisposable
    {
        private readonly List<CK_ATTRIBUTE> _attrs = new List<CK_ATTRIBUTE>();
        private readonly List<IntPtr> _bufs = new List<IntPtr>();

        public uint Count { get { return (uint)_attrs.Count; } }
        public CK_ATTRIBUTE[] Template { get { return _attrs.ToArray(); } }

        public void AddUInt(uint type, uint value)
        {
            var p = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(p, (int)value);
            _bufs.Add(p);
            _attrs.Add(new CK_ATTRIBUTE { type = type, pValue = p, ulValueLen = 4 });
        }

        public void AddBytes(uint type, byte[] v)
        {
            if (v == null) return;
            var p = Marshal.AllocHGlobal(v.Length);
            Marshal.Copy(v, 0, p, v.Length);
            _bufs.Add(p);
            _attrs.Add(new CK_ATTRIBUTE { type = type, pValue = p, ulValueLen = (uint)v.Length });
        }

        public void AddString(uint type, string v)
        {
            AddBytes(type, Encoding.UTF8.GetBytes(v ?? ""));
        }

        public void Dispose()
        {
            foreach (var b in _bufs) { try { Marshal.FreeHGlobal(b); } catch { } }
            _bufs.Clear();
            _attrs.Clear();
        }
    }

    /// <summary>
    /// 导入 PKCS#12：先写证书对象，再分别用「最小模板 / 完整模板」尝试写私钥对象，
    /// 逐步打印返回码，用于判定本设备是否支持外部私钥导入。
    /// </summary>
    private static void ImportPkcs12(uint session, C_CreateObjectFn createObj,
        string path, string password, bool certOnly)
    {
        Console.WriteLine();
        Console.WriteLine("  === 导入 PFX（C_CreateObject） ===");
        if (createObj == null) { Console.WriteLine("    [!] DLL 未导出 C_CreateObject"); return; }
        if (!System.IO.File.Exists(path)) { Console.WriteLine("    [!] 文件不存在: " + path); return; }

        X509Certificate2 cert;
        try
        {
            cert = new X509Certificate2(path, string.IsNullOrEmpty(password) ? null : password,
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            Console.WriteLine("    [!] 打开 PFX 失败（密码是否正确？）: " + ex.Message);
            return;
        }

        using (cert)
        {
            byte[] der;
            try { der = cert.Export(X509ContentType.Cert); }
            catch (Exception ex) { Console.WriteLine("    [!] 导出证书失败: " + ex.Message); return; }

            var id = SHA1.HashData(der);
            var label = cert.GetNameInfo(X509NameType.SimpleName, false);
            Console.WriteLine("    Subject       = " + cert.Subject);
            Console.WriteLine("    Issuer        = " + cert.Issuer);
            Console.WriteLine("    NotAfter      = " + cert.NotAfter.ToString("yyyy-MM-dd"));
            Console.WriteLine("    HasPrivateKey = " + cert.HasPrivateKey);
            Console.WriteLine("    CKA_ID(SHA1)  = " + Convert.ToHexString(id));

            // A) 证书对象（CKO_CERTIFICATE）
            uint hCert = 0;
            using (var a = new AttrBuilder())
            {
                a.AddUInt(CKA_CLASS, CKO_CERTIFICATE);
                a.AddUInt(CKA_CERTIFICATE_TYPE, CKC_X_509);
                a.AddUInt(CKA_TOKEN, 1);
                a.AddBytes(CKA_VALUE, der);
                a.AddBytes(CKA_ID, id);
                a.AddString(CKA_LABEL, label);
                var r = createObj(session, a.Template, a.Count, ref hCert);
                Console.WriteLine("    [A] 创建证书对象 → " + Err(r)
                                  + (r == CKR_OK ? "   句柄=0x" + hCert.ToString("X") : ""));
            }

            // B) 私钥对象（CKO_PRIVATE_KEY）
            if (!certOnly && cert.HasPrivateKey)
            {
                using (var rsa = cert.GetRSAPrivateKey())
                {
                    if (rsa == null)
                    {
                        Console.WriteLine("    [B] PFX 内私钥不是 RSA，跳过私钥导入");
                    }
                    else
                    {
                        var p = rsa.ExportParameters(true);

                        uint h1 = 0, r1;
                        using (var a = new AttrBuilder())
                        {
                            a.AddUInt(CKA_CLASS, CKO_PRIVATE_KEY);
                            a.AddUInt(CKA_KEY_TYPE, CKK_RSA);
                            a.AddUInt(CKA_TOKEN, 1);
                            a.AddUInt(CKA_PRIVATE, 1);
                            a.AddBytes(CKA_ID, id);
                            a.AddBytes(CKA_MODULUS, p.Modulus);
                            a.AddBytes(CKA_PUBLIC_EXPONENT, p.Exponent);
                            r1 = createObj(session, a.Template, a.Count, ref h1);
                        }
                        Console.WriteLine("    [B1] 私钥(最小模板 CLASS/KEY_TYPE/TOKEN/PRIVATE/ID/MODULUS/E) → " + Err(r1));

                        uint h2 = 0, r2;
                        using (var a = new AttrBuilder())
                        {
                            a.AddUInt(CKA_CLASS, CKO_PRIVATE_KEY);
                            a.AddUInt(CKA_KEY_TYPE, CKK_RSA);
                            a.AddUInt(CKA_TOKEN, 1);
                            a.AddUInt(CKA_PRIVATE, 1);
                            a.AddBytes(CKA_ID, id);
                            a.AddString(CKA_LABEL, label);
                            a.AddBytes(CKA_MODULUS, p.Modulus);
                            a.AddBytes(CKA_PUBLIC_EXPONENT, p.Exponent);
                            a.AddBytes(CKA_PRIVATE_EXPONENT, p.D);
                            a.AddBytes(CKA_PRIME_1, p.P);
                            a.AddBytes(CKA_PRIME_2, p.Q);
                            a.AddBytes(CKA_EXPONENT_1, p.DP);
                            a.AddBytes(CKA_EXPONENT_2, p.DQ);
                            a.AddBytes(CKA_COEFFICIENT, p.InverseQ);
                            r2 = createObj(session, a.Template, a.Count, ref h2);
                        }
                        Console.WriteLine("    [B2] 私钥(完整模板，含 D/P/Q/DP/DQ/InverseQ) → " + Err(r2));

                        if (r1 != CKR_OK && r2 != CKR_OK)
                        {
                            Console.WriteLine("    => 结论：本设备不接受外部私钥导入（两次 C_CreateObject 均失败）。");
                            Console.WriteLine("       恒宝 U 宝的私钥由卡内生成、证书由银行渠道下载，");
                            Console.WriteLine("       因此「导入含私钥的 PFX」在该设备上不可用；证书对象本身可写入。");
                        }
                        else
                        {
                            Console.WriteLine("    => 私钥导入成功（" + (r1 == CKR_OK ? "最小模板" : "完整模板")
                                              + "），可用 --sign 验证签名，用 --list 复核证书列表。");
                        }
                    }
                }
            }
            else if (certOnly)
            {
                Console.WriteLine("    [B] --cert-only 已开启，跳过私钥导入");
            }
            Console.WriteLine("    === 导入结束 ===");
        }
    }
}
