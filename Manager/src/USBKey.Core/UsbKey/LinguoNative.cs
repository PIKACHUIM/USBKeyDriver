using System.Runtime.InteropServices;
using System.Text;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 凌国（Linguo）USB Key 底层互操作层：设备枚举 + SCSI 直通 APDU 传输。
/// <para>
/// 逆向来源：<c>Library/Linguo USB Key DLL/ZjkccbUKey/win32/ZJK_LgKit.exe</c>
/// （官方管理工具）与 <c>LgImpl.dll</c>（凌国 CSP），2026-09 静态逆向。关键证据：
/// </para>
/// <list type="bullet">
/// <item><b>设备枚举</b>：<c>SetupDiGetClassDevsA</c>，ClassGuid 硬编码于 RVA 0x45DFA0，
/// 值为 <c>{53F56308-B6BF-11D0-94F2-00A0C91EFB8B}</c>（GUID_DEVINTERFACE_CDROM）——
/// 凌国 Key 以 U 盘/CD-ROM 复合设备形态暴露，管理指令走 SCSI 直通。</item>
/// <item><b>打开设备</b>：<c>CreateFileA(path, 0xC0000000, 3, 0, 3, 0x80, 0)</c>
/// （反汇编 0x4075A9-0x407572）。</item>
/// <item><b>通信</b>：<c>DeviceIoControl</c>，IOCTL 取 <c>0x4D014</c>
/// （IOCTL_SCSI_PASS_THROUGH_DIRECT）与 <c>0x4D004</c>（IOCTL_SCSI_PASS_THROUGH）。</item>
/// <item><b>SPT 结构常量</b>（反汇编 0x404E97/0x404EA1/0x404EA6 的立即数）：
/// Length=0x2C、CdbLength=0x0C、SenseInfoLength=0x18；SenseInfoOffset=0x30
/// （0x404F06 处写入，等于结构 44 字节 8 字节对齐后的位置）。</item>
/// <item><b>厂商 CDB 命令码</b>：<c>Cdb[0]=0xE2</c>（0x404F0E 写入），
/// <c>Cdb[8] = 数据长度低字节</c>（0x404F13 写入），APDU 本体经数据阶段
/// （DataBuffer）传输。</item>
/// <item><b>响应格式</b>：数据 + SW1SW2，代码校验 <c>0x9000</c>（0x40557D）。</item>
/// <item><b>设备识别</b>：SCSI INQUIRY(0x12) 响应中含 ASCII <c>"LGUSB   ZJK"</c>
/// （0x404B00 与 RVA 0x452BF8 字面量逐字节比较；注意是 3 个空格）。</item>
/// </list>
/// <para>本类不依赖任何厂商 DLL（纯 P/Invoke），因此不受 DLL 位数限制。</para>
/// </summary>
internal static class LinguoNative
{
    // ======================= 常量 =======================

    /// <summary>设备接口 GUID（逆向自 RVA 0x45DFA0）。</summary>
    internal static readonly Guid DeviceInterfaceGuid = new("53F56308-B6BF-11D0-94F2-00A0C91EFB8B");

    /// <summary>IOCTL_SCSI_PASS_THROUGH（0x004D004）。</summary>
    internal const uint IoctlScsiPassThrough = 0x0004D004;

    /// <summary>IOCTL_SCSI_PASS_THROUGH_DIRECT（0x004D014）——官方工具主用。</summary>
    internal const uint IoctlScsiPassThroughDirect = 0x0004D014;

    /// <summary>SCSI_PASS_THROUGH(_DIRECT).Length（逆向 0x2C）。</summary>
    internal const ushort SptLength = 0x2C;

    /// <summary>CDB 长度（逆向 0x0C）。</summary>
    internal const byte SptCdbLength = 0x0C;

    /// <summary>传感数据长度（逆向 0x18）。</summary>
    internal const byte SptSenseLength = 0x18;

    /// <summary>传感数据在缓冲内的偏移（逆向 0x30）。</summary>
    internal const uint SptSenseOffset = 0x30;

    /// <summary>厂商自定义 CDB 命令码：发送/接收 APDU（逆向 0xE2）。</summary>
    internal const byte CdbApdu = 0xE2;

    /// <summary>SCSI INQUIRY 的 CDB[0]。</summary>
    internal const byte ScsiInquiry = 0x12;

    /// <summary>数据缓冲上限（逆向 0x400）。</summary>
    internal const int DataBufferSize = 0x400;

    /// <summary>设备识别标识（中间 3 个空格，见 RVA 0x452BF8）。</summary>
    internal const string DeviceSignature = "LGUSB   ZJK";

    internal const uint GenericReadWrite = 0xC0000000;
    internal const uint OpenExisting = 3;
    internal const uint FileAttributeNormal = 0x80;

    /// <summary>SCSI_IOCTL_DATA_OUT。</summary>
    internal const byte DataOut = 0;
    /// <summary>SCSI_IOCTL_DATA_IN。</summary>
    internal const byte DataIn = 1;

    // ======================= 数据结构 =======================

    /// <summary>SCSI_PASS_THROUGH_DIRECT（x86，44 字节，与逆向 P/Invoke 布局一致）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ScsiPassThroughDirect
    {
        public ushort Length;
        public byte ScsiStatus;
        public byte PathId;
        public byte TargetId;
        public byte Lun;
        public byte CdbLength;
        public byte SenseInfoLength;
        public byte DataIn;
        public uint DataTransferLength;
        public uint TimeOutValue;
        public IntPtr DataBuffer;
        public uint SenseInfoOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Cdb;
    }

    /// <summary>
    /// 普通 SCSI_PASS_THROUGH（x86，44 字节）。
    /// 与 DIRECT 版的唯一区别：数据缓冲用相对 IOCTL 缓冲的**偏移**而非指针。
    /// 官方工具的设备识别（0x404A50）走的就是这一版 + <see cref="IoctlScsiPassThrough"/>。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ScsiPassThrough
    {
        public ushort Length;
        public byte ScsiStatus;
        public byte PathId;
        public byte TargetId;
        public byte Lun;
        public byte CdbLength;
        public byte SenseInfoLength;
        public byte DataIn;
        public uint DataTransferLength;
        public uint TimeOutValue;
        public uint DataBufferOffset;
        public uint SenseInfoOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Cdb;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SpDeviceInterfaceData
    {
        public int CbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    // ======================= SetupAPI =======================

    private const uint DigcfPresent = 0x02;
    private const uint DigcfDeviceInterface = 0x10;

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr deviceInfoSet, IntPtr deviceInfoData, ref Guid interfaceClassGuid,
        uint memberIndex, ref SpDeviceInterfaceData deviceInterfaceData);

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet, ref SpDeviceInterfaceData deviceInterfaceData,
        IntPtr deviceInterfaceDetailData, int deviceInterfaceDetailDataSize,
        out int requiredSize, IntPtr deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    // ======================= 文件 / IOCTL =======================

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr CreateFileA(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr device, uint ioControlCode,
        IntPtr inBuffer, int inBufferSize,
        IntPtr outBuffer, int outBufferSize,
        out int bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static readonly IntPtr InvalidHandle = new(-1);

    // ======================= 设备枚举 =======================

    /// <summary>枚举设备接口路径（形如 <c>\\?\usbstor#cdrom&amp;ven_...&amp;...#{53f56308-...}</c>）。</summary>
    internal static List<string> EnumerateDevicePaths()
    {
        var result = new List<string>();
        var guid = DeviceInterfaceGuid;
        IntPtr set = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero,
                                        DigcfPresent | DigcfDeviceInterface);
        if (set == IntPtr.Zero || set == InvalidHandle) return result;

        try
        {
            uint index = 0;
            while (true)
            {
                var ifData = new SpDeviceInterfaceData { CbSize = Marshal.SizeOf<SpDeviceInterfaceData>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref guid, index, ref ifData))
                    break;

                SetupDiGetDeviceInterfaceDetail(set, ref ifData, IntPtr.Zero, 0, out int required, IntPtr.Zero);
                if (required > 0)
                {
                    IntPtr buf = Marshal.AllocHGlobal(required);
                    try
                    {
                        // SP_DEVICE_INTERFACE_DETAIL_DATA.cbSize：x86 = 4 + 1 = 5
                        // （与官方工具 0x40753F 的 mov DWORD PTR [ebp],0x5 一致）
                        Marshal.WriteInt32(buf, 5);
                        if (SetupDiGetDeviceInterfaceDetail(set, ref ifData, buf, required, out _, IntPtr.Zero))
                        {
                            string path = Marshal.PtrToStringAnsi(buf + 4) ?? "";
                            if (!string.IsNullOrWhiteSpace(path)) result.Add(path);
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
                index++;
            }
        }
        finally
        {
            SetupDiDestroyDeviceInfoList(set);
        }
        return result;
    }

    // ======================= 设备会话 =======================

    /// <summary>已打开的设备会话。</summary>
    internal sealed class DeviceHandle : IDisposable
    {
        private readonly IntPtr _h;
        private readonly object _ioSync = new();

        internal string Path { get; }
        internal string SerialNumber { get; set; } = "";

        /// <summary>
        /// SCSI 逻辑单元号。凌国 Key 为「CD-ROM + 私有通信 LUN」复合设备时，
        /// 私有命令需发到非 0 的 LUN（真机校准项）。
        /// </summary>
        internal byte Lun { get; set; }

        /// <summary>SCSI PathId（官方工具置 1，真机校准项）。</summary>
        internal byte PathId { get; set; }

        /// <summary>SCSI TargetId（官方工具置 1，真机校准项）。</summary>
        internal byte TargetId { get; set; }

        internal DeviceHandle(string path, IntPtr handle)
        {
            Path = path;
            _h = handle;
        }

        internal bool IsValid => _h != IntPtr.Zero && _h != InvalidHandle;

        /// <summary>
        /// 发送 ISO7816 APDU 并读取响应。
        /// <para>
        /// 传输布局（与官方工具一致）：<c>CDB[0]=0xE2</c>、<c>CDB[8]=len&amp;0xFF</c>、
        /// <c>DataBuffer</c> 指向 APDU 缓冲、<c>DataTransferLength=len</c>、
        /// <c>SenseInfoOffset=0x30</c>。
        /// </para>
        /// <para>
        /// <paramref name="mode"/> 决定读写方式：<see cref="TransferMode.SingleShot"/> 为
        /// 单次调用（DataIn=IN，把 APDU 放入数据缓冲后由驱动原位回填响应）；
        /// <see cref="TransferMode.SendThenRead"/> 为先 OUT 发送、再 IN 读取（官方 DataIn=0 的行为）。
        /// 二者在真机上只有一个成立，故做成可切换以便校准。
        /// </para>
        /// </summary>
        internal byte[] Transceive(byte[] apdu, TransferMode mode, out ushort sw)
        {
            sw = 0;
            if (!IsValid) return Array.Empty<byte>();
            if (apdu.Length < 4) throw new ArgumentException("APDU 至少 4 字节（CLA INS P1 P2）", nameof(apdu));
            if (apdu.Length > DataBufferSize) throw new ArgumentException($"APDU 过长（>{DataBufferSize}）", nameof(apdu));

            lock (_ioSync)
            {
                if (mode == TransferMode.SingleShot)
                {
                    var buf = new byte[DataBufferSize];
                    Array.Copy(apdu, buf, apdu.Length);
                    if (!Exec(apdu.Length, buf, DataIn, out int got))
                        return Array.Empty<byte>();
                    return ExtractSw(buf, got, out sw);
                }
                else
                {
                    var outBuf = new byte[DataBufferSize];
                    Array.Copy(apdu, outBuf, apdu.Length);
                    if (!Exec(apdu.Length, outBuf, DataOut, out _))
                        return Array.Empty<byte>();

                    var inBuf = new byte[DataBufferSize];
                    if (!Exec(DataBufferSize, inBuf, DataIn, out int got))
                        return Array.Empty<byte>();
                    return ExtractSw(inBuf, got, out sw);
                }
            }
        }

        private static byte[] ExtractSw(byte[] data, int len, out ushort sw)
        {
            if (len >= 2)
            {
                sw = (ushort)((data[len - 2] << 8) | data[len - 1]);
                return data.AsSpan(0, len - 2).ToArray();
            }
            sw = 0;
            return Array.Empty<byte>();
        }

        /// <summary>按官方布局执行一次 SCSI_PASS_THROUGH_DIRECT。</summary>
        private bool Exec(int transferLength, byte[] dataBuffer, byte dataIn, out int returnedLength)
        {
            returnedLength = 0;
            int structSize = Marshal.SizeOf<ScsiPassThroughDirect>(); // 44
            int total = checked((int)SptSenseOffset + SptSenseLength); // 0x48

            IntPtr ctrl = Marshal.AllocHGlobal(total);
            IntPtr data = Marshal.AllocHGlobal(dataBuffer.Length);
            try
            {
                for (int i = 0; i < total; i++) Marshal.WriteByte(ctrl, i, 0);

                var spt = new ScsiPassThroughDirect
                {
                    Length = SptLength,
                    CdbLength = SptCdbLength,
                    SenseInfoLength = SptSenseLength,
                    Lun = Lun,
                    DataIn = dataIn,
                    DataTransferLength = (uint)transferLength,
                    TimeOutValue = 10,
                    DataBuffer = data,
                    SenseInfoOffset = SptSenseOffset,
                    Cdb = new byte[16],
                };
                spt.Cdb[0] = CdbApdu;
                spt.Cdb[8] = (byte)(transferLength & 0xFF);
                spt.Cdb[9] = (byte)((transferLength >> 8) & 0xFF);

                Marshal.StructureToPtr(spt, ctrl, false);
                Marshal.Copy(dataBuffer, 0, data, dataBuffer.Length);

                bool ok = DeviceIoControl(_h, IoctlScsiPassThroughDirect, ctrl, total,
                                          ctrl, total, out _, IntPtr.Zero);
                if (!ok && dataIn == DataIn)
                {
                    // 部分驱动要求输出缓冲使用同一块内存；失败时再试一次（保持静默，交由上层判断）
                    return false;
                }

                var back = Marshal.PtrToStructure<ScsiPassThroughDirect>(ctrl);
                int got = (int)Math.Min(back.DataTransferLength, (uint)dataBuffer.Length);
                if (got > 0) Marshal.Copy(data, dataBuffer, 0, got);
                returnedLength = got;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(ctrl);
                Marshal.FreeHGlobal(data);
            }
        }

        /// <summary>
        /// 读取 SCSI INQUIRY 响应。
        /// <para>
        /// 长度默认 192（0xC0），与官方工具一致（0x404A8D 处 <c>Cdb[4] = 0xC0</c>、
        /// <c>DataTransferLength = 0xC0</c>）。部分厂商把标识放在标准 36 字节之后的
        /// 扩展区（其 <c>additional length</c> 字段可达 0x5B+），故必须读满。
        /// </para>
        /// </summary>
        internal byte[] Inquiry(int length = 192)
        {
            var cdb = new byte[6];
            cdb[0] = ScsiInquiry;
            cdb[4] = (byte)Math.Min(length, 255);
            var buf = new byte[length];
            if (!ExecScsi(cdb, buf, DataIn, out int got)) return Array.Empty<byte>();
            return got > 0 ? buf.AsSpan(0, Math.Min(got, length)).ToArray() : Array.Empty<byte>();
        }

        /// <summary>
        /// 用**与官方工具完全一致**的参数发 SCSI INQUIRY（0x404A50 的复刻）：
        /// <c>IOCTL_SCSI_PASS_THROUGH(0x4D004)</c>、<c>Length=0x2C</c>、<c>CdbLength=6</c>、
        /// <c>Cdb[0]=0x12</c>、<c>Cdb[4]=0xC0</c>、<c>DataTransferLength=0xC0</c>、
        /// <c>DataBufferOffset=0x50</c>、<c>SenseInfoOffset=0x30</c>、<c>PathId=TargetId=1</c>、
        /// 输入/输出同一块 0x110 字节缓冲，数据位于 offset 0x50。
        /// </summary>
        internal byte[] OfficialInquiry()
        {
            const int total = 0x110;   // = DataBufferOffset(0x50) + DataTransferLength(0xC0)
            const int dataOffset = 0x50;
            const int dataLen = 0xC0;

            IntPtr buf = Marshal.AllocHGlobal(total);
            try
            {
                for (int i = 0; i < total; i++) Marshal.WriteByte(buf, i, 0);

                var spt = new ScsiPassThrough
                {
                    Length = SptLength,
                    PathId = 1,
                    TargetId = 1,
                    Lun = Lun,
                    CdbLength = 6,
                    SenseInfoLength = SptSenseLength,
                    DataIn = DataIn,
                    DataTransferLength = dataLen,
                    TimeOutValue = 0x0F,
                    DataBufferOffset = dataOffset,
                    SenseInfoOffset = SptSenseOffset,
                    Cdb = new byte[16],
                };
                spt.Cdb[0] = ScsiInquiry;
                spt.Cdb[4] = (byte)dataLen;
                Marshal.StructureToPtr(spt, buf, false);

                bool ok = DeviceIoControl(_h, IoctlScsiPassThrough, buf, SptLength, buf, total, out _, IntPtr.Zero);
                if (!ok)
                {
                    // 失败时用 SPT_DIRECT 兜底（部分驱动只支持 DIRECT 版）
                    return Inquiry(dataLen);
                }

                var back = Marshal.PtrToStructure<ScsiPassThrough>(buf);
                int got = (int)Math.Min(back.DataTransferLength == 0 ? 0u : back.DataTransferLength, (uint)dataLen);
                if (got <= 0) got = dataLen;
                var data = new byte[got];
                Marshal.Copy(buf + dataOffset, data, 0, got);
                return data;
            }
            catch
            {
                return Inquiry(dataLen);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        /// <summary>执行任意 SCSI CDB（用于 INQUIRY 等非 APDU 命令）。</summary>
        private bool ExecScsi(byte[] cdb, byte[] dataBuffer, byte dataIn, out int returnedLength)
        {
            returnedLength = 0;
            int total = checked((int)SptSenseOffset + SptSenseLength);
            IntPtr ctrl = Marshal.AllocHGlobal(total);
            IntPtr data = Marshal.AllocHGlobal(dataBuffer.Length);
            try
            {
                for (int i = 0; i < total; i++) Marshal.WriteByte(ctrl, i, 0);
                var spt = new ScsiPassThroughDirect
                {
                    Length = SptLength,
                    PathId = PathId,
                    TargetId = TargetId,
                    CdbLength = SptCdbLength,
                    SenseInfoLength = SptSenseLength,
                    Lun = Lun,
                    DataIn = dataIn,
                    DataTransferLength = (uint)dataBuffer.Length,
                    TimeOutValue = 10,
                    DataBuffer = data,
                    SenseInfoOffset = SptSenseOffset,
                    Cdb = new byte[16],
                };
                Array.Copy(cdb, 0, spt.Cdb, 0, Math.Min(cdb.Length, 12));
                Marshal.StructureToPtr(spt, ctrl, false);

                if (!DeviceIoControl(_h, IoctlScsiPassThroughDirect, ctrl, total, ctrl, total, out _, IntPtr.Zero))
                    return false;

                var back = Marshal.PtrToStructure<ScsiPassThroughDirect>(ctrl);
                int got = (int)Math.Min(back.DataTransferLength, (uint)dataBuffer.Length);
                if (got > 0) Marshal.Copy(data, dataBuffer, 0, got);
                returnedLength = got;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(ctrl);
                Marshal.FreeHGlobal(data);
            }
        }

        public void Dispose()
        {
            if (_h != IntPtr.Zero && _h != InvalidHandle) CloseHandle(_h);
        }
    }

    /// <summary>APDU 传输模式（真机校准用开关）。</summary>
    internal enum TransferMode
    {
        /// <summary>单次 IN 调用（APDU 放数据缓冲，响应原位回填）。</summary>
        SingleShot,
        /// <summary>先 OUT 发送再 IN 读取（与官方 DataIn=0 的行为一致）。</summary>
        SendThenRead,
    }

    /// <summary>打开设备路径。</summary>
    internal static DeviceHandle Open(string path)
    {
        IntPtr h = CreateFileA(path, GenericReadWrite, 3, IntPtr.Zero,
                               OpenExisting, FileAttributeNormal, IntPtr.Zero);
        if (h == IntPtr.Zero || h == InvalidHandle)
            throw new IOException($"打开设备失败：{path}（Win32 错误 {Marshal.GetLastWin32Error()}）");
        return new DeviceHandle(path, h);
    }

    /// <summary>
    /// 识别凌国 Key：严格复刻官方工具 0x404A50 的校验规则——
    /// INQUIRY 响应 <c>offset 8..15</c> 必须等于 <c>"LGUSB   "</c>（含 3 个空格），
    /// 且 <c>offset 16..18</c> 必须等于 <c>"ZJK"</c>。
    /// </summary>
    internal static bool Probe(DeviceHandle dev, out string vendorProduct)
    {
        vendorProduct = "";
        try
        {
            var resp = dev.OfficialInquiry();
            if (resp.Length < 19) return false;

            string vendor = Encoding.ASCII.GetString(resp, 8, 8);      // 含空格，不 Trim
            string product = Encoding.ASCII.GetString(resp, 16, Math.Min(16, resp.Length - 16)).TrimEnd();
            vendorProduct = $"{vendor.TrimEnd()} {product}".Trim();

            return vendor == DeviceSignature[..8]
                   && resp[16] == (byte)'Z'
                   && resp[17] == (byte)'J'
                   && resp[18] == (byte)'K';
        }
        catch
        {
            return false;
        }
    }
}
