using System.Text;

namespace USBKey.Core.UsbKey.HengBao;

/// <summary>
/// 恒宝 U 宝的 SCSI-BOT 直通传输通道（完全按 <c>CMBCp.dll</c> 反汇编结果复刻，
/// 2026-09-21 实机验证通过，详见 <c>Roadmap/07-HengBao-U宝逆向分析.md</c> §2.2.5）。
///
/// <para><b>协议要点</b></para>
/// <list type="bullet">
/// <item>设备枚举：<c>GUID_DEVINTERFACE_DISK</c> + <c>GUID_DEVINTERFACE_CDROM</c>，
/// 设备路径（大写后）必须包含 <c>HENGBAO</c>；这就是恒宝未插时
/// <c>C_GetSlotList</c> 返回 0 的原因（别家 CD-ROM 都因不含该串被过滤）。</item>
/// <item>打开：<c>CreateFileA(path, 0xC0000000, 3, 0, 1, 0x80, 0)</c>。</item>
/// <item>透传：<c>DeviceIoControl(IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014)</c>；
/// <c>TargetId=1</c>、<c>Lun=0</c>、<c>CdbLength=16</c>、<c>SenseInfoLength=16</c>，
/// CDB[0]=<c>0xFA</c>、CDB[1]=<c>0x3A</c>(写) / <c>0x08</c>(读)，其余 14 字节为 0。</item>
/// <item>命令帧 <c>43 &lt;len_hi&gt; &lt;len_lo&gt; &lt;payload…&gt;</c>（<c>0x43</c> = 'C'）；
/// 响应帧 <c>52 &lt;len_hi&gt; &lt;len_lo&gt; &lt;payload…&gt;</c>（<c>0x52</c> = 'R'）。</item>
/// </list>
///
/// <para><b>注意</b>：本类只负责「把一段 payload 送进去、把响应 payload 取出来」，
/// 不清楚 APDU 与 MSP 安全报文（后者见 <see cref="HengBaoMspSession"/>）。</para>
/// </summary>
public static class HengBaoScsi
{
    // ---- Win32 常量 ----
    private const uint GenericReadWrite = 0xC0000000;
    private const uint FileShareReadWrite = 0x3;
    private const uint OpenExisting = 3;
    private const uint IoctlScsiPassThroughDirect = 0x0004D014;
    private const byte ScsiDataOut = 0;
    private const byte ScsiDataIn = 1;
    private const uint DigcfPresent = 0x02;
    private const uint DigcfDeviceInterface = 0x10;

    /// <summary>设备路径过滤串（与厂商 <c>EnumDevicesByGuid</c> 一致，大小写不敏感）。</summary>
    public const string PathFilter = "HENGBAO";

    private static readonly Guid GuidDevInterfaceDisk = new("53F56307-B6BF-11D0-94F2-00A0C91EFB8B");
    private static readonly Guid GuidDevInterfaceCdrom = new("53F56308-B6BF-11D0-94F2-00A0C91EFB8B");

    /// <summary>命令帧首字节（'C'）。</summary>
    public const byte FrameCommand = 0x43;
    /// <summary>响应帧首字节（'R'）。</summary>
    public const byte FrameResponse = 0x52;

    // ======================================================================
    // SPTD 结构各字段偏移：32/64 位不同（含 8 字节对齐的 DataBuffer 指针）
    // ======================================================================
    private static int SptdLength => IntPtr.Size == 4 ? 44 : 56;
    private static int OffTargetId => 4;
    private static int OffLun => 5;
    private static int OffCdbLength => 6;
    private static int OffSenseInfoLength => 7;
    private static int OffDataIn => 8;
    private static int OffDataTransferLength => 12;   // 32/64 位同偏移
    private static int OffTimeOutValue => 16;         // 32/64 位同偏移
    private static int OffDataBuffer => IntPtr.Size == 4 ? 20 : 24;
    private static int OffSenseInfoOffset => IntPtr.Size == 4 ? 24 : 32;
    private static int OffCdb => IntPtr.Size == 4 ? 28 : 36;
    private static int SenseOffsetValue => IntPtr.Size == 4 ? 48 : 56;   // 厂商用 48（x86）
    private static int BufferSize => SenseOffsetValue + 32;

    // ======================================================================
    // 设备枚举
    // ======================================================================

    /// <summary>
    /// 枚举恒宝设备接口路径（与厂商逻辑一致：Disk + CDROM 两个接口类，路径须含 <c>HENGBAO</c>）。
    /// </summary>
    public static IReadOnlyList<string> EnumerateDevicePaths()
    {
        var all = new List<string>();
        Collect(GuidDevInterfaceCdrom, all);
        Collect(GuidDevInterfaceDisk, all);
        var hits = new List<string>();
        foreach (var p in all)
            if (p.IndexOf(PathFilter, StringComparison.OrdinalIgnoreCase) >= 0)
                hits.Add(p);
        return hits;
    }

    /// <summary>列出全部（未过滤的）Disk/CDROM 接口路径，便于诊断。</summary>
    public static IReadOnlyList<string> EnumerateAllStoragePaths()
    {
        var all = new List<string>();
        Collect(GuidDevInterfaceCdrom, all);
        Collect(GuidDevInterfaceDisk, all);
        return all;
    }

    private static void Collect(Guid guid, List<string> into)
    {
        var set = SetupDiGetClassDevs(ref guid, IntPtr.Zero, IntPtr.Zero, DigcfPresent | DigcfDeviceInterface);
        if (set == IntPtr.Zero || set == new IntPtr(-1)) return;
        try
        {
            uint index = 0;
            while (true)
            {
                var data = new SP_DEVICE_INTERFACE_DATA { cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>() };
                if (!SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref guid, index, ref data)) break;
                index++;

                uint needed = 0;
                SetupDiGetDeviceInterfaceDetail(set, ref data, IntPtr.Zero, 0, ref needed, IntPtr.Zero);
                if (needed == 0) continue;

                var buf = Marshal.AllocHGlobal((int)needed);
                try
                {
                    // 32 位下 SP_DEVICE_INTERFACE_DETAIL_DATA_A.cbSize = 4 + 1；64 位为 8
                    Marshal.WriteInt32(buf, IntPtr.Size == 4 ? 5 : 8);
                    if (!SetupDiGetDeviceInterfaceDetail(set, ref data, buf, needed, ref needed, IntPtr.Zero))
                        continue;
                    var path = Marshal.PtrToStringAnsi(new IntPtr(buf.ToInt64() + 4));
                    if (!string.IsNullOrEmpty(path)) into.Add(path!);
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    // ======================================================================
    // 通道
    // ======================================================================

    /// <summary>打开一条设备通道。失败时 <paramref name="win32Error"/> 为 GetLastError。</summary>
    public static HengBaoScsiChannel? TryOpen(string devicePath, out int win32Error)
    {
        win32Error = 0;
        var h = CreateFile(devicePath, GenericReadWrite, FileShareReadWrite, IntPtr.Zero,
            OpenExisting, 0x80, IntPtr.Zero);
        if (h == new IntPtr(-1))
        {
            win32Error = Marshal.GetLastWin32Error();
            return null;
        }
        return new HengBaoScsiChannel(devicePath, h);
    }

    /// <summary>
    /// 发一条 SCSI 直通命令。返回 false 时 <paramref name="win32Error"/> 为 Win32 错误码，
    /// <paramref name="sense"/> 为感知数据。
    /// </summary>
    internal static bool ScsiCommand(IntPtr h, byte[] cdb, byte dataIn, byte[] data,
        out byte[] sense, out int transferred, out int win32Error)
    {
        sense = new byte[16];
        transferred = 0;
        win32Error = 0;

        var buf = Marshal.AllocHGlobal(BufferSize);
        var dataPtr = Marshal.AllocHGlobal(Math.Max(data.Length, 1));
        try
        {
            for (int i = 0; i < BufferSize; i++) Marshal.WriteByte(buf, i, 0);
            if (data.Length > 0) Marshal.Copy(data, 0, dataPtr, data.Length);

            Marshal.WriteInt16(buf, 0, (short)SptdLength);
            Marshal.WriteByte(buf, OffTargetId, 1);            // 厂商固定 TargetId = 1
            Marshal.WriteByte(buf, OffLun, 0);
            Marshal.WriteByte(buf, OffCdbLength, (byte)Math.Min(cdb.Length, 16));
            Marshal.WriteByte(buf, OffSenseInfoLength, 16);
            Marshal.WriteByte(buf, OffDataIn, dataIn);
            Marshal.WriteInt32(buf, OffDataTransferLength, data.Length);
            Marshal.WriteInt32(buf, OffTimeOutValue, 60);      // 厂商 CMBCp.dll 用 60 秒
            Marshal.WriteIntPtr(buf, OffDataBuffer, dataPtr);
            Marshal.WriteInt32(buf, OffSenseInfoOffset, SenseOffsetValue);
            Marshal.Copy(cdb, 0, new IntPtr(buf.ToInt64() + OffCdb), Math.Min(cdb.Length, 16));

            uint returned = 0;
            bool ok = DeviceIoControl(h, IoctlScsiPassThroughDirect,
                buf, (uint)BufferSize, buf, (uint)BufferSize, ref returned, IntPtr.Zero);

            Marshal.Copy(new IntPtr(buf.ToInt64() + SenseOffsetValue), sense, 0, 16);

            if (!ok)
            {
                win32Error = Marshal.GetLastWin32Error();
                return false;
            }

            var got = Marshal.ReadInt32(buf, OffDataTransferLength);
            if (got < 0) got = 0;
            if (got > data.Length) got = data.Length;
            transferred = got;
            if (got > 0) Marshal.Copy(dataPtr, data, 0, got);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>把感知数据转成可读文本。</summary>
    public static string DescribeSense(byte[]? sense)
    {
        if (sense == null || sense.Length < 14) return "(无感知数据)";
        if (sense[0] == 0 && sense[1] == 0 && sense[2] == 0) return "(无感知数据)";
        return $"Sense Key=0x{sense[2] & 0x0F:X2} ASC=0x{sense[12]:X2} ASCQ=0x{sense[13]:X2}";
    }

    // ======================================================================
    // 帧
    // ======================================================================

    /// <summary>组厂商命令帧：<c>43 len_hi len_lo &lt;payload&gt;</c>。</summary>
    public static byte[] BuildFrame(byte[] payload)
    {
        var f = new byte[payload.Length + 3];
        f[0] = FrameCommand;
        f[1] = (byte)(payload.Length >> 8);
        f[2] = (byte)(payload.Length & 0xFF);
        Buffer.BlockCopy(payload, 0, f, 3, payload.Length);
        return f;
    }

    /// <summary>
    /// 解析响应帧，返回其中的 payload（注意：payload 末 2 字节是卡片的 SW1/SW2，
    /// 但在 MSP 模式下这 2 字节其实是密文的一部分，由 <see cref="HengBaoMspSession"/> 处理）。
    /// </summary>
    public static bool TryParseFrame(byte[] raw, int got, out byte[] payload, out string error)
    {
        payload = Array.Empty<byte>();
        error = "";
        if (got < 3) { error = $"响应不足 3 字节（got={got}）"; return false; }
        if (raw[0] != FrameResponse)
        {
            error = $"响应帧首字节不是 0x52（实际 0x{raw[0]:X2}）";
            return false;
        }
        int len = (raw[1] << 8) | raw[2];
        if (len + 3 > got) len = got - 3;
        payload = new byte[len];
        Buffer.BlockCopy(raw, 3, payload, 0, len);
        return true;
    }

    /// <summary>十六进制串（大写）。</summary>
    public static string ToHex(byte[] data)
    {
        if (data == null || data.Length == 0) return "";
        var sb = new StringBuilder(data.Length * 2);
        foreach (var b in data) sb.Append(b.ToString("X2"));
        return sb.ToString();
    }

    // ======================================================================
    // P/Invoke
    // ======================================================================

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator,
        IntPtr hwndParent, uint flags);

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr hDevice, uint ioControlCode,
        IntPtr inBuffer, uint inBufferSize, IntPtr outBuffer, uint outBufferSize,
        ref uint bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}

/// <summary>
/// 一条已打开的恒宝设备通道。<see cref="Transmit"/> 做一次「写帧 + 读帧」往返。
/// </summary>
public sealed class HengBaoScsiChannel : IDisposable
{
    private IntPtr _handle;
    private readonly string _path;

    internal HengBaoScsiChannel(string path, IntPtr handle)
    {
        _path = path;
        _handle = handle;
    }

    /// <summary>设备接口路径。</summary>
    public string DevicePath => _path;

    public bool IsOpen => _handle != IntPtr.Zero && _handle != new IntPtr(-1);

    /// <summary>
    /// 发送一段 payload（会套上 <c>43 len…</c> 帧头）并读回响应帧的 payload。
    /// </summary>
    public bool Transmit(byte[] payload, out byte[] responsePayload, out string error)
    {
        responsePayload = Array.Empty<byte>();
        error = "";
        if (!IsOpen) { error = "设备未打开"; return false; }

        var frame = HengBaoScsi.BuildFrame(payload);
        var writeCdb = new byte[16]; writeCdb[0] = 0xFA; writeCdb[1] = 0x3A;
        var readCdb = new byte[16]; readCdb[0] = 0xFA; readCdb[1] = 0x08;

        if (!HengBaoScsi.ScsiCommand(_handle, writeCdb, 0 /*DATA_OUT*/, frame,
                out var sense, out _, out var err))
        {
            error = $"写命令帧失败 err={err} {HengBaoScsi.DescribeSense(sense)}";
            return false;
        }

        var resp = new byte[512];
        if (!HengBaoScsi.ScsiCommand(_handle, readCdb, 1 /*DATA_IN*/, resp,
                out sense, out var got, out err))
        {
            error = $"读响应失败 err={err} {HengBaoScsi.DescribeSense(sense)}";
            return false;
        }

        if (!HengBaoScsi.TryParseFrame(resp, got, out responsePayload, out error))
        {
            error += $"（原始响应 {HengBaoScsi.ToHex(resp.AsSpan(0, Math.Min(got, 32)).ToArray())}）";
            return false;
        }
        return true;
    }

    /// <summary>标准 SCSI INQUIRY：用于验证直通通道本身是否可用。</summary>
    public bool Inquiry(out string vendor, out string product, out string revision, out string error)
    {
        vendor = product = revision = "";
        error = "";
        var inq = new byte[36];
        var cdb = new byte[] { 0x12, 0, 0, 0, 36, 0 };
        if (!HengBaoScsi.ScsiCommand(_handle, cdb, 1 /*DATA_IN*/, inq,
                out var sense, out var got, out var err))
        {
            error = $"INQUIRY 失败 err={err} {HengBaoScsi.DescribeSense(sense)}";
            return false;
        }
        if (got >= 36)
        {
            vendor = Encoding.ASCII.GetString(inq, 8, 8).Trim();
            product = Encoding.ASCII.GetString(inq, 16, 16).Trim();
            revision = Encoding.ASCII.GetString(inq, 32, 4).Trim();
        }
        return true;
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero && _handle != new IntPtr(-1))
        {
            try { CloseHandle(_handle); } catch { }
        }
        _handle = IntPtr.Zero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
