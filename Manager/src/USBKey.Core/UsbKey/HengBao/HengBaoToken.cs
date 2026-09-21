using System.Text;

namespace USBKey.Core.UsbKey.HengBao;

/// <summary>
/// 从卡片读到的设备信息（由 <c>80 32 00 00</c> 返回的 TLV 解析）。
/// <para>实测样例（49 字节）：<c>01 02 14D6 | 02 02 3032 | 03 08 &lt;8字节序列号&gt; |
/// 04 04 &lt;BCD 生产日期&gt; | 05 16 &lt;22字节&gt; | 0F</c></para>
/// </summary>
public sealed class HengBaoDeviceInfo
{
    /// <summary>设备接口路径。</summary>
    public string DevicePath { get; set; } = "";
    /// <summary>USB VID（TLV tag 01，实测 0x14D6）。</summary>
    public int Vid { get; set; }
    /// <summary>USB PID（TLV tag 02，实测 0x3032）。</summary>
    public int Pid { get; set; }
    /// <summary>序列号（TLV tag 03，8 字节，十六进制）。</summary>
    public string SerialNumber { get; set; } = "";
    /// <summary>生产日期（TLV tag 04，BCD 编码，可空）。</summary>
    public DateTime? ProductionDate { get; set; }
    /// <summary>设备编号（TLV tag 05 尾部的 16 位 ASCII 数字串）。</summary>
    public string DeviceCode { get; set; } = "";
    /// <summary>信息块末尾的孤立字节（实测 <c>0x0F</c>，含义待确认，可能是口令最大长度）。</summary>
    public int? Trailer { get; set; }
    /// <summary>原始 TLV（十六进制，便于诊断）。</summary>
    public string RawTlvHex { get; set; } = "";
    /// <summary><c>80 32 00 01</c> 的原始返回（8 字节，含义待确认）。</summary>
    public string RawStatus01Hex { get; set; } = "";
    /// <summary><c>80 32 00 04</c> 的原始返回（7 字节，含义待确认）。</summary>
    public string RawStatus04Hex { get; set; } = "";
    /// <summary><c>00 20 00 00 00</c> + GET RESPONSE 得到的状态字（口令状态查询，只读、不消耗尝试次数）。</summary>
    public string PinStateCode { get; set; } = "";

    /// <summary>人类可读摘要（列表/详情页用）。</summary>
    public string Describe()
    {
        var parts = new List<string>();
        if (Vid != 0) parts.Add($"USB {Vid:X4}:{Pid:X4}");
        if (!string.IsNullOrEmpty(SerialNumber)) parts.Add("序列号 " + SerialNumber);
        if (ProductionDate is { } d) parts.Add("生产日期 " + d.ToString("yyyy-MM-dd"));
        if (!string.IsNullOrEmpty(DeviceCode)) parts.Add("设备编号 " + DeviceCode);
        if (Trailer is { } t) parts.Add($"信息块尾字节 0x{t:X2}");
        if (!string.IsNullOrEmpty(PinStateCode)) parts.Add("口令状态 " + PinStateCode);
        return string.Join(" · ", parts);
    }
}

/// <summary>
/// 恒宝 U 宝的高层卡操作。内部完成「SCSI-BOT 透传 + MSP 安全会话」两件事，
/// 对外只暴露普通 APDU 语义（<c>Transmit</c>）。
///
/// <para><b>使用</b>：<see cref="TryOpen"/> 一次即可完成打开设备与 MSP 握手；
/// 之后所有命令都自动封装。完整协议见 <c>Roadmap/07-HengBao-U宝逆向分析.md</c> §2.2.5。</para>
/// </summary>
public sealed class HengBaoToken : IDisposable
{
    /// <summary>当卡片返回 0x6Cxx 时表示「Le 不对」，重试即可（厂商 <c>READ BINARY</c> 等命令同样依此）。</summary>
    private const int MaxLeFixRetry = 2;

    private readonly HengBaoScsiChannel _channel;
    private readonly HengBaoMspSession _msp;

    private HengBaoToken(HengBaoScsiChannel channel, HengBaoMspSession msp, string handshakeLog)
    {
        _channel = channel;
        _msp = msp;
        HandshakeLog = handshakeLog;
    }

    /// <summary>设备接口路径。</summary>
    public string DevicePath => _channel.DevicePath;

    /// <summary>握手过程的可读日志（便于界面/日志排查）。</summary>
    public string HandshakeLog { get; }

    /// <summary>会话密钥（十六进制）。注意：这是敏感材料，仅用于诊断，不要写入常规日志。</summary>
    public string SessionKeyHex => _msp.SessionKeyHex;

    // ======================================================================
    // 打开
    // ======================================================================

    /// <summary>打开设备并完成 MSP 握手。失败时 <paramref name="error"/> 说明具体卡在哪一步。</summary>
    public static bool TryOpen(string devicePath, out HengBaoToken? token, out string error)
    {
        token = null;
        var channel = HengBaoScsi.TryOpen(devicePath, out var win32)
            ?? throw new InvalidOperationException(
                   $"无法打开设备（Win32 错误 {win32}）：{devicePath}\n" +
                   "常见原因：未以管理员身份运行（需要打开 CD-ROM/磁盘设备接口）。");
        try
        {
            if (!HengBaoMspHandshake.TryEstablish(channel, out var session, out error, out var log))
                return false;
            token = new HengBaoToken(channel, session!, log);
            return true;
        }
        catch
        {
            channel.Dispose();
            throw;
        }
    }

    /// <summary>
    /// 枚举并尝试打开全部恒宝设备，返回可用的设备信息与其句柄；
    /// <paramref name="diagnostics"/> 记录每个设备失败的原因（用于界面提示）。
    /// </summary>
    public static IReadOnlyList<HengBaoDeviceInfo> Discover(
        out List<(string Path, string Error)> diagnostics)
    {
        var result = new List<HengBaoDeviceInfo>();
        diagnostics = new List<(string, string)>();

        var paths = HengBaoScsi.EnumerateDevicePaths();
        if (paths.Count == 0)
        {
            diagnostics.Add(("(无)", "没有任何 Disk/CD-ROM 设备路径包含 \"" + HengBaoScsi.PathFilter + "\""));
            return result;
        }

        foreach (var path in paths)
        {
            HengBaoToken? token = null;
            try
            {
                if (!TryOpen(path, out token, out var err))
                {
                    diagnostics.Add((path, err));
                    continue;
                }
                if (!token!.ReadDeviceInfo(out var info, out var err2))
                {
                    diagnostics.Add((path, "已握手但读信息失败：" + err2));
                    continue;
                }
                result.Add(info!);
            }
            catch (Exception ex)
            {
                diagnostics.Add((path, ex.Message));
            }
            finally
            {
                token?.Dispose();
            }
        }
        return result;
    }

    // ======================================================================
    // APDU
    // ======================================================================

    /// <summary>发一条受 MSP 保护的 APDU。</summary>
    public bool Transmit(byte[] apdu, out uint sw, out byte[] data, out string error)
        => _msp.Transmit(apdu, out sw, out data, out error);

    /// <summary>
    /// 发送 APDU；若卡片回 <c>0x6Cxx</c>（Le 不对），自动用 <c>xx</c> 作为 Le 重发。
    /// 这是该 COS 的固定套路（例如 <c>80 32 00 00 FF</c> → <c>6C31</c> → <c>80 32 00 00 31</c>）。
    /// </summary>
    public bool TransmitWithLeFix(byte[] apdu, out uint sw, out byte[] data, out string error)
    {
        sw = 0;
        data = Array.Empty<byte>();
        error = "";
        var current = (byte[])apdu.Clone();
        for (int attempt = 0; attempt <= MaxLeFixRetry; attempt++)
        {
            if (!Transmit(current, out sw, out data, out error)) return false;
            if ((sw & 0xFF00) != 0x6C00) return true;

            var wanted = (byte)(sw & 0xFF);
            if (current.Length == 0 || current[current.Length - 1] == wanted) return true;   // 已经是对的，避免死循环
            current[current.Length - 1] = wanted;
        }
        return true;
    }

    /// <summary>选择令牌应用：<c>SELECT ADF1</c> + <c>GET RESPONSE</c>，成功时应取到 DF 名 <c>HBKEY</c>。</summary>
    public bool SelectTokenApplication(out byte[] fci, out string error)
    {
        fci = Array.Empty<byte>();
        error = "";

        if (!Transmit(new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0xAD, 0xF1 }, out var sw, out _, out error))
            return false;

        // 实测卡片返回 0x6109（还有 9 字节待取），需用 GET RESPONSE 取 FCI
        if (sw == 0x6109)
        {
            if (!Transmit(new byte[] { 0x00, 0xC0, 0x00, 0x00, 0x09 }, out var sw2, out fci, out error))
                return false;
            if (sw2 != 0x9000)
            {
                error = $"GET RESPONSE 返回 0x{sw2:X4}";
                return false;
            }
            return true;
        }

        if (sw == 0x9000) return true;
        error = $"SELECT ADF1 返回 0x{sw:X4}";
        return false;
    }

    /// <summary>读取卡片设备信息（<c>80 32 00 00</c>）及其它状态块。</summary>
    public bool ReadDeviceInfo(out HengBaoDeviceInfo? info, out string error)
    {
        info = null;
        error = "";

        if (!SelectTokenApplication(out _, out error)) return false;

        // 设备信息 TLV
        if (!TransmitWithLeFix(new byte[] { 0x80, 0x32, 0x00, 0x00, 0xFF }, out var sw, out var tlv, out error))
            return false;
        if (sw != 0x9000)
        {
            error = $"80 32 00 00 返回 0x{sw:X4}";
            return false;
        }

        var result = new HengBaoDeviceInfo
        {
            DevicePath = DevicePath,
            RawTlvHex = HengBaoScsi.ToHex(tlv),
        };
        ParseDeviceInfoTlv(tlv, result);

        // 另外两个状态块（含义待确认，先原样保留）
        if (TransmitWithLeFix(new byte[] { 0x80, 0x32, 0x00, 0x01, 0xFF }, out var sw1, out var d1, out _)
            && sw1 == 0x9000)
            result.RawStatus01Hex = HengBaoScsi.ToHex(d1);

        if (TransmitWithLeFix(new byte[] { 0x80, 0x32, 0x00, 0x04, 0xFF }, out var sw4, out var d4, out _)
            && sw4 == 0x9000)
            result.RawStatus04Hex = HengBaoScsi.ToHex(d4);

        // 口令状态查询：只发 <c>00 20 00 00 00</c>，不带任何口令数据，因此不会消耗尝试次数
        try
        {
            if (Transmit(new byte[] { 0x00, 0x20, 0x00, 0x00, 0x00 }, out var swP, out _, out _)
                && (swP & 0xFF00) == 0x6100)
            {
                var le = (byte)(swP & 0xFF);
                var getResp = new byte[] { 0x00, 0xC0, 0x00, 0x00, le };
                if (Transmit(getResp, out var swG, out var dG, out _) && swG == 0x9000)
                    result.PinStateCode = HengBaoScsi.ToHex(dG);
            }
            else
            {
                result.PinStateCode = $"SW=0x{swP:X4}";
            }
        }
        catch { /* 状态查询失败不影响主体信息 */ }

        info = result;
        return true;
    }

    /// <summary>
    /// 解析 <c>80 32 00 00</c> 的 TLV：<c>tag(1) len(1) value(len)</c>，末尾可能有一个孤立字节。
    /// </summary>
    private static void ParseDeviceInfoTlv(byte[] tlv, HengBaoDeviceInfo into)
    {
        int off = 0;
        while (off + 2 <= tlv.Length)
        {
            var tag = tlv[off];
            var len = tlv[off + 1];
            if (off + 2 + len > tlv.Length) break;
            var value = new byte[len];
            Buffer.BlockCopy(tlv, off + 2, value, 0, len);

            switch (tag)
            {
                case 0x01:
                    if (len == 2) into.Vid = (value[0] << 8) | value[1];
                    break;
                case 0x02:
                    if (len == 2) into.Pid = (value[0] << 8) | value[1];
                    break;
                case 0x03:
                    into.SerialNumber = HengBaoScsi.ToHex(value);
                    break;
                case 0x04:
                    if (len == 4)
                    {
                        // BCD：YY YY MM DD
                        int y = (value[0] >> 4) * 1000 + (value[0] & 0x0F) * 100
                                + (value[1] >> 4) * 10 + (value[1] & 0x0F);
                        int mo = (value[2] >> 4) * 10 + (value[2] & 0x0F);
                        int da = (value[3] >> 4) * 10 + (value[3] & 0x0F);
                        if (y is >= 1990 and <= 2099 && mo is >= 1 and <= 12 && da is >= 1 and <= 31)
                            into.ProductionDate = new DateTime(y, mo, da);
                    }
                    break;
                case 0x05:
                    // 尾部为 16 位 ASCII 数字的设备编号
                    var sb = new StringBuilder();
                    foreach (var b in value)
                        if (b >= 0x30 && b <= 0x39) sb.Append((char)b);
                    if (sb.Length >= 8) into.DeviceCode = sb.ToString();
                    break;
            }
            off += 2 + len;
        }

        if (off < tlv.Length) into.Trailer = tlv[off];
    }

    public void Dispose() => _channel.Dispose();
}
