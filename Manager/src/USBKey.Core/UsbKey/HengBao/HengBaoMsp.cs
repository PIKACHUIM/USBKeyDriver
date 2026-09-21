using System.Numerics;
using System.Security.Cryptography;

namespace USBKey.Core.UsbKey.HengBao;

/// <summary>
/// MSP 安全报文的密码学原语（按 <c>CMBCC.dll</c> 反汇编复刻，2026-09-21 实机验证通过）。
///
/// <para><b>逆向依据</b></para>
/// <list type="bullet">
/// <item><c>RsaEngine (sub_10021719)</c>：PKCS#1 v1.5 type-2 的<b>外形</b>，但填充串恒为
/// <c>0x01</c>（不是随机数）—— 即 <c>EM = 00 02 || 01×109 || 00 || K</c>，<c>c = EM^65537 mod n</c>。</item>
/// <item><c>MspCipher (sub_1001F02A)</c>：输入/输出都是 <b>hex 串</b>；
/// hex→bin 后追加 <c>0x80</c> 并补 <c>0x00</c> 到 8 字节倍数，密钥 16 字节走
/// 3DES（两密钥，K3=K1）—— 即标准 3DES-ECB + ISO/IEC 9797-1 方法 2 填充。</item>
/// </list>
/// </summary>
public static class HengBaoMspCrypto
{
    /// <summary>RSA 模数字节数（1024 位）。</summary>
    public const int ModulusSize = 128;
    /// <summary>会话密钥字节数。</summary>
    public const int SessionKeySize = 16;
    /// <summary>RSA 公开指数（厂商硬编码）。</summary>
    public const int PublicExponent = 65537;

    /// <summary>生成 16 字节随机会话密钥。</summary>
    public static byte[] NewSessionKey()
    {
        var k = new byte[SessionKeySize];
        RandomNumberGenerator.Fill(k);
        return k;
    }

    /// <summary>
    /// 组装待加密的 128 字节块：<c>00 02 || 01 × (128-16-3) || 00 || K</c>。
    /// </summary>
    public static byte[] BuildSessionKeyBlock(byte[] sessionKey16)
    {
        if (sessionKey16.Length != SessionKeySize)
            throw new ArgumentException($"会话密钥必须是 {SessionKeySize} 字节", nameof(sessionKey16));

        const int k = ModulusSize;
        var em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x02;
        var padLen = k - sessionKey16.Length - 3;      // 109
        for (int i = 0; i < padLen; i++) em[2 + i] = 0x01;
        em[2 + padLen] = 0x00;
        Buffer.BlockCopy(sessionKey16, 0, em, 3 + padLen, sessionKey16.Length);
        return em;
    }

    /// <summary>用卡片公钥（128 字节模数）加密 16 字节会话密钥，返回 128 字节密文。</summary>
    public static byte[] RsaEncryptSessionKey(byte[] modulus128, byte[] sessionKey16)
    {
        if (modulus128.Length != ModulusSize)
            throw new ArgumentException($"模数必须是 {ModulusSize} 字节", nameof(modulus128));

        var em = BuildSessionKeyBlock(sessionKey16);
        var m = new BigInteger(em, isUnsigned: true, isBigEndian: true);
        var n = new BigInteger(modulus128, isUnsigned: true, isBigEndian: true);
        var c = BigInteger.ModPow(m, PublicExponent, n);

        var raw = c.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > ModulusSize)
            throw new CryptographicException("RSA 结果长度超出模长");

        var result = new byte[ModulusSize];
        Buffer.BlockCopy(raw, 0, result, ModulusSize - raw.Length, raw.Length);
        return result;
    }

    /// <summary>
    /// 3DES-ECB（两密钥，K3=K1）。加密时按厂商规则追加 <c>0x80</c> 并补 <c>0x00</c> 到 8 字节倍数；
    /// 解密时要求长度已是 8 的倍数（不做去填充，由调用方按长度字段截取）。
    /// </summary>
    public static byte[] TripleDesEcb(byte[] data, byte[] key16, bool encrypt)
    {
        if (key16.Length != 16 && key16.Length != 24)
            throw new ArgumentException("3DES 密钥必须是 16 或 24 字节", nameof(key16));

        byte[] input;
        if (encrypt)
        {
            var padded = new List<byte>(data);
            padded.Add(0x80);
            while (padded.Count % 8 != 0) padded.Add(0x00);
            input = padded.ToArray();
        }
        else
        {
            if (data.Length == 0 || data.Length % 8 != 0)
                throw new CryptographicException($"密文长度不是 8 的倍数（{data.Length}）");
            input = data;
        }

#pragma warning disable SYSLIB0021 // 厂商算法即 3DES，此处必须使用
        using var tdes = TripleDES.Create();
#pragma warning restore SYSLIB0021
        tdes.Mode = CipherMode.ECB;
        tdes.Padding = PaddingMode.None;
        tdes.Key = key16;

        using var xf = encrypt ? tdes.CreateEncryptor() : tdes.CreateDecryptor();
        return xf.TransformFinalBlock(input, 0, input.Length);
    }
}

/// <summary>
/// 一条已建立 MSP 安全会话的卡片通道。所有 APDU 都会自动封装/解封。
///
/// <para><b>报文格式（<c>MSP::XSendAPDU (sub_1001FA64)</c>）</b></para>
/// <list type="bullet">
/// <item>请求 payload = <c>01</c> + <c>3DES_enc( bin( 长度4位hex + APDU的hex ) )</c></item>
/// <item>响应 payload = <c>01</c> + 密文；解密后得到 <c>长度4hex + 数据hex + SW4hex</c>，
/// 其中 <c>长度 = 数据字节数 + 2</c>。</item>
/// </list>
/// </summary>
public sealed class HengBaoMspSession
{
    private readonly byte[] _key;
    private readonly HengBaoScsiChannel _channel;

    internal HengBaoMspSession(HengBaoScsiChannel channel, byte[] sessionKey16)
    {
        _channel = channel;
        _key = sessionKey16;
    }

    /// <summary>会话密钥的十六进制表示（大写，与厂商 <c>BinToHex</c> 一致，仅用于日志/诊断）。</summary>
    public string SessionKeyHex => HengBaoScsi.ToHex(_key);

    /// <summary>
    /// 发一条受保护 APDU。成功时 <paramref name="sw"/> 为卡片状态字，
    /// <paramref name="data"/> 为响应数据（不含 SW）。
    /// </summary>
    public bool Transmit(byte[] apdu, out uint sw, out byte[] data, out string error)
    {
        sw = 0;
        data = Array.Empty<byte>();
        error = "";

        // ---- 封装：明文 hex = 长度(4 hex) + APDU(hex)，整体 hexdecode 后加密 ----
        var plainHex = apdu.Length.ToString("X4") + HengBaoScsi.ToHex(apdu);
        byte[] cipher;
        try
        {
            cipher = HengBaoMspCrypto.TripleDesEcb(HexToBytes(plainHex), _key, encrypt: true);
        }
        catch (Exception ex)
        {
            error = "封装失败：" + ex.Message;
            return false;
        }

        var payload = new byte[cipher.Length + 1];
        payload[0] = 0x01;                       // 厂商在密文前固定加 1 字节 0x01
        Buffer.BlockCopy(cipher, 0, payload, 1, cipher.Length);

        if (!_channel.Transmit(payload, out var respPayload, out error))
        {
            error = "传输失败：" + error;
            return false;
        }

        // ---- 解封：响应 payload = 01 + 密文（密文长度必须是 8 的倍数）----
        if (respPayload.Length < 9)
        {
            error = $"响应过短（{respPayload.Length} 字节：{HengBaoScsi.ToHex(respPayload)}）";
            return false;
        }
        var cipherLen = respPayload.Length - 1;
        if (cipherLen % 8 != 0)
        {
            error = $"响应密文长度不是 8 的倍数（{cipherLen} 字节：{HengBaoScsi.ToHex(respPayload)}）";
            return false;
        }

        var cipherIn = new byte[cipherLen];
        Buffer.BlockCopy(respPayload, 1, cipherIn, 0, cipherLen);

        byte[] plain;
        try
        {
            plain = HengBaoMspCrypto.TripleDesEcb(cipherIn, _key, encrypt: false);
        }
        catch (Exception ex)
        {
            error = "解封失败：" + ex.Message;
            return false;
        }

        // 解密结果是「结果字节的 hex 串」
        var hex = HengBaoScsi.ToHex(plain);
        if (hex.Length < 8)
        {
            error = $"解密结果过短（{hex}）";
            return false;
        }

        var total = Convert.ToInt32(hex.Substring(0, 4), 16);   // = 数据字节数 + 2
        var dataLen = total - 2;
        if (dataLen < 0 || 4 + dataLen * 2 + 4 > hex.Length)
        {
            error = $"长度字段异常（长度={total}，解密结果={hex}）";
            return false;
        }

        data = HexToBytes(hex.Substring(4, dataLen * 2));
        sw = Convert.ToUInt32(hex.Substring(4 + dataLen * 2, 4), 16);
        return true;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
        if (hex.Length % 2 != 0) hex = hex.Substring(0, hex.Length - 1);
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }
}

/// <summary>
/// MSP 握手（厂商 <c>Handshake (sub_1001FDDE)</c>）：建立安全会话。
///
/// <para>四步（全部要求 <c>SW=0x9000</c>）：</para>
/// <list type="number">
/// <item><c>80 F2 03 00 01</c> → 应答首字节须为 <c>0x01</c>（进入令牌模式的标志）</item>
/// <item><c>80 F4 02 00 00</c></item>
/// <item><c>80 F4 00 00 87</c> → 135 字节，其中 <b>字节 2..129 是 128 字节 RSA 模数</b></item>
/// <item><c>80 F4 01 00 80</c> + 128 字节密文（用模数加密随机 16 字节会话密钥）</item>
/// </list>
/// </summary>
public static class HengBaoMspHandshake
{
    /// <summary>在已打开的通道上执行握手。成功后 <paramref name="session"/> 可直接用于发受保护 APDU。</summary>
    public static bool TryEstablish(HengBaoScsiChannel channel, out HengBaoMspSession? session,
        out string error, out string log)
    {
        session = null;
        error = "";
        var trace = new System.Text.StringBuilder();

        void Trace(string s)
        {
            trace.AppendLine(s);
        }

        // 步骤 1
        if (!PlainApdu(channel, Hex("80F2030001"), out var sw1, out var d1, out error)) { log = trace.ToString(); return false; }
        Trace($"80F2030001 → SW=0x{sw1:X4} 数据={HengBaoScsi.ToHex(d1)}");
        if (sw1 != 0x9000)
        {
            error = $"80F2030001 返回 0x{sw1:X4}（期望 0x9000）——卡片未进入令牌模式";
            log = trace.ToString();
            return false;
        }
        if (d1.Length < 1 || d1[0] != 0x01)
        {
            error = $"80F2030001 应答首字节不是 0x01（实际 {HengBaoScsi.ToHex(d1)}）";
            log = trace.ToString();
            return false;
        }

        // 步骤 2
        if (!PlainApdu(channel, Hex("80F4020000"), out var sw2, out _, out error)) { log = trace.ToString(); return false; }
        Trace($"80F4020000 → SW=0x{sw2:X4}");
        if (sw2 != 0x9000)
        {
            error = $"80F4020000 返回 0x{sw2:X4}（期望 0x9000）";
            log = trace.ToString();
            return false;
        }

        // 步骤 3：取卡片密钥材料
        if (!PlainApdu(channel, Hex("80F4000087"), out var sw3, out var blob, out error)) { log = trace.ToString(); return false; }
        Trace($"80F4000087 → SW=0x{sw3:X4} 数据={blob.Length} 字节");
        if (sw3 != 0x9000)
        {
            error = $"80F4000087 返回 0x{sw3:X4}（期望 0x9000）";
            log = trace.ToString();
            return false;
        }
        if (blob.Length < 2 + HengBaoMspCrypto.ModulusSize)
        {
            error = $"卡片密钥材料只有 {blob.Length} 字节，不足 {2 + HengBaoMspCrypto.ModulusSize} 字节";
            log = trace.ToString();
            return false;
        }

        // 厂商从 hex 串第 4 个字符（= 字节 2）起取 128 字节作为模数
        var modulus = new byte[HengBaoMspCrypto.ModulusSize];
        Buffer.BlockCopy(blob, 2, modulus, 0, modulus.Length);
        if (modulus[0] == 0)
        {
            error = "模数首字节为 0，偏移解析可能有误";
            log = trace.ToString();
            return false;
        }

        // 步骤 4：生成会话密钥并用模数加密后回送
        var key = HengBaoMspCrypto.NewSessionKey();
        byte[] cipher;
        try
        {
            cipher = HengBaoMspCrypto.RsaEncryptSessionKey(modulus, key);
        }
        catch (Exception ex)
        {
            error = "RSA 加密会话密钥失败：" + ex.Message;
            log = trace.ToString();
            return false;
        }

        var step4 = new List<byte>(Hex("80F40100"));
        step4.Add((byte)cipher.Length);                       // 0x80
        step4.AddRange(cipher);
        if (!PlainApdu(channel, step4.ToArray(), out var sw4, out _, out error)) { log = trace.ToString(); return false; }
        Trace($"80F4010080 + {cipher.Length} 字节密文 → SW=0x{sw4:X4}");
        if (sw4 != 0x9000)
        {
            error = $"80F4010080 返回 0x{sw4:X4}（期望 0x9000）——RSA 填充或模数偏移不符";
            log = trace.ToString();
            return false;
        }

        session = new HengBaoMspSession(channel, key);
        Trace($"会话密钥 K = {HengBaoScsi.ToHex(key)}（MSP 已启用）");
        log = trace.ToString();
        return true;
    }

    /// <summary>发送一条「明文 APDU」（握手阶段使用，不做 MSP 封装）。</summary>
    public static bool PlainApdu(HengBaoScsiChannel channel, byte[] apdu, out uint sw,
        out byte[] data, out string error)
    {
        sw = 0;
        data = Array.Empty<byte>();
        if (!channel.Transmit(apdu, out var payload, out error))
        {
            error = "传输失败：" + error;
            return false;
        }
        if (payload.Length < 2)
        {
            error = $"响应载荷不足 2 字节（{HengBaoScsi.ToHex(payload)}）";
            return false;
        }
        sw = (uint)((payload[payload.Length - 2] << 8) | payload[payload.Length - 1]);
        data = new byte[payload.Length - 2];
        Buffer.BlockCopy(payload, 0, data, 0, data.Length);
        return true;
    }

    private static byte[] Hex(string s)
    {
        var b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }
}
