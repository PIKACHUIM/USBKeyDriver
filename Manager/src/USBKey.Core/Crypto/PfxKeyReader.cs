using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace USBKey.Core.Crypto;

/// <summary>
/// 从 PFX 中取出 RSA 私钥参数（供「把外部密钥对写进卡里」的导入流程使用）。
/// <para>
/// <b>为什么不能直接 <c>cert.GetRSAPrivateKey().ExportParameters(true)</c></b>：
/// Windows 上 PFX 的私钥由 CNG 保管（Microsoft Software Key Storage Provider），
/// CNG 的导出策略有两种，导入时默认只给 <c>AllowExport</c>（允许再导出为加密 PKCS#8/PFX），
/// <b>不给</b> <c>AllowPlaintextExport</c>（允许导出明文密钥材料）。
/// 而 <see cref="X509KeyStorageFlags.Exportable"/> 并不等于"可明文导出"，
/// 于是 <c>ExportParameters(true)</c> 会被 NCryptExportKey 拒绝，报
/// <c>NTE_NOT_SUPPORTED (0x80090029)</c>，界面上的表现就是"操作失败：不支持请求的操作。"。
/// </para>
/// <para>
/// 兜底做法：先尝试直接取参数（传统 CAPI 承载的密钥、或策略已放开时会成功）；
/// 失败则用 <see cref="RSA.ExportEncryptedPkcs8PrivateKey(string, PbeParameters)"/> 导出
/// <b>口令加密的 PKCS#8</b>（这一步只要求 AllowExport，是被允许的），
/// 再在内存里重新导入取出参数。全程不落盘、不修改系统密钥的导出策略。
/// </para>
/// </summary>
public static class PfxKeyReader
{
    /// <summary>兜底链路用的临时口令：只在本进程内存中传递，不写文件、不留存。</summary>
    private const string TempPassword = "usbkey-pfx-transient";

    /// <summary>
    /// 读取 PFX。
    /// <para>
    /// 先试 <c>EphemeralKeySet</c>（不落盘、不污染用户密钥容器）；若该 PFX 的私钥只能由
    /// 传统 CSP（厂商 CSP / 国密 CSP）承载，Windows 会拒绝，此时回退到普通导入方式。
    /// </para>
    /// </summary>
    public static X509Certificate2 Load(string pfxPath, string? password)
    {
        try
        {
            return new X509Certificate2(pfxPath, password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException)
        {
            // 回退到普通导入；若这次仍失败，其报错（密码错误等）原样抛出，由调用方给出提示
            return new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable);
        }
    }

    /// <summary>读取 PFX 并取出 RSA 私钥参数，同时返回证书对象（由调用方负责 Dispose）。</summary>
    public static RSAParameters ReadRsaPrivateKey(string pfxPath, string? password, out X509Certificate2 certificate)
    {
        var cert = Load(pfxPath, password);
        try
        {
            var p = ReadRsaPrivateKey(cert);
            certificate = cert;
            return p;
        }
        catch
        {
            cert.Dispose();
            throw;
        }
    }

    /// <summary>从已装载的证书中取出 RSA 私钥参数（含 CNG 明文导出限制的兜底）。</summary>
    public static RSAParameters ReadRsaPrivateKey(X509Certificate2 cert)
    {
        var rsa = cert.GetRSAPrivateKey()
            ?? throw new NotSupportedException(
                "该 PFX 里没有 RSA 私钥（可能只有证书，或使用的是 SM2/ECC 密钥）。");

        using (rsa)
        {
            var p = ExportRsaPrivateKey(rsa);

            // 校验：取出的私钥必须与证书公钥配对，否则写进卡里也签不了名
            using var pub = cert.GetRSAPublicKey();
            if (pub != null)
            {
                var e = pub.ExportParameters(false);
                if (!(e.Modulus ?? Array.Empty<byte>()).SequenceEqual(p.Modulus ?? Array.Empty<byte>()))
                    throw new InvalidOperationException("PFX 中的私钥与证书公钥不匹配，已停止导入。");
            }
            return p;
        }
    }

    /// <summary>取 RSA 私钥的全部参数（必要时走"加密 PKCS#8 → 内存重新导入"的兜底链路）。</summary>
    public static RSAParameters ExportRsaPrivateKey(RSA rsa)
    {
        // 快路径：CAPI 承载的密钥、或 CNG 已放开明文导出策略时可直接取
        try
        {
            var direct = rsa.ExportParameters(true);
            if (HasPrivateParts(direct)) return direct;
        }
        catch (CryptographicException)
        {
            // 落到兜底
        }

        byte[] encrypted;
        try
        {
            // CNG 的 AllowExport 允许"再导出为口令加密的 PKCS#8"
            encrypted = rsa.ExportEncryptedPkcs8PrivateKey(TempPassword,
                new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 1));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "无法从 PFX 中取出私钥：" + ex.Message + "\n" +
                "该密钥可能被标记为不可导出（导出策略禁止），或由不支持的提供程序保管。", ex);
        }

        RSAParameters p;
        try
        {
            using var probe = RSA.Create();
            probe.ImportEncryptedPkcs8PrivateKey(TempPassword, encrypted, out _);
            p = probe.ExportParameters(true);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "私钥已导出但无法重新解析（" + ex.Message + "），请改用可导出的 PFX。", ex);
        }

        if (!HasPrivateParts(p))
            throw new InvalidOperationException("无法取出完整的 RSA 私钥参数，请改用可导出的 PFX。");
        return p;
    }

    private static bool HasPrivateParts(RSAParameters p) =>
        p.Modulus is { Length: > 0 } && p.Exponent is { Length: > 0 } && p.D is { Length: > 0 } &&
        p.P is { Length: > 0 } && p.Q is { Length: > 0 } &&
        p.DP is { Length: > 0 } && p.DQ is { Length: > 0 } && p.InverseQ is { Length: > 0 };
}
