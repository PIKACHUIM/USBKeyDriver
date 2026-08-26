using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace USBKey.Core.Licensing;

/// <summary>
/// 授权文档（license.key 反序列化的结果）。
/// 需求：私钥签名 "机器码|到期日|平台" → BASE64 存储于签名项；其余字段作为明文字段便于展示与核验。
/// </summary>
public class LicenseDocument
{
    public string LicenseId { get; set; } = "";
    public string MachineCode { get; set; } = "";
    /// <summary>授权到期日期，格式 yyyy-MM-dd。</summary>
    public string Expiry { get; set; } = "";
    /// <summary>授权允许的平台列表。</summary>
    public List<string> Platforms { get; set; } = new();
    /// <summary>签发时间。</summary>
    public string IssuedAt { get; set; } = "";

    /// <summary>签名，BASE64(UrlSafe)，对象为机器码|期|平台 规范化串。</summary>
    public string Signature { get; set; } = "";

    /// <summary>计算被签名的规范化原文。</summary>
    public string ComputePayload() =>
        $"{MachineCode}|{NormalizeDate(Expiry)}|{string.Join(",", (Platforms ?? new()).OrderBy(x => x))}";

    private static string NormalizeDate(string s)
    {
        if (DateTime.TryParse(s, out var d)) return d.ToString("yyyyMMdd");
        return s?.Replace("-", "").Replace("/", "") ?? "";
    }
}

/// <summary>授权校验结果。</summary>
public enum LicenseStatus
{
    Valid,
    Missing,       // 不存在 license.key
    MachineMismatch,
    Expired,
    PlatformMismatch,
    SignatureInvalid,
    Malformed,
}

/// <summary>授权校验结果。</summary>
public class LicenseCheckResult
{
    public LicenseStatus Status { get; init; }
    public LicenseDocument? Document { get; init; }
    public string Message { get; init; } = "";
    public DateTime ValidUntilUtc { get; init; }
    public bool IsValid => Status == LicenseStatus.Valid;
}

/// <summary>
/// 管理端/核心校验器。内置公钥，用于验签；并负责读取、解析、校验 license.key。
/// </summary>
public static class LicenseVerifier
{
    // 开发环境公钥（SubjectPublicKeyInfo, url-safe base64）。生产替换为对应私钥的公钥。
    private const string EmbeddedPublicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx065OnA7XSX0g_i1Ce3jrrvP7-bCSvrb1JdWmd5j-_Rop5gnqQeDjdP9g7f3NOVdRtM7ia-m2uyEXaumjtekR5be3s-xDJ8iG6-c_jrZSgOc9_KaBTP4bT-JRRNIcfHKgEAqdgXU05Wy8-wxbh9BusnWMdI7Y0pknTg5A1WNH4kKLktvtrxaICCnABjjb0RP0838Tpqt8vcgx_W5Keu7VtbGB_9p_SHEtWNWpIlhvDdhrPGbX-IlMa3vQNDHgGrTkmklIQAHiPxHP7T7dHBfEr6URGf6hLa3_lFjzMprt0bOWL0zIHCFy3xazQM33CkK4CdMwI7ck3XQnhY2I2yScQIDAQAB";

    /// <summary>加载并校验 license.key。nowUtc 优先使用联网时间。</summary>
    public static LicenseCheckResult Check(string licensePath, string currentMachineCode, IEnumerable<string>? requiredPlatforms, DateTime? nowUtc = null)
    {
        if (!File.Exists(licensePath))
            return new LicenseCheckResult { Status = LicenseStatus.Missing, Message = "未找到授权文件 license.key" };

        LicenseDocument doc;
        try
        {
            doc = JsonSerializer.Deserialize<LicenseDocument>(File.ReadAllText(licensePath))!;
        }
        catch
        {
            return new LicenseCheckResult { Status = LicenseStatus.Malformed, Message = "license.key 解析失败" };
        }
        if (doc == null)
            return new LicenseCheckResult { Status = LicenseStatus.Malformed, Message = "license.key 内容为空" };

        // 1. 验签
        if (!VerifySignature(doc))
            return new LicenseCheckResult { Status = LicenseStatus.SignatureInvalid, Message = "授权签名无效" };

        // 2. 机器码绑定
        if (!string.Equals(doc.MachineCode?.Trim(), currentMachineCode?.Trim(), StringComparison.OrdinalIgnoreCase))
            return new LicenseCheckResult { Status = LicenseStatus.MachineMismatch, Message = "授权与本机机器码不匹配" };

        // 3. 到期时间
        var now = nowUtc ?? DateTime.UtcNow;
        if (!DateTime.TryParse(doc.Expiry, out var expiryUtc))
            return new LicenseCheckResult { Status = LicenseStatus.Malformed, Message = "授权到期日期格式错误" };
        if (expiryUtc < now.Date)
            return new LicenseCheckResult { Status = LicenseStatus.Expired, Message = $"授权已于 {expiryUtc:yyyy-MM-dd} 过期" };

        // 4. 平台匹配：授权平台需覆盖所需平台中的至少一个
        if (requiredPlatforms != null && requiredPlatforms.Any())
        {
            var authPlats = (doc.Platforms ?? new()).Select(p => p.Trim().ToLowerInvariant()).ToHashSet();
            var need = requiredPlatforms.Select(p => p.Trim().ToLowerInvariant()).ToHashSet();
            if (!authPlats.Overlaps(need))
                return new LicenseCheckResult
                {
                    Status = LicenseStatus.PlatformMismatch,
                    Message = $"授权平台( {string.Join(",", doc.Platforms!)} )不包含所需平台( {string.Join(",", requiredPlatforms)} )",
                };
        }

        return new LicenseCheckResult
        {
            Status = LicenseStatus.Valid,
            Document = doc,
            Message = "授权有效",
            ValidUntilUtc = expiryUtc,
        };
    }

    /// <summary>用内置公钥验签。</summary>
    public static bool VerifySignature(LicenseDocument doc)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(UrlSafeToStd(EmbeddedPublicKey)), out _);
            var sig = Convert.FromBase64String(UrlSafeToStd(doc.Signature?.Trim() ?? ""));
            return rsa.VerifyData(
                Encoding.UTF8.GetBytes(doc.ComputePayload()),
                sig,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }
        catch { return false; }
    }

    /// <summary>url-safe base64 → 标准 base64。</summary>
    public static string UrlSafeToStd(string s) => s.Replace('-', '+').Replace('_', '/');
    /// <summary>标准 base64 → url-safe base64。</summary>
    public static string StdToUrlSafe(string s) => s.Replace('+', '-').Replace('/', '_');
}
