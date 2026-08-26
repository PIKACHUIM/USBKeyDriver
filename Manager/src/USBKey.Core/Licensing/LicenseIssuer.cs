using System.Security.Cryptography;
using System.Text;

namespace USBKey.Core.Licensing;

/// <summary>管理签名参数。</summary>
public class LicenseIssueRequest
{
    public required string MachineCode { get; init; }
    public required DateTime Expiry { get; init; }
    public required IReadOnlyList<string> Platforms { get; init; }
    public string? LicenseId { get; init; }
}

/// <summary>
/// 授权签发器（仅授权终端使用）。持有与核心内嵌公钥对应的私钥，
/// 生成 license.key 并输出 JSON。
/// </summary>
public static class LicenseIssuer
{
    // 开发环境私钥（PKCS#8, PEM→base64 单行）。授权终端持有；生产需严格保护。
    private const string IssuerPrivateKey =
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDHTrk6cDtdJfSD+LUJ7eOuu8/v5sJK+tvUl1aZ3mP79GinmCepB4ON0/2Dt/c05V1G0zuJr6ba7IRdq6aO16RHlt7ez7EMnyIbr5z+OtlKA5z38poFM/htP4lFE0hx8cqAQCp2BdTTlbLz7DFuH0G6ydYx0jtjSmSdODkDVY0fiQouS2+2vFogIKcAGONvRE/TzfxOmq3y9yDH9bkp67tW1sYH/2n9IcS1Y1akiWG8N2Gs8Ztf4iUxre9A0MeAatOSaSUhAAeI/Ec/tPt0cF8SvpREZ/qEtrf+UWPMymu3Rs5YvTMgcIXLfFrNAzfcKQrgJ0zAjtyTddCeFjYjbJJxAgMBAAECggEAA9gQ2n+vpWxF+wWg+EAOVCBrMkVRGgEcnE0O7ojLhOCB5DmbCjeK4gFkslWp/ustkWAhldY9cZt+MhBNdhPSp07RnZqD36pyDfalIIIiDrtjG6UiM1d9Qx4ml553lzsCnNaf+wbBxBLvEKVNjsIrkl6yMuPLIW8d4apj7xyHTERfow2NXhYjCv63hzUg+27vd8xSbzzwIz7cm0nzMm4H0pjDyLg8MahqXUsjwrPXwn3DIOuSy8W7icg7L2cW7w/caarp6/LL7xWdV6YWxvpooV2rT0YmiaHEewHLMYkASbQx3d4lsHHuxtOC5kbcoPo3Fo5FMt9MEB54i57GHSh5wQKBgQDUWnVjWkWOcpx4xiYkQpHcbo6SLwsoLoWb+tEIvzY5yrVxz9jOcHYfy+ZwB7i9z66E6wEgCE6TyLVlujGQ0TiCfhURUc0Ayo8VsCJT5j7zKCiML2XjXKW12BFKiULJiUCZp7BSDSJNmLvjFvatw6A8N0gzj5nNbektWD7f6GJfdwKBgQDwRdK4/ceUXCWx4yGyGUVOYtwgfamSsTP6pO3oPRfiorHcBRvkE9aTjaOSy+H25O9rm1DxwMktDXkmw7sYRh/KSe7lDW7/4cIrolIpxQqdYTV9XADp1V8psFJJMnpNYPbmgHCdT1TbsKsOCFM9+fvU/AoVuCXh5dintcbIeOUnVwKBgE/V3nJG2wWuAzPI00gomuvzyLge5aPqsaKtzm7qbHmXw1WRneInF9Hmd7FAxezeqq8gJyEi3l/jQoeHU+EtN4Cf5E3Jojgc72Ro/s7qLlp+i5gArd6n00klfYK3Thu09UuPZtPCSlZACMtcs8sqVBCve/6ei2VXYCYDGkhV9r4LAoGADssNvUwKtKyzuW8VjQSXSss1aF60SQ7V93GeIDVauh5wOu6pl/JMvMr0rj4VTIEt6H8ojanj+P0iX2ufok/29xp0NfAMzH5W2R7mViIGlEf+5hf7CmqTsFplxpHwC8GTkf+Ib3cJ73jCH1wN2/v/ME7QRCQRWQYwv6qmcYNYAIMCgYBqyowLWI8xYYFENw6O/lL+0ehAG2Vsc4fprzsWAPzdcYndGV2PEeanPlvh9mJNuAORcm/Ix5U+059NkCIa/OTBIchj/6hTYWq9grvTpXstYhgbaoXZ2y4aIrjoIPdPYyj3qbC1YEZNDZporp65isOl/4w/xgKAQJ4hDUONt7Qz1A==";

    /// <summary>签发授权文档并返回 json 文本。</summary>
    public static string Issue(LicenseIssueRequest req)
    {
        var doc = new LicenseDocument
        {
            LicenseId = req.LicenseId ?? Guid.NewGuid().ToString("N").Substring(0, 16).ToUpperInvariant(),
            MachineCode = req.MachineCode.Trim(),
            Expiry = req.Expiry.ToString("yyyy-MM-dd"),
            Platforms = req.Platforms.Distinct().ToList(),
            IssuedAt = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
        };

        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(IssuerPrivateKey), out _);
        var payloadBytes = Encoding.UTF8.GetBytes(doc.ComputePayload());
        var sig = rsa.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        doc.Signature = LicenseVerifier.StdToUrlSafe(Convert.ToBase64String(sig));

        return System.Text.Json.JsonSerializer.Serialize(
            doc,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }
}
