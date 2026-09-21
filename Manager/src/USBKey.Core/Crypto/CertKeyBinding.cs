using USBKey.Core.Common;

namespace USBKey.Core.Crypto;

/// <summary>Windows 侧的密钥存储类型。</summary>
public enum KeyStoreKind
{
    /// <summary>CryptoAPI 加密服务提供程序（CSP，老接口）。</summary>
    Capi,
    /// <summary>CNG 密钥存储提供程序（KSP）。</summary>
    Cng,
}

/// <summary>
/// 证书与「私钥容器」的绑定信息。
/// <para>
/// 注册证书时只把 X.509 公钥塞进证书库是不够的：证书还必须带上
/// <c>CERT_KEY_PROV_INFO_PROP_ID</c> 属性指明「哪个提供程序 + 哪个容器」持有私钥，
/// 系统才知道这张证书有私钥（资源管理器里显示小钥匙、可以签名/解密）。
/// 没有这个属性，<c>certutil -store my</c> 会显示「密钥容器 = (null)」，也就是"没有注册私钥"。
/// </para>
/// </summary>
public sealed class CertKeyBinding
{
    /// <summary>CAPI 密钥用途：签名（AT_SIGNATURE）。</summary>
    public const int AtSignature = 2;

    /// <summary>CAPI 密钥用途：密钥交换/加密（AT_KEYEXCHANGE）。</summary>
    public const int AtKeyExchange = 1;

    /// <summary>CNG 密钥用途：CERT_NCRYPT_KEY_SPEC。</summary>
    public const int NcryptKeySpec = unchecked((int)0xFFFFFFFF);

    /// <summary>提供程序类别（CSP / KSP）。</summary>
    public KeyStoreKind Kind { get; init; } = KeyStoreKind.Capi;

    /// <summary>CSP 或 KSP 名称（注册表里的键名）。</summary>
    public string ProviderName { get; init; } = "";

    /// <summary>密钥容器名（CNG 下即 key name）。</summary>
    public string ContainerName { get; init; } = "";

    /// <summary>CAPI 提供程序类型（PROV_RSA_FULL=1）。CNG 固定为 0。</summary>
    public int ProviderType { get; init; } = 1;

    /// <summary>密钥用途（CAPI：AT_SIGNATURE/AT_KEYEXCHANGE；CNG：CERT_NCRYPT_KEY_SPEC）。</summary>
    public int KeySpec { get; init; } = AtSignature;

    /// <summary>是否有效（提供程序名与容器名都非空）。</summary>
    public bool IsValid => !string.IsNullOrWhiteSpace(ProviderName) && !string.IsNullOrWhiteSpace(ContainerName);

    /// <summary>写给用户看的说明文本。</summary>
    public string Describe() => Kind == KeyStoreKind.Cng
        ? $"KSP「{ProviderName}」密钥「{ContainerName}」"
        : $"CSP「{ProviderName}」容器「{ContainerName}」(type={ProviderType}, keySpec={KeySpec})";

    public override string ToString() => Describe();
}

/// <summary>
/// 把卡侧容器名解析成 Windows 侧的私钥容器绑定。
/// <para>
/// 策略：优先使用 config.json 里显式指定的提供程序（<c>keyslist.&lt;平台&gt;[].csp / .ksp</c>）；
/// 未指定时遍历系统已注册的全部 CSP/KSP，谁的容器列表里存在与卡侧容器名同名的条目就用谁。
/// 这一步是纯探测（枚举容器列表不需要 PIN），不会向卡下发改动性指令。
/// </para>
/// </summary>
public static class CertKeyBinder
{
    /// <summary>
    /// 解析私钥容器绑定；找不到返回 null（此时只能注册"仅含公钥"的证书）。
    /// </summary>
    /// <param name="containerCandidates">卡侧可能的容器名（容器名 / UUID / 证书 CN）。</param>
    /// <param name="pinnedProvider">config.json 指定的 CSP/KSP 名称（指定后只探测它）。</param>
    /// <param name="pinnedKind">指定提供程序类别；null 表示按名字在两类里都找。</param>
    /// <param name="keySpec">CAPI 密钥用途（由证书用途推断）。</param>
    public static CertKeyBinding? Resolve(IEnumerable<string> containerCandidates, string? pinnedProvider = null,
        KeyStoreKind? pinnedKind = null, int keySpec = CertKeyBinding.AtSignature)
    {
        var candidates = containerCandidates
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (candidates.Count == 0) return null;

        var providers = KeyStoreRegistry.Providers;
        IEnumerable<KeyStoreProvider> ordered;
        if (!string.IsNullOrWhiteSpace(pinnedProvider))
        {
            ordered = providers.Where(p =>
                string.Equals(p.Name, pinnedProvider!.Trim(), StringComparison.OrdinalIgnoreCase) &&
                (pinnedKind == null || p.Kind == pinnedKind));
        }
        else
        {
            // 厂商 CSP 排在微软自带的前面：卡上的容器只可能在厂商提供程序里出现，
            // 先探测它们能显著减少对智能卡 CSP 的无效调用（部分 CSP 枚举容器会去唤醒读卡器）。
            ordered = providers.Where(p => !IsMicrosoftBuiltin(p.Name))
                               .Concat(providers.Where(p => IsMicrosoftBuiltin(p.Name)));
        }

        CertKeyBinding? pinnedBinding = null;
        foreach (var p in ordered)
        {
            var containers = KeyStoreRegistry.ListContainers(p);
            var hit = containers.FirstOrDefault(c =>
                candidates.Any(x => string.Equals(x, c, StringComparison.OrdinalIgnoreCase)));

            if (hit == null)
            {
                // 配置里点名了提供程序、但它的容器列表里没有同名条目（CSP 与卡侧的容器命名可能不是一套）：
                // 记下来，等其它提供程序都试完再决定
                if (pinnedBinding == null && !string.IsNullOrWhiteSpace(pinnedProvider))
                {
                    pinnedBinding = new CertKeyBinding
                    {
                        Kind = p.Kind,
                        ProviderName = p.Name,
                        ContainerName = candidates[0],
                        ProviderType = p.Kind == KeyStoreKind.Cng ? 0 : p.ProviderType,
                        KeySpec = p.Kind == KeyStoreKind.Cng ? CertKeyBinding.NcryptKeySpec : keySpec,
                    };
                }
                continue;
            }

            var binding = new CertKeyBinding
            {
                Kind = p.Kind,
                ProviderName = p.Name,
                ContainerName = hit,
                ProviderType = p.Kind == KeyStoreKind.Cng ? 0 : p.ProviderType,
                KeySpec = p.Kind == KeyStoreKind.Cng ? CertKeyBinding.NcryptKeySpec : keySpec,
            };
            Log.Write($"[私钥] 已匹配到 {binding.Describe()}");
            return binding;
        }

        if (pinnedBinding != null)
        {
            Log.Write($"[私钥] 采用配置指定的提供程序（未在容器列表中确认）：{pinnedBinding.Describe()}");
            return pinnedBinding;
        }

        Log.Write($"[私钥] 未找到匹配的私钥容器（候选：{string.Join("、", candidates)}）；" +
                  $"已探测 {providers.Count} 个已注册的 CSP/KSP。" +
                  "如需指定，可在 config.json 的 keyslist.<平台>[] 里填 csp 或 ksp 字段。");
        return null;
    }

    /// <summary>把证书用途文本映射成 CAPI 密钥用途（默认签名）。</summary>
    public static int KeySpecFromUsage(string? keyUsage) =>
        keyUsage != null && (keyUsage.Contains("加密") || keyUsage.Contains("交换"))
            ? CertKeyBinding.AtKeyExchange
            : CertKeyBinding.AtSignature;

    private static bool IsMicrosoftBuiltin(string name) =>
        name.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase);
}
