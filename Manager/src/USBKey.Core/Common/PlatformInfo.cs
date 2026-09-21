namespace USBKey.Core.Common;

/// <summary>
/// 平台标识 → 界面展示信息。
/// <para>
/// config.json 的 <c>platform</c> / <c>keyslist</c> 里用的是英文键（lnca、bjca…），
/// 直接显示给用户可读性极差（"lnca" ≠ 用户认知里的"辽宁CA"）。
/// 界面上统一通过本类取中文名，不要再把平台键直接抛给用户。
/// </para>
/// </summary>
public static class PlatformInfo
{
    /// <summary>平台键 → (显示名, 一句话说明)。键为小写。</summary>
    private static readonly Dictionary<string, (string Name, string Note)> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["lnca"] = ("辽宁CA", "辽宁数字证书认证中心（LNCA）USB Key"),
        ["lnca1"] = ("辽宁CA", "辽宁数字证书认证中心（LNCA）USB Key"),
        ["lnca2"] = ("辽宁CA", "辽宁数字证书认证中心（LNCA）USB Key"),
        ["bjca"] = ("北京CA", "北京数字认证（BJCA）USB Key"),
        ["gm3000"] = ("龙脉 GM3000", "龙脉（Longmai）GM3000 USB Key"),
        ["longmai"] = ("龙脉 GM3000", "龙脉（Longmai）GM3000 USB Key"),
        ["gm"] = ("龙脉 GM3000", "龙脉（Longmai）GM3000 USB Key"),
        ["hengbao"] = ("恒宝 U 宝", "恒宝（HengBao）民生银行 U 宝"),
        // ePass3003：本平台对接的是 HZCA（杭州银行 / HCCB）定制版的 PKCS#11 中间件 HCCBCSP11.dll，
        // 名称与厂商工具保持一致，不要写成「飞天 ePass3003」——用户拿它和官方工具对照时会以为是两把卡。
        ["epass3003"] = ("ePass 3003 (HZCA)", "飞天诚信 ePass3003（HZCA／HCCB 定制版，PKCS#11 中间件 HCCBCSP11.dll）"),
        ["linguo"] = ("凌国 UKey", "凌国（张家口银行）USB Key"),
        ["zjkccb"] = ("凌国 UKey", "凌国（张家口银行）USB Key"),
        ["zjk"] = ("凌国 UKey", "凌国（张家口银行）USB Key"),
        ["skf"] = ("SKF 通用", "SKF（GM/T 0016）通用中间件平台"),
        ["mock"] = ("模拟设备", "演示/自测用的模拟设备"),
    };

    /// <summary>取平台的中文显示名（未登记的平台原样返回）。</summary>
    public static string DisplayName(string? platformKey)
    {
        if (string.IsNullOrWhiteSpace(platformKey)) return "—";
        return Map.TryGetValue(platformKey.Trim(), out var v) ? v.Name : platformKey.Trim();
    }

    /// <summary>取平台说明；未登记返回空串。</summary>
    public static string Note(string? platformKey)
    {
        if (string.IsNullOrWhiteSpace(platformKey)) return "";
        return Map.TryGetValue(platformKey.Trim(), out var v) ? v.Note : "";
    }

    /// <summary>下拉框用："辽宁CA (lnca)"——中文名优先，括号内保留原始键便于排查。</summary>
    public static string ComboLabel(string? platformKey)
    {
        if (string.IsNullOrWhiteSpace(platformKey)) return "—";
        var key = platformKey.Trim();
        var name = DisplayName(key);
        return name == key ? key : $"{name} ({key})";
    }
}
