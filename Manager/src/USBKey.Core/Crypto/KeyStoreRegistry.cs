using System.Text;
using Microsoft.Win32;
using USBKey.Core.Common;

namespace USBKey.Core.Crypto;

/// <summary>系统里已注册的一个密钥存储提供程序（CAPI 的 CSP 或 CNG 的 KSP）。</summary>
/// <param name="Name">注册表里的名称（CryptAcquireContext / NCryptOpenStorageProvider 都按它调用）。</param>
/// <param name="ImagePath">提供程序实现 DLL（CAPI 为 "Image Path"，CNG 为 UM\Image）。</param>
/// <param name="ProviderType">CAPI 提供程序类型（PROV_RSA_FULL=1 等）；CNG 无此概念，恒为 0。</param>
/// <param name="Kind">CSP / KSP。</param>
public sealed record KeyStoreProvider(string Name, string ImagePath, int ProviderType, KeyStoreKind Kind)
{
    /// <summary>实现 DLL 的文件名（含扩展名，去目录）。</summary>
    public string ImageFileName
    {
        get
        {
            try { return Path.GetFileName(ImagePath ?? "") ?? ""; }
            catch { return ImagePath ?? ""; }
        }
    }

    public override string ToString() => $"[{(Kind == KeyStoreKind.Cng ? "KSP" : "CSP")}] {Name}";
}

/// <summary>
/// 枚举系统已注册的 CSP / KSP，并列出它们各自的密钥容器。
/// <para>
/// 只读探测：CAPI 走 <c>CryptAcquireContext(CRYPT_VERIFYCONTEXT)</c> + <c>PP_ENUMCONTAINERS</c>，
/// CNG 走 <c>NCryptOpenStorageProvider</c> + <c>NCryptEnumKeys</c>。
/// 列容器不会要求 PIN，也不会改动卡上内容。
/// </para>
/// </summary>
public static class KeyStoreRegistry
{
    private static readonly object Gate = new();
    private static IReadOnlyList<KeyStoreProvider>? _providers;

    /// <summary>已注册的 CSP/KSP 列表（进程内缓存；新装驱动后重启程序即可刷新）。</summary>
    public static IReadOnlyList<KeyStoreProvider> Providers
    {
        get
        {
            lock (Gate) return _providers ??= Discover();
        }
    }

    /// <summary>丢弃缓存（下次访问重新读取注册表）。</summary>
    public static void Invalidate()
    {
        lock (Gate) _providers = null;
    }

    /// <summary>列出某提供程序下可见的密钥容器名；失败返回空列表（不抛异常）。</summary>
    public static IReadOnlyList<string> ListContainers(KeyStoreProvider provider)
    {
        try
        {
            return provider.Kind == KeyStoreKind.Cng
                ? ListCngKeys(provider.Name)
                : ListCapiContainers(provider);
        }
        catch (Exception ex)
        {
            Log.Write($"[私钥] 枚举 {provider} 的容器失败：{ex.Message}");
            return Array.Empty<string>();
        }
    }

    // ============================================================ 注册表发现

    private static List<KeyStoreProvider> Discover()
    {
        var list = new List<KeyStoreProvider>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // CAPI：64 位视图、32 位视图、当前用户 三处都可能有
        // （国产 CSP 常用 HKCU 注册，例如「ZGHD Cryptographic Service Provider v1.0 For LNCA」）。
        foreach (var (root, sub) in new (RegistryKey, string)[]
                 {
                     (Registry.LocalMachine, @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider"),
                     (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider"),
                     (Registry.CurrentUser, @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider"),
                 })
        {
            try
            {
                using var key = root.OpenSubKey(sub);
                if (key == null) continue;
                foreach (var name in key.GetSubKeyNames())
                {
                    if (!seen.Add(name)) continue;
                    using var item = key.OpenSubKey(name);
                    var image = item?.GetValue("Image Path") as string ?? "";
                    var type = item?.GetValue("Type") is int t ? t : 1;
                    list.Add(new KeyStoreProvider(name, image, type, KeyStoreKind.Capi));
                }
            }
            catch (Exception ex)
            {
                Log.Write($"[私钥] 读取 CSP 注册表 {sub} 失败：{ex.Message}");
            }
        }

        // CNG：HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\<名称>\UM\Image
        try
        {
            using var kspRoot = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Cryptography\Providers");
            if (kspRoot != null)
            {
                foreach (var name in kspRoot.GetSubKeyNames())
                {
                    // 只保留可能持有卡内私钥的 KSP：
                    // · 厂商 KSP（智能卡厂商自带的密钥存储提供程序）；
                    // · 微软的智能卡 KSP（minidriver 卡经它暴露密钥）。
                    // 其余系统 KSP（Passport / Platform Crypto / Primitive / SSL / Software …）与卡无关，
                    // 而且实测对它们调用 NCryptEnumKeys 会因个别实现返回的数组不规范而<b>直接访问冲突崩进程</b>，
                    // 因此一律跳过。
                    if (IsMicrosoftBuiltin(name) &&
                        !name.Equals("Microsoft Smart Card Key Storage Provider", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!seen.Add(name)) continue;
                    using var um = kspRoot.OpenSubKey(name + @"\UM");
                    var image = um?.GetValue("Image") as string ?? "";
                    list.Add(new KeyStoreProvider(name, image, 0, KeyStoreKind.Cng));
                }
            }
        }
        catch (Exception ex)
        {
            Log.Write($"[私钥] 读取 KSP 注册表失败：{ex.Message}");
        }

        return list;
    }

    private static bool IsMicrosoftBuiltin(string name) =>
        name.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase);

    // ============================================================ CAPI（CSP）

    private const uint PP_ENUMCONTAINERS = 2;
    private const uint CRYPT_FIRST = 0x00000001;
    private const uint CRYPT_NEXT = 0x00000002;
    private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;

    private static IReadOnlyList<string> ListCapiContainers(KeyStoreProvider provider)
    {
        var result = new List<string>();
        // CRYPT_VERIFYCONTEXT：只取提供程序句柄用于枚举，不绑定任何密钥容器，
        // 因此既不需要 PIN，也不会对卡下发改动性指令。
        if (!CryptAcquireContextW(out var hProv, null, provider.Name,
                unchecked((uint)provider.ProviderType), CRYPT_VERIFYCONTEXT))
            return result;

        try
        {
            var buffer = new byte[1024];
            var flags = CRYPT_FIRST;
            while (true)
            {
                uint len = (uint)buffer.Length;
                if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, buffer, ref len, flags)) break;
                var name = DecodeAnsi(buffer, (int)len);
                if (name.Length > 0) result.Add(name);
                flags = CRYPT_NEXT;
            }
        }
        finally
        {
            CryptReleaseContext(hProv, 0);
        }
        return result;
    }

    private static string DecodeAnsi(byte[] buffer, int length)
    {
        var limit = Math.Min(length, buffer.Length);
        if (limit <= 0) return "";
        var end = Array.IndexOf(buffer, (byte)0, 0, limit);
        if (end < 0) end = limit;
        return Encoding.Default.GetString(buffer, 0, end).Trim();
    }

    // ============================================================ CNG（KSP）

    [StructLayout(LayoutKind.Sequential)]
    private struct NCryptKeyName
    {
        public IntPtr pszName;
        public IntPtr pszAlgid;
        public uint dwLegacyKeySpec;
        public uint dwFlags;
    }

    private static IReadOnlyList<string> ListCngKeys(string providerName)
    {
        var result = new List<string>();
        if (NCryptOpenStorageProvider(out var hProv, providerName, 0) != 0) return result;

        var enumState = IntPtr.Zero;
        try
        {
            var size = Marshal.SizeOf<NCryptKeyName>();
            // 批次/条目都设上限：NCryptEnumKeys 在个别实现上可能返回不规范数组，
            // 无上限地往后读会越界并直接把进程打崩（实测 Microsoft Passport KSP 即如此）。
            for (var batch = 0; batch < 64; batch++)
            {
                if (NCryptEnumKeys(hProv, null, out var names, ref enumState, 0) != 0 || names == IntPtr.Zero)
                    break;
                try
                {
                    // 返回的是 NCryptKeyName 数组，以「全零项」结束
                    for (var i = 0; i < 1024; i++)
                    {
                        var item = Marshal.PtrToStructure<NCryptKeyName>(names + i * size);
                        if (item.pszName == IntPtr.Zero) break;
                        var name = Marshal.PtrToStringUni(item.pszName);
                        if (!string.IsNullOrEmpty(name)) result.Add(name);
                    }
                }
                finally
                {
                    NCryptFreeBuffer(names);
                }
            }
        }
        finally
        {
            if (enumState != IntPtr.Zero) NCryptFreeBuffer(enumState);
            NCryptFreeObject(hProv);
        }
        return result;
    }

    // ============================================================ P/Invoke

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptAcquireContextW(out IntPtr phProv, string? pszContainer,
        string? pszProvider, uint dwProvType, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, byte[]? pbData,
        ref uint pdwDataLen, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptEnumKeys(IntPtr hProvider, string? pszScope, out IntPtr ppKeyName,
        ref IntPtr ppEnumState, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeBuffer(IntPtr pvInput);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(IntPtr hObject);
}
