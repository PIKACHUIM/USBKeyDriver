using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using USBKey.Core.Common;

namespace USBKey.Core.Crypto;

/// <summary>
/// 证书辅助：证书查看、系统 CSP 证书库（当前用户 My 存储）注册/注销。
/// 注意：本模块只处理「证书」本身，【绝不操作/导出任何私钥】。
/// </summary>
public static class CertHelper
{
    /// <summary>打开系统证书查看器查看指定证书文件。</summary>
    public static void ViewCertificateFile(string cerPath)
    {
        if (!File.Exists(cerPath)) throw new FileNotFoundException("证书文件不存在", cerPath);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(cerPath) { UseShellExecute = true });
    }

    /// <summary>
    /// 将证书注册到当前用户“个人”证书库。
    /// </summary>
    /// <param name="certDer">证书 DER 编码。</param>
    /// <param name="friendlyName">友好名称（可空）。</param>
    /// <param name="keyBinding">
    /// 私钥容器绑定：写入 <c>CERT_KEY_PROV_INFO_PROP_ID</c>，告诉系统这张证书的私钥
    /// 由哪个提供程序（CSP/KSP）的哪个容器持有——即"把卡内私钥一起注册进来"。
    /// 卡上的证书必然带私钥，因此注册时应当始终带上它；取不到绑定说明厂商 CSP/KSP 没装好，
    /// 属于要报出来的错误，而不是一种正常的中间状态。
    /// </param>
    public static void Register(byte[] certDer, string? friendlyName = null, CertKeyBinding? keyBinding = null)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        using var clone = new X509Certificate2(certDer);
        if (!string.IsNullOrEmpty(friendlyName)) clone.FriendlyName = friendlyName;
        if (keyBinding is { IsValid: true })
        {
            ApplyKeyBinding(clone.Handle, keyBinding);
            Log.Write($"[私钥] 证书「{friendlyName}」已绑定 {keyBinding.Describe()}");
        }

        // 同指纹的旧条目先移除再添加：
        // ① X509Store.Add 走的是 CERT_STORE_ADD_ALWAYS，重复注册会留下多份副本；
        // ② 只有重新添加，本次写入的私钥容器信息才一定生效（覆盖库里已有的旧副本）。
        if (!string.IsNullOrEmpty(clone.Thumbprint))
        {
            foreach (var old in store.Certificates.Find(X509FindType.FindByThumbprint, clone.Thumbprint, false))
                store.Remove(old);
        }

        store.Add(clone);
        store.Close();
    }

    /// <summary>
    /// 把「提供程序 + 容器」写进证书上下文（CERT_KEY_PROV_INFO_PROP_ID）。
    /// <para>
    /// 必须在 <c>store.Add</c> 之前对该证书上下文设置，属性才会随证书一起入库。
    /// CNG（KSP）按约定用 <c>dwProvType=0</c> + <c>dwKeySpec=CERT_NCRYPT_KEY_SPEC</c>，
    /// 与 CAPI（CSP）的写法不同。
    /// </para>
    /// </summary>
    private static void ApplyKeyBinding(IntPtr certContext, CertKeyBinding binding)
    {
        if (certContext == IntPtr.Zero) throw new InvalidOperationException("证书上下文不可用，无法绑定私钥容器");

        var isCng = binding.Kind == KeyStoreKind.Cng;
        var info = new CRYPT_KEY_PROV_INFO
        {
            pwszContainerName = binding.ContainerName,
            pwszProvName = binding.ProviderName,
            dwProvType = isCng ? 0u : unchecked((uint)binding.ProviderType),
            dwFlags = 0,
            cProvParam = 0,
            rgProvParam = IntPtr.Zero,
            dwKeySpec = isCng ? unchecked((uint)CertKeyBinding.NcryptKeySpec) : unchecked((uint)binding.KeySpec),
        };

        if (!CertSetCertificateContextProperty(certContext, CERT_KEY_PROV_INFO_PROP_ID, 0, ref info))
        {
            var err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"写入私钥容器信息失败（Win32={err}）：{binding.Describe()}");
        }
    }

    /// <summary>
    /// 当前用户“个人”库里全部证书的指纹（一次打开、批量比对）。
    /// <para>
    /// 只判断「证书在不在库里」——取证口径是证书库本身，不涉及私钥：
    /// USB Key 上的证书必然带着卡内私钥，系统侧只有"注册了/没注册"两种状态，
    /// 不存在"注册了但没私钥"这种中间态，也没有必要（更无法）从证书库去反推卡上有没有私钥。
    /// </para>
    /// </summary>
    public static HashSet<string> RegisteredThumbprints()
    {
        var all = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (var c in store.Certificates)
        {
            if (!string.IsNullOrEmpty(c.Thumbprint)) all.Add(c.Thumbprint);
        }
        store.Close();
        return all;
    }

    /// <summary>按指纹从当前用户“个人”证书库移除证书。</summary>
    public static bool UnregisterByThumbprint(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var c in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false))
        {
            store.Remove(c);
            store.Close();
            return true;
        }
        store.Close();
        return false;
    }

    /// <summary>判断证书是否已在当前用户“个人”库中。</summary>
    public static bool IsRegistered(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        store.Close();
        return found.Count > 0;
    }

    /// <summary>注册 CSP Provider（驱动）到系统 Crypto 默认 provider 列表，便于系统按名称调用。
    /// 写 HKLM 需要管理员权限；无权限时写入 HKCU。</summary>
    public static void RegisterCspProvider(string providerName, string dllPath, int providerType = 1)
    {
        var root = Registry.LocalMachine.CreateSubKey(
            $@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{providerName}", true);
        root?.SetValue("Image Path", dllPath, RegistryValueKind.String);
        root?.SetValue("Type", providerType, RegistryValueKind.DWord);
        root?.Close();
    }

    /// <summary>注销已注册的 CSP Provider。</summary>
    public static void UnregisterCspProvider(string providerName)
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{providerName}", false);
        }
        catch { }
    }

    // ============================================================ 私钥容器信息（CERT_KEY_PROV_INFO）

    private const uint CERT_KEY_PROV_INFO_PROP_ID = 2;

    /// <summary>CRYPT_KEY_PROV_INFO：证书上记录「私钥在哪个提供程序、哪个容器里」。</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, uint dwPropId,
        uint dwFlags, ref CRYPT_KEY_PROV_INFO pvData);
}
