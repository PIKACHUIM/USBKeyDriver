using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

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

    /// <summary>将证书（不含私钥）注册到当前用户“个人”证书库。</summary>
    public static void Register(byte[] certDer, string? friendlyName = null)
    {
        using var cert = new X509Certificate2(certDer);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var clone = new X509Certificate2(certDer);
        if (!string.IsNullOrEmpty(friendlyName)) clone.FriendlyName = friendlyName;
        store.Add(clone);
        store.Close();
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
}
