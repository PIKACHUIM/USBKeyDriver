namespace USBKey.Core.UsbKey;

/// <summary>解锁方式。</summary>
public enum UnlockMethod
{
    /// <summary>PUK 解锁</summary>
    Puk,
    /// <summary>Admin Key 解锁</summary>
    AdminKey,
    /// <summary>挑战码解锁（需管理员生成挑战码）</summary>
    Challenge,
}

/// <summary>
/// 某平台 USB Key 驱动的操作接口抽象。
/// <para>
/// 注意：按产品要求，本接口【不提供任何破解型能力】：
/// 不含导出私钥；所有改PIN/解锁必须先经身份认证（PIN/PUK/AdminKey/挑战码），
/// 绝不提供“无凭据直接修改或解锁”的接口。
/// </para>
/// </summary>
public interface IKeyProvider : IDisposable
{
    /// <summary>平台名（小写，如 lnca）。</summary>
    string PlatformName { get; }

    /// <summary>该平台的驱动 DLL 是否可用（存在于 Library 目录并可加载）。</summary>
    bool IsAvailable { get; }

    /// <summary>初始化（加载 DLL、准备环境）。失败抛出带说明的异常。</summary>
    void Initialize();

    /// <summary>枚举当前连接的本平台 USB Key 设备。</summary>
    IReadOnlyList<UsbKeyDevice> Enumerate();

    /// <summary>打开指定设备（返回带句柄的设备，未登录）。</summary>
    UsbKeyDevice Open(int handleOrSerial);

    /// <summary>PIN 认证登录（解锁）设备。</summary>
    void Login(UsbKeyDevice device, string pin);

    /// <summary>登出（锁定）设备。</summary>
    void Logout(UsbKeyDevice device);

    /// <summary>读取设备详情（序列号/版本/容量/固件）。</summary>
    UsbKeyDevice GetDetail(UsbKeyDevice device);

    /// <summary>列出设备上的证书/容器。</summary>
    IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device);

    /// <summary>本地导入 PFX 证书（仅支持私钥与证书；导入到 Key）。</summary>
    void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword);

    /// <summary>导出证书（仅公钥部分，不导私钥），保存为 .cer/.crt。</summary>
    void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath);

    /// <summary>查看证书详情（打开系统证书查看器，基于证书内容）。</summary>
    void ViewCertificate(KeyContainer container);

    /// <summary>删除设备上的证书/容器。</summary>
    void DeleteContainer(UsbKeyDevice device, KeyContainer container);

    /// <summary>注册证书到系统 CSP 证书库。</summary>
    void RegisterToCsp(KeyContainer container);

    /// <summary>从系统 CSP 证书库注销证书。</summary>
    void UnregisterFromCsp(KeyContainer container);

    /// <summary>使用 PIN 修改当前密码。</summary>
    void ChangePin(UsbKeyDevice device, string oldPin, string newPin);

    /// <summary>使用 PUK 或 AdminKey 解锁设备并重设 PIN。</summary>
    void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin);

    /// <summary>管理员生成挑战码（部分设备支持）。仅管理员模式调用。</summary>
    string GenerateChallenge(UsbKeyDevice device);

    /// <summary>管理员生成挑战码时使用挑战码+新PIN解锁（对端验证）。</summary>
    void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin);

    /// <summary>重置/初始化设备。设置初始 PIN，可选 PUK/AdminKey（带默认随机）。</summary>
    void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null);
}
