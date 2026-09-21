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

    /// <summary>
    /// 重置设备是否必须先提供「当前 PIN」。
    /// <para>
    /// 恒宝 U 宝（CMBCp.dll / PKCS#11）没有 SO PIN / PUK，且 C_InitToken、C_InitPIN
    /// 均为返回 CKR_FUNCTION_NOT_SUPPORTED 的桩函数，因此重置只能走
    /// 「用当前 PIN 登录 → 删除设备上全部对象（清空内容）→ C_SetPIN 重设口令」。
    /// 这类平台返回 true，界面会在重置前要求输入当前 PIN，并跳过 PUK/AdminKey 询问。
    /// </para>
    /// </summary>
    bool ResetRequiresCurrentPin { get; }

    /// <summary>
    /// 该平台是否支持导入「外部 PFX（含私钥）」。
    /// <para>
    /// 默认 true。私钥"卡内生成、不可导出亦不可导入"的平台（SKF / ePass3003 等）覆写为 false，
    /// 界面据此<b>直接禁用</b>该按钮，而不是让用户点了再弹一个错误。
    /// </para>
    /// </summary>
    bool SupportsImportPfx => true;

    /// <summary>
    /// 导入证书是否需要先以用户 PIN 登录。
    /// <para>
    /// 默认 false：绝大多数平台的 <c>ImportPfx</c> 只用「设备序列号 + PFX 密码」，不依赖登录会话。
    /// 曾经界面写死「导入必须已登录」，而 BJCA 的用户 PIN 是按容器逐个校验的、
    /// 空卡无从登录 —— 于是形成「登录失败 → 导入按钮灰掉 → 什么也做不了」的死锁。
    /// </para>
    /// </summary>
    bool ImportRequiresLogin => false;

    /// <summary>
    /// 该平台是否支持「卡内生成密钥对 → 导出 PKCS#10/公钥 → 导回 CA 签发证书」的登记流程。
    /// 这是 BJCA / SKF 这类私钥不可导入的卡唯一的建证路径。
    /// </summary>
    bool SupportsKeyEnrollment => false;

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

    /// <summary>
    /// 注册证书到系统证书库，并把卡内私钥容器一并关联。
    /// <para>
    /// 只写证书本体（公钥）是不够的：证书还需要 CERT_KEY_PROV_INFO 属性指明私钥所在
    /// 的提供程序与容器，系统才认这张证书"有私钥"。默认实现把绑定信息挂到容器对象上，
    /// 再由各平台既有的 <see cref="RegisterToCsp(KeyContainer)"/> 读取并写入证书属性，
    /// 因此各平台无需重复实现。
    /// </para>
    /// </summary>
    /// <param name="container">目标证书/容器。</param>
    /// <param name="keyBinding">解析到的私钥容器绑定；null 表示只注册证书本体。</param>
    void RegisterToCsp(KeyContainer container, Crypto.CertKeyBinding? keyBinding)
    {
        container.KeyBinding = keyBinding;
        RegisterToCsp(container);
    }

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

    /// <summary>
    /// 重置/初始化设备：清空设备内容并把口令重设为 <paramref name="newPin"/>。
    /// <para>
    /// 支持真·令牌初始化的平台（有 SO PIN / PUK）走 C_InitToken 类路径，
    /// 使用 <paramref name="puk"/> / <paramref name="adminKey"/>；
    /// 不支持初始化的平台（见 <see cref="ResetRequiresCurrentPin"/>）
    /// 则使用 <paramref name="currentPin"/> 登录后清空全部对象并改口令。
    /// </para>
    /// </summary>
    /// <param name="device">目标设备（若已登录可不传 currentPin）。</param>
    /// <param name="newPin">重置后的新 PIN。</param>
    /// <param name="puk">PUK（可选，null 表示随机生成）。</param>
    /// <param name="adminKey">Admin Key / SO PIN（可选）。</param>
    /// <param name="currentPin">当前 PIN（可选；<see cref="ResetRequiresCurrentPin"/> 为 true 时必填）。</param>
    void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null);
}
