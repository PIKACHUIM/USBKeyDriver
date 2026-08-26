# USB Key 管理端系统 - API接口文档

**文档版本**：v1.0  
**编制日期**：2026-08-23  
**目标读者**：厂商驱动对接开发者

---

## 1. 概述

本文档详细描述 `IKeyProvider` 接口规范，用于对接不同厂商的 USB Key 设备。实现此接口即可将新厂商的设备集成到管理端系统。

### 1.1 接口定义位置

**命名空间**：`USBKey.Core.UsbKey`  
**文件**：`src/USBKey.Core/UsbKey/IKeyProvider.cs`

### 1.2 实现示例

- **MockKeyProvider**：完整的模拟实现（参考）
- **LncaProvider**：LNCA厂商实现（部分待对接）

---

## 2. IKeyProvider 接口

### 2.1 接口声明

```csharp
namespace USBKey.Core.UsbKey;

public interface IKeyProvider : IDisposable
{
    // 基础属性
    string PlatformName { get; }
    bool IsAvailable { get; }
    
    // 初始化
    void Initialize();
    
    // 设备管理
    IReadOnlyList<UsbKeyDevice> Enumerate();
    UsbKeyDevice Open(int handleOrSerial);
    void Login(UsbKeyDevice device, string pin);
    void Logout(UsbKeyDevice device);
    UsbKeyDevice GetDetail(UsbKeyDevice device);
    
    // 证书管理
    IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device);
    void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword);
    void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath);
    void ViewCertificate(KeyContainer container);
    void DeleteContainer(UsbKeyDevice device, KeyContainer container);
    
    // 系统集成
    void RegisterToCsp(KeyContainer container);
    void UnregisterFromCsp(KeyContainer container);
    
    // 密码与解锁
    void ChangePin(UsbKeyDevice device, string oldPin, string newPin);
    void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin);
    string GenerateChallenge(UsbKeyDevice device);
    void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin);
    void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null);
}
```

---

## 3. 属性

### 3.1 PlatformName

**类型**：`string`  
**访问**：只读  
**说明**：平台唯一标识符（小写），如 `"lnca"`、`"mock"`

**示例**：
```csharp
public string PlatformName => "myvendor";
```

**要求**：
- 必须小写
- 字母、数字、下划线
- 与 `config.json` 的 `platform` 数组匹配

---

### 3.2 IsAvailable

**类型**：`bool`  
**访问**：只读  
**说明**：驱动DLL是否可用（是否存在且可加载）

**示例**：
```csharp
public bool IsAvailable => File.Exists(Path.Combine(_libRoot, "vendor_sdk.dll"));
```

**用途**：
- 在枚举设备前检查驱动可用性
- UI显示"驱动未安装"提示

---

## 4. 初始化

### 4.1 Initialize

**签名**：`void Initialize()`  
**说明**：初始化Provider，加载驱动DLL、准备环境

**调用时机**：
- `KeyManager.InitializeAll()` 时调用
- 在第一次枚举设备前必须调用

**实现要求**：
- 加载厂商DLL（LoadLibrary）
- 初始化SDK环境
- 失败时抛出异常（带明确描述）

**示例**：
```csharp
public void Initialize()
{
    if (_initialized) return;
    
    var dllPath = Path.Combine(_libRoot, "vendor_sdk.dll");
    _module = NativeDll.Load(dllPath);
    if (_module == null)
        throw new FileNotFoundException("驱动DLL未找到", dllPath);
    
    // 调用SDK初始化函数
    var initFunc = _module.GetDelegate<InitFunc>("VendorSDK_Init");
    if (initFunc == null || initFunc() != 0)
        throw new InvalidOperationException("SDK初始化失败");
    
    _initialized = true;
}
```

---

## 5. 设备管理

### 5.1 Enumerate

**签名**：`IReadOnlyList<UsbKeyDevice> Enumerate()`  
**说明**：枚举当前已插入的本平台 USB Key 设备

**返回**：设备列表（可为空）

**实现方式**：
1. **厂商SDK接口**（推荐）：调用SDK的枚举函数
2. **WMI/SetupAPI**：按VID/PID过滤USB设备
3. **PCSC智能卡**：枚举智能卡读卡器

**示例**（WMI方式）：
```csharp
public IReadOnlyList<UsbKeyDevice> Enumerate()
{
    var result = new List<UsbKeyDevice>();
    
    using var searcher = new ManagementObjectSearcher(
        "SELECT * FROM Win32_PnPEntity WHERE PNPClass='USB'");
    
    foreach (ManagementBaseObject obj in searcher.Get())
    {
        var devId = obj["PNPDeviceID"]?.ToString() ?? "";
        var match = Regex.Match(devId, @"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})");
        if (!match.Success) continue;
        
        int vid = Convert.ToInt32(match.Groups[1].Value, 16);
        int pid = Convert.ToInt32(match.Groups[2].Value, 16);
        
        // 检查VID/PID是否匹配（从config.keyslist获取）
        if (!IsMyDevice(vid, pid)) continue;
        
        result.Add(new UsbKeyDevice
        {
            Platform = PlatformName,
            VendorName = "厂商名",
            Model = obj["Name"]?.ToString() ?? "USB Key",
            SerialNumber = ExtractSerial(devId),
            Handle = result.Count,
            Vid = vid,
            Pid = pid
        });
    }
    
    return result;
}
```

---

### 5.2 Open

**签名**：`UsbKeyDevice Open(int handleOrSerial)`  
**说明**：打开指定设备（返回带句柄的设备对象）

**参数**：
- `handleOrSerial`：设备句柄或序列号索引

**返回**：已打开的设备对象

**实现要求**：
- 设备句柄有效性检查
- 失败时抛出异常

**示例**：
```csharp
public UsbKeyDevice Open(int handleOrSerial)
{
    var devices = Enumerate();
    if (handleOrSerial >= 0 && handleOrSerial < devices.Count)
        return devices[handleOrSerial];
    
    throw new InvalidOperationException("设备索引无效");
}
```

---

### 5.3 Login

**签名**：`void Login(UsbKeyDevice device, string pin)`  
**说明**：使用PIN认证登录（解锁）设备

**参数**：
- `device`：设备对象
- `pin`：PIN码（字符串）

**副作用**：
- 成功时设置 `device.IsLoggedIn = true`

**异常**：
- PIN错误：抛出 `InvalidOperationException("PIN验证失败")`
- 设备锁定：抛出 `InvalidOperationException("设备已锁定，请使用PUK解锁")`

**示例**：
```csharp
public void Login(UsbKeyDevice device, string pin)
{
    var func = _module.GetDelegate<LoginFunc>("VendorSDK_Login");
    int ret = func(device.Handle, pin);
    
    switch (ret)
    {
        case 0:
            device.IsLoggedIn = true;
            return;
        case 0x6983:
            throw new InvalidOperationException("设备已锁定");
        case 0x63C0:
            throw new InvalidOperationException("PIN错误，剩余0次");
        case 0x63C1:
            throw new InvalidOperationException("PIN错误，剩余1次");
        default:
            throw new InvalidOperationException($"登录失败，错误码：0x{ret:X}");
    }
}
```

---

### 5.4 Logout

**签名**：`void Logout(UsbKeyDevice device)`  
**说明**：登出（锁定）设备

**副作用**：
- 设置 `device.IsLoggedIn = false`

**示例**：
```csharp
public void Logout(UsbKeyDevice device)
{
    var func = _module.GetDelegate<LogoutFunc>("VendorSDK_Logout");
    func?.Invoke(device.Handle);
    device.IsLoggedIn = false;
}
```

---

### 5.5 GetDetail

**签名**：`UsbKeyDevice GetDetail(UsbKeyDevice device)`  
**说明**：读取设备详细信息（序列号、固件版本、容量等）

**返回**：更新后的设备对象

**示例**：
```csharp
public UsbKeyDevice GetDetail(UsbKeyDevice device)
{
    var func = _module.GetDelegate<GetInfoFunc>("VendorSDK_GetInfo");
    
    var info = new DeviceInfo();
    int ret = func(device.Handle, ref info);
    if (ret != 0) return device;
    
    device.SerialNumber = info.SerialNumber;
    device.FirmwareVersion = info.FirmwareVersion;
    device.CapacityKb = info.CapacityKb;
    
    return device;
}
```

---

## 6. 证书管理

### 6.1 ListContainers

**签名**：`IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)`  
**说明**：列出设备上的所有证书/容器

**前提**：设备必须已登录

**返回**：证书列表（可为空）

**实现要求**：
- 读取设备上的证书或密钥容器列表
- 解析证书内容（X509）
- 填充 `KeyContainer` 对象

**示例**：
```csharp
public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
{
    if (!device.IsLoggedIn)
        throw new InvalidOperationException("请先登录设备");
    
    var result = new List<KeyContainer>();
    
    // 枚举容器
    var enumFunc = _module.GetDelegate<EnumContainersFunc>("VendorSDK_EnumContainers");
    int count = enumFunc(device.Handle);
    
    for (int i = 0; i < count; i++)
    {
        // 读取证书
        var getCertFunc = _module.GetDelegate<GetCertFunc>("VendorSDK_GetCert");
        byte[] certBytes = new byte[4096];
        int len = getCertFunc(device.Handle, i, certBytes);
        
        // 解析X509证书
        using var cert = new X509Certificate2(certBytes, 0, len);
        
        result.Add(new KeyContainer
        {
            Name = GetCN(cert.Subject),
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = $"{cert.SignatureAlgorithm.FriendlyName}",
            KeyUsage = GetKeyUsage(cert),
            ContainerName = $"Container_{i}",
            ContainerUuid = Guid.NewGuid().ToString(),
            CertRaw = certBytes.Take(len).ToArray()
        });
    }
    
    return result;
}
```

---

### 6.2 ImportPfx

**签名**：`void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)`  
**说明**：导入PFX证书（含私钥）到USB Key

**参数**：
- `pfxPath`：PFX文件路径
- `pfxPassword`：PFX密码

**前提**：设备已登录

**实现要求**：
- 读取PFX文件
- 提取证书与私钥
- 写入USB Key

**示例**：
```csharp
public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
{
    if (!device.IsLoggedIn)
        throw new InvalidOperationException("请先登录设备");
    
    // 加载PFX
    var cert = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.Exportable);
    var privateKey = cert.GetRSAPrivateKey();
    if (privateKey == null)
        throw new InvalidOperationException("PFX不含私钥");
    
    // 导出私钥参数
    var keyParams = privateKey.ExportParameters(true);
    
    // 调用SDK导入
    var func = _module.GetDelegate<ImportKeyFunc>("VendorSDK_ImportKey");
    int ret = func(
        device.Handle,
        cert.RawData, cert.RawData.Length,
        keyParams.Modulus, keyParams.Modulus.Length,
        keyParams.D, keyParams.D.Length);
    
    if (ret != 0)
        throw new InvalidOperationException($"导入失败，错误码：0x{ret:X}");
}
```

---

### 6.3 ExportCertificate

**签名**：`void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)`  
**说明**：导出证书（仅公钥）到文件

**注意**：**绝不导出私钥**（安全要求）

**示例**：
```csharp
public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
{
    if (container.CertRaw == null || container.CertRaw.Length == 0)
        throw new InvalidOperationException("证书数据不可用");
    
    // 确保只导出公钥证书
    using var cert = new X509Certificate2(container.CertRaw);
    var publicOnly = cert.Export(X509ContentType.Cert); // 不含私钥
    
    File.WriteAllBytes(outputPath, publicOnly);
}
```

---

### 6.4 ViewCertificate

**签名**：`void ViewCertificate(KeyContainer container)`  
**说明**：打开系统证书查看器查看证书详情

**实现**：
```csharp
public void ViewCertificate(KeyContainer container)
{
    // 保存到临时文件
    var tmpFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".cer");
    File.WriteAllBytes(tmpFile, container.CertRaw);
    
    // 调用系统查看器
    Process.Start(new ProcessStartInfo(tmpFile) { UseShellExecute = true });
}
```

---

### 6.5 DeleteContainer

**签名**：`void DeleteContainer(UsbKeyDevice device, KeyContainer container)`  
**说明**：从USB Key删除证书/容器

**前提**：设备已登录

**实现**：
```csharp
public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
{
    if (!device.IsLoggedIn)
        throw new InvalidOperationException("请先登录设备");
    
    var func = _module.GetDelegate<DeleteContainerFunc>("VendorSDK_DeleteContainer");
    int ret = func(device.Handle, container.ContainerUuid);
    
    if (ret != 0)
        throw new InvalidOperationException($"删除失败，错误码：0x{ret:X}");
}
```

---

### 6.6 RegisterToCsp / UnregisterFromCsp

**签名**：
- `void RegisterToCsp(KeyContainer container)`
- `void UnregisterFromCsp(KeyContainer container)`

**说明**：将证书注册/注销到系统CSP证书库（当前用户"个人"存储）

**实现**：
```csharp
public void RegisterToCsp(KeyContainer container)
{
    using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    
    using var cert = new X509Certificate2(container.CertRaw);
    cert.FriendlyName = container.Name;
    store.Add(cert);
    
    store.Close();
    container.IsRegisteredInCsp = true;
}

public void UnregisterFromCsp(KeyContainer container)
{
    using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    
    var found = store.Certificates.Find(
        X509FindType.FindByThumbprint, 
        container.Thumbprint, 
        false);
    
    foreach (var c in found)
        store.Remove(c);
    
    store.Close();
    container.IsRegisteredInCsp = false;
}
```

---

## 7. 密码与解锁

### 7.1 ChangePin

**签名**：`void ChangePin(UsbKeyDevice device, string oldPin, string newPin)`  
**说明**：使用旧PIN修改为新PIN

**前提**：设备已登录

**参数校验**：
- `newPin` 长度 >= 6（调用前已由 `Validators.EnsurePin()` 校验）

**示例**：
```csharp
public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
{
    if (!device.IsLoggedIn)
        throw new InvalidOperationException("请先登录设备");
    
    var func = _module.GetDelegate<ChangePinFunc>("VendorSDK_ChangePin");
    int ret = func(device.Handle, oldPin, newPin);
    
    if (ret != 0)
        throw new InvalidOperationException($"修改密码失败，错误码：0x{ret:X}");
}
```

---

### 7.2 Unlock

**签名**：`void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)`  
**说明**：使用PUK/AdminKey解锁被锁定的设备

**参数**：
- `method`：解锁方式（Puk / AdminKey / Challenge）
- `credential`：凭据（PUK码 / Admin Key）
- `newPin`：新的PIN（解锁后设置）

**实现**：
```csharp
public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
{
    int ret = 0;
    
    switch (method)
    {
        case UnlockMethod.Puk:
            var pukFunc = _module.GetDelegate<UnlockByPukFunc>("VendorSDK_UnlockByPuk");
            ret = pukFunc(device.Handle, credential, newPin);
            break;
        
        case UnlockMethod.AdminKey:
            var adminFunc = _module.GetDelegate<UnlockByAdminFunc>("VendorSDK_UnlockByAdmin");
            ret = adminFunc(device.Handle, credential, newPin);
            break;
        
        default:
            throw new NotSupportedException("不支持的解锁方式");
    }
    
    if (ret != 0)
        throw new InvalidOperationException($"解锁失败，错误码：0x{ret:X}");
    
    device.IsLoggedIn = true;
}
```

---

### 7.3 GenerateChallenge

**签名**：`string GenerateChallenge(UsbKeyDevice device)`  
**说明**：生成挑战码（管理员模式，用于远程解锁）

**返回**：挑战码字符串（通常为十六进制）

**实现**：
```csharp
public string GenerateChallenge(UsbKeyDevice device)
{
    var func = _module.GetDelegate<GenChallengeFunc>("VendorSDK_GenerateChallenge");
    byte[] challenge = new byte[16];
    int ret = func(device.Handle, challenge);
    
    if (ret != 0)
        throw new InvalidOperationException("生成挑战码失败");
    
    return BitConverter.ToString(challenge).Replace("-", "");
}
```

---

### 7.4 UnlockByChallenge

**签名**：`void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)`  
**说明**：使用挑战码响应解锁设备

**参数**：
- `challenge`：挑战码（由管理员生成）
- `response`：响应码（由管理员根据挑战码计算）
- `newPin`：新的PIN

**实现**：
```csharp
public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
{
    var func = _module.GetDelegate<UnlockByChallengeFunc>("VendorSDK_UnlockByChallenge");
    
    byte[] challengeBytes = HexStringToBytes(challenge);
    byte[] responseBytes = HexStringToBytes(response);
    
    int ret = func(device.Handle, challengeBytes, responseBytes, newPin);
    
    if (ret != 0)
        throw new InvalidOperationException("挑战码响应无效");
    
    device.IsLoggedIn = true;
}
```

---

### 7.5 ResetDevice

**签名**：`void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null)`  
**说明**：初始化/重置设备（清除所有证书与密钥）

**参数**：
- `newPin`：新的PIN（必填）
- `puk`：PUK码（可选，null表示随机生成）
- `adminKey`：Admin Key（可选，null表示随机生成）

**警告**：此操作不可逆，会清除所有数据

**实现**：
```csharp
public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null)
{
    // 生成随机PUK/AdminKey（如果未提供）
    puk ??= Validators.RandomPassword(8);
    adminKey ??= Validators.RandomPassword(16);
    
    var func = _module.GetDelegate<ResetFunc>("VendorSDK_Reset");
    int ret = func(device.Handle, newPin, puk, adminKey);
    
    if (ret != 0)
        throw new InvalidOperationException($"重置设备失败，错误码：0x{ret:X}");
    
    device.IsLoggedIn = true;
}
```

---

## 8. 数据模型

### 8.1 UsbKeyDevice

**用途**：描述一台USB Key设备

```csharp
public class UsbKeyDevice
{
    public string Platform { get; set; }        // 平台名（如"lnca"）
    public string VendorName { get; set; }      // 厂商显示名
    public string Model { get; set; }           // 设备型号
    public string SerialNumber { get; set; }    // 序列号
    public int Handle { get; set; }             // 设备句柄/索引
    public int Vid { get; set; }                // USB VID
    public int Pid { get; set; }                // USB PID
    public string FirmwareVersion { get; set; } // 固件版本
    public long CapacityKb { get; set; }        // 容量（KB）
    public bool IsLoggedIn { get; set; }        // 登录状态
    public string Notes { get; set; }           // 备注
    
    public string TrayLabel => string.IsNullOrEmpty(SerialNumber)
        ? $"{Platform.ToUpperInvariant()}-{Model}"
        : $"{Platform.ToUpperInvariant()}-{SerialNumber}";
}
```

---

### 8.2 KeyContainer

**用途**：描述USB Key上的一个证书/容器

```csharp
public class KeyContainer
{
    public string Name { get; set; }                // 证书名称/CN
    public string ContainerName { get; set; }       // 容器名（CSP用）
    public string ContainerUuid { get; set; }       // 容器UUID
    public string Algorithm { get; set; }           // 算法（如"RSA 2048/SHA256"）
    public string Subject { get; set; }             // 主题DN
    public string Issuer { get; set; }              // 签发者DN
    public DateTime? NotBefore { get; set; }        // 有效期起
    public DateTime? NotAfter { get; set; }         // 有效期止
    public string KeyUsage { get; set; }            // 密钥用途
    public string ExtendedKeyUsage { get; set; }    // 扩展用途
    public bool IsRegisteredInCsp { get; set; }     // 是否已注册到CSP
    public string SerialNumber { get; set; }        // 证书序列号
    public string Thumbprint { get; set; }          // 证书指纹(SHA1)
    public byte[]? CertRaw { get; set; }            // 证书字节（DER编码）
    
    public string ValidityText =>
        (NotBefore?.ToString("yyyy-MM-dd") ?? "-") + " ~ " + 
        (NotAfter?.ToString("yyyy-MM-dd") ?? "-");
}
```

---

### 8.3 UnlockMethod

**用途**：解锁方式枚举

```csharp
public enum UnlockMethod
{
    Puk,        // PUK解锁
    AdminKey,   // Admin Key解锁
    Challenge,  // 挑战码解锁
}
```

---

## 9. 辅助类

### 9.1 NativeDll（DLL加载）

**位置**：`USBKey.Core.Native.NativeDll`

**用途**：加载非托管DLL并解析导出函数

**示例**：
```csharp
// 加载DLL
using var module = NativeDll.Load(@"C:\Path\To\vendor.dll");
if (module == null)
    throw new FileNotFoundException("DLL未找到");

// 按名称获取函数
var func = module.GetDelegate<MyDelegateType>("FunctionName");

// 按序号获取函数（序号导出）
var func2 = module.GetDelegateByOrdinal<MyDelegateType>(101);

// 调用
int result = func(param1, param2);
```

---

### 9.2 Validators（参数校验）

**位置**：`USBKey.Core.Common.Validators`

**常用方法**：
```csharp
// 校验PIN长度（>= 6位）
Validators.EnsurePin(pin, "PIN");

// 校验密码一致性
Validators.EnsureSame(newPin, confirmPin, "新PIN");

// 生成随机密码
string randomPin = Validators.RandomPassword(8); // 8位随机
```

---

### 9.3 CertHelper（证书操作）

**位置**：`USBKey.Core.Crypto.CertHelper`

**常用方法**：
```csharp
// 注册证书到CSP
CertHelper.Register(certBytes, "友好名称");

// 注销证书
CertHelper.UnregisterByThumbprint(thumbprint);

// 判断证书是否已注册
bool isReg = CertHelper.IsRegistered(thumbprint);

// 查看证书文件
CertHelper.ViewCertificateFile(cerPath);
```

---

## 10. 集成指南

### 10.1 实现Provider

```csharp
// 1. 创建类实现接口
public class MyVendorProvider : IKeyProvider
{
    private string _libRoot;
    private NativeDll.Module? _module;
    
    public string PlatformName => "myvendor";
    public bool IsAvailable => File.Exists(Path.Combine(_libRoot, "myvendor_sdk.dll"));
    
    public MyVendorProvider(string libraryRoot)
    {
        _libRoot = libraryRoot;
    }
    
    public void Initialize()
    {
        _module = NativeDll.Load(Path.Combine(_libRoot, "myvendor_sdk.dll"));
        if (_module == null)
            throw new FileNotFoundException("驱动DLL未找到");
    }
    
    // 实现所有接口方法...
    
    public void Dispose()
    {
        _module?.Dispose();
    }
}
```

### 10.2 注册Provider

**位置**：`USBKey.Manager/AppContext.cs`

```csharp
public AppContext(AppConfig config)
{
    Config = config;
    Keys = new KeyManager(config);
    
    // 注册各厂商Provider
    Keys.Register(new LncaProvider(AppPaths.LibraryDir));
    Keys.Register(new MyVendorProvider(AppPaths.LibraryDir)); // 新增
    Keys.Register(new MockKeyProvider());
}
```

### 10.3 配置文件

**config.json**：
```json
{
  "platform": ["lnca", "myvendor", "mock"],
  "keyslist": {
    "myvendor": [
      {
        "name": "MyVendor USB Key",
        "vid": "1234",
        "pid": "5678"
      }
    ]
  }
}
```

### 10.4 测试

```powershell
# 1. 编译
dotnet build USBKey.sln -c Release

# 2. 复制厂商DLL到Library目录
Copy-Item "C:\VendorSDK\*.dll" "C:\USBKey\Library\MyVendor\"

# 3. 运行管理端
.\src\USBKey.Manager\bin\Release\net8.0-windows\USBKey.Manager.exe

# 4. 选择厂商："myvendor"
# 5. 测试枚举、登录、证书操作等
```

---

## 11. 常见错误

### 11.1 DLL加载失败

**错误**：`FileNotFoundException: 驱动DLL未找到`

**原因**：
- DLL路径错误
- DLL依赖项缺失（如VC++ Runtime）

**解决**：
```powershell
# 检查DLL是否存在
Test-Path "C:\USBKey\Library\MyVendor\myvendor_sdk.dll"

# 检查依赖项（使用Dependency Walker）
# 或使用dumpbin查看导入表
dumpbin /imports myvendor_sdk.dll
```

---

### 11.2 函数签名不匹配

**错误**：运行时崩溃或返回异常值

**原因**：委托签名与实际DLL函数不一致

**解决**：
1. 用IDA Pro反汇编DLL
2. 确认参数类型、个数、调用约定
3. 修正委托定义

**示例**：
```csharp
// 错误的签名（假设实际是StdCall）
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate int LoginFunc(IntPtr handle, string pin);

// 正确的签名
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int LoginFunc(IntPtr handle, [MarshalAs(UnmanagedType.LPStr)] string pin);
```

---

### 11.3 设备枚举为空

**错误**：`Enumerate()` 返回空列表

**原因**：
- 设备未插入
- VID/PID配置错误
- USB驱动未安装

**调试**：
```powershell
# 检查设备管理器
Get-PnpDevice -PresentOnly | Where-Object { $_.Class -eq 'USB' }

# 检查VID/PID
# 右键设备 → 属性 → 详细信息 → 硬件ID
# 示例：USB\VID_1234&PID_5678&REV_0100
```

---

## 12. 性能优化

### 12.1 延迟加载

**场景**：DLL加载耗时

**优化**：
```csharp
private NativeDll.Module? _module;

private NativeDll.Module Module
{
    get
    {
        if (_module == null)
            Initialize();
        return _module!;
    }
}

public IReadOnlyList<UsbKeyDevice> Enumerate()
{
    // 首次使用时才加载DLL
    var func = Module.GetDelegate<EnumFunc>("VendorSDK_Enum");
    // ...
}
```

---

### 12.2 缓存设备列表

**场景**：频繁调用`Enumerate()`

**优化**：
```csharp
private List<UsbKeyDevice> _cachedDevices = new();
private DateTime _lastEnum = DateTime.MinValue;

public IReadOnlyList<UsbKeyDevice> Enumerate()
{
    if ((DateTime.Now - _lastEnum).TotalSeconds < 5)
        return _cachedDevices; // 5秒内使用缓存
    
    _cachedDevices = DoActualEnumerate();
    _lastEnum = DateTime.Now;
    return _cachedDevices;
}
```

---

## 13. 安全建议

### 13.1 不导出私钥

**要求**：`ExportCertificate` 仅导出公钥证书

**检查**：
```csharp
public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
{
    // 确保不含私钥
    using var cert = new X509Certificate2(container.CertRaw);
    if (cert.HasPrivateKey)
    {
        // 重新导出为仅公钥
        var publicOnly = cert.Export(X509ContentType.Cert);
        File.WriteAllBytes(outputPath, publicOnly);
    }
    else
    {
        File.WriteAllBytes(outputPath, container.CertRaw);
    }
}
```

---

### 13.2 凭据校验

**要求**：所有解锁/改密操作需先认证

**检查**：
```csharp
public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
{
    // 必须验证旧PIN
    if (!VerifyPin(device, oldPin))
        throw new InvalidOperationException("旧PIN验证失败");
    
    // 再执行修改
    // ...
}
```

---

## 附录

### A. 完整实现示例（MockKeyProvider）

参见源代码：`src/USBKey.Core/UsbKey/MockKeyProvider.cs`

---

### B. LNCA部分实现

参见源代码：`src/USBKey.Core/UsbKey/LncaProvider.cs`

---

### C. 联系方式

技术支持：见README.md

---

**文档结束**
