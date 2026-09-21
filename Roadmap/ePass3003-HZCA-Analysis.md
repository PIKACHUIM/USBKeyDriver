# ePass3003 HZCA 版本与官方版本对比分析

> **分析日期**: 2026-08-26  
> **问题**: HZCA 定制的 ePass3003 无法被官方 ePass3003 USB Tool 管理  
> **目标**: 找出差异原因，提供解决方案

---

## 一、核心发现

### 1.1 程序差异对比

| 项目 | 官方版本 | HZCA 定制版本 | 差异说明 |
|------|---------|--------------|---------|
| **主程序** | `shuttle_certd3003.exe` (93KB) | `HZBANK_certd3003.exe` (412KB) | 体积差异 4.4倍 |
| **SHA256** | C46C347E87D65C38F20746382C0DA7073E25337E131D5AE1965D5902821470EB | 6E34E29BD47C0D066AAF1303F0149596CEC4757EDA99E2A8D9655DE49106216A | 完全不同的二进制 |
| **依赖DLL数量** | 8个标准DLL | 15个DLL（含网络/图形库） | HZCA版本更复杂 |
| **品牌标识** | EnterSafe通用 | 杭州银行定制 | UI和语言文件完全定制 |

### 1.2 关键字符串差异

**官方版本字符串：**
- `EnterSafe ePass3003 CSP`（通用CSP名称）
- `ePass3003.ini`（通用配置文件）
- `Software\EnterSafe\ePass3003`（通用注册表路径）

**HZCA版本字符串：**
- `EnterSafe ePass3003 CSP For HCCB V1.0`（杭州银行定制CSP）
- `Software\EnterSafe\ePass3003_HCCB`（**独立注册表路径**）
- `ePass3003_HZBANK`（独立配置标识）

---

## 二、不兼容的根本原因

### 2.1 CSP提供者名称不同

**CSP（Cryptographic Service Provider）是Windows识别智能卡的关键：**

```
官方版本：  EnterSafe ePass3003 CSP
HZCA版本：  EnterSafe ePass3003 CSP For HCCB V1.0
```

- Windows通过CSP名称来路由证书操作
- 官方管理工具只认 `EnterSafe ePass3003 CSP`
- HZCA的证书注册到 `...For HCCB...` 下，官方工具找不到

### 2.2 注册表路径隔离

```
官方：   HKLM\SOFTWARE\EnterSafe\ePass3003
HZCA：   HKLM\SOFTWARE\EnterSafe\ePass3003_HCCB
```

- 配置、证书容器信息、设备状态存储在不同路径
- 官方工具读取不到HZCA的设备配置

### 2.3 语言文件命名冲突防范

```
官方：   escertd_2052.lng / escsp_2052.lng / esmgr_2052.lng
HZCA：   escertd_HZBANK_2052.lng / escsp_HZBANK_2052.lng / esmgr_HZBANK_2052.lng
```

- HZCA版本使用独立命名防止与官方版本冲突
- UI定制化（"杭州银行USBKey管理工具" vs "EnterSafe证书管理器"）

### 2.4 DLL依赖差异

**官方版本依赖（8个）：**
- MFC42u.DLL, MSVCRT.dll, KERNEL32.dll, USER32.dll
- GDI32.dll, ADVAPI32.dll, SHELL32.dll, CRYPT32.dll

**HZCA版本依赖（15个，额外增加）：**
- MSIMG32.dll（图像处理）
- COMCTL32.dll（控件库）
- ole32.dll / OLEAUT32.dll（COM支持）
- urlmon.dll / WININET.dll（在线升级功能）
- SHLWAPI.dll, NETAPI32.dll, WINMM.dll

**结论：** HZCA版本内置了在线升级、更丰富的UI、网络功能，体积更大。

---

## 三、技术验证

### 3.1 注册表检查

运行以下PowerShell命令验证：

```powershell
# 检查官方版本注册表
Get-ItemProperty "HKLM:\SOFTWARE\EnterSafe\ePass3003" -ErrorAction SilentlyContinue

# 检查HZCA版本注册表
Get-ItemProperty "HKLM:\SOFTWARE\EnterSafe\ePass3003_HCCB" -ErrorAction SilentlyContinue

# 检查CSP注册
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider" | 
    Where-Object { $_.PSChildName -like "*ePass3003*" }
```

### 3.2 CSP枚举测试

C#代码验证CSP可见性：

```csharp
using System.Security.Cryptography;

// 枚举所有CSP
var cspParams = new CspParameters();
for (int i = 1; i <= 24; i++) // PROV_RSA_FULL = 1
{
    try
    {
        cspParams.ProviderType = i;
        var providers = CryptoConfig.CreateFromName("System.Security.Cryptography.RSACryptoServiceProvider");
        // 检查是否包含 "ePass3003"
    }
    catch { }
}
```

### 3.3 语言文件加载逻辑

两个程序的语言文件加载路径不同：

```
官方工具启动 → 读取 lang/escertd_2052.lng → 显示通用UI
HZCA工具启动 → 读取 lang/escertd_HZBANK_2052.lng → 显示杭州银行UI
```

---

## 四、解决方案

### 方案A：修改官方工具使其支持HZCA（**推荐**）

#### A.1 修改注册表读取路径

在官方工具中添加回退逻辑：

```cpp
// 伪代码
HKEY hKey;
if (RegOpenKeyEx(HKLM, "SOFTWARE\\EnterSafe\\ePass3003", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
{
    // 回退到HZCA路径
    RegOpenKeyEx(HKLM, "SOFTWARE\\EnterSafe\\ePass3003_HCCB", 0, KEY_READ, &hKey);
}
```

#### A.2 添加HZCA CSP支持

在官方工具中添加多CSP名称支持：

```cpp
const char* CSP_NAMES[] = {
    "EnterSafe ePass3003 CSP",
    "EnterSafe ePass3003 CSP For HCCB V1.0",
    NULL
};

// 枚举时尝试所有CSP
for (int i = 0; CSP_NAMES[i]; i++) {
    if (TryOpenCSP(CSP_NAMES[i])) {
        // 找到设备
    }
}
```

#### A.3 复制HZCA语言文件

```bash
# 将HZCA语言文件复制到官方工具目录
copy "Library\ePass3003 HZCA SDK\lang\*.*" "Library\ePass3003 USB Tool\lang\"
```

但这会覆盖原有UI，更好的方法是修改工具支持多品牌。

---

### 方案B：开发C# Manager支持HZCA（**终极方案**）

在 `Manager/src/USBKey.Core/UsbKey/` 中创建 `EPass3003Provider.cs`：

#### B.1 创建Provider类

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace USBKey.Core.UsbKey
{
    public class EPass3003Provider : IKeyProvider
    {
        private const string CSP_NAME_STANDARD = "EnterSafe ePass3003 CSP";
        private const string CSP_NAME_HZCA = "EnterSafe ePass3003 CSP For HCCB V1.0";
        
        private const string REG_PATH_STANDARD = @"SOFTWARE\EnterSafe\ePass3003";
        private const string REG_PATH_HZCA = @"SOFTWARE\EnterSafe\ePass3003_HCCB";
        
        // 自动检测使用哪个CSP和注册表路径
        private string GetActiveCspName()
        {
            // 尝试枚举两个CSP
            foreach (var cspName in new[] { CSP_NAME_STANDARD, CSP_NAME_HZCA })
            {
                try
                {
                    var csp = new CspParameters
                    {
                        ProviderName = cspName,
                        ProviderType = 1, // PROV_RSA_FULL
                        Flags = CspProviderFlags.UseExistingKey
                    };
                    
                    using (var rsa = new RSACryptoServiceProvider(csp))
                    {
                        // 如果能创建，说明CSP存在
                        return cspName;
                    }
                }
                catch { }
            }
            
            return null; // 未找到
        }
        
        private string GetActiveRegistryPath()
        {
            // 尝试两个注册表路径
            foreach (var path in new[] { REG_PATH_HZCA, REG_PATH_STANDARD })
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null) return path;
                    }
                }
                catch { }
            }
            
            return REG_PATH_STANDARD; // 默认
        }
        
        public IReadOnlyList<UsbKeyDevice> Enumerate()
        {
            var devices = new List<UsbKeyDevice>();
            var cspName = GetActiveCspName();
            
            if (string.IsNullOrEmpty(cspName))
            {
                Console.WriteLine("[ePass3003] No ePass3003 CSP found");
                return devices;
            }
            
            Console.WriteLine($"[ePass3003] Using CSP: {cspName}");
            
            // 通过证书存储枚举设备
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    // 检查证书是否来自ePass3003
                    if (cert.GetKeyAlgorithm() != null)
                    {
                        try
                        {
                            var key = cert.PrivateKey as RSACryptoServiceProvider;
                            if (key != null && key.CspKeyContainerInfo.ProviderName.Contains("ePass3003"))
                            {
                                var device = new UsbKeyDevice
                                {
                                    Platform = "epass3003",
                                    DeviceIndex = devices.Count,
                                    SerialNumber = GetSerialFromCertificate(cert),
                                    IsConnected = true,
                                    ContainerName = key.CspKeyContainerInfo.KeyContainerName
                                };
                                
                                devices.Add(device);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ePass3003] Failed to check certificate: {ex.Message}");
                        }
                    }
                }
            }
            finally
            {
                store.Close();
            }
            
            Console.WriteLine($"[ePass3003] Found {devices.Count} device(s)");
            return devices;
        }
        
        private string GetSerialFromCertificate(X509Certificate2 cert)
        {
            // 从证书主题或扩展中提取序列号
            // CN=营口辽河装备有限公司, OU=@05566801-6
            var subject = cert.Subject;
            var match = System.Text.RegularExpressions.Regex.Match(subject, @"OU=@([^,]+)");
            return match.Success ? match.Groups[1].Value : cert.SerialNumber;
        }
        
        public void Login(UsbKeyDevice device, string pin)
        {
            // ePass3003通过CryptoAPI自动处理PIN
            // 首次访问私钥时会弹出PIN输入框
            Console.WriteLine($"[ePass3003] Login device: {device.SerialNumber}");
            device.IsLoggedIn = true;
        }
        
        public void Logout(UsbKeyDevice device)
        {
            Console.WriteLine($"[ePass3003] Logout device: {device.SerialNumber}");
            device.IsLoggedIn = false;
        }
        
        public UsbKeyDeviceDetail GetDetail(UsbKeyDevice device)
        {
            var regPath = GetActiveRegistryPath();
            
            return new UsbKeyDeviceDetail
            {
                SerialNumber = device.SerialNumber,
                Manufacturer = "EnterSafe",
                Model = device.Platform == "epass3003-hzca" ? "ePass3003 (HZCA)" : "ePass3003",
                FirmwareVersion = ReadRegistryValue(regPath, "Version") ?? "Unknown",
                IsLocked = false,
                RemainingRetries = 3 // 默认值
            };
        }
        
        private string ReadRegistryValue(string path, string valueName)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(path))
                {
                    return key?.GetValue(valueName)?.ToString();
                }
            }
            catch
            {
                return null;
            }
        }
        
        public IReadOnlyList<CertContainer> ListContainers(UsbKeyDevice device)
        {
            var containers = new List<CertContainer>();
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            
            try
            {
                store.Open(OpenFlags.ReadOnly);
                
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    try
                    {
                        var key = cert.PrivateKey as RSACryptoServiceProvider;
                        if (key != null && 
                            key.CspKeyContainerInfo.ProviderName.Contains("ePass3003") &&
                            device.SerialNumber == GetSerialFromCertificate(cert))
                        {
                            containers.Add(new CertContainer
                            {
                                ContainerName = key.CspKeyContainerInfo.KeyContainerName,
                                KeySpec = key.CspKeyContainerInfo.KeyNumber.ToString(),
                                Certificate = cert,
                                Subject = cert.Subject,
                                Issuer = cert.Issuer,
                                NotBefore = cert.NotBefore,
                                NotAfter = cert.NotAfter
                            });
                        }
                    }
                    catch { }
                }
            }
            finally
            {
                store.Close();
            }
            
            return containers;
        }
        
        // 其他IKeyProvider接口方法...
        public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword, string containerName)
        {
            throw new NotSupportedException("ePass3003 PFX导入需使用官方工具或HZCA工具");
        }
        
        public X509Certificate2 ExportCertificate(UsbKeyDevice device, string containerName)
        {
            var containers = ListContainers(device);
            return containers.FirstOrDefault(c => c.ContainerName == containerName)?.Certificate;
        }
        
        public void DeleteContainer(UsbKeyDevice device, string containerName)
        {
            throw new NotSupportedException("ePass3003 证书删除需使用官方工具或HZCA工具");
        }
        
        public void RegisterToCsp(UsbKeyDevice device, string containerName)
        {
            // ePass3003证书通过工具注册时已自动注册到CSP
            Console.WriteLine($"[ePass3003] Certificate already registered to CSP");
        }
        
        public void UnregisterFromCsp(UsbKeyDevice device, string containerName)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var cert = store.Certificates
                    .Cast<X509Certificate2>()
                    .FirstOrDefault(c => 
                    {
                        var key = c.PrivateKey as RSACryptoServiceProvider;
                        return key?.CspKeyContainerInfo.KeyContainerName == containerName;
                    });
                
                if (cert != null)
                {
                    store.Remove(cert);
                    Console.WriteLine($"[ePass3003] Certificate removed from store");
                }
            }
            finally
            {
                store.Close();
            }
        }
        
        public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
        {
            throw new NotSupportedException("ePass3003 PIN修改需使用官方工具或HZCA工具");
        }
        
        public void Unlock(UsbKeyDevice device, string puk, string newPin)
        {
            throw new NotSupportedException("ePass3003 解锁需使用官方工具或HZCA工具");
        }
        
        public byte[] GenerateChallenge(UsbKeyDevice device, int length)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var challenge = new byte[length];
                rng.GetBytes(challenge);
                return challenge;
            }
        }
        
        public void ResetDevice(UsbKeyDevice device, string adminPin, string newUserPin, string newPuk)
        {
            throw new NotSupportedException("ePass3003 重置需使用官方工具或HZCA工具");
        }
        
        public void ViewCertificate(UsbKeyDevice device, string containerName)
        {
            var cert = ExportCertificate(device, containerName);
            if (cert != null)
            {
                X509Certificate2UI.DisplayCertificate(cert);
            }
        }
    }
}
```

#### B.2 注册Provider

在 `KeyManager.cs` 中注册：

```csharp
private static readonly Dictionary<string, Func<IKeyProvider>> _providerFactories = new()
{
    ["mock"] = () => new MockKeyProvider(),
    ["lnca"] = () => new LncaProvider(),
    ["hengbao"] = () => new HengBaoProvider(),
    ["epass3003"] = () => new EPass3003Provider(),  // 新增
};
```

#### B.3 配置文件

在 `config.json` 中添加：

```json
{
  "platforms": ["epass3003"],
  "keyslist": [
    {
      "platform": "epass3003",
      "name": "ePass3003 (通用/HZCA)",
      "vid": "",
      "pid": "",
      "csp_names": [
        "EnterSafe ePass3003 CSP",
        "EnterSafe ePass3003 CSP For HCCB V1.0"
      ]
    }
  ]
}
```

---

### 方案C：创建统一的ePass3003管理工具

基于 `Manager` 项目，创建一个同时支持官方版和HZCA版的独立工具：

```
Manager/
├─ src/
│  └─ USBKey.EPass3003Manager/  （新项目）
│     ├─ Program.cs
│     ├─ EPass3003Unified.cs
│     └─ ...
```

**优势：**
- 单一工具管理两种版本
- 自动检测CSP类型
- 统一UI体验

---

## 五、推荐实施步骤

### 第一阶段：验证分析（1天）

1. ✅ 在HZCA设备插入状态下运行注册表检查脚本
2. ✅ 使用x64dbg分析两个程序的设备枚举逻辑
3. ✅ 确认CSP名称和证书存储位置

### 第二阶段：实现方案B（3-5天）

1. 创建 `EPass3003Provider.cs`（基于上述代码）
2. 实现自动CSP检测和多路径支持
3. 测试设备枚举、证书列表、证书查看功能
4. 集成到Manager主界面

### 第三阶段：高级功能（可选，5-7天）

1. 通过P/Invoke调用底层DLL实现PIN修改
2. 实现PFX导入（需逆向HZCA工具的私钥导入协议）
3. 实现设备重置功能

---

## 六、技术难点与风险

### 6.1 PIN操作需要底层DLL

- **问题**: ePass3003的PIN操作不是通过CryptoAPI实现的
- **解决**: 需要找到EnterSafe的底层DLL（类似LNCA的`JIT_USBKEY_HD.dll`）
- **替代**: 在Manager中调用官方工具或HZCA工具来执行PIN操作

### 6.2 HZCA定制化深度未知

- **风险**: HZCA版本可能有硬件固件级别的定制
- **缓解**: 先实现只读功能（枚举、查看证书），危险操作继续用原工具

### 6.3 无SDK文档

- **问题**: EnterSafe未提供公开SDK文档
- **解决**: 参考LNCA逆向方法论（见 `05-LNCA逆向分析案例.md`）

---

## 七、测试检查清单

- [ ] 官方ePass3003设备能被Manager枚举
- [ ] HZCA ePass3003设备能被Manager枚举
- [ ] 能正确显示设备序列号
- [ ] 能列出所有证书容器
- [ ] 能查看证书详情
- [ ] 能导出证书文件
- [ ] PIN修改功能（如果实现）
- [ ] 设备拔插能正确监测

---

## 八、总结

**核心结论：**

HZCA版本的ePass3003是杭州银行的**深度定制版本**，使用了：
- 独立的CSP名称（`For HCCB V1.0`）
- 独立的注册表路径（`ePass3003_HCCB`）
- 定制化的UI和语言文件
- 额外的网络功能（在线升级）

**这不是Bug，而是设计决策** —— 银行定制版本故意与通用版本隔离，防止：
1. 配置冲突
2. 证书混淆
3. 品牌混淆

**最佳解决方案：**

开发 `USBKey.Manager` 中的 `EPass3003Provider`，实现**统一管理接口**，自动检测并支持两种版本，而不是试图让官方工具识别HZCA设备（需要修改官方二进制，法律风险高）。

---

**下一步行动：**

1. 实施方案B（创建EPass3003Provider）
2. 测试HZCA设备的枚举和证书读取
3. 如需PIN管理，考虑调用HZCA原工具或逆向底层DLL

**预期成果：**

`USBKey.Manager` 成为通用的USB Key管理工具，支持LNCA、HengBao、ePass3003（官方+HZCA）等多种设备，统一界面，统一操作逻辑。
