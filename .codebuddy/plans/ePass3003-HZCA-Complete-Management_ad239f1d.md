---
name: ePass3003-HZCA-Complete-Management
overview: 使用PKCS#11接口实现完整的HZCA ePass3003设备管理功能，包括设备枚举、证书导入导出、PIN管理、设备初始化、CSP注册等全套功能
todos:
  - id: explore-lnca-pattern
    content: 使用 [subagent:code-explorer] 深入分析 LncaProvider 和 LncaNative 的实现，提取 DLL 加载、P/Invoke 声明、错误处理、资源管理的完整模式
    status: completed
  - id: create-pkcs11-native
    content: 创建 EPass3003Native.cs，实现完整的 PKCS#11 v2.40 标准接口 P/Invoke 声明，包括常量（50+）、结构体（10+）、函数委托（40+）
    status: completed
    dependencies:
      - explore-lnca-pattern
  - id: implement-dll-loading
    content: 实现 EPass3003Provider 的 DLL 加载和初始化逻辑，支持 32/64 位自动选择，通过 C_GetFunctionList 获取函数表并解析所有函数指针
    status: completed
    dependencies:
      - create-pkcs11-native
  - id: implement-device-enumerate
    content: 实现设备枚举方法 Enumerate，使用 C_GetSlotList 和 C_GetTokenInfo 直接枚举 USB 设备，完全移除证书存储遍历代码
    status: completed
    dependencies:
      - implement-dll-loading
  - id: implement-session-management
    content: 实现会话管理（OpenSession, CloseSession）和 PIN 登录（Login CKU_USER, Logout），支持会话缓存优化
    status: completed
    dependencies:
      - implement-device-enumerate
  - id: implement-cert-list
    content: 实现证书列表方法 ListContainers，使用 C_FindObjects 查找 CKO_CERTIFICATE 对象，C_GetAttributeValue 读取证书 DER 数据并转换为 X509Certificate2
    status: completed
    dependencies:
      - implement-session-management
  - id: implement-cert-import
    content: 实现证书导入方法 ImportPfx，解析 PFX 文件，使用 C_CreateObject 创建证书对象和私钥对象（RSA参数分解）
    status: completed
    dependencies:
      - implement-cert-list
  - id: implement-cert-delete
    content: 实现证书删除方法 DeleteContainer，使用 C_DestroyObject 删除设备上的证书和私钥对象
    status: completed
    dependencies:
      - implement-cert-import
  - id: implement-pin-management
    content: 实现 PIN 管理方法：ChangePin（C_SetPIN），Unlock（C_Login SO + C_InitPIN 实现 PUK 解锁）
    status: completed
    dependencies:
      - implement-session-management
  - id: implement-device-reset
    content: 实现设备初始化方法 ResetDevice，使用 C_InitToken 重置设备并设置初始 SO PIN 和用户 PIN
    status: completed
    dependencies:
      - implement-pin-management
  - id: implement-key-generation
    content: 实现密钥对生成方法（可选），使用 C_GenerateKeyPair 在设备内生成 RSA 密钥对
    status: completed
    dependencies:
      - implement-cert-list
  - id: implement-csp-registration
    content: 实现 CSP 注册方法 RegisterToCsp 和 UnregisterFromCsp，操作 Windows 证书存储进行注册和注销
    status: completed
    dependencies:
      - implement-cert-list
  - id: test-complete-functionality
    content: 完整测试所有功能：设备枚举、证书导入导出删除、PIN 修改、PUK 解锁、设备初始化、CSP 注册，确认无错误日志且功能正常
    status: completed
    dependencies:
      - implement-cert-delete
      - implement-device-reset
      - implement-csp-registration
---

# 用户需求

## 核心目标

实现完整的HZCA ePass3003 USB Key设备管理功能，替代当前错误的证书存储遍历实现。

## 功能需求

### 1. 设备管理

- 设备枚举和识别（通过PKCS#11直接枚举，不遍历证书存储）
- 设备信息查询（序列号、型号、容量、固件版本）
- 设备初始化/重置（C_InitToken）

### 2. 证书管理

- 导入PFX证书到设备（解析PFX，使用C_CreateObject创建证书和私钥对象）
- 从设备导出证书（C_GetAttributeValue读取CKA_VALUE）
- 删除设备上的证书（C_DestroyObject）
- 注册证书到Windows CSP（证书存储操作）
- 从CSP注销证书（从证书存储删除）

### 3. PIN管理

- 用户PIN登录（C_Login CKU_USER）
- 登出（C_Logout）
- 修改用户PIN（C_SetPIN）
- SO PIN登录（C_Login CKU_SO，管理员模式）
- PUK解锁（C_Login SO + C_InitPIN重置用户PIN）

### 4. 密钥管理

- 设备内生成RSA密钥对（C_GenerateKeyPair）
- 导入密钥对到设备（C_CreateObject创建私钥对象）
- 签名操作（C_SignInit + C_Sign）
- 验签操作（C_VerifyInit + C_Verify）
- 加密解密（C_EncryptInit + C_Encrypt / C_DecryptInit + C_Decrypt）

## 问题分析

### 当前实现的严重错误

文件：`Manager/src/USBKey.Core/UsbKey/EPass3003Provider.cs`

错误1：遍历系统所有证书存储

```
var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
foreach (X509Certificate2 cert in store.Certificates) {
    // 尝试访问每个证书的私钥
    // 产生大量错误日志
}
```

错误2：功能严重不足

- 只能查看证书，不能导入、删除
- 不能修改PIN
- 不能初始化设备
- 不能生成密钥对

错误3：性能和日志问题

- 每次枚举产生8-9个错误日志
- UI频繁刷新导致日志爆炸
- 性能低下

## 正确方案

### 技术路线

使用PKCS#11标准接口，像LNCA Provider一样：

1. 动态加载HCCBCSP11.dll（32位/64位自动选择）
2. 获取PKCS#11函数表（C_GetFunctionList）
3. 使用标准PKCS#11接口管理设备

### PKCS#11函数映射

| 功能 | PKCS#11函数 |
| --- | --- |
| 初始化 | C_Initialize |
| 设备枚举 | C_GetSlotList, C_GetSlotInfo |
| 会话管理 | C_OpenSession, C_CloseSession |
| 登录登出 | C_Login, C_Logout |
| PIN管理 | C_SetPIN, C_InitPIN |
| 对象查找 | C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal |
| 属性读取 | C_GetAttributeValue, C_SetAttributeValue |
| 对象管理 | C_CreateObject, C_DestroyObject |
| 密钥生成 | C_GenerateKeyPair |
| 密码学 | C_SignInit, C_Sign, C_VerifyInit, C_Verify |
| 加密解密 | C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt |
| 设备初始化 | C_InitToken |
| 清理 | C_Finalize |


### 参考实现

LNCA Provider已经成功实现了完整的设备管理功能：

- DLL加载：NativeDll.Load
- 函数解析：module.GetDelegate
- 委托声明：UnmanagedFunctionPointer
- 错误处理：返回值检查
- 资源管理：Dispose模式

# 技术方案

## 技术栈

- 语言：C# (.NET 8)
- 平台：Windows (x86/x64)
- 接口标准：PKCS#11 v2.40
- 目标DLL：HCCBCSP11.dll
- 参考实现：LncaProvider

## 实现方案

### 1. 架构设计

```
EPass3003Native.cs
├─ PKCS#11常量定义（CKR_*, CKO_*, CKA_*, CKU_*, CKK_*, CKM_*）
├─ PKCS#11结构体（CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ATTRIBUTE等）
├─ PKCS#11函数委托（40+个函数指针类型）
└─ 函数表结构（CK_FUNCTION_LIST）

EPass3003Provider.cs
├─ IKeyProvider接口实现
├─ DLL加载和初始化
├─ 设备枚举（Enumerate）
├─ 证书管理（ListContainers, ImportPfx, ExportCertificate, DeleteContainer）
├─ PIN管理（Login, Logout, ChangePin, Unlock）
├─ 设备管理（ResetDevice, GetDetail）
├─ CSP注册（RegisterToCsp, UnregisterFromCsp）
└─ 资源清理（Dispose）
```

### 2. DLL加载策略

```
// 优先级顺序
string[] dllPaths = {
    Environment.Is64BitProcess 
        ? @"C:\Windows\System32\HCCBCSP11.dll"
        : @"C:\Windows\SysWOW64\HCCBCSP11.dll",
    "HCCBCSP11.dll" // PATH环境变量
};

foreach (var path in dllPaths) {
    module = NativeDll.Load(path);
    if (module != null) break;
}
```

### 3. PKCS#11初始化流程

```
1. LoadLibrary("HCCBCSP11.dll")
2. GetProcAddress("C_GetFunctionList")
3. 调用C_GetFunctionList获取函数表指针
4. Marshal.PtrToStructure解析CK_FUNCTION_LIST
5. 从函数表中解析所有函数指针为委托
6. 调用C_Initialize初始化库
```

### 4. 设备枚举流程

```
1. C_GetSlotList(FALSE, NULL, &count) 获取插槽数量
2. C_GetSlotList(FALSE, slots, &count) 获取插槽列表
3. 对每个slotID：
   - C_GetSlotInfo获取插槽信息
   - 检查CKF_TOKEN_PRESENT标志
   - C_GetTokenInfo获取Token信息
   - 构造UsbKeyDevice对象
4. 返回设备列表
```

### 5. 证书枚举流程

```
1. C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL, NULL, &session)
2. C_Login(session, CKU_USER, pin, pinLen)
3. 设置查找模板：CK_ATTRIBUTE[] = {
     {CKA_CLASS, CKO_CERTIFICATE}
   }
4. C_FindObjectsInit(session, template, templateCount)
5. C_FindObjects(session, objects, maxObjects, &foundCount)
6. 对每个object：
   - C_GetAttributeValue读取CKA_VALUE（证书DER数据）
   - C_GetAttributeValue读取CKA_LABEL（证书标签）
   - new X509Certificate2(derData)
   - 构造KeyContainer对象
7. C_FindObjectsFinal(session)
8. C_CloseSession(session)
```

### 6. 证书导入流程（PFX）

```
1. X509Certificate2 cert = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.Exportable)
2. 提取证书DER数据：cert.Export(X509ContentType.Cert)
3. 提取私钥：RSA rsa = cert.GetRSAPrivateKey()
4. 导出私钥参数：RSAParameters params = rsa.ExportParameters(true)
5. C_OpenSession + C_Login
6. 创建证书对象：
   CK_ATTRIBUTE[] certAttrs = {
     {CKA_CLASS, CKO_CERTIFICATE},
     {CKA_CERTIFICATE_TYPE, CKC_X_509},
     {CKA_VALUE, certDer},
     {CKA_LABEL, "cert label"},
     {CKA_TOKEN, TRUE}
   }
   C_CreateObject(session, certAttrs, &certHandle)
7. 创建私钥对象：
   CK_ATTRIBUTE[] keyAttrs = {
     {CKA_CLASS, CKO_PRIVATE_KEY},
     {CKA_KEY_TYPE, CKK_RSA},
     {CKA_MODULUS, params.Modulus},
     {CKA_PRIVATE_EXPONENT, params.D},
     {CKA_PRIME_1, params.P},
     {CKA_PRIME_2, params.Q},
     {CKA_EXPONENT_1, params.DP},
     {CKA_EXPONENT_2, params.DQ},
     {CKA_COEFFICIENT, params.InverseQ},
     {CKA_TOKEN, TRUE},
     {CKA_PRIVATE, TRUE},
     {CKA_SENSITIVE, TRUE}
   }
   C_CreateObject(session, keyAttrs, &keyHandle)
8. C_CloseSession
```

### 7. PIN管理流程

```
修改PIN：
1. C_OpenSession + C_Login(oldPin)
2. C_SetPIN(session, oldPin, newPin)
3. C_CloseSession

PUK解锁：
1. C_OpenSession
2. C_Login(session, CKU_SO, puk, pukLen)
3. C_InitPIN(session, newPin, newPinLen)
4. C_CloseSession
```

### 8. 设备初始化流程

```
1. C_InitToken(slotID, soPinUtf8, soPinLen, labelUtf8)
2. 设置SO PIN和设备标签
3. C_OpenSession + C_Login(CKU_SO, soPin)
4. C_InitPIN设置初始用户PIN
5. C_CloseSession
```

## 关键代码结构

### EPass3003Native.cs核心定义

```
// PKCS#11常量
public const uint CKR_OK = 0;
public const uint CKU_USER = 1;
public const uint CKU_SO = 0;
public const uint CKO_CERTIFICATE = 0x00000001;
public const uint CKO_PRIVATE_KEY = 0x00000003;
public const uint CKA_CLASS = 0x00000000;
public const uint CKA_VALUE = 0x00000011;
public const uint CKA_LABEL = 0x00000003;
public const uint CKK_RSA = 0x00000000;
public const uint CKM_RSA_PKCS = 0x00000001;

// 结构体
[StructLayout(LayoutKind.Sequential)]
public struct CK_VERSION {
    public byte major;
    public byte minor;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_INFO {
    public CK_VERSION cryptokiVersion;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] manufacturerID;
    public uint flags;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] libraryDescription;
    public CK_VERSION libraryVersion;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_SLOT_INFO {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] slotDescription;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] manufacturerID;
    public uint flags;
    public CK_VERSION hardwareVersion;
    public CK_VERSION firmwareVersion;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_TOKEN_INFO {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] label;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] manufacturerID;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] model;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] serialNumber;
    public uint flags;
    public uint ulMaxSessionCount;
    public uint ulSessionCount;
    public uint ulMaxRwSessionCount;
    public uint ulRwSessionCount;
    public uint ulMaxPinLen;
    public uint ulMinPinLen;
    public uint ulTotalPublicMemory;
    public uint ulFreePublicMemory;
    public uint ulTotalPrivateMemory;
    public uint ulFreePrivateMemory;
    public CK_VERSION hardwareVersion;
    public CK_VERSION firmwareVersion;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] utcTime;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_ATTRIBUTE {
    public uint type;
    public IntPtr pValue;
    public uint ulValueLen;
}

// 函数委托
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetFunctionList_t(out IntPtr ppFunctionList);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_Initialize_t(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_Finalize_t(IntPtr pReserved);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetSlotList_t(
    byte tokenPresent,
    IntPtr pSlotList,
    ref uint pulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetSlotInfo_t(
    uint slotID,
    IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetTokenInfo_t(
    uint slotID,
    IntPtr pInfo);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_OpenSession_t(
    uint slotID,
    uint flags,
    IntPtr pApplication,
    IntPtr Notify,
    ref uint phSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_CloseSession_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_Login_t(
    uint hSession,
    uint userType,
    byte[] pPin,
    uint ulPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_Logout_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_FindObjectsInit_t(
    uint hSession,
    IntPtr pTemplate,
    uint ulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_FindObjects_t(
    uint hSession,
    IntPtr phObject,
    uint ulMaxObjectCount,
    ref uint pulObjectCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_FindObjectsFinal_t(uint hSession);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetAttributeValue_t(
    uint hSession,
    uint hObject,
    IntPtr pTemplate,
    uint ulCount);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_CreateObject_t(
    uint hSession,
    IntPtr pTemplate,
    uint ulCount,
    ref uint phObject);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_DestroyObject_t(
    uint hSession,
    uint hObject);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_SetPIN_t(
    uint hSession,
    byte[] pOldPin,
    uint ulOldLen,
    byte[] pNewPin,
    uint ulNewLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_InitPIN_t(
    uint hSession,
    byte[] pPin,
    uint ulPinLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_InitToken_t(
    uint slotID,
    byte[] pPin,
    uint ulPinLen,
    byte[] pLabel);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GenerateKeyPair_t(
    uint hSession,
    IntPtr pMechanism,
    IntPtr pPublicKeyTemplate,
    uint ulPublicKeyAttributeCount,
    IntPtr pPrivateKeyTemplate,
    uint ulPrivateKeyAttributeCount,
    ref uint phPublicKey,
    ref uint phPrivateKey);
```

### EPass3003Provider.cs核心结构

```
public sealed class EPass3003Provider : IKeyProvider
{
    private NativeDll.Module? _module;
    private bool _initialized;
    
    // PKCS#11函数委托
    private C_Initialize_t? _C_Initialize;
    private C_Finalize_t? _C_Finalize;
    private C_GetSlotList_t? _C_GetSlotList;
    private C_OpenSession_t? _C_OpenSession;
    private C_Login_t? _C_Login;
    // ... 其他40+个函数
    
    public string PlatformName => "epass3003";
    
    public bool IsAvailable => LoadDll();
    
    public void Initialize() {
        if (_initialized) return;
        if (!LoadDll()) throw new Exception("无法加载HCCBCSP11.dll");
        LoadFunctions();
        CheckRv(_C_Initialize(IntPtr.Zero));
        _initialized = true;
    }
    
    private bool LoadDll() {
        if (_module != null) return true;
        string[] paths = GetDllPaths();
        foreach (var path in paths) {
            _module = NativeDll.Load(path);
            if (_module != null) return true;
        }
        return false;
    }
    
    private void LoadFunctions() {
        var getFunctionList = _module.GetDelegate<C_GetFunctionList_t>("C_GetFunctionList");
        IntPtr pFunctionList;
        CheckRv(getFunctionList(out pFunctionList));
        
        var functionList = Marshal.PtrToStructure<CK_FUNCTION_LIST>(pFunctionList);
        
        _C_Initialize = Marshal.GetDelegateForFunctionPointer<C_Initialize_t>(functionList.C_Initialize);
        _C_Finalize = Marshal.GetDelegateForFunctionPointer<C_Finalize_t>(functionList.C_Finalize);
        // ... 解析其他函数指针
    }
    
    public IReadOnlyList<UsbKeyDevice> Enumerate() {
        Initialize();
        
        uint count = 0;
        CheckRv(_C_GetSlotList(0, IntPtr.Zero, ref count));
        
        var slots = new uint[count];
        var slotsPtr = Marshal.AllocHGlobal((int)(count * 4));
        CheckRv(_C_GetSlotList(0, slotsPtr, ref count));
        Marshal.Copy(slotsPtr, (int[])slots, 0, (int)count);
        Marshal.FreeHGlobal(slotsPtr);
        
        var devices = new List<UsbKeyDevice>();
        for (int i = 0; i < count; i++) {
            var tokenInfo = GetTokenInfo(slots[i]);
            if (tokenInfo != null) {
                devices.Add(CreateDevice(slots[i], tokenInfo));
            }
        }
        
        return devices;
    }
    
    private void CheckRv(uint rv) {
        if (rv != CKR_OK) {
            throw new Exception($"PKCS#11错误: 0x{rv:X8}");
        }
    }
}
```

## 性能优化

1. 会话缓存：保持会话打开，避免频繁Open/Close
2. 批量属性查询：一次GetAttributeValue调用获取多个属性
3. 延迟初始化：只在首次使用时初始化PKCS#11库
4. 资源池：重用PKCS#11对象句柄

## 错误处理

1. PKCS#11返回值检查：所有函数调用后检查CK_RV
2. 错误码映射：将PKCS#11错误码映射为友好消息
3. 资源清理：使用try-finally确保会话和内存释放
4. 日志优化：只记录真正的异常，不记录正常的"未找到"情况

## 目录结构

```
Manager/src/USBKey.Core/UsbKey/
├── EPass3003Native.cs      [NEW] PKCS#11 P/Invoke声明（1000+行）
└── EPass3003Provider.cs    [REWRITE] 完全重写（800+行）
```

## 使用的扩展

### SubAgent

- **code-explorer**
- 目的：深入分析LncaProvider和LncaNative的DLL加载模式、P/Invoke声明模式、错误处理机制
- 预期结果：提取可复用的Native调用模式、委托声明模板、资源管理最佳实践