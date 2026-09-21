---
name: ePass3003-HZCA-Provider-Refactor
overview: 重构EPass3003Provider，使用PKCS#11接口直接调用HCCBCSP11.dll管理HZCA USB Key，替代错误的证书存储遍历方式
todos:
  - id: explore-lnca-pattern
    content: 使用 [subagent:code-explorer] 分析 LncaProvider 和 LncaNative 的实现模式，提取 DLL 加载、P/Invoke 声明、错误处理的最佳实践
    status: pending
  - id: create-native-bindings
    content: 创建 EPass3003Native.cs，实现 PKCS#11 标准接口的 P/Invoke 声明（常量、结构体、函数委托），参考 PKCS#11 v2.40 规范和 LncaNative 模式
    status: pending
    dependencies:
      - explore-lnca-pattern
  - id: rewrite-provider-init
    content: 重写 EPass3003Provider 的初始化逻辑，实现 DLL 加载（32/64位自动选择）和 C_GetFunctionList 调用
    status: pending
    dependencies:
      - create-native-bindings
  - id: implement-enumerate
    content: 实现设备枚举方法，通过 C_GetSlotList 和 C_GetSlotInfo 直接枚举 USB 设备，移除所有证书存储遍历代码
    status: pending
    dependencies:
      - rewrite-provider-init
  - id: implement-list-containers
    content: 实现证书列表方法，通过 C_OpenSession、C_FindObjects、C_GetAttributeValue 查询设备上的证书对象并转换为 X509Certificate2
    status: pending
    dependencies:
      - implement-enumerate
  - id: implement-core-operations
    content: 实现核心操作方法（Login、Logout、ExportCertificate、GetDetail），使用 PKCS#11 接口替代 CryptoAPI
    status: pending
    dependencies:
      - implement-list-containers
  - id: test-and-verify
    content: 测试验证功能完整性，确认无错误日志、设备枚举正常、证书列表准确、导出功能可用
    status: pending
    dependencies:
      - implement-core-operations
---

## 用户需求

重构 EPass3003Provider，使用 PKCS#11 接口直接调用 HCCBCSP11.dll 管理 HZCA USB Key，替代错误的证书存储遍历方式。

## 核心问题

当前实现完全错误：

1. 遍历系统所有证书存储查找 ePass3003 证书
2. 产生大量无用错误日志（每次枚举8-9个错误）
3. 性能低下且不准确
4. 依赖证书存储而不是真实设备

## 正确方案

通过逆向分析 HZBANK_certd3003.exe 发现：

- 使用 PKCS#11 标准接口（C_GetFunctionList）
- 动态加载 HCCBCSP11.dll
- 直接枚举 USB 设备和证书对象

## 实现目标

1. 像 LNCA Provider 一样通过 P/Invoke 调用 HCCBCSP11.dll
2. 使用 PKCS#11 标准接口枚举设备和证书
3. 消除所有证书存储遍历代码
4. 无错误日志，性能优秀
5. 支持设备枚举、证书列表、证书导出等核心功能

## 技术栈

- **语言**: C# (.NET 8)
- **平台**: Windows (x86/x64)
- **接口标准**: PKCS#11 v2.40
- **目标DLL**: HCCBCSP11.dll (32位/64位双版本)
- **参考实现**: LncaProvider

## 实现方案

### 1. PKCS#11 Native 声明

创建 `EPass3003Native.cs`，P/Invoke 声明 PKCS#11 函数：

```
// 核心函数
C_Initialize        // 初始化库
C_Finalize         // 清理库
C_GetSlotList      // 枚举插槽（设备）
C_GetSlotInfo      // 获取插槽信息
C_OpenSession      // 打开会话
C_CloseSession     // 关闭会话
C_Login            // PIN 登录
C_Logout           // 登出
C_FindObjectsInit  // 初始化对象查找
C_FindObjects      // 查找对象
C_FindObjectsFinal // 结束查找
C_GetAttributeValue // 获取对象属性
```

### 2. 设备枚举流程

```
1. C_Initialize() 初始化 PKCS#11 库
2. C_GetSlotList() 获取所有插槽（slotID）
3. C_GetSlotInfo() 获取插槽信息（判断是否有设备）
4. 返回设备列表（每个 slotID 对应一个设备）
```

### 3. 证书枚举流程

```
1. C_OpenSession() 打开会话（指定 slotID）
2. C_FindObjectsInit() 初始化查找（过滤条件：CKO_CERTIFICATE）
3. C_FindObjects() 查找所有证书对象
4. C_GetAttributeValue() 获取证书属性（CKA_VALUE 获取证书DER数据）
5. 解析为 X509Certificate2
6. C_FindObjectsFinal() 结束查找
7. C_CloseSession() 关闭会话
```

## 架构设计

### 模块划分

```
EPass3003Native.cs        - PKCS#11 P/Invoke 声明（结构体、常量、函数）
EPass3003Provider.cs      - IKeyProvider 实现（设备管理逻辑）
```

### 关键数据结构

```
// PKCS#11 标准结构
CK_C_INITIALIZE_ARGS      // 初始化参数
CK_SLOT_INFO             // 插槽信息
CK_SESSION_INFO          // 会话信息
CK_ATTRIBUTE             // 属性模板
CK_FUNCTION_LIST         // 函数表指针
```

### DLL 加载策略

```
// 优先级：
1. SysWOW64\HCCBCSP11.dll  (32位进程)
2. System32\HCCBCSP11.dll   (64位进程)
3. 环境变量 PATH 中的 HCCBCSP11.dll
```

## 实现细节

### 错误处理

- PKCS#11 函数返回 `CK_RV` 错误码
- `CKR_OK (0)` 表示成功
- 其他值表示错误，映射为异常消息

### 性能优化

1. 会话缓存：避免频繁 Open/Close
2. 属性批量查询：一次获取多个属性
3. 对象句柄复用：减少查找次数

### 日志优化

- 只记录真正的异常（PKCS#11 返回非 CKR_OK）
- 不记录正常的"未找到"情况
- Debug 级别记录详细调用信息

## 目录结构

```
Manager/src/USBKey.Core/UsbKey/
├── EPass3003Native.cs      [NEW] PKCS#11 P/Invoke 声明
└── EPass3003Provider.cs    [REWRITE] 完全重写，使用 PKCS#11
```

## 关键代码结构

### EPass3003Native.cs

```
// PKCS#11 常量
public const uint CKR_OK = 0;
public const uint CKO_CERTIFICATE = 0x00000001;
public const uint CKA_VALUE = 0x00000011;
public const uint CKA_LABEL = 0x00000003;

// 函数指针委托
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_Initialize_t(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetSlotList_t(bool tokenPresent, IntPtr pSlotList, ref uint pulCount);

// 函数表结构
[StructLayout(LayoutKind.Sequential)]
public struct CK_FUNCTION_LIST {
    public CK_VERSION version;
    public IntPtr C_Initialize;
    public IntPtr C_Finalize;
    // ... 其他函数指针
}
```

### EPass3003Provider 核心方法签名

```
private void LoadPKCS11Library();
private void InitializePKCS11();
private List<uint> GetSlotList();
private bool IsTokenPresent(uint slotID);
private IntPtr OpenSession(uint slotID);
private void CloseSession(IntPtr session);
private List<IntPtr> FindCertificateObjects(IntPtr session);
private byte[] GetCertificateData(IntPtr session, IntPtr certObject);
```

## 代码探索

- **code-explorer**
- 目的：深入分析 LncaProvider 和 LncaNative 的 DLL 加载、P/Invoke 声明、错误处理模式
- 预期结果：提取可复用的 Native 调用模式和错误处理机制

## 参考文档

- **Roadmap/05-LNCA逆向分析案例.md**：LNCA 的 DLL 调用实现经验
- **PKCS#11 v2.40 标准文档**：PKCS#11 接口定义和使用规范