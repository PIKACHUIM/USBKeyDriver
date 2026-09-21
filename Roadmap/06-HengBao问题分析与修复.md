# HengBao USB Key 问题分析与修复报告

> ## ⚠️ 重要更正（2026-09-20，已完成 IDA 逐函数复核）
>
> 本文件中 **“修复 2：更正 PKCS#11 调用约定（Cdecl → StdCall）” 的结论是错误的，已回退为 `Cdecl`**。
>
> 复核方法与证据（详见 [07-HengBao-U宝逆向分析.md](./07-HengBao-U宝逆向分析.md)）：
> 用 IDA Pro 8.3 解析 `CMBCp.dll` 的全部 68 个 `C_*` 导出（`E9 rel32` 跳转桩 → 真实实现），
> 逐个扫描函数尾的 `ret` 形式，结果为 **68/68 均为裸 `retn`（`__cdecl`）**，
> 只有 `DllMain` 是 `retn 0Ch`（`__stdcall`，3 参数）。
> 同样的检测对飞天 `HCCBCSP11.dll` 得到 `cdecl=68 stdcall=0 other=0`。
>
> 因此用 `StdCall` 委托调用 `Cdecl` 函数会造成**调用栈失衡**（每次调用 ESP 偏移 4×参数个数），
> 表现为返回随机错误码（例如 `C_OpenSession` 返回 `CKR_FUNCTION_FAILED(6)`）。
>
> 另外「枚举返回 0 个设备」还有两个同等重要的原因，均已在新版本中修正：
> 1. `C_GetSlotList` 返回的“槽位”实际是**设备路径字符串指针**（Win32 下 4 字节），
>    必须原样回传，不能当索引重建；
> 2. `C_GetSlotInfo` 是**硬编码**信息且恒返回 `CKR_OK`，只有 `C_GetTokenInfo` / `C_OpenSession`
>    才真正打开设备，因此**枚举时必须用 `C_GetTokenInfo` 过滤**。
>
> 本文件中的「修复 1：更正 DLL 路径配置」仍然有效（已保留在 `USBKey.Manager.csproj`）。

## 问题现象

恒宝（HengBao）民生银行 USB Key 驱动无法正常列出 USB 设备和进行管理操作。

## 根本原因分析

通过深入分析项目代码，发现了两个关键问题：

### 1. 路径配置错误

**文件**：`Manager/src/USBKey.Manager/USBKey.Manager.csproj`

**问题**：项目配置中复制 HengBao 库文件的源路径配置错误

```xml
<!-- 错误配置 -->
<None Include="..\..\..\Library\HengBao\*.dll" ... />
<None Include="..\..\..\Library\HengBao\*.ini" ... />
<None Include="..\..\..\Library\HengBao\*.sig" ... />
```

**实际路径**：`Library/HengBao USB Manage/`（包含空格）

**影响**：构建时无法将 `CMBCp.dll` 及其依赖文件复制到输出目录，导致运行时找不到 DLL。

### 2. PKCS#11 调用约定错误（核心问题）

**文件**：`Manager/src/USBKey.Core/UsbKey/CkmNative.cs`

**问题**：所有 PKCS#11 函数委托使用了错误的调用约定

```csharp
// 错误：使用 Cdecl 约定
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_InitializeFn(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint C_GetSlotListFn(byte tokenPresent, uint[] pSlotList, ref uint pulCount);
```

**技术背景**：

1. **PKCS#11 标准约定**：国际 PKCS#11 标准在 Windows 平台通常使用 `__stdcall` 调用约定
2. **中国厂商实现**：恒宝、飞天等中国 USB Key 厂商的 Windows DLL 实现均遵循 `__stdcall`
3. **项目中的证据**：
   - `GpIfdNative.cs`（飞天 IFD 接口）→ `CallingConvention.StdCall` ✓
   - `LncaHardApiNative.cs`（LNCA 硬件 API）→ `CallingConvention.StdCall` ✓
   - `CkmNative.cs`（PKCS#11 通用接口）→ `CallingConvention.Cdecl` ✗

**调用约定不匹配的后果**：

- 调用栈损坏（Stack corruption）
- 返回值错误或随机数据
- 函数调用失败但不报错
- 枚举设备返回 0 个设备
- 可能导致程序崩溃或内存访问违规

## 修复方案

### 修复 1：更正路径配置

**文件**：`Manager/src/USBKey.Manager/USBKey.Manager.csproj`

```xml
<!-- 修复后：正确的源路径，并增加缺失的文件类型 -->
<None Include="..\..\..\Library\HengBao USB Manage\*.dll" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
<None Include="..\..\..\Library\HengBao USB Manage\*.ini" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
<None Include="..\..\..\Library\HengBao USB Manage\*.sig" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
<None Include="..\..\..\Library\HengBao USB Manage\*.cer" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
<None Include="..\..\..\Library\HengBao USB Manage\*.h64" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
<None Include="..\..\..\Library\HengBao USB Manage\*.hbl" Link="Library\HengBao\%(Filename)%(Extension)" CopyToOutputDirectory="PreserveNewest" />
```

**说明**：
- 修正源路径为 `Library\HengBao USB Manage\`
- 增加 `.cer`、`.h64`、`.hbl` 等配置文件的复制规则
- 输出目标保持为 `Library\HengBao\`（简化路径，避免空格）

### 修复 2：更正 PKCS#11 调用约定

**文件**：`Manager/src/USBKey.Core/UsbKey/CkmNative.cs`

将所有 PKCS#11 函数委托的调用约定从 `Cdecl` 改为 `StdCall`：

```csharp
// 修复后：使用正确的 StdCall 约定
// 注意：中国 USB Key 厂商（恒宝、飞天等）的 Windows PKCS#11 实现使用 __stdcall 约定
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint C_InitializeFn(IntPtr pInitArgs);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint C_FinalizeFn(IntPtr pReserved);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint C_GetFunctionListFn(out IntPtr ppFunctionList);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint C_GetSlotListFn(byte tokenPresent, uint[] pSlotList, ref uint pulCount);

// ... 所有其他 PKCS#11 函数委托
```

**涉及的函数**（共 17 个）：
1. `C_InitializeFn`
2. `C_FinalizeFn`
3. `C_GetFunctionListFn`
4. `C_GetSlotListFn`
5. `C_GetTokenInfoFn`
6. `C_GetSlotInfoFn`
7. `C_OpenSessionFn`
8. `C_CloseSessionFn`
9. `C_LoginFn`
10. `C_LogoutFn`
11. `C_SetPINFn`
12. `C_InitPINFn`
13. `C_InitTokenFn`
14. `C_GetAttributeValueFn`
15. `C_FindObjectsInitFn`
16. `C_FindObjectsFn`
17. `C_FindObjectsFinalFn`
18. `C_CreateObjectFn`
19. `C_DestroyObjectFn`
20. `C_GenerateKeyPairFn`
21. `C_SignInitFn`
22. `C_SignFn`
23. `C_GetInfoFn`

## 影响范围

此修复影响所有使用 PKCS#11 标准接口的 USB Key 厂商：

1. **恒宝（HengBao）**：`HengBaoProvider.cs` → 使用 `CkmNative`
2. **飞天 ePass3003**：`EPass3003Provider.cs` → 使用 `CkmNative`
3. **未来其他 PKCS#11 设备**：任何基于标准 PKCS#11 的实现

**不影响**：
- LNCA：使用私有 API（`LncaNative.cs`），不使用 PKCS#11
- GP IFD：使用私有 IFD 接口（`GpIfdNative.cs`）

## 验证方法

修复后的验证步骤：

### 1. 重新编译
```powershell
cd g:\Codes\USBKeyDriver\Manager
dotnet clean
dotnet build --configuration Debug
```

### 2. 检查输出目录
确认 `bin\Debug\net8.0-windows\win-x86\Library\HengBao\` 目录下包含：
- `CMBCp.dll`（32位 PKCS#11 库）
- `CMBC.dll`、`CMBC64.dll` 等依赖库
- 配置文件（`.ini`、`.sig`、`.cer` 等）

### 3. 插入恒宝 USB Key 并运行
```powershell
.\bin\Debug\net8.0-windows\win-x86\USBKey.Manager.exe
```

### 4. 预期结果
- 控制台输出：`[HengBao] 尝试加载 DLL: ...`
- 控制台输出：`[HengBao] DLL 加载成功`
- `Enumerate()` 方法返回至少 1 个设备
- 设备信息包含正确的型号、序列号、固件版本

### 5. 测试功能
- 列出证书
- 登录（PIN 验证）
- 导入证书
- 导出证书
- 签名操作

## 技术总结

### 调用约定的重要性

Windows 平台的 P/Invoke 调用约定必须与 DLL 导出函数的实际约定完全匹配，否则会导致：

1. **栈不平衡**：
   - `__cdecl`：调用者清理栈（Caller cleanup）
   - `__stdcall`：被调用者清理栈（Callee cleanup）
   - 不匹配会导致栈指针错位，后续调用全部失败

2. **参数传递错误**：
   - 参数压栈顺序可能不同
   - 寄存器使用约定不同
   - 导致参数错位或丢失

3. **返回值损坏**：
   - 返回值寄存器（EAX/RAX）可能被污染
   - 读取到随机数据或错误值

### 调试技巧

1. **对比其他 Native 类**：同一项目中的其他 DLL 接口是最好的参考
2. **查看厂商文档**：PKCS#11 标准文档或厂商 SDK 文档
3. **使用工具**：`dumpbin /exports`（需 Visual Studio）或 `Dependencies.exe`
4. **逆向验证**：使用 IDA Pro 或 Ghidra 查看实际导出函数的调用约定

### 最佳实践

1. **统一约定**：同一厂商/标准的所有函数使用相同调用约定
2. **添加注释**：在代码中明确说明调用约定的选择理由
3. **参考实现**：优先参考厂商提供的 C/C++ 示例代码
4. **测试覆盖**：每个 Provider 都应有基本的枚举和初始化测试

## 修复日期

2026-08-26

## 相关文档

- [PKCS#11 标准文档](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11)
- [05-LNCA逆向分析案例.md](./05-LNCA逆向分析案例.md)
- 项目路径结构：`Roadmap/README.md`
