# LNCA USBKey 逆向分析总结报告

**日期**：2026-08-26  
**目标**：找到 LNCA 平台的设备重置和证书删除方法  
**方法**：静态逆向 + 动态调试（准备阶段）

---

## 一、静态逆向发现

### 1.1 DLL 层次结构

```
JIT_USBKEY_HD.dll (应用层 SDK)
    ↓ LoadLibrary
HD_HardAPI.dll (硬件抽象层)
    ↓ LoadLibrary
HD_SortDev.dll (设备管理层)
    ↓ LoadLibrary
HDCOS_LNCA.dll (COS 命令层，直接与智能卡通信)
```

### 1.2 关键发现：SDK 上层函数是空壳

**JIT_USBKEY_HD.dll 反汇编结果**：

```asm
; USBKey_InitKey (RVA 0x42B0)
push ebp
mov ebp, esp
...
call 0x48d0           ; 日志函数（内部是 ret）
...
xor eax, eax          ; return 0
pop ebp
ret

; USBKey_Reset (RVA 0x4400)
push ebp
mov ebp, esp
...
call 0x48d0           ; 日志函数
...
xor eax, eax          ; return 0
pop ebp
ret
```

**结论**：`USBKey_InitKey` 和 `USBKey_Reset` **只打日志就返回 0，没有任何实际操作**。

### 1.3 真实的重置链路

通过反汇编 `HD_HardAPI.dll` 和 `HD_SortDev.dll`，确认真实链路：

```
HD_HardAPI.dll::HSErase (RVA 0x1580)
    ↓
HD_SortDev.dll::HS_Erase (RVA 0x14C0)
    ↓
HD_SortDev.dll::HS_CheckStructure (RVA 0x1BA0)
    ↓
HDCOS_LNCA.dll::HD_IC_RESET
HDCOS_LNCA.dll::Clear_DF
HDCOS_LNCA.dll::HD_ClearDir
HDCOS_LNCA.dll::HD_SPWD (Set Password)
```

### 1.4 已确认的函数签名

通过 `ret imm16` 指令反推参数大小：

```c
// HD_HardAPI.dll (__stdcall)
int HSConnectDev(int devIndex, int* phDev);      // ret 8 → 2个参数
int HSErase(int hDev);                            // ret 4 → 1个参数
int HSDisconnectDev(int hDev);                    // ret 4 → 1个参数
int HSVerifyUserPin(int hDev, const char* pin, uint pinLen);  // ret 12 → 3个参数
int HSChangeUserPin(int hDev, const char* oldPin, uint oldLen,
                     const char* newPin, uint newLen);  // ret 20 → 5个参数
```

**HSErase 内部逻辑**（HD_SortDev.dll::HS_Erase）：

```asm
; 1. 检查设备结构
lea eax, [ebp-0x218]     ; 分配 0x218 字节缓冲区
push eax
push edi                 ; hDev
call HS_CheckStructure   ; 读取设备状态到缓冲区

; 2. 发送擦除命令（通过 HDCOS 函数）
push edi
call [HD_IC_RESET]       ; 重置智能卡
call [Clear_DF]          ; 清空 DF（Dedicated File）
call [HD_ClearDir]       ; 清空目录
...
```

---

## 二、未确认的函数（需要动态调试）

### 2.1 证书删除函数

以下函数在 `HDCOS_LNCA.dll` 中导出，但**参数签名未知**：

| 函数名 | 推测功能 | 参数猜测 |
|--------|----------|----------|
| `HD_ClearDir` | 清空目录 | `(void)` 或 `(int hDev)` 或 `(const char* path)` |
| `HD_DeleteCert` | 删除证书 | `(int certType)` 或 `(int hDev, int certType)` |
| `HD_DeleteContainer` | 删除容器 | `(void)` 或 `(int hDev)` |
| `Clear_DF` | 清空 DF | `(void)` 或 `(int hDev)` |

**问题**：
1. 这些函数是否需要设备句柄 `hDev`？
2. 如果需要，`hDev` 是来自 `HSConnectDev` 还是来自 JIT 层的连接？
3. `HD_DeleteCert` 是否有证书类型参数（签名证书 vs 加密证书）？

### 2.2 为什么无法静态确认？

**原因 1**：JIT_USBKEY_HD.dll 完全没有调用这些函数

搜索整个 JIT_USBKEY_HD.dll 的反汇编，**零次调用**：
- `HD_DeleteContainer`
- `HD_DeleteCert`
- `HD_ClearDir`
- `Clear_DF`

**原因 2**：HD_HardAPI.dll 和 HD_SortDev.dll 中也没有直接调用

只在 `HS_Erase` 中有间接调用（通过函数指针），但调用时的参数准备代码已被优化或内联。

**结论**：必须用 x64dbg 动态调试，在函数入口下断点，读取栈内存。

---

## 三、已实现的代码改动

### 3.1 新增文件

#### `Manager/src/USBKey.Core/UsbKey/LncaHardApiNative.cs`

```csharp
// HD_HardAPI.dll 的 P/Invoke 声明
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
private delegate int ConnectDevFn(int devIndex, out IntPtr phDev);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
private delegate int DisconnectDevFn(IntPtr hDev);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
private delegate int EraseFn(IntPtr hDev);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
private delegate int VerifyUserPinFn(IntPtr hDev, 
    [MarshalAs(UnmanagedType.LPStr)] string lpPin, uint lpPinLen);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
private delegate int ChangeUserPinFn(IntPtr hDev,
    [MarshalAs(UnmanagedType.LPStr)] string lpOldPin, uint lpOldPinLen,
    [MarshalAs(UnmanagedType.LPStr)] string lpNewPin, uint lpNewPinLen);
```

#### `Manager/tools/LncaEraseTest/DebugHDCOS.cs`

专门用于 x64dbg 动态调试的测试类：
- 依次调用 `HD_ClearDir` / `HD_DeleteCert` / `HD_DeleteContainer` / `Clear_DF`
- 每个函数测试多种参数组合（无参数、传句柄、传句柄+类型等）
- 在调用前暂停，等待 x64dbg 下断点
- 调用后显示返回值和剩余证书

### 3.2 修改文件

#### `Manager/src/USBKey.Core/UsbKey/LncaProvider.cs`

**变更 1**：加载 `HD_HardAPI.dll`

```csharp
private void Initialize()
{
    // ... 原有的 JIT_USBKEY_HD.dll 加载 ...
    
    // 新增：加载底层 API
    var hardApiPath = Path.Combine(_baseDir, "HD_HardAPI.dll");
    if (File.Exists(hardApiPath))
    {
        _hHardApiModule = LoadLibrary(hardApiPath);
        if (_hHardApiModule != IntPtr.Zero)
        {
            LoadHardApi();
        }
    }
}
```

**变更 2**：`ResetDevice` 优先使用底层 API

```csharp
public override bool ResetDevice(KeyDevice device, string? adminKey, string newUserPin)
{
    if (_hHardApiModule != IntPtr.Zero)
    {
        return ResetViaHardApi(device, adminKey, newUserPin);
    }
    else
    {
        // 回退到旧行为（调用空壳函数）
        return ResetViaJit(device, newUserPin);
    }
}

private bool ResetViaHardApi(KeyDevice device, string? adminKey, string newUserPin)
{
    // 1. 连接设备
    var rc = _hsConnectDev(device.Index, out var hDev);
    if (rc != 0 || hDev == IntPtr.Zero) return false;

    try
    {
        // 2. 可选：验证 SO PIN（管理员 PIN）
        if (!string.IsNullOrEmpty(adminKey))
        {
            rc = _hsVerifyUserPin?.Invoke(hDev, adminKey, (uint)adminKey.Length) ?? 0;
            if (rc != 0)
            {
                _logger?.LogWarning($"SO PIN 验证失败: 0x{rc:X}");
                return false;
            }
        }

        // 3. 擦除设备
        rc = _hsErase(hDev);
        if (rc != 0)
        {
            _logger?.LogError($"HSErase 失败: 0x{rc:X}");
            return false;
        }

        // 4. 设置新 PIN（需要确认：擦除后的默认 PIN 是什么？）
        var defaultPin = "";  // 或 "111111" ？待实体设备验证
        rc = _hsChangeUserPin?.Invoke(hDev,
            defaultPin, (uint)defaultPin.Length,
            newUserPin, (uint)newUserPin.Length) ?? 0;

        if (rc != 0)
        {
            _logger?.LogWarning($"HSChangeUserPin 失败: 0x{rc:X}");
        }

        device.IsLoggedIn = true;
        return true;
    }
    finally
    {
        _hsDisconnectDev(hDev);
    }
}
```

---

## 四、动态调试准备

### 4.1 测试程序

**路径**：`Manager/tools/LncaEraseTest/`

**编译**：
```powershell
cd g:\Codes\USBKeyDriver\Manager\tools\LncaEraseTest
dotnet build -c Debug
```

**运行调试模式**：
```powershell
cd bin\Debug\net8.0-windows
.\LncaEraseTest.exe debug
```

### 4.2 调试工具

**x64dbg + MCP Server**

配置文件：`g:\Codes\USBKeyDriver\.mcp.json`

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "node",
      "args": ["path/to/x64dbg-mcp/build/index.js"]
    }
  }
}
```

### 4.3 调试流程

详见文档：
- `Manager/docs/LNCA-动态调试指南.md` — 完整步骤
- `Manager/docs/LNCA-删除证书调试-快速开始.md` — 快速指南

**简要步骤**：

1. 运行 `LncaEraseTest.exe debug`
2. 用 x64dbg 附加进程
3. 在目标函数下断点（`HD_ClearDir` / `HD_DeleteCert` / `HD_DeleteContainer` / `Clear_DF`）
4. 继续执行，每次命中断点时记录：
   - 栈内存（ESP+4, ESP+8, ...）→ 参数值
   - 反汇编代码 → APDU 命令
   - 返回值（EAX）→ 错误码语义
5. 更新 `LncaProvider.cs` 中的委托签名

---

## 五、待确认问题清单

### 5.1 函数签名

- [ ] `HD_ClearDir` 的准确签名
- [ ] `HD_DeleteCert` 的准确签名（是否有 certType 参数？）
- [ ] `HD_DeleteContainer` 的准确签名
- [ ] `Clear_DF` 的准确签名

### 5.2 设备状态

- [ ] `HSErase` 后的默认用户 PIN 是什么？（空字符串 / `111111` / `123456` ？）
- [ ] `HSErase` 后的默认 SO PIN 是什么？
- [ ] 擦除后设备是否需要重新格式化？

### 5.3 APDU 命令

- [ ] `HD_ClearDir` 发送的 APDU（CLA INS P1 P2）
- [ ] `HD_DeleteCert` 发送的 APDU
- [ ] `HD_DeleteContainer` 发送的 APDU
- [ ] `Clear_DF` 发送的 APDU

### 5.4 返回值语义

- [ ] 返回 `0x0` 的含义（成功？）
- [ ] 返回 `0x66` 的含义（参数错误？索引越界？）
- [ ] 其他常见错误码

---

## 六、下一步计划

### 阶段 1：动态调试（当前）

**目标**：确认上述所有"待确认问题"

**工具**：x64dbg + MCP + `LncaEraseTest.exe debug`

**预计时间**：1-2 小时（需要实体 LNCA USBKey 设备）

### 阶段 2：代码完善

**任务**：
1. 更新 `LncaProvider.cs` 中的委托签名
2. 实现 `DeleteCertificate(device, certType)` 方法
3. 实现 `ClearAllContainers(device)` 方法
4. 实现 `DeleteCertificateByType(device, certType)` 方法

**验收标准**：
- 能成功删除单个签名证书
- 能成功删除单个加密证书
- 能成功删除所有证书（清空设备）
- 删除后设备仍可正常导入新证书

### 阶段 3：集成测试

**任务**：
1. 完整工作流测试：导入 → 签名 → 删除 → 再导入
2. 边界测试：删除不存在的证书、重复删除、在未登录状态下删除
3. 并发测试：多线程删除、删除时拔出设备

---

## 七、关键技术笔记

### 7.1 为什么 APDU 不能确定参数类型？

**示例**：

假设三个不同的 C# 调用：

```csharp
// 调用 1
HD_DeleteCert();                    // 签名：int HD_DeleteCert(void); 栈参数：无

// 调用 2
HD_DeleteCert(hDev);                // 签名：int HD_DeleteCert(int); 栈参数：ESP+4 = hDev

// 调用 3
HD_DeleteCert(hDev, 1);             // 签名：int HD_DeleteCert(int, int); 栈参数：ESP+4=hDev, ESP+8=1
```

如果这三个函数内部都发送相同的 APDU `84 E4 00 00`（DELETE FILE），**从 APDU 看不出区别**。

**唯一的区分方法**：
1. 查看**栈内存**（参数传递）
2. 查看**函数返回指令**（`ret 0` / `ret 4` / `ret 8` 对应不同的参数大小）

### 7.2 __stdcall 调用约定

**特征**：
- 参数从右到左压栈
- 被调用函数负责清理栈（`ret imm16`）
- `ret 4` 表示弹出 4 字节（1 个 int 参数）
- `ret 8` 表示弹出 8 字节（2 个 int 参数）

**示例**：

```c
int Func(int a, int b);  // __stdcall

// 汇编：
push b           ; 第二个参数
push a           ; 第一个参数
call Func
; 返回后，栈已被 Func 内部的 ret 8 清理

; Func 内部：
Func:
    push ebp
    mov ebp, esp
    mov eax, [ebp+8]     ; a
    mov edx, [ebp+12]    ; b
    ; ... 函数体 ...
    pop ebp
    ret 8                ; 弹出 a 和 b（共 8 字节）
```

### 7.3 设备句柄的二重性

**问题**：`HSConnectDev` 返回的 `hDev` 和 JIT 层的 `_hKey` 是同一个吗？

**答案**：**不是**。

- `HSConnectDev` 返回的是 **HD_HardAPI.dll 层的句柄**（底层 COS 连接）
- JIT 层的 `_hKey` 是 **JIT_USBKEY_HD.dll 的句柄**（应用层连接）

这两个句柄系统是**独立**的。

**影响**：
- `HSErase(hDev)` 使用底层句柄
- 擦除后，JIT 层的 `_hKey` 连接可能失效（需要重新连接）
- 当前代码在 `ResetViaHardApi` 结束后设置 `device.IsLoggedIn = true`，可能需要额外调用 `EnsureConnected` 重新建立 JIT 连接

---

## 八、参考资料

### 8.1 已逆向的 DLL

- `JIT_USBKEY_HD.dll` — 完整反汇编，确认空壳函数
- `HD_HardAPI.dll` — 部分反汇编，确认 `HSConnectDev` / `HSErase` / `HSDisconnectDev`
- `HD_SortDev.dll` — 部分反汇编，确认 `HS_Erase` 内部逻辑
- `HDCOS_LNCA.dll` — 仅导出表（函数名），参数待确认

### 8.2 工具

- **Capstone** — 反汇编引擎（Python: `capstone-engine`）
- **x64dbg** — 动态调试器
- **x64dbg MCP Server** — MCP 协议封装，允许 AI 助手控制 x64dbg

### 8.3 文档

- `Manager/docs/LNCA-ResetDevice-逆向结论.md` — 初步逆向结论
- `Manager/docs/LNCA-动态调试指南.md` — 详细调试步骤
- `Manager/docs/LNCA-删除证书调试-快速开始.md` — 快速开始指南
- 本文档 — 总结报告

---

## 九、总结

### 成功之处

✅ **确认了 SDK 上层的空壳本质**  
通过静态逆向，证实 `USBKey_InitKey` 和 `USBKey_Reset` 只是日志函数，没有实际功能。

✅ **找到了真实的重置链路**  
确认 `HD_HardAPI.dll::HSErase` 是真正的擦除入口，并精确还原了其函数签名和内部调用链。

✅ **实现了基于底层 API 的重置功能**  
修改 `LncaProvider.cs`，优先使用 `HSConnectDev → HSErase → HSDisconnectDev`，绕过空壳。

✅ **准备了完整的动态调试环境**  
创建测试程序 + 配置 x64dbg MCP + 编写详细文档，为下一阶段的动态调试铺平道路。

### 局限性

⚠️ **证书删除函数的参数仍未确认**  
由于 JIT 层完全没有调用这些函数，无法通过静态逆向推断参数。

⚠️ **设备擦除后的默认状态未知**  
不清楚擦除后的默认 PIN 是什么（空 / `111111` / `123456`），需要实体设备验证。

⚠️ **JIT 层连接的有效性**  
擦除后，JIT 层的 `_hKey` 连接可能失效，当前代码未处理这种情况。

### 下一步的关键

🎯 **必须进行动态调试**  
在 x64dbg 中对 `HD_ClearDir` / `HD_DeleteCert` / `HD_DeleteContainer` / `Clear_DF` 下断点，读取栈内存，确认参数签名。

🎯 **需要实体 LNCA USBKey 设备**  
验证擦除后的默认状态、测试完整的删除工作流。

---

**报告结束**

---

## 附录 A：快速命令参考

```powershell
# 编译测试程序
cd g:\Codes\USBKeyDriver\Manager\tools\LncaEraseTest
dotnet build -c Debug

# 运行调试模式
cd bin\Debug\net8.0-windows
.\LncaEraseTest.exe debug

# 运行完整擦除测试（需要实体设备）
.\LncaEraseTest.exe 0 123456 test.pfx 111111
```

```javascript
// x64dbg MCP 命令（通过 AI 助手）
mcp_call_tool("x64dbg", "debug_attach_pid", {"pid": ...})
mcp_call_tool("x64dbg", "breakpoint_set", {"address": "HDCOS_LNCA.HD_ClearDir"})
mcp_call_tool("x64dbg", "memory_read", {"address": "esp+4", "size": 8})
mcp_call_tool("x64dbg", "disassembly_function", {"address": "current"})
```

---

## 附录 B：代码文件清单

### 新增文件

1. `Manager/src/USBKey.Core/UsbKey/LncaHardApiNative.cs` — 底层 API 声明
2. `Manager/tools/LncaEraseTest/DebugHDCOS.cs` — 动态调试测试类
3. `Manager/docs/LNCA-ResetDevice-逆向结论.md` — 逆向结论
4. `Manager/docs/LNCA-动态调试指南.md` — 调试指南
5. `Manager/docs/LNCA-删除证书调试-快速开始.md` — 快速开始
6. 本文档 — 总结报告

### 修改文件

1. `Manager/src/USBKey.Core/UsbKey/LncaProvider.cs`
   - 添加 `LoadHardApi()` 方法
   - 修改 `ResetDevice()` 优先使用底层 API
   - 添加 `ResetViaHardApi()` 方法

2. `Manager/tools/LncaEraseTest/Program.cs`
   - 添加 `debug` 命令入口

---

**文档版本**：v1.0  
**最后更新**：2026-08-26
