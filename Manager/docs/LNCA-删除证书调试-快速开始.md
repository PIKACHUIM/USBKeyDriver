# LNCA 删除证书功能调试 - 快速开始

## 背景

静态逆向发现 `JIT_USBKEY_HD.dll` 的 `USBKey_InitKey` 和 `USBKey_Reset` 是空壳函数（只打日志就返回 0）。真正的删除功能在底层 `HDCOS_LNCA.dll` 中，但参数签名未知。

## 两种调试方案

### 方案 A：静态逆向（已完成 ✓）

**结果**：JIT 层完全没有调用底层删除函数，无法从调用链推断参数。

**结论**：必须动态调试。

---

### 方案 B：动态调试（x64dbg + MCP）

**目标函数**（HDCOS_LNCA.dll）：
- `HD_ClearDir` — 清空目录
- `HD_DeleteCert` — 删除证书  
- `HD_DeleteContainer` — 删除容器
- `Clear_DF` — 清空 DF

**关键问题**：这些函数需要什么参数？`(void)` / `(int hDev)` / `(int hDev, int type)` / `(const char* path)` ？

---

## 快速调试步骤

### 1. 启动测试程序

```powershell
cd g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\_逆向分析\probe\LncaEraseTest\bin\Debug\net8.0-windows
.\LncaEraseTest.exe debug
```

程序会提示等待 x64dbg 附加。

---

### 2. 通过 AI 助手附加 x64dbg

```
请使用 x64dbg MCP 工具附加到 LncaEraseTest.exe 进程
```

AI 会调用：
```javascript
mcp_call_tool("x64dbg", "debug_attach_pid", {"pid": ...})
```

---

### 3. 在目标函数下断点

```
请在以下地址下断点：
- HDCOS_LNCA.HD_ClearDir
- HDCOS_LNCA.HD_DeleteCert  
- HDCOS_LNCA.HD_DeleteContainer
- HDCOS_LNCA.Clear_DF
```

---

### 4. 继续执行

在测试程序窗口按任意键，程序会依次调用测试函数。

---

### 5. 每次命中断点时记录

```
请读取断点处的参数：
- ESP+4（第一个参数）
- ESP+8（第二个参数）
并反汇编当前函数，查找 APDU 发送代码
```

AI 会调用：
```javascript
mcp_call_tool("x64dbg", "memory_read", {"address": "esp+4", "size": 8})
mcp_call_tool("x64dbg", "disassembly_function", {"address": "current"})
```

---

## 测试矩阵

程序会自动测试：

| 函数 | 测试 1 | 测试 2 |
|------|--------|--------|
| HD_ClearDir | 无参数 `()` | 传句柄 `(hDev)` |
| HD_DeleteCert | 传句柄 `(hDev)` | 传句柄+类型 `(hDev, 1)` |
| HD_DeleteContainer | 无参数 `()` | 传句柄 `(hDev)` |
| Clear_DF | 无参数 `()` | 传句柄 `(hDev)` |

每次调用后，程序会显示返回值，并在最后列出设备上的剩余证书。

---

## 预期输出示例

```
=== 测试 1: HD_ClearDir ===

[1.1] HD_ClearDir() 无参数
即将调用，x64dbg 应该断在函数入口...
  返回: 0x0

[1.2] HD_ClearDir(hDev) 传设备句柄
即将调用，观察参数...
  返回: 0x0

=== 最终检查 ===
调用 TestListCertificates 查看证书是否被删除...

[✓] 设备上的证书：
- 签名证书：CN=测试用户
- 加密证书：CN=测试用户
```

---

## 关键信息收集

对每个函数，需要确定：

### 1. 参数个数和类型

**通过栈内存**：
- 如果 `ESP+4` 是有效设备句柄（如 `0x00001234`），则至少有 1 个参数
- 如果 `ESP+8` 也有合理值，则至少有 2 个参数
- 通过 `ret imm16` 确认参数总大小（`ret 4` = 1 个 int，`ret 8` = 2 个 int）

### 2. APDU 命令

**在函数反汇编中查找**：
```asm
push 0x84        ; CLA
push 0xE4        ; INS (DELETE FILE)
push 0x00        ; P1
push 0x00        ; P2
call SendAPDU
cmp ax, 0x9000   ; 检查 SW
```

或查找对其他 HDCOS 函数的调用：
```asm
call HD_IC_RESET
call HD_SendData
```

### 3. 返回值语义

- `0x0` = 成功？
- `0x66` = 参数错误？（HD_HardAPI.dll 中索引越界返回 0x66）
- 其他值 = COS 错误码？

---

## 完成标准

调试完成后，应该能回答：

✅ `HD_ClearDir` 的准确签名：`int HD_ClearDir(?)` 

✅ `HD_DeleteCert` 的准确签名：`int HD_DeleteCert(?, ?)`

✅ `HD_DeleteContainer` 的准确签名：`int HD_DeleteContainer(?)`

✅ `Clear_DF` 的准确签名：`int Clear_DF(?)`

✅ 每个函数发送的 APDU 命令（CLA INS P1 P2）

✅ 返回值 0x0 / 非零 的含义

---

## 后续步骤

1. 更新 `LncaProvider.cs` 中的委托定义
2. 实现 `DeleteCertificate(device, certType)` 方法  
3. 实现 `ClearAllContainers(device)` 方法
4. 测试完整工作流：导入证书 → 签名 → 删除 → 确认删除

---

**重要提醒**：

> APDU 不会告诉你参数类型——它只是最终发送的字节流。  
> 函数签名必须通过**栈内存布局**和 `ret imm16` 反推，而不是 APDU 内容。

**示例**：
```c
// 即使函数内部发送相同的 APDU "84 E4 00 00"，
// 这三个签名在调用层是不同的：
int HD_DeleteCert(void);              // ret 0
int HD_DeleteCert(int hDev);          // ret 4
int HD_DeleteCert(int hDev, int type);// ret 8
```

只有通过栈内存和返回指令才能确定哪个是正确的。
