# LNCA USBKey 动态调试指南

## 目标

通过 **x64dbg** + **MCP 工具**动态调试 `HDCOS_LNCA.dll`，确定以下函数的准确签名：

- `HD_ClearDir` — 清空目录
- `HD_DeleteCert` — 删除证书
- `HD_DeleteContainer` — 删除容器
- `Clear_DF` — 清空 DF（Dedicated File）

由于静态逆向发现 JIT_USBKEY_HD.dll 完全没有调用这些底层函数，必须通过动态调试确认参数。

---

## 前置条件

### 1. x64dbg MCP Server 已配置

确保 `.mcp.json` 中已包含 x64dbg MCP 配置：

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

### 2. 测试程序已编译

```powershell
cd g:\Codes\USBKeyDriver\Manager\tools\LncaEraseTest
dotnet build -c Debug
```

---

## 调试步骤

### 第一阶段：启动 x64dbg 并附加进程

#### 1. 运行测试程序（调试模式）

```powershell
cd g:\Codes\USBKeyDriver\Manager\tools\LncaEraseTest\bin\Debug\net8.0-windows
.\LncaEraseTest.exe debug
```

程序会输出：

```
=== x64dbg 动态调试准备 ===

📌 建议操作：
   1. 用 x64dbg 附加到本进程
   2. 在以下地址下断点：
      - HDCOS_LNCA.HD_ClearDir
      - HDCOS_LNCA.HD_DeleteCert
      - HDCOS_LNCA.HD_DeleteContainer
      - HDCOS_LNCA.Clear_DF
   3. 按任意键继续，程序会依次调用这些函数
   4. 在 x64dbg 中观察参数和返回值

✓ DLL 加载成功

等待 x64dbg 附加...
附加后按任意键继续...
```

#### 2. 用 x64dbg 附加进程

在另一个终端或通过 AI 助手使用 MCP 工具：

```javascript
// 通过 MCP 调用 x64dbg
mcp_call_tool("x64dbg", "debug_attach_pid", {
  "pid": <LncaEraseTest.exe 的进程 ID>
})
```

或手动启动 x64dbg：

```powershell
x64dbg.exe -a <LncaEraseTest.exe 进程 ID>
```

---

### 第二阶段：下断点

#### 方法 A：使用 MCP 工具

```javascript
// 在 HD_ClearDir 下断点
mcp_call_tool("x64dbg", "breakpoint_set", {
  "address": "HDCOS_LNCA.HD_ClearDir"
})

// 在 HD_DeleteCert 下断点
mcp_call_tool("x64dbg", "breakpoint_set", {
  "address": "HDCOS_LNCA.HD_DeleteCert"
})

// 在 HD_DeleteContainer 下断点
mcp_call_tool("x64dbg", "breakpoint_set", {
  "address": "HDCOS_LNCA.HD_DeleteContainer"
})

// 在 Clear_DF 下断点
mcp_call_tool("x64dbg", "breakpoint_set", {
  "address": "HDCOS_LNCA.Clear_DF"
})
```

#### 方法 B：x64dbg 命令行

在 x64dbg 命令窗口输入：

```
bp HDCOS_LNCA.HD_ClearDir
bp HDCOS_LNCA.HD_DeleteCert
bp HDCOS_LNCA.HD_DeleteContainer
bp HDCOS_LNCA.Clear_DF
```

---

### 第三阶段：继续执行并观察参数

#### 1. 在测试程序窗口按任意键

程序会开始依次调用测试函数。

#### 2. 每次命中断点时，记录参数

**关键寄存器（x86 stdcall）：**

- **ESP+4** = 第一个参数
- **ESP+8** = 第二个参数
- **ESP+12** = 第三个参数
- ...

**使用 MCP 工具查看寄存器：**

```javascript
// 获取寄存器值
mcp_call_tool("x64dbg", "register_get_batch", {
  "names": ["esp", "eax", "ecx", "edx"]
})

// 读取栈内存（参数）
mcp_call_tool("x64dbg", "memory_read", {
  "address": "<ESP+4 的值>",
  "size": 16
})
```

**x64dbg 命令行：**

```
// 查看前 4 个参数
dd esp L4

// 查看寄存器
r
```

#### 3. 单步执行并观察 APDU

**关键：在函数内部找到 APDU 发送点**

使用 MCP 工具反汇编函数：

```javascript
mcp_call_tool("x64dbg", "disassembly_function", {
  "address": "HDCOS_LNCA.HD_ClearDir"
})
```

在反汇编中查找：

- `call HD_IC_RESET` 或类似的 COS 函数
- `84 00 00 00` 等 APDU 特征字节
- SW 状态码检查（如 `cmp ax, 0x9000`）

#### 4. 记录返回值

每个函数返回后，查看 `EAX` 寄存器：

```javascript
mcp_call_tool("x64dbg", "register_get", {
  "name": "eax"
})
```

---

## 测试用例矩阵

程序会依次测试以下调用：

| 测试 | 函数 | 参数假设 | 预期行为 |
|------|------|----------|---------|
| 1.1 | `HD_ClearDir()` | 无参数 | 可能需要先选择 DF |
| 1.2 | `HD_ClearDir(hDev)` | 设备句柄 | 清空当前 DF |
| 2.1 | `HD_DeleteCert(hDev)` | 设备句柄 | 删除默认证书 |
| 2.2 | `HD_DeleteCert(hDev, 1)` | 句柄 + 类型 | 删除加密证书（Type=1） |
| 3.1 | `HD_DeleteContainer()` | 无参数 | 删除默认容器 |
| 3.2 | `HD_DeleteContainer(hDev)` | 设备句柄 | 删除容器 |
| 4.1 | `Clear_DF()` | 无参数 | 清空默认 DF |
| 4.2 | `Clear_DF(hDev)` | 设备句柄 | 清空 DF |

---

## 预期发现

### APDU 命令

根据 ISO 7816 标准和国密 COS 规范，删除操作可能使用以下 APDU：

| 命令 | CLA | INS | P1 | P2 | 说明 |
|------|-----|-----|----|----|------|
| DELETE FILE | 80/84 | E4 | 00 | 00 | 删除当前文件 |
| ERASE BINARY | 80 | 0E | 00 | 00 | 擦除二进制文件内容 |
| INITIALIZE | 80 | 50 | 00 | 00 | 初始化应用 |

### 参数签名

预期的函数签名（待确认）：

```c
// 假设 1：需要句柄
int HD_ClearDir(int hDev);
int HD_DeleteCert(int hDev, int certType);
int HD_DeleteContainer(int hDev);
int Clear_DF(int hDev);

// 假设 2：无需句柄（内部维护全局状态）
int HD_ClearDir(void);
int HD_DeleteCert(int certType);
int HD_DeleteContainer(void);
int Clear_DF(void);

// 假设 3：需要 DF 路径
int HD_ClearDir(int hDev, const char* dfPath);
int Clear_DF(const char* dfPath);
```

---

## 调试记录模板

请在调试过程中记录以下信息：

```markdown
### HD_ClearDir

**测试 1.1**（无参数）：
- 断点命中：是 / 否
- ESP+4 值：
- 函数内观察到的 APDU：
- 返回值（EAX）：
- 行为：

**测试 1.2**（hDev）：
- ESP+4 值（hDev）：0x________
- 函数内观察到的 APDU：
  - CLA INS P1 P2 Lc Data
- 返回值（EAX）：0x________
- 行为：

---

### HD_DeleteCert

（重复上述格式）

---

### HD_DeleteContainer

（重复上述格式）

---

### Clear_DF

（重复上述格式）
```

---

## 故障排除

### 问题 1：断点未命中

**原因**：函数名可能有装饰（name mangling）

**解决**：

```javascript
// 列出 HDCOS_LNCA.dll 的所有导出
mcp_call_tool("x64dbg", "module_get_exports", {
  "module": "HDCOS_LNCA"
})
```

然后用实际导出名下断点（如 `_HD_ClearDir@4`）。

### 问题 2：参数值看起来异常

**原因**：可能读取了错误的栈位置

**解决**：

1. 确认函数序言（prologue）：
   ```asm
   push ebp
   mov ebp, esp
   ```
   
2. 如果有序言，参数在 `EBP+8`、`EBP+12` 等位置

3. 如果无序言，参数在 `ESP+4`、`ESP+8` 等位置

### 问题 3：APDU 不可见

**原因**：APDU 发送在更底层

**解决**：

1. 在 `HD_IC_RESET` / `HD_SendAPDU` 等函数下断点
2. 或在 `DeviceIoControl` 下断点（智能卡驱动层）

---

## 下一步

调试完成后：

1. 更新 `LncaProvider.cs` 中的委托签名
2. 实现 `DeleteCertificate` / `ClearContainer` 等方法
3. 测试完整的"删除证书"工作流

---

**关键提醒**：APDU 不会"知道"参数序列——它只看到最终的字节流。函数签名必须通过**栈内存布局**确定，而不是 APDU 内容。
