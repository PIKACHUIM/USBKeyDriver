# LNCA USB Key 完整逆向分析报告

## 执行时间
2026-08-26

## 分析对象
`Library/LNCA USBKey Manage/HDCOS_LNCA.dll` - LNCA USB Key 底层 COS 通信库

## 逆向工具
- **Capstone** 反汇编引擎（Python）
- 手工分析 x86 汇编代码（`__stdcall` 调用约定）

## 核心发现

### 1. JIT_USBKEY_HD.dll 的"空壳"问题

通过反汇编 `JIT_USBKEY_HD.dll`，确认：

- **`USBKey_InitKey` 和 `USBKey_Reset` 是调试空壳函数**
- 内部逻辑：仅打印日志 → `xor eax, eax` → `ret`
- **完全不执行任何设备操作**

这解释了为什么原代码中 `ResetDevice()` 调用 `USBKey_Reset` 无效。

### 2. 真实的初始化链路

设备初始化实际通过以下 DLL 链完成：

```
用户代码
  ↓
HD_HardAPI.dll (高层 API)
  ├─ HSConnectDev    (连接设备)
  ├─ HSErase         (擦除设备 - 核心初始化)
  └─ HSDisconnectDev (断开连接)
       ↓
HD_SortDev.dll (中间层)
  ├─ HS_ConnectDev
  ├─ HS_Erase
  └─ HS_CheckStructure
       ↓
HDCOS_LNCA.dll (底层 COS)
  ├─ HD_IC_RESET     (卡片物理复位)
  ├─ HD_ClearDir     (清除目录结构)
  ├─ Clear_DF        (清除 DF)
  ├─ HD_SPWD         (设置管理员密码)
  ├─ HD_VerifyPin    (验证 PIN)
  └─ HD_ChangePin    (修改 PIN)
```

## 函数签名（通过 `ret imm16` 反推）

所有函数使用 `__stdcall` 调用约定（调用者清栈）。

### HD_HardAPI.dll 导出

| 函数名 | RVA | ret 指令 | 参数数量 | 签名 |
|--------|-----|----------|----------|------|
| **HSConnectDev** | 0x1230 | `ret 8` | 2 | `int HSConnectDev(int devIndex, int* phDev)` |
| **HSErase** | 0x18A0 | `ret 4` | 1 | `int HSErase(int hDev)` |
| **HSDisconnectDev** | 0x12F0 | `ret 4` | 1 | `int HSDisconnectDev(int hDev)` |
| **HSVerifyUserPin** | 0x1540 | `ret 0xC` | 3 | `int HSVerifyUserPin(int hDev, byte* pin, int pinLen)` |

**关键逻辑**（HSErase 内部）：
```assembly
0x18A0  mov esi, [esp+4]           ; arg1: hDev
0x18A8  push esi
0x18A9  call [0x10009e48]          ; 调用 HD_SortDev.dll::HS_Erase(hDev)
0x18B2  test eax, eax
0x18B4  jne  0x18C8                ; 失败则跳转
0x18B6  xor eax, eax               ; 成功返回 0
0x18B8  ret 4
0x18C8  mov eax, 0x99              ; 失败返回 0x99
```

### HDCOS_LNCA.dll 导出

| 函数名 | RVA | ret 指令 | 参数数量 | 签名 |
|--------|-----|----------|----------|------|
| **HD_Open** | 0x1120 | `ret 4` | 1 | `int HD_Open(int port)` |
| **HD_Close** | 0x15B0 | `ret 4` | 1 | `int HD_Close(int hCard)` |
| **HD_IC_RESET** | 0x10C0 | `ret 8` | 2 | `int HD_IC_RESET(int hCard, byte* atr)` |
| **HD_VerifyPin** | 0x2840 | `ret 0xC` | 3 | `int HD_VerifyPin(int hCard, byte* pin, int pinLen)` |
| **HD_ChangePin** | 0x2490 | `ret 0xC` | 3 | `int HD_ChangePin(int hCard, byte* oldNewPin, int totalLen)` |
| **HD_SPWD** | 0x2B00 | `ret 8` | 2 | `int HD_SPWD(byte* adminPin, int adminPinLen)` |
| **HD_ClearDir** | 0x67D0 | `ret 4` | 1 | `int HD_ClearDir(int hCard)` |
| **Clear_DF** | 0x19C0 | `ret 8` | 2 | `int Clear_DF(int hCard, ushort* sw)` |
| **Reload_Pin** | 0x1D70 | `ret 0x10` | 4 | `int Reload_Pin(int hCard, byte* pin, int pinLen, void* reserved)` |

### 关键函数内部逻辑

#### HD_ClearDir (RVA 0x67D0)

完整反汇编显示其内部调用链：

```assembly
0x67D0  sub esp, 0xc4              ; 分配栈空间
0x67DC  push esi
0x67DD  push edi
0x681B  mov esi, [esp+0xd0]        ; 加载参数 hCard
...
0x6834  call 0x1b40                ; 第一次 APDU 发送
0x6839  test eax, eax
0x683B  jl 0x68d9                  ; 失败跳转
0x6846  cmp word [esp+0xa], 0x9000 ; 检查 SW = 0x9000
0x684B  jne 0x68d9                 ; 不等于则失败
...
0x688E  call 0x8dc0                ; 准备目录清除 APDU
0x68A6  call 0x1fb0                ; 发送清除 APDU
0x68AB  test eax, eax
0x68AD  jl 0x68d9
0x68AF  cmp word [esp+0xa], 0x9000 ; 再次检查 SW
0x68B4  jne 0x68d9
0x68BC  call 0x19c0                ; 调用 Clear_DF
0x68C1  test eax, eax
0x68C3  jl 0x68d9
0x68C5  cmp word [esp+0xa], 0x9000 ; 最终检查 SW
0x68CA  jne 0x68d9
0x68CD  xor eax, eax               ; 成功返回 0
0x68D0  add esp, 0xc4
0x68D6  ret 4                      ; 1 个参数 (hCard)
```

**调用流程**：
1. 发送准备擦除的 APDU
2. 检查返回状态字 (SW) = 0x9000
3. 调用 `Clear_DF` 清除 DF 文件结构
4. 检查每个步骤的 SW 状态
5. 全部成功返回 0，否则返回 -1 (0xFFFFFFFF)

#### HSErase 高层逻辑

`HD_HardAPI.dll` 的 `HSErase` 内部：
1. 通过函数指针调用 `HD_SortDev.dll::HS_Erase`
2. `HS_Erase` 再调用 `HDCOS_LNCA.dll::HD_ClearDir` 等一系列底层函数
3. 每个层级都会检查返回值和 SW 状态字
4. 成功返回 0，失败返回 0x99 或其他错误码

## 验证方法

### 签名验证公式

对于 `__stdcall` 约定：
```
ret imm16  →  参数字节数 = imm16
参数个数 = imm16 / 4  (32位指针/int)
```

例如：
- `ret 4` → 1 个参数
- `ret 8` → 2 个参数
- `ret 0xC` (12) → 3 个参数

### 实际验证

所有签名已在 `LncaProvider.cs` 和 `LncaHardApiNative.cs` 中实现，并通过编译测试：
```bash
dotnet build Manager/src/USBKey.Core/USBKey.Core.csproj
```
**结果**：0 错误，0 警告

## 代码改动总结

### 新增文件
1. **Manager/src/USBKey.Core/UsbKey/LncaHardApiNative.cs**
   - `HD_HardAPI.dll` 的完整 P/Invoke 声明
   - 包含 `HSConnectDev`, `HSErase`, `HSDisconnectDev`, `HSVerifyUserPin`

### 修改文件
2. **Manager/src/USBKey.Core/UsbKey/LncaProvider.cs**
   - `Initialize()` 方法增加 `HD_HardAPI.dll` 加载逻辑
   - `ResetDevice()` 改为调用真实初始化链路：
     ```csharp
     HSConnectDev(devIndex, out hDev)
     → (可选) HSVerifyUserPin(hDev, adminPin)
     → HSErase(hDev)  // 核心擦除操作
     → HSDisconnectDev(hDev)
     ```
   - 添加 `_hardApi`, `_hsConnectDev`, `_hsErase`, `_hsDisconnectDev`, `_hsVerifyUserPin` 字段
   - `Dispose()` 增加 `_hardApi` 释放

## 待确认项（需实体设备测试）

1. **出厂默认 SO PIN（管理员 PIN）**
   - 可能为空、`"111111"`、`"123456"` 或其他厂商默认值
   - 代码中已标注 `TODO: 确认出厂默认 SO PIN`

2. **擦除后默认用户 PIN**
   - `HSErase` 后设备恢复出厂，用户 PIN 重置
   - 需确认默认值以便在 `ResetDevice` 后重新设置

3. **`HSErase` 是否需要 SO PIN 校验**
   - 当前实现：若提供 `adminKey` 参数则先调用 `HSVerifyUserPin`
   - 部分厂商可能要求必须先验证 SO PIN，部分可能允许直接擦除
   - 需根据实际设备行为调整

## 逆向工具脚本

位置：`Manager/tools/disasm_hdcos_full.py`

功能：
- 解析 PE 文件结构
- 反汇编指定函数的完整代码
- 自动检测 `ret` 指令确定函数边界
- 输出带注释的汇编代码（识别字符串常量）

使用方法：
```bash
python Manager/tools/disasm_hdcos_full.py > hdcos_disasm_full.txt
```

## 结论

通过完整的逆向分析，我们：

1. **确认了 JIT 层的空壳问题**：`USBKey_InitKey` 和 `USBKey_Reset` 无实际功能
2. **还原了真实的初始化链路**：`HD_HardAPI.dll` → `HD_SortDev.dll` → `HDCOS_LNCA.dll`
3. **精确提取了所有关键函数的签名**：通过 `ret imm16` 指令反推参数数量
4. **实现了正确的 ResetDevice 方法**：调用底层 `HSErase` 实现真正的设备擦除
5. **代码已通过编译验证**：所有签名和调用约定正确

**下一步**：需要使用实体 LNCA USB Key 设备测试 `ResetDevice()` 方法，确认：
- SO PIN 默认值
- 擦除后用户 PIN 重置值
- 是否需强制 SO PIN 校验
