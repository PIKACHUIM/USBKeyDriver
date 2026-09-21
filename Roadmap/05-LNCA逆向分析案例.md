# LNCA USB Key 驱动逆向分析报告

> 目标：使 USBKey.Manager 可直接管理 LNCA 智能卡设备。
> 分析对象：`Library/LNCA/` 下的厂商驱动 DLL。
> 分析工具：objdump（msys64 mingw64）+ strings + x86x64dbgmcp（x64dbg，用于动态验证）。

---

## 一、核心结论（TL;DR）

1. **所有驱动 DLL 均为 32 位（pei-i386）**，宿主进程必须以 x86 运行（已在 `USBKey.Manager.csproj` 设置 `<PlatformTarget>x86</PlatformTarget>`）。
2. **这些 DLL 均有「名字导出」**。早期 `tools/DumpExports.ps1` 因解析导出名表时按序号顺序读取名字指针（而名字表实为字典序），误判为“纯序号导出”。实际可直接 `GetProcAddress("函数名")`。
3. **调用约定为 `__stdcall`**，返回 `int`（`0` = 成功，非 `0` = 错误码）。
4. **字符串为 ANSI（`char*`）**。
5. 句柄 `hKey` 为 `IntPtr`，由 `USBKey_Connect` 输出，其后所有操作携带。

---

## 二、DLL 分层架构

```
USBKey.Manager (C# / .NET 8, x86)
        │ 按名字 GetProcAddress
        ▼
JIT_USBKEY_HD.dll   ← 高层设备管理 API（USBKey_*，44 导出，序号 101-144）★ 对接目标
        │ 内部调用
        ▼
HDCOS_LNCA.dll      ← COS 命令层（HD_*/HDJIT_*，104 导出）
GP_COS_LNCA.dll     ← 标准 COS 命令（Change_Pin/Verify_Pin/Read_Binary…，79 导出）
        │ 内部调用
        ▼
GP_IFD_LNCA.dll     ← 读卡器接口层（HD_OpenPort/HD_ApduT0…，46 导出，序号 201-246）
HDIFD20B.dll        ← 读卡器接口（同序号 201-246）
        │
        ▼
CIDCUSB.sys         ← USB WDM 驱动（内核态）
```

- `GP_CSP_LNCA.dll` / `GP_CSP_LNCA_EX.dll`：标准 Windows CSP（`CPAcquireContext` 等 25 导出），供系统 CryptoAPI 调用，与设备管理无关。
- `HD_HardAPI.dll`：硬件层（`HS*`，17 导出）。
- `JIT_KEYTOOL_HD.dll`：密钥工具（`USBKey_Open/ReadKey/WriteKey`，5 导出）。

---

## 三、JIT_USBKEY_HD.dll 完整导出表（逆向确认）

> 签名由 DLL 内置调试日志字符串（`"USBKey_xxx Start... hKey = 0x%08x, ..."`）+ 反汇编确认。

### 3.1 设备连接 / 会话

| 序号 | 函数 | 签名（__stdcall） | 说明 |
|---|---|---|---|
| 101 | `USBKey_Connect` | `int(uint dwKeyIndex, uint bandRate, int* phKey)` | 连接指定索引设备（索引 0..3），输出句柄 |
| 102 | `USBKey_Disconnect` | `int(int* phKey)` | 断开连接 |
| 103 | `USBKey_UserLogin` | `int(hKey, char* lpPinStr, uint len)` | PIN 登录 |
| 104 | `User_Exit` | `int(hKey)` | 登出/退出会话 |

### 3.2 PIN / 解锁 / 重置

| 序号 | 函数 | 签名 | 说明 |
|---|---|---|---|
| 105 | `USBKey_ChangePin` | `int(hKey, char* oldPin, uint oLen, char* newPin, uint nLen)` | 改 PIN |
| 106 | `USBKey_UnlockPin` | `int(hKey, char* unlockPin, uint len)` | PUK 解锁 |
| 127 | `USBKey_VerifyPin` | `int(hKey, uint type, char* pin, uint len)` | 验证 PIN（type: 0=用户,1=管理） |
| 128 | `USBKey_UserUnlockPin` | `int(hKey, char* unlockPin, uint uLen, char* userPin, uint pLen)` | PUK 解锁并重设用户 PIN |
| 126 | `USBKey_InitKey` | `int(hKey, char* userPin, uint, char* operPin, uint, char* unlockPin, uint)` | 初始化密钥（重置时设置三种 PIN） |
| 132 | `USBKey_Reset` | `int(hKey, byte* rData, uint rLen)` | 重置设备 |

### 3.3 设备信息

| 序号 | 函数 | 签名 |
|---|---|---|
| 129 | `USBKey_GetDevState` | `int(hKey, uint* pKeyStatus)`（KEY_ONLINE/KEY_LOGIN/KEY_OFFLINE） |
| 140 | `USBKey_GetKeySN` | `int(hKey, char* lpKeySN, uint len)` |
| 143 | `USBKey_GetDevicePort` | `int(char* szDeviceName, uint* pnPort)` |
| 131 | `USBKey_ListKey` | `int(uint* count)`（返回设备数量，单参数） |
| 141/142 | `USBKey_Register/UnRegisterNotification` | `int(uint hWnd)` / `int()` |

### 3.4 证书 / 密钥

| 序号 | 函数 | 签名 | 说明 |
|---|---|---|---|
| 124 | `USBKey_WriteCert` | `int(hKey, uint certType, byte* cert, uint len)` | 写证书 |
| 125 | `USBKey_ReadCert` | `int(hKey, uint certType, byte* cert, uint* len)` | 读证书 |
| 144 | `USBKey_RegisterCert` | `int(hKey, uint certType)` | 注册证书 |
| 113 | `USBKey_GenRSAKeyPair` | `int(hKey, uint pubKeyType, byte* pub, uint* pubLen, byte* pri, uint* priLen)` | 设备内生成 RSA 密钥对 |
| 114 | `USBKey_SignData` | `int(hKey, uint algID, byte* in, uint inLen, byte* out, uint* outLen)` | 签名 |
| 115 | `USBKey_VerifySign` | `int(hKey, uint algID, byte* pub, uint pubLen, byte* sig, uint sigLen, byte* data, uint dataLen)` | 验签 |
| 116 | `USBKey_RsEnDecryptData` | `int(hKey, uint keyType, byte* encPub, uint, byte* in, uint, byte* out, uint*)` | RSA 加解密 |
| 122 | `USBKey_WritePubPriKey` | `int(hKey, uint dEnKeyIndex, byte* pri, uint, byte* pubEncKey, uint, uint algID)` | 导入密钥对 |
| 119 | `USBKey_GetRandom` | `int(hKey, byte* out, uint len)` | 取随机数 |
| 120 | `USBKey_GenKey` | `int(hKey, uint algID, byte* out, uint* outLen)` | 生成密钥 |

### 3.5 Key 内文件系统（证书/数据存储）

| 序号 | 函数 | 签名 |
|---|---|---|
| 107 | `USBKey_CreatFile` | `int(hKey, char* name, uint nameLen, uint fileLen)` |
| 108 | `USBKey_WriteFile` | `int(hKey, char* name, uint, byte* data, uint dataLen)` |
| 109 | `USBKey_ReadFile` | `int(hKey, char* name, uint, uint rdataLen, byte* rdata, uint* outLen)` |
| 110 | `USBKey_DelFile` | `int(hKey, char* name, uint nameLen)` |
| 111 | `USBKey_RFileLen` | `int(hKey, char* name, uint, uint* pFileLen)` |

---

## 四、关键反汇编证据

### 4.1 `USBKey_Connect`（0x10001DF0）
```
sub $0xac,%esp
...
cmp $0x4,%esi            ; dwKeyIndex < 4，否则返回 0x3EA (KEYMAX)
...
call *0x10021068         ; 内部枚举/打开设备
...
mov %eax,0x0(%ebp)       ; *phKey = 句柄
...
xor %eax,%eax            ; 返回 0
ret $0xc                 ; __stdcall，3 参数（12 字节）
```

### 4.2 `USBKey_ListKey`（0x100043A0）
```
mov %esi,0x0(%ebp)       ; *count = 设备数量
ret $0x4                 ; __stdcall，单参数（int* count）
```
→ 澄清：`ListKey` 返回的是**设备数量**（0..4），不是密钥容器列表。

---

## 五、代码实现映射

| IKeyProvider 方法 | 对接的 DLL 函数 |
|---|---|
| `Enumerate` | WMI（`Win32_PnPEntity` 按 VID/PID） |
| `Login` | `USBKey_Connect` + `USBKey_UserLogin` |
| `Logout` | `User_Exit` + `USBKey_Disconnect` |
| `GetDetail` | `USBKey_GetKeySN` + `USBKey_GetDevState` |
| `ListContainers` | `USBKey_ReadCert`（type 0=签名 / 1=加密） |
| `ImportPfx` | `USBKey_WriteCert` + `USBKey_RegisterCert` +（私钥导入） |
| `ExportCertificate` / `ViewCertificate` | `USBKey_ReadCert` |
| `RegisterToCsp` / `UnregisterFromCsp` | 标准 CryptoAPI（`X509Store`） |
| `ChangePin` | `USBKey_ChangePin` |
| `Unlock` | `USBKey_UserUnlockPin` / `USBKey_UnlockPin` |
| `GenerateChallenge` | `USBKey_GetRandom` |
| `ResetDevice` | `USBKey_InitKey`（回退 `USBKey_Reset`） |

---

## 六、动态验证结果（实体设备 + LncaProbe 探针）

已通过 x86 探针程序（`tools/LncaProbe`，独立 `LoadLibrary("JIT_USBKEY_HD.dll")`）在**实体设备插入**状态下完成运行时验证：

### 6.1 验证通过的核心函数

| 函数 | 结果 |
|---|---|
| `USBKey_ListKey` | rc=0，count=1（检测到 1 台设备） |
| `USBKey_Connect(0, 0, &hKey)` | rc=0（bandRate=0 即可连接，确认该参数被忽略） |
| `USBKey_GetKeySN` | rc=0，序列号 = `01102001519176` |
| `USBKey_GetDevState` | rc=0，state=0x1（未登录）/ 0x2（已登录） |
| `USBKey_VerifyPin(type=0)` | rc=0（默认 PIN = `123456`） |
| `USBKey_UserLogin` | rc=0 |
| `USBKey_GetRandom` | rc=0，成功生成 16 字节随机数 |
| `USBKey_ReadCert(type=0)` | rc=0，读出 X.509 证书 `CN=营口辽河装备有限公司, OU=@05566801-6, L=营口, S=辽宁, C=CN`（1151 字节） |
| `USBKey_ReadCert(type=1)` | rc=0（加密证书） |
| `User_Exit` + `USBKey_Disconnect` | rc=0 |

### 6.2 逆向修正（动态验证发现并修复的签名错误）

1. **`USBKey_GetKeySN` 第三个参数为指针**（`uint*`，in/out 长度），非值。反汇编 `mov (%eax),%ecx` 解引用证实。之前按值传递导致崩溃，已改为 `ref uint`。
2. **`USBKey_GetRandom` 参数顺序为 `(hKey, len, buf)`**，非 `(hKey, buf, len)`。日志打印顺序与参数传递顺序不一致，通过反汇编循环体（`cmp %edi,%esi` 用长度做循环、`mov %dl,-0x1(%esi,%ebx,1)` 用指针做基址）确认真实顺序，已修正。

### 6.3 关键事实确认

- 默认 PIN：`123456`
- 设备序列号：`01102001519176`
- 证书：签名证书（type 0）+ 加密证书（type 1），均为标准 X.509 DER（1151 字节）
- 设备状态：`0x1`=在线未登录，`0x2`=已登录

---

## 七、仍待验证项

1. **多容器语义**：JIT 层为"签名 + 加密证书对"模型。多容器需扩展 `HD_ReadContainerListInfo` / `HD_ReadContainerInfoEx`（HDCOS 层）。
2. **`ImportPfx` 私钥导入**：`USBKey_WritePubPriKey` 要求私钥先以设备公钥加密（`dPubEncKey`/`dAlgID`），加密协议需逆向 `HDJIT_ImportRsaPrivateKey` 链路确认。已修复：不再用 `GenRSAKeyPair` 兜底（会造成证书与设备内私钥不匹配），改为「读设备加密证书提取加密公钥 → PKCS#1 v1.5 加密私钥 → `WritePubPriKey`」，协议假设仍待实体设备验证。
3. **`DeleteContainer` 定位方式**：已修复——不再用 `container.ContainerName`（实为证书 CN）误调 `DelFile`；明确抛 `NotSupportedException`，待 `HD_DeleteCert`/`HD_DeleteContainer` 逆向确认后对接。
4. **挑战码解锁**：`HD_ExternalMF` / `External_Authentication` 协议待确认。
5. **`ChangePin`/`Unlock`/`Reset` 运行时验证**：签名已从反汇编确认（`ret $0x14` 等），但涉及修改设备状态，需谨慎实测。
6. **返回值错误码表**：已知 `0x3E9`（打开失败）、`0x3EA`（KEYMAX）、`0x3EB`（参数无效）、`0x3F0`，其余待补充。

---

## 八、x64dbg 注意事项

**调试器位数必须匹配**：LNCA 驱动 DLL 为 32 位，必须用 **x32dbg**（`x96dbg.exe` 启动器选 x32dbg），不能用 x64dbg。本次实测发现用户启动的是 x64dbg，加载 x86 探针时报 0 模块（位数不匹配），故改用独立 x86 探针程序 `tools/LncaProbe` 直接运行完成全部验证。

若需用 x64dbg 观察 DLL 内部调用链（如私钥导入加密协议），请切换到 x32dbg 后重试：
1. `x96dbg.exe` → 选 **x32dbg**；
2. 插件菜单 → `x64dbg MCP Server` → `Start MCP HTTP Server`；
3. 加载 `tools/LncaProbe`（x86）或 `USBKey.Manager.exe`，在 `USBKey_*` 下断点。

---

## 九、逆向方法论总结（如何逆向厂商 USB Key 驱动）

### 9.1 工具链

| 工具 | 用途 |
|---|---|
| `objdump -p`（msys64 mingw64） | 查看 PE 导出表/导入表/位数（`file format pei-i386` = 32 位） |
| `objdump -d --start-address --stop-address` | 反汇编指定函数 |
| `strings`（msys64） | 提取 DLL 内嵌字符串（函数名、调试日志、错误消息） |
| `x64dbg / x32dbg`（x86x64dbgmcp） | 动态调试，观察运行时参数/返回值/崩溃点 |
| `Python` | 解析 PE 头、与 x64dbg MCP（SSE/JSON-RPC）交互 |

### 9.2 逆向步骤（推荐顺序）

1. **枚举导出表**：`objdump -p DLL | Select-String "\+base\["`，过滤 `Export RVA` 行得到「序号 + 函数名」。**关键坑**：导出名表按字典序排列，不要按序号顺序读。
2. **提取字符串找签名线索**：`strings -n 5 DLL`。厂商 DLL 常内置形如 `"USBKey_UserLogin Start... hKey=0x%08x, lpPinStr=%s, lpPinStrLen=%u"` 的调试日志，**直接泄漏函数参数顺序和类型**（`%u`=uint、`%s`=字符串、`%08x`=指针/句柄）。
3. **反汇编确认签名**（3 个判据）：
   - 函数结尾 `ret $0xN` → `N/4` = 参数个数；
   - 入口 `mov 0x4(%esp),%eax` 等 → 参数读取顺序；
   - `mov (%eax),%ecx`（解引用）= 该参数是**指针**；直接 `push %eax` = 该参数是**值**。
4. **写探针程序动态验证**：独立 x86 程序 `LoadLibrary` + `GetProcAddress`，逐个调用并打印返回值。一次崩溃定位一个签名错误，逐步收敛。
5. **（可选）x64dbg 动态观察**：在关键函数下断点，观察参数传递与内部调用链。

### 9.3 关键经验与坑

1. **导出名表是字典序**，早期 `DumpExports.ps1` 按序号顺序读名字，误判为"纯序号导出"。
2. **日志打印顺序 ≠ 参数传递顺序**：`GetRandom` 的日志按 `(hKey, buf, len)` 打印，但真实参数是 `(hKey, len, buf)`，必须以反汇编为准。
3. **长度参数分"值/指针"**：输入字符串长度（PIN 等）是**值**；输出缓冲长度（`GetKeySN` 的 `lpKeySNLen`）是**指针**（in/out），错误传值会解引用无效地址崩溃。
4. **调试器位数必须匹配**：32 位 DLL 必须用 x32dbg；用 x64dbg 加载 x86 目标会 0 模块。
5. **设备枚举不能用 WMI**：设备通过 usbip/VMware/厂商私有驱动接入时，标准 PNP 枚举不到，必须用 DLL 自己的枚举函数（`USBKey_ListKey`）。

### 9.4 实现 IKeyProvider 需要的接口清单

| IKeyProvider 方法 | 需要对接的 DLL 函数 |
|---|---|
| `Enumerate` | `USBKey_ListKey` + `USBKey_Connect` + `USBKey_GetKeySN` |
| `Login` | `USBKey_Connect` + `USBKey_UserLogin` |
| `Logout` | `User_Exit` + `USBKey_Disconnect` |
| `GetDetail` | `USBKey_GetKeySN` + `USBKey_GetDevState` |
| `ListContainers` | `USBKey_ReadCert`（type 0=签名 / 1=加密） |
| `ImportPfx` | `USBKey_WriteCert` + `USBKey_RegisterCert` + `USBKey_WritePubPriKey`（私钥） |
| `ExportCertificate` / `ViewCertificate` | `USBKey_ReadCert` |
| `DeleteContainer` | HDCOS 层 `HD_DeleteCert` / `HD_DeleteContainer`（签名已逆向确认，见第十一章） |
| `RegisterToCsp` / `UnregisterFromCsp` | 标准 CryptoAPI（`X509Store`，无需 DLL） |
| `ChangePin` | `USBKey_ChangePin` |
| `Unlock` | `USBKey_UserUnlockPin` / `USBKey_UnlockPin` |
| `GenerateChallenge` | `USBKey_GetRandom` |
| `ResetDevice` | `USBKey_InitKey`（回退 `USBKey_Reset`） |

---

## 十、问题排查记录：Manager 看不到设备

### 10.1 根因（三重）

1. **枚举方式错误**：`LncaProvider.Enumerate` 原来用 WMI 枚举 `PNPClass='USB'` 并按 `keyslist` 的 VID/PID 过滤。但：
   - config.json 的 `vid=16A0, pid=0D00` 是占位值，与真实设备不符；
   - 设备通过 `usbip-win VHUB`/VMware 虚拟化接入，标准 PNP 枚举根本看不到 LNCA 设备（实测 USB 列表无 16A0/0D00，CIDCUSB 驱动也未安装）。
2. **Library 未部署**：bin 输出目录没有 `Library/LNCA/`，`FindLibraryRoot` 找不到 `JIT_USBKEY_HD.dll`，provider 无法初始化。
3. **配置干扰**：`usermode=false`（管理模式无授权会卡激活流程）+ `platform` 含 `mock`（模拟设备干扰）。

### 10.2 修复

1. **`Enumerate` 改用 DLL 枚举**：`USBKey_ListKey` 取数量 → 逐个 `USBKey_Connect` + `USBKey_GetKeySN` 取序列号 → `USBKey_Disconnect`。彻底摆脱 WMI 与 VID/PID。
2. **csproj 配置部署**：`USBKey.Manager.csproj` 增加 `<None Include>` 项，构建时复制 `Library/LNCA/*.dll` 与 `config/*` 到输出目录。
3. **config.json 修正**：`usermode=true`（免授权验证）、`platform=["lnca"]`（去 mock）、VID/PID 清空（枚举靠 ListKey）。

### 10.3 验证

探针程序（`tools/LncaProbe`）实测：`ListKey`→count=1、`Connect`→rc=0、`GetKeySN`→序列号 `01102001519176`、`ReadCert`→证书 `CN=营口辽河装备有限公司`，全流程 rc=0。

---

**分析日期**：2026-08-25
**分析者**：AI 逆向协作（objdump + strings + 反汇编 + 动态探针验证）
**版本**：1.3

---

## 十一、删除证书函数签名逆向（2026-09-01 新增）

### 11.1 背景

`DeleteContainer` 长期无法对接，根本原因：**JIT 层（`USBKey_*`，44 导出）没有删除证书的独立函数**，而 HDCOS 层（`HD_*`，104 导出）的 `HD_DeleteCert` / `HD_DeleteContainer` **未被任何上层 DLL 静态导入**（通过 `LoadLibrary` + `GetProcAddress` 动态调用，或纯内部调用），因此无法从调用链推断签名。

### 11.2 签名确定方法

用 Python + Capstone 反汇编入口，依据 `ret imm16`（`__stdcall` 参数总字节数）确定参数个数，再依据 prologue 中的 `strlen`（`repne scasb`）判断字符串参数、依据句柄传递判断设备句柄。

### 11.3 已确认签名（HDCOS_LNCA.dll）

| 函数 | RVA | ret | 签名 |
|------|-----|-----|------|
| `HD_DeleteCert` | 0x7210 | `ret 8` | `int HD_DeleteCert(const char* A, const char* B)` |
| `HD_DeleteContainer` | 0x6A10 | `ret 8` | `int HD_DeleteContainer(int hDev, int containerId)` |
| `HD_DelCertFrIE` | 0x6FD0 | `ret 0x10` | 4 参数（IE 删除，暂不采用） |
| `HD_ClearDir` | 0x67D0 | `ret 4` | `int HD_ClearDir(int hDev)` |
| `HD_ReadContainerListInfo` | 0x6650 | `ret 8` | 2 参数（读容器列表） |
| `HD_ReadContainerInfo` | 0x6280 | `ret 0x10` | `int HD_ReadContainerInfo(hDev, outBuf, lenPtr, containerId)` |
| `HD_CreateContainer` | 0x68F0 | — | 创建容器 |

### 11.4 `HD_DeleteCert` 参数语义

反汇编证据（RVA 0x7210）：

```
mov edi, [esp+0x110]      ; 参数1 = 字符串A
repne scasb               ; strlen(A) → 拷贝到局部 buf
mov edi, [esp+0x10c]      ; 参数2 = 字符串B
...
mov byte[esp+ecx+8], 0xff ; 在 A 末尾插入 0xFF 分隔符
lea edx, [esp+ecx+9]      ; B 写入位置 = A + 0xFF + 1
strlen(B) → 拷贝 B
lea ecx, [esp+8]          ; 组合串 = A + 0xFF + B
call 0x8b60               ; 内部处理（含 MessageBox 弹窗）
ret 8
```

**结论**：`HD_DeleteCert` 将两个字符串拼成 `A \x00ff B` 复合标识符。推测 A = 容器名、B = 证书别名（CN），但**精确语义需真实设备验证**。

### 11.5 `HD_DeleteContainer` 参数语义

反汇编证据（RVA 0x6A10，完整流程）：

```
mov eax, [esp+4]          ; 参数1 = hDev（设备句柄）
push 0 / push eax
call 0x7d40               ; 连接/打开设备
...
call 0x8ff0(3, hDev)      ; 第1步：选择/验证
mov bx, word[esp+0x158]   ; 参数2 = containerId（16 位 word）
mov al, bl
add al, 0x10              ; P1 = bl + 0x10（删除容器指令）
push al
call 0x22b0               ; 第2步：删除主命令（APDU）
mov cl, bh                ; 高字节 = 容器类型字段
mov byte[esp+0x28], cl
mov byte[esp+0x29], bl
call 0x1c40               ; 发送 APDU
call 0x8ff0(0x83, hDev)   ; 第3步：收尾
call 0x5b90               ; 提交
call 0x15b0               ; 释放
ret 8
```

**结论**：

- 签名：`int HD_DeleteContainer(int hDev, WORD containerId)`
- `containerId` 低字节 `bl` = 容器索引（1/2/3，与 `HD_ReadContainerListInfo` 枚举编号一致）
- `containerId` 高字节 `bh` = 证书类型（0=签名 / 1=加密）
- 删除指令 APDU 的 P1 = `bl + 0x10`

与 `HD_ReadContainerListInfo` 交叉验证（RVA 0x6650）：

```
mov eax, [esp+0x160]      ; 参数2 = 输出缓冲区
lea ebp, [eax+4]          ; 缓冲区偏移 +4
mov dword[ebp-4], 0       ; 缓冲区前4字节 = count
xor ebx, ebx
inc cl                    ; 容器编号从 1 开始
add ebx, 4                ; 每个容器记录偏移 +4
add ecx, 0x80             ; 每个容器记录 0x80 = 128 字节
cmp ebp, 3                ; 最多 3 个容器
jl loop
```

即 `HD_ReadContainerListInfo(hDev, outBuf)` 返回：

```
[0:4]   = count（容器数量，最多 3）
[4:...] = 每容器 128 字节记录（含容器名/证书标识）
```

**注意**：函数末尾真实返回为 `ret 8`（早期误读的内部错误路径 `ret 4` 已澄清）。

### 11.6 对接风险提示

1. `HD_DeleteCert` 内部会弹 **MessageBox**（`call dword[0x10017180]`），不适合静默调用；对接时应优先 `HD_DeleteContainer`（按容器索引删除，无弹窗）。
2. **无真实 LNCA 设备可验证**（当前环境仅插入 Feitian ePass3003），上述签名通过静态反汇编确定，未做实机验证，**对接后必须在真实设备上测试**。
3. ePass3003 平台的 `DeleteContainer` 已通过标准 PKCS#11 `C_DestroyObject` 完整实现（见 `EPass3003Provider.cs`），无需逆向。

---

## 十二、「完全格式化 + 重设 PIN」链路逆向（2026-09-20 新增）

### 12.1 背景

`ResetDevice`（初始化）长期无法落地，历史结论是「公开 DLL 无「无需认证的初始化重置 PIN」入口」。本次用**静态反汇编定位到真正的 COS 层入口**，彻底推翻该结论。

### 12.2 三个错误入口（已排除）

| 入口 | 结论 | 证据 |
|------|------|------|
| `JIT_USBKEY_HD.dll::USBKey_InitKey` / `USBKey_Reset` | 调试空壳 | 仅打印日志后 `xor eax,eax; ret` |
| `HDCOS_LNCA.dll::InitialCard`（RVA 0x73F0） | 空 stub | `or eax,0xffffffff; ret 0x10`（4 参数直接返回 -1） |
| `HD_HardAPI.dll::HSErase` → `HD_SortDev.dll::HS_Erase` | 只擦「存储层文件系统」 | 内部 APDU 为 `DD EA`/`DD FA`/`AD F1~F3` 系列文件系统命令，不重置 COS PIN |

另：`HSChangeUserPin` / `HSReWriteUserPin`（HD_SortDev 层）经反汇编确认**必须先校验旧 PIN**（`HS_ReWriteUserPin` 先 `strlen` 校验旧 PIN 1~16、新 PIN 2~16，再调用内部 0x4760），故不能用于「旧 PIN 未知」。

### 12.3 正确入口：`HD_ClearDir` = COS 层完全格式化

`HDCOS_LNCA.dll::HD_ClearDir`（RVA 0x67D0，`ret 4`）内部链路（逐条反汇编确认）：

```
Get_Challenge(hCard, 8, &challenge, &sw)          ; APDU CLA 0x84，取 8 字节挑战
  ↓
[0x10019050..0x10019060] 内置传输密钥（16B，数据段常量）
  ↓ call 0x10008dc0(...)                           ; 挑战应答计算
External_Authentication(hCard, 0, resp8, &sw)     ; APDU CLA 0x82，P1=0（管理员/传输密钥）
  ↓ 校验 SW == 0x9000
Clear_DF(hCard, &sw)                              ; 私有 APDU：BF CE 00 00 00
```

**关键点**：

1. 外部认证用的传输密钥**硬编码在 DLL 数据段**（RVA 0x19050：`63 79 74 62 79 68 79 78 73 79 6b 79 68 62 08 31` = `"cytbyhyxsykyhb"` + `08 31`），**不需要用户 PIN**。
   ⚠️ **实机修正（见 12.9）**：该常量是整个 SDK 共用的「出厂默认传输密钥」，只有**未修改过管理员口令**的卡才接受它；批量个性化后的卡密钥已被替换，此时 `HD_ClearDir` 必定失败（返回 -1），必须由调用方提供 SO 口令走备用链路。
2. 交叉引用扫描（`_逆向分析/tools/disasm_lnca.py --xrefs`）证明：`Clear_DF` 在 DLL 内**只有一个调用者**，即 `HD_ClearDir`（`0x68BC`）——它是 COS 层清除数据区（DF）的**唯一入口**。
3. `HD_ClearDir` 与 `HSErase` 互补：前者清 COS 层数据区（证书/容器/密钥记录），后者清存储层文件系统，**两者叠加才是真正的「完全格式化」**。

### 12.4 重设 PIN 的三个入口

| 入口 | 签名 | 底层命令 |
|------|------|----------|
| `Reload_Pin` | `int(hCard, uint dataLen, byte* data, void* reserved)`，`ret 0x10` | APDU `80 5E 00 00 Lc data`（ISO7816-4 INS 0x5E = RESET RETRY COUNTER） |
| `HD_ChangePin` | `int(hCard, byte* oldNewPin, uint len)`，`ret 0xC` | 缓冲区格式 `旧PIN + 0xFF + 新PIN`（DLL 以 0xFF 拆分，与 `HD_DeleteCert` 同一风格） |
| `HSReWriteUserPin` | `int(hDev, char* old, char* new)`，`ret 0xC` | 存储层改 PIN，**必须先验证旧 PIN** |

`Reload_Pin` 在 DLL 内**无任何内部调用者**（xrefs 为空）→ 它是专供上层管理工具（`GP_ADM_LNCA.exe`）调用的导出 API，语义即 ISO7816 RESET RETRY COUNTER。

### 12.5 `HD_VerifyPin` 的真实语义（重要）

`HD_VerifyPin(hCard, byte* pin, uint len)`（RVA 0x2840，`ret 0xC`）**不是**简单 VERIFY，而是：

```
0x10008d10(len, pin)                       ; 以 PIN 作为密钥材料做密钥派生
Get_Challenge(hCard, 8, &ch, &sw)
0x10008dc0(...)                            ; 计算 8 字节响应
External_Authentication(hCard, 1, resp, &sw)  ; P1=1（用户 PIN 外部认证）
SW 判定：0x9000 = 通过；(SW & 0xFFF0)==0x63C0 → 返回剩余重试次数（为 0 则返回 -1）；
        0x6983 / 0x9303 → -1（锁定/被拒）
```

即：**COS 的 PIN 认证 = 用 PIN 做挑战应答外部认证**（PIN 即"密钥"）。这解释了历史上「默认 123456 验证失败返回 0x3EE」的现象，也说明**盲目遍历默认 PIN 会消耗重试计数**，实现时必须限制尝试次数。

### 12.6 设备打开方式

`HD_Open(int port)`（RVA 0x1120，`ret 4`）→ 返回卡片句柄（0 表示失败）；`HD_Close(hCard)`（RVA 0x15B0）关闭。
`HD_OpenJITDevice(char* devSN, int* phCard)`（RVA 0x9070，`ret 8`）为 JIT 层使用的打开流程：遍历 port 0~3 → `HD_Open(port)` → `HD_GET_BCDSN` 比对序列号 → `HD_IC_RESET` → `HD_GET_SN`。

**调用链权威性证据**：`JIT_USBKEY_HD.dll` 的字符串表中同时出现 `HDCOS_LNCA` 与 `HD_ChangePin`/`HD_VerifyPin`/`HD_OpenJITDevice`/`HDJIT_VerifyAdminPin` 等导入名，证明 **HDCOS_LNCA.dll 就是 LNCA 的权威 COS 层**（注意与同目录的 `HD_hdcos480.dll` 是**两个不同文件**：139264B vs 57344B，SHA256 不同）。

### 12.7 代码落地

| 位置 | 内容 |
|------|------|
| `Manager/src/USBKey.Core/UsbKey/LncaHdcosNative.cs` | HDCOS 层 P/Invoke 声明（新增） |
| `Manager/src/USBKey.Core/UsbKey/LncaProvider.cs::ResetDevice` | 新流程：存储层擦除 → `HD_ClearDir` 完全格式化 → 重设 PIN（Reload_Pin → HD_ChangePin → HSReWriteUserPin）→ `HD_VerifyPin` 验证 |
| `Library/LNCA USBKey Manage/_逆向分析/probe/LncaProbe` | 实机验证探针（`--format [port] [新PIN] [SO口令] [PUK] [--dry]`；`--dry` 只读探测，不做破坏性操作） |
| `Library/LNCA USBKey Manage/_逆向分析/tools/disasm_lnca.py` | 反汇编工具（`--full`/`--xrefs`/`--imports`/`--strings`/`--wstrings`/`--data`/`--findpat`/`--countpat`/`--addrrefs`） |
| `Library/LNCA USBKey Manage/_逆向分析/tools/lnca_keytest.ps1` | P1=0 通道候选密钥批量验证脚本 |
| `Library/LNCA USBKey Manage/_逆向分析/README.md` | 归档索引：结论摘要 + 全部工具用法 + 路径说明 |

**诚实原则**：每一步真实返回码都记录到 `LncaProvider.LastResetReport`；只有最终 `HD_VerifyPin(新 PIN)` 通过才判定成功，否则抛出带完整报告的异常，绝不假装成功。

### 12.8 待实机验证项

1. `HD_ClearDir` 是否真的能清空 COS 层数据区（需真实 LNCA 设备，当前环境仅 Feitian ePass3003，`HD_Open` 返回 0）。
2. `Clear_DF` 后 User PIN 是否回到出厂默认（若回到默认，`HD_ChangePin` 用默认旧 PIN 即可改密）。
3. `Reload_Pin` 的数据域语义（「PUK + 新 PIN」还是「仅新 PIN」）需按固件实测确定。
4. 各步返回码含义（`SW` 与 DLL 返回值）需实测建立对照表。

### 12.9 实机测试记录（2026-09-20，真机 LNCA Key）

设备：`HD_GET_BCDSN = 01102001519176`，`HD_GET_SN = SZD23B10`（ATR 前 8 字节即 `SZD23B10`），擦除前持有一张加密证书
`CN=营口辽河装备有限公司, OU=@05566801-6`（1151 字节）。

#### (1) HDCOS 返回码约定（与 JIT 层不同！）

| 调用 | 返回 | SW | 说明 |
|------|------|----|------|
| `HD_Open(0)` | `0xA4E6A50` | — | 句柄非 0 即成功 |
| `HD_GET_BCDSN` / `HD_GET_SN` | `0` | — | 成功 0 |
| `Get_Challenge(hCard, 8, ...)` | **`8`** | `0x9000` | **成功 = 返回数据字节数**（非 0！） |
| `Select_File(hCard,0,0,0,0)` | `8` | `0x9000` | 同上 |
| `External_Authentication(P1=0, 错误响应)` | `0` | **`0x63CF`** | 认证失败，**末位 = 剩余重试次数（15）** |
| `Clear_DF`（未认证） | `0` | **`0x6982`** | 「安全状态不满足」→ 格式化必须先认证 |
| `HD_ClearDir` | **`0xFFFFFFFF`** | — | 内置默认密钥不匹配 → 失败 |
| `Reload_Pin(hCard, len, 新PIN, 0)` | `0` | — | ⚠️ **该函数不检查 SW，返回值无成功语义** |

#### (2) 关键结论（逐条实测）

1. `HD_ClearDir` → **-1（失败）**：本卡的管理员/传输密钥已非 SDK 内置默认值 `cytbyhyxsykyhb`。
2. `Clear_DF` 直连 → `SW=0x6982`：**完全格式化必须处于已认证会话**，不能绕过。
3. `Reload_Pin`（仅新 PIN）→ 返回 0 但 **PIN 实际未改变**：`HD_VerifyPin(新PIN)` 仍为 -1，JIT 层
   `USBKey_UserLogin(新PIN)` → `0x3E9` 失败。→ **`Reload_Pin` 的 rc 不能作为成功判据**，必须用 `HD_VerifyPin` 终判。
4. `HD_VerifyPin` → **-1 = 用户 PIN 已锁定**（SW=0x63C0，重试次数 0）；成功返回 `0`，其他失败返回 `-1000`。
   （其成功路径还会再调一次 `Verify_Pin(hCard, 0, 6, ...)` 做二次确认。）
5. `HSErase`（存储层）→ **rc=0 成功**，但**证书仍在**（擦除后 `ReadCert(type=1)` 仍返回同一张证书）→ 证实
   「存储层擦除 ≠ 完全格式化」，**必须叠加 COS 层 `Clear_DF` 才是完整格式化**。
6. `HDJIT_VerifyAdminPin` 用 `12345678`、`cytbyhyxsykyhb` 均返回 -1（不匹配）；未继续穷举以免耗尽
   P1=2 认证计数（该计数同样为 15 次起算）。
7. 出厂默认传输密钥在同一 SDK 的多个模块中重复出现（`HDCOS_LNCA.dll` ×4、`GP_COS_LNCA.dll` ×4、
   `HD_SortDev.dll` ×1 @0xE058、`LNCACSPSetup.exe` ×1），可确认为「默认值」而非本卡密钥。

#### (3) 因此的工程结论

- **可自动完成**：存储层擦除（`HSErase`，rc=0）。
- **需要凭据才能完成**：COS 层完全格式化（`Clear_DF` 需已认证会话）+ 用户 PIN 重设
  （`HD_VerifyPin` 显示 PIN 已锁定，须用 PUK 走 INS 0x5E，或先用 SO 口令完成 `External_Authentication` P1=2）。
- 代码已实现双链路：内置密钥优先；失败则（提供 SO 口令时）`HDJIT_VerifyAdminPin` → `Clear_DF` → `HDJIT_ReloadPin`，
  并在失败时自动跑 `Get_Challenge`/`Select_File`/`External_Authentication` 逐层诊断，把 rc 与 SW 写入报告。

#### (3.5) 认证通道状态与「暴力测试」可行性（2026-09-20 二次实测）

`Clear_DF` 失败根因可完整定位为**认证通道全部不可用**：

```
Clear_DF → SW=0x6982（安全状态不满足：需先外部认证）
   └─ External_Authentication 三条通道实测：
        P1=0 传输密钥   ：可尝试、且失败【不递减】计数（连续 10 次恒为 0x63CF）
                         但密钥 ≠ SDK 内置默认值 → 恒失败
        P1=1 用户 PIN   ：SW=0x63C0 → 已锁定（重试次数 0）
        P1=2 管理员/SO  ：SW=0x6983 → 已锁定（第 1 次即返回锁定；随后出现 0x6D00）
```

- 内置默认密钥常量 `cytbyhyxsykyhb` + `08 31`（16B）已用 4 种形态测试全部不匹配：
  14 字符 ASCII、16 字节原样、8 字节前缀 `cytbyhyx`、另一内置 16 字节常量
  `A62F1A1D6F5F85E2F31DFA933F273947`（RVA 0x190F4）。
- 密钥变换 `sub_8D10`（RVA 0x8D10）实现为「对每个低位置 1 的字节翻转 bit7」，即
  **SO 口令近乎原样作为对称密钥**参与挑战应答 → **不存在「由序列号推导密钥」的可能**。
- 单次认证实测 **≈137 ms**（10 次 1367 ms）。

**暴力测试结论：不可行。**
1. P1=2（管理员）通道**已锁定**，任何候选项都被直接拒绝（0x6983），与口令是否正确无关 → 无法枚举。
2. 即便未锁定：SO 口令长度 6~16、且按原样用作密钥，空间 ≥ 10⁶（6 位数字）～10¹¹+（字母数字）；
   按 137 ms/次，10⁶ ≈ 38 小时、2×10⁹ ≈ 8.7 年。
3. P1=0 通道虽不锁定，但要枚举必须先复现 `sub_8DC0` 的挑战应答算法（需逆向
   0x1000F160/0x1000F570 的对称算法与 0x1000F980 的编码），且同样受限于密钥空间。

**唯一可行路径**：由厂商/客户提供传输密钥或 SO 口令（或用厂商管理工具 `GP_ADM_LNCA.exe`
按其授权的初始化流程处理）。本软件已实现「输入 SO 口令 → `HDJIT_VerifyAdminPin` → `Clear_DF`
→ `HDJIT_ReloadPin`」链路，拿到口令即可一键完成完全格式化与 PIN 重设。

#### (6) 厂商工具与「另一个 COS 层」的发现（2026-09-21）

厂商工具都在仓库内：`Library/LNCA USBKey Manage/`（2026-08-22 同批）

| 文件 | 大小 | 说明 |
|------|------|------|
| `GP_ADM_LNCA.exe` | 88 KB | 管理工具（原生 C++/MFC GUI，v2.0.0.6） |
| `GP_CLT_LNCA.exe` | 236 KB | 客户端工具 |
| `GP_CLT_LNCA_Service.exe` | 24 KB | 自动登录服务 |
| `LNCACSPSetup.exe` / `VISTA64_DriverInstall.exe` | 678/64 KB | CSP 安装与驱动安装 |

**`GP_ADM_LNCA.exe` 的动态导入名（字符串证据）**：`HD_ClearDir`、`HD_ChangePin`、`HD_VerifyPin`、
`HD_Open`/`HD_Close`/`HD_IC_RESET`、`HD_GET_BCDSN`/`HD_GET_SN`、`HD_ReadContainerInfoEx`、
`HD_WriteContainerInfoEx`、`HD_StoreCert`/`HD_StoreCertEx`、`HD_ReadLableInfo`/`HD_WriteLableInfo`、
`HD_ReadBinFileNoLen`/`HD_WriteBinFileNoLen`、`HD_AddCertToIE`/`HD_DelCertFrIE`/`HD_DeleteCert`、
`HD_IsHDDevice`、`HD_RegisterCardNotification`；模块引用 `GP_COS_LNCA`/`GP_IFD_LNCA`/`GP_CLT_LNCA`/`GPClientLNCAClass`。
→ **证实 `HD_ClearDir` 即官方「清除/初始化」入口**。

**另一个 COS 层：`GP_COS_LNCA.dll`（604 KB）**，比 `HDCOS_LNCA.dll` 多出 `HD_StoreCertEx`、
`HD_OpenReaderEx`、`HD_IsHDDevice` 等导出，且 **`InitialCard` 是真实现**：

| 导出 | HDCOS_LNCA.dll | GP_COS_LNCA.dll |
|------|----------------|-----------------|
| `InitialCard` | 0x73F0 **空 stub**（`or eax,-1`） | **0x6910 真实现**（`ret 0x10`，4 参数） |

`GP_COS_LNCA!InitialCard` 逻辑（反汇编还原）：

```
字符串参数① 长度限制 6~8   → SO PIN
字符串参数② 长度限制 6~16  → 用户 PIN
  sub_8340()（= HDCOS 的 sub_8D10：低位置 1 的字节翻转 bit7）
  → ExternalAuthMF(hCard)          [RVA 0xE160，内部加载 GP_IFD.dll 用 HD_ApduT0 发 APDU]
  → Create_File(hCard, 0xB, F2 20 33…) / Write_Key(0x84, P1=0, P2=0xF2…)
  → sub_2970(hCard, …, 0x10082020 /*内置 16B 常量*/, 16, …)   ← 用内置密钥封装后写入
  失败统一返回 0xFFFFFC18 (-1000)
```

**实测（本卡）**：用 `LncaProbe --mf` 直接调用其第一步 `ExternalAuthMF(hCard)`（只认证、不写入）：

```
GP_COS_LNCA!HD_Open(0) → hCard=0xA496A30
ExternalAuthMF(hCard)  → -1000      ← 失败
```

结论：`GP_COS_LNCA.dll` 同样内置 `cytbyhyxsykyhb`+`08 31`（@0x82020/0x82030，且 `InitialCard`
在 0x6D14 把它当加密密钥用），本卡该密钥已被替换 ⇒ **COS 层的「初始化 / 完全格式化」在本卡上不可达**，
与 `HD_ClearDir`、`HD_VerifyPin` 的结论完全一致。厂商侧唯一可行路径是拿到该卡真实传输密钥
（或使用 `GP_ADM_LNCA.exe` 按其授权流程处理）。

#### (7) 认证通道全面测绘与 P1=0 密钥验证器（2026-09-21）

**APDU 层还原（HDCOS_LNCA.dll）**

| 导出 | 签名 | APDU |
|------|------|------|
| `Verify_Pin` | `int(hCard, byte p2, uint len, byte* data, ushort* sw)` | `00 20 00 P2 Lc <PIN>`（ISO VERIFY） |
| `Change_Pin` | `int(hCard, byte p2, uint len, byte* data, ushort* sw)` | `80 5E 01 P2 Lc <data>` |
| `Reload_Pin` | `int(hCard, uint len, byte* data, void* reserved)` | `80 5E 00 00 Lc <data>`（unblock） |
| `External_Authentication` | `int(hCard, uint p1, byte* resp8, ushort* sw)` | `CLA 82 P1 00 08 <resp>` |
| `HD_Application_Manager` | `int(hCard, uint apduLen, byte* apdu, byte* respBuf, ushort* sw)` | 通用 APDU 通道（5 参数，ret 0x14） |
| `HD_ChangePin` | 内部流程 = `Verify_Pin`(旧PIN) → `Write_Key`(写新 PIN 记录) | — |

**实机测绘结果（本卡，SN 01102001519176）**

| 探测 | 结果 |
|------|------|
| `Verify_Pin` P2=0x00 | **SW=0x6982 安全状态不满足**（参考数据存在，但未认证） |
| `Verify_Pin` P2=0x01/0x02/0x80/0x81/0x83/0x84 | **SW=0x6A88 参考数据未找到**（这些引用不存在） |
| `Verify_Pin` 全部 P2 用 Lc=0 | 一律 0x6700（先判长度，不区分 P2，无法用于枚举） |
| `External_Authentication` P1=0 | 0x63CF，**连续 10+ 次恒为 15 → 不递减、不锁定** |
| `External_Authentication` P1=1 | **0x6983 已锁定** |
| `External_Authentication` P1=2 | **0x6983 已锁定** |
| `Clear_DF`（`BF CE 00 00 00`） | **0x6982**（须已认证） |
| 任意 APDU 经 `HD_Application_Manager` 发 `00 2C` / `80 5E` | `rc=-300`，SW 未回填 → **被 DLL 层拦截，未到卡** |
| `HD_VerifyPin(新PIN)` | -1（走 0x6983 分支，与 P1=1 已锁一致） |

**P1=0 密钥验证器**：由于 `HD_ClearDir` 的认证只是「`Get_Challenge` → 内部函数 `sub_8DC0(challenge,8,out,key16,0)` 算响应 → `External_Authentication(P1=0)`」，
可用 **按 RVA 直接调用内部函数**（`sub_8D10` @0x8D10 变换、`sub_8DC0` @0x8DC0 计算）自行构造响应，
从而在 **P1=0（唯一不锁定）通道** 上验证任意候选密钥（`LncaProbe --key <候选>`）。

自检：用 SDK 内置常量 `637974627968797873796B7968620831` 自算响应 → `SW=0x63CF`，
**与 `HD_ClearDir` 内部实测结果完全一致** ⇒ 验证器实现忠实可信。

已试候选（全部 0x63CF 失败）：SDK 内置常量 16B、内置随机常量 `A62F1A1D…F273947`、`SZD23B10`、`01102001519176`。

⇒ **结论**：本卡唯一未锁的认证通道是 P1=0 传输密钥；只要拿到该密钥（或放进候选清单命中），
即可通过 `Clear_DF` 完成完全格式化、并由 `HDJIT_ReloadPin`/`InitialCard` 重设 PIN。
穷举不可行（6~16 字节口令空间），只有「候选清单」有意义。

#### (8) 华大通用层被砍掉的解锁命令复用（2026-09-21）

**重要发现：`HD_hdcos480.dll`（华大通用 COS）保留了 LNCA 定制版（`HDCOS_LNCA.dll`）没有的命令**：

| 导出 | APDU | 状态 |
|------|------|------|
| `Get_Info` (0x2050) | `BF C8 00 00 0F` | **可用**：rc=15，SW=0x9000，返回固定 15 字节 `86 01 4D 56 34 FA FD 00 00 39 38 FA FD 9E 4B 00` |
| `Pin_Unblock` (0x27B0) | `84 24 00 P2 Lc <data>`（INS 0x24） | 长度校验：**只接受 12 或 18 字节**（其余 0x6700） |
| `Application_UnBlock` (0x24A0) | `84 18 00 00 04 <4B>` | 未测 |
| `Card_Block` (0x2500) / `Freeze_MF` (0x2000) | 私有 | 未测 |

**`Pin_Unblock` 实测（PUK 解锁通道）**：P2=0/1/2/3 × 候选 PUK(123456/111111/888888/666666/999999/000000) 全部返回
**SW=0x6984（Reference data invalidated）**，且**从不出现 0x63Cx 计数** ⇒ **该卡的「用户 PIN 解锁码(PUK)」同样已失效**（不是"猜错"，而是"引用已作废"）。

**至此认证通道测绘完整**：

| 通道 | 本卡结果 |
|------|----------|
| 外部认证 P1=0（传输密钥） | 未锁定（恒 0x63CF=15），但密钥 ≠ SDK 内置两把 |
| 外部认证 P1=1（用户 PIN） | `0x6983` 已锁定 |
| 外部认证 P1=2（管理员/SO） | `0x6983` 已锁定 |
| ISO VERIFY P2=0 | `0x6982`（受外部认证门控） |
| INS 0x24 解锁（PUK 计数） | `0x6984` 参考数据已失效 |
| `Clear_DF` / `HD_ClearDir` | 需已认证 → 不可达 |

**厂商工具与安装包调查**：`GP_ADM_LNCA.exe` 只调用 `HD_*` 证书类接口（无 SO PIN / 初始化 / 导入导出）；
`LNCA数字证书管家安装包.exe`（Inno）解出的是 Qt5 云驱动客户端，其 `data\Driver.ini` 给出驱动映射：
**华大 USBKey(vid_1677) → `LNCACSPSetup1070(Rsa&Sm2).exe`**（CSP v1.0.7.0）；该 CSP 包为 **ASPack 加壳**，
静态无法解包，需运行安装后才能取到其中的 COS DLL（**当前唯一未挖掘的密钥来源**）。
`LNCAUSBKey0.100.0.2Setup.exe`（→ `C:\Program Files (x86)\USBKeyActive\`）与管家安装目录均**不含 COS/密钥**。

#### (9) 终局结论：CSP 1.0.7.0 的密钥与 SDK 版完全一致（2026-09-21）

安装 `LNCACSPSetup1070(Rsa&Sm2).exe` 后，完整中间件落到 `C:\Windows\SysWOW64\`：

| 模块 | 与 SDK 版对比 | keyB(`cytbyhy…`)/keyA(`A62F1A1D…`)/0x11×8 |
|------|---------------|------------------------------------------|
| `HDCOS_LNCA.dll` | **哈希相同** | 4 / 3 / 1 |
| `HD_hdcos480.dll` | **哈希相同** | 0 / 0 / 0 |
| `GP_COS_LNCA.dll` | 哈希不同 | **4 / 1 / 1（与新 SDK 一致）** |
| `GP_COS_LNCA_RSA.dll`（SDK 无） | 新增 | **4 / 1 / 1** |
| `GP_COS_LNCA_SM2.dll`（SDK 无） | 新增 | **0 / 0 / 0（无内置密钥表）** |
| `SKF_APP_LNCA.dll`（SDK 无） | 新增 | 0 / 0 / 0 |
| `GP_IFD_LNCA.dll` | 哈希不同 | 0 / 0 / 0 |
| `HD_SortDev.dll` / `JIT_USBKEY_HD.dll` | 相同/新增 | 1 / 1 / 1、0/0/0 |

→ **即便最新 CSP，内置密钥表仍是那两把，不存在第三把。**
另外按「描述符+密钥」结构体形态（`0001010000000511`+keyA、`0002020000000522`+keyB 等）重试，结果仍为 `0x63CF`。

**最终判定**：本卡的个人化传输密钥与该型号 SDK 的内置密钥不同（该批次/该客户被替换），
且用户 PIN、PUK、管理员通道均已锁定/失效 ⇒ **软件侧无法自救**，须由 LNCA 或签发 CA
提供传输密钥（拿到后本软件已可就地完成「完全格式化 + 重设 PIN + 验证」）。

#### (4) 复现命令

```powershell
# 工具归档位置（2026-09-21 起统一收纳于此）
$R = "G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\_逆向分析"
$P = "$R\probe\LncaProbe\bin\Release\net8.0\LncaProbe.exe"

# 只读状态快照（不消耗任何认证计数，可反复执行）
& $P --jitstate
& $P --state 0

# 逐层定位（不加 --noerase 会真的发 Clear_DF）
& $P --deep 0 [--noerase]

# P1=0 通道候选密钥验证（不锁定，可安全试）
& $P --key "<候选密钥>"
pwsh -File "$R\tools\lnca_keytest.ps1"

# 完整格式化 + 重设 PIN（破坏性）：port、新PIN、SO口令
& $P --format 0 <新PIN> <SO口令>
```

---

**分析日期**：2026-09-20
**分析方法**：Capstone 静态反汇编 + PE 导出/导入表解析 + 交叉引用扫描（`Library/LNCA USBKey Manage/_逆向分析/tools/disasm_lnca.py`）
**版本**：1.4
