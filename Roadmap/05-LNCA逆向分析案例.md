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
2. **`ImportPfx` 私钥导入**：`USBKey_WritePubPriKey` 要求私钥先以设备公钥加密（`dPubEncKey`/`dAlgID`），加密协议需逆向 `HDJIT_ImportRsaPrivateKey` 链路确认。当前采用设备内 `GenRSAKeyPair` 兜底。
3. **`DeleteContainer` 定位方式**：需确认证书容器与 Key 内文件的对应关系。
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
| `DeleteContainer` | `USBKey_DelFile`（待确认） |
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
**版本**：1.2
