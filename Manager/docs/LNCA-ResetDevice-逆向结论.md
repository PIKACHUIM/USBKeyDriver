# LNCA「重置设备初始化」逆向结论与修复

> 目标：解决 LNCA 平台 `ResetDevice`（重置设备初始化）不生效的问题。
> 逆向对象：`Library/LNCA USBKey Manage/` 下的 DLL 链。
> 工具：capstone（静态反汇编，`tools/disasm_*.py` / `tools/dump_*.py`）。

## 一、DLL 分层结构（逆向确认）

```
GP_ADM_LNCA.exe / GP_CLT_LNCA.exe      GUI 管理端（LoadLibrary + GetProcAddress 动态加载）
  └── JIT_USBKEY_HD.dll                高层 SDK（44 个 USBKey_* 导出，按名字导出）
  └── HD_HardAPI.dll                   硬件高层 API（HSConnectDev/HSErase/...，17 个导出）
        └── LoadLibrary("HD_SortDev.dll")  真实实现层（HS_ConnectDev/HS_Erase/...）
              └── HDCOS_LNCA.dll            COS 命令层（104 个导出，HD_IC_RESET/Clear_DF/HD_ClearDir/HD_SPWD...）
                    └── GP_IFD_LNCA.dll     IFD 读卡器层（HD_ResetCard/HD_ApduT0...）
                          └── CIDCUSB.sys   内核驱动
```

## 二、核心发现：InitKey/Reset 是「空壳」

对 `JIT_USBKEY_HD.dll` 静态反汇编确认：

- `USBKey_InitKey`（RVA 0x42B0，ord 63）：`__stdcall`，7 参数（`ret 0x1c`），
  函数体只打印 `"USBKey_InitKey Start..."` / `"USBKey_InitKey Success"` 后 `xor eax,eax; ret`。
  其 `call 0x48d0` 目标是 `ret`（空函数）——**未调用任何真实设备操作，恒返回 0**。
- `USBKey_Reset`（RVA 0x4400，ord 69）：`__stdcall`，3 参数（`ret 0xc`），同为调试空壳。

结论：**依赖 `USBKey_InitKey`/`USBKey_Reset` 实现的 `ResetDevice` 永远不会真正擦除设备。**

## 三、真正的初始化链路（已还原签名）

| DLL | 函数 | RVA | 调用约定 | 签名 |
|-----|------|-----|---------|------|
| HD_HardAPI.dll | `HSConnectDev` | 0x1230 | stdcall, ret 8 | `int HSConnectDev(int devIndex, int* phDev)` |
| HD_HardAPI.dll | `HSDisconnectDev` | 0x1280 | stdcall, ret 4 | `int HSDisconnectDev(int hDev)` |
| HD_HardAPI.dll | `HSErase` | 0x1290 | stdcall, ret 4 | `int HSErase(int hDev)`（内部调 `[0x10009e0c]`） |
| HD_SortDev.dll | `HS_ConnectDev` | 0x1260 | stdcall, ret 8 | `int HS_ConnectDev(int devIndex, int* phDev)` |
| HD_SortDev.dll | `HS_Erase` | 0x1340 | stdcall, ret 4 | `int HS_Erase(int hDev)`（发 APDU 校验 SW=0x9000） |
| HD_SortDev.dll | `HS_CheckStructure` | 0x14F0 | stdcall, ret 4 | `int HS_CheckStructure(int hDev)` |
| HDCOS_LNCA.dll | `HD_IC_RESET` | 0x10C0 | stdcall, ret 8 | `int HD_IC_RESET(handle, byte* atr)`（卡复位，校验 0x9000） |
| HDCOS_LNCA.dll | `Clear_DF` | 0x19C0 | — | 清除 DF 文件系统 |
| HDCOS_LNCA.dll | `HD_ClearDir` | 0x67D0 | — | 清除目录 |
| HDCOS_LNCA.dll | `HD_SPWD` | 0x2B00 | — | 设置密码 |
| HDCOS_LNCA.dll | `InitialCard` | 0x73F0 | ret 0x10 | **空壳**（`or eax,0xffffffff; ret` 恒返回 -1） |

错误码约定：`0x66` = 设备索引越界，`0x67` = 句柄无效，`0x9000` = APDU 成功。

## 四、修复方案

`LncaProvider.ResetDevice` 改为优先走 `HD_HardAPI.dll` 的真实链路：

```
HSConnectDev(devIndex, &hDev) → (可选 HSVerifySOPin) → HSErase(hDev) → HSChangeUserPin(hDev, 旧PIN, 新PIN) → HSDisconnectDev(hDev)
```

若 `HD_HardAPI.dll` 不存在（非关键路径），回退到旧的 `USBKey_InitKey`（空壳，仅兼容）。

> ⚠️ **本节的「HSErase → HSChangeUserPin」修复方案已被 2026-09 决定性实测推翻，详见第八节。**
> 该方案只能擦除「存储层文件系统」，无法重置 COS 层 PIN。

## 五、涉及改动文件

- `Manager/src/USBKey.Core/UsbKey/LncaHardApiNative.cs`（新增）——HD_HardAPI.dll 委托定义
- `Manager/src/USBKey.Core/UsbKey/LncaProvider.cs`——加载 HD_HardAPI.dll + 重写 ResetDevice

## 六、逆向工具脚本（tools/）

- `dump_exports_pure.py`：无依赖解析 PE 导出表（判定名字 vs 序号导出）
- `dump_imports.py`：解析导入表（判定动态加载链）
- `disasm_*.py`：capstone 静态反汇编关键函数，依据 `ret imm16` 反推参数个数
- `dump_hdcos_exports.py`：修正字段布局后正确解析 HDCOS/HD_HardAPI 导出

## 七、决定性实测（2026-09，x86 宿主 + 实机）

用 `tools/LncaEraseProbe`（x86）直接调用 HD_HardAPI.dll 实测，结果：

```
HSConnectDev(idx=0)   rc=0x0  hDev=0x74B9740   ← 连接成功
HSGetSerial           rc=0x0  sn="01519176"    ← 序列号读出
HSGetTotalSize        rc=0x0  total=64253      ← 容量读出
HSVerifyUserPin(123456) rc=0x70                ← 存储层 PIN 校验失败
HSErase               rc=0x0                    ← 存储层擦除「成功」
擦除后 HSVerifyUserPin(各种默认PIN) 全部 rc=0x70  ← PIN 未变！
```

### 关键事实

1. **x86 架构**：三个 DLL 均为 pei-i386（32 位），宿主必须以 x86 运行，否则
   `LoadLibrary` 返回 `err=193 (ERROR_BAD_EXE_FORMAT)`。此前 x64 探针因此失败。
2. **HS 层 = 存储层，与 COS 层是两个独立子系统**：
   - `HD_HardAPI.dll → HD_SortDev.dll`（`HS_*`）：管「文件系统存储」，PIN 是「文件访问 PIN」。
   - `HDCOS_LNCA.dll`（`HD_*`）：管「证书/密钥/User PIN/SO PIN」（COS 卡操作系统）。
   - 用户侧「默认 123456 验证失败返回 0x3EE」的 PIN 在 **COS 层**，`HSErase` 根本碰不到它。
3. **`HSErase` 擦除后 COS PIN 保持不变**——实测擦除成功后，存储层 PIN 校验仍返回 0x70。
4. **`HSChangeUserPin` / `HSReWriteUserPin` 均需「旧 PIN」**（内部先 strlen 校验旧 PIN，再发
   APDU 验证），在旧 PIN 未知时必然失败（返回 0x69/0x70）。

## 八、决定性结论

**在 User PIN 与 SO PIN 均未知（忘记 PIN）的情况下，公开 DLL 接口中不存在「无需认证的
初始化重置 PIN」入口。**

| 候选函数 | 层 | 结论 |
|---------|----|------|
| `HS_Erase`（HSErase） | 存储层 | 只擦文件系统，**不重置 COS PIN**（已实测） |
| `InitialCard`（HDCOS） | COS | **空 stub**，`or eax,0xffffffff; ret 0x10` 恒返回 -1 |
| `HD_IC_RESET` / `HD_Open`（HDCOS） | COS | 实为 DllMain 初始化代码（加载 GP_IFD_LNCA.dll 绑定函数指针），非卡片重置 |
| `HD_ResetCard`（GP_IFD） | IFD | 芯片级复位（断电重启），不重置 PIN |
| `HS_ChangeUserPin` / `HS_ReWriteUserPin` | 存储层 | 需旧 PIN 先验证，无法用于忘记 PIN |
| `HD_Application_Manager`（HDCOS） | COS | 仅 GET RESPONSE（INS 0xC0）封装 |

**标准初始化流程**需厂商「传输密钥（Transport Key）+ 外部认证（External Authenticate）」，
该密钥不在公开 DLL 中。

### 错误码对照（本次实测 + 反汇编确认）

| 返回码 | 层 | 含义 |
|--------|----|------|
| `0x00` | 通用 | 成功 |
| `0x66` (102) | HS | 设备索引越界 |
| `0x67` (103) | HS | 句柄无效 / 参数为空 |
| `0x69` (105) | HS | PIN 长度不合法（<2 或 >16） |
| `0x70` (112) | HS | 存储层 PIN 验证失败（密码错误） |
| `0x76` (118) | HS | HS_ReWriteUserPin 重写失败 |
| `0x3EE` (1006) | JIT | `USBKey_VerifyPin` 失败（底层 `HD_VerifyPin` 返回负数） |
| `0x3F0` (1008) | JIT | 参数无效（type 非 0/1） |
| `0x63Cx` (SW) | COS | PIN 验证失败，x = 剩余尝试次数（x=0 表示永久锁定） |
| `0x6983` | COS | PIN 已锁定 |
| `0x9303` | COS | 认证方法被锁 |
| `0x9000` (SW) | COS | APDU 成功 |

### 对 `LncaProvider.ResetDevice` 的影响

`ResetDevice` 已改为「诚实报告」：执行存储层 `HSErase` 后，用 `HSVerifyUserPin` 验证常见
默认 PIN 是否可验证，并把结论写入日志，**绝不假装「COS PIN 已重置」**。若需真正恢复 COS
层 PIN，需厂商传输密钥（当前不可得），或改用带「初始化密钥」的专用初始化工具。

## 九、PUK 解锁机制（2026-09 补充逆向，决定性收尾）

在「忘记 PIN」方向上的最后一击，彻底逆向并实测了 **PUK（解锁 PIN）重置用户 PIN** 的完整链路。

### 9.1 JIT 层入口（`JIT_USBKEY_HD.dll`）

| 函数 | RVA | 签名（ret 反推） | 语义 |
|------|-----|-----------------|------|
| `USBKey_UnlockPin` | 0x2230 | `int(hKey, unlockPin, unlockPinLen)`（ret 0xC） | 用 PUK 认证，把用户 PIN 重置为**硬编码 "111111"** |
| `USBKey_UserUnlockPin` | 0x4540 | `int(hKey, unlockPin, uLen, userPin, pLen)`（ret 0x14） | 用 PUK 认证，把用户 PIN 重置为**指定 userPin** |
| `USBKey_VerifyPin` | 0x4440 | `int(hKey, type, pin, pinLen)`（ret 0x10） | type=0 用户 PIN，type=1 管理员(SO) PIN |
| `USBKey_InitKey` | 0x42B0 | `int(hKey, userPin, operPin, unlockPin)`（ret 0x1C） | **空壳**，只打日志返回 0 |
| `USBKey_Reset` | 0x4400 | `int(hKey, rData, rLen)`（ret 0xC） | **空壳**，只打日志返回 0 |

关键反汇编证据（`USBKey_UnlockPin` 0x2264）：

```asm
0x2264: mov eax, [0x100273d8]   ; 读全局 "111111"
0x22C4: push 6                   ; 参数5 = 6
0x22C6: push edx                 ; 参数4 = "111111"（硬编码新 PIN）
0x22C7: push edi                 ; 参数3 = unlockPinLen
0x22C8: push ebx                 ; 参数2 = unlockPin（PUK）
0x22C9: push esi                 ; 参数1 = hDev
0x22CA: call [0x10021074]        ; → HDCOS_LNCA.dll!HDJIT_ReloadPin
```

### 9.2 底层实现（`HDCOS_LNCA.dll`）

`HDJIT_ReloadPin`（RVA 0xB780，ret 0x14 = 5 参数）：

```c
int HDJIT_ReloadPin(int hDev, const char* unlockPin, uint unlockPinLen,
                    const char* newPin, uint newPinLen);   // newPinLen 校验 6~16
```

APDU 流程（完整还原）：

```
1. Select_File(P1=0,P2=0)                    ; 选择 PIN 文件
2. 拷贝 unlockPin → 0x8d10 构造（DES 加密）
3. Get_Challenge (APDU 84 84 00 00 08)       ; 取 8 字节随机数
4. 0x8dc0 密钥变换（用固定传输密钥）
5. External_Authentication (APDU 80 82 ... 0D <8字节> 08)
6. 再次 Get_Challenge + 0x8dc0 + 加密 newPin
7. Write_Key (0x1aa0)                        ; 写新 PIN
```

**传输密钥（硬编码）**：16 字节 @ HDCOS RVA 0x19050：

```
hex: 63 79 74 62 79 68 79 78 73 79 6b 79 68 62 08 31
     "cytbyhyxsykyhb\x081"
```

`0x8ff0(hDev, type)` 是独立的「纯传输密钥外部认证」辅助函数（**不需要任何 PIN**），
被 `HD_DeleteContainer` 调用做鉴权（`call 0x8ff0; push 3` / `push 0x83`）。

### 9.3 实测结果（x86 探针 `tools/LncaUnlockProbe`）

| 测试 | 候选 | 结果 |
|------|------|------|
| 用户 PIN (type=0) | 123456 / 111111 / … | 全部 0x3EE（失败） |
| 管理员 PIN (type=1) | 12345678 / 11111111 / 88888888 / 00000000 / … | 全部 0x3EE |
| PUK（USBKey_UnlockPin / UserUnlockPin） | 24 个候选（6/8/12 位常见默认值） | 全部 0x3EE |

### 9.4 最终结论

1. **官方「初始化/重置」入口全部为空壳**（`USBKey_InitKey` / `USBKey_Reset` / `InitialCard`）。
2. **唯一真实的「重置 PIN」路径**是 `HDJIT_ReloadPin`（PUK 认证），但需要**正确的 PUK**。
3. **实测设备的所有 PIN（用户/SO/PUK）均已非出厂默认**，30+ 个常见候选全部验证失败。
4. **公开 DLL 接口中不存在「忘记所有 PIN」后的免认证重置入口**。恢复设备的唯一途径是：
   - 厂商提供**传输密钥**（`HDJIT_ReloadPin` 用的是 DLL 内置密钥，但该密钥与生产设备是否
     匹配需厂商确认，实测认证未通过）；
   - 或厂商提供**正确的 PUK / SO PIN**；
   - 或使用厂商**专用初始化工具**（带外部认证密钥）。

> 结论与本报告第八节一致，但本次补齐了「PUK 解锁链路」的完整逆向证据链，
> 使「无免认证重置入口」这一结论具备完整的函数级依据。
