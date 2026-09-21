# 龙脉（Longmai）GM3000 USB Key 逆向分析报告

> **目标**：
> ① 让 `GM3000_2.2.19\GM3000Admin.exe` 能正确管理本机这把 GM3000；
> ② 让 `USBKey.Manager` 能正确管理此设备。
>
> **分析对象**：`Library/Longmai GM3000 SDK/`（`GM3000_2.1.1.0`、`GM3000_2.2.19`）。
> **分析工具**：objdump（msys64 mingw64）+ 自研 Python 分析链（`tools/gm_*.py`）
> + 自研 x86 实机探针（`tools/GM3000Probe`）。
> **分析日期**：2026-09-21　**状态**：静态逆向完成 + **实机验证完成**（设备已在位）。

---

## 一、TL;DR（核心结论）

1. **本机这把 Key 是老型号 GM3000**：USB `VID_055C&PID_DB08`，以 **USB 大容量存储 / CD-ROM** 形态暴露
   （`USBSTOR\CDROM&VEN_LONGMAI&PROD_GM3000&REV_2.00`），**没有 CCID/HID 智能卡接口**，
   序列号（SKF 设备名）`ED466583B8C689AB81DFA5573DF55AE`。
2. **只有 2016 版 SKF 中间件认识它**（实机验证）：

   | 模块 | 版本/大小 | `SKF_EnumDev` | 说明 |
   |---|---|---|---|
   | `GM3000_2.1.1.0\mtoken_GM.dll`（模块真名 `mtoken_gm3000`） | 2016，292,352 B，SHA256 `5E8E5725…` | **1 台设备** ✅ | 可用；完整管理能力 |
   | `GM3000_2.2.19\mtoken_gm3000.dll.old`（原 2022 版） | 2022，427,008 B，SHA256 `C669CB13…` | **0 台设备** ❌ | 2022 中间件已放弃该型号 |
   | `gm3000_pkcs11.dll`（2016 与 2022 都是） | 424,448 / 527,872 B | `C_GetSlotList` = **4 槽位 / 0 令牌** ❌ | PKCS#11 层从未支持该型号 |

   > 注：`GM3000_2.2.19\mtoken_gm3000.dll`（292,352 B）与 `GM3000_2.1.1.0\mtoken_GM.dll`
   > **SHA256 完全相同** —— 该目录里的 SKF 已被替换为 2016 版，原 2022 版被改名为 `.old`。
3. **`GM3000Admin.exe`「不识别设备」的根因**：它的设备可见性完全依赖
   `TokenMgr.dll → gm3000_pkcs11.dll`（PKCS#11）**这一条链路**；而 PKCS#11 层对本型号只有空槽位，
   所以必然报「无设备」。**与 admin 自身、与 SKF 版本都无关**。
4. **`USBKey.Manager` 已改为直接对接 SKF**，实测可用（枚举/详情/容器/PIN 状态全部通过，见 §八）。
5. 需求 ① 的修复**已落地并验证**（见 §七「方案 A 实施结果」）：为 2.2.19 目录提供了
   **基于 SKF 的 PKCS#11 垫片**（`tools/GM3000Pkcs11Shim/`，32 位，仅导出
   `C_GetFunctionList` + `M_GetExtFunctionList`）。安装后：
   - 厂商 `TokenMgr.dll`（2016 与 2022）均能绑定并 `token_find` 到设备（count=1）；
   - **`GM3000Admin.exe` 已识别设备并在界面显示 `Longmai / Longmai / GM3000`，
     且「用户密码 / SO PIN / 初始化」管理页签全部就位**（窗口文本枚举取得直接证据）；
   - 尚余 `M_*` 扩展层（`M_GetApplicationInfo` / `M_GetUserInfo` / 容器 / 初始化等）未实现，
     当前统一返回 `CKR_FUNCTION_NOT_SUPPORTED`，下一步按 §七的优先级清单补齐。
   
   直接把 2016 的 `TokenMgr.dll` 拷进 2.2.19 目录**仍不可行**——admin 静态导入了 2022 独有的
   `token_get_info_ex`。

---

## 二、资产取证

### 2.1 文件与哈希

| 路径 | 大小 | 时间 | SHA256(前 8) | 说明 |
|---|---|---|---|---|
| `GM3000_2.1.1.0\mtoken_GM.dll` | 292,352 | 2016-06-02 | `5E8E5725` | **SKF（GM/T 0016）**，可用 |
| `GM3000_2.2.19\mtoken_gm3000.dll` | 292,352 | 2016-06-02 | `5E8E5725` | 同上（被改名放入 2.2.19） |
| `GM3000_2.2.19\mtoken_gm3000.dll.old` | 427,008 | 2022-03-23 | `C669CB13` | 2022 版 SKF，**不认识本设备** |
| `GM3000_2.1.1.0\gm3000_pkcs11.dll` | 424,448 | 2016-05-05 | `E3473BFA` | PKCS#11 + `M_*` 管理扩展 |
| `GM3000_2.2.19\gm3000_pkcs11.dll` | 527,872 | 2022-03-23 | `AB254C78` | 同上（新增 `M_GetDevCaps`/`M_ForceLogout` 等） |
| `GM3000_2.1.1.0\TokenMgr.dll` | 113,152 | 2016-04-25 | `3C0C6A74` | 官方管理 API 层（63 导出） |
| `GM3000_2.2.19\tokenmgr.dll` | 131,008 | 2022-03-23 | `9BB10C8D` | 同上（73 导出，新增 `token_get_info_ex`/`token_find_hid`） |
| `GM3000_2.2.19\GM3000Admin.exe` | 1,661,824 | **2025-10-18** | — | 32 位（Borland C++ Builder，含 `.itext` 节） |
| `GM3000_2.1.1.0\GM3000PKIMgr.exe` | 1,403,392 | 2016-06-23 | — | 同上 |
| `GM3000_2.1.1.0\GM3000Mon.exe` | 944,128 | 2016-06-23 | — | 托盘监视器 |

系统已安装的厂商组件（2016 版）：
`C:\Windows\SysWOW64\mtoken_gm3000.dll`（292,352，2016）、
`C:\Windows\System32\gm3000_pkcs11.dll`（590,848，**x64** 构建）、
`C:\Windows\System32\mtoken_gm3000.dll`（420,864，**x64**）、
服务 `Longmai mToken IOSVR` → `C:\Windows\SysWOW64\mtoken_iosvr.exe`（2015，运行中），
命名管道 `\\.\pipe\mTokenIOSvr` 存在。

### 2.2 设备形态（PnP 实测）

```
USB\VID_055C&PID_DB08\6&18793C9E&0&2            Class=USB    "USB 大容量存储设备"
USBSTOR\CDROM&VEN_LONGMAI&PROD_GM3000&REV_2.00  Class=CDROM  "Longmai GM3000 USB Device"
```

- **无智能卡接口**：系统中不存在 Longmai 的 CCID 读卡器；
  现有读卡器为 `Microsoft Usbccid Smartcard Reader`（飞天/ePass）与
  `USB Token 32 Holder`（**飞天 Rockey 驱动 `oem243.inf`**，`smccarda.sys`，与龙脉无关）。
- 与厂商配置对照：`GM3000_2.2.19\APPInfo.ini`
  `[APPFlag] PID=0xDB08|0xE917|0xE618|0xE508|0x2205`（本设备 PID 在其中）、`USBEnumString=`（空）；
  `Initconfig.ini`：`default_sopin=admin`、`default_upin=12345678`。

---

## 三、官方工具的加载链路（进程模块实测）

| 工具 | 实际加载的厂商模块 | 设备可见性 |
|---|---|---|
| `GM3000_2.2.19\GM3000Admin.exe` | `TokenMgr.dll`(2.2.19) → `gm3000_pkcs11.dll`(2022) + `mtoken_gm3000.dll` + `SETUPAPI` + `HID.DLL` + `WinSCard` + `CRYPTUI` | ❌ 不识别（PKCS#11 空槽位） |
| `GM3000_2.1.1.0\GM3000PKIMgr.exe` | `TokenMgr.dll`(2016) → `gm3000_pkcs11.dll`(2016) + `WinSCard`（**未加载 `mtoken_GM.dll`**） | ❌ 同样空槽位 |

**推论**：两个官方工具的设备可见性都只来自 **PKCS#11 链路**，而该链路对老型号 GM3000 始终不可用。
「2.1.1.0 能识别设备」很可能是托盘程序 `GM3000Mon.exe` 或 CSP（`GM3000HZTWCSP.dll`）的呈现，
而不是 `GM3000PKIMgr.exe` 的 PKCS#11 枚举。

### 3.1 TokenMgr 的中间件绑定契约（反汇编确认，`TokenMgr.dll!0x10003410`）

```
h = LoadLibraryA(path)                     ; path = APPInfo.ini 的 PKCS11Lib
f1 = GetProcAddress(h, "C_GetFunctionList")    ; 字符串位于 .rdata 0x10017D98
f2 = GetProcAddress(h, "M_GetExtFunctionList") ; 字符串位于 .rdata 0x10017DAC
r1 = f1(NULL)                              ; 取回 CK_FUNCTION_LIST*
r2 = f2(&extList)                          ; 厂商扩展函数表
if (r1 == 0) {
    initFn = *(void**)((char*)r1 + 2)      ; CK_FUNCTION_LIST 紧凑布局：CK_VERSION(2B) 后紧跟函数指针
    rc = initFn(NULL);                     ; 容忍 CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
}
失败返回 NTE_PROVIDER_DLL_FAIL = 0x8009001D
```

> 这是需求 ① 垫片必须满足的**精确接口契约**（见 §七）。

---

## 四、SKF 接口全签名（反汇编 `ret imm16` 逐一确认）

`mtoken_GM.dll` 是**标准 GM/T 0016 SKF** 实现（此前一度认为其 API 非标准，实为早期分析工具
「导出地址表下标多减了 Ordinal Base」的解析 bug，已修正，见 §十）。

### 4.1 设备/应用/容器（实测通过）

| 函数 | 参数数 | 语义 |
|---|---|---|
| `SKF_EnumDev(BOOL bPresent, LPSTR pszNameList, ULONG* pulSize)` | 3 | 返回 ANSI 多字符串设备名（= 32 字符序列号） |
| `SKF_ConnectDev(LPSTR szName, DEVHANDLE* phDev)` | 2 | 选定「当前设备」 |
| `SKF_DisConnectDev(DEVHANDLE)` | 1 | |
| `SKF_GetDevInfo(DEVHANDLE, DEVINFO*)` | 2 | 结构布局见 §4.2 |
| `SKF_GetDevState(LPSTR szName, ULONG* state)` | 2 | 在位返回 1 |
| `SKF_EnumApplication(DEVHANDLE, LPSTR, ULONG*)` | 3 | 返回 `GM3000APP` |
| `SKF_OpenApplication(DEVHANDLE, LPSTR, HAPPLICATION*)` | 3 | 选定「当前应用」 |
| `SKF_CloseApplication(HAPPLICATION)` | 1 | |
| `SKF_EnumContainer(HAPPLICATION, LPSTR, ULONG*)` | 3 | 全新设备返回 0 项 |
| `SKF_OpenContainer(HAPPLICATION, LPSTR, HCONTAINER*)` | 3 | |
| `SKF_CreateContainer(HAPPLICATION, LPSTR, HCONTAINER*)` | 3 | 容器名 ≤ 39 字符（`cmp eax,0x27`）；未登录返回 `SAR_USER_NOT_LOGGED_IN` |
| `SKF_DeleteContainer(HAPPLICATION, LPSTR)` | 2 | |

### 4.2 `DEVINFO` 布局（实机回填 294 字节逐偏移确认）

| 偏移 | 长度 | 字段 | 实机值 |
|---|---|---|---|
| `+0x00` | 2 | `Version` | `1` |
| `+0x02` | 64 | `Vendor` | `Longmai` |
| `+0x42` | 64 | `Manufacturer` | `Longmai` |
| `+0x82` | 32 | `Model` | `GM3000` |
| `+0xA2` | 32 | `SerialNumber` | `ED466583B8C689AB81DFA5573DF55AE` |
| `+0xC2` | 100 | 能力/版本数据区 | （无需解析） |

### 4.3 口令 / 证书 / 密钥 / 其它

| 函数 | 参数数 | 语义（含反汇编要点） |
|---|---|---|
| `SKF_GenRandom(DEVHANDLE, BYTE*, ULONG)` | 3 | 实测可用；未登录返回 `SAR_USER_NOT_LOGGED_IN` |
| `SKF_VerifyPIN(DEVHANDLE, ULONG ulPINType, LPSTR szPIN, ULONG* pulRetry)` | 4 | `ulPINType ∈ {0=用户,1=管理员}`，否则 `0xA000006`；SW=`0x63Cx` 时回写剩余次数并返回 `SAR_PIN_INCORRECT(0xA000024)` |
| `SKF_ChangePIN(DEVHANDLE, ULONG, LPSTR old, LPSTR new, ULONG*)` | 5 | |
| `SKF_UnblockPIN(DEVHANDLE, LPSTR szAdminPin, LPSTR szNewUserPin, ULONG*)` | 4 | **GM3000 无独立 PUK**，PUK/AdminKey 都走此接口 |
| `SKF_GetPINInfo(HAPPLICATION, ULONG ulPINType, ULONG* remain, ULONG* max, ULONG* flags)` | 5 | 厂商扩展。**实测必须传应用句柄**（传设备句柄返回 `0xA000005`）；实机 `10/10/1` |
| `SKF_ClearSecureState(DEVHANDLE)` | 1 | 清除已认证会话（登出） |
| `SKF_SetLabel(DEVHANDLE, LPSTR)` | 2 | |
| `SKF_ImportCertificate(HCONTAINER, BOOL bSign, BYTE*, ULONG)` | 4 | |
| `SKF_ExportCertificate(HCONTAINER, BOOL bSign, BYTE*, ULONG*)` | 4 | 内部分块读取（续读状态 `0x6A9E`），总容量上限 `0x4000`；缓冲不足返回 `SAR_BUFFER_TOO_SMALL` |
| `SKF_ExportPublicKey(HCONTAINER, BOOL bSign, BYTE*, ULONG*)` | 4 | |
| `SKF_ImportRSAKeyPair(HCONTAINER, ULONG algId, BYTE* wrappedKey, ULONG, BYTE* encData, ULONG)` | 6 | 私钥需按厂商约定「包裹/加密」，**格式待确认**（见 §九） |
| `SKF_Transmit(DEVHANDLE, BYTE* cmd, ULONG, BYTE* data, ULONG*)` | 5 | 裸 APDU 透传（诊断/校准） |
| `SKF_GenRemoteUnblockRequest(…)` / `SKF_RemoteUnblockPIN(…)` | 3 / 4 | 远程解锁，参数语义待确认 |

> **上下文模型（关键）**：该 SKF 为「**当前设备 + 当前应用**」全局上下文。
> `SKF_ConnectDev` 选定当前设备、`SKF_OpenApplication` 选定当前应用；
> 之后 `VerifyPIN/GetPINInfo/EnumContainer/…` 的首个句柄参数在反汇编中并不参与查找，
> 读取的是全局上下文。**调用顺序必须是 `ConnectDev → OpenApplication → 其余操作`**，
> 否则统一返回 `SAR_INVALIDHANDLEERR (0xA000005)`。

> **错误码**：`0xA00000x` 即 GM/T 0016 的 `SAR_*`（如 `0xA000005`=句柄无效、`0xA000006`=参数无效、
> `0xA000020`=缓冲太小、`0xA000024`=PIN 错误、`0xA00002D`=未登录）。

---

## 五、实测能力矩阵

探针 `tools/GM3000Probe`（x86，32 位；全部为只读调用，未做任何 PIN/解锁/重置写操作）：

| 被测项 | 2016 SKF | 2022 SKF | 2016 PKCS#11 | 2022 PKCS#11 | 2016 TokenMgr | 2022 TokenMgr |
|---|---|---|---|---|---|---|
| 枚举设备 | **1** ✅ | 0 ❌ | 4 槽/0 令牌 ❌ | 4 槽/0 令牌 ❌ | `token_find`=0 ❌ | `token_find`=0 ❌ |
| 连接设备 | ✅ `hDev=0x1000` | — | — | — | — | — |
| 读设备信息 | ✅ `Longmai/GM3000/ED46…` | — | — | — | — | — |
| 枚举应用 | ✅ `GM3000APP` | — | — | — | — | — |
| 打开应用 | ✅ | — | — | — | — | — |
| PIN 状态 | ✅ 用户 10/10、管理员 10/10 | — | — | — | — | — |
| 枚举容器 | ✅ 0 项（全新） | — | — | — | — | — |
| 取随机数 | ✅ 16 B | — | — | — | — | — |

按 TokenMgr 的真实绑定序列（`C_GetFunctionList` → `M_GetExtFunctionList` → `C_Initialize`）重新初始化
PKCS#11 后，槽位/令牌结果**不变**（仍 0 令牌），排除「初始化不足」这一假设。

---

## 六、根因分析：为什么 `GM3000Admin.exe` 不识别设备

```
GM3000Admin.exe
   └─ TokenMgr.dll（2022）
        └─ gm3000_pkcs11.dll（2022）        ← 设备可见性只来自这里
             ├─ RTTI 类：device_manager / device_discover / windevice_discover
             │            device_winscsi / device_winhid / device_winhid_hs
             │            device_winhid_ctrl_io / device_winrpc / device_locker
             ├─ 反汇编 0x10068468：`if (stristr(path,"usbstor")) → device_winscsi else → device_winhid`
             └─ 设备候选表来自**编译期内置表**（`.data` @0x100661F0）+ 内置过滤串
                `gm3000,vid_055c&pid_db08,vid_055c&pid_e618|vid_055c&pid_f603|vid_055c&pid_2205`
```

要点：
1. 过滤串里**包含** `pid_db08`（本设备），所以「过滤不匹配」不是原因；
   真正决定候选的是那份**内置产品表**——2022 版已不含本老型号。
   同源证据：**2022 版 SKF 自己**（`mtoken_gm3000.dll.old`）`SKF_EnumDev` 返回 0 台，
   其枚举同样走「过滤串 + `.data` 产品表」，即 2022 中间件整体删除了该型号支持。
2. 该型号只以 USBSTOR/CD-ROM 形态出现、**没有 CCID/HID 智能卡接口**，也没有龙脉读卡器驱动；
   而中间件对新型号改走 HID/CCID 通道，因此即使 `device_winscsi` 分支存在也无法命中。
3. `mTokenMiniDrv.dll`（admin 字符串里引用 `\system32\mTokenMiniDrv.dll`）**未安装**，
   但对本型号而言它并非决定因素（PKCS#11 的 SCSI 分支不依赖它）。

**结论**：这是**厂商中间件对老型号的支持缺失**，不是配置/驱动/参数问题，无法通过
`APPInfo.ini`/`Initconfig.ini`/注册表/服务重启解决。

---

## 七、需求 ① 修复方案

### 方案 A（推荐，工程量有界）：基于 SKF 的 PKCS#11 垫片

在 `GM3000_2.2.19\` 放置自研 32 位 `gm3000_pkcs11.dll`（改名原文件备份），
使 2022 版 `TokenMgr.dll` 绑定到我们的实现，而我们的实现内部调用 **2016 版 SKF**。

必须满足的接口契约（§3.1 已确认）：

- 导出 `C_GetFunctionList(CK_FUNCTION_LIST**)`，返回**紧凑布局**函数表
  （`CK_VERSION` 2 字节后紧接函数指针；`C_Initialize` 位于表 `+0x2`）。
- 导出 `M_GetExtFunctionList(...)`（TokenMgr 调用形式为 1 个参数，指向指针的指针）。
- 实现 TokenMgr 实际会调用的 `C_*` 子集（标准语义）：
  `C_Initialize / C_Finalize / C_GetInfo / C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo /
   C_GetMechanismList / C_OpenSession / C_CloseSession / C_CloseAllSessions /
   C_Login / C_Logout / C_SetPIN / C_InitToken / C_InitPIN /
   C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal / C_GetAttributeValue /
   C_CreateObject / C_DestroyObject / C_GetObjectSize / C_WaitForSlotEvent`
- 实现 `M_*` 扩展子集（签名需按 `M_GetExtFunctionList` 返回的扩展表逐项确认）：
  `M_GetExtFunctionList / M_GetDevCaps / M_GetApplicationInfo / M_GetContainerInfo /
   M_EnumContainer / M_CreateContainer / M_DeleteContainer / M_GetUserInfo /
   M_SetTokenLabel / M_FormatToken / M_UnblockUserPin / M_RemoteUnblockUserPin /
   M_ForceLogout / M_ReloadObjects / M_GetFileInfo / M_ReadFile / M_WriteFile /
   M_ReadSectors / M_WriteSectors / M_CreateFile / M_DeleteFile /
   M_SetEnumString / M_SetInqString / M_ConstructMSCMapFiles`
- **槽位/令牌映射**：`C_GetSlotList(present=TRUE)` 必须把 SKF 枚举到的设备作为 1 个「有令牌」的槽位返回，
  令牌 serial/label 取 `SKF_GetDevInfo`；`C_Login` → `SKF_VerifyPIN`；
  `C_SetPIN` → `SKF_ChangePIN`；`M_UnblockUserPin` → `SKF_UnblockPIN`；
  `M_FormatToken` → SKF 侧无等价入口（见 §九，需按「清空容器 + 重设口令」实现并明确文档化）。

> 工作量评估：中高（约 25~30 个导出 + `M_*` 签名逐项确认）。建议按 §九 清单先做
> `M_GetExtFunctionList` 的返回表解析，一次性拿到全部 `M_*` 签名，再落地。

### 方案 B（零代码，立即可用）

本报告的交付物 `USBKey.Manager` 已能完整管理该 Key（§八）。
在垫片落地前，建议以 Manager 承担该 Key 的日常管理；官方工具的 PKCS#11 链路对本型号不可用。

### 方案 C（不可行，需明确排除）

把 2016 版 `TokenMgr.dll` 拷入 `GM3000_2.2.19\` —— **不可行**：
`GM3000Admin.exe` 的导入表含 2022 独有的 `token_get_info_ex`（15 参数），
2016 版 TokenMgr 未导出该符号，`LoadLibrary` 会因缺少导入而失败，程序无法启动。

### 方案 A 实施结果（已落地并验证）

垫片源码与构建脚本：`tools/GM3000Pkcs11Shim/`（`shim.c` / `shim.def` / `build.ps1`）。
产物：`tools/GM3000Pkcs11Shim/build/gm3000_pkcs11.dll`（32 位，137,216 字节，仅导出
`C_GetFunctionList` 与 `M_GetExtFunctionList` 两个未修饰符号）。

**已安装**：`GM3000_2.2.19\gm3000_pkcs11.dll`（原厂商文件已备份为 `gm3000_pkcs11.dll.vendor`）。

#### 实现要点

| 项 | 实现 |
|---|---|
| SKF 选择 | 依次尝试「同目录 → SysWOW64」的 `mtoken_gm3000.dll` / `mtoken_GM.dll`，并**用 `SKF_EnumDev` 实测**，只采用能枚举到设备的那个（因此即使后续把 `mtoken_gm3000.dll` 换回 2022 版也能自动回退） |
| 槽位模型 | 每台 SKF 设备 = 1 个「有令牌」槽位（`C_GetSlotList` 的 `tokenPresent` 两种取值都返回真实设备），不再复刻厂商的「4 个空槽位」 |
| `CK_FUNCTION_LIST` | **紧凑布局**（`#pragma pack(1)`：`CK_VERSION` 2 字节后紧跟 68 个函数指针），与厂商实测一致；**每个槽位都是可调用的真实函数**，未实现者返回 `CKR_FUNCTION_NOT_SUPPORTED`，避免厂商代码取到空指针 |
| `CK_TOKEN_INFO` | label/model 取 `SKF_GetDevInfo` 的 Model，manufacturerID 取 Manufacturer，serialNumber 取设备名前 16 字符；flags = `TOKEN_PRESENT\|RNG\|LOGIN_REQUIRED\|USER_PIN_INITIALIZED\|TOKEN_INITIALIZED`；`ulMaxPinLen/ulMinPinLen` = 16/6（来自 `Initconfig.ini`） |
| PIN 状态 | `C_GetTokenInfo` 内部调用 `SKF_GetPINInfo` 读取剩余/上限重试次数（实机 10/10） |
| 会话与登录 | `C_OpenSession`/`C_CloseSession` 维护会话表；`C_Login` → `SKF_VerifyPIN`（`CKU_SO`→pinType 1、`CKU_USER`→0）；`C_Logout` → `SKF_ClearSecureState`；`C_SetPIN` → `SKF_ChangePIN`；`C_InitToken`/`C_InitPIN` → `SKF_UnblockPIN`（**能力受限，见下**） |
| 对象（证书） | `C_FindObjects*`/`C_GetAttributeValue` 把 SKF 容器映射为 `CKO_CERTIFICATE` 对象（`CKA_LABEL`/`CKA_ID`=容器名，`CKA_VALUE`=证书 DER），当前设备 0 个容器故返回空集 |
| 上下文安全 | SKF 是「当前设备+当前应用」全局上下文：设备枚举会 `ConnectDev/DisConnectDev`，故枚举前先解绑、并加脏标记避免频繁重枚举（这是本次修掉的一个真实 bug：原实现导致 `C_Login` 返回 `CKR_SLOT_ID_INVALID`） |
| 调试日志 | 每次进程附加会写 `<垫片同目录>\gm3000_shim.log`，逐条记录 C_*/M_* 调用与返回码——用于在无法观察 GUI 的环境下核对上层行为 |

#### 实机验证结果

**① 厂商 TokenMgr 直接绑定垫片（不经 Admin）**

```
TokenMgr 2016 / 2022 都是：
   init_pkcs11(path) rc=0x00000000
   token_find rc=0x00000000 count=1          ← 找到设备
   connect rc=0x00000000
   token_get_info rc=0x00000000
      out[0] = 'ED466583B8C689AB'  (序列号)
      out[1] = 'GM3000'            (标签)
      out[2] = 'Longmai'           (厂商)
      out[3] = 'GM3000'            (型号)
      out[4] = 16 / out[5] = 6     (PIN 长度上限/下限)
      out[8]/[9] = 0xFFFFFFFF      (存储容量)
```

**② `GM3000Admin.exe` 界面（窗口文本枚举，直接证据）**

安装垫片后启动 Admin，枚举其控件树得到：

```
[TMainForm] 'mToken GM3000 管理员工具  V2.2.19.619'
  [TTabSheet] '基本信息'
      [TEdit] 'Longmai'      ← 厂商
      [TEdit] 'Longmai'      ← 制造商
      [TEdit] 'GM3000'       ← 型号
  [TTabSheet] '用户密码'  /  [TTabSheet] 'SO PIN'  /  [TButton] '初始化'
```

即**设备已被识别、基本信息已正确显示、管理页签（用户密码 / SO PIN / 初始化）全部就位**；
（对比：安装垫片前 Admin 完全不出现该设备。）

垫片日志同时确认了完整调用链：

```
C_Initialize ok, devices=1
C_GetSlotList(tokenPresent=1) -> slots=1
C_OpenSession(slot=0, flags=0x00000006) -> session=1
C_GetTokenInfo(slot=0) serial=ED466583B8C689AB flags=0x0000040D bind=0x0 remain=10 max=10
M_slot[17] (M_GetApplicationInfo) -> 0x00000054 (尚未实现)
M_slot[ 0] (M_GetUserInfo)        -> 0x00000054 (尚未实现)
```

#### 仍需完成的部分（下一步，已完全定位）

**调用约定已更正**：`M_*` 导出层是**纯 cdecl**（参数全在栈上、被调用者不清理），垫片原有的
cdecl 桩本身就是对的。此前报告里「第 1 个参数走 ecx 寄存器 + 其余走栈」的结论有误——
那是把 RVA **0x2B40** 当成了 `M_GetUserInfo`，而 0x2B40 实际是 `M_GetFileInfo`；
`M_GetUserInfo` 的真实 RVA 是 **0x2770**、`M_GetApplicationInfo` 是 **0x2C20**
（`M_FormatToken` = 0x2850、`M_SetTokenLabel` = 0x2810、`M_UnblockUserPin` = 0x27C0）。

各函数真实签名（导出层逐条反汇编确认）：

| 槽位 | 函数 | 参数 | 语义 |
|---|---|---|---|
| 0 | `M_GetUserInfo` | `(handle, pinType, M_PIN_STATE* out12)` — 3 参 | `pinType` **1 = 管理员(SO)、0 = 用户**（与 `SKF_GetPINInfo` 一致） |
| 17 | `M_GetApplicationInfo` | `(handle, char out[64], p3..p7)` — 7 参 | 把 64 字节应用名写入出参 2（内部 `memcpy(out, appObj+0x104, 64)`） |

`M_PIN_STATE`（12 字节，由 `gm3000_pkcs11.dll!0x1000B020` 反汇编确认）：

```
+0x00 ULONG 剩余重试次数
+0x04 ULONG 最大重试次数
+0x08 BYTE  1 = 口令已被使用/修改过（剩余 < 上限）
+0x09 BYTE  1 = 仅剩最后一次机会
+0x0a BYTE  1 = 已锁定（剩余 = 0）
+0x0b BYTE  1 = 口令仍为出厂默认值
```

TokenMgr 的 `token_get_pin_state` 正是把这 12 字节拆成 6 个出参（前 2 个按 DWORD、后 4 个各取 1 字节），
Admin 据此显示「剩余重试次数 / 是否锁定」。**这也解释了 `K_Dead` 的触发**：
只要该调用失败，TokenMgr 就回退到错误值 1，Admin 便一律按「已锁定」渲染。

后续按「日志 → 反汇编 → 补实现 → 再跑 Admin 看日志」的闭环逐项补齐，优先级：

| 优先级 | 槽位 | 函数 | 用途 |
|---|---|---|---|
| ✅ 已实现 | 17 | `M_GetApplicationInfo` | 输出 64 字节应用名（SKF 实测值 `GM3000APP`） |
| ✅ 已实现 | 0 | `M_GetUserInfo` | 输出 12 字节口令状态，数据源 `SKF_GetPINInfo` |
| 中 | 8 / 7 / 5 / 6 | `M_GetContainerInfo` / `M_EnumContainer` / `M_CreateContainer` / `M_DeleteContainer` | 容器（证书）管理 |
| 中 | 2 / 3 / 4 | `M_UnblockUserPin` / `M_SetTokenLabel` / `M_FormatToken` | 解锁 / 改名 / 初始化 |
| 低 | 9–16、19 | 扇区/文件读写、MSC 映射文件 | CSP/存储层相关 |

> 垫片已为这 20 个槽位保留与厂商完全一致的下标顺序，补实现时只需替换 `M_Dispatch` 中对应分支。

##### 已定位的具体症状：Admin 提示「USBKey已锁定」

安装垫片后 Admin 会弹 `提示 / USBKey已锁定`。**这不是设备真被锁** —— 垫片经 SKF 读到的
`SKF_GetPINInfo` 显示用户与管理员口令均为 **10/10**（未锁定）。它是「状态读取失败 → 按已锁定处理」：

1. 文案来自语言文件 `GM3000_2.2.19\Languages\CHS_2052.lng`（UTF-16LE），
   同一字典里 `K_Find_Error/K_GetKeyInfo_Error = 未检测到USBKey`、`K_Dead = USBKey已锁定` ——
   即 Admin 区分「**找不到**设备」与「找到但**状态不可用**」，后者报这句话。
2. TokenMgr 的 `token_get_pin_state`（`TokenMgr.dll!0x5DF0`）在**任何**失败分支上都
   `mov eax,1; ret`：节点未就绪（`[node+0xCC]==0`）→ 返回 1；转到真实实现（`0x7E10`）后
   若中间件调用失败 → 同样 `mov eax,1`。
3. 节点「就绪」标志由 `TokenMgr.dll!0x7B00` 置位，其判定条件正是
   **`C_OpenSession(slotID, flags=6)` 是否成功**（垫片日志里 `flags=0x00000006` 与此完全吻合）。
4. 垫片日志显示链路停在最后两步：

   ```
   C_OpenSession(slot=0, flags=0x00000006) -> session=1
   C_GetTokenInfo(slot=0) ... remain=10 max=10
   M_slot[17] (M_GetApplicationInfo) -> 0x00000054   ← 未实现
   M_slot[ 0] (M_GetUserInfo)        -> 0x00000054   ← 未实现
   ```

   即 Admin 向中间件索取「口令状态/应用信息」时，垫片返回 `CKR_FUNCTION_NOT_SUPPORTED`，
   TokenMgr 于是回退到错误值 `1`，Admin 便渲染成 `K_Dead`。

**修复（已实施并验证）**：垫片已实现槽位 **0** 与 **17**，并为出参加了可写性校验
（`VirtualQuery` 判定，缓冲区不可写就返回错误，绝不写坏上层栈）。数据源全部来自 SKF：
口令状态用 `SKF_GetPINInfo`（并对「剩余/上限」做 min/max 归一，兼容厂商两参数顺序差异；
上限为 0 时按「未知」处理，不臆断为已锁定），应用名用 `SKF_EnumApplication`。

ABI 层复刻 TokenMgr 调用序列的验证（`GM3000Probe shimabi`，**不依赖 GUI**）：

```
C_GetSlotList(NULL) → rc=0x0 count=1
C_OpenSession(slot=0, flags=6) → rc=0x0 session=1
ext[17] M_GetApplicationInfo → rc=0x0 应用名='GM3000APP'
ext[0] M_GetUserInfo(pinType=1) → rc=0x0 剩余=10 上限=10 已锁定=0 默认口令=1
ext[0] M_GetUserInfo(pinType=0) → rc=0x0 剩余=10 上限=10 已锁定=0 默认口令=1
```

Admin 实机运行的垫片日志（`GM3000_2.2.19\gm3000_shim.log`）同时确认两个槽位已由 `0x54` 变为 `0x0`：

```
M_GetApplicationInfo(slot=0) -> 'GM3000APP'
M_slot[17] a1=00000000 a2=001AF908 a3=1767680 a4=001AF8FC -> 0x00000000
QueryPinState(slot=0, pinType=1) raw=10/10 -> 剩余=10 上限=10 默认=1
M_GetUserInfo(pinType=1) -> 剩余=10 上限=10 已用过=0 仅剩1次=0 已锁定=0 默认=1
M_slot[ 0] a1=00000000 a2=00000001 a3=1767340 a4=0000000A -> 0x00000000
```

##### 「初始化」的 SO PIN：界面确实要输入（更正上一版结论）

Admin 点「初始化」**确实会要求输入 SO PIN**。实测它是通过
**`C_Login(CKU_SO, <口令>)`** 完成校验（日志中可见 `C_Login(userType=0, pinLen=5)`），
而不是把口令传给格式化入口——`TokenMgr!0x10005650` 的格式化调用只传
**(句柄, 标签, 标签长度)**，这一点不变。

而当时这次登录**必然失败**，原因见下节（垫片自伤，口令根本没送到设备）。

因此：

- Admin 点「初始化」**需要输入 SO PIN**（出厂值 `admin`，见下节实测）；
- 但真正落地格式化的是 PKCS#11 `M_FormatToken`（**槽位 4**，厂商 RVA `0x2850`），
  垫片当前仍返回 `CKR_FUNCTION_NOT_SUPPORTED` —— 这是「初始化」按钮**唯一剩余的前置条件**；
- SKF（`mtoken_gm3000.dll`）侧**没有**等价的格式化导出（见 §八），故真·初始化只能靠对齐
  `M_FormatToken` 的设备命令语义；
- 在补齐之前可用等价手段：`SKF_UnblockPIN`（以管理员口令重设用户口令）+ 逐个
  `SKF_DeleteContainer`。Manager 的 `Gm3000Provider.ResetDevice` 已按此实现并如实标注边界。

> 顺带修正一处旧结论：`SKF_GetPINInfo` 的第 3 个出参是**「是否为出厂默认口令」**，
> 并非「PIN 是否已初始化」；垫片原先据此清 `CKF_USER_PIN_INITIALIZED` 的做法已移除
> （本设备出厂即已格式化，用户/管理员口令均为 10/10、且仍为默认值）。

##### 「SO PIN 验证不正确」的根因（已修复）：句柄种类 + PIN 编号都错了

现象：Admin 输入 SO PIN 后固定报「验证不正确」。日志里对应的调用是

```
C_Login(userType=0, pinLen=5) -> 0x00000003 (retry=0)
```

`0x3` 不是 PIN 错误，而是 `MapSar(0x0A000005)` = **SAR_INVALIDHANDLEERR** ——
**口令根本没送到设备，一个重试次数也没消耗**（`retry=0`，设备侧仍 10/10）。两处错误：

**① 句柄种类错。** 本厂商 SKF 会校验句柄种类，用 `SKF_ClearSecureState` / `SKF_GenRandom`
（都无副作用、不消耗 PIN 次数）做零风险实测即得：

| 函数 | 需要句柄 | 实测结果 |
|---|---|---|
| `SKF_VerifyPIN` | **应用句柄** | `(hDev)` → `0x0A000005`；`(hApp)` → 正常 |
| `SKF_ClearSecureState` | **应用句柄** | `(hDev)` → `0x0A000005`；`(hApp)` → `0x0` |
| `SKF_GetPINInfo` | **应用句柄** | `(hDev)` → `0x0A000005`；`(hApp)` → `0x0` |
| `SKF_GenRandom` | **设备句柄** | `(hDev)` → `0x0`；`(hApp)` → **进程崩溃 0xC0000005** |

> ⚠️ 注意最后一行：**传错句柄种类不一定会返回错误码，有的函数直接解引用崩溃**。
> 因此禁止「两种句柄各试一次」的探测方式，必须先实测确认（`tools/GM3000Probe skfhandle`）。

**② PIN 编号反了。** 实测（`tools/GM3000Probe skfpin`）：

```
pinType=0 剩余=10/10  VerifyPIN(hApp, 0, "admin")    → rc=0x00000000  ✅ 管理员/SO，出厂口令 admin
pinType=1 剩余=10/9   VerifyPIN(hApp, 1, "12345678") → rc=0x00000000  ✅ 用户，出厂口令 12345678
```

即 **`ulPINType`：0 = 管理员(SO)、1 = 用户**（与 `M_GetUserInfo` 的编号一致）；
成功验证后该口令的剩余次数会**复位为上限**（实测 9/10 → 10/10）。
另确认 `SKF_GetPINInfo(hApp, type, &上限, &剩余, &是否默认)` 的**出参顺序是「上限在前」**。

**修复落点**（垫片与 Manager 同一组 bug，均已修）：

| 文件 | 修改 |
|---|---|
| `tools/GM3000Pkcs11Shim/shim.c` | `VerifyPIN/ChangePIN/UnblockPIN/ClearSecureState` 首参改用 `g_curApp`；`CKU_SO → pinType 0`、`CKU_USER → pinType 1`；`C_SetPIN` 按会话身份选择编号 |
| `Manager/src/USBKey.Core/UsbKey/Gm3000Native.cs` | `PinTypeSO = 0` / `PinTypeUser = 1`；委托首参更名 `hApp` 并注明种类；`GetPinInfoFn` 出参顺序改为 `(max, remain)` |
| `Manager/src/USBKey.Core/UsbKey/Gm3000Provider.cs` | `Login/Unlock/ResetDevice/ChangePin/Logout` 全部改传 `_hApp`；`GetDetail` 按新顺序取值 |

**端到端复验**（`tools/GM3000Probe shimabi`，复刻 Admin 的失败调用）：

```
C_Login(CKU_SO, pinLen=5) → rc=0x00000000  ✅ 管理员口令验证通过
ext[17] M_GetApplicationInfo → rc=0x0 应用名='GM3000APP'
ext[0] M_GetUserInfo(pinType=0/SO) → rc=0x0 剩余=10 上限=10 已锁定=0
ext[0] M_GetUserInfo(pinType=1/用户) → rc=0x0 剩余=10 上限=10 已锁定=0
```

Manager 侧只读回归：`GetDetail → 用户PIN 10/10，管理员PIN 10/10` ✅

##### 点「初始化」崩溃（Access violation at 30334D47）的根因与完整实现

现象：点「初始化」后 Admin 弹

```
Access violation at address 30334D47. Read of address 30334D47.
```

`0x30334D47` 正是 ASCII **`"GM30"`** —— 有人把字符串当函数指针调用了。

**根因**：扩展表 `+0x54` 处厂商放的是**哨兵值 `0x83000101`**（「该项不存在」），
文本描述区从 `+0x58` 才开始。垫片早期把 `desc` 文本放在 `+0x54`，初始化流程读该偏移时
把 `"GM30"` 当成函数指针 → 崩。对照（`GM3000Probe tables`）：

| 偏移 | 厂商 2.1.1.0 | 修好的垫片 |
|---|---|---|
| +0x50 | `M_ConstructMSCMapFiles` | 同名桩函数 ✅ |
| +0x54 | `0x83000101`（哨兵） | `0x83000101` ✅ |
| +0x58 | `"GM30"`+`"00"` → `GM3000` | 相同 ✅ |
| +0x78 | `"Long"`+`"mai"` → `Longmai` | 相同 ✅ |

**初始化调用序列（TokenMgr 反汇编确认）**：

```
M_FormatToken(handle, arg2)            ← 扩展表 +0x14（槽位 4，2 参 cdecl）
C_InitPIN(session, <新用户口令>, len)   ← 函数表 +0x2a（紧凑布局 index 10 ✓）
C_Logout(session)                      ← 函数表 +0x4e（index 19 ✓）
```

垫片实现：槽位 4 = 清空当前应用下全部容器（证书随容器消失）；`C_InitPIN` = 用**缓存的
管理员口令**走 `SKF_UnblockPIN(hApp, adminPin, newUserPin)`（本设备 SKF 无格式化入口，
这是等价实现，能力边界见 §八）；`C_Logout` 复用已修好的 `ClearSecureState`。

**「初始化不需要 SO PIN」**：按需求实现为 `C_Login(CKU_SO, …)` 的**兼容模式**——先按真实
口令验证（通过则缓存该口令供后续改密/初始化复用），若设备拒绝则**仍返回成功**，并把内部
管理员口令退回出厂值 `admin`。该行为会大声写日志，不做静默伪装；用户口令（`CKU_USER`）
仍严格按设备返回结果处理。

端到端复刻（`GM3000Probe initflow`，用出厂用户口令当「新口令」以免误改）：

```
C_Login(CKU_SO, len=5)      → rc=0x0
ext[4] M_FormatToken        → rc=0x0
C_InitPIN(session=1, len=8) → rc=0x0
C_Logout(session=1)         → rc=0x0
收尾：pinType=0 / pinType=1 剩余均 10/10、已锁定=0
```

##### 扩展表项数：2.2.19 是 **25** 项（此前只做了 20 项 → 启动即崩）

`GM3000Admin` 走的是 **2.2.19 的 TokenMgr**，而它读的扩展表比 2.1.1.0 多了 5 项：

| 索引 | 偏移 | 2.1.1.0 | **2.2.19** |
|---|---|---|---|
| 0–19 | +0x04..+0x50 | 20 项 | 20 项（同名同序） |
| 20 | +0x54 | —（文本区） | `M_ForceLogout` |
| 21 | +0x58 | — | `M_RemoteUnblockUserPin` |
| **22** | **+0x5C** | — | **`M_GetDevCaps`** |
| 23 | +0x60 | — | `M_SetInqString` |
| 24 | +0x64 | — | `M_RemoteUnblockUserPinMS` |
| 文本区 | 2.1.1.0：`"GM3000"`@+0x58 / `"Longmai"`@+0x78 | | **2.2.19：`"GM3000"`@+0x68 / `"Longmai"`@+0x88** |

垫片原先只有 20 项、文本紧跟在 `+0x54`，于是 2.2.19 的 TokenMgr 在 `C_GetTokenInfo`
之后立刻去取 `extTable[22]`（= `+0x5C`），取到的是文本 `"00\0\0"` = `0x00003030`，
把它当函数指针调用 → **`Access violation at address 00003030`**（先前那次
`30334D47` = `"GM30"` 是同一根因，只是当时文本起点在 `+0x54`）。

> 结论：**扩展表项数必须按目标 TokenMgr 版本对齐**。垫片现按 2.2.19 布局给出 25 项，
> 并把描述区放到 `+0x68` / `+0x88`。

##### 「设备信息」字段不一致（已定位真实来源）

厂商 2.1.1.0 工具与垫片的对照（同一台设备）：

| 字段 | 厂商工具 | 垫片（修复前） | 真实来源（DEVINFO 实测偏移） |
|---|---|---|---|
| 最小密码长度 | 4 | 6 | `+0xD3` = 4 |
| 总空间 / 剩余空间 | 128 KB / 128 KB | 0 KB / 0 KB | `+0xD6` = `0x00020000` = 128 KB |
| 硬件版本 | 5.00 | 1.00 | `+0xC2` = `05 00` |
| 固件版本 | 2.15 | 1.00 | `+0xC4` = `02 0F` |

`SKF_GetDevInfo` 的 DEVINFO 转储（`GM3000Probe devinfo`）逐字节确认了上述偏移；
垫片 `C_GetTokenInfo` 现已按这些偏移如实回报（字段缺失时退回保守值，不编造）。

> 另注：2.2.19 的 TokenMgr 会额外调用 **`M_GetDevCaps`（槽位 22）**，厂商用它补齐设备能力；
> 垫片目前该槽位返回 `CKR_FUNCTION_NOT_SUPPORTED`，TokenMgr 会退回 `C_GetTokenInfo` 的取值。
> 若界面仍有字段偏差，下一步就按 `gm3000_pkcs11.dll(2.2.19)!0x17C0` 的 3 参签名补实现。

##### 「空间不足」（初始化 / 导入证书都被它挡住）的根因：容量取自**私有内存**

Admin 点「初始化」后弹「空间不足」，导入证书同样被拒。设备并非真的没空间——是
`CK_TOKEN_INFO` 的**私有内存**两个字段仍为 `0xFFFFFFFF`。

实测（`GM3000Probe tm`，2.2.19 的 TokenMgr）确认 `token_get_info` 的出参映射：

| TokenMgr 出参 | `CK_TOKEN_INFO` 偏移 | 含义 |
|---|---|---|
| out[4] / out[5] | 116 / 120 | `ulMaxPinLen` / `ulMinPinLen` |
| **out[8] / out[9]** | **132 / 136** | **`ulTotalPrivateMemory` / `ulFreePrivateMemory`** |
| out[10] / out[11] | 140 / 142 | `hardwareVersion` / `firmwareVersion` |

即界面显示的「总空间 / 剩余空间」取自**私有**内存字段。垫片此前只填了公共内存
（偏移 124/128），私有那两个仍是 `0xFFFFFFFF`，Admin 把它当作无效值 → 判「空间不足」。

修复后（按 DEVINFO 实测容量同时填入公共/私有；本设备为单一存储池，与厂商工具显示的
128 KB 一致）：

```
out[8] = 0x00020000（128 KB）    out[9] = 0x00020000（128 KB）
```

> 次要因素：`Initconfig.ini` 记载出厂 `default_sopin=admin`（≥`minSOPINLen=4`）、
> `default_upin=12345678`；而 Admin 启动阶段会自动尝试一次 `C_Login(CKU_SO)`，某次日志中其
> 口令长度为 6 —— 若与实际出厂口令不符，会消耗 SO PIN 重试次数（当前 10/10）。
> 垫片日志会记录每次登录的真实返回码与剩余次数，可据此判断。

#### 安装 / 回滚

```powershell
# 安装（已执行）：备份厂商原文件后覆盖
Copy-Item "<SDK>\GM3000_2.2.19\gm3000_pkcs11.dll" "<SDK>\GM3000_2.2.19\gm3000_pkcs11.dll.vendor"
Copy-Item "tools\GM3000Pkcs11Shim\build\gm3000_pkcs11.dll" "<SDK>\GM3000_2.2.19\gm3000_pkcs11.dll"

# 回滚
Copy-Item "<SDK>\GM3000_2.2.19\gm3000_pkcs11.dll.vendor" "<SDK>\GM3000_2.2.19\gm3000_pkcs11.dll" -Force

# 自己重建垫片（需 VS2022 的 MSVC x86 工具链）
powershell -NoProfile -ExecutionPolicy Bypass -File tools\GM3000Pkcs11Shim\build.ps1
```

> ⚠️ `GM3000_2.2.19\mtoken_gm3000.dll` 当前是 **2016 版**（292,352B，支持本设备）。
> 垫片会优先使用它；若把它换回 `.old`（2022 版），垫片会自动回退到 `SysWOW64` 的 2016 版。
> 另注：Admin 启动时会自动尝试一次 `C_Login(userType=0/CKU_SO)`，若其内置默认口令与实际不符会消耗
> 1 次 SO PIN 重试次数（当前 10/10）。垫片日志会记录每次登录的真实返回码与剩余次数。

---

## 八、需求 ② 交付：`USBKey.Manager` 集成（实测通过）

### 8.1 新增/修改文件

| 文件 | 作用 |
|---|---|
| `Manager/src/USBKey.Core/UsbKey/Gm3000Native.cs` | SKF（GM/T 0016）P/Invoke 层：`SAR_*` 错误码、`SkfDevInfo` 结构、全部委托；模块定位（`Library/GM3000` → `Library` → `SysWOW64`） |
| `Manager/src/USBKey.Core/UsbKey/Gm3000Provider.cs` | `IKeyProvider` 实现（枚举/会话/登录/容器/证书/改密/解锁/重置/CSP 注册/随机数/标签/APDU 透传） |
| `Manager/src/USBKey.Manager/AppContext.cs` | 注册平台 `gm3000`（别名 `longmai` / `gm`） |
| `Manager/config/config.json` | `platform` 增加 `gm3000`；`keyslist.gm3000`（VID `055C` / PID `DB08`） |
| `Manager/src/USBKey.Manager/USBKey.Manager.csproj` | 把 2016 版 SKF 以 `mtoken_gm3000.dll` 名复制到输出 `Library\GM3000\` |

> 选用 **2016 版**（`GM3000_2.1.1.0\mtoken_GM.dll`，即模块真名 `mtoken_gm3000.dll`）随包分发，
> 因为 2022 版 `SKF_EnumDev` 对本设备返回 0。

### 8.2 实机验证输出（`tools/GM3000Probe provider`，走 Manager 真实代码）

```
---- Gm3000Provider（Manager 真实实现，只读路径）
   PlatformName=gm3000  IsAvailable=True
   设备数=1
   == GM3000-ED466583B8C689AB81DFA5573DF55AE
      Vendor=Longmai Model=GM3000 SN=ED466583B8C689AB81DFA5573DF55AE FW=DEVINFO v1 Notes=制造商 Longmai；设备状态 1
      GetDetail → Notes=制造商 Longmai；设备状态 1；用户PIN 10/10，管理员PIN 10/10
      容器数=0
```

### 8.3 能力与边界（诚实标注）

| 能力 | 状态 |
|---|---|
| 设备枚举 / 详情 / PIN 状态 / 容器列表 | ✅ **实机验证通过**（只读） |
| 证书导出 / 查看 / 注册到系统证书库 | ✅ 代码就绪（本设备暂无容器，未产生数据面验证） |
| 登录（`SKF_VerifyPIN`） | ✅ 参数由反汇编确认（**未实机执行**，避免消耗 PIN 重试次数） |
| 修改 PIN（`SKF_ChangePIN`） | ✅ 参数确认，未实机执行 |
| 解锁（`SKF_UnblockPIN`，管理员口令） | ✅ 参数确认，未实机执行 |
| 重置设备 | ⚠️ **能力受限**：见下 |
| 导入 PFX | ⚠️ **证书可导入；私钥导入格式待确认**：见下 |
| 挑战码 / 远程解锁 | ❌ 已定位 `SKF_GenRemoteUnblockRequest` / `SKF_RemoteUnblockPIN`，参数语义待确认，当前明确抛 `NotSupportedException` |

**重置（初始化）的能力边界**：厂商工具的真·初始化是 PKCS#11 `M_FormatToken`，
而本机 PKCS#11 层看不到该型号，SKF 侧**没有等价的格式化入口**。
`Gm3000Provider.ResetDevice` 因此采用与 `LncaProvider` 一致的「可靠性分级 + 诚实反馈」：
① 用管理员(SO)口令走 `SKF_UnblockPIN` 重设用户 PIN（或提供当前 PIN 走 `SKF_ChangePIN`）；
② 逐个 `SKF_DeleteContainer` 清空全部容器，失败项全部写入报告；
③ 最后用新 PIN 重新 `SKF_VerifyPIN` 认证，**只有通过才判定成功**，否则抛出含完整报告的异常。

**导入 PFX 的边界**：`SKF_ImportRSAKeyPair` 要求私钥按厂商约定「包裹/加密」后传入，
该包裹格式尚未逆向确认。实现为：证书一定导入；私钥以「PKCS#1 DER + 空加密数据」尝试一次，
并把真实返回码写入 `LastImportNote` 与日志，**绝不假装成功**。

---

## 九、待实机确认清单

| # | 项目 | 当前结论 | 验证方法 |
|---|---|---|---|
| 1 | `SKF_VerifyPIN` 实机行为 | ✅ **已实测**：`ulPINType` 0=管理员(SO)/1=用户，首参必须应用句柄；SO=`admin`、用户=`12345678` 均可通过 | `GM3000Probe skfpin`（已执行） |
| 2 | `SKF_ChangePIN` / `SKF_UnblockPIN` 实机行为 | 参数与句柄已确认（5 / 4 参、应用句柄、`ulPINType` 同上）；**尚未实机写操作**（避免改动用户口令） | 需要时用 `Unlock`/`ResetDevice` 走一次 |
| 3 | `SKF_ImportRSAKeyPair` 的私钥包裹格式 | **未确认** | 反汇编内部 `0x1001f030` 链路 + 对照 `SKF_ExportPublicKey` 输出格式；或用官方工具导入后对比设备内容 |
| 4 | `SKF_ExportCertificate` 的 `bSign` 语义 | 标准语义（`true`=签名证书），内部为分块续读 | 导入 1 张证书后分别以 `true/false` 读取比对 |
| 5 | `SKF_GetPINInfo` 的第 1 参数 | ✅ **已实证必须是应用句柄**（传设备句柄返回 `0xA000005`）；出参顺序确认为 `(上限, 剩余, 是否默认)` | `GM3000Probe skfhandle` / `skfpin`（已执行） |
| 6 | 容器名/证书标签的生成规则 | CN ≤ 39 字符，超长截断 | 官方工具导入后 `SKF_EnumContainer` 的取值 |
| 7 | `SKF_GenRemoteUnblockRequest` / `SKF_RemoteUnblockPIN` 参数 | **未确认** | 反汇编 + 与 `helper_gen_remote_unlock_response` 对照 |
| 8 | PKCS#11 垫片所需的 `M_*` 完整签名表 | ✅ 已确认槽位 0/1/4/11/17 的签名与语义（见 §七）；其余槽位签名待补 | `tools/tm_ext_sites.py` 定位调用点 + 导出层反汇编 |
| 9 | `SKF_SetLabel` 的首参句柄种类 | **未确认**（GM/T 0016 标准写作 `HAPPLICATION`，但本厂商有「不校验种类、传错直接崩」的先例） | 用 `GM3000Probe` 以**当前标签原值**试写一次（写同值无副作用），先试应用句柄、仅在返回 `0xA000005` 时再试设备句柄 |

> ⚠️ 第 1/2 项涉及**真实消耗 PIN 重试次数**，请在确认凭据后再执行。

---

## 十、分析方法与工具（本次新增，可复用）

| 工具 | 用途 |
|---|---|
| `tools/gm_pe.py` | 纯 Python PE 解析：`info`（节区/数据目录）/`exports`/`imports`/`strings`/`findva`/`xref` |
| `tools/gm_dump_all.py` | 批量落盘 GM3000 全部二进制的导出/导入/特征/关键字符串 → `tools/gm_out/` |
| `tools/gm_dis.py` / `gm_disraw.py` | 按导出名 / 按显式 RVA 反汇编（产物落盘，规避 PowerShell 编码与转义问题） |
| `tools/gm_sig.py` | 依据函数尾部 `ret imm16` **批量推断导出的调用约定与参数个数** |
| `tools/gm_dbg.py` | PE 头部与数据目录原始字节调试（用于定位解析器 bug） |
| `tools/gm_hexdump.py` | 十六进制 + 字符串 + 小端整数三视图转储（用于还原回填结构体） |
| `tools/gm_modules.py` | 跨 WOW64 枚举指定进程的**32 位模块**（Toolhelp32 + `EnumProcessModulesEx`） |
| `tools/GM3000Probe/` | x86 实机探针：`scan` / `p11` / `p11init` / `tmstyle` / `tables` / `skf` / `tm` / `provider` / `all` |
| `tools/GM3000Pkcs11Shim/` | **PKCS#11 垫片**（`shim.c` + `shim.def` + `build.ps1`）：基于 SKF 实现 PKCS#11，供厂商 TokenMgr/Admin 使用 |
| `tools/win_dump_windows.ps1` | 递归枚举指定进程的窗口/控件文本（无法看屏时观察 GUI 状态） |
| `tools/tm_find_ext_calls.py` | 检索 TokenMgr 中经扩展表调用 `M_*` 的调用点，用于推断参数约定 |

### 方法论沉淀（本次踩坑）

1. **`Ordinal Base` 必须参与换算**：PE 导出名表里的 `AddressOfNameOrdinals[i]` 是
   **导出地址表下标**，真实序号 = `Ordinal Base + 下标`。若在取 RVA 时再次减去 `base`，
   会导致**所有被分析函数整体错位一个导出**（本次一度把 `SKF_EnumContainer` 当成
   `SKF_EnumDev`、把 `SKF_VerifyPIN` 当成 `SKF_SetLabel`，得出「GM3000 SKF 非标准」的错误结论）。
   **交叉验证方法**：与 `objdump -p` 的 `[EAT 下标] +base[真实序号] hint 名称` 逐行对齐。
2. **PE32/PE32+ 数据目录偏移**：分别为可选头 `+96` / `+112`（不是 `+92` / `+108`）；
   且数据目录项要按**文件偏移**读取，不能拿 RVA 当偏移。
3. **Borland（`.itext` 节）二进制的导出多为 `__stdcall`，但 `M_*` 扩展为无栈清理的变体**，
   不能只凭 `ret` 判断 cdecl，需结合参数压栈顺序与寄存器传参分析。
4. **「当前上下文」型 SDK**：GM3000 的 SKF 用全局当前设备/当前应用，句柄参数形同虚设；
   遇到「同一句柄在 A 函数成功、在 B 函数报句柄无效」时，应优先怀疑**前置调用未完成**，
   而不是句柄类型错误。
5. **判定「中间件不支持某型号」要拿同源证据**：本次靠
   「2022 SKF 枚举 0 台 + 2022 PKCS#11 0 令牌 + 2.1.1.0 工具也 0 令牌」
   三条独立证据共同指向「中间件删除了该型号支持」，而非配置问题。

---

## 十一、变更文件清单

**新增**

- `Manager/src/USBKey.Core/UsbKey/Gm3000Native.cs`
- `Manager/src/USBKey.Core/UsbKey/Gm3000Provider.cs`
- `Roadmap/docs/Longmai-GM3000-逆向分析报告.md`（本文件）
- `tools/gm_pe.py`、`gm_dump_all.py`、`gm_dis.py`、`gm_disraw.py`、`gm_sig.py`、`gm_dbg.py`、`gm_hexdump.py`、`gm_modules.py`、`tm_find_ext_calls.py`、`win_dump_windows.ps1`
- `tools/GM3000Probe/`（`GM3000Probe.csproj`、`Program.cs`）
- `tools/GM3000Pkcs11Shim/`（`shim.c`、`shim.def`、`build.ps1`、`build/gm3000_pkcs11.dll`）
- `tools/gm_out/`（分析产物，可随时重建）

**修改**

- `Manager/src/USBKey.Manager/AppContext.cs`（注册 `gm3000`）
- `Manager/src/USBKey.Manager/USBKey.Manager.csproj`（复制 2016 版 SKF 到输出）
- `Manager/config/config.json`（`platform` + `keyslist.gm3000`）
- `Roadmap/README.md`（文档索引）

**在厂商 SDK 目录内的改动（可回滚）**

| 路径 | 改动 | 回滚方式 |
|---|---|---|
| `Library/Longmai GM3000 SDK/GM3000_2.2.19/gm3000_pkcs11.dll` | 替换为自研 PKCS#11 垫片 | 用同目录的 `gm3000_pkcs11.dll.vendor` 覆盖回去 |
| `GM3000_2.2.19/gm3000_pkcs11.dll.vendor` | 新增（2022 版厂商原件备份） | 删除即可 |
| `GM3000_2.2.19/gm3000_shim.log` | 新增（垫片运行日志，可随时删） | 删除即可 |

其余厂商文件均**未改动**（仅读取）；`mtoken_gm3000.dll.old` 的既有替换状态保持原样，未做回滚。

---

## 十二、Admin 四个报错的定位与修复（2026-09-21 追加）

> 方法仍然同 §七：**实机探针先把 TokenMgr/Admin 的真实调用链驱动出来**（`GM3000Probe tmfix` /
> `adminfix` / `skfcont` / `shimabi`），再用反汇编定位判定条件，最后改垫片并回归。

### 12.1 「修改名称」提示失败 —— 回读的是启动时缓存的旧名

**根因**：令牌「名称」在设备侧就是 `DEVINFO + 0x82` 那个字段（实测证据见下），
而垫片 `C_GetTokenInfo` 的 `label` 填的是 `g_devs[slot].model` —— 它在 `C_Initialize`
时读一次就**再没刷新**。于是 `SKF_SetLabel` 明明成功写入了设备，界面回读仍是旧名，
Admin 判「修改失败」（文案 `K_Set_No = 修改失败`）。

实机证据（`GM3000Probe adminfix`）：

```
改名前 DEVINFO 可读串: Longmai | Longmai | GM3000 | ED466583B8C689AB...
SetLabel(hDev,'ZZTESTZZ') → 0x0
DEVINFO 变化 @0x082 len=8: 'GM3000··' → 'ZZTESTZZ'     ← 名称就是 DEVINFO+0x82
SetLabel(hApp,'ZZTESTZZ2') → 0x0A000006（无效参数）      ← 句柄必须是**设备句柄**（垫片用的正是它）
恢复 SetLabel('GM3000') → 0x0；与改前一致=是
```

**修复**：新增 `RefreshDeviceSnapshot(slot)`（`SKF_GetDevInfo` → 刷新名称/厂商/型号/序列号/版本/容量），
在 `C_GetTokenInfo` 开头与 `M_SetTokenLabel` 成功后各调一次。

回归（`GM3000Probe tmfix`，走 TokenMgr 真实入口）：

```
token_get_info(改名前) 名称='ZZTESTZZ'      ← 读的是设备当前值
token_set_label('GM3000') → token_get_info 名称='GM3000'   ✅
```

> 顺带解决待确认项 #9：`SKF_SetLabel` 的首参是**设备句柄**（应用句柄返回 `0x0A000006`）。

### 12.2 「修改 SO PIN」失败 ErrorCode=0x1

`0x1` 是 **TokenMgr 自己的失败哨兵**（不是 PKCS#11 码）。反汇编 `token_change_sopin`
（2.2.19 rva `0x6200` → worker `0x84E0`）：

```asm
if (index >= g_tokenCount)      → return 1
if (token[index]+0xCC == 0)     → return 1      ; 未连接
C_GetSessionInfo(session,&info)
if (info.state != 4)            → return 1      ; 必须 == CKS_RW_SO_FUNCTIONS
C_SetPIN(session, old, new)
if (ret != 0)                   → return 1
```

即它**要求会话状态为「SO 已登录的读写会话」**，而垫片 `C_GetSessionInfo` 原本写的是
`loggedUser ? 2 : 0` —— 永远是「RW 公开/用户」，**从不报 4**，所以恒返回 1。

**修复**（`C_GetSessionInfo` 如实区分五种状态）：

| 会话 | 状态值 |
|---|---|
| SO 已登录 | `4` `CKS_RW_SO_FUNCTIONS` |
| 用户已登录 | RW→`3` / RO→`1` |
| 未登录 | RW→`2` / RO→`0` |

回归：

```
token_login_so(0, len=5) → 0x0 ✅
token_change_sopin(0, 旧=新) → 0x0 ✅ 通过（修复前恒 0x1）
```

### 12.3 「下载 ISO」失败 0x54 —— 文件类槽位缺失

`0x54` 是本垫片返回的 `CKR_FUNCTION_NOT_SUPPORTED`，即该槽位此前没实现。厂商扩展表中
文件/扇区相关槽位与 SKF（GM/T 0016）文件 API **一一对应**，已补齐：

| 槽位 | 厂商函数 | 参数 | 实现（SKF） |
|---|---|---|---|
| 12 | `M_CreateFile` | `(handle,name,size,readRights,writeRights)` 5 参 | `SKF_CreateFile`（同 5 参） |
| 13 | `M_DeleteFile` | `(handle,name)` | `SKF_DeleteFile` |
| 14 | `M_WriteFile` | `(handle,name,offset,data,size)` 5 参 | `SKF_WriteFile`（同 5 参） |
| 15 | `M_ReadFile` | `(handle,name,offset,size,out,outLen)` 6 参 | `SKF_ReadFile`（同 6 参） |
| 16 | `M_GetFileInfo` | `(handle,name,FILEATTRIBUTE*)` | `SKF_GetFileInfo` |

实机回归（`GM3000Probe shimabi`，未提供用户口令，故写入被设备按「未登录」拒绝）：

```
ext[12] M_CreateFile('ZZTEST.DAT', size=17) → 0x00000000  ✅ 设备上真的建了文件
ext[14] M_WriteFile(off=0, size=17)         → 0x00000101   ← 与建容器同理：写操作要求**用户**角色
ext[15] M_ReadFile                           → 0x00000101
ext[16] M_GetFileInfo                        → 0x00000082   ← CKR_OBJECT_HANDLE_INVALID（映射正确）
ext[13] M_DeleteFile('ZZTEST.DAT')           → 0x00000000  ✅
```

> 结论：**写入类操作（建/删容器、写文件）要求「用户」角色的已验证状态**（裸 SKF 直测
> `skfcont` 已证实：即便 `VerifyPIN(SO)` 成功，`SKF_CreateContainer` 仍返回 `0x0A00002D`）。
> Admin 的导入/下载流程本身会 `C_Login(CKU_USER)`，垫片会把该口令缓存下来，
> 一旦中间的 `ReloadObjects` 等调用破坏了应用句柄上的安全状态，就用缓存口令自动恢复。
> 另：**扇区类槽位（9/10 `M_Read/WriteSectors`、19 `M_ConstructMSCMapFiles`）仍返回「不支持」**
> —— SKF（GM/T 0016）没有扇区级接口，无法如实映射；若「下载 ISO」走的是扇区路径，
> 需要另行评估（不能做假成功）。

### 12.4 系统检测「CSP 未安装」——检测依据与处置

反汇编 Admin 的检测函数（`GM3000Admin.exe!0x52788F`）：

```asm
mov  $0x80000002,%edx                 ; HKEY_LOCAL_MACHINE
call RootKey
mov  $0x52793C,%edx                   ; "\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\"
call 拼接(路径 + <APPInfo.ini 的 CSPName>)
call TRegistry.OpenKey                ; 打开成功即判「已安装」
```

即判定条件是 **`HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\<CSPName>` 是否存在**
（Admin 未导入 `crypt32`，纯注册表判定）。本机实况：

| 项 | 值 |
|---|---|
| 本机已注册的 Longmai CSP | `Longmai GM3000 for HZ CSP V1.1` → `%SystemRoot%\system32\GM3000HZTWCSP_s.x64.dll`（文件存在 ✅） |
| `APPInfo.ini` 原先写的 | `CSPName=Longmai mToken GM3000 CSP V1.1`、`CSPLib=GM3000CSP.dll` |
| `GM3000CSP.dll` | **全盘不存在**（`System32`/`SysWOW64`/仓库都没有） |

→ 名字对不上（且期望的 DLL 不在本机），所以判「未安装」。

**处置**：把 `APPInfo.ini` 的 `CSPLib` / `CSPName` 对齐到**本机实际安装**的那个 CSP
（`GM3000HZTWCSP.dll` / `Longmai GM3000 for HZ CSP V1.1`）。这是「配置对齐本机现实」，
不是伪装安装；若以后要装厂商 mToken 版 CSP（`GM3000CSP.dll`，需从厂商安装包获取），
把这两行改回去即可：

```ini
CSPLib=GM3000CSP.dll
CSPName=Longmai mToken GM3000 CSP V1.1
```

> 若目标是把**该** CSP 真正装上，必须拿到厂商的 `GM3000CSP.dll` 安装包——
> 本机与仓库内都没有该文件。

### 12.5 本轮改动的文件

| 文件 | 改动 |
|---|---|
| `tools/GM3000Pkcs11Shim/shim.c` | ①`C_GetTokenInfo` 前刷新设备快照（名称随设备走）②`C_GetSessionInfo` 如实报 5 种状态（SO=4）③实现槽位 12/13/14/15/16（文件类）④`M_Dispatch`/桩扩到 6 参以承载 5/6 参函数⑤新增 `RestoreSecureState*` 用缓存口令恢复「已验证」状态 |
| `Library/Longmai GM3000 SDK/GM3000_2.2.19/APPInfo.ini` | `CSPLib` / `CSPName` 对齐本机已安装的 HZ 版 CSP（可改回，见 12.4） |
| `tools/GM3000Probe/Program.cs` | 新增 `adminfix` / `tmfix` 命令（驱动 Admin 的改名/改密真实入口）、`shimabi` 增加容器+文件槽位回归 |
| `tools/gm_exttable.py` | 新增：直接读厂商扩展表静态结构（`M_GetExtFunctionList` 只是把 rva `0x7BB30` 的表指针写回出参），权威还原 25 项槽位顺序 |

### 12.6 Manager 侧：空容器的「名称」不应显示容器 UUID

**现象**：Manager 的「证书 / 容器」列表里，空容器（卡内只有容器壳、没有证书）的名称列显示成
`{AD96F3E8-CAC2-4CB5-8F24-B8595BCA4B1D}` 这类 UUID。

**根因**：容器名在设备上就是 UUID 形式（Admin 导入时创建的容器即如此）。
Provider 在「取不到证书」时把 `Name` 留成了容器名：

```csharp
var kc = new KeyContainer { ContainerName = containerName, Name = containerName, ... };
if (der != null) { ... kc.Name = cert.GetNameInfo(X509NameType.SimpleName, false); }   // 只有有证书才覆盖
```

`KeyContainer` 的语义是：`Name` = **证书 CN**、`ContainerName` = **容器名（可能为 UUID）**，
界面上也分别对应「名称」列与「容器 UUID」列 —— 把容器名当名称显示属于把两列混为一谈。

**修复**：无证书时 `Name` 保持为空（有证书仍用证书 CN 覆盖）：

| 文件 | 改动 |
|---|---|
| `Manager/src/USBKey.Core/UsbKey/Gm3000Provider.cs` | `ReadContainerLocked`：`Name` 默认 `""`，不再回退成容器名 |
| `Manager/src/USBKey.Core/UsbKey/SkfProvider.cs` | 无证书分支同样 `Name = ""`（打开失败/解析失败等**错误占位行**仍保留容器名，便于定位是哪个容器出错） |

**实机验证**（`tools/GM3000Probe provider`，走 Manager 真实代码）：

```
容器数=3
  {AD96F3E8-CAC2-4CB5-8F24-B8595BCA4B1D} |  |  | 数据加密          ← 名称列为空 ✅
  Pikachu Common Code Sign SHA256 V02 | Pikachu Common Code Sign SHA256 V02 | O=... | 数字签名   ← 有证书，正常 ✅
  {FA0D192A-2D33-489E-B8D0-B08CF9957EFB} |  |  | 数据加密          ← 名称列为空 ✅
```

> 遗留观察（未改，等确认）：无证书容器的「密钥用途」当前落到 `数据加密`，
> 但这只是「签名证书没取到」的兜底推断，卡内其实**没有任何证书**，
> 显示成空或「无证书」更如实。

---

**版本**：v1.1（2026-09-21）
**作者**：AI 逆向协作（objdump + 自研 Python 分析链 + x86 实机探针）
