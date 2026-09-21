# 恒宝（HengBao）民生银行 U 宝 —— 逆向分析与 Manager 对接报告

> 分析日期：2026-09-20
> 目标目录：`Library/HengBao USB Manage/`
> 分析工具：IDA Pro 8.3（`idat.exe` / `idat64.exe`）+ 自研 PE/资源解析脚本（`Manager/tools/HengBaoIda/`）
> 对接代码：`Manager/src/USBKey.Core/UsbKey/HengBaoProvider.cs`、`CkmNative.cs`
> 验证工具：`Manager/tools/HengBaoProbe/`

---

## 0. 结论速览（TL;DR）

| 问题 | 结论 |
|------|------|
| 用哪个接口对接 | `CMBCp.dll`，标准 **PKCS#11 v2.x**（32 位） |
| 调用约定 | **`__cdecl`**（68/68 个 `C_*` 导出全部如此）。`StdCall` 会栈失衡，得到随机错误码 —— **Roadmap/06 的“修复 2”是错的，本报告更正之** |
| 出厂口令 | **`111111`**（6 位；长度 6–15 位，不可为顺序/重复；官方资源串 ID=1094 明确写出） |
| 能否用 PKCS#11 初始化令牌 | **不能**。`C_InitToken`、`C_InitPIN` 是 `mov eax,54h; retn` 的桩函数，恒返回 `CKR_FUNCTION_NOT_SUPPORTED(0x54)` |
| 有没有 SO PIN / PUK | **没有**。`C_Login` 只接受 `CKU_USER(1)`，其它 userType 直接返回 `CKR_USER_TYPE_INVALID(0x103)` |
| 本工程如何实现「重置」 | 「用当前口令登录 → 删除设备上全部对象（清空内容）→ `C_SetPIN` 重设口令」 |
| 真正的「初始化 U 宝」（恢复出厂态、口令回 111111） | 只存在于厂商层：官方工具 `CMBCu.exe` 与 CSP `CMBCC.dll`，走自研 HID / SCSI-BOT / ISO7816 APDU 链路 + U 宝按键确认，**未导出任何可调用 API** |
| 枚举设备的坑 | `C_GetSlotList` 返回的“槽位”实际是**设备路径字符串指针**（Win32 下 4 字节），必须原样回传；`C_GetSlotInfo` 是**硬编码**信息，只有 `C_GetTokenInfo` / `C_OpenSession` 才真正打开设备 |

---

## 1. 本机实测状态（2026-09-20，已插实机）

用重写后的探针（`__cdecl` 版）在开发机上实跑，结果如下：

```
[+] LoadLibrary 成功 handle=0x10000000
[1] C_Initialize → CKR_OK(0)
[2] C_GetSlotList(TRUE,NULL) → CKR_OK(0) count=1
----- 槽位[0] 句柄=0x1003DFA8 -----
  设备路径字符串 : \\?\usbstor#cdrom&ven_hengbao&prod_uranusafe_key&rev_1.00#7&6bbbb1f&0#{53f56308-…}01
  C_GetSlotInfo  → CKR_OK(0)  描述="HENGBAO KEY" 厂商="HENGBAO Co.LTD" flags=0x5
  C_GetTokenInfo → CKR_FUNCTION_FAILED(6)   ← 设备通信失败/设备未就绪
在线设备数：0
```

PnP 侧的证据：

| 状态 | 类别 | 设备 | InstanceId |
|------|------|------|-----------|
| OK | USB | USB 大容量存储设备 | `USB\VID_1677&PID_0107\535A4432334231300048C24C77504E` |
| OK | CDROM | HengBao UranuSafe Key USB Device | `USBSTOR\CDROM&VEN_HENGBAO&PROD_URANUSAFE_KEY&REV_1.00\7&6BBBB1F&0` |

- 该设备**只暴露一个 CD-ROM 功能**（盘符 `E:`，卷标 `CMBC_UBAO`，600 KB ISO），
  **没有任何 `HIDClass` / 智能卡（CCID）接口**，也没有可写的可移动磁盘 LUN。
- 卷标内的文件：
  ```
  E:\AUTORUN.INF
  E:\CMBC_HB_AutoUpdate.exe          (85 KB)
  E:\CMBC_HB_UranuSafe_Install.exe   (452 KB)   ← 厂商驱动安装程序
  ```

**结论：`C_GetTokenInfo` 失败是「厂商驱动未安装 / 设备处于 CD-ROM 单一形态」导致，不是调用约定的问题**
（用 `Cdecl` 后 `C_Initialize`、`C_GetSlotList`、`C_GetSlotInfo` 全部正常返回，
且槽位路径确实指向本机的 `usbstor#cdrom&ven_hengbao…` 设备，说明枚举链路已经跑通）。

处理办法：运行 `E:\CMBC_HB_UranuSafe_Install.exe` 安装厂商驱动（提供 HID / SCSI-BOT 通道）后重新插拔 U 宝，
再执行探针即可验证 `C_GetTokenInfo / C_Login / 对象枚举 / C_SetPIN / 重置` 全链路。

> 该结论与上一轮会话（用 `Cdecl` 手写探针）的观察一致：DLL 加载、PKCS#11 初始化、槽位枚举、
> `C_GetSlotInfo` 全部通过，只有需要真正与卡片通信的 `C_GetTokenInfo` / `C_OpenSession` 返回 `6`。

---

## 2. 组件清单与角色

| 文件 | 大小 | 架构 | 角色 | 关键证据 |
|------|------|------|------|----------|
| `CMBCp.dll` | 272 KB | x86 | **PKCS#11 模块**（对接目标） | 导出 68 个 `C_*`；PDB 路径 `D:\CvsRoot\Uranusafe5.0\UranusafeKitV5.0\Src\Pkcs11\Windows\pkcs11\Debug\pkcs11.pdb`；内部源码名 `uZJPKCS11.cpp`、`implglue.cpp`、`token_comm.cpp` |
| `CMBCC.dll` | 331 KB | x86 | **CryptoAPI CSP**（同时内嵌整套设备层与工具对话框） | 导出 `CPAcquireContext…CPVerifySignature`、`GetCspName`；含 `初始化U宝，请按键确认` 等字符串 |
| `CMBC64C.dll` | 349 KB | x64 | 上者的 64 位版 | 导出同 27 个 `CP*` |
| `CMBC.dll` | 28 KB | x86 | CSP 注册/加载壳（`DllRegisterServer`/`DllUnregisterServer`，导入 `FindResourceA/LoadLibraryA`） | 导出 27 个 `CP*` + 注册函数 |
| `CMBC64.dll` | 12 KB | x64 | 同上，64 位壳 | — |
| `CMBCu.exe` | 293 KB | x86 | **官方管理工具「民生银行U宝管理工具（恒宝）」** v1.2，MFC | 源码路径 `…\CMBC_SKF\PCPlatformV5.0\SRC\Manager\UserTool\UserTool.cpp`、`Device.cpp` |
| `CMBCs.ini` | 336 B | — | 工具配置：`CSP=UranuSafe CSP For CMBC V1.0`、`Code=CMBC_SKF`、`Version=5.1.1.42` | — |
| `CMBC.sig` / `CMBC64.sig` | 136 B | — | 厂商签名文件 | — |
| `cfca/*.cer` | — | — | CFCA 根/运营 CA 证书 | — |
| `CMBC0409.hbl` / `CMBC0409.h64`（及 `CMBC0C04.*`） | 22 KB / 21 KB | — | 厂商数据文件（0409=英文、0C04=简中），内含大量 UTF-16 本地化文案，供 `CMBCu.exe`/`CMBCC.dll` 读取 | — |

> 注意：`CMBCu.exe` **没有**静态导入任何恒宝 DLL（只导入 KERNEL32/USER32/GDI32/SETUPAPI/**HID**/CRYPT32 等），
> 它自己实现了 HID / SCSI-BOT / APDU 三层通信；`CMBCp.dll` 同样直接导入 `HID` + `SETUPAPI`，
> 也就是说**三家（PKCS#11、CSP、工具）各自内嵌了一份相同的设备层代码**。

---

## 2.1 实机联调记录（2026-09-21，驱动已装）

### 2.1.1 实测结果

结论先说：**本工程的 PKCS#11 对接比厂商自带的官方工具"更能干活"（能枚举到设备并进入设备层），
但卡片本身对该协议返回 `SW=6E00`，导致令牌无法打开；
厂商自己的 `CMBCu.exe` 在同一台机器、同一个 U 宝上同样认不到设备。**

| 步骤 | 探针（cdecl，本工程） | 官方工具 `CMBCu.exe` |
|------|----------------------|----------------------|
| 加载 DLL / C_Initialize | ✅ `CKR_OK` | ✅ |
| C_GetSlotList | ✅ `count=1`（CD-ROM 设备接口路径） | ✅ 进入枚举 |
| C_GetSlotInfo | ✅（硬编码信息） | — |
| **C_GetTokenInfo** | ❌ **`CKR_FUNCTION_FAILED(6)`** | ❌ 未枚举到任何设备 |
| 设备层 `CTSPBot::OpenDevice` | ✅ 被调用，发出 APDU | 未走到（0 设备） |

### 2.1.2 DLL 内部日志（硬证据）

`CMBCp.dll` 会写自己的内部 trace（导入 `fopen/fprintf`），日志路径（需先创建目录，否则静默失败）：

```
C:\HBLogFile\TSPLogFile.txt     ← 设备层 trace（THidTSP / CTSPBot / MSP APDU）
c:\hblogfile\CSPLogFile.txt
c:\zj_log\zj_csp.log            ← PKCS#11 层 trace（uZJPKCS11.cpp 文件名 + 行号）
```

本机实测（先 `New-Item -ItemType Directory C:\HBLogFile, C:\hblogfile, C:\zj_log` 再跑探针）：

```
[CTSPBot::EnumDevice
CTSPBot::EnumDevice]
[THidTSP::EnumDevice
* SetupDiEnumDeviceInterfaces dwReturn=0x103          ← 0x103 = ERROR_NO_MORE_ITEMS（遍历结束）
return value=0x00000000                                ← 匹配到 0 个 HID 设备
THidTSP::EnumDevice]
[CTSPBot::OpenDevice
CTSPBot::OpenDevice]
Param: *szCommand=00A4000002ADF1        ← SELECT ADF1
szReply = ,return value len=0x00000000,ulSW = 6e00     ← 卡片回 6E00
Param: *szCommand=80320000FF            ← 取随机数/厂商命令
szReply = ,return value len=0x00000000,ulSW = 6e00
Param: *szCommand=00A40000020003        ← SELECT 0003
szReply = ,return value len=0x00000000,ulSW = 6e00
```

### 2.1.3 失败点在代码里的确切位置

`KOpenDevice`（`0x1002161D`，源文件 `token_comm.cpp`）**要求卡片的 select 返回 `0x9000`**，
否则整轮打开失败并把最后一个 SW 作为错误码向上返回：

```c
v10 = sub_100251C0(v9, 3);                       // 关键：SW 必须 == 0x9000
if ( v10 == 36864 /*0x9000*/
  && (Size=20, v10 = sub_100253C4(v9, 0, Src, &Size), v10 == 36864)
  && (...,        v10 = sub_100251C0(v9, 1),           v10 == 36864)
  && (Size=76,    v10 = sub_100253C4(v9, 0, Src, &Size), v10 == 36864) )
{
    ... 读 label/serial，打开成功 ...
}
else v11 = v10;                                  // ← 这里得到 0x6E00
```

于是：

```
卡片回 6E00 → KOpenDevice 返回 0x6E00 → C_GetTokenInfo 返回 CKR_FUNCTION_FAILED(6)
```

> `0x6E00`（ISO7816: CLA not supported）在 CMBCp.dll 里**不是常量**（用 IDA 扫立即数 0 命中），
> 说明它就是**设备真实返回的状态字**，不是本地合成的错误码。

### 2.1.4 设备侧的客观事实

| 检查项 | 结果 |
|--------|------|
| 设备 USB 设备 | `USB\VID_14D6&PID_3032`（USB 大容量存储设备） |
| 子设备 | `USBSTOR\CDROM&VEN_HENGBAO&PROD_URANUSAFE_KEY&REV_1.00\7&19756BC4&0` |
| 该设备的全部 CompatibleIds | `USB\COMPAT_VID_14D6&Class_08&SubClass_06&Prot_50` → **只有 Mass Storage / SCSI / BOT** |
| 历史上是否出现过其它接口 | **从未**出现 HID(Class_03) / CCID(Class_0B) 接口 |
| 厂商工具枚举的 HID 过滤条件 | `HidD_GetAttributes → VendorID == 5334 (0x14D6)`，本机 **0 个匹配** |
| 光盘内容 | `CMBC_HB_UranuSafe_Install.exe`（NSIS，需管理员）、`CMBC_HB_AutoUpdate.exe` |
| 安装包内含文件 | 只有用户态 DLL（含装到系统目录的 `hbcmbc86.dll` / `hbcmbc64.dll`）+ `CMBCu.exe` + 证书；**没有任何 `.sys` / `.inf`** |

**即：这台机器上"能装的驱动"已经装完了（安装包本来就不含内核驱动），
而该 U 宝在 USB 上从未暴露过令牌接口（HID/CCID），令牌只能通过 **SCSI 直通（CTSPBot）** 访问，
而卡片对该通道一律回 `6E00`。**

### 2.1.5 结论与处置建议

> ⚠ **本节原结论（"厂商工具也认不到 → 设备故障 → 去柜台"）已于 2026-09-21 被实机验证推翻，
> 正确结论见 §2.2。** 下面保留原文以便追溯，阅读时请以 §2.2 为准。

1. ~~**代码侧没有遗留问题**~~。真机联调前的 PKCS#11 语义修正（`cdecl`、不透明槽位、
   `C_GetTokenInfo` 过滤）确实都是必要且正确的，但这**不足以**让设备工作。
2. ~~**根本原因在设备/卡片状态**~~ —— 错的。根因在**协议层**：卡片要求先完成厂商
   MSP 安全报文握手（见 §2.2），而 `CMBCp.dll` 不做这段握手。

----


---

## 2.2 根因确认（2026-09-21，实机 + 探针直连设备）

> 本节是**结论性章节**。§2.1 的"设备故障/去柜台"判断已被下面的实验推翻。

### 2.2.1 方法：绕开 CMBCp.dll 直连设备

按 `CMBCp.dll` 的反汇编结果，在 `HengBaoProbe.exe` 里复刻了整套设备层，新增 4 个模式：

| 模式 | 作用 |
|------|------|
| `--raw [--apdu HEX]` | 枚举接口 → `INQUIRY` 自检 → 用厂商帧发一条 APDU，打印原始响应 |
| `--seq "A,B,C"` | **同一设备会话**内按序发多条 APDU（关键：卡片状态不跨会话保留） |
| `--brute [--cla HEX]` | 遍历 CLA×INS，打印所有 SW ≠ 6E00 的组合 |
| `--cdb-scan` | 扫描 TargetId/Lun 与 CDB 子命令，找复位/上电类命令 |
| `--open-new` | 用 `dwCreationDisposition=1`（复刻官方工具的 CreateFile 参数） |

设备层规格（`CMBCp.dll` `sub_10028FC1` / `sub_10028DE9` / `sub_10028CFF` / `sub_100291A5`）：

```
枚举     SetupDiGetClassDevs(GUID_DEVINTERFACE_DISK) + (GUID_DEVINTERFACE_CDROM)
         设备路径 strupr 后必须包含 "HENGBAO"           ← 别家 CD-ROM 因此被过滤掉
打开     CreateFileA(path, 0xC0000000, 3, 0, 1/*官方*/, 0x80, 0)
透传     DeviceIoControl(IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014)
           Length=44, TargetId=1, Lun=0, CdbLength=16, SenseInfoLength=16,
           DataTransferLength=帧长(写)/512(读), SenseInfoOffset=48, TimeOut=60(官方 300)
           CDB = FA 3A(写) / FA 08(读)，其余 14 字节为 0
命令帧   43 <len_hi> <len_lo> <apdu…>        （0x43='C'）
响应帧   52 <len_hi> <len_lo> <payload…>     （0x52='R'，payload 末 2 字节 = SW1 SW2 大端）
```

### 2.2.2 实测证据

**(1) SCSI 透传本身完全正常**

```
[1] SCSI INQUIRY 成功，返回 36 字节
    Vendor="HengBao" Product="UranuSafe Key" Rev="1.00"
[2] 写命令帧成功: 43000700A4000002ADF1
[3] 读响应 5 字节: 5200026E00     （帧头 52 0002；载荷 6E00）
```

**(2) `6E00` 与 CLA / INS 完全无关，只与 APDU 长度有关**

| APDU | 长度 | SW |
|------|------|-----|
| `00A40000` | 4 | `6700`（长度错误） |
| `00A4000000` / `0000000000` / `8032000000` | 5 | `6E00` |
| `00A4000002ADF1` | 7 | `6E00` |
| `00 00 00 00`（CLA=00 INS=00） | 4 | `6700` |
| CLA=0x00/0x80/0x90/0xFF 全部 256 个 INS | 4 | 一律 `6700` |

⇒ 长度校验发生在 INS 分派**之前**；`6E00` 是这套 COS 的通用"不识别/未授权"码，
**不是** ISO7816 意义上的"CLA 不支持"。

**(3) 厂商官方工具 `CMBCu.exe` 在**同一只 U 宝**上工作完全正常**（抓 `C:\HBLogFile\TSPLogFile.txt`）

```
[CTSPBot::OpenDevice
80F2030001            → 9000, 数据 01          ← 握手第 1 步（厂商命令）
80F4020000            → 6901                   ← 握手第 2 步
80F4000087            → 135 字节 6E808A…03010001   （卡片公钥/密钥材料）
80F4010080 +128 字节  → 9000                   ← 主机应答（RSA）
00A4000002ADF1        → 6109                   ← 握手后 SELECT ADF1 才通
00C0000009            → 6F07 84 05 48424B4559  ← FCI：DF 名 = "HBKEY"
80320000FF            → 6C31 → 8032000031      → 49 字节卡信息
00A40000020001 / 00B000004C → "CMBC_SKF"…
00A40000020003 / 00B0000020 → "CMBC" + "11_OpenTOKE"
0020000000            → 6102（VERIFY，等待口令）
```

**(4) 关键证据：`MSP::XSendAPDU` 内部含解密层**

`CMBCp.dll` / `CMBCu.exe` / `CMBCC.dll` 均含这些字符串（同地址簇）：

```
*********MSP::XSendAPDU Decrypt error*********
80F2030001     80F4020000     80F4000087     80F40100%02X%s
```

⇒ 握手之后，APDU 走 **MSP 安全报文封装**（请求要封装、响应要解密）。
**未封装（裸）的 APDU 一律被卡片回 `6E00`** —— 这正是本工程观察到的现象。

**(5) 已有"修复"尝试均无效**（均已实测）

| 尝试 | 结果 |
|------|------|
| 单独发 `80F2030001` + `80F4020000` + SELECT（同一会话） | SELECT 仍 `6E00` |
| 完整重放官方工具握手（含 128 字节应答原文） | 4 步全部 `9000`，但 SELECT 仍 `6E00`（应答是会话相关的，重放无效） |
| 先发官方工具开头的 3 条探测 APDU 再握手 | 仍 `6E00` |
| `--open-new`（CREATE_NEW，复刻官方 CreateFile） | 无差别 |
| TargetId 0–3 × Lun 0–3 全组合 | 一律 `6E00` |
| CDB[1] 全 256 种子命令扫描 | 仅 `0x3A`(写)/`0x08`(读) 有效，其余 254 个超时或"设备不可用" |
| 并发运行 `CMBCu.exe`（已建立安全会话）后跑 PKCS#11 探针 | `C_GetTokenInfo` 仍返回 `6` |

### 2.2.3 结论

| 项 | 结论 |
|----|------|
| 设备是否故障 | **否**。官方工具能完整读卡（HBKEY / CMBC_SKF / 卡信息 / PIN 重试次数） |
| SCSI 透传是否可用 | **可用**。`INQUIRY` 正常，厂商命令帧收发正常 |
| 为什么 PKCS#11 全部失败 | `CMBCp.dll` 的 `KOpenDevice` 直接发裸 `SELECT ADF1`，**不做 MSP 握手**；卡片对裸 APDU 一律回 `6E00` |
| 之前文档的"去柜台"结论 | **错误，已作废**（见 §2.1.5 的更正说明） |
| 本工程能否用 PKCS#11 做重置/清空/改密 | **当前不能**。需要先复现 MSP 安全报文（握手 + 封装 + MAC/解密），否则 `C_OpenSession`/`C_Login` 永远打不开 |
| 官方工具能否完成"初始化 U 宝" | **能**（这是目前唯一可行的路径） |

### 2.2.4 下一步（唯一有意义的逆向目标）

复现 `MSP` 安全报文，从而在 Manager 侧独立完成握手，让 `CMBCp.dll` 之后能正常打开令牌：

1. 反编译 `CMBCu.exe` 中引用 `80F40100%02X%s` / `80F2030001` / `MSP::XSendAPDU Decrypt error`
   的函数簇，还原：
   - 会话密钥协商算法（`80F4000087` 的 135 字节如何解析成 RSA 公钥/挑战）；
   - `80F4010080` 那 128 字节如何算出来（随机数 + 公钥加密？还是签名？）；
   - 握手后每包 APDU 的封装/解封（对称算法、IV、MAC 规则）。
2. 在探针里实现 `--msp-open`：完成握手并保持会话，然后把后续 APDU 交给它；
   验证 `00A4000002ADF1` 能拿到 `6109`。
3. 握手可用后，再评估两条落地路线：
   - **A（推荐）**：Manager 自己在打开设备前先跑一次握手，之后照常调用 `CMBCp.dll`；
   - **B**：完全自研设备层（含 MSP），在 Manager 内直接实现 `初始化 U 宝 / 清空 / 改口令`，
     不再依赖 `CMBCp.dll`（工作量更大，但能覆盖 PKCS#11 未实现的"真·初始化"）。

> 所需的厂商参考材料：`CMBCu.exe`（可执行）、`CMBCC.dll`（x86 CSP，含设备层与 MSP），
> 两者均已在 `Library/HengBao USB Manage/` 与 `Manager/tools/HengBaoIda/`（IDA 数据库）。

### 2.2.5 ✅ 已攻克（2026-09-21）：MSP 协议完整复刻并实机验证

`HengBaoProbe.exe --msp-open` 已能**不依赖任何厂商 DLL/工具**，用自研实现完成握手并用安全报文读卡：

```
00A4000002ADF1 → SW=0x6109
00C0000009     → SW=0x9000  数据 9 字节  6F07840548424B4559              （FCI，DF 名 "HBKEY"）
00A40000020001 → SW=0x9000
00B000004C     → SW=0x9000  数据 76 字节 0000030009434D42435F534B4600…  （"CMBC_SKF"）
00A40000020003 → SW=0x9000
00B0000020     → SW=0x9000  数据 32 字节 434D42430000…31315F4F70656E544F4B45（"CMBC" / "11_OpenTOKE"）
0020000000     → SW=0x6102  （VERIFY，等待口令）
```

与官方 `CMBCu.exe` 的设备层日志**逐字节一致**；且 `00A40000020001` 与 `00A40000020003`
的应答密文完全相同（都回 `0002900080000000`），印证了 ECB 的确定性。

**完整协议规格（均已实机验证）**

| 层 | 内容 |
|----|------|
| 传输 | `IOCTL_SCSI_PASS_THROUGH_DIRECT(0x4D014)`，`TargetId=1`、`Lun=0`、`CDB=FA3A(写)/FA08(读)`、`SenseInfoOffset=48`、`TimeOut=60`（官方 300） |
| 枚举 | `GUID_DEVINTERFACE_DISK` + `GUID_DEVINTERFACE_CDROM`，设备路径（大写）须含 `"HENGBAO"` |
| 命令帧 | `43 <len_hi> <len_lo> <payload>`；响应帧 `52 <len_hi> <len_lo> <payload>` |
| 明文 APDU | `payload` = 裸 APDU 字节（握手阶段） |
| 握手 1 | `80F2030001` → 须 `SW=9000` 且应答首字节 `01` |
| 握手 2 | `80F4020000` → 须 `SW=9000` |
| 握手 3 | `80F4000087` → 135 字节；**字节 2..129 = 128 字节 RSA 模数**，指数固定 `65537` |
| 会话密钥 | 16 字节随机 `K`；`EM = 00 02 \|\| 01×109 \|\| 00 \|\| K`（PKCS#1 v1.5 外形、填充串恒为 `0x01`） |
| 握手 4 | `80F40100 80 <c = EM^65537 mod n 的 256 hex>` → 须 `SW=9000`；此后 MSP 生效 |
| MSP 密码 | **3DES-ECB（两密钥，K3=K1，密钥 = K 的 16 字节原文）**；hex→bin → 追加 `0x80` 并补 `0x00` 到 8 字节倍数 → 逐块加/解密 → bin→hex。DES 表已与标准 IP/FP/PC1/PC2/S-box 逐字节比对一致 |
| MSP 请求 | `payload` = `01` + 密文；密文 = `3DES_enc( bin( apduLen 的 4 位 hex + APDU 的 hex ) )` |
| MSP 应答 | `payload` = `01` + 8 字节密文（无独立 SW）；`hex(3DES_dec(该 8 字节))` = `长度4hex + 数据hex + SW4hex`，其中 `长度 = 数据字节数 + 2` |

> 代码位置：`Manager/tools/HengBaoProbe/Program.cs` 的 `MspHandshake` / `RsaEncryptSessionKey` /
> `Des3Ecb` / `MspSend`（`--msp-open` 模式）。
>
> 踩坑记录（极易误判）：
> 1. `MSP::XSendAPDU` 中传输层返回的是**二进制**（数据+2 字节 SW），DLL 内部才转 hex；
>    而 `MspCipher(sub_1001F02A)` 的**输入是 hex 串、输出也是 hex 串**（结果再 hex 编码一次）。
>    若把解密结果当 ASCII 直接读，会得到 `..a.?...` 这类"垃圾"——其实正是
>    `00 02 61 09 80 00 00 00` 的 ASCII 呈现。
> 2. 应答载荷里那 2 字节"SW"其实是**密文的后 2 字节**；DLL 会把它们与前面的 6 字节重新拼成
>    完整 8 字节密文再解密（`MSP::XSendAPDU` 0x1001FC01/0x1001FC2D 处）。

**下一步**：把 `MspHandshake`/`MspSend` 平移进 `HengBaoProvider`，在打开设备前先建立 MSP 会话；
之后即可实现 `VERIFY(0020…)`、`READ BINARY(00B0…)`，并最终落地「初始化 U 宝 / 清空 / 改口令」。
（注意：`VERIFY` 会消耗口令重试次数，联调时先用 `0020 0000` 查询剩余次数，不要盲目试错。）

---

## 3. 分析环境与脚本

IDA 需先把 Python 指向内置解释器（否则 `-S` 脚本会被当未知扩展名忽略）：

```powershell
& 'G:\Setup\IDA_Pro_8.3\idapyswitch.exe' --force-path 'G:\Setup\IDA_Pro_8.3\python38\python3.dll' -v
```

关键脚本（`Manager/tools/HengBaoIda/`）：

| 脚本 | 作用 |
|------|------|
| `ida_dump_exports.py` | 导出表 + 原型（首版） |
| `ida_dump2.py` | 解析导出跳转桩 → 真实实现 |
| `ida_p11.py` | **PKCS#11 专项**：强制 `plan_and_wait` 全量分析 → 解析 `E9 rel32` 跳转桩 → 判定调用约定（`retn` / `retn imm`）→ 反编译关键入口 |
| `ida_cc.py` | 批量判定某个 DLL 所有 `C_*` 的调用约定（用于交叉验证 CMBCp.dll 与 HCCBCSP11.dll） |
| `ida_hb.py` | 导入表 / 导出表 / 按关键字（ASCII+UTF-16LE）定位并反编译引用者 |
| `ida_strids.py` | 按**资源字符串 ID**（立即数）定位代码并反编译 |
| `rsrc_dump.py` | 自研 PE 资源解析（RT_STRING 字符串 ID、RT_MENU），`pefile` 不可用时的替代 |
| `hbstrings.py` | 原始文件 ASCII/UTF-16LE(CJK) 字符串提取 |
| `ida_ranges.py` | 指定地址范围裸反汇编 |

> 踩坑记录：
> 1. `-S` 脚本运行时**自动分析可能尚未完成**，必须先 `ida_auto.auto_wait()` 或 `plan_and_wait(start,end)`，否则导出地址处全是 `db 0E9h`（未识别指令）。
> 2. `idc.ARGV` 里的中文参数经 PowerShell 会变乱码，关键字要**写进 UTF-8 文件**由脚本读取。
> 3. `CMBCu.exe` 的 `.rsrc` 在 IDA 里没被加载成段（RVA 0x14F000，但 `.data` 的 virtual size 高达 0x13A41C 压住了它），所以字符串搜不到 —— 需用 `rsrc_dump.py` 单独解析。

---

## 4. PKCS#11 层（`CMBCp.dll`）

### 3.1 调用约定：`__cdecl`

`ida_p11.py` 对 68 个 `C_*` 逐一解析跳转桩并扫描函数尾的 `ret` 形式，结果：

```
C_Initialize      real=1001B2D0 ret_imm=0 cdECL
C_GetSlotList     real=1001B480 ret_imm=0 cdECL
C_OpenSession     real=1001B990 ret_imm=0 cdECL
C_Login           real=1001D130 ret_imm=0 cdECL
C_SetPIN          real=1001F2E0 ret_imm=0 cdECL
...
DllEntryPoint     real=10029855 ret_imm=12 STDCALL(3 args)
```

即：**业务函数裸 `retn`（调用者清栈 = cdecl），只有 `DllMain` 是 `retn 0Ch`**（stdcall，3 参数）。
`ida_cc.py` 对 `HCCBCSP11.dll`（飞天 ePass3003）做同样检测，结果 `SUMMARY cdecl=68 stdcall=0 other=0`。

> **结论**：两个 PKCS#11 库都必须用 `CallingConvention.Cdecl`。
> `Roadmap/06-HengBao问题分析与修复.md` §“修复 2”把它改成 `StdCall` 属于误判，
> 会破坏调用栈并让后续调用返回随机码，本报告予以更正（已在代码中改回 `Cdecl`）。

### 3.2 未实现的桩函数

以下导出是 6 字节的桩函数（`mov eax, 54h ; retn`），恒返回 `CKR_FUNCTION_NOT_SUPPORTED(0x54)`：

| 导出 | 地址 | 反汇编 |
|------|------|--------|
| `C_InitToken` | `0x1001F2A0` | `mov eax,54h; retn` |
| `C_InitPIN` | `0x1001F2C0` | `mov eax,54h; retn` |
| `C_GetObjectSize` | `0x1001DD40` | `mov eax,54h; retn` |
| `C_CopyObject` | `0x1001F3A0` | `mov eax,54h; retn` |
| `C_GetFunctionStatus` | `0x1001F540` | `mov eax,54h; retn` |
| `C_VerifyRecover` | `0x1001F4A0` | 桩 |
| `C_DeriveKey` / `C_DigestKey` / `C_DigestEncryptUpdate` 等 | — | 桩 |

**这是「不能用 PKCS#11 重置设备」的直接证据。**

### 3.3 槽位语义（重要）

```
C_GetSlotList  → sub_1001B480  → EnumSlots(sub_10012570) → sub_1002156A(&unk_1003DFA8, &count)
C_OpenSession  → sub_1001B990  → sub_100012E9(slot, &handle) → sub_1002161D（KOpenDevice）
C_GetTokenInfo → sub_1001B560  → sub_100012E9(slot, &handle) → sub_10021523（KGetDeviceInfo）
```

- `EnumSlots`（`0x10012570`）：调 `sub_1002156A` 枚举设备，把 **NUL 分隔的设备路径字符串**写进全局缓冲 `unk_1003DFA8`，
  然后把**每个字符串的首地址**写回调用方数组（`*v2++ = v4; v4 += strlen(v4)+1;`）。
  ⇒ 调用方拿到的 `CK_SLOT_ID` 其实是 **字符串指针**，必须原样回传给 `C_OpenSession` / `C_GetTokenInfo`。
  （Win32 下指针 4 字节，与 `CK_ULONG` 同宽，所以 C# 里用 `uint` 承载即可，但不能当索引重建。）
- `C_GetSlotInfo`（`0x1001F580`）：**完全硬编码** —— 描述 `"HengBao Key"`、厂商 `"HengBao Co.,Ltd"`、
  `flags=5`（`CKF_TOKEN_PRESENT|CKF_HW_SLOT`），**永远返回 CKR_OK**，所以它不能用来判断设备是否在线。
- `C_GetTokenInfo`（`0x1001B560`）：真正打开设备读信息；**打不开就返回 `6 = CKR_FUNCTION_FAILED`**。
  ⇒ **枚举时必须用 `C_GetTokenInfo` 过滤**，否则会把不存在的“幽灵槽位”当设备。

### 3.4 认证：只有用户口令

```c
int C_Login(session, userType, pPin, ulPinLen) {
  if (!init) return 0x190;                       // CKR_CRYPTOKI_NOT_INITIALIZED
  if (!session) return 0xB3;                     // CKR_SESSION_HANDLE_INVALID
  if (userType != CKU_USER/*1*/) return 0x103;   // CKR_USER_TYPE_INVALID  ← 无 SO
  if (!pPin) return 0xA0;                        // CKR_PIN_INCORRECT
  ...
  sub_1000128F(dev, pin, len, 0, &tmp);          // 卡内校验
  ...
}
```

⇒ **没有 `CKU_SO` / PUK 通道**，因此 `Unlock()`（PUK/AdminKey 解锁）在本设备上无法实现，
`ResetDevice` 只能用「当前用户口令」授权。

### 3.5 改口令：`C_SetPIN` 可用

`C_SetPIN`（`0x1001F2E0`）不是桩，会调用 `sub_100012F3(session_dev, 0, oldPin, oldLen, newPin, newLen, &out)`，
即卡内的改口令命令。返回码映射：

```
成功 → 0
失败 → 0xA0 (CKR_PIN_INCORRECT) 或 0xA4 (CKR_PIN_LOCKED)
```

⇒ **「重设口令」通过 `C_SetPIN` 实现是可靠的**。

### 3.6 对象模型

```c
C_FindObjectsInit(session, tmpl, count) {
   sub_1000157D(session->dev, listB);            // 枚举「设备（卡片）上的对象」
   sub_100015F0(session->mem, listA, tmpl, count, 0);   // 内存对象
   sub_100015F0(listB,          listC, tmpl, count, 1);
   merge(listA, listC) → session->list
}
C_DestroyObject(session, obj) {
   unlink(session->mem, obj); unlink(session->list, obj);
   if (obj->isTokenObject && obj->cardHandle) sub_100016CC(obj->cardHandle);  // 同步删卡内文件
   free(obj);
}
```

- 设备上的证书/密钥会被 `sub_1000157D` 枚举出来，所以 `C_FindObjectsInit(CKO_CERTIFICATE)` + `C_GetAttributeValue(CKA_VALUE)`
  能读出 X.509 证书（本工程 `ListContainers` 即此路径）。
- `C_DestroyObject` 对「token 对象」会一并删除卡内文件 ⇒ **「清空内容」可通过遍历各类对象并逐个 `C_DestroyObject` 实现**。
- 同一对象可能被两类列表同时命中，删除顺序上会出现 `CKR_OBJECT_HANDLE_INVALID(0x82)`，属正常，应容忍。

### 3.7 `CK_TOKEN_INFO` 的厂商私有语义

`C_GetTokenInfo`（`0x1001B560`）填充布局（标准 160 字节）：

| 偏移 | 字段 | 厂商实际写入 |
|------|------|--------------|
| 0/32/64/80 | label / manufacturerID / model / serialNumber | 卡片读回值（`sub_10001523`），缺省回退 |
| 96 | `flags` | `1037 = 0x40D` |
| 100 | `ulMaxSessionCount` | 20 |
| **104** | **`ulSessionCount`** | **复用为「PIN 剩余尝试次数」**（来自 `sub_1000105F(slot)+8`） |
| 108 | `ulMaxRwSessionCount` | 20 |
| 112/116/120 | `ulRwSessionCount`/`ulMaxPinLen`/`ulMinPinLen` | 1 / 100 / 0 |
| 124–136 | 容量四元组 | 20000 / 10000 / 20000 / 10000 |
| 140/142 | hardwareVersion / firmwareVersion | 3.1 / 3.1 |
| 144 | `utcTime` | `"%d%02d%02d%02d%02d%02d"` 本机时间 |

⇒ 本工程把偏移 104 的数值作为「PIN 剩余尝试次数」展示（UI 的设备备注里）。

### 3.8 跨进程口令共享

`CMBCp.dll` 与 `CMBCC.dll` 都含字符串 `HENGBAO_FILEMAPPING_STRING_ghSDWEADFO`，
通过 `OpenFileMappingA` / `CreateFileMappingA` 共享口令与重试计数，
并有 `VerifyPIN DialogBox1`、`请确认U宝显示的信息`、`PIN认证，按"OK"键确认，或按"C"键取消` 等资源串
（`CMBCp.dll` 的对话框资源 ID `0x8F`）。

⇒ 该 U 宝**带屏幕与按键**，认证可能是「电脑上输入 + U 宝上按 OK 确认」双因子流程。

---

## 5. 设备层：HID / SCSI-BOT / ISO7816

`CMBCp.dll` 导入表（节选）证明它自己实现设备通信：

```
HID      HidD_GetAttributes / HidD_GetPreparsedData / HidD_GetFeature / HidD_SetFeature / HidP_GetCaps
SETUPAPI SetupDiEnumDeviceInterfaces / SetupDiGetDeviceInterfaceDetailA / SetupDiDestroyDeviceInfoList
KERNEL32 DeviceIoControl / CreateFileA / ReadFile / WriteFile
```

对应的类名（字符串）：`THidTSP::EnumDevice/OpenDevice/CloseDevice/SendData`、
`CTSPBot::EnumDevice/OpenDevice`、`TBotUTSP::CloseDevice`、`MSP::XSendAPDU`、
以及 `HidD_SetFeature dwReturn=0x%x`、`DeviceIoControl(uSptdWbOut.SPTD.DataBuffer…`（SCSI 直通）等日志串。

设备打开流程（`KOpenDevice` = `0x1002161D`）：

1. `sub_10028226(path)` 打开传输通道；
2. 从路径尾部分解 2 位十六进制组（`strtoul(v5,0,16)`，直到值 < 0x80）→ 得到 `v18[]` 参数；
3. `sub_100250EE(dev, 44529, …)` → `44529 = 0xADF1`，即 **SELECT ADF1**：`00 A4 00 00 02 AD F1`；
4. `sub_100251C0(dev, 3)` + `sub_100253C4(dev, 0, buf, &20)` → 读 20 字节；
5. `sub_100251C0(dev, 1)` + `sub_100253C4(dev, 0, buf, &76)` → 读 76 字节；
6. 写入对象结构的 `+456 / +520` 等字段。

`KGetDeviceInfo`（`0x10021833`）从对象 `+264 / +328 / +392 / +456 / +520 / +584…` 拷出 5 段字符串 + 3 个 DWORD 给 `C_GetTokenInfo`。

### 4.1 从官方工具与 CSP 提取到的 APDU 模板

（`CMBCu.exe` `.data` 0x13584–0x137xx、`CMBCC.dll` 0x3048C–0x30BA4 等，均为 `%02X/%04X` 格式化模板）

```
8034%02X00%02X            8034%02X000A            00B0%04X%02X
00D6%04X%02X%s            002000%02X%02X%s        042000%02X08%s
002001%02X00              042001%02X00            00C00000%02X
00840000%02X              80320000%02X            80320001%02X
80320004%02X              805E01%02X%02x%s%s      845E01%02X%02x%s%s
805E01%02X00              845E01%02X00            80F40100%02X%s
80E002000B%04X%04X%02X%02X%02X%02X%02X00          （Put Data 封装，含 1E/1D/20/08/0C/04/03/02/01/00 等 P1P2）
80E002000D0C%04X…%02X00%02X00                     80E001000EADF1%04xF1F18001FF48424B4559   （HBKEY）
80E0000017%04X%04X%02X%02X%02X%02XFF315041592E5359532E4444463031   （1PAY.SYS.DDF01）
80C0%02X00%02X%08X%s      80C0%02X01%02X%s        80C0%02X0F%02X%s
80C0%02X02%02X%s          80C60102%02X%s          80C60100%02X%s
80C2%04X%02X%s            80C6%04X%02X%s          80C8%02X%02X%02X%s
80CA0300%02X%s            80CA0302%02X%s          80CE%04X01%02X
80E80102%02X%s            80EA0102%02X%s          80EC0100%02X%04X%s
```

内嵌的完整指令样例（`CMBCu.exe` 文件偏移 0x1295C 起）：

```
00D684000400300000                                    读二进制
00D6830020434D4243…31315F4F70656E544F4B45             "…CMBC…1_OpenTOKE"
00D68300A05572616E7553616665204B657920312E32…         "UranuSafe Key 1.2" + "HB 12345678" …
00A4000002ADF1                                        SELECT ADF1
00A40000023F00                                        SELECT MF(3F00)
80E001000EADF1%04xF1F18001FF48424B4559               → "HBKEY"
80D4010015383333330148425F52656C6F61645F557365725F5F  → "83333\x01HB_Reload_User__"
80D401001536F0EF330148425F4170704B65795F4144465F5F5F  → "…HB_AppKey_ADF___"
80D401001539F0F3330048425F4D61696E4B65795F4144465F5F  → "…HB_MainKey_ADF__"
80D401001539F0F0330248425F4D61696E4B65795F4D465F5F5F  → "…HB_MainKey_MF___"
802A000008FFFFFFFFFFFFFFFF                            性能/安全操作
```

可见该卡是**带文件系统的 COS**（MF `3F00`、ADF1、`HB_MainKey_*`、`HB_AppKey_ADF`、`HB_Reload_User` 等文件）。

---

## 6. 重置（「初始化 U 宝」）链路

### 5.1 官方工具的实现

`CMBCu.exe` 的字符串是**资源字符串**，因此先用 `rsrc_dump.py` 解出 ID，再用 `ida_strids.py`
按立即数定位代码。关键 ID：

| 资源 ID | 文案 |
|---------|------|
| 135 | `验证U宝口令，请按键确认` + 说明行 |
| 136 | `修改U宝口令，请按键确认` |
| **137** | **`初始化U宝，请按键确认`** |
| 138 | `等待按键确认超时！` |
| 139 | `已按"C"键取消了U宝的操作！` |
| 140 | `剩余:%d秒` |
| 1094 | `U宝硬件初始口令为"111111"。您尚未修改此口令，出于安全，请重新设置！` |
| 1096 | `U宝口令已经锁定！` |
| 1100 | `为了交易安全，建议使用密码键盘输入密码！` |
| 1107 | `为了交易安全，新口令不允许修改为"111111"！` |
| 1108 | `请连接U宝！` |
| 1109 | `U宝初始化` |
| **1110** | **`注意：初始化会将U宝内的证书信息全部删除，继续执行吗？`** |
| **1111 / 1112** | **`初始化U宝成功` / `初始化U宝失败`** |
| 1115 | `验证U宝口令失败！` |
| 1145 / 1146 | 菜单：`修改U宝口令` / `初始化U宝` |

**初始化处理函数 = `sub_407E53`**（引用 ID 1110 与 1111）：

```c
int sub_407E53(HWND hDlg) {
  if (!dword_54E034) return 0;
  LoadStringA(hInstance, 0x454, &Buffer, 20);   // 1108 请连接U宝！
  LoadStringA(hInstance, 0x455, Text, 256);     // 1109 U宝初始化
  SendMessageA(GetDlgItem(hDlg,1015), 0x110C, 0, lParam);   // 自定义控件取设备对象
  v3 = lParam[9];
  if (sub_4015B0(hDlg, Text, &Buffer, 0x131) == 1) {        // 用户点「确定」
      sub_4099C6(*(char**)v3, &hMutex);                     // 打开设备
      v5 = *(_DWORD*)(*(_DWORD*)(v3+4) + 320);              // 设备上下文
      if (sub_402225(hMutex, "111111", lstrlenA("111111"), v5)) {   // ← 校验出厂口令 111111
          sub_403BE5(0);
          sub_4083B1(hDlg);                                 // 重新启用界面按钮
          LoadStringA(hInstance, 0x456, Text, 256);         // 1110 删除证书警告
          sub_4015B0(hDlg, Text, &Buffer, 0x40);
          sub_4088F1(hDlg);                                 // 刷新设备列表/证书树
      } else {
          LoadStringA(hInstance, 0x457, Text, 256);         // 1111
          sub_4015B0(hDlg, Text, &Buffer, 0x30);
      }
      return sub_409BD3(hMutex);
  }
}
```

配合 ID 137/138/139/140 的**按键等待线程 `StartAddress`（`0x405FBF`）**：
提示 `初始化U宝，请按键确认`，用 `SetTimer` 倒计时（`剩余:%d秒`），
超时报 `等待按键确认超时！`，用户按 C 时报 `已按"C"键取消了U宝的操作！`。

⇒ 官方「初始化 U 宝」= **校验出厂口令 111111 → 提示用户在 U 宝上按键确认 → 卡片文件系统复位 + 证书清空**，
等价于把设备打回出厂态。**该逻辑没有导出，只能由工具/CSP 内部调用。**

### 5.2 为什么 Manager 不能复刻

1. 需要厂商自研的 **HID / SCSI-BOT 通道 + MSP 封装（含应答解密）**，非标准 PCSC；
2. 需要**卡片文件系统级操作**（SELECT/READ/UPDATE/性能安全操作等一整套 APDU 编排）；
3. 需要**U 宝物理按键确认**与倒计时交互；
4. 需要在**没有 SO PIN / PUK** 的前提下用出厂口令 `111111` 授权；
5. 官方工具一次初始化就 `DELETE`/重建 ADF 与密钥文件，**误操作即不可逆**。

### 5.3 本工程实现的重置语义

```
重置（恒宝） = 用当前口令 C_Login(CKU_USER)
             → 遍历 CKO_CERTIFICATE / CKO_PRIVATE_KEY / CKO_PUBLIC_KEY / CKO_DATA
                逐个 C_DestroyObject（含卡内文件联动删除）   ← 「清空内容」
             → C_SetPIN(旧口令, 新口令)                       ← 「重设密码」
             → 关闭会话、用新口令重新登录
```

- 界面（`MainForm.DoReset`）在 `provider.ResetRequiresCurrentPin == true` 时只询问
  **当前口令 + 新口令**，不再询问 PUK / Admin Key，并在结果框展示执行报告
  （`HengBaoProvider.LastResetSummary`：删除对象数 / 失败项）。
- 若需要「恢复出厂态（口令回 111111）」，界面已明确提示使用 **厂商工具 `CMBCu.exe`** 或到柜台处理。

---

## 7. Manager 侧改动清单

| 文件 | 改动 |
|------|------|
| `USBKey.Core/UsbKey/CkmNative.cs` | ① 全部委托改为 **`Cdecl`**；② 槽位参数统一 `uint` 并注明是**不透明句柄**（设备路径指针）不得当索引；③ 补齐 `CKR_*`（0x06/0x54/0x82/0x103/0x180/0x190…）、`CKF_*`、`CKA_*`、`CKM_*`；④ `CK_TOKEN_INFO` 文档化厂商私有字段；⑤ `C_GetSlotList` 支持 `null` 取数量 |
| `USBKey.Core/UsbKey/HengBaoProvider.cs` | 全量重写：`RefreshSlots` 用 `C_GetTokenInfo` 过滤真实设备（1.2s 缓存）+ 从设备路径解析 VID/PID 并套用白名单；`EnsureSession` 支持槽位变更时自动重开会话；`ListContainers` 按 `CKA_ID` 关联私钥、标注「有/无私钥」；`ImportPfx` 明确报「本设备不支持导入外部私钥」；`ResetDevice` 实现「清空内容 + 重设口令」；新增 `EraseAllObjects()` 与 `LastResetSummary`；`Unlock/GenerateChallenge/UnlockByChallenge` 给出明确不支持原因 |
| `USBKey.Core/UsbKey/EPass3003Provider.cs` | `ResetDevice` 修正为使用**真实槽位**（原先把界面索引当槽位号传给 `C_InitToken`） |
| `USBKey.Manager/MainForm.cs` | `DoReset` 支持 `ResetRequiresCurrentPin`：询问当前口令、跳过 PUK/AdminKey、展示恒宝执行报告 |
| `tools/HengBaoProbe/Program.cs` | 探针重写为 `Cdecl` + 正确的槽位用法；覆盖 枚举/槽位信息/Token信息/会话/登录/对象统计/证书解析/签名自检/清空/改口令；`C_InitToken`/`C_InitPIN` 默认**不调用**（`--probe-init` 才探测，避免在非桩实现上误清空令牌） |

---

## 8. 实机验证方法

```powershell
cd g:\Codes\USBKeyDriver\Manager\tools\HengBaoProbe
dotnet build -c Debug
# 1) 只读体检（默认口令 111111）
.\bin\Debug\net8.0\HengBaoProbe.exe "G:\Codes\USBKeyDriver\Library\HengBao USB Manage\CMBCp.dll" 111111
# 2) 加签名自检
.\bin\Debug\net8.0\HengBaoProbe.exe "" 111111 --sign
# 3) 清空内容 + 重设口令（会真的写入，需在提示处输入 YES）
.\bin\Debug\net8.0\HengBaoProbe.exe "" 111111 --reset 654321
```

判读要点：

| 现象 | 含义 |
|------|------|
| `C_GetSlotList` 返回 0 | 设备未插入，或驱动未切到 HID/SCSI 通道（只在 U 盘/CD-ROM 模式） |
| `C_GetSlotList` 返回 ≥1，但 `C_GetTokenInfo → CKR_FUNCTION_FAILED(6)` | 槽位是枚举出的路径但**设备打不开**：驱动/固件异常、被其他进程独占、或非 HID 模式 |
| `C_OpenSession → 0x180` | 未带 `CKF_SERIAL_SESSION(0x04)` |
| `C_Login → CKR_PIN_INCORRECT(0xA0)` | 口令错（出厂为 `111111`）；注意 U 宝可能需要按键确认 |
| `C_SetPIN → 0xA0/0xA4` | 旧口令不对 / 口令已锁 |
| `C_Sign` 成功 | 卡内私钥可用，证书与私钥 `CKA_ID` 匹配 |

---

## 9. 遗留问题（需实机确认）

1. **未接入实机**：本次分析全程静态（当前机器上无 VID_1677 等恒宝 CCID/HID 令牌）。
   `C_GetTokenInfo` 返回 `CKR_FUNCTION_FAILED(6)` 在无设备时是预期行为，需实机复核是否存在其它原因。
2. `C_DestroyObject` 对**卡片内证书/私钥对象**的实际删除效果（是否同时删掉卡内文件、私钥是否可删）需实机验证；
   若私钥不可删，则「清空内容」只能清掉证书，需在界面上说明。
3. 「一张卡多个证书」时的 `CKA_ID` 配对假设需实机验证（本工程按 SHA1 指纹写 `CKA_ID`，读回时按 `CKA_ID` 配对）。
4. 设备层是否还有**未发现的重置专用 APDU**（例如 `80E4…` DELETE FILE 序列）—— 若能在实机上抓包对比
   `CMBCu.exe` 初始化前后的 HID/SCSI 报文，即可补全「真·初始化」实现。

---

## 10. 对 `Roadmap/06-HengBao问题分析与修复.md` 的更正

| 06 文档的结论 | 实际（2026-09-20 复核） |
|---------------|------------------------|
| 路径配置错误（`Library\HengBao\*.dll` 应为 `Library\HengBao USB Manage\*.dll`） | **正确**，已保留（`USBKey.Manager.csproj` 第 11–16 行） |
| 所有 PKCS#11 委托应从 `Cdecl` 改为 `StdCall`（“修复 2”） | **错误**。IDA 逐函数验证 68/68 均为 `__cdecl`（裸 `retn`），`DllMain` 才是 `retn 0Ch`。已改回 `Cdecl`；用 `StdCall` 会栈失衡并产生随机错误码 |
| 结论「枚举设备返回 0 个设备」由调用约定导致 | 除约定外，还有**槽位是不透明句柄**、**必须用 `C_GetTokenInfo` 过滤**两个原因，二者已同时修正 |

---

## 附录 A：关键地址速查

| 符号 | 地址 | 说明 |
|------|------|------|
| `C_Initialize` | `0x1001B2D0` | 初始化，重复调用返回 `0x191` |
| `C_GetSlotList` | `0x1001B480` → `0x10012570`(EnumSlots) → `0x1002156A` | 返回设备名字符串指针数组 |
| `C_GetSlotInfo` | `0x1001F580` | 硬编码 |
| `C_GetTokenInfo` | `0x1001B560` → `0x10012610`/`0x1002161D`(KOpenDevice) | 真正打开设备 |
| `C_OpenSession` | `0x1001B990` → `0x10012610` | 需 `CKF_SERIAL_SESSION` |
| `C_Login` | `0x1001D130` | 仅 `CKU_USER` |
| `C_SetPIN` | `0x1001F2E0` → `0x100012F3` | 改口令（可用） |
| `C_InitToken` / `C_InitPIN` | `0x1001F2A0` / `0x1001F2C0` | 桩，返回 `0x54` |
| `C_FindObjectsInit` | `0x1001DD60` → `0x1000157D`(设备对象) + `0x100015F0` | 合并卡内与内存对象 |
| `C_DestroyObject` | `0x1001DC20` | 联动删卡内文件 |
| `KGetDeviceInfo` | `0x10021833` | 从设备对象拷出 label/serial 等 |
| 官方工具初始化处理 | `0x407E53` | 校验 `"111111"` + 按键确认 |
| 官方工具按键等待线程 | `0x405FBF` | `剩余:%d秒` 倒计时 |
| 官方工具改口令 | `0x407C87` / `0x407FCF` | ID 1107/1094/1118 |

## 附录 B：工具链复现命令

```powershell
# 1) 让 IDA 用内置 Python3
& 'G:\Setup\IDA_Pro_8.3\idapyswitch.exe' --force-path 'G:\Setup\IDA_Pro_8.3\python38\python3.dll'

# 2) PKCS#11 全量分析（调用约定 + 反编译）
cd g:\Codes\USBKeyDriver\Manager\tools\HengBaoIda
& 'G:\Setup\IDA_Pro_8.3\idat.exe' -A -c -L"log_p11.txt" -S"ida_p11.py" CMBCp.dll

# 3) 资源字符串 ID（CMBCu.exe）
python rsrc_dump.py rsrc_cmbcu.txt CMBCu.exe

# 4) 按资源 ID 定位代码
& 'G:\Setup\IDA_Pro_8.3\idat.exe' -A -c -L"log_strids.txt" -S"ida_strids.py" CMBCu.exe

# 5) 调用约定交叉验证（其它厂商 PKCS#11）
& 'G:\Setup\IDA_Pro_8.3\idat.exe' -A -c -L"log_cc.txt" -S"ida_cc.py cc_epass.txt" HCCBCSP11.dll
```
