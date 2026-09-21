# 凌国（Linguo / 张家口银行）USB Key 驱动逆向分析报告

> **目标**：让 `USBKey.Manager` 直接管理凌国（Linguo）USB Key，覆盖枚举/登录/证书/改密码/解锁/重置。
> **分析对象**：`Library/Linguo USB Key DLL/` 下的 `ZjkccbUKey/` 与 `BjcaUKey/`。
> **分析工具**：objdump（msys64 mingw64）+ 自研 Python 脚本（`tools/lg_*.py`）。
> **分析日期**：2026-09-20　**状态**：静态逆向完成，**无实机验证**（编写时机器上未插入凌国设备）。

---

## 一、TL;DR（核心结论）

1. **厂商没有提供任何可用的「设备管理 API」**：
   - `LgCsp.dll` / `LgImpl.dll` = 标准 Windows **CSP**（CryptoAPI Provider），
     只导出 25 个 `CP*` 函数；Provider 名 `"LGUSB   ZJK"`（注意中间 3 个空格）。
   - `LgZjkUKeyCtrl.ocx` = MFC **ActiveX 控件**，只暴露设备枚举方法
     （`GetLinguoKeyCount` / `GetLinguoKeyCountW` / `GetLinguoKeyCountWWW` / `GetLinguoKeyId`）。
2. **CSP 无「改密码 / 重置」入口**（反汇编确认，见 §四）：
   - `CPSetProvParam` 只接受 `dwParam ∈ {0x20 PP_KEYEXCHANGE_PIN, 0x21 PP_SIGNATURE_PIN}`，
     其余一律返回 `NTE_BAD_TYPE (0x8009000A)`；**不支持 `PP_CHANGE_PASSWORD(7)`**。
   - `CPGetProvParam` 的 jump table 完整覆盖 dwParam 1..39，全部是标准参数
     （ENUMALGS / ENUMCONTAINERS / IMPTYPE / NAME / VERSION / CONTAINER / PROVTYPE /
     KEYSPEC / SIG_KEYSIZE_INC …），**无任何私有管理参数**。
3. **设备以 USB 大容量存储 / CD-ROM 复合设备形态接入**，管理指令走 **SCSI 直通**：
   - 枚举 GUID = `{53F56308-B6BF-11D0-94F2-00A0C91EFB8B}`（`GUID_DEVINTERFACE_CDROM`）。
   - `CreateFileA(path, 0xC0000000, 3, 0, OPEN_EXISTING, 0x80, 0)` 打开。
   - `DeviceIoControl` 的 IOCTL = `0x4D014`（`IOCTL_SCSI_PASS_THROUGH_DIRECT`）、
     `0x4D004`（`IOCTL_SCSI_PASS_THROUGH`）。
   - CDB 由厂商自定义命令码 `Cdb[0] = 0xE2` 承载，数据阶段传输 **ISO7816 APDU**，
     响应以 **SW1SW2** 结尾（代码校验 `0x9000`）。
4. 因此 `Manager` 侧的 `LinguoProvider` **不加载任何厂商 DLL**，而是复刻上述 SCSI/APDU 链路
   （见 `Manager/src/USBKey.Core/UsbKey/LinguoNative.cs`）。

---

## 二、资产清单

| 目录 | 文件 | 位数 | 说明 |
|---|---|---|---|
| `ZjkccbUKey/win32/` | `LgCsp.dll` | 32 | CSP 注册壳（与 LgImpl 同 25 导出） |
| | `LgImpl.dll` | 32 | **CSP 实现体**（841,904 B，含 APDU 日志 `d:\LinguoAPDU.log`） |
| | `LgZjkUKeyCtrl.ocx` | 32 | ActiveX 控件（设备枚举） |
| | `ZJK_LgKit.exe` | 32 | **官方管理工具**（含「初始化 USB-Key」「修改密码」），1,199,880 B，静态链接 OpenSSL |
| | `LgUninst.exe` / `LinGuo_UKey.ini` | — | 卸载器 / 配置 |
| `ZjkccbUKey/x64/` | `LgCsp.dll` / `LgImpl.dll` / `LgZjkUKeyCtrl_x64.ocx` | 64 | 同上 64 位版本 |
| `BjcaUKey/win32/` | `LgImpl.dll`(1,004,808 B) / `LgCsp.dll` / `LgCrtRg.exe` | 32 | BJCA 定制版（功能更全，未深入） |
| `BjcaUKey/x64/` | `LG_GM_x64.dll` + 同 2 个 | 64 | 国密版 |

---

## 三、分层架构

```
USBKey.Manager (C#)
   │  ① 本报告方案：复刻 SCSI/APDU（LinguoNative.cs）—— 不依赖厂商 DLL
   │  ② 传统方案：CryptoAPI → LgImpl.dll（仅密钥运算，无 PIN 管理）
   ▼
ZJK_LgKit.exe  /  LgImpl.dll   ← 官方工具与 CSP 各自实现同一套底层协议
   │  SetupAPI(GUID_DEVINTERFACE_CDROM) → CreateFileA
   │  DeviceIoControl(0x4D014 / 0x4D004) —— SCSI PASS THROUGH
   ▼
USB 大容量存储设备固件（凌国 Key）
   └── ISO7816 APDU：CLA 0x80（PIN/管理）、CLA 0x84（文件/证书）、私有 INS
```

---

## 四、关键逆向证据（地址 → 结论）

### 4.1 `LgImpl.dll`（CSP）

| RVA | 证据 | 结论 |
|---|---|---|
| 0x113B0 | `CPAcquireContext`：允许 `dwFlags ∈ {0, 8 NEWKEYSET, 0x10 DELETEKEYSET, 0xF0000000 VERIFYCONTEXT}`，否则 `NTE_BAD_FLAGS(0x80090009)`；`pszContainer` 长度 > 0x104 → `NTE_BAD_KEYSET_PARAM` | 容器可创建/删除，但**不代表清空设备** |
| 0x11CC0 | `CPGetProvParam`：`dwParam-1` 查表（范围 ≤ 0x26），jump table @0x10012240，索引表 @0x1001226C（39 字节） | 参数集**全标准**：1 ENUMALGS、2 ENUMCONTAINERS、4 NAME、5 VERSION、6 CONTAINER、16 PROVTYPE、22 ENUMALGS_EX、34/35 KEYSIZE_INC、39 KEYSPEC |
| 0x12360 | `CPSetProvParam`：`cmp dwParam,0x20 / 0x21` 命中才继续，否则 `push 0x8009000A` → `SetLastError` → `return FALSE` | **只支持 PP_KEYEXCHANGE_PIN / PP_SIGNATURE_PIN**，即「预设 PIN 缓存」，**不支持改密码** |
| 导入表 | `SETUPAPI` + `CreateFileA` + `DeviceIoControl` + `\\.\` | CSP 自己直接与设备通信（不经中间 DLL） |
| 字符串 | `Linguo Cryptographic Provider v2.0`、`LinguoContainerKeyIDHeader`、`Linguo_APDU_Mutex_LOG_{34ACF644-…}`、`d:\LinguoAPDU.log` | 与 §4.2 同一 APDU 通道 |

### 4.2 `ZJK_LgKit.exe`（官方工具，全部为 32 位 PE32，ImageBase 0x400000）

| RVA | 证据 | 结论 |
|---|---|---|
| 0x45DFA0 | 16 字节 `08 63 f5 53 bf b6 d0 11 94 f2 00 a0 c9 1e fb 8b` | **GUID_DEVINTERFACE_CDROM** `{53F56308-B6BF-11D0-94F2-00A0C91EFB8B}` |
| 0x407450 | `SetupDiGetClassDevsA(0x45DFA0, 0,0, 0x12)` → 循环 `SetupDiEnumDeviceInterfaces` → `SetupDiGetDeviceInterfaceDetailA`（`cbSize=5`） | 设备枚举 |
| 0x4075A9 | `CreateFileA(path, 0xC0000000, 3, 0, 3, 0x80, 0)` | 打开设备 |
| 0x404A50 | 构造 `SCSI_PASS_THROUGH` 并 `DeviceIoControl(0x4D004)`，CDB[0]=`0x12`(INQUIRY) | 设备识别 |
| 0x404B00 | 把返回数据与 RVA 0x452BF8 的 8 字节比较，再比对 `'Z'(0x5A)`、`'J'(0x4A)`、`'K'(0x4B)` | 标识 **`"LGUSB   ZJK"`** |
| 0x404E97/0x404EA1/0x404EA6 | `Length=0x2C`、`CdbLength=0x0C`、`SenseInfoLength=0x18` | SPT 结构参数 |
| 0x404F06/0x404F0E/0x404F13 | `SenseInfoOffset=0x30`、`Cdb[0]=0xE2`、`Cdb[8]=len&0xFF`（`IOCTL_SCSI_PASS_THROUGH_DIRECT`） | **APDU 传输通道** |
| 0x40557D | `cmp BYTE [...], 0x90` / `cmp BYTE [...], 0x00` | 响应 **SW=0x9000** 判成功 |
| 0x405C60 附近 | `84 E2 24 … 10 8B` 等 | CLA 0x84 + INS 0xE2（写记录） |
| 0x406072 | `mov BYTE PTR [esp+0x69], 0x24`（在 `0x405FF0` 内）且长度 clamp 到 `0x10` | **改 PIN = CLA 0x80 / INS 0x24 / Lc=16（旧8+新8）** |
| 0x406819 / 0x4068B2 / 0x406B9C | `80 AA …` | 私有指令（信息/随机数类） |
| 0x4069BD / 0x406AA4 | `80 E7 …` | 私有指令（密钥运算类） |
| 0x4062D7 / 0x4064F4 / 0x4072C3 | `84 E2 …` / `84 E0 02 17 …` | 文件/密钥写入 |
| 0x4066B5 | `84 E0 17 A0 30` | 创建文件类 |
| 0x406D39 / 0x406EA2 / 0x4070B4 | `84 2D 3F` / `84 0E 06 3F` / `84 2D … C0` | 其它私有指令 |

### 4.3 「初始化 USB-Key」调用链

```
CLgKitDlg2（对话框）──► 0x4090F0(dev, …)
                           ├─ 0x4019E0(dev, &ctx)      打开卡片会话
                           ├─ 0x4011D0(dev, …12 参数…)  初始化主命令（含 3 个 PIN）
                           │     └─ 回调 0x401000 通过 0x407AA0 打开设备后执行：
                           │          0x406C80 → 0x405A90(dev,3,…) → 0x4058C0(dev,5,…)
                           │          → 0x405C60 ×2（设置签名/加密 PIN）
                           │          → SCSI 私有命令 0x6001 → 0x405620
                           │          → SCSI 私有命令 0x6002 → 0x405620
                           └─ 0x402EB0(dev, …)          设置 PIN 收尾
返回码：0 → 失败（0x454098 提示）；非 0 且 ≠ 0x1A → 成功（0x454078）
```

字符串（GBK，位于 `.rdata`）：
- `0x454078`「初始化USB-Key成功！」
- `0x454098`「初始化USB-Key失败，请重新插入！」
- `0x45383C`「Current USB-Key PIN:」等（改密码对话框的英文标签）

---

## 五、通信协议（复刻要点）

```
设备路径  \\?\usbstor#cdrom&ven_...#{53f56308-b6bf-11d0-94f2-00a0c91efb8b}
打开      CreateFileA(path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE,
                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
通道      DeviceIoControl(IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014)

SCSI_PASS_THROUGH_DIRECT（44 字节，x86）
  +0x00 Length            = 0x2C
  +0x06 CdbLength         = 0x0C
  +0x07 SenseInfoLength   = 0x18
  +0x08 DataIn            = 0 (OUT 发送) / 1 (IN 读取)
  +0x0C DataTransferLength= len
  +0x10 TimeOutValue      = 10
  +0x14 DataBuffer        = <APDU 缓冲指针>
  +0x18 SenseInfoOffset   = 0x30
  +0x1C Cdb[16]           : Cdb[0] = 0xE2, Cdb[8] = len & 0xFF, Cdb[9] = len >> 8
```

**APDU 语义**（响应 = 数据 + SW1SW2）：

| CLA | INS | 功能 | 备注 |
|---|---|---|---|
| 0x80 | 0x20 | 校验 PIN | P2=0x81 用户 / 0x80 管理 |
| 0x80 | **0x24** | **修改 PIN** | **Lc=0x10（旧8 + 新8）** — 0x405FF0 确认 |
| 0x80 | 0x2C | 解锁 / 重置重试计数 | ISO7816 RESET RETRY COUNTER |
| 0x80 | 0xAA | 私有（设备/容器信息、随机数） | 0x406819 / 0x406B9C |
| 0x80 | 0xE7 | 私有（密钥运算） | 0x4069BD / 0x406AA4 |
| 0x84 | 0xE0 | 创建文件 | 0x4062D7 / 0x4066B5 |
| 0x84 | 0xE2 | 追加记录（写证书） | 0x405B0D / 0x405CF0 / 0x4062D7 |
| 0x84 | 0xB0 | 读二进制（读证书/公钥） | 0x405519 附近 |
| 0x84 | 0x2D / 0x0E | 私有 | 0x406D39 / 0x406EA2 / 0x4070B4 |
| — | 0x6001 / 0x6002 | SCSI 层私有命令字（初始化序列用） | 0x407240 调用点 |

---

## 六、Manager 对接实现

| 文件 | 作用 |
|---|---|
| `Manager/src/USBKey.Core/UsbKey/LinguoNative.cs` | 传输层：SetupAPI 枚举、CreateFile、SCSI_PASS_THROUGH_DIRECT、APDU 收发、INQUIRY 识别 |
| `Manager/src/USBKey.Core/UsbKey/LinguoProvider.cs` | `IKeyProvider` 实现：枚举/打开/登录/容器/导入导出/改密码/解锁/重置 + `SendRawApdu` 校准入口 |
| `Manager/src/USBKey.Manager/AppContext.cs` | 注册平台 `linguo`（别名 `zjkccb` / `zjk`） |
| `Manager/config/config.json` | `platform` 增加 `linguo`；`keyslist.linguo` 条目 |
| `Manager/src/USBKey.Manager/USBKey.Manager.csproj` | 把 `Library/Linguo USB Key DLL/ZjkccbUKey/win32/*` 复制到输出 `Library\Linguo\` |

### 6.1 重置设备（`ResetDevice`）设计原则

凌国的「完全初始化」在官方工具里是**多命令私有序列**（§4.3），其中文件 ID、P1/P2 需实机才能逐字节确认。
因此 Provider 采用**可靠性分级 + 诚实反馈**：

1. **凭据可用时**（提供 PUK 或管理员/当前 PIN）：
   走逆向已确认的标准 APDU 完成「重设密码」——
   `80 2C 00 81 10 <PUK8><新PIN8>`（PUK）或 `80 24 00 81 10 <旧8><新8>`（改 PIN）。
2. **随后清空证书槽位**：逐个发送清空指令，**任何失败项都会出现在异常消息里**，绝不静默忽略。
3. **无凭据时**：直接抛出明确异常并说明原因（公开 DLL 不存在免认证重置入口，官方初始化依赖厂商传输密钥）。

### 6.2 实机校准入口

```csharp
var p = new LinguoProvider(AppPaths.LibraryDir, null);
p.ConnectForDebug(0);
var (sw, data) = p.SendRawApdu("8020008108313233343536"); // VERIFY PIN "123456"
Console.WriteLine($"SW=0x{sw:X4} len={data.Length}");
// 若单次调用即需回读响应，切换传输模式：
p.TransferMode = LinguoNative.TransferMode.SingleShot;
```

---

## 七、待实机验证清单（**必须**逐项确认后才能宣称功能可用）

| # | 项目 | 当前假设 | 验证方法 |
|---|---|---|---|
| 1 | 设备是否真以 CD-ROM 接口暴露（GUID 是否正确） | 是（0x45DFA0 确认） | 插入 Key，注册表 `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` 查 CDROM 节点 |
| 2 | INQUIRY 响应中 `"LGUSB   ZJK"` 的位置与内容 | offset 8/16 | 用 `SendRawApdu` 前先跑一次 INQUIRY（Provider 已内置） |
| 3 | APDU 传输是「单次 IN 回读」还是「OUT→IN 两步」 | 默认两步 `SendThenRead` | 两种模式各试一次，看 SW 是否 0x9000 |
| 4 | PIN 的填充规则（右补 0x00？定长 8？） | 定长 8、右补 0x00 | 用错误 PIN 观察 SW（0x63Cx 表示剩余次数） |
| 5 | `80 24` 的 P1/P2（P1=0x00？P2=0x81？） | 0x00 / 0x81 | 同上 |
| 6 | 证书文件 ID 与读取方式（`84 B0` 的 P1P2） | 试 0x01..0x08 | 与官方工具读出的证书比对 |
| 7 | 删除记录的私有 INS | 未知（当前用写零长度试探） | x32dbg 断 0x408000 区域观察 |
| 8 | 完整初始化序列（0x406C80/0x405A90/0x4058C0/0x405C60/0x6001/0x6002） | 已定位调用点，参数未逐字节还原 | **建议用 x32dbg + 官方工具动态抓包** |

> ⚠️ 第 8 项涉及**写固件文件系统**，在未完全确认前**不要**在真实 Key 上试跑自研序列，
> 以免破坏设备。建议先在官方工具上抓取完整 APDU 流（`d:\LinguoAPDU.log` 是 CSP 的日志开关，
> 或直接 hook `DeviceIoControl`）再落地。

---

## 八、分析工具（本次新增，可复用）

| 脚本 | 用途 |
|---|---|
| `tools/lg_pe_dump.py` | 解析 objdump `-p` 输出的导出表/导入表 |
| `tools/lg_str.py` | 提取 ASCII + **GBK 中文** + UTF-16 + UTF-8 字符串（可直接 `--out` 落盘，避免 PowerShell 编码破坏） |
| `tools/lg_find_ref.py` | 在 PE 中定位字符串（GBK/UTF-16/ASCII）并反查引用地址 |
| `tools/lg_xref.py` | 搜索 .text 中对 VA/IAT 的 `push` / `call ds:[imm32]` 引用 |

产物（`tools/lg_*.txt`）：导出/导入表、全量字符串、各关键函数反汇编。

### 方法论要点（复用到其它厂商）

1. **先看导出表**：只有 `CP*` 就是 CSP，只有 `DllRegisterServer` 就是 COM 控件 —— 都意味着「没有管理 API」。
2. **再找 GetProcAddress 字符串**：能直接暴露工具实际调用的函数名（本例反证了「没有可调用的管理导出」，因而必须走协议层）。
3. **设备枚举 GUID 是突破口**：`SetupDiGetClassDevsA` 的第一个参数就是硬编码 GUID，转成字符串即知设备形态
   （本例 `GUID_DEVINTERFACE_CDROM` → 立刻判定「SCSI 直通」）。
4. **IOCTL 立即数**：`0x4D004`/`0x4D014` 反查 CTL_CODE 即得 `IOCTL_SCSI_PASS_THROUGH(_DIRECT)`。
5. **结构体常量三件套**：`Length / CdbLength / SenseInfoLength` 的立即数足以还原整块结构布局。
6. **SW 校验是协议确认的标志**：代码里出现 `cmp …,0x90` + `cmp …,0x00` 即说明对端是 ISO7816 APDU。

---

**版本**：v1.0（2026-09-20）
**作者**：AI 逆向协作（objdump + 自研 Python 分析链）
