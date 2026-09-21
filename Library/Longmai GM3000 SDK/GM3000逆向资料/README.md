# GM3000 逆向资料（分析文档 + 工具 + 产物）

> 位置：`Library\Longmai GM3000 SDK\GM3000逆向资料\`
> 对象：Longmai mToken GM3000（本机实测：序列号 `ED466583B8C689AB…`、硬件 5.00 / 固件 2.15、容量 131072 字节、PIN 10/10）
> 主文档：`docs\Longmai-GM3000-逆向分析报告.md`（版本 v1.3，结论都在里面，本文件只做索引与速查）

---

## 目录结构

| 路径 | 内容 |
|---|---|
| `docs\` | **主分析报告** `Longmai-GM3000-逆向分析报告.md`：设备能力、Admin 各功能的调用链、槽位表、错误码映射、修复清单、验证命令 |
| `shim\` | **PKCS#11 垫片**：`shim.c` + `shim.def` + `build.ps1`（MSVC x86），产物 `shim\build\gm3000_pkcs11.dll` |
| `probe\` | **独立探针** `GM3000Probe`（C# / .NET 8 / x86）：把 Admin 与 TokenMgr 的调用序列在 ABI 层复刻，脱离 GUI 取证 |
| `scripts\` | 纯 Python 3 分析脚本（无第三方依赖）：PE 解析、反汇编落盘、扩展表解析、TokenMgr 调用点定位 |
| `disasm\` | 脚本产物（反汇编 / 导出表 / 字符串 / 结构转储），可随时重建，不要手改 |

---

## 一分钟上手

### 1) 重新构建并安装垫片

```powershell
cd "g:\Codes\USBKeyDriver\Library\Longmai GM3000 SDK\GM3000逆向资料"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\shim\build.ps1"
Copy-Item ".\shim\build\gm3000_pkcs11.dll" "..\GM3000_2.2.19\gm3000_pkcs11.dll" -Force
```

> 原厂 DLL 备份在 `..\GM3000_2.2.19\gm3000_pkcs11.dll.vendor`。
> 安装前先关掉 `GM3000Admin.exe`（DLL 被占用会复制失败）。

### 2) 冒烟测试（全部打到真实设备；先把 Admin 关掉，避免设备被两个进程同时占用）

```powershell
$p = ".\probe\bin\Release\net8.0-windows\win-x86\GM3000Probe.exe"

& $p shimabi                                        # ABI 复刻：登录 / 容器 / 文件 / 标签 / 缓冲不足语义
& $p ckobj                                          # 复刻「三步导入」：公钥→私钥→证书对象的记账与回查
& $p sectors                                        # 扇区读写（幂等：读 0 号扇区 → 原样写回 → 回读比对）
& $p skfcerts "..\GM3000_2.2.19\mtoken_gm3000.dll"  # 裸 SKF 清点每个容器里的签名/密钥交互证书
& $p shimabi "..\GM3000_2.2.19\gm3000_pkcs11.dll" <用户PIN>   # 提供用户口令可完整验证建容器
```

### 3) 反汇编 / 解析（脚本按 RVA 落盘，规避 PowerShell 编码问题）

```powershell
$py = "C:\Users\pikachuren\AppData\Local\Programs\Python\Python312\python.exe"
$d  = "..\GM3000_2.2.19\gm3000_pkcs11.dll.vendor"

& $py .\scripts\gm_disraw.py $d V2219_M_WriteSectors 0x13B0:0x50   # → .\disasm\V2219_M_WriteSectors.0013B0.dis.txt
& $py .\scripts\gm_exttable.py $d 0x0 --auto 25                    # 厂商扩展表 25 项槽位顺序
& $py .\scripts\gm_pe.py      $d exports                           # 导出表
```

---

## 关键速查

### 设备能力（实测）

```
硬件 5.00   固件 2.15   最小口令长度 4   空间 131072 字节（128 KB）
单一存储池：容器证书即「对象」，无独立公钥存储
SKF（GM/T 0016）接口：mtoken_gm3000.dll（254 个导出，含 SKF_Transmit 透传口）
```

### 厂商扩展表（`M_GetExtFunctionList`，2.2.19 静态表 rva 0x7BB30，25 项）

| 槽位 | 函数 | 垫片实现 |
|---|---|---|
| 0 | `M_GetUserInfo` | ✅ |
| 1 | `M_GetExtFunctionList` | ✅（返回本表） |
| 3 | `M_SetTokenLabel(handle,label)` | ✅ `SKF_SetLabel` |
| 4 | `M_FormatToken` | ✅ |
| 5 | `M_CreateContainer(handle,name)` | ✅ `SKF_CreateContainer` |
| 6 | `M_DeleteContainer(handle,name)` | ✅ `SKF_DeleteContainer` |
| 7 | `M_EnumContainer(handle,list,pulSize)` | ✅ `SKF_EnumContainer`（缓冲不足回 `0x21`，与厂商一致） |
| 9 / 10 | `M_WriteSectors` / `M_ReadSectors`（各 4 参） | ✅ 用 `SKF_Transmit` 透传设备帧（cmd 写 `0x2A` / 读 `0x28`，**每扇区 2048 字节**） |
| 11 | `M_ReloadObjects` | ✅ **只清本地缓存，绝不解绑上下文**（见下） |
| 12–16 | `M_CreateFile/DeleteFile/WriteFile/ReadFile/GetFileInfo` | ✅ `SKF_*File` 系列 |
| 17 | `M_GetApplicationInfo` | ✅ |
| 19 | `M_ConstructMSCMapFiles(handle,?)` | ⛔ 未实现（2 参；入口 0x16B0 → 0x0C720，若 ISO 后续需要再补） |
| 20 | `M_ForceLogout(handle)` | ✅ `SKF_ClearSecureState` + 清登录态 |
| 8 / 18 | `M_GetContainerInfo` / `M_SetEnumString` | ⛔ 未实现（Admin 目前未调用） |

### 错误码（PKCS#11 ↔ 设备）

| 设备码 | 含义 | 映射到 PKCS#11 |
|---|---|---|
| `0x0A00002D` | 尚未处于已验证状态 | `CKR_USER_NOT_LOGGED_IN (0x101)` |
| `0x0A000031` | 文件不存在 | `CKR_*`（垫片按上下文映射） |
| `0x0A000010` | 参数长度非法（名字带残留会触发） | 未映射 → 兜底 `CKR_DEVICE_ERROR (0x30)` |
| `0x0A000020` | 缓冲不足 | 槽位 7 按厂商约定回 `0x21` |
| `0x54` | `CKR_FUNCTION_NOT_SUPPORTED` | 槽位未实现（历史：改名/容器/文件/扇区都报过它） |

### Admin 各功能的调用链（要点）

| 功能 | 链路 | 关键点 |
|---|---|---|
| 初始化 | `C_Login(SO)` → `M_FormatToken(4)` → `C_InitPIN` | 容量字段取自 `CK_TOKEN_INFO` 的**私有内存**（偏移 132/136），留 `0xFFFFFFFF` 会被判「空间不足」 |
| 改名 | `M_SetTokenLabel(3)` → 回读 `C_GetTokenInfo` | 名称就是 `DEVINFO+0x82`，回读必须**重读设备**（`RefreshDeviceSnapshot`） |
| 改 SO PIN | `token_change_sopin` | 要求 `C_GetSessionInfo.state == CKS_RW_SO_FUNCTIONS(4)` |
| 导入证书 | `M_CreateContainer(5)` → `C_CreateObject(class=2)` → `C_CreateObject(class=3)` → `C_CreateObject(class=1)` | 前两步是**记账对象**（设备无对应入口），后一步才用 `SKF_ImportCertificate(bSign)` 落卡；Admin 会**回查**对象，查不到就中止（`ErrorCode=0x4`） |
| 下载 ISO | `C_Login(user)` → `M_WriteSectors(9)` | 16 字节头 `{cmd, start(4B 大端), count(2B 大端), 0×9}` + `count×2048` 负载 |
| 系统检测（CSP） | 读 `APPInfo.ini` 的 `CSPName` → 查 `HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\<名字>` | 本机实际注册的是 `Longmai GM3000 for HZ CSP V1.1`，ini 已对齐 |

### 已知边界 / 注意

1. **`M_ReloadObjects`（槽位 11）绝不能重连设备**：SKF 的「口令已验证」状态挂在**应用句柄**上，
   一旦 `UnbindContext`（关闭应用+断开设备），后续建容器只会回 `SAR_USER_NOT_LOGGED_IN(0x0A00002D)`。
2. **建容器要求「用户」角色**：裸 SKF 实测，只在管理员口令下调用一律回 `0x0A00002D`（与垫片无关）。
3. **私钥导入是「尽力而为」**：`SKF_ImportRSAKeyPair` 的包裹格式未确认，失败**不阻断**（证书仍会写入）。
4. **原厂 `gm3000_pkcs11.dll` 认不到本设备**（`C_GetSlotList(present=1)` 返回 0），不能作为后备方案；
   它只依赖 `KERNEL32/ADVAPI32/USER32/SETUPAPI/HID`，走的是自己那套 HID 私有协议。
5. 垫片日志：`..\GM3000_2.2.19\gm3000_shim.log`（每次加载重写；含槽位、参数、原始返回码、对象属性转储）。

---

## 资料版本

| 日期 | 变更 |
|---|---|
| 2026-09-21 | 建目录：报告 v1.3 + 垫片（155136 B）+ 探针 + 14 个脚本 + 203 个反汇编产物 |
