# LNCA（华大 USBKey）逆向归档

本目录收纳 **LNCA 平台的全部逆向成果、临时脚本与探针工程**。
厂商原始文件在上一级 `../official driver/`（DLL/驱动/安装包，勿与本目录混放）。

> 归档日期：2026-09-21
> 关联文档：`Roadmap/05-LNCA逆向分析案例.md` §十二、`Roadmap/docs/LNCA-*.md`

---

## 一、目录结构

| 目录 | 内容 |
|------|------|
| `tools/` | 通用工具：`disasm_lnca.py`（PE 反汇编）、`lnca_keytest.ps1`（候选密钥验证） |
| `scripts/` | 本次逆向过程产生的 108 个一次性反汇编/转储脚本（`disasm_*.py`、`dump_*.py`、`find_*.py` 等） |
| `probe/` | 6 个 .NET 探针工程，**`LncaProbe` 为当前主探针**，其余为早期探索版 |

---

## 二、结论摘要（真机实测，设备 SN `01102001519176`，ATR 前 8 字节 = ASCII `SZD23B10`）

### 2.1 认证通道矩阵 ← **核心结论：所有凭据通道均已失效**

| 通道 | APDU | 本卡实测结果 |
|------|------|--------------|
| 外部认证 **P1=0**（传输密钥） | `CLA 82 00 00 08 <resp>` | ✅ **未锁定**：连续 10+ 次恒为 `0x63CF`（15 次，**不递减**）；但密钥 ≠ SDK 内置值 |
| 外部认证 **P1=1**（用户 PIN） | `CLA 82 01 00 08` | ❌ `0x6983` **已锁定** |
| 外部认证 **P1=2**（管理员/SO） | `CLA 82 02 00 08` | ❌ `0x6983` **已锁定** |
| ISO VERIFY `P2=0x00` | `00 20 00 00 Lc <PIN>` | `0x6982`（受外部认证门控）；其余 P2 → `0x6A88` 不存在 |
| INS 0x24 解锁（PUK 计数） | `84 24 00 P2 Lc <data>` | ❌ `0x6984` **参考数据已失效**（数据长度仅接受 **12 / 18** 字节） |
| 完全格式化 `Clear_DF` | `BF CE 00 00 00` | `0x6982` **需已认证** → 不可达 |
| 存储层擦除 `HSErase` | （DD/AD 系列） | ✅ rc=0，但**不动 COS 层证书/容器** |

### 2.2 内置密钥表（DLL 数据段，三处同构）

| 条目 | 描述符 | 16 字节密钥 | 出现位置 |
|------|--------|-------------|----------|
| 1 | `00 01 01 00 00 00 0F 11`（id=0x11） | `A62F1A1D6F5F85E2F31DFA933F273947` | `HD_SortDev@0xE038`、`HDCOS_LNCA@0x190EC`、`GP_COS_LNCA@0x82024` |
| 2 | `00 02 02 00 00 00 05 22`（id=0x22） | `637974627968797873796B7968620831`（`"cytbyhyxsykyhb"`+`08 31`） | `HD_SortDev@0xE050`、`HDCOS_LNCA@0x19050`、`GP_COS_LNCA@0x82020` |

- **两把均被本卡拒绝**（已用 DLL 内部函数自算响应复现，结果与 `HD_ClearDir` 内部完全一致 → 实现忠实，非计算错误）。
- 已确认 **不存在第三把密钥**：SDK 版与最新 CSP（LNCACSPSetup1070，含 `GP_COS_LNCA_RSA.dll` / `GP_COS_LNCA_SM2.dll` / `SKF_APP_LNCA.dll`）的密钥表**完全一致**。

### 2.3 关键导出与内部函数（`HDCOS_LNCA.dll`，除非注明）

| 函数 | RVA | 语义 |
|------|-----|------|
| `HD_ClearDir` | 0x67D0 | **完全格式化**：`Get_Challenge` → 内置密钥挑战应答 → `External_Authentication(P1=0)` → `Clear_DF` |
| `Clear_DF` | 0x19C0 | 私有 APDU `BF CE 00 00 00`（全 DLL 唯一调用者就是 `HD_ClearDir`） |
| `Reload_Pin` | 0x1D70 | APDU `80 5E 00 00 Lc <data>`（ISO7816 INS 0x5E RESET RETRY COUNTER） |
| `Change_Pin` / `HD_ChangePin` | 0x1930 / 0x2490 | `80 5E 01 P2 Lc`；`HD_ChangePin` = `Verify_Pin`(旧) → `Write_Key`(新) |
| `Verify_Pin` | 0x18A0 | APDU `00 20 00 P2 Lc <PIN>`（标准 VERIFY，**SW 带剩余次数**） |
| `External_Authentication` | 0x1FB0 | `CLA 82 P1 00 08 <resp>`；失败 SW=`0x63Cx`（末位=剩余次数） |
| `Get_Challenge` | 0x1B40 | `CLA 84`，返回 8 字节挑战（**成功时 rc=字节数 8**，非 0） |
| `HD_Application_Manager` | 0x17C0 | 通用 APDU 通道；但 `00 2C`/`80 5E` 被 DLL 层拦截（`rc=-300`） |
| `sub_8D10` | 0x8D10 | 变换：**低位置 1 的字节翻转 bit7**（密钥/口令归一化） |
| `sub_8DC0` | 0x8DC0 | 挑战应答计算：`(data, len, out, key16, mode)`，`len` 必须为 8 的倍数 |
| `HDJIT_VerifyAdminPin` | 0xBAB0 | 用**调用方提供的口令**做 `External_Authentication(P1=2)`（本卡已锁） |
| `HDJIT_ReloadPin` | 0xB8B0 | 管理员认证(P1=2) → 写入 28 字节密钥记录（`CLA 84 INS D4 P1=1 P2=0xF1`） |
| `InitialCard` | 0x73F0 | **空 stub**（`or eax,-1; ret 0x10`）← 勿用 |
| `GP_COS_LNCA!InitialCard` | 0x6910 | **真实现**（4 参数：SO PIN 6~8 位 + 用户 PIN 6~16 位 + 标志），但依赖缺失的 `GP_IFD.dll` |
| `HD_hdcos480!Pin_Unblock` | 0x27B0 | `84 24 00 P2 Lc`（LNCA 定制版被砍掉的解锁命令，长度校验 12/18） |
| `HD_hdcos480!Get_Info` | 0x2050 | `BF C8 00 00 0F` → rc=15，返回 `86014D5634FAFD00003938FAFD9E4B00`（只读） |

### 2.4 终判

**本卡的传输密钥在个人化阶段被替换为非默认值**（卡上带 `CN=营口辽河装备有限公司, OU=@05566801-6` 证书，属 CA 签发场景），
且用户 PIN、PUK、管理员三条凭据通道**均已锁定/失效** ⇒ **软件侧无法自救**。

唯一出路：**由 LNCA 或签发 CA 提供该卡的传输密钥**（拿到后本仓库软件可一条命令完成「完全格式化 + 重设 PIN + 验证」）。
这也解释了为什么厂商工具 `GP_ADM_LNCA.exe` 不提供 SO PIN / 初始化功能——它不是用来救已失效卡的。

### 2.5 实测注意事项

- 卡片在**多次认证失败后会自行掉线**（`ListKey→count=0`，PnP 中消失），需**重新插拔**才能恢复。
- `HD_VerifyPin` 返回值语义：`0` = 通过；`-1` = 已锁定（走 `0x6983` 分支）；`-1000` = 其他失败。
- `Reload_Pin` 的返回值**不检查 SW**，rc=0 **不代表成功**，必须用 `HD_VerifyPin` 终判。
- `HSVerifyUserPin`（存储层）返回 `0x67`=句柄无效、`0x69`=PIN 长度非法、`0x70`=通用验证失败（**不返回剩余次数**）。

---

## 三、工具用法

### 3.1 `tools/disasm_lnca.py` — PE 反汇编 / 数据提取

```powershell
py -3 tools/disasm_lnca.py <dll> <导出名|0xRVA> [长度] [--full]   # 反汇编
py -3 tools/disasm_lnca.py <dll> --dump                            # 导出表（由 LncaProbe 提供）
py -3 tools/disasm_lnca.py <dll> --xrefs [过滤]                    # 内部 call 交叉引用
py -3 tools/disasm_lnca.py <dll> --imports | --strings [过滤]      # 导入表 / ASCII 串
py -3 tools/disasm_lnca.py <dll> --wstrings [过滤]                 # UTF-16 串
py -3 tools/disasm_lnca.py <dll> --data 0xRVA 长度                 # 数据段转储
py -3 tools/disasm_lnca.py <dll> --findpat <hex>                   # 字节模式搜索（带上下文）
py -3 tools/disasm_lnca.py <dll> --countpat <hex>                  # 只输出命中数量（ASCII 安全）
py -3 tools/disasm_lnca.py <dll> --addrrefs 0xRVA                  # 查找引用该地址的代码位置
```

### 3.2 `probe/LncaProbe` — 实机探针（当前主工具）

```powershell
$P = "probe\LncaProbe\bin\Release\net8.0\LncaProbe.exe"
& $P --state    [port]                 # 只读状态快照（序列号/容器列表）
& $P --jitstate                        # 只读 JIT 层快照（设备数/SN/证书），不消耗任何计数
& $P --refs     [port]                 # 零成本探测 ISO VERIFY 参考数据
& $P --verify   <P2hex> <PIN> [port]   # ISO VERIFY 通道测 PIN（SW 带剩余次数）
& $P --authcnt  [port] [P1] [次数]     # 外部认证通道计数行为
& $P --apdu     <hex> [port]           # 发送任意 APDU 并打印 SW
& $P --deep     [port] [--noerase]     # 逐层定位格式化失败点
& $P --key      <候选…> [--port N]     # ★ P1=0 通道候选密钥验证（自动试原样/变换两种形态）
& $P --unblock  <数据hex> [P2] [port]  # 华大 INS 0x24 解锁通道（PUK 计数）
& $P --mf       [port]                 # GP_COS_LNCA!ExternalAuthMF（含 GP_IFD.dll 改名副本方案）
& $P --format   [port] [新PIN] [SO口令] [PUK] [--dry]   # ★ 完全格式化 + 重设 PIN
```

> DLL 目录由 `ResolveLncDir()` 自动解析（`LNCA_DLL_DIR` 环境变量可覆盖），
> 查找顺序：`official driver` → SDK 根 → 仓库 `Library\...` → `C:\Windows\SysWOW64`。

### 3.3 `tools/lnca_keytest.ps1` — 候选密钥批量验证

```powershell
pwsh -File tools/lnca_keytest.ps1                              # 内置有界候选清单（约 30 个）
pwsh -File tools/lnca_keytest.ps1 -CandidatesFile .\keys.txt   # 自定义清单（# 注释，hex: 前缀=原始字节）
pwsh -File tools/lnca_keytest.ps1 -Key "87654321" "hex:0011223344556677"
```
命中会提示 `*** 命中！***` 并给出后续的 `--format` 命令。

---

## 四、相关文档与路径

| 内容 | 路径 |
|------|------|
| 完整逆向分析（十二章） | `Roadmap/05-LNCA逆向分析案例.md` §十二 |
| 实现指南 | `Roadmap/docs/LNCA-ResetDevice-实现指南.md` |
| 任务清单 | `Roadmap/docs/LNCA-任务清单.md` |
| 逆向分析总结报告 | `Manager/docs/LNCA-逆向分析总结报告.md` |
| 动态调试指南 | `Manager/docs/LNCA-动态调试指南.md` |
| 删除证书调试-快速开始 | `Manager/docs/LNCA-删除证书调试-快速开始.md` |
| 厂商原始文件 | `Library/LNCA USBKey Manage/official driver/` |
| 已安装中间件（CSP 1.0.7.0） | `C:\Windows\SysWOW64\`（`HDCOS_LNCA.dll` 等，与 SDK 版哈希一致/近似） |
| 临时解包目录（可清理） | `tools\_pkg_extract\`、`tools\_pkg_usbkey\`、`%TEMP%\lnca_gpifd_shim\` |

**打包规则已同步**：`Manager/src/USBKey.Manager/USBKey.Manager.csproj` 的复制源已改为
`Library\LNCA USBKey Manage\official driver\*.dll|*.exe`（输出到 `Library\LNCA\`）。

---

## 五、后续若拿到传输密钥

```powershell
# 1) 先验证密钥（P1=0 通道不锁定，可安全试）
& $P --key "<传输密钥>" 
#    或 hex: 形式： --key hex:637974627968797873796B7968620831

# 2) 命中后执行完全格式化 + 重设 PIN（破坏性）
& $P --format 0 <新PIN> <传输密钥>
#    GUI 路径：USBKey.Manager →「重置设备」→ 输入管理员口令（SO PIN）
```

软件侧链路（`LncaProvider.ResetDevice`）已就绪并带**逐层诊断报告**，
失败时会把每步的真实 rc 与 SW 写入 `LastResetReport`，绝不假装成功。
