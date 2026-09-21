# BJCA（北京数字认证）USBKey 逆向分析资料

> 本目录存放 **BJCA 客户端组件（XTXAppCOM）与其支持下各厂商 USBKey** 的逆向分析结论、
> 现场实证数据与配套临时脚本/样本。
>
> 设备基准：林果 **LG3073**（`VID:PID = 6588:1514`，SN `5303201812001784`），
> `driver.ini` 中登记为 `type = SKF`。
>
> 最后更新：2026-09-21

---

## 一、结论速查

| 问题 | 结论 | 依据 |
|------|------|------|
| BJCA 与 SKF 是什么关系 | **不是并列关系**：BJCA 是上层门户，SKF 是它支持的三类设备接口之一 | `Driver\driver.ini` 的 `type` 字段 |
| BJCA 组件怎么访问设备 | 按 VID/PID 查 `driver.ini` 分派；LG3073 走 `type=SKF` → `lgu3073_p1514_gm.dll` | 同左 |
| BJCA 删容器为什么失败 | **它内部就是调 `SKF_DeleteContainer`**，失败被包装成 `0x0B000028` | 组件 trace 日志 |
| BJCA 列表里的条目为何删不掉 | 该条目只存在于**组件进程内的缓存**，卡上并无对应容器 | trace + 卡内枚举 |
| `0x0A00002E` 是什么 | **目标容器不存在**（已认证状态下），并非字面的"应用不存在" | 零写入对照实验 |
| 删除容器是否必须先认证 | **是**，中间件在最前面就查认证状态，无法绕过 | 零写入对照实验 |
| 能否导入外部私钥（PFX） | **不能**（设备侧缺"设备加密公钥"通道） | 见 `02-私钥导入可行性.md` |

---

## 二、文档索引

| 文档 | 内容 |
|------|------|
| [`01-架构关系（SKF与BJCA）.md`](./01-架构关系（SKF与BJCA）.md) | 两者层级关系、`driver.ini` 证据链、能力分工表 |
| [`02-私钥导入可行性.md`](./02-私钥导入可行性.md) | **核心**：方案 A/B/C 全部路径的实测与结论（含 BJCA `ImportPlainKeyCert` 与 SKF `SKF_ImportRSAKeyPair`） |
| [`03-容器管理（权限·缓存·同步）.md`](./03-容器管理（权限·缓存·同步）.md) | 删除权限实测、BJCA 用户列表缓存机制、双向同步删除实现 |

> 更宏观的对接说明仍在仓库 `Roadmap/` 下：
> `07-BJCA逆向分析与对接.md`（BJCA 组件）、`08-SKF(GM-T0016)通用对接.md`（SKF 国标）。

---

## 三、子目录

| 目录 | 内容 |
|------|------|
| `artifacts/` | 静态分析产物：PE 导出/导入表、字符串提取、反汇编片段、GUID 清单等 |
| `scripts/` | 分析脚本（Python/PowerShell）：PE 解析、字符串提取（含 GBK/UTF-16）、交叉引用搜索 |
| `samples/pfx/` | 实测用 PFX 样本，覆盖多种编码与算法（见下） |
| `probes/` | 探针工具的用法说明（**源码在 `Manager/tools/`**，因依赖 `USBKey.Core` 故不搬迁） |

### samples/pfx 说明

为验证"PFX 编码格式是否影响导入"而生成，**两种编码对照**：

| 文件 | 编码 | 用途 |
|------|------|------|
| `legacy.pfx` | **PBES1（3DES + SHA1）** | 老式编码，组件可解析 |
| `modern.pfx` | PBES2（AES-256 + PBKDF2） | 现代编码，组件 `PKCS12_parse` 直接拒绝 |
| `rsa1024.pfx` | PBES1 + RSA-1024 | 密钥长度对照 |
| `ec256.pfx` | PBES1 + EC P-256 | 非 RSA 对照（组件只认 PKCS#1 RSA） |
| `sm2.pfx` | PBES1 + SM2 | 国密对照 |

口令均为 `1234`。生成命令见 `scripts/` 内说明或 `02-私钥导入可行性.md`。

---

## 四、探针工具用法

源码位于 `Manager/tools/`（需与 `USBKey.Core` 一起编译）：

```bash
# 只读：列出容器/证书（含按 CertID 约定兜底取证书）
CertListProbe skf
CertListProbe bjca

# 只读：零写入对照实验，判定 SKF_DeleteContainer 是否要求先认证
CertListProbe skf --probe-delete-perm

# 只读：评估「导入密钥对」的先决条件（设备算法能力、容器公钥可导出性）
CertListProbe skf --probe-import

# 写操作：空负载调用 SKF_ImportRSAKeyPair（建/删临时容器）
CertListProbe skf --probe-import-call

# 写操作：按国标构造真实参数导入 RSA 密钥对（建/删临时容器）
CertListProbe skf --probe-import-real

# BJCA 侧：导入 PFX 专项实测（老式/现代编码对照）
BjcaProbe pfximport <pfx路径> [口令] [--cleanup]
```

> ⚠️ 标"写操作"的探针会创建临时容器，虽已内建清理，但**建议在可接受风险的卡上运行**。
> 所有 PIN 认证失败都会**真实消耗重试次数**，不要试探口令。
