# 探针工具

> **源码不在本目录**，而在仓库 `Manager/tools/` 下。原因是它们引用 `USBKey.Core`
> （需要复用 `BjcaProvider` / `SkfProvider` / `SkfSession`），搬离项目会无法编译。
>
> 本目录仅记录**用法与输出含义**，便于脱离源码阅读分析结论。

---

## 1. CertListProbe（SKF / BJCA 通用）

`Manager/tools/CertListProbe/`

| 命令 | 性质 | 作用 |
|------|------|------|
| `CertListProbe skf` | 只读 | 列出 SKF 侧容器/证书（含"证书 / 仅密钥 / 空容器"内容分类） |
| `CertListProbe bjca` | 只读 | 列出 BJCA 侧容器/证书，并打印 `SOF_GetUserList` / `SOF_GetAllContainerName` 原始值 |
| `--verify-admin [--admin-pin <pin>]` | 只读 | 校验管理口令认证是否可通过 |
| `--probe-delete-perm` | **零写入** | 对照实验：未认证 vs 已认证状态下删「不存在的容器名」，判定删除是否要求先认证 |
| `--as-user` | 只读 | 以用户 PIN 认证后做同样判定（需有效用户 PIN） |
| `--probe-import` | 只读 | 评估「导入密钥对」先决条件：设备算法能力位图、各容器公钥可导出性 |
| `--probe-import-call` | **写操作** | 空负载调用 `SKF_ImportRSAKeyPair`，观察参数校验反应；含"先生成密钥对再重试"的分水岭实验 |
| `--probe-import-real` | **写操作** | 按国标构造真实参数导入 RSA 密钥对，遍历「字节序 × padding × 对称算法」组合 |

**"零写入"的含义**：实验中只使用**卡上不存在**的容器名，因此不会创建、删除或修改卡上任何数据。
**"写操作"** 会建临时容器（默认 `ZZIMPORTTEST` / `ZZIMPKEY`），结束时由 `SKF_DeleteContainer` 清理。

### 典型输出解读

```
== 5303201812001784 的容器 / 证书 ==
   共 1 项
   类型       容器名                      算法                     证书CN                 有效期                      已注册
   证书       UserKey                  RSA                    Test User            2026-09-21 ~ 2027-09-21  是
```

`类型` 列对应 `KeyContainerContent`：`证书` / `仅密钥` / `空容器` / `未知`。
「空容器」与「仅密钥」的区分依赖能否导出公钥，SKF 侧可精确判定，BJCA 侧受限于组件能力只能标为未知。

---

## 2. BjcaProbe（BJCA 组件专用）

`Manager/tools/BjcaProbe/`

| 命令 | 性质 | 作用 |
|------|------|------|
| `BjcaProbe typelib [过滤]` | 只读 | 导出 DLL 内嵌 TypeLib 的权威签名 |
| `BjcaProbe probe [dll路径]` | 只读 | 免注册激活 `XTXApp` 并做连通性测试（含按名字导出 vs vtable 槽位一致性校验） |
| `BjcaProbe readonly [dll路径]` | 只读 | 探测设备信息 / 容器 / 证书 / 重试次数 |
| `BjcaProbe provider` | 只读 | 联调生产实现 `BjcaProvider` |
| `BjcaProbe reset ...` | **写操作** | 重置设备（清空内容 + 重设口令，不可撤销） |
| `BjcaProbe certtest [用户PIN] [--cleanup]` | **写操作** | 证书链路实测（建容器→公钥/P10→导入证书/PFX→登录→清理） |
| `BjcaProbe pfximport <pfx路径> [口令] [--cleanup]` | **写操作** | PFX 导入专项实测，用于对比不同 PFX 编码的接受情况 |

---

## 3. 静态分析脚本

见 [`../scripts/`](../scripts/)：

| 脚本 | 作用 |
|------|------|
| `bjca_analyze.py` | 通用 PE 分析：`exports`（导出表）、`imports`、`argcounts`（用 `ret imm16` 推算**真实参数个数**，用于核对国标签名） |
| `bjca_typelib.ps1` | 导出 DLL 内嵌 TypeLib 的接口定义 |
| `lg_pe_dump.py` | PE 导出/导入表解析 |
| `lg_str.py` | 字符串提取（ASCII + **GBK 中文** + UTF-16LE） |
| `lg_find_ref.py` / `lg_xref.py` | 字符串定位与交叉引用搜索 |

---

## 4. 关键日志位置

| 日志 | 路径 | 用途 |
|------|------|------|
| BJCA 组件 trace | `C:\BJCAROOT\BJCAlog\xtx\XTXAppCOM.log` | **最有价值**：可见组件内部真实调用链（`cryptobucket.cpp` / `cryptousbicwrap.cpp` 等） |
| BJCA 核心服务 | `C:\BJCAROOT\BJCAlog\XTXCoreSvr\pawd.log` | 后台服务 |
| Manager 应用日志 | `<输出目录>\logs\app_YYYYMMDD.log` | `[BJCA] ... 原始列表：...` 那行是排查列表异常的关键 |

> 组件 trace 是**解决问题的主要抓手** —— `Roadmap/07` 里"不支持导入 PFX"的错误结论，
> 正是因为没有查看该日志（它明确写了 `PKCS12_parse error`，即失败在解析阶段）。
