# USB Key 管理端系统

企业级 USB Key（智能卡）管理系统，支持证书导入、查看、导出、注册、密码管理、设备解锁与重置。

## 项目结构

```
c:/USBKey/
├── USBKey.sln                        # Visual Studio 解决方案
├── src/
│   ├── USBKey.Core/                  # 核心库（配置、授权、DLL接口、证书）
│   ├── USBKey.Manager/               # 管理端主程序（WinForms，720x480）
│   └── USBKey.LicenseTool/           # 授权生成终端（仅授权管理员使用）
├── config/
│   ├── config.json                   # 运行配置（平台、功能、设置）
│   └── license.key                   # 授权文件（管理模式需要）
├── Library/
│   └── LNCA/                         # 厂商驱动 DLL（JIT_USBKEY_HD.dll 等）
└── tools/                            # 开发工具（PE分析、密钥生成等）
```

## 快速开始

### 1. 用户模式运行（无需授权）

```powershell
cd c:\USBKey
.\src\USBKey.Manager\bin\Release\net8.0-windows\USBKey.Manager.exe
```

- 默认 `config.json` 的 `usermode: false` 需改为 `true` 以启用用户模式
- 用户模式：查看证书、登录/登出、注册证书到系统
- 功能受 `config.json` 的 `features` 控制

### 2. 管理模式运行（需要授权）

**首次启动** → 弹出授权激活窗口：
1. 复制显示的**机器码**（格式：`XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`）
2. 将机器码提供给授权管理员
3. 使用 `USBKey.LicenseTool.exe` 生成 `license.key`
4. 将生成的授权 JSON 粘贴到激活窗口，点击"保存并验证授权"
5. 验证通过后程序继续运行

**管理模式功能**：
- 导入 PFX 证书到 USB Key
- 修改密码、解锁设备（PUK/挑战码）
- 重置设备（初始化，清除所有证书）
- 设置用户权限（生成用户客户端配置）

### 3. 授权生成（授权管理员）

```powershell
.\src\USBKey.LicenseTool\bin\Release\net8.0-windows\USBKey.LicenseTool.exe
```

1. 输入目标机器码
2. 勾选授权平台（lnca / mock 等）
3. 设置有效期
4. 点击"生成授权" → 复制或保存为 `license.key`

**安全提示**：授权终端持有 RSA 私钥，仅供授权管理员使用，不得外传。

## 配置文件说明（config.json）

### 核心字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `usermode` | bool | `false`=管理模式（需授权），`true`=用户模式（无需授权） |
| `platform` | string[] | 启用的平台列表，如 `["lnca", "mock"]` |
| `keyslist` | object | 各平台的 USB 设备 VID/PID 白名单 |
| `features` | object | 功能按钮的可见性/可用性（`enabled`/`hidden`/`disabled`） |
| `settings` | object | 用户偏好（删除证书/改密码权限、登录超时、自动注册等） |

### 功能控制（features）

```json
{
  "features": {
    "importcert": "enabled",      // 本地导入 PFX
    "viewcert": "enabled",        // 查看证书
    "exportcert": "enabled",      // 导出证书（不含私钥）
    "delcert": "disabled",        // 删除证书（禁用但可见）
    "regcert": "enabled",         // 注册/注销到系统 CSP
    "changepin": "disabled",      // 修改密码
    "unlock": "enabled",          // 解锁设备
    "reset": "enabled",           // 重置设备
    "cloudimport": "hidden"       // 云端导入（完全隐藏）
  }
}
```

- `enabled`：可用
- `hidden`：完全不可见
- `disabled`：可见但禁用（按钮置灰）

## 厂商 DLL 接口对接

### 当前状态

- **LNCA 平台**：DLL 加载框架已实现，但具体接口签名需实物设备 + IDA Pro 逆向确认
  - 已探测：`JIT_USBKEY_HD.dll`（44 导出，序号 101-144）
  - 已探测：`HD_HardAPI.dll`（17 导出，序号 1-17）
  - 导出方式：序号导出（无函数名），通过 `GetProcAddress("#N")` 调用
- **Mock 平台**：完整模拟实现，可用于演示与 UI 测试

### 接口对接步骤（待用户提供 IDA 环境）

1. 插入实体 LNCA USB Key
2. 用 IDA Pro 打开 `JIT_USBKEY_HD.dll`
3. 逆向分析序号导出的函数签名（参数类型、返回值、调用约定）
4. 在 `USBKey.Core/UsbKey/LncaProvider.cs` 中填充委托定义
5. 重新编译即可对接真实设备

**当前操作真实 LNCA 设备时**会抛出 `NotSupportedException`，提示接口待逆向对接。设备枚举（通过 WMI 的 VID/PID）正常工作。

## 主要功能

### 管理端（USBKey.Manager.exe）

#### 1. 设备管理
- 自动枚举已插入的 USB Key（支持多厂商，通过 `config.json` 的 `platform` 与 `keyslist` 配置）
- PIN 登录/登出（会话超时保护，默认 15 分钟）
- 查看设备详情（序列号、固件版本、容量、VID/PID）

#### 2. 证书管理
- **导入**：本地 PFX 证书导入到 USB Key
- **查看**：打开系统证书查看器查看详情
- **导出**：导出证书（仅公钥，不含私钥）为 `.cer` 文件
- **删除**：从 USB Key 删除证书/容器
- **注册/注销**：将证书注册到系统 CSP 证书库（供应用程序调用）

#### 3. 密码与解锁
- **修改密码**：使用旧 PIN 修改为新 PIN（需先登录）
- **解锁设备**：
  - PUK 解锁（输入 PUK + 新 PIN）
  - Admin Key 解锁（输入 Admin Key + 新 PIN）
  - 挑战码解锁（管理员生成挑战码，用户提供响应）

#### 4. 设备重置
- 初始化设备（清除所有证书）
- 设置新 PIN、PUK、Admin Key（可选随机生成）
- **警告**：重置操作不可逆，所有证书将被清除

#### 5. 系统设置
- **用户设置**：登录超时、开机自启、自动注册证书、软件信息
- **管理设置**（仅管理模式）：
  - 配置用户权限（生成用户客户端配置）
  - 查看授权状态（机器码、有效期）
  - 更新授权

#### 6. 托盘与热插拔
- 最小化到系统托盘
- USB 热插拔监听（设备插入/移除自动刷新）
- 托盘菜单：显示主界面、查看设备、退出

### 授权终端（USBKey.LicenseTool.exe）

- 输入目标机器码、选择平台、设置有效期
- 生成 RSA 签名的授权文件（license.key）
- 复制到剪贴板或保存为文件

## 技术栈

- **.NET 8**（C# 12，Windows Forms）
- **核心库**：
  - 配置：`System.Text.Json`
  - 授权：RSA-PKCS1-SHA256 签名（内嵌公钥，私钥由授权终端持有）
  - 机器码：WMI（CPUID + 硬盘序列号 + 主板 UUID）→ SHA256
  - 联网取时：HTTP Date 头（防本地时钟回拨绕过授权）
  - USB 监听：WMI Win32_DeviceChangeEvent + 轮询兜底
  - 证书：`System.Security.Cryptography.X509Certificates`
  - DLL 对接：`LoadLibrary` + `GetProcAddress`（序号导出）
- **UI**：720x480 WinForms，手写布局，托盘图标

## 安全设计

### 1. 授权体系
- **公钥内嵌**：软件内置 RSA 公钥，用于验证授权签名
- **私钥隔离**：私钥仅存在于授权终端，不打包进管理端
- **机器码绑定**：授权与硬件绑定（CPUID+硬盘+主板），无法跨机器使用
- **时间防篡改**：管理模式启动必须联网取时间（HTTP Date），防回拨本地时钟绕过到期校验
- **平台绑定**：授权指定支持的平台（lnca/mock 等），运行时校验交集

### 2. 不提供破解接口
- **无导出私钥**：所有证书导出仅含公钥部分，绝不导出私钥
- **无无凭据解锁**：所有密码修改/解锁操作必须先经身份认证（PIN/PUK/AdminKey/挑战码）
- **接口层严格校验**：`IKeyProvider` 接口定义明确排除破解型能力

### 3. 敏感操作保护
- 导入证书、重置设备、解锁设备：管理模式下再次校验授权有效性
- 会话超时：登录会话有默认 15 分钟超时保护
- 删除证书：需二次确认

## 开发与构建

### 环境要求
- .NET 8 SDK（已安装在 `%LOCALAPPDATA%\DotNetSdk\sdk-x64`）
- Windows 10/11（x64）
- Visual Studio 2022（可选，已可用 `dotnet` CLI）

### 构建

```powershell
cd c:\USBKey
dotnet build USBKey.sln -c Release
```

输出：
- 管理端：`src\USBKey.Manager\bin\Release\net8.0-windows\USBKey.Manager.exe`
- 授权终端：`src\USBKey.LicenseTool\bin\Release\net8.0-windows\USBKey.LicenseTool.exe`

### 运行测试

```powershell
# 用户模式（Mock 设备演示）
.\src\USBKey.Manager\bin\Release\net8.0-windows\USBKey.Manager.exe

# 管理模式（需先生成授权）
# 1. 启动管理端 → 记录机器码
# 2. 启动授权终端 → 生成 license.key
# 3. 激活后重新启动
```

## 部署

### 用户客户端部署
1. 复制 `USBKey.Manager.exe` 及其依赖 DLL 到目标目录
2. 复制 `config/config.json`，设置 `usermode: true`
3. 复制 `Library/` 目录（厂商驱动 DLL）
4. （可选）配置 `features` 限制用户权限

### 管理员部署
1. 与用户客户端相同，但 `config.json` 设置 `usermode: false`
2. 首次启动时激活授权（需联网取时间）
3. 将 `license.key` 与可执行文件同目录的 `config/` 下

### 授权终端部署
1. **仅部署给授权管理员**，不得外传
2. 单独目录，包含 `USBKey.LicenseTool.exe` 及其依赖
3. 私钥已编译进二进制（生产环境需重新生成密钥对并替换 `LicenseIssuer.cs` 中的私钥）

## 已知限制与待完成

### 已实现
- ✅ 配置体系（config.json）
- ✅ 授权体系（RSA 签名、机器码绑定、联网取时）
- ✅ 抽象接口层（`IKeyProvider`）
- ✅ Mock 平台（完整模拟，可演示）
- ✅ LNCA DLL 加载框架（通过序号导出解析）
- ✅ USB 热插拔监听
- ✅ WinForms UI（720x480，托盘）
- ✅ 证书管理（导入/查看/导出/删除/注册）
- ✅ 系统设置（用户/管理页签）

### 待完成（需实物设备 + IDA）
- ⏳ LNCA 真实接口对接（需逆向 `JIT_USBKEY_HD.dll` 序号导出的函数签名）
  - 当前状态：框架已搭建，调用真实设备时抛出 `NotSupportedException` 并提示待逆向
  - 对接方法：见上文"接口对接步骤"
- ⏳ 云端导入证书（需后端服务支持，当前为 `hidden`）
- ⏳ REST API（已实现 `RestApiServer`，默认未启用）

## 常见问题

### Q1: 启动提示"未找到授权文件"？
**A**: 管理模式需要 `config/license.key`。用户模式将 `config.json` 的 `usermode` 改为 `true` 即可跳过授权。

### Q2: 真实 LNCA 设备无法操作？
**A**: 当前 LNCA 接口待逆向对接。用 Mock 平台演示 UI 与流程，真实对接需实物设备 + IDA Pro 确认函数签名。见 `LncaProvider.cs` 的 `NotImplemented<T>()` 提示。

### Q3: 如何生成授权？
**A**: 用 `USBKey.LicenseTool.exe`，输入机器码、选择平台、设置有效期，生成 license.key 并提供给用户。

### Q4: 授权到期后会怎样?
**A**: 管理模式启动时校验授权，过期则无法运行并提示更新授权。用户模式不受影响。

### Q5: 机器码是否会变化？
**A**: 机器码基于 CPUID+硬盘序列号+主板 UUID 的 SHA256，硬件不变则机器码稳定。更换主板/硬盘会导致机器码变化，需重新授权。

### Q6: 如何支持多个平台/厂商？
**A**: 在 `config.json` 的 `platform` 与 `keyslist` 中添加新厂商的配置，并实现对应的 `IKeyProvider`（参考 `MockKeyProvider` 与 `LncaProvider`）。

## 许可与支持

- **版权**：Copyright © 2026
- **技术支持**：见软件"系统设置"中的软件信息

---

**开发环境**：Windows 11 x64 + .NET 8 SDK  
**构建日期**：2026-08-23  
**版本**：1.0.0.0
