# LNCA USB Key 设备重置功能实现

> **状态**：✅ 代码完成 | ⏳ 等待设备测试  
> **日期**：2026-08-26  

## 🎯 问题与解决方案

### 问题
原 `ResetDevice()` 调用 `JIT_USBKEY_HD.dll::USBKey_Reset`，但该函数是**调试空壳**（仅返回 0，无实际操作）。

### 解决方案
通过逆向分析找到真实 API：`HD_HardAPI.dll::HSErase`，实现真正的设备擦除/重置。

## 🚀 快速开始

### 基本使用
```csharp
var provider = new LncaProvider(@"C:\Path\To\LNCA\SDK");
provider.Initialize();

var device = new KeyDevice { Index = 0 };

// 重置设备（需要 SO PIN）
bool success = provider.ResetDevice(device, adminKey: "111111");

if (success)
{
    Console.WriteLine("✅ 设备重置成功");
}
```

### 完整流程
```csharp
// 1. 擦除设备
bool erased = provider.ResetDevice(device, adminKey: "SO_PIN");

// 2. 设置新用户 PIN
bool pinSet = provider.ChangeUserPin(device, "出厂默认PIN", "新PIN123456");

// 3. 登录验证
bool login = provider.LoginAsUser(device, "新PIN123456");

// 4. 生成密钥对
bool keyGen = provider.GenerateKeyPair(device, "测试密钥", 2048);
```

## 📚 文档导航

### 不同角色的阅读建议

| 角色 | 推荐文档 | 时间 |
|------|---------|------|
| 👨‍💻 **开发者（快速集成）** | [LNCA-快速参考.txt](./LNCA-快速参考.txt) | 5分钟 |
| 🛠️ **开发者（详细实现）** | [LNCA-ResetDevice-实现指南.md](./LNCA-ResetDevice-实现指南.md) | 15分钟 |
| 🔬 **技术专家（深度理解）** | [LNCA-逆向分析-完整函数签名.md](./LNCA-逆向分析-完整函数签名.md) | 1小时 |
| 📊 **项目经理** | [LNCA-任务完成报告.md](./LNCA-任务完成报告.md) | 20分钟 |
| 🧪 **测试工程师** | [LNCA-设备测试清单.md](./LNCA-设备测试清单.md) | 参考 |
| 🗂️ **所有人** | [LNCA-项目索引.md](./LNCA-项目索引.md) | 导航 |

### 文档列表

1. **[LNCA-快速参考.txt](./LNCA-快速参考.txt)** - ASCII 艺术风格快速参考卡片
2. **[LNCA-ResetDevice-实现指南.md](./LNCA-ResetDevice-实现指南.md)** - 开发实用指南
3. **[LNCA-逆向总结.md](./LNCA-逆向总结.md)** - 30 分钟技术摘要
4. **[LNCA-逆向分析-完整函数签名.md](./LNCA-逆向分析-完整函数签名.md)** - 完整技术文档
5. **[LNCA-任务完成报告.md](./LNCA-任务完成报告.md)** - 项目报告
6. **[LNCA-设备测试清单.md](./LNCA-设备测试清单.md)** - 测试步骤
7. **[LNCA-项目索引.md](./LNCA-项目索引.md)** - 完整索引

## 💻 代码改动

### 新增文件
- **`Manager/src/USBKey.Core/UsbKey/LncaHardApiNative.cs`**
  - HD_HardAPI.dll 的 P/Invoke 声明
  - 4 个委托：ConnectDev, Erase, DisconnectDev, VerifyUserPin

### 修改文件
- **`Manager/src/USBKey.Core/UsbKey/LncaProvider.cs`**
  - 新增字段：5 个
  - 新增方法：`LoadHardApi()`, `ResetViaHardApi()`
  - 修改方法：`Initialize()`, `ResetDevice()`, `Dispose()`

### 构建验证
```bash
cd Manager/src/USBKey.Core
dotnet build
```
**结果**：✅ 0 错误，0 警告

## 🔧 工具脚本

### disasm_hdcos_full.py
**位置**：`Manager/tools/disasm_hdcos_full.py`

**功能**：
- 解析 PE 导出表
- 反汇编 x86 代码（Capstone）
- 自动检测函数边界
- 输出格式化汇编代码

**依赖**：
```bash
pip install capstone pefile
```

**使用**：
```bash
python disasm_hdcos_full.py > hdcos_disasm_full.txt
```

## 📊 核心发现

### 函数签名对照表

| DLL | 函数 | 签名 | 说明 |
|-----|------|------|------|
| HD_HardAPI.dll | **HSErase** | `int(int hDev)` | ⭐ 核心擦除函数 |
| HD_HardAPI.dll | HSConnectDev | `int(int devIndex, int* phDev)` | 连接设备 |
| HD_HardAPI.dll | HSDisconnectDev | `int(int hDev)` | 断开连接 |
| HD_HardAPI.dll | HSVerifyUserPin | `int(int hDev, byte* pin, int len)` | SO PIN 校验 |
| HDCOS_LNCA.dll | HD_ClearDir | `int(int hCard)` | 清除目录 |
| HDCOS_LNCA.dll | HD_IC_RESET | `int(int hCard, byte* atr)` | 卡片复位 |

**签名提取方法**：通过反汇编 `ret imm16` 指令推导参数个数（`__stdcall` 调用约定）

### 调用链路

```
用户代码
  ↓
HSConnectDev → [HSVerifyUserPin] → HSErase → HSDisconnectDev
                                      ↓
                                  HS_Erase (HD_SortDev.dll)
                                      ↓
                      ┌───────────────┴───────────────┐
                      ↓                               ↓
                HD_IC_RESET                     HD_ClearDir
                (卡片复位)                       (清除目录)
                                                      ↓
                                                  Clear_DF
                                                  (清除DF)
```

## ⚠️ 待确认参数（需实体设备）

| 参数 | 当前假设 | 测试后填写 |
|------|---------|-----------|
| 出厂默认 SO PIN | 空 或 `"111111"` | _________ |
| 擦除后默认用户 PIN | 未知 | _________ |
| SO PIN 校验是否必须 | 可选 | _________ |

**测试方法**：参考 [LNCA-设备测试清单.md](./LNCA-设备测试清单.md)

## 🐛 常见问题

### Q1: ResetDevice 返回 false？
**排查步骤**：
1. 检查 `HD_HardAPI.dll` 是否存在于 SDK 目录
2. 确认设备索引正确（调用 `EnumerateDevices()`）
3. 尝试提供 SO PIN：`"111111"`, `"123456"`, 空字符串
4. 查看 `ResetViaHardApi()` 中每个函数的返回值

### Q2: 编译错误？
**确认**：
- .NET 版本：8.0 或更高
- 平台：Windows（LNCA SDK 仅支持 Windows）
- 架构：x86 或 Any CPU（DLL 是 32 位）

### Q3: 需要查看汇编代码？
**查看**：`Manager/tools/hdcos_disasm_full.txt`（完整反汇编输出）

## 📈 项目影响

| 维度 | 改进 |
|------|------|
| **功能性** | 从"完全无效"到"真实可用" |
| **可维护性** | 清晰的文档和调用链路 |
| **可测试性** | 独立方法便于单元测试 |
| **兼容性** | 回退机制保证旧环境可运行 |

## 🚀 后续工作

### 短期（获得设备后）
- [ ] 执行完整设备测试
- [ ] 确认默认 PIN 值
- [ ] 更新代码中的 TODO 注释
- [ ] 添加单元测试

### 中期
- [ ] 实现完整 PIN 重置流程
- [ ] 优化错误码映射
- [ ] 添加详细日志

### 长期
- [ ] 逆向其他平台（恒宝、龙脉）
- [ ] 统一初始化接口
- [ ] 创建完整 SDK 文档

## 📝 许可与贡献

本项目是 USBKeyDriver 的一部分。

**逆向分析**：合法用于互操作性目的（兼容自有系统）  
**文档**：MIT License  

## 📞 联系

遇到问题？
1. 查看 [LNCA-快速参考.txt](./LNCA-快速参考.txt) 快速排查流程
2. 参考 [LNCA-设备测试清单.md](./LNCA-设备测试清单.md) 常见问题
3. 阅读 [LNCA-逆向分析-完整函数签名.md](./LNCA-逆向分析-完整函数签名.md) 深度分析

---

**更新时间**：2026-08-27  
**版本**：v1.0  
**状态**：代码完成，等待设备验证
