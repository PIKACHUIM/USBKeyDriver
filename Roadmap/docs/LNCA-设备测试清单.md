# LNCA 设备测试清单

## ✅ 已完成

- [x] 逆向分析 `JIT_USBKEY_HD.dll`，确认 `USBKey_Reset` 是空壳
- [x] 定位真实初始化 API：`HD_HardAPI.dll::HSErase`
- [x] 提取 8 个关键函数的精确签名（通过 `ret imm16` 反推）
- [x] 实现 `LncaHardApiNative.cs` P/Invoke 声明
- [x] 重写 `LncaProvider.ResetDevice()` 方法
- [x] 编译验证通过（0 错误 0 警告）
- [x] 输出 3 份技术文档（完整版、实用版、摘要版）

## 🔄 待测试（需实体设备）

### 测试 1：基本擦除功能
```csharp
var provider = new LncaProvider(@"C:\Path\To\LNCA\SDK");
provider.Initialize();
var device = new KeyDevice { Index = 0 };

// 不提供 SO PIN
bool result = provider.ResetDevice(device);
Console.WriteLine($"擦除结果: {result}");
```

**预期**：
- [ ] 返回 `true`（成功）或 `false`（需要 SO PIN）
- [ ] 记录实际返回值和错误码

---

### 测试 2：SO PIN 校验
```csharp
// 尝试常见默认 SO PIN
string[] testPins = { "", "111111", "123456", "888888", "000000" };

foreach (var pin in testPins)
{
    var device = new KeyDevice { Index = 0 };
    bool result = provider.ResetDevice(device, adminKey: pin);
    Console.WriteLine($"SO PIN '{pin}': {(result ? "✅ 成功" : "❌ 失败")}");
    
    if (result) break; // 找到正确的默认 PIN
}
```

**预期**：
- [ ] 确定出厂默认 SO PIN 值
- [ ] 记录为：`______`

---

### 测试 3：擦除后设备状态
```csharp
// 擦除前
bool loginBefore = provider.LoginAsUser(device, "旧PIN");
Console.WriteLine($"擦除前登录: {loginBefore}");

// 执行擦除
bool erased = provider.ResetDevice(device, adminKey: "确认的SO_PIN");

// 擦除后
bool loginAfter = provider.LoginAsUser(device, "");  // 尝试空PIN
Console.WriteLine($"擦除后（空PIN）: {loginAfter}");

loginAfter = provider.LoginAsUser(device, "111111");  // 尝试常见默认
Console.WriteLine($"擦除后（111111）: {loginAfter}");
```

**预期**：
- [ ] 确定擦除后默认用户 PIN
- [ ] 记录为：`______`

---

### 测试 4：完整重置流程
```csharp
try
{
    var device = new KeyDevice { Index = 0 };
    
    // 1. 擦除设备
    bool erased = provider.ResetDevice(device, adminKey: "确认的SO_PIN");
    if (!erased)
    {
        Console.WriteLine("❌ 擦除失败");
        return;
    }
    
    // 2. 设置新用户 PIN
    bool pinSet = provider.ChangeUserPin(device, "出厂默认PIN", "新PIN123456");
    Console.WriteLine($"设置新PIN: {(pinSet ? "✅" : "❌")}");
    
    // 3. 使用新PIN登录
    bool login = provider.LoginAsUser(device, "新PIN123456");
    Console.WriteLine($"新PIN登录: {(login ? "✅" : "❌")}");
    
    // 4. 生成测试密钥对
    bool keyGen = provider.GenerateKeyPair(device, "测试密钥", 2048);
    Console.WriteLine($"生成密钥: {(keyGen ? "✅" : "❌")}");
}
catch (Exception ex)
{
    Console.WriteLine($"❌ 异常: {ex.Message}");
}
```

**预期**：
- [ ] 完整流程无异常
- [ ] 所有步骤返回 `true`

---

## 📝 测试结果记录表

| 测试项 | 结果 | 备注 |
|--------|------|------|
| 不提供 SO PIN 擦除 | ⬜ 成功 / ⬜ 失败 | 返回值: _____ |
| 出厂默认 SO PIN | ⬜ 找到 | 值: _____ |
| 擦除后默认用户 PIN | ⬜ 确认 | 值: _____ |
| SO PIN 校验必要性 | ⬜ 必须 / ⬜ 可选 |  |
| 完整重置流程 | ⬜ 通过 / ⬜ 失败 | 错误: _____ |

---

## 🐛 常见问题排查

### 问题 1：`HSConnectDev` 返回 0x66
**原因**：设备索引越界  
**解决**：
```csharp
// 枚举所有设备
var devices = provider.EnumerateDevices();
Console.WriteLine($"找到 {devices.Count} 个设备");
foreach (var dev in devices)
{
    Console.WriteLine($"  设备 {dev.Index}: {dev.SerialNumber}");
}
```

### 问题 2：`HSErase` 返回 0x99
**原因**：可能需要 SO PIN 校验  
**解决**：提供 `adminKey` 参数

### 问题 3：`HSVerifyUserPin` 失败
**原因**：SO PIN 错误  
**解决**：联系厂商确认默认 SO PIN

---

## 📋 待更新代码位置

测试确认后，更新以下代码中的 TODO：

### 文件：`LncaProvider.cs`
```csharp
// 第 583 行左右
// TODO: 确认出厂默认 SO PIN（当前假设为空或 "111111"）
if (!string.IsNullOrEmpty(adminKey) && _hsVerifyUserPin != null)
{
    // ... SO PIN 校验 ...
}

// 第 595 行左右
// TODO: 4. 重新设置用户 PIN（需确认出厂默认值）
// 当前跳过，由调用方在擦除后手动设置
```

**更新为**：
```csharp
// 确认的出厂默认 SO PIN（实测值：_____）
if (!string.IsNullOrEmpty(adminKey) && _hsVerifyUserPin != null)
{
    // ...
}

// 4. 重新设置用户 PIN（出厂默认：_____）
byte[] defaultPin = Encoding.ASCII.GetBytes("测试确认的默认PIN");
byte[] newPin = Encoding.ASCII.GetBytes("888888");
// 调用 ChangeUserPin...
```

---

## 📞 需要联系信息

如果测试遇到问题，建议联系：

1. **LNCA 厂商技术支持**
   - 确认出厂默认 SO PIN
   - 确认擦除后默认用户 PIN
   - 索取完整的 SDK 文档

2. **现有 LNCA 设备用户**
   - 询问初始化设备的操作步骤
   - 确认管理工具 `GP_ADM_LNCA.exe` 的使用方法

---

## 🎯 测试完成标准

全部测试通过后，标记为 ✅：

- [ ] 至少成功擦除 1 次设备
- [ ] 确认出厂默认 SO PIN
- [ ] 确认擦除后默认用户 PIN
- [ ] 完整重置流程（擦除 → 设置 PIN → 登录 → 生成密钥）通过
- [ ] 更新代码中的 TODO 注释
- [ ] 更新文档中的"待确认项"

---

**测试负责人**：_______  
**测试日期**：_______  
**设备型号**：_______  
**SDK 版本**：_______
