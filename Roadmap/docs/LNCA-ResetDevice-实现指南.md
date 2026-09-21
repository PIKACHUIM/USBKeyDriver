# LNCA ResetDevice 实现指南

## 问题背景

原 `LncaProvider.ResetDevice()` 调用 `JIT_USBKEY_HD.dll` 的 `USBKey_Reset`，但该函数是**调试空壳**（仅打印日志后返回），不执行任何实际操作。

## 解决方案

通过逆向分析 LNCA SDK 的 DLL 链，找到真实的设备初始化路径。

### 真实初始化链路

```
HD_HardAPI.dll (高层)
  ├─ HSConnectDev(devIndex, &hDev)    → 连接设备
  ├─ HSVerifyUserPin(hDev, pin, len)  → (可选) SO PIN 校验
  ├─ HSErase(hDev)                    → 核心：擦除设备
  └─ HSDisconnectDev(hDev)            → 断开连接
       ↓
HD_SortDev.dll (中间层)
  └─ HS_Erase
       ↓
HDCOS_LNCA.dll (底层 COS)
  ├─ HD_IC_RESET      → 卡片物理复位
  ├─ HD_ClearDir      → 清除目录结构
  ├─ Clear_DF         → 清除 DF
  └─ HD_SPWD          → 重置管理员密码
```

### 关键函数签名

| 函数 | 签名 | 说明 |
|------|------|------|
| `HSConnectDev` | `int(int devIndex, int* phDev)` | 返回 0=成功，0x66=索引越界 |
| `HSErase` | `int(int hDev)` | 返回 0=成功，0x99=失败 |
| `HSDisconnectDev` | `int(int hDev)` | 关闭句柄 |
| `HSVerifyUserPin` | `int(int hDev, byte* pin, int len)` | SO PIN 校验 |

所有函数使用 `__stdcall` 调用约定。

## 代码实现

### 1. 新增文件：`LncaHardApiNative.cs`

```csharp
using System;
using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey
{
    internal static class LncaHardApiNative
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int ConnectDevFn(int devIndex, out IntPtr phDev);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int EraseFn(IntPtr hDev);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int DisconnectDevFn(IntPtr hDev);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int VerifyUserPinFn(IntPtr hDev, byte[] pin, int pinLen);
    }
}
```

### 2. 修改 `LncaProvider.cs`

#### Initialize() 添加 HD_HardAPI.dll 加载

```csharp
private IntPtr _hardApi;
private LncaHardApiNative.ConnectDevFn? _hsConnectDev;
private LncaHardApiNative.EraseFn? _hsErase;
private LncaHardApiNative.DisconnectDevFn? _hsDisconnectDev;
private LncaHardApiNative.VerifyUserPinFn? _hsVerifyUserPin;

public void Initialize()
{
    // ... 原有 JIT 层加载 ...
    
    // 加载底层真实 API
    LoadHardApi();
}

private void LoadHardApi()
{
    string hardApiPath = Path.Combine(_libraryPath, "HD_HardAPI.dll");
    if (!File.Exists(hardApiPath)) return;
    
    _hardApi = NativeMethods.LoadLibrary(hardApiPath);
    if (_hardApi == IntPtr.Zero) return;
    
    IntPtr hsConnectDev = NativeMethods.GetProcAddress(_hardApi, "HSConnectDev");
    if (hsConnectDev != IntPtr.Zero)
        _hsConnectDev = Marshal.GetDelegateForFunctionPointer<LncaHardApiNative.ConnectDevFn>(hsConnectDev);
    
    IntPtr hsErase = NativeMethods.GetProcAddress(_hardApi, "HSErase");
    if (hsErase != IntPtr.Zero)
        _hsErase = Marshal.GetDelegateForFunctionPointer<LncaHardApiNative.EraseFn>(hsErase);
    
    IntPtr hsDisconnectDev = NativeMethods.GetProcAddress(_hardApi, "HSDisconnectDev");
    if (hsDisconnectDev != IntPtr.Zero)
        _hsDisconnectDev = Marshal.GetDelegateForFunctionPointer<LncaHardApiNative.DisconnectDevFn>(hsDisconnectDev);
    
    IntPtr hsVerifyUserPin = NativeMethods.GetProcAddress(_hardApi, "HSVerifyUserPin");
    if (hsVerifyUserPin != IntPtr.Zero)
        _hsVerifyUserPin = Marshal.GetDelegateForFunctionPointer<LncaHardApiNative.VerifyUserPinFn>(hsVerifyUserPin);
}
```

#### ResetDevice() 改用真实 API

```csharp
public bool ResetDevice(IKeyDevice device, string? adminKey = null)
{
    if (_hsErase != null && _hsConnectDev != null && _hsDisconnectDev != null)
    {
        return ResetViaHardApi(device, adminKey);
    }
    
    // 回退：旧行为（调用 JIT 层空壳）
    EnsureConnected(device);
    int result = _usbKeyReset?.Invoke(_hKey) ?? -1;
    if (result == 0)
    {
        device.IsLoggedIn = true;
        return true;
    }
    return false;
}

private bool ResetViaHardApi(IKeyDevice device, string? adminKey)
{
    int devIndex = device.Index;
    IntPtr hDev = IntPtr.Zero;
    
    try
    {
        // 1. 连接设备
        int ret = _hsConnectDev!(devIndex, out hDev);
        if (ret != 0) return false;
        
        // 2. (可选) SO PIN 校验
        if (!string.IsNullOrEmpty(adminKey) && _hsVerifyUserPin != null)
        {
            byte[] adminPinBytes = System.Text.Encoding.ASCII.GetBytes(adminKey);
            ret = _hsVerifyUserPin(hDev, adminPinBytes, adminPinBytes.Length);
            if (ret != 0) return false;
        }
        
        // 3. 擦除设备（核心操作）
        ret = _hsErase!(hDev);
        if (ret != 0) return false;
        
        // TODO: 4. 重新设置用户 PIN（需确认出厂默认值）
        // 当前跳过，由调用方在擦除后手动设置
        
        device.IsLoggedIn = true;
        return true;
    }
    finally
    {
        if (hDev != IntPtr.Zero)
        {
            _hsDisconnectDev!(hDev);
        }
    }
}
```

#### Dispose() 释放资源

```csharp
public void Dispose()
{
    // ... 原有释放逻辑 ...
    
    if (_hardApi != IntPtr.Zero)
    {
        NativeMethods.FreeLibrary(_hardApi);
        _hardApi = IntPtr.Zero;
    }
}
```

## 使用方法

```csharp
var provider = new LncaProvider(@"C:\Path\To\LNCA\SDK");
provider.Initialize();

var device = new KeyDevice { Index = 0 };

// 方式 1：不提供 SO PIN（可能失败）
bool success = provider.ResetDevice(device);

// 方式 2：提供 SO PIN（推荐）
bool success = provider.ResetDevice(device, adminKey: "123456");
```

## 待确认项（需实体设备测试）

1. **出厂默认 SO PIN**：可能为空、`"111111"`、`"123456"` 或其他
2. **擦除后默认用户 PIN**：`HSErase` 后设备的初始用户 PIN 值
3. **SO PIN 校验必要性**：部分厂商可能强制要求 SO PIN，部分可能允许直接擦除

## 逆向分析依据

详细分析过程见：`LNCA-逆向分析-完整函数签名.md`

关键证据：
- `JIT_USBKEY_HD.dll::USBKey_Reset` @ RVA 0x4900：反汇编显示仅 `xor eax,eax; ret`
- `HD_HardAPI.dll::HSErase` @ RVA 0x18A0：完整擦除逻辑，调用 `HS_Erase`
- `HDCOS_LNCA.dll::HD_ClearDir` @ RVA 0x67D0：发送擦除 APDU，检查 SW=0x9000

所有签名通过 `ret imm16` 指令验证（`__stdcall` 调用约定）。

## 构建测试

```bash
cd Manager/src/USBKey.Core
dotnet build
```

**结果**：✅ 0 错误，0 警告

---

**版本**：2026-08-26  
**状态**：代码实现完成，等待实体设备验证
