# USB Key 厂商 DLL 逆向对接指南

> **目标读者**：需要对接第三方 USB Key / 智能卡设备的 C# 开发者  
> **适用场景**：厂商未提供或提供不完整 SDK 文档，需要通过逆向分析 DLL 来实现设备对接  
> **前置技能**：C# P/Invoke、Win32 PE 格式基础、基本汇编阅读能力

---

## 目录

1. [逆向分析流程](#1-逆向分析流程)
2. [工具准备](#2-工具准备)
3. [静态分析](#3-静态分析)
4. [动态分析](#4-动态分析)
5. [C# 对接实现](#5-c-对接实现)
6. [常见问题与陷阱](#6-常见问题与陷阱)
7. [完整案例：LNCA USB Key](#7-完整案例lnca-usb-key)

---

## 1. 逆向分析流程

### 1.1 总体策略

```
静态分析（获取函数签名）
    ↓
编写测试程序（验证签名）
    ↓
动态调试（修正错误签名）
    ↓
实现 C# 封装
    ↓
集成到主程序
```

### 1.2 核心原则

1. **不要一次性实现所有功能** - 逐个函数验证，确保每个签名正确
2. **先用独立测试程序，再集成到主程序** - 避免主程序崩溃
3. **日志优先** - 每个 DLL 调用都记录参数和返回值
4. **以动态分析为准** - 静态分析的结论需要动态验证

---

## 2. 工具准备

### 2.1 必备工具

| 工具 | 用途 | 下载/安装 |
|------|------|-----------|
| **objdump** | PE 文件分析、反汇编 | MSYS2 / MinGW64 |
| **strings** | 提取 DLL 内嵌字符串 | MSYS2 / GNU binutils |
| **x64dbg / x32dbg** | 动态调试、观察运行时行为 | https://x64dbg.com/ |
| **IDA Free / Ghidra** | 深度反汇编分析（可选） | IDA: https://hex-rays.com/ida-free/ |
| **Python** | 编写自动化分析脚本 | https://www.python.org/ |

### 2.2 环境准备

```bash
# 1. 安装 MSYS2
# 下载: https://www.msys2.org/
# 安装后执行：
pacman -S mingw-w64-x86_64-binutils

# 2. 验证 objdump
objdump --version

# 3. 验证 x64dbg
# 启动 x96dbg.exe，根据 DLL 位数选择 x32dbg 或 x64dbg
```

### 2.3 项目结构

```
USBKeyProject/
├─ Library/                    # 厂商 DLL 存放位置
│  └─ VendorName/
│     ├─ main_api.dll          # 主接口 DLL
│     ├─ dependency1.dll       # 依赖 DLL
│     └─ ...
├─ tools/
│  ├─ TestProbe/               # 独立测试程序
│  │  ├─ TestProbe.csproj
│  │  └─ Program.cs
│  └─ scripts/
│     ├─ analyze_dll.ps1       # DLL 分析脚本
│     └─ extract_exports.py    # 导出表提取
└─ src/
   └─ Core/
      └─ Native/
         ├─ VendorNative.cs    # P/Invoke 声明
         └─ VendorProvider.cs  # 设备操作封装
```

---

## 3. 静态分析

### 3.1 第一步：确定 DLL 位数

```bash
objdump -f main_api.dll
```

**关键输出：**
```
main_api.dll:     file format pei-i386      # 32位 DLL
# 或
main_api.dll:     file format pei-x86-64    # 64位 DLL
```

**C# 项目配置：**
```xml
<PropertyGroup>
  <!-- 32位 DLL 必须设置 -->
  <PlatformTarget>x86</PlatformTarget>
  
  <!-- 64位 DLL 设置 -->
  <PlatformTarget>x64</PlatformTarget>
</PropertyGroup>
```

### 3.2 第二步：提取导出函数

#### 方法 1：使用 objdump

```bash
objdump -p main_api.dll | grep "\[" | grep -E "^\s+\["
```

**输出示例：**
```
[  101] USBKey_Connect
[  102] USBKey_Disconnect
[  103] USBKey_UserLogin
...
```

#### 方法 2：使用 PowerShell 脚本

```powershell
# extract_exports.ps1
$dllPath = "Library/VendorName/main_api.dll"
$exports = dumpbin /exports $dllPath 2>$null | Select-String -Pattern "\d+\s+[A-F0-9]+\s+[A-F0-9]+\s+\w+"

foreach ($line in $exports) {
    if ($line -match "(\d+)\s+([A-F0-9]+)\s+([A-F0-9]+)\s+(\w+)") {
        Write-Host "[$($matches[1])] $($matches[4])"
    }
}
```

**⚠️ 重要陷阱：**
- **导出名表按字典序排列，不是按序号排列**
- 不要依赖序号顺序来读取函数名
- 总是通过函数名调用：`GetProcAddress("FunctionName")`

### 3.3 第三步：提取字符串线索

```bash
strings -n 5 main_api.dll > strings.txt
```

**寻找的关键线索：**

1. **调试日志字符串**（最有价值）：
```
"USBKey_UserLogin Start... hKey=0x%08x, lpPinStr=%s, lpPinStrLen=%u"
"USBKey_Connect Success... phKey=0x%08x"
"Error: Invalid parameter at line %d"
```

从格式字符串可以推断：
- `%08x` → `IntPtr`（句柄/指针）
- `%s` → `string`（ANSI 字符串）
- `%u` / `%d` → `uint` / `int`

2. **错误消息**：
```
"Device not found"
"PIN verification failed"
"Buffer too small"
```

3. **函数名自身**（确认导出表）

### 3.4 第四步：反汇编关键函数

```bash
# 1. 找到函数地址
objdump -p main_api.dll | grep "USBKey_Connect"
# 输出: [  101] 0x10001DF0 USBKey_Connect

# 2. 反汇编该函数
objdump -d --start-address=0x10001DF0 --stop-address=0x10001E50 main_api.dll
```

**关键信息：**

#### A. 判断调用约定和参数数量

```asm
; 函数结尾
...
ret $0xC        ; __stdcall, 3个参数 (12字节 = 3 * 4)
; 或
ret             ; __cdecl
```

**参数数量计算：**
- `ret $0xN` → 参数数量 = `N / 4`（32位）或 `N / 8`（64位）

#### B. 判断参数类型

```asm
; 读取第1个参数（值传递）
mov 0x4(%esp),%eax    ; eax = 参数1

; 读取第2个参数（指针传递）
mov 0x8(%esp),%ecx    ; ecx = 参数2地址
mov (%ecx),%edx       ; edx = *参数2（解引用）
```

**规律：**
- `mov (%reg),%reg` → **指针参数**（需要 `ref` / `out` / `IntPtr`）
- 直接 `push %reg` → **值参数**

#### C. 判断返回值类型

```asm
xor %eax,%eax    ; eax = 0（成功返回0）
ret

; 或
mov $0x3EA,%eax  ; eax = 错误码
ret
```

**规律：**
- 几乎所有 USB Key DLL 返回 `int`
- `0` = 成功，非 `0` = 错误码

---

## 4. 动态分析

### 4.1 编写独立测试程序

**目的：** 在不影响主程序的情况下验证函数签名

#### 项目结构

```
tools/TestProbe/
├─ TestProbe.csproj
└─ Program.cs
```

#### TestProbe.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <PlatformTarget>x86</PlatformTarget>  <!-- 根据DLL位数 -->
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  </PropertyGroup>
</Project>
```

#### Program.cs 模板

```csharp
using System;
using System.Runtime.InteropServices;

class TestProbe
{
    // ========== 测试不同的函数签名 ==========
    
    // 签名1: 假设参数都是值
    [DllImport("main_api.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_Connect_V1(uint index, uint baudRate, IntPtr hKey);
    
    // 签名2: 假设最后一个参数是指针
    [DllImport("main_api.dll", EntryPoint = "USBKey_Connect", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_Connect_V2(uint index, uint baudRate, out IntPtr hKey);
    
    // 签名3: 尝试 Cdecl
    [DllImport("main_api.dll", EntryPoint = "USBKey_Connect", CallingConvention = CallingConvention.Cdecl)]
    static extern int USBKey_Connect_V3(uint index, uint baudRate, out IntPtr hKey);
    
    // ========== 辅助函数 ==========
    
    [DllImport("main_api.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_ListKey(out uint count);
    
    static void Main()
    {
        Console.WriteLine("=== USB Key DLL 测试探针 ===\n");
        
        // 1. 枚举设备
        uint count = 0;
        int rc = USBKey_ListKey(out count);
        Console.WriteLine($"[1] USBKey_ListKey: rc=0x{rc:X}, count={count}");
        
        if (rc != 0 || count == 0)
        {
            Console.WriteLine("没有设备，按任意键退出...");
            Console.ReadKey();
            return;
        }
        
        // 2. 测试不同的 Connect 签名
        Console.WriteLine("\n[2] 测试 USBKey_Connect 签名:");
        
        Console.WriteLine("  签名1 (值传递):");
        try
        {
            IntPtr hKey1 = IntPtr.Zero;
            rc = USBKey_Connect_V1(0, 0, hKey1);
            Console.WriteLine($"    rc=0x{rc:X}, hKey=0x{hKey1.ToInt32():X}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    ✗ 异常: {ex.Message}");
        }
        
        Console.WriteLine("  签名2 (指针传递 + StdCall):");
        try
        {
            IntPtr hKey2;
            rc = USBKey_Connect_V2(0, 0, out hKey2);
            Console.WriteLine($"    rc=0x{rc:X}, hKey=0x{hKey2.ToInt32():X}");
            
            if (rc == 0)
            {
                Console.WriteLine("    ✓ 签名2 成功！");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    ✗ 异常: {ex.Message}");
        }
        
        Console.WriteLine("  签名3 (指针传递 + Cdecl):");
        try
        {
            IntPtr hKey3;
            rc = USBKey_Connect_V3(0, 0, out hKey3);
            Console.WriteLine($"    rc=0x{rc:X}, hKey=0x{hKey3.ToInt32():X}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    ✗ 异常: {ex.Message}");
        }
        
        Console.WriteLine("\n测试完成，按任意键退出...");
        Console.ReadKey();
    }
}
```

#### 编译和运行

```bash
cd tools/TestProbe
dotnet build --configuration Release

# 复制 DLL 到输出目录
Copy-Item ../../Library/VendorName/*.dll bin/Release/net8.0/

# 运行测试
./bin/Release/net8.0/TestProbe.exe
```

### 4.2 使用 x64dbg 动态调试

#### 步骤 1：启动调试器

```bash
# 根据 DLL 位数选择
x96dbg.exe  # 启动器，选择 x32dbg 或 x64dbg
```

#### 步骤 2：加载测试程序

```
File -> Open -> 选择 TestProbe.exe
```

#### 步骤 3：在目标函数设置断点

```
1. 按 Ctrl+G，输入函数名：USBKey_Connect
2. 按 F2 设置断点
3. 按 F9 运行到断点
```

#### 步骤 4：观察参数和返回值

**32位程序栈布局（__stdcall）：**

```
[ESP+0]  = 返回地址
[ESP+4]  = 参数1
[ESP+8]  = 参数2
[ESP+12] = 参数3
...
```

**在断点处查看：**
- 右键栈窗口 → `Follow in Dump` → 查看参数值
- 单步执行（F7）观察寄存器变化
- 函数返回后查看 `EAX`（返回值）

#### 步骤 5：记录正确的参数

```
实际观察到的调用:
USBKey_Connect(0, 0, 0x0012FF50)
                ^  ^  ^
              index baud  phKey指针

返回后:
EAX = 0
*0x0012FF50 = 0x06F29AB0  (hKey值)
```

**结论：签名2 正确！**

---

## 5. C# 对接实现

### 5.1 创建 Native 声明文件

```csharp
// src/Core/Native/VendorNative.cs
using System;
using System.Runtime.InteropServices;

namespace USBKey.Core.Native
{
    internal static class VendorNative
    {
        private const string DllName = "main_api.dll";
        
        // ========== 设备连接 ==========
        
        /// <summary>
        /// 连接设备
        /// </summary>
        /// <param name="index">设备索引 (0..3)</param>
        /// <param name="baudRate">波特率 (传0即可)</param>
        /// <param name="phKey">输出设备句柄</param>
        /// <returns>0=成功, 非0=错误码</returns>
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_Connect(uint index, uint baudRate, out IntPtr phKey);
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_Disconnect(IntPtr hKey);
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_ListKey(out uint count);
        
        // ========== PIN 管理 ==========
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_UserLogin(
            IntPtr hKey,
            [MarshalAs(UnmanagedType.LPStr)] string lpPinStr,
            uint lpPinStrLen);
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_ChangePin(
            IntPtr hKey,
            [MarshalAs(UnmanagedType.LPStr)] string lpOldPin,
            uint lpOldPinLen,
            [MarshalAs(UnmanagedType.LPStr)] string lpNewPin,
            uint lpNewPinLen);
        
        // ========== 证书操作 ==========
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_ReadCert(
            IntPtr hKey,
            uint certType,
            byte[] cert,
            ref uint certLen);
        
        [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
        internal static extern int USBKey_WriteCert(
            IntPtr hKey,
            uint certType,
            byte[] cert,
            uint certLen);
    }
}
```

### 5.2 创建 Provider 封装

```csharp
// src/Core/Native/VendorProvider.cs
using System;
using System.Collections.Generic;

namespace USBKey.Core.UsbKey
{
    public class VendorProvider : IKeyProvider
    {
        private IntPtr _hKey = IntPtr.Zero;
        
        public IReadOnlyList<UsbKeyDevice> Enumerate()
        {
            Console.WriteLine("[Vendor] 枚举设备...");
            
            uint count = 0;
            int rc = VendorNative.USBKey_ListKey(out count);
            Console.WriteLine($"[Vendor] ListKey: rc=0x{rc:X}, count={count}");
            
            if (rc != 0)
            {
                throw new InvalidOperationException($"枚举设备失败 (错误码 0x{rc:X})");
            }
            
            var devices = new List<UsbKeyDevice>();
            
            for (uint i = 0; i < count; i++)
            {
                try
                {
                    IntPtr hKey;
                    rc = VendorNative.USBKey_Connect(i, 0, out hKey);
                    Console.WriteLine($"[Vendor] Connect({i}): rc=0x{rc:X}, hKey=0x{hKey.ToInt32():X}");
                    
                    if (rc == 0)
                    {
                        // 读取序列号...
                        var device = new UsbKeyDevice
                        {
                            Platform = "vendor",
                            DeviceIndex = (int)i,
                            SerialNumber = "...",  // 从设备读取
                            IsConnected = true
                        };
                        
                        devices.Add(device);
                        
                        VendorNative.USBKey_Disconnect(hKey);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Vendor] 枚举设备{i}失败: {ex.Message}");
                }
            }
            
            return devices;
        }
        
        public void Login(UsbKeyDevice device, string pin)
        {
            Console.WriteLine($"[Vendor] 登录设备: {device.SerialNumber}");
            
            IntPtr hKey;
            int rc = VendorNative.USBKey_Connect((uint)device.DeviceIndex, 0, out hKey);
            if (rc != 0)
            {
                throw new InvalidOperationException($"连接设备失败 (错误码 0x{rc:X})");
            }
            
            _hKey = hKey;
            
            rc = VendorNative.USBKey_UserLogin(hKey, pin, (uint)pin.Length);
            Console.WriteLine($"[Vendor] UserLogin: rc=0x{rc:X}");
            
            if (rc != 0)
            {
                VendorNative.USBKey_Disconnect(hKey);
                _hKey = IntPtr.Zero;
                throw new InvalidOperationException($"登录失败 (错误码 0x{rc:X})");
            }
            
            device.IsLoggedIn = true;
        }
        
        public void Logout(UsbKeyDevice device)
        {
            if (_hKey != IntPtr.Zero)
            {
                VendorNative.USBKey_Disconnect(_hKey);
                _hKey = IntPtr.Zero;
            }
            
            device.IsLoggedIn = false;
        }
        
        // 实现其他 IKeyProvider 方法...
    }
}
```

---

## 6. 常见问题与陷阱

### 6.1 崩溃问题

#### 问题 1：Access Violation (0xC0000005)

**原因：**
- 函数签名错误（参数类型/顺序/数量）
- 调用约定错误（`StdCall` vs `Cdecl`）
- 传递了无效指针

**解决方法：**
```csharp
// 错误：传递值参数
int rc = USBKey_Connect(0, 0, hKey);  // ✗

// 正确：传递指针参数
int rc = USBKey_Connect(0, 0, out hKey);  // ✓
```

#### 问题 2：栈不平衡

**现象：**
```
程序运行一段时间后崩溃
或调用某个函数后，后续所有调用都失败
```

**原因：** 调用约定错误

**解决方法：**
```csharp
// 测试两种调用约定
[DllImport("api.dll", CallingConvention = CallingConvention.StdCall)]  // 大多数情况
[DllImport("api.dll", CallingConvention = CallingConvention.Cdecl)]   // 少数情况
```

### 6.2 参数问题

#### 问题 3：字符串乱码

**原因：** 字符编码错误

**解决方法：**
```csharp
// ANSI 编码（大多数 USB Key DLL）
[DllImport("api.dll")]
static extern int Function([MarshalAs(UnmanagedType.LPStr)] string str);

// Unicode 编码（少数）
[DllImport("api.dll")]
static extern int Function([MarshalAs(UnmanagedType.LPWStr)] string str);
```

#### 问题 4：缓冲区长度参数

**陷阱：** 长度参数可能是"值"或"指针"

```csharp
// 输入长度（值）
int USBKey_UserLogin(IntPtr hKey, string pin, uint pinLen);  // ✓

// 输出长度（指针，in/out）
int USBKey_ReadCert(IntPtr hKey, uint type, byte[] buf, ref uint bufLen);  // ✓ ref
int USBKey_ReadCert(IntPtr hKey, uint type, byte[] buf, uint bufLen);      // ✗ 错误
```

**识别方法：**
- 反汇编中有 `mov (%eax),%ecx` → **指针**（用 `ref` / `out`）
- 反汇编中直接 `cmp $0x100,%eax` → **值**

#### 问题 5：参数顺序错误

**陷阱：** 日志打印顺序 ≠ 参数传递顺序

**示例：** LNCA 的 `USBKey_GetRandom`
```
DLL 日志: "GetRandom: hKey=0x%08x, buf=0x%08x, len=%u"
实际参数: int USBKey_GetRandom(IntPtr hKey, uint len, byte[] buf)
                                             ^^^^    ^^^^
                                            顺序反了！
```

**解决方法：** 以反汇编为准，不要完全信任日志

### 6.3 错误码问题

#### 问题 6：不知道错误码含义

**解决方法 1：** 提取 DLL 内的错误消息

```bash
strings api.dll | grep -i "error\|failed\|invalid"
```

**解决方法 2：** 查看官方工具的错误提示

**解决方法 3：** 暴力测试常见错误码

```csharp
Dictionary<int, string> ErrorCodes = new()
{
    { 0, "成功" },
    { 1, "通用错误" },
    { 5, "参数错误" },
    { 6, "PIN 错误" },
    { 50, "设备未连接" },
    { 105, "权限不足" },
    // ...
};
```

---

## 7. 完整案例：LNCA USB Key

### 7.1 背景

- **厂商 DLL**：`JIT_USBKEY_HD.dll`（32位，__stdcall）
- **依赖 DLL**：`GP_IFD_LNCA.dll`, `HDCOS_LNCA.dll` 等
- **设备类型**：LNCA 智能卡

### 7.2 静态分析结果

```bash
# 导出函数数量
objdump -p JIT_USBKEY_HD.dll | grep "^\[" | wc -l
# 输出: 44个导出函数

# 提取日志字符串
strings JIT_USBKEY_HD.dll | grep "Start\.\.\."
```

**关键发现：**
```
"USBKey_Connect Start... dwKeyIndex=%u, bandRate=%u, phKey=0x%08x"
"USBKey_UserLogin Start... hKey=0x%08x, lpPinStr=%s, lpPinStrLen=%u"
"USBKey_ReadCert Start... hKey=0x%08x, certType=%u, cert=0x%08x, certLen=%u"
```

### 7.3 反汇编验证

```bash
objdump -d --start-address=0x10001DF0 --stop-address=0x10001E50 JIT_USBKEY_HD.dll
```

**`USBKey_Connect` 关键代码：**
```asm
10001DF0:  sub    $0xac,%esp         ; 分配栈空间
10001DF4:  mov    0x4(%esp),%esi     ; esi = dwKeyIndex
10001E10:  cmp    $0x4,%esi          ; if (dwKeyIndex >= 4)
10001E13:  ja     10001E20           ;     return 0x3EA (KEYMAX)
...
10001E40:  mov    0xC(%esp),%ebp     ; ebp = phKey
10001E44:  mov    %eax,0x0(%ebp)     ; *phKey = 句柄
10001E47:  xor    %eax,%eax          ; return 0
10001E49:  ret    $0xC                ; __stdcall, 3参数
```

**结论：**
```csharp
[DllImport("JIT_USBKEY_HD.dll", CallingConvention = CallingConvention.StdCall)]
internal static extern int USBKey_Connect(uint dwKeyIndex, uint bandRate, out IntPtr phKey);
```

### 7.4 动态测试

**测试程序输出：**
```
[1] USBKey_ListKey: rc=0x0, count=1
[2] 测试 USBKey_Connect 签名:
  签名1 (值传递):
    ✗ 异常: Attempted to read or write protected memory
  签名2 (指针传递 + StdCall):
    rc=0x0, hKey=0x6F29AB0
    ✓ 签名2 成功！
```

### 7.5 最终实现

完整代码见：
- `Manager/src/USBKey.Core/UsbKey/LncaNative.cs`
- `Manager/src/USBKey.Core/UsbKey/LncaProvider.cs`

**核心要点：**
1. ✅ 所有函数使用 `__stdcall`
2. ✅ 字符串使用 `ANSI` 编码（`LPStr`）
3. ✅ 输出参数使用 `out` / `ref`
4. ✅ 枚举使用 DLL 自己的 `USBKey_ListKey`，不依赖 WMI

### 7.6 遗留问题

**`USBKey_Reset` 函数无法使用：**
- 所有签名尝试均导致崩溃
- 需要进一步逆向或联系厂商

**临时方案：**
```csharp
public void ResetDevice(UsbKeyDevice device, string newPin, ...)
{
    throw new NotSupportedException("LNCA 设备暂不支持重置功能");
}
```

---

## 附录 A：PowerShell 分析脚本

```powershell
# analyze_dll.ps1
param(
    [string]$DllPath = "Library/main_api.dll"
)

Write-Host "=== DLL 分析工具 ===" -ForegroundColor Green
Write-Host "目标: $DllPath`n"

# 1. 检查文件存在
if (-not (Test-Path $DllPath)) {
    Write-Host "错误: 文件不存在" -ForegroundColor Red
    exit 1
}

# 2. 检查位数
Write-Host "[1] 检查 DLL 位数..." -ForegroundColor Yellow
$fileOutput = & file $DllPath 2>$null
if ($fileOutput -match "PE32\+") {
    Write-Host "  64位 DLL" -ForegroundColor Cyan
} elseif ($fileOutput -match "PE32") {
    Write-Host "  32位 DLL" -ForegroundColor Cyan
} else {
    Write-Host "  无法确定位数" -ForegroundColor Red
}

# 3. 提取导出函数
Write-Host "`n[2] 导出函数列表:" -ForegroundColor Yellow
$exports = & objdump -p $DllPath | Select-String "\["
$exportCount = ($exports | Measure-Object).Count
Write-Host "  共 $exportCount 个导出函数`n" -ForegroundColor Cyan

foreach ($line in $exports) {
    Write-Host "  $line"
}

# 4. 提取字符串
Write-Host "`n[3] 关键字符串:" -ForegroundColor Yellow
$strings = & strings -n 10 $DllPath | Select-String "Start\.\.\.|Error|Failed"
foreach ($str in $strings) {
    Write-Host "  $str" -ForegroundColor Gray
}

Write-Host "`n分析完成!" -ForegroundColor Green
```

---

## 附录 B：参考资料

- **PE 格式文档**: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- **x86 汇编参考**: https://www.felixcloutier.com/x86/
- **x64dbg 文档**: https://help.x64dbg.com/
- **P/Invoke 文档**: https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke

---

**文档版本**: v1.0  
**最后更新**: 2026-08-26  
**作者**: USB Key Manager 开发团队
