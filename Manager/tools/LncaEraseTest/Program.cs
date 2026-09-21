using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace LncaEraseTest;

/// <summary>
/// 完整功能验证：擦除 → 设置 PIN → 导入证书 → 签名测试。
/// 用法：LncaEraseTest [devIndex] [newPin] [pfxPath] [pfxPassword]
/// 示例：LncaEraseTest 0 123456 test.pfx 111111
/// </summary>
internal static class Program
{
    private const string LibRoot = @"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
    private const uint DefaultBaudRate = 0x12c;  // 300

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    // ---- HD_HardAPI.dll（擦除层）----
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSConnectDev(int devIndex, out IntPtr phDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSDisconnectDev(IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSErase(IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSVerifyUserPin(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpPin, uint lpPinLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSChangeUserPin(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpOldPin,
        [MarshalAs(UnmanagedType.LPStr)] string lpNewPin);

    // ---- JIT_USBKEY_HD.dll（高层 SDK，用于证书导入/签名）----
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_Connect(uint devIndex, uint baudRate, out IntPtr phKey);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_Disconnect(ref IntPtr phKey);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_VerifyPin(IntPtr hKey, byte flag,
        [MarshalAs(UnmanagedType.LPStr)] string pin, uint pinLen, ref uint retryCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_ImportP12(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string lpP12FileName,
        [MarshalAs(UnmanagedType.LPStr)] string lpPinP12, uint nP12Len);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_RSASign(IntPtr hKey, IntPtr hContainer,
        byte[] pbData, uint dwDataLen, byte[] pbSignature, ref uint pdwSignLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_EnumContainer(IntPtr hKey, uint index,
        StringBuilder containerName, ref uint nameLen);

    private static T? Resolve<T>(IntPtr mod, string name) where T : Delegate
    {
        var p = GetProcAddress(mod, name);
        if (p == IntPtr.Zero) { Console.WriteLine($"  [x] 未找到导出 {name}"); return null; }
        return Marshal.GetDelegateForFunctionPointer<T>(p);
    }

    private static int Main(string[] args)
    {
        // 如果第一个参数是 "testpin"，运行默认 PIN 测试
        if (args.Length > 0 && args[0].Equals("testpin", StringComparison.OrdinalIgnoreCase))
        {
            TestDefaultPin.Run();
            return 0;
        }

        // 如果第一个参数是 "state"，查看设备状态
        if (args.Length > 0 && args[0].Equals("state", StringComparison.OrdinalIgnoreCase))
        {
            TestDeviceState.Run();
            return 0;
        }

        // 如果第一个参数是 "listcert"，列出证书
        if (args.Length > 0 && args[0].Equals("listcert", StringComparison.OrdinalIgnoreCase))
        {
            TestListCertificates.Run();
            return 0;
        }

        // 如果第一个参数是 "debug"，启动 x64dbg 调试模式
        if (args.Length > 0 && args[0].Equals("debug", StringComparison.OrdinalIgnoreCase))
        {
            DebugHDCOS.Run();
            return 0;
        }

        // 如果第一个参数是 "auto"，启动自动化调试模式（无需用户交互）
        if (args.Length > 0 && args[0].Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            AutoDebug.Run();
            return 0;
        }

        // 如果第一个参数是 "fullerase"，完整擦除测试
        if (args.Length > 0 && args[0].Equals("fullerase", StringComparison.OrdinalIgnoreCase))
        {
            TestCompleteErase.Run();
            return 0;
        }

        Console.WriteLine("=== LNCA 完整功能验证：擦除 → 导入证书 → 签名 ===\n");

        int devIndex = args.Length > 0 ? int.Parse(args[0]) : 0;
        string newPin = args.Length > 1 ? args[1] : "123456";
        string? pfxPath = args.Length > 2 ? args[2] : null;
        string? pfxPass = args.Length > 3 ? args[3] : null;

        Console.WriteLine($"参数：devIndex={devIndex}, newPin={newPin}, pfxPath={pfxPath ?? "(未指定)"}");
        Console.WriteLine($"库目录: {LibRoot}\n");

        if (!Directory.Exists(LibRoot))
        {
            Console.WriteLine("[x] 库目录不存在");
            return 2;
        }

        SetDllDirectory(LibRoot);

        // 加载依赖
        foreach (var dep in new[] { "GP_IFD_LNCA.dll", "HDCOS_LNCA.dll", "HD_SortDev.dll" })
        {
            var h = LoadLibrary(Path.Combine(LibRoot, dep));
            Console.WriteLine($"加载 {dep}: {(h == IntPtr.Zero ? "失败" : "OK")}");
        }

        var hardMod = LoadLibrary(Path.Combine(LibRoot, "HD_HardAPI.dll"));
        var jitMod = LoadLibrary(Path.Combine(LibRoot, "JIT_USBKEY_HD.dll"));
        if (hardMod == IntPtr.Zero || jitMod == IntPtr.Zero)
        {
            Console.WriteLine($"[x] DLL 加载失败");
            return 3;
        }

        // 解析 HD_HardAPI 导出
        var hsConnect = Resolve<HSConnectDev>(hardMod, "HSConnectDev");
        var hsDisconnect = Resolve<HSDisconnectDev>(hardMod, "HSDisconnectDev");
        var hsErase = Resolve<HSErase>(hardMod, "HSErase");
        var hsChangePin = Resolve<HSChangeUserPin>(hardMod, "HSChangeUserPin");
        var hsVerifyPin = Resolve<HSVerifyUserPin>(hardMod, "HSVerifyUserPin");

        // 解析 JIT_USBKEY_HD 导出
        var jitConnect = Resolve<USBKey_Connect>(jitMod, "USBKey_Connect");
        var jitDisconnect = Resolve<USBKey_Disconnect>(jitMod, "USBKey_Disconnect");
        var jitVerifyPin = Resolve<USBKey_VerifyPin>(jitMod, "USBKey_VerifyPin");
        var jitImportP12 = Resolve<USBKey_ImportP12>(jitMod, "USBKey_ImportP12");
        var jitEnumContainer = Resolve<USBKey_EnumContainer>(jitMod, "USBKey_EnumContainer");
        var jitSign = Resolve<USBKey_RSASign>(jitMod, "USBKey_RSASign");

        if (hsConnect == null || hsErase == null || jitConnect == null)
        {
            Console.WriteLine("[x] 关键导出缺失");
            return 4;
        }

        // ==== 第一步：擦除设备 ====
        Console.WriteLine("\n【第一步：擦除设备】");
        int rc = hsConnect(devIndex, out var hDev);
        Console.WriteLine($"  HSConnectDev rc=0x{rc:X} hDev=0x{hDev.ToInt64():X}");
        if (rc != 0 || hDev == IntPtr.Zero)
        {
            Console.WriteLine($"[x] 连接失败，请确认设备已插入");
            return 5;
        }

        try
        {
            rc = hsErase(hDev);
            Console.WriteLine($"  HSErase rc=0x{rc:X} {(rc == 0 ? "✓" : "✗")}");
            if (rc != 0) return 6;

            // 擦除后设置初始 PIN
            if (hsChangePin != null)
            {
                rc = hsChangePin(hDev, string.Empty, newPin);
                Console.WriteLine($"  HSChangeUserPin(空 → '{newPin}') rc=0x{rc:X} {(rc == 0 ? "✓" : "✗")}");
                if (rc != 0)
                {
                    Console.WriteLine($"  [!] 改 PIN 失败，尝试用默认 PIN '111111' 改为新 PIN");
                    rc = hsChangePin(hDev, "111111", newPin);
                    Console.WriteLine($"  HSChangeUserPin('111111' → '{newPin}') rc=0x{rc:X} {(rc == 0 ? "✓" : "✗")}");
                }
            }
        }
        finally
        {
            hsDisconnect?.Invoke(hDev);
        }

        // ==== 第二步：导入证书 ====
        if (!string.IsNullOrEmpty(pfxPath) && File.Exists(pfxPath) && !string.IsNullOrEmpty(pfxPass))
        {
            Console.WriteLine($"\n【第二步：导入证书 {pfxPath}】");
            rc = jitConnect((uint)devIndex, DefaultBaudRate, out var hKey);
            Console.WriteLine($"  USBKey_Connect rc=0x{rc:X} hKey=0x{hKey.ToInt64():X}");
            if (rc != 0 || hKey == IntPtr.Zero) return 7;

            try
            {
                // 先验证 PIN
                uint retry = 0;
                rc = jitVerifyPin(hKey, 0, newPin, (uint)newPin.Length, ref retry);
                Console.WriteLine($"  USBKey_VerifyPin rc=0x{rc:X} {(rc == 0 ? "✓" : $"✗ (剩余重试 {retry})")}");
                if (rc != 0) return 8;

                // 导入 PFX
                rc = jitImportP12(hKey, pfxPath, pfxPass, (uint)pfxPass.Length);
                Console.WriteLine($"  USBKey_ImportP12 rc=0x{rc:X} {(rc == 0 ? "✓ 导入成功" : "✗ 导入失败")}");
                if (rc != 0) return 9;

                // 枚举容器
                Console.WriteLine("\n【第三步：枚举容器】");
                for (uint i = 0; i < 8; i++)
                {
                    var sb = new StringBuilder(256);
                    uint len = 256;
                    rc = jitEnumContainer(hKey, i, sb, ref len);
                    if (rc == 0 && sb.Length > 0)
                        Console.WriteLine($"  容器 {i}: {sb}");
                    else if (rc != 0)
                        break;
                }

                // 签名测试
                Console.WriteLine("\n【第四步：签名测试】");
                byte[] testData = Encoding.UTF8.GetBytes("LNCA Erase Test Signature");
                byte[] signature = new byte[256];
                uint sigLen = 256;
                rc = jitSign(hKey, IntPtr.Zero, testData, (uint)testData.Length, signature, ref sigLen);
                Console.WriteLine($"  USBKey_RSASign rc=0x{rc:X} sigLen={sigLen} {(rc == 0 ? "✓ 签名成功" : "✗")}");
                if (rc == 0 && sigLen > 0)
                {
                    Console.WriteLine($"  签名(前16字节): {BitConverter.ToString(signature, 0, Math.Min(16, (int)sigLen))}");
                }
            }
            finally
            {
                var h = hKey;
                jitDisconnect?.Invoke(ref h);
            }
        }
        else
        {
            Console.WriteLine("\n[i] 未指定 PFX，跳过证书导入与签名测试");
        }

        Console.WriteLine("\n=== 验证完成 ===");
        return 0;
    }
}
