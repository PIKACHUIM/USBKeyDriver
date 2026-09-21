using System;
using System.Runtime.InteropServices;

namespace LncaEraseTest;

/// <summary>
/// 测试 LNCA 擦除后的默认 PIN（通过 JIT_USBKEY_HD.dll 的 VerifyPin）
/// </summary>
internal static class TestDefaultPin
{
    private const string LibRoot = @"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
    private const uint DefaultBaudRate = 0x12c;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern bool SetDllDirectory(string lpPathName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_Connect(uint devIndex, uint baudRate, out IntPtr phKey);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_Disconnect(ref IntPtr phKey);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_VerifyPin(IntPtr hKey, byte flag,
        [MarshalAs(UnmanagedType.LPStr)] string pin, uint pinLen, ref uint retryCount);

    public static void Run()
    {
        Console.WriteLine("=== 测试 LNCA 擦除后的默认 PIN ===\n");

        SetDllDirectory(LibRoot);
        var jitMod = LoadLibrary(System.IO.Path.Combine(LibRoot, "JIT_USBKEY_HD.dll"));
        if (jitMod == IntPtr.Zero)
        {
            Console.WriteLine("[x] JIT_USBKEY_HD.dll 加载失败");
            return;
        }

        var connect = Marshal.GetDelegateForFunctionPointer<USBKey_Connect>(
            GetProcAddress(jitMod, "USBKey_Connect"));
        var disconnect = Marshal.GetDelegateForFunctionPointer<USBKey_Disconnect>(
            GetProcAddress(jitMod, "USBKey_Disconnect"));
        var verifyPin = Marshal.GetDelegateForFunctionPointer<USBKey_VerifyPin>(
            GetProcAddress(jitMod, "USBKey_VerifyPin"));

        var rc = connect(0, DefaultBaudRate, out var hKey);
        Console.WriteLine($"USBKey_Connect: rc=0x{rc:X} hKey=0x{hKey.ToInt64():X}");
        if (rc != 0 || hKey == IntPtr.Zero)
        {
            Console.WriteLine("[x] 连接失败");
            return;
        }

        try
        {
            // 常见默认 PIN 列表
            string[] candidates = {
                "",           // 空
                "111111",     // 常见默认
                "123456",     // 常见默认
                "000000",     // 常见默认
                "888888",     // 常见默认
                "12345678",   // 8 位默认
                "00000000",   // 8 位默认
                "11111111",   // 8 位默认
                "FFFFFFFF",   // 厂商特殊
                "LNCA2024",   // 厂商年份
            };

            Console.WriteLine("\n尝试常见默认 PIN：\n");
            foreach (var pin in candidates)
            {
                uint retry = 0;
                rc = verifyPin(hKey, 0, pin, (uint)pin.Length, ref retry);
                var result = rc == 0 ? "✓ 成功" : $"✗ (rc=0x{rc:X}, 剩余重试{retry})";
                Console.WriteLine($"  PIN='{pin}' (长度{pin.Length}) → {result}");
                
                if (rc == 0)
                {
                    Console.WriteLine($"\n【找到默认 PIN】: '{pin}'");
                    return;
                }
            }

            Console.WriteLine("\n[!] 未找到默认 PIN，设备可能需要特殊初始化流程");
        }
        finally
        {
            var h = hKey;
            disconnect(ref h);
        }
    }
}
