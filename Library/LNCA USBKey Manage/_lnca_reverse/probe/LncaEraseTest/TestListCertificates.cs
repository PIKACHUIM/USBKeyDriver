using System;
using System.Runtime.InteropServices;

namespace LncaEraseTest;

/// <summary>
/// 列出 LNCA 设备上的证书（验证擦除是否成功）
/// </summary>
internal static class TestListCertificates
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
    private delegate int USBKey_ReadCert(IntPtr hKey, uint certType,
        [In, Out] byte[] certData, ref uint certLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_VerifyPin(IntPtr hKey, byte flag,
        [MarshalAs(UnmanagedType.LPStr)] string pin, uint pinLen, ref uint retryCount);

    private static T? GetDelegate<T>(IntPtr mod, string name) where T : Delegate
    {
        var ptr = GetProcAddress(mod, name);
        return ptr == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(ptr);
    }

    public static void Run(string? pin = null)
    {
        Console.WriteLine("=== 列出 LNCA 设备证书（验证擦除）===\n");

        SetDllDirectory(LibRoot);
        var jitMod = LoadLibrary(System.IO.Path.Combine(LibRoot, "JIT_USBKEY_HD.dll"));
        if (jitMod == IntPtr.Zero)
        {
            Console.WriteLine("[x] JIT_USBKEY_HD.dll 加载失败");
            return;
        }

        var connect = GetDelegate<USBKey_Connect>(jitMod, "USBKey_Connect");
        var disconnect = GetDelegate<USBKey_Disconnect>(jitMod, "USBKey_Disconnect");
        var readCert = GetDelegate<USBKey_ReadCert>(jitMod, "USBKey_ReadCert");
        var verifyPin = GetDelegate<USBKey_VerifyPin>(jitMod, "USBKey_VerifyPin");

        if (connect == null || disconnect == null || readCert == null)
        {
            Console.WriteLine("[x] 关键函数导出缺失");
            return;
        }

        var rc = connect(0, DefaultBaudRate, out var hKey);
        Console.WriteLine($"USBKey_Connect: rc=0x{rc:X} hKey=0x{hKey.ToInt64():X}");
        if (rc != 0 || hKey == IntPtr.Zero)
        {
            Console.WriteLine("[x] 连接失败");
            return;
        }

        try
        {
            // 如果提供了 PIN，先验证
            if (!string.IsNullOrEmpty(pin) && verifyPin != null)
            {
                uint retry = 0;
                rc = verifyPin(hKey, 0, pin, (uint)pin.Length, ref retry);
                Console.WriteLine($"USBKey_VerifyPin('{pin}'): rc=0x{rc:X} {(rc == 0 ? "✓" : $"✗ (剩余重试{retry})")}\n");
            }

            // 尝试读取证书（type 0=签名证书, 1=加密证书）
            Console.WriteLine("枚举证书（USBKey_ReadCert）：\n");
            int totalFound = 0;
            
            for (uint type = 0; type <= 1; type++)
            {
                byte[] certBuf = new byte[8192];
                uint certLen = (uint)certBuf.Length;
                rc = readCert(hKey, type, certBuf, ref certLen);
                
                if (rc == 0 && certLen > 0)
                {
                    totalFound++;
                    string typeName = type == 0 ? "签名证书" : "加密证书";
                    Console.WriteLine($"  [Type={type} ({typeName})] 长度={certLen} 字节");
                    var hex = BitConverter.ToString(certBuf, 0, Math.Min(32, (int)certLen));
                    Console.WriteLine($"    头部: {hex}");
                }
                else
                {
                    string typeName = type == 0 ? "签名证书" : "加密证书";
                    Console.WriteLine($"  [Type={type} ({typeName})] rc=0x{rc:X}（不存在）");
                }
            }

            Console.WriteLine($"\n{(totalFound == 0 ? "✓ 设备已擦除（无证书）" : $"✗ 设备未擦除（仍有 {totalFound} 个证书）")}");
        }
        finally
        {
            var h = hKey;
            disconnect(ref h);
        }
    }
}
