using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LncaEraseTest;

/// <summary>
/// 查看 LNCA 设备状态（GetDevState / GetKeySN）
/// </summary>
internal static class TestDeviceState
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
    private delegate int USBKey_GetDevState(IntPtr hKey, out uint state);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_GetKeySN(IntPtr hKey, StringBuilder sn, ref uint snLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int USBKey_InitKey(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string userPin, uint userPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string operPin, uint operPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string unlockPin, uint unlockPinLen);

    public static void Run()
    {
        Console.WriteLine("=== 查看 LNCA 设备状态 ===\n");

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
        var getDevState = Marshal.GetDelegateForFunctionPointer<USBKey_GetDevState>(
            GetProcAddress(jitMod, "USBKey_GetDevState"));
        var getKeySN = Marshal.GetDelegateForFunctionPointer<USBKey_GetKeySN>(
            GetProcAddress(jitMod, "USBKey_GetKeySN"));
        var initKey = Marshal.GetDelegateForFunctionPointer<USBKey_InitKey>(
            GetProcAddress(jitMod, "USBKey_InitKey"));

        var rc = connect(0, DefaultBaudRate, out var hKey);
        Console.WriteLine($"USBKey_Connect: rc=0x{rc:X} hKey=0x{hKey.ToInt64():X}");
        if (rc != 0 || hKey == IntPtr.Zero)
        {
            Console.WriteLine("[x] 连接失败");
            return;
        }

        try
        {
            // 读取设备状态
            rc = getDevState(hKey, out var state);
            Console.WriteLine($"USBKey_GetDevState: rc=0x{rc:X} state=0x{state:X}");

            // 读取序列号
            var sb = new StringBuilder(64);
            uint snLen = 64;
            rc = getKeySN(hKey, sb, ref snLen);
            Console.WriteLine($"USBKey_GetKeySN: rc=0x{rc:X} SN='{sb}'");

            // 尝试用 JIT 层的 InitKey 初始化（这是空壳，但可能触发状态变化）
            Console.WriteLine("\n尝试调用 USBKey_InitKey（空壳函数）...");
            rc = initKey(hKey, "123456", 6, "admin123", 8, "unlock88", 8);
            Console.WriteLine($"USBKey_InitKey: rc=0x{rc:X}");

            // 再次读取状态
            rc = getDevState(hKey, out state);
            Console.WriteLine($"再次 GetDevState: rc=0x{rc:X} state=0x{state:X}");
        }
        finally
        {
            var h = hKey;
            disconnect(ref h);
        }
    }
}
