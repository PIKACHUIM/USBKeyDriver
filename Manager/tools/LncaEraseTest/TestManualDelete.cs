using System;
using System.Runtime.InteropServices;

namespace LncaEraseTest;

/// <summary>
/// 测试手动删除证书（通过 HDCOS_LNCA.dll 的 HD_DeleteCert）
/// </summary>
internal static class TestManualDelete
{
    private const string LibRoot = @"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern bool SetDllDirectory(string lpPathName);

    // HD_DeleteCert 签名待确认（从反汇编看，参数是两个字符串指针）
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]  // HDCOS 可能是 cdecl
    private delegate int HD_DeleteCert_Fn(
        [MarshalAs(UnmanagedType.LPStr)] string param1,
        [MarshalAs(UnmanagedType.LPStr)] string param2);

    public static void Run()
    {
        Console.WriteLine("=== 测试手动删除证书 ===\n");
        Console.WriteLine("[!] 此功能需要进一步逆向确认 HD_DeleteCert 的精确签名");
        Console.WriteLine("[!] 当前仅作探索性测试\n");

        SetDllDirectory(LibRoot);
        
        // 加载依赖链
        LoadLibrary(System.IO.Path.Combine(LibRoot, "GP_IFD_LNCA.dll"));
        LoadLibrary(System.IO.Path.Combine(LibRoot, "HDCOS_LNCA.dll"));
        
        var hdcosMod = LoadLibrary(System.IO.Path.Combine(LibRoot, "HDCOS_LNCA.dll"));
        if (hdcosMod == IntPtr.Zero)
        {
            Console.WriteLine("[x] HDCOS_LNCA.dll 加载失败");
            return;
        }

        var ptr = GetProcAddress(hdcosMod, "HD_DeleteCert");
        if (ptr == IntPtr.Zero)
        {
            Console.WriteLine("[x] HD_DeleteCert 导出不存在");
            return;
        }

        Console.WriteLine($"[+] HD_DeleteCert 找到，地址=0x{ptr.ToInt64():X}");
        Console.WriteLine("[!] 需要先确认参数含义和调用方式");
        Console.WriteLine("[!] 建议：先用 x64dbg 动态调试，观察其他代码如何调用此函数");
    }
}
