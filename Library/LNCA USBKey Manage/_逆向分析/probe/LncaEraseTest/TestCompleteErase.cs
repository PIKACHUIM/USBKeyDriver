using System;
using System.Runtime.InteropServices;

namespace LncaEraseTest;

/// <summary>
/// 完整测试 LNCA 擦除链路：HSErase + HDCOS 各删除函数组合
/// </summary>
internal static class TestCompleteErase
{
    private const string LibRoot = @"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern bool SetDllDirectory(string lpPathName);

    // HD_HardAPI.dll
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSConnectDev(int devIndex, out IntPtr phDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSDisconnectDev(IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSErase(IntPtr hDev);

    // HDCOS_LNCA.dll — 需要通过反汇编确认签名
    // HD_ClearDir (ord 31, RVA 0x67D0): 从反汇编看参数复杂，先尝试简单签名
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int HD_ClearDir_1param(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int HD_ClearDir_2param(IntPtr handle, int param2);

    // HD_DeleteCert (ord 47, RVA 0x7210): 从反汇编看接受两个字符串参数
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int HD_DeleteCert(
        [MarshalAs(UnmanagedType.LPStr)] string path1,
        [MarshalAs(UnmanagedType.LPStr)] string path2);

    // HD_DeleteContainer (ord 30, RVA 0x6A10): 从反汇编看第一个参数是 [esp+4]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int HD_DeleteContainer(IntPtr container_or_index);

    // Clear_DF (ord 23, RVA 0x19C0): 从反汇编看参数在 [esp+0x224]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int Clear_DF(IntPtr handle, int param2);

    private static T? GetDelegate<T>(IntPtr mod, string name) where T : Delegate
    {
        var ptr = GetProcAddress(mod, name);
        return ptr == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(ptr);
    }

    public static void Run()
    {
        Console.WriteLine("=== 完整测试 LNCA 擦除链路 ===\n");

        SetDllDirectory(LibRoot);

        // 加载依赖链
        foreach (var dep in new[] { "GP_IFD_LNCA.dll", "HDCOS_LNCA.dll", "HD_SortDev.dll" })
        {
            var h = LoadLibrary(System.IO.Path.Combine(LibRoot, dep));
            Console.WriteLine($"加载 {dep}: {(h == IntPtr.Zero ? "失败" : "OK")}");
        }

        var hardMod = LoadLibrary(System.IO.Path.Combine(LibRoot, "HD_HardAPI.dll"));
        var hdcosMod = LoadLibrary(System.IO.Path.Combine(LibRoot, "HDCOS_LNCA.dll"));

        if (hardMod == IntPtr.Zero || hdcosMod == IntPtr.Zero)
        {
            Console.WriteLine("[x] 关键 DLL 加载失败");
            return;
        }

        // 解析 HD_HardAPI.dll 导出
        var hsConnect = GetDelegate<HSConnectDev>(hardMod, "HSConnectDev");
        var hsDisconnect = GetDelegate<HSDisconnectDev>(hardMod, "HSDisconnectDev");
        var hsErase = GetDelegate<HSErase>(hardMod, "HSErase");

        // 解析 HDCOS_LNCA.dll 导出（按名字）
        var hdClearDir = GetDelegate<HD_ClearDir_1param>(hdcosMod, "HD_ClearDir");
        var hdDeleteCert = GetDelegate<HD_DeleteCert>(hdcosMod, "HD_DeleteCert");
        var hdDeleteContainer = GetDelegate<HD_DeleteContainer>(hdcosMod, "HD_DeleteContainer");
        var clearDF = GetDelegate<Clear_DF>(hdcosMod, "Clear_DF");

        Console.WriteLine($"\nHD_HardAPI 导出解析：");
        Console.WriteLine($"  HSConnectDev: {(hsConnect != null ? "✓" : "✗")}");
        Console.WriteLine($"  HSErase: {(hsErase != null ? "✓" : "✗")}");

        Console.WriteLine($"\nHDCOS_LNCA 导出解析（按名字）：");
        Console.WriteLine($"  HD_ClearDir: {(hdClearDir != null ? "✓" : "✗")}");
        Console.WriteLine($"  HD_DeleteCert: {(hdDeleteCert != null ? "✓" : "✗")}");
        Console.WriteLine($"  HD_DeleteContainer: {(hdDeleteContainer != null ? "✓" : "✗")}");
        Console.WriteLine($"  Clear_DF: {(clearDF != null ? "✓" : "✗")}");

        if (hsConnect == null || hsErase == null || hsDisconnect == null)
        {
            Console.WriteLine("\n[x] HD_HardAPI 关键导出缺失");
            return;
        }

        // 连接设备
        Console.WriteLine($"\n【步骤 1】连接设备...");
        var rc = hsConnect(0, out var hDev);
        Console.WriteLine($"  HSConnectDev: rc=0x{rc:X} hDev=0x{hDev.ToInt64():X}");
        if (rc != 0 || hDev == IntPtr.Zero)
        {
            Console.WriteLine("[x] 连接失败");
            return;
        }

        try
        {
            // 检查擦除前的证书
            Console.WriteLine($"\n【步骤 2】擦除前检查证书...");
            TestListCertificates.Run();

            // 执行 HSErase
            Console.WriteLine($"\n【步骤 3】执行 HSErase...");
            rc = hsErase(hDev);
            Console.WriteLine($"  HSErase: rc=0x{rc:X} {(rc == 0 ? "✓" : "✗")}");

            // 检查 HSErase 后的证书
            Console.WriteLine($"\n【步骤 4】HSErase 后检查证书...");
            TestListCertificates.Run();

            // 尝试 HD_DeleteContainer（可能需要参数，先尝试空指针）
            if (hdDeleteContainer != null)
            {
                Console.WriteLine($"\n【步骤 5】尝试 HD_DeleteContainer...");
                try
                {
                    rc = hdDeleteContainer(IntPtr.Zero);
                    Console.WriteLine($"  HD_DeleteContainer(0): rc=0x{rc:X}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  HD_DeleteContainer 调用失败: {ex.Message}");
                }
            }

            // 尝试 HD_ClearDir（参数未知，先尝试只传句柄）
            if (hdClearDir != null)
            {
                Console.WriteLine($"\n【步骤 6】尝试 HD_ClearDir...");
                try
                {
                    rc = hdClearDir(hDev);
                    Console.WriteLine($"  HD_ClearDir(hDev): rc=0x{rc:X}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  HD_ClearDir 调用失败: {ex.Message}");
                }
            }

            // 最终检查证书
            Console.WriteLine($"\n【步骤 7】最终检查证书...");
            TestListCertificates.Run();
        }
        finally
        {
            Console.WriteLine($"\n【步骤 8】断开设备...");
            hsDisconnect(hDev);
        }

        Console.WriteLine("\n=== 测试完成 ===");
        Console.WriteLine("\n[提示] 如果证书仍存在，需要用 x64dbg 动态调试找到正确的删除流程。");
    }
}
