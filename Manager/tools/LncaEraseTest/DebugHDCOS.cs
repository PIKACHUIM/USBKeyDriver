using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace LncaEraseTest;

/// <summary>
/// 专门用于 x64dbg 动态调试 HDCOS_LNCA.dll 函数的测试类
/// </summary>
public static class DebugHDCOS
{
    // Native methods
    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
    // HD_HardAPI.dll
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSConnectDev(int devIndex, out IntPtr phDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSDisconnectDev(IntPtr hDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSErase(IntPtr hDev);
    
    // HDCOS_LNCA.dll - 各种删除函数（参数待确认）
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_ClearDir_NoParam();
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_ClearDir_1Param(IntPtr p1);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_ClearDir_2Params(IntPtr p1, IntPtr p2);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteCert_1Param(IntPtr p1);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteCert_2Params(IntPtr p1, int p2);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteContainer_NoParam();
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteContainer_1Param(IntPtr p1);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int Clear_DF_NoParam();
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int Clear_DF_1Param(IntPtr p1);

    private static T? GetDelegate<T>(IntPtr module, string name) where T : Delegate
    {
        var addr = NativeMethods.GetProcAddress(module, name);
        return addr == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(addr);
    }

    public static void Run()
    {
        Console.WriteLine("=== x64dbg 动态调试准备 ===\n");
        Console.WriteLine("📌 建议操作：");
        Console.WriteLine("   1. 用 x64dbg 附加到本进程");
        Console.WriteLine("   2. 在以下地址下断点：");
        Console.WriteLine("      - HDCOS_LNCA.HD_ClearDir");
        Console.WriteLine("      - HDCOS_LNCA.HD_DeleteCert");
        Console.WriteLine("      - HDCOS_LNCA.HD_DeleteContainer");
        Console.WriteLine("      - HDCOS_LNCA.Clear_DF");
        Console.WriteLine("   3. 按任意键继续，程序会依次调用这些函数");
        Console.WriteLine("   4. 在 x64dbg 中观察参数和返回值\n");
        
        var baseDir = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
        
        var hardMod = NativeMethods.LoadLibrary($@"{baseDir}\HD_HardAPI.dll");
        var hdcosMod = NativeMethods.LoadLibrary($@"{baseDir}\HDCOS_LNCA.dll");
        
        if (hardMod == IntPtr.Zero || hdcosMod == IntPtr.Zero)
        {
            Console.WriteLine("❌ DLL 加载失败");
            return;
        }
        
        var hsConnect = GetDelegate<HSConnectDev>(hardMod, "HSConnectDev");
        var hsDisconnect = GetDelegate<HSDisconnectDev>(hardMod, "HSDisconnectDev");
        var hsErase = GetDelegate<HSErase>(hardMod, "HSErase");
        
        if (hsConnect == null || hsDisconnect == null)
        {
            Console.WriteLine("❌ 函数解析失败");
            return;
        }
        
        Console.WriteLine("✓ DLL 加载成功");
        Console.WriteLine("\n等待 x64dbg 附加...");
        Console.WriteLine("附加后按任意键继续...");
        Console.ReadKey(true);
        
        // 连接设备
        Console.WriteLine("\n【步骤 1】连接设备...");
        var rc = hsConnect(0, out var hDev);
        Console.WriteLine($"  HSConnectDev(0): rc=0x{rc:X}, hDev=0x{hDev:X}");
        
        if (rc != 0 || hDev == IntPtr.Zero)
        {
            Console.WriteLine("❌ 连接失败");
            return;
        }
        
        // 暂停，让用户在 x64dbg 中下断点
        Console.WriteLine("\n【准备就绪】设备已连接，句柄=0x{0:X}", hDev);
        Console.WriteLine("现在可以在 x64dbg 中下断点了。");
        Console.WriteLine("按任意键开始调用测试函数...\n");
        Console.ReadKey(true);
        
        // 测试 1: HD_ClearDir（尝试不同参数）
        Console.WriteLine("=== 测试 1: HD_ClearDir ===");
        
        Console.WriteLine("\n[1.1] HD_ClearDir() 无参数");
        Console.WriteLine("即将调用，x64dbg 应该断在函数入口...");
        Thread.Sleep(500);
        var clearDir0 = GetDelegate<HD_ClearDir_NoParam>(hdcosMod, "HD_ClearDir");
        if (clearDir0 != null)
        {
            try
            {
                rc = clearDir0();
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        Console.WriteLine("\n[1.2] HD_ClearDir(hDev) 传设备句柄");
        Console.WriteLine("即将调用，观察参数...");
        Thread.Sleep(500);
        var clearDir1 = GetDelegate<HD_ClearDir_1Param>(hdcosMod, "HD_ClearDir");
        if (clearDir1 != null)
        {
            try
            {
                rc = clearDir1(hDev);
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        // 测试 2: HD_DeleteCert
        Console.WriteLine("\n=== 测试 2: HD_DeleteCert ===");
        
        Console.WriteLine("\n[2.1] HD_DeleteCert(hDev)");
        Thread.Sleep(500);
        var delCert1 = GetDelegate<HD_DeleteCert_1Param>(hdcosMod, "HD_DeleteCert");
        if (delCert1 != null)
        {
            try
            {
                rc = delCert1(hDev);
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        Console.WriteLine("\n[2.2] HD_DeleteCert(hDev, 1) 尝试删除加密证书");
        Thread.Sleep(500);
        var delCert2 = GetDelegate<HD_DeleteCert_2Params>(hdcosMod, "HD_DeleteCert");
        if (delCert2 != null)
        {
            try
            {
                rc = delCert2(hDev, 1);  // Type=1 是加密证书
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        // 测试 3: HD_DeleteContainer
        Console.WriteLine("\n=== 测试 3: HD_DeleteContainer ===");
        
        Console.WriteLine("\n[3.1] HD_DeleteContainer() 无参数");
        Thread.Sleep(500);
        var delCont0 = GetDelegate<HD_DeleteContainer_NoParam>(hdcosMod, "HD_DeleteContainer");
        if (delCont0 != null)
        {
            try
            {
                rc = delCont0();
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        Console.WriteLine("\n[3.2] HD_DeleteContainer(hDev)");
        Thread.Sleep(500);
        var delCont1 = GetDelegate<HD_DeleteContainer_1Param>(hdcosMod, "HD_DeleteContainer");
        if (delCont1 != null)
        {
            try
            {
                rc = delCont1(hDev);
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        // 测试 4: Clear_DF
        Console.WriteLine("\n=== 测试 4: Clear_DF ===");
        
        Console.WriteLine("\n[4.1] Clear_DF() 无参数");
        Thread.Sleep(500);
        var clearDF0 = GetDelegate<Clear_DF_NoParam>(hdcosMod, "Clear_DF");
        if (clearDF0 != null)
        {
            try
            {
                rc = clearDF0();
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        Console.WriteLine("\n[4.2] Clear_DF(hDev)");
        Thread.Sleep(500);
        var clearDF1 = GetDelegate<Clear_DF_1Param>(hdcosMod, "Clear_DF");
        if (clearDF1 != null)
        {
            try
            {
                rc = clearDF1(hDev);
                Console.WriteLine($"  返回: 0x{rc:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}");
            }
        }
        
        // 最后检查证书
        Console.WriteLine("\n=== 最终检查 ===");
        Console.WriteLine("调用 TestListCertificates 查看证书是否被删除...\n");
        TestListCertificates.Run();
        
        // 断开连接
        hsDisconnect(hDev);
        Console.WriteLine("\n✓ 测试完成");
    }
}
