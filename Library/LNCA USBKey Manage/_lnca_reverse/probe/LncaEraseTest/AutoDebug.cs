using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace LncaEraseTest;

/// <summary>
/// 自动化调试类 - 无需用户交互，直接执行所有测试
/// 用于 x64dbg 自动附加调试
/// </summary>
public static class AutoDebug
{
    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);
    }

    // HD_HardAPI.dll
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSConnectDev(int devIndex, out IntPtr phDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSDisconnectDev(IntPtr hDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HSErase(IntPtr hDev);
    
    // HDCOS_LNCA.dll
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_ClearDir(IntPtr hDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteCert(IntPtr hDev, int certType);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int HD_DeleteContainer(IntPtr hDev);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int Clear_DF(IntPtr hDev);

    private static T? GetDelegate<T>(IntPtr module, string name) where T : Delegate
    {
        var addr = NativeMethods.GetProcAddress(module, name);
        if (addr == IntPtr.Zero)
        {
            Console.WriteLine($"[!] 未找到导出: {name}");
            return null;
        }
        Console.WriteLine($"[✓] {name} @ 0x{addr:X}");
        return Marshal.GetDelegateForFunctionPointer<T>(addr);
    }

    public static void Run()
    {
        Console.WriteLine("=== 自动化调试模式 ===");
        Console.WriteLine("此模式无需用户交互，适合 x64dbg 自动附加\n");
        
        var baseDir = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
        
        Console.WriteLine($"[1] 设置 DLL 目录: {baseDir}");
        NativeMethods.SetDllDirectory(baseDir);
        
        Console.WriteLine("\n[2] 加载依赖 DLL...");
        var deps = new[] { "GP_IFD_LNCA.dll", "HD_SortDev.dll" };
        foreach (var dep in deps)
        {
            var h = NativeMethods.LoadLibrary($@"{baseDir}\{dep}");
            Console.WriteLine($"    {dep}: {(h == IntPtr.Zero ? "失败" : $"0x{h:X}")}");
        }
        
        Console.WriteLine("\n[3] 加载主要 DLL...");
        var hdcosMod = NativeMethods.LoadLibrary($@"{baseDir}\HDCOS_LNCA.dll");
        var hardMod = NativeMethods.LoadLibrary($@"{baseDir}\HD_HardAPI.dll");
        
        if (hdcosMod == IntPtr.Zero || hardMod == IntPtr.Zero)
        {
            Console.WriteLine("[X] DLL 加载失败");
            return;
        }
        
        Console.WriteLine($"    HDCOS_LNCA.dll: 0x{hdcosMod:X}");
        Console.WriteLine($"    HD_HardAPI.dll: 0x{hardMod:X}");
        
        Console.WriteLine("\n[4] 解析函数...");
        var hsConnect = GetDelegate<HSConnectDev>(hardMod, "HSConnectDev");
        var hsDisconnect = GetDelegate<HSDisconnectDev>(hardMod, "HSDisconnectDev");
        var hsErase = GetDelegate<HSErase>(hardMod, "HSErase");
        
        var hdClearDir = GetDelegate<HD_ClearDir>(hdcosMod, "HD_ClearDir");
        var hdDeleteCert = GetDelegate<HD_DeleteCert>(hdcosMod, "HD_DeleteCert");
        var hdDeleteContainer = GetDelegate<HD_DeleteContainer>(hdcosMod, "HD_DeleteContainer");
        var clearDF = GetDelegate<Clear_DF>(hdcosMod, "Clear_DF");
        
        if (hsConnect == null || hsDisconnect == null)
        {
            Console.WriteLine("[X] 关键函数解析失败");
            return;
        }
        
        Console.WriteLine("\n[5] 等待附加调试器...");
        Console.WriteLine($"    进程 ID: {System.Diagnostics.Process.GetCurrentProcess().Id}");
        Console.WriteLine($"    HD_ClearDir 地址: HDCOS_LNCA.dll+0x67D0");
        Console.WriteLine("    请使用 x64dbg 附加此进程并设置断点");
        Console.WriteLine("    按任意键继续...");
        Console.ReadKey(true);
        
        Console.WriteLine("\n========================================");
        Console.WriteLine("开始执行测试函数");
        Console.WriteLine("========================================\n");
        
        // 连接设备
        Console.WriteLine("【测试 0】连接设备");
        var rc = hsConnect(0, out var hDev);
        Console.WriteLine($"  HSConnectDev(0) = 0x{rc:X}, hDev = 0x{hDev:X}");
        
        if (rc != 0 || hDev == IntPtr.Zero)
        {
            Console.WriteLine("[!] 设备未连接，继续执行其他测试（使用空句柄）\n");
        }
        else
        {
            Console.WriteLine("[✓] 设备已连接\n");
        }
        
        // 测试各个函数
        Console.WriteLine("【测试 1】HD_ClearDir");
        if (hdClearDir != null)
        {
            Console.WriteLine("  准备调用 HD_ClearDir，触发调试器断点...");
            System.Diagnostics.Debugger.Break(); // 触发断点
            
            try
            {
                Console.WriteLine("  调用 HD_ClearDir...");
                rc = hdClearDir(hDev);
                Console.WriteLine($"  HD_ClearDir(0x{hDev:X}) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        Console.WriteLine("【测试 2】HD_DeleteCert (签名证书)");
        if (hdDeleteCert != null)
        {
            Thread.Sleep(500);
            try
            {
                rc = hdDeleteCert(hDev, 0);  // Type 0 = 签名证书
                Console.WriteLine($"  HD_DeleteCert(0x{hDev:X}, 0) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        Console.WriteLine("【测试 3】HD_DeleteCert (加密证书)");
        if (hdDeleteCert != null)
        {
            Thread.Sleep(500);
            try
            {
                rc = hdDeleteCert(hDev, 1);  // Type 1 = 加密证书
                Console.WriteLine($"  HD_DeleteCert(0x{hDev:X}, 1) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        Console.WriteLine("【测试 4】HD_DeleteContainer");
        if (hdDeleteContainer != null)
        {
            Thread.Sleep(500);
            try
            {
                rc = hdDeleteContainer(hDev);
                Console.WriteLine($"  HD_DeleteContainer(0x{hDev:X}) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        Console.WriteLine("【测试 5】Clear_DF");
        if (clearDF != null)
        {
            Thread.Sleep(500);
            try
            {
                rc = clearDF(hDev);
                Console.WriteLine($"  Clear_DF(0x{hDev:X}) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        Console.WriteLine("【测试 6】HSErase (完整擦除)");
        if (hsErase != null && hDev != IntPtr.Zero)
        {
            Thread.Sleep(500);
            try
            {
                rc = hsErase(hDev);
                Console.WriteLine($"  HSErase(0x{hDev:X}) = 0x{rc:X}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  异常: {ex.Message}\n");
            }
        }
        
        // 断开连接
        if (hDev != IntPtr.Zero && hsDisconnect != null)
        {
            Console.WriteLine("【清理】断开设备连接");
            hsDisconnect(hDev);
            Console.WriteLine("  HSDisconnectDev 完成\n");
        }
        
        Console.WriteLine("========================================");
        Console.WriteLine("所有测试完成！");
        Console.WriteLine("========================================");
        
        Console.WriteLine("\n按任意键退出...");
        Console.ReadKey(true);
    }
}
