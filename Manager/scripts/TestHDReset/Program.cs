using System;
using System.Runtime.InteropServices;

class TestHDReset
{
    // 测试 HD_Reset (来自 GP_COS_LNCA.dll 或 GP_IFD_LNCA.dll)
    
    [DllImport("GP_IFD_LNCA.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int HD_Reset(IntPtr hDev);
    
    [DllImport("GP_IFD_LNCA.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int HD_FindDevice(out int pNum);
    
    [DllImport("GP_IFD_LNCA.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int HD_OpenDevice(int nDevIdx, out IntPtr phDev);
    
    static void Main()
    {
        Console.WriteLine("测试 HD_Reset 函数...\n");
        
        // 1. 查找设备
        int num = 0;
        int rc = HD_FindDevice(out num);
        Console.WriteLine($"HD_FindDevice: rc=0x{rc:X}, num={num}");
        
        if (rc != 0 || num == 0)
        {
            Console.WriteLine("没有设备");
            Console.ReadKey();
            return;
        }
        
        // 2. 打开设备
        IntPtr hDev = IntPtr.Zero;
        rc = HD_OpenDevice(0, out hDev);
        Console.WriteLine($"HD_OpenDevice: rc=0x{rc:X}, hDev=0x{hDev.ToInt32():X}");
        
        if (rc != 0)
        {
            Console.WriteLine("打开设备失败");
            Console.ReadKey();
            return;
        }
        
        // 3. 调用 HD_Reset
        Console.WriteLine("\n调用 HD_Reset...");
        try
        {
            rc = HD_Reset(hDev);
            Console.WriteLine($"HD_Reset 返回: 0x{rc:X}");
            
            if (rc == 0)
            {
                Console.WriteLine("✓ 重置成功！");
            }
            else
            {
                Console.WriteLine($"✗ 重置失败，错误码: 0x{rc:X}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"异常: {ex.Message}");
        }
        
        Console.WriteLine("\n按任意键退出...");
        Console.ReadKey();
    }
}
