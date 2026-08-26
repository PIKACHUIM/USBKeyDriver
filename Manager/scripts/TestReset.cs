using System;
using System.Runtime.InteropServices;
using System.Text;

class TestReset
{
    // 测试不同的函数签名
    
    // 签名1: byte[]
    [DllImport("JIT_USBKEY_HD.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_Reset_V1(IntPtr hKey, byte[] rData, uint rLen);
    
    // 签名2: IntPtr
    [DllImport("JIT_USBKEY_HD.dll", EntryPoint = "USBKey_Reset", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_Reset_V2(IntPtr hKey, IntPtr rData, uint rLen);
    
    // 签名3: Cdecl
    [DllImport("JIT_USBKEY_HD.dll", EntryPoint = "USBKey_Reset", CallingConvention = CallingConvention.Cdecl)]
    static extern int USBKey_Reset_V3(IntPtr hKey, IntPtr rData, uint rLen);
    
    // 辅助函数
    [DllImport("JIT_USBKEY_HD.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_ListKey(out uint count);
    
    [DllImport("JIT_USBKEY_HD.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int USBKey_Connect(uint index, out IntPtr hKey);
    
    static void Main()
    {
        Console.WriteLine("测试 USBKey_Reset 的正确调用方式...\n");
        
        // 1. 枚举设备
        uint count = 0;
        int rc = USBKey_ListKey(out count);
        Console.WriteLine($"ListKey: rc=0x{rc:X}, count={count}");
        
        if (rc != 0 || count == 0)
        {
            Console.WriteLine("没有设备");
            return;
        }
        
        // 2. 连接设备
        IntPtr hKey = IntPtr.Zero;
        rc = USBKey_Connect(0, out hKey);
        Console.WriteLine($"Connect: rc=0x{rc:X}, hKey=0x{hKey.ToInt32():X}");
        
        if (rc != 0)
        {
            Console.WriteLine("连接失败");
            return;
        }
        
        // 3. 测试不同的 Reset 签名
        Console.WriteLine("\n测试签名1 (byte[]):");
        try
        {
            var buf1 = new byte[256];
            rc = USBKey_Reset_V1(hKey, buf1, (uint)buf1.Length);
            Console.WriteLine($"  返回: 0x{rc:X}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  异常: {ex.Message}");
        }
        
        Console.WriteLine("\n测试签名2 (IntPtr, StdCall):");
        try
        {
            var buf2 = new byte[256];
            var handle = GCHandle.Alloc(buf2, GCHandleType.Pinned);
            rc = USBKey_Reset_V2(hKey, handle.AddrOfPinnedObject(), (uint)buf2.Length);
            handle.Free();
            Console.WriteLine($"  返回: 0x{rc:X}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  异常: {ex.Message}");
        }
        
        Console.WriteLine("\n测试签名3 (IntPtr, Cdecl):");
        try
        {
            var buf3 = new byte[256];
            var handle = GCHandle.Alloc(buf3, GCHandleType.Pinned);
            rc = USBKey_Reset_V3(hKey, handle.AddrOfPinnedObject(), (uint)buf3.Length);
            handle.Free();
            Console.WriteLine($"  返回: 0x{rc:X}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  异常: {ex.Message}");
        }
        
        Console.WriteLine("\n按任意键退出...");
        Console.ReadKey();
    }
}
