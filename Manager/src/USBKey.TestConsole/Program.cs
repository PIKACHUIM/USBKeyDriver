using System;
using USBKey.Core.UsbKey;

namespace USBKey.TestConsole;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== ePass3003 完整功能测试 ===\n");
        
        try
        {
            var provider = new EPass3003Provider();
            
            Console.WriteLine($"Provider可用: {provider.IsAvailable}");
            Console.WriteLine($"平台名称: {provider.PlatformName}\n");
            
            if (!provider.IsAvailable)
            {
                Console.WriteLine("❌ Provider不可用");
                return;
            }
            
            Console.WriteLine("=== 1. 设备枚举测试 ===\n");
            var devices = provider.Enumerate();
            
            Console.WriteLine($"✅ 找到 {devices.Count} 台设备\n");
            
            foreach (var device in devices)
            {
                Console.WriteLine($"设备:");
                Console.WriteLine($"  序列号: {device.SerialNumber}");
                Console.WriteLine($"  平台: {device.Platform}");
                Console.WriteLine($"  型号: {device.Model}");
                Console.WriteLine();
            }
            
            if (devices.Count == 0)
            {
                Console.WriteLine("⚠️  未找到设备，无法进行后续测试");
                return;
            }
            
            var testDevice = devices[0];
            Console.WriteLine($"=== 使用设备: {testDevice.SerialNumber} 进行测试 ===\n");
            
            // TODO: 后续测试（需要PIN码）
            // - ListContainers (需要PIN)
            // - ImportPfx
            // - ExportCertificate
            // - DeleteContainer
            // - ChangePin
            // - ResetDevice
            
            Console.WriteLine("✅ 基础枚举测试完成！");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ 错误: {ex.Message}");
            Console.WriteLine($"\n堆栈:\n{ex.StackTrace}");
        }
        
        Console.WriteLine("\n按回车键退出...");
        Console.ReadLine();
    }
}
