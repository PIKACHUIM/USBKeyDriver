// 测试 LncaProvider.Enumerate（模拟 Manager 启动流程）
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

class TestEnumerate
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ListKeyFn(out uint count);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ConnectFn(uint idx, uint baud, out IntPtr hKey);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetKeySNFn(IntPtr hKey, StringBuilder sn, ref uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int DisconnectFn(ref IntPtr hKey);

    [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string name);

    static T GetDelegate<T>(IntPtr hMod, string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(GetProcAddress(hMod, name));

    static void Main()
    {
        try
        {
            // 模拟 FindLibraryRoot 查找 Library/LNCA
            var baseDir = AppContext.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, "Library"),
                Path.Combine(baseDir, "Library", "LNCA"),
                Path.Combine(baseDir, "..", "..", "..", "..", "..", "Library", "LNCA"),
            };
            string libraryRoot = null;
            foreach (var c in candidates)
            {
                var fullPath = Path.GetFullPath(c);
                if (Directory.Exists(fullPath) && File.Exists(Path.Combine(fullPath, "JIT_USBKEY_HD.dll")))
                {
                    libraryRoot = fullPath;
                    break;
                }
            }

            if (libraryRoot == null)
            {
                Console.WriteLine("❌ 找不到 Library/LNCA（查找路径：" + string.Join(", ", candidates) + "）");
                return;
            }

            Console.WriteLine($"✓ 找到 Library: {libraryRoot}");
            var dllPath = Path.Combine(libraryRoot, "JIT_USBKEY_HD.dll");
            var hMod = LoadLibrary(dllPath);
            if (hMod == IntPtr.Zero)
            {
                Console.WriteLine($"❌ LoadLibrary 失败: {dllPath}");
                return;
            }
            Console.WriteLine($"✓ LoadLibrary 成功");

            var listKey = GetDelegate<ListKeyFn>(hMod, "USBKey_ListKey");
            var connect = GetDelegate<ConnectFn>(hMod, "USBKey_Connect");
            var getKeySN = GetDelegate<GetKeySNFn>(hMod, "USBKey_GetKeySN");
            var disconnect = GetDelegate<DisconnectFn>(hMod, "USBKey_Disconnect");

            // 执行 Enumerate 流程
            if (listKey(out uint count) != 0)
            {
                Console.WriteLine("❌ ListKey 失败");
                return;
            }
            Console.WriteLine($"✓ ListKey: count={count}");

            for (uint i = 0; i < count && i < 4; i++)
            {
                Console.WriteLine($"\n--- 设备 {i} ---");
                if (connect(i, 0, out var hKey) != 0 || hKey == IntPtr.Zero)
                {
                    Console.WriteLine($"  Connect 失败");
                    continue;
                }
                Console.WriteLine($"  Connect 成功: hKey=0x{hKey:X}");

                var sb = new StringBuilder(64);
                uint snLen = 64;
                if (getKeySN(hKey, sb, ref snLen) == 0 && sb.Length > 0)
                    Console.WriteLine($"  序列号: {sb}");
                else
                    Console.WriteLine($"  GetKeySN 失败");

                var h = hKey;
                disconnect(ref h);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ 异常: {ex.Message}\n{ex.StackTrace}");
        }
    }
}
