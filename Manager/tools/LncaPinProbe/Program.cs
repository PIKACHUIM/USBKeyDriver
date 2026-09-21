using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LncaPinProbe
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string path);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32.dll")]
        static extern bool FreeLibrary(IntPtr h);

        delegate int ConnectFn(uint idx, uint baud, out IntPtr hKey);
        delegate int DisconnectFn(ref IntPtr hKey);
        delegate int ListKeyFn(out uint cnt);
        delegate int VerifyPinFn(IntPtr hKey, uint type, string pin, uint len);
        delegate int UserLoginFn(IntPtr hKey, string pin, uint len);
        delegate int UserExitFn(IntPtr hKey);

        static T Get<T>(IntPtr h, string name) where T : Delegate
            => Marshal.GetDelegateForFunctionPointer<T>(GetProcAddress(h, name));

        static int Main(string[] args)
        {
            string dllPath = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll";
            IntPtr h = LoadLibrary(dllPath);
            if (h == IntPtr.Zero) { Console.WriteLine($"LoadLibrary 失败 err={Marshal.GetLastWin32Error()}"); return 1; }

            var connect = Get<ConnectFn>(h, "USBKey_Connect");
            var disconnect = Get<DisconnectFn>(h, "USBKey_Disconnect");
            var listKey = Get<ListKeyFn>(h, "USBKey_ListKey");
            var verifyPin = Get<VerifyPinFn>(h, "USBKey_VerifyPin");
            var login = Get<UserLoginFn>(h, "USBKey_UserLogin");
            var exit = Get<UserExitFn>(h, "User_Exit");

            uint cnt = 0xFFFFFFFF;
            int rc = listKey(out cnt);
            Console.WriteLine($"ListKey rc=0x{rc:X} count={cnt}");

            IntPtr hKey = IntPtr.Zero;
            rc = connect(0, 0, out hKey);
            Console.WriteLine($"Connect rc=0x{rc:X} hKey=0x{hKey:X}");
            if (rc != 0 || hKey == IntPtr.Zero) { FreeLibrary(h); return 2; }

            // 常见 PIN 候选
            string[] pins = {
                "123456", "12345678", "111111", "11111111", "000000", "00000000",
                "888888", "88888888", "654321", "1234", "1234567890", "admin", "ADMIN"
            };

            Console.WriteLine("\n=== 用户 PIN 测试 (type=0) ===");
            foreach (var pin in pins)
            {
                rc = verifyPin(hKey, 0, pin, (uint)pin.Length);
                if (rc == 0) { Console.WriteLine($"[+] 用户 PIN 命中: \"{pin}\"  rc=0x{rc:X}"); break; }
                else Console.WriteLine($"[ ] \"{pin}\"  rc=0x{rc:X}");
            }

            Console.WriteLine("\n=== 管理员 PIN 测试 (type=1) ===");
            foreach (var pin in pins)
            {
                rc = verifyPin(hKey, 1, pin, (uint)pin.Length);
                if (rc == 0) { Console.WriteLine($"[+] 管理员 PIN 命中: \"{pin}\"  rc=0x{rc:X}"); break; }
                else Console.WriteLine($"[ ] \"{pin}\"  rc=0x{rc:X}");
            }

            Console.WriteLine("\n=== UserLogin 测试 ===");
            foreach (var pin in pins)
            {
                rc = login(hKey, pin, (uint)pin.Length);
                if (rc == 0) { Console.WriteLine($"[+] UserLogin 命中: \"{pin}\"  rc=0x{rc:X}"); break; }
                else Console.WriteLine($"[ ] \"{pin}\"  rc=0x{rc:X}");
            }

            exit(hKey);
            disconnect(ref hKey);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
            return 0;
        }
    }
}
