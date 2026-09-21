using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LncaUnlockProbe
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string path);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32.dll")]
        static extern bool FreeLibrary(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint SetDllDirectory(string path);

        delegate int ConnectFn(uint idx, uint baud, out IntPtr hKey);
        delegate int DisconnectFn(ref IntPtr hKey);
        delegate int ListKeyFn(out uint cnt);
        delegate int VerifyPinFn(IntPtr hKey, uint type, string pin, uint len);
        // USBKey_UnlockPin(hKey, lpUnlockPin, UnlockPinLen) —— 重置用户 PIN 为 "111111"
        delegate int UnlockPinFn(IntPtr hKey, string unlockPin, uint unlockPinLen);
        // USBKey_UserUnlockPin(hKey, unlockPin, uLen, userPin, pLen) —— 重置为用户指定 PIN
        delegate int UserUnlockPinFn(IntPtr hKey, string unlockPin, uint uLen, string userPin, uint pLen);

        static T Get<T>(IntPtr h, string name) where T : Delegate
            => Marshal.GetDelegateForFunctionPointer<T>(GetProcAddress(h, name));

        static int Main(string[] args)
        {
            string dir = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
            SetDllDirectory(dir);

            IntPtr h = LoadLibrary(dir + @"\JIT_USBKEY_HD.dll");
            if (h == IntPtr.Zero) { Console.WriteLine($"LoadLibrary 失败 err={Marshal.GetLastWin32Error()}"); return 1; }

            var connect = Get<ConnectFn>(h, "USBKey_Connect");
            var disconnect = Get<DisconnectFn>(h, "USBKey_Disconnect");
            var listKey = Get<ListKeyFn>(h, "USBKey_ListKey");
            var verifyPin = Get<VerifyPinFn>(h, "USBKey_VerifyPin");
            var unlockPin = Get<UnlockPinFn>(h, "USBKey_UnlockPin");
            var userUnlock = Get<UserUnlockPinFn>(h, "USBKey_UserUnlockPin");

            uint cnt = 0xFFFFFFFF;
            int rc = listKey(out cnt);
            Console.WriteLine($"[0] ListKey rc=0x{rc:X} count={cnt}");

            IntPtr hKey = IntPtr.Zero;
            rc = connect(0, 0, out hKey);
            Console.WriteLine($"[1] Connect rc=0x{rc:X} hKey=0x{hKey:X}");
            if (rc != 0 || hKey == IntPtr.Zero) { FreeLibrary(h); return 2; }

            // 先验证管理员 PIN（type=1），确认 SO PIN 是否也未知
            Console.WriteLine("\n=== 管理员 PIN (type=1) 快速验证 ===");
            foreach (var p in new[] { "12345678", "11111111", "88888888", "00000000", "123456", "111111" })
            {
                rc = verifyPin(hKey, 1, p, (uint)p.Length);
                Console.WriteLine($"    VerifyPin(type=1, \"{p}\") rc=0x{rc:X}");
            }

            // 扩展 PUK 候选
            string[] pukCandidates = {
                "12345678", "11111111", "88888888", "00000000",
                "123456", "111111", "87654321", "654321",
                "000000", "888888", "1234", "1234567890",
                "11223344", "01234567", "13579", "24680",
                "admin", "ADMIN", "password", "888888",
                "123456789012", "000000000000", "111111111111", "888888888888",
            };

            Console.WriteLine("\n=== USBKey_UserUnlockPin 测试（PUK 候选，新 PIN=123456）===");
            bool hit = false;
            foreach (var puk in pukCandidates)
            {
                rc = userUnlock(hKey, puk, (uint)puk.Length, "123456", 6);
                if (rc == 0)
                {
                    Console.WriteLine($"[+] 命中 PUK: \"{puk}\"  → 用户 PIN 已重置为 123456");
                    hit = true;
                    break;
                }
                // 只打印非 0x3EE 的特殊返回码
                if (rc != 0x3EE && rc != 0x3EB)
                    Console.WriteLine($"[?] PUK \"{puk}\" rc=0x{rc:X}");
            }
            if (!hit) Console.WriteLine("[-] 所有 PUK 候选均失败 (0x3EE)");

            // 最终验证用户 PIN
            Console.WriteLine("\n=== 最终用户 PIN 验证 ===");
            foreach (var p in new[] { "123456", "111111" })
            {
                rc = verifyPin(hKey, 0, p, (uint)p.Length);
                Console.WriteLine($"    VerifyPin(type=0, \"{p}\") rc=0x{rc:X}");
            }

            disconnect(ref hKey);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
            return 0;
        }
    }
}
