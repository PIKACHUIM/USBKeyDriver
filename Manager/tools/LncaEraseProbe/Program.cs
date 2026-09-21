using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LncaEraseProbe
{
    class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string path);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetDllDirectory(string path);
        [DllImport("kernel32.dll")]
        static extern bool FreeLibrary(IntPtr h);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSConnectDevFn(uint devIndex, out IntPtr phDev);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSDisconnectDevFn(IntPtr hDev);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSEraseFn(IntPtr hDev);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSVerifyUserPinFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string pin);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSGetSerialFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sn, ref uint len);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSGetTotalSizeFn(IntPtr hDev, out uint size);

        static T Get<T>(IntPtr h, string name) where T : Delegate
        {
            IntPtr addr = GetProcAddress(h, name);
            if (addr == IntPtr.Zero) throw new Exception("找不到导出: " + name);
            return Marshal.GetDelegateForFunctionPointer<T>(addr);
        }

        static int Main(string[] args)
        {
            bool doErase = args.Length >= 1 && args[0] == "--erase";
            string dllDir = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
            string dll = System.IO.Path.Combine(dllDir, "HD_HardAPI.dll");

            Console.WriteLine("=== LNCA 初始化/重置(擦除) 测试 ===");
            Console.WriteLine("DLL: " + dll);
            Console.WriteLine("模式: " + (doErase ? "执行擦除(--erase)" : "仅探测(未加 --erase)"));

            // 关键：设置 DLL 搜索目录，确保 HD_SortDev.dll 能被 DllMain 的 LoadLibrary 找到
            SetDllDirectory(dllDir);

            IntPtr h = LoadLibrary(dll);
            if (h == IntPtr.Zero) { Console.WriteLine("[!] LoadLibrary 失败 err=" + Marshal.GetLastWin32Error()); return 1; }
            Console.WriteLine("[+] LoadLibrary OK handle=0x" + h.ToString("X"));

            var connect = Get<HSConnectDevFn>(h, "HSConnectDev");
            var disconnect = Get<HSDisconnectDevFn>(h, "HSDisconnectDev");
            var erase = Get<HSEraseFn>(h, "HSErase");
            var verifyPin = Get<HSVerifyUserPinFn>(h, "HSVerifyUserPin");
            var getSerial = Get<HSGetSerialFn>(h, "HSGetSerial");
            var getTotal = Get<HSGetTotalSizeFn>(h, "HSGetTotalSize");

            // 连接
            IntPtr hDev = IntPtr.Zero;
            int rc = -1;
            for (uint i = 0; i < 8; i++)
            {
                rc = connect(i, out hDev);
                Console.WriteLine("[1] HSConnectDev(idx=" + i + ") rc=0x" + rc.ToString("X") + " hDev=0x" + hDev.ToString("X"));
                if (rc == 0 && hDev != IntPtr.Zero) break;
            }
            if (rc != 0 || hDev == IntPtr.Zero) { Console.WriteLine("[!] Connect 失败"); FreeLibrary(h); return 2; }

            // 序列号 / 容量
            var sb = new StringBuilder(64); uint snLen = 64;
            rc = getSerial(hDev, sb, ref snLen);
            Console.WriteLine("[2] HSGetSerial rc=0x" + rc.ToString("X") + " sn=\"" + sb + "\" len=" + snLen);
            uint total = 0;
            rc = getTotal(hDev, out total);
            Console.WriteLine("[3] HSGetTotalSize rc=0x" + rc.ToString("X") + " total=" + total);

            // 擦除前的 PIN 验证（观察当前状态）
            rc = verifyPin(hDev, "123456");
            Console.WriteLine("[4] 擦除前 HSVerifyUserPin(123456) rc=0x" + rc.ToString("X"));

            if (!doErase)
            {
                Console.WriteLine("[*] 未加 --erase，仅探测。加 --erase 参数执行初始化重置。");
                disconnect(hDev);
                FreeLibrary(h);
                return 0;
            }

            Console.WriteLine();
            Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            Console.WriteLine("!!  警告：即将执行 HSErase，将永久删除设备上所有数据  !!");
            Console.WriteLine("!!  （包括全部证书、私钥、文件，恢复出厂默认 PIN）      !!");
            Console.WriteLine("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            Console.WriteLine("[*] 已通过 --erase 参数确认，开始执行擦除...");

            // 执行擦除
            rc = erase(hDev);
            Console.WriteLine("[5] HSErase rc=0x" + rc.ToString("X") + (rc == 0 ? "  (成功)" : "  (失败)"));

            // 擦除后立即验证（同一句柄）
            rc = verifyPin(hDev, "123456");
            Console.WriteLine("[6] 擦除后(同句柄) HSVerifyUserPin(123456) rc=0x" + rc.ToString("X"));

            // 断开并重新连接，再验证
            disconnect(hDev);
            hDev = IntPtr.Zero;
            rc = -1;
            for (uint i = 0; i < 8; i++)
            {
                rc = connect(i, out hDev);
                if (rc == 0 && hDev != IntPtr.Zero) break;
            }
            Console.WriteLine("[7] 重新连接 rc=0x" + rc.ToString("X") + " hDev=0x" + hDev.ToString("X"));

            if (rc == 0 && hDev != IntPtr.Zero)
            {
                // 尝试多个常见默认 PIN
                foreach (var pin in new[] { "123456", "12345678", "111111", "000000", "888888", "1234", "11111111", "00000000" })
                {
                    int r2 = verifyPin(hDev, pin);
                    Console.WriteLine("[8] 重连后 HSVerifyUserPin(\"" + pin + "\") rc=0x" + r2.ToString("X") + (r2 == 0 ? "  <== 匹配!" : ""));
                    if (r2 == 0) break;
                }
                disconnect(hDev);
            }

            FreeLibrary(h);
            Console.WriteLine("=== 擦除测试完成 ===");
            return 0;
        }
    }
}
