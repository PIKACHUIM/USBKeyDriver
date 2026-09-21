using System;
using System.Runtime.InteropServices;

namespace LncaHdcosProbe
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

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ReadContainerListInfoFn([MarshalAs(UnmanagedType.LPStr)] string devPath, IntPtr outBuf);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int DeleteContainerFn([MarshalAs(UnmanagedType.LPStr)] string devPath, ushort containerId);

        static T Get<T>(IntPtr h, string name) where T : Delegate
        {
            var addr = GetProcAddress(h, name);
            if (addr == IntPtr.Zero) { Console.WriteLine($"[!] 未找到导出 {name}"); return null; }
            return Marshal.GetDelegateForFunctionPointer<T>(addr);
        }

        static int Main(string[] args)
        {
            string dir = @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage";
            SetDllDirectory(dir);

            IntPtr h = LoadLibrary(dir + @"\HDCOS_LNCA.dll");
            if (h == IntPtr.Zero) { Console.WriteLine($"[!] LoadLibrary 失败 err={Marshal.GetLastWin32Error()}"); return 1; }
            Console.WriteLine($"[+] HDCOS_LNCA.dll 加载成功");

            var listInfo = Get<ReadContainerListInfoFn>(h, "HD_ReadContainerListInfo");
            var delContainer = Get<DeleteContainerFn>(h, "HD_DeleteContainer");

            // 1) 只读 count，不解析记录
            IntPtr buf = Marshal.AllocHGlobal(0x400);
            int rc = listInfo("", buf);
            int cnt = (rc == 0) ? Marshal.ReadInt32(buf) : -1;
            Console.WriteLine($"[1] HD_ReadContainerListInfo(\"\") rc=0x{rc:X} count={cnt}");

            // 2) 删除容器
            for (ushort cid = 1; cid <= 3; cid++)
            {
                int r2 = delContainer("", cid);
                Console.WriteLine($"[2] HD_DeleteContainer(\"\", {cid}) rc=0x{r2:X}");
            }

            // 3) 再次列出
            rc = listInfo("", buf);
            int cnt2 = (rc == 0) ? Marshal.ReadInt32(buf) : -1;
            Console.WriteLine($"[3] 删除后 count={cnt2}");

            Marshal.FreeHGlobal(buf);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
            return 0;
        }
    }
}
