using System;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// LNCA 驱动探针：独立加载 JIT_USBKEY_HD.dll，验证 USBKey_* 函数签名与设备行为。
/// 用法：LncaProbe.exe [dllPath] [pin]
/// </summary>
class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")]
    static extern bool FreeLibrary(IntPtr h);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ConnectFn(uint idx, uint baud, out IntPtr phKey);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int DisconnectFn(ref IntPtr phKey);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int UserLoginFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string pin, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int UserExitFn(IntPtr hKey);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetKeySNFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sn, ref uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetDevStateFn(IntPtr hKey, out uint state);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ListKeyFn(out uint count);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ReadCertFn(IntPtr hKey, uint type, [In, Out] byte[] cert, ref uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int VerifyPinFn(IntPtr hKey, uint type, [MarshalAs(UnmanagedType.LPStr)] string pin, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetRandomFn(IntPtr hKey, uint len, [Out] byte[] buf);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int WriteCertFn(IntPtr hKey, uint type, [In] byte[] cert, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ChangePinFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string oldPin, uint oLen, [MarshalAs(UnmanagedType.LPStr)] string newPin, uint nLen);

    static T Get<T>(IntPtr h, string name) where T : Delegate
    {
        var addr = GetProcAddress(h, name);
        if (addr == IntPtr.Zero) { Console.WriteLine($"[!] 未找到导出 {name}"); return null; }
        return Marshal.GetDelegateForFunctionPointer<T>(addr);
    }

    static int Main(string[] args)
    {
        string dllPath = args.Length > 0 ? args[0] : @"G:\Codes\USBKeyDriver\Library\LNCA\JIT_USBKEY_HD.dll";
        string pin = args.Length > 1 ? args[1] : "123456";

        Console.WriteLine("=== LNCA 驱动探针 ===");
        Console.WriteLine($"DLL: {dllPath}  PIN: {pin}");
        IntPtr h = LoadLibrary(dllPath);
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] LoadLibrary 失败 err={Marshal.GetLastWin32Error()}"); return 1; }
        Console.WriteLine($"[+] LoadLibrary OK handle=0x{h:X}");

        var connect = Get<ConnectFn>(h, "USBKey_Connect");
        var disconnect = Get<DisconnectFn>(h, "USBKey_Disconnect");
        var login = Get<UserLoginFn>(h, "USBKey_UserLogin");
        var exit = Get<UserExitFn>(h, "User_Exit");
        var getSN = Get<GetKeySNFn>(h, "USBKey_GetKeySN");
        var getState = Get<GetDevStateFn>(h, "USBKey_GetDevState");
        var listKey = Get<ListKeyFn>(h, "USBKey_ListKey");
        var readCert = Get<ReadCertFn>(h, "USBKey_ReadCert");
        var verifyPin = Get<VerifyPinFn>(h, "USBKey_VerifyPin");
        var getRandom = Get<GetRandomFn>(h, "USBKey_GetRandom");
        var writeCert = Get<WriteCertFn>(h, "USBKey_WriteCert");

        // 1) ListKey
        uint cnt = 0xFFFFFFFF;
        int rc = listKey(out cnt);
        Console.WriteLine($"[1] ListKey rc=0x{rc:X} count={cnt}");

        // 2) Connect
        IntPtr hKey = IntPtr.Zero;
        int connectRc = -1;
        foreach (var baud in new uint[] { 0, 9600, 19200, 38400, 57600, 115200 })
        {
            connectRc = connect(0, baud, out hKey);
            Console.WriteLine($"[2] Connect(idx=0, baud={baud}) rc=0x{connectRc:X} hKey=0x{hKey:X}");
            if (connectRc == 0 && hKey != IntPtr.Zero) break;
        }
        if (connectRc != 0 || hKey == IntPtr.Zero) { Console.WriteLine("[!] Connect 失败"); FreeLibrary(h); return 2; }

        // 3) GetKeySN
        var sb = new StringBuilder(64);
        uint snLen = 64;
        rc = getSN(hKey, sb, ref snLen);
        Console.WriteLine($"[3] GetKeySN rc=0x{rc:X} sn=\"{sb}\" len={snLen}");

        // 4) GetDevState
        uint st = 0;
        rc = getState(hKey, out st);
        Console.WriteLine($"[4] GetDevState rc=0x{rc:X} state=0x{st:X} ({StateName(st)})");

        // 5) VerifyPin (type 0=用户)
        rc = verifyPin(hKey, 0, pin, (uint)pin.Length);
        Console.WriteLine($"[5] VerifyPin(type=0) rc=0x{rc:X}");

        // 6) UserLogin
        rc = login(hKey, pin, (uint)pin.Length);
        Console.WriteLine($"[6] UserLogin rc=0x{rc:X}");

        // 6b) 登录后再看状态
        rc = getState(hKey, out st);
        Console.WriteLine($"[6b] GetDevState(登录后) rc=0x{rc:X} state=0x{st:X} ({StateName(st)})");

        // 7) GetRandom
        var rnd = new byte[16];
        rc = getRandom(hKey, 16, rnd);
        Console.WriteLine($"[7] GetRandom rc=0x{rc:X} data={Convert.ToHexString(rnd)}");

        // 8) ReadCert type 0 (签名)
        var cert = new byte[8192];
        uint certLen = (uint)cert.Length;
        rc = readCert(hKey, 0, cert, ref certLen);
        Console.WriteLine($"[8] ReadCert(type=0) rc=0x{rc:X} len={certLen}");
        if (rc == 0 && certLen > 0)
        {
            var der = new byte[Math.Min(certLen, cert.Length)];
            Array.Copy(cert, der, der.Length);
            Console.WriteLine($"     cert head: {Convert.ToHexString(der, 0, Math.Min(32, der.Length))}");
            try
            {
                var x = new System.Security.Cryptography.X509Certificates.X509Certificate2(der);
                Console.WriteLine($"     X509: {x.Subject}");
            }
            catch (Exception ex) { Console.WriteLine($"     X509 解析失败: {ex.Message}"); }
        }

        // 9) ReadCert type 1 (加密)
        certLen = (uint)cert.Length;
        rc = readCert(hKey, 1, cert, ref certLen);
        Console.WriteLine($"[9] ReadCert(type=1) rc=0x{rc:X} len={certLen}");

        // 10) UserExit + Disconnect
        rc = exit(hKey);
        Console.WriteLine($"[10] User_Exit rc=0x{rc:X}");
        rc = disconnect(ref hKey);
        Console.WriteLine($"     Disconnect rc=0x{rc:X} hKey=0x{hKey:X}");

        FreeLibrary(h);
        Console.WriteLine("=== 完成 ===");
        return 0;
    }

    static string StateName(uint st) => st switch
    {
        0 => "KEY_OFFLINE",
        1 => "KEY_LOGIN/ONLINE",
        2 => "KEY_ONLINE/LOGIN",
        _ => "?"
    };
}
