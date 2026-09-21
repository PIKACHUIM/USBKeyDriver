using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    /// <summary>
    /// 解析 LNCA 厂商 DLL 所在目录（2026-09 起厂商文件已归入 <c>official driver</c> 子目录）。
    /// <para>查找顺序：环境变量 <c>LNCA_DLL_DIR</c> → 自程序目录逐级向上匹配下列相对路径
    /// （<c>official driver</c> / <c>Library\LNCA USBKey Manage\official driver</c> /
    /// <c>Library\LNCA USBKey Manage</c> / <c>Library\LNCA</c>）→ 仓库根 → <c>C:\Windows\SysWOW64</c>（CSP 安装位置）。</para>
    /// </summary>
    static string ResolveLncDir()
    {
        const string probe = "HDCOS_LNCA.dll";

        var env = Environment.GetEnvironmentVariable("LNCA_DLL_DIR");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(Path.Combine(env, probe)))
            return env;

        var bases = new List<string>();
        var cur = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && !string.IsNullOrEmpty(cur); i++)
        {
            bases.Add(cur);
            cur = Path.GetDirectoryName(cur.TrimEnd(Path.DirectorySeparatorChar));
        }
        bases.Add(@"G:\Codes\USBKeyDriver");

        var relatives = new[]
        {
            "official driver",
            @"Library\LNCA USBKey Manage\official driver",
            @"Library\LNCA USBKey Manage",
            @"Library\LNCA",
            ".",
        };

        foreach (var b in bases)
            foreach (var rel in relatives)
            {
                var c = Path.GetFullPath(Path.Combine(b, rel));
                if (File.Exists(Path.Combine(c, probe))) return c;
            }

        var sysWow = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        if (File.Exists(Path.Combine(sysWow, probe))) return sysWow;

        return @"G:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\official driver";
    }

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
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int RegisterCertFn(IntPtr hKey, uint type, [MarshalAs(UnmanagedType.LPStr)] string containerName, uint nameLen);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int RFileLenFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string name, uint nameLen, out uint fileLen);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int WritePubPriKeyFn(IntPtr hKey, uint enKeyIndex, [In] byte[] pri, uint priLen, [In] byte[] pubEncKey, uint pubEncKeyLen, uint algID);

    // HD_HardAPI 层
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSConnectDevFn(uint devIndex, out IntPtr phDev);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSDisconnectDevFn(IntPtr hDev);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSEraseFn(IntPtr hDev);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSVerifyUserPinFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string pin);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSVerifySOPinFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string soPin);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSChangeUserPinFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string oldPin, [MarshalAs(UnmanagedType.LPStr)] string newPin);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSChangeSOPinFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string oldPin, [MarshalAs(UnmanagedType.LPStr)] string newPin);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSCreateFileFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string name, uint nameLen, uint size, uint readRight, uint writeRight);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSWriteFileFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string name, [In] byte[] data, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSReadFileFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string name, [Out] byte[] data, ref uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSDeleteFileFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string name);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSHasFileExistFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] string name, out uint exist);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSGetSerialFn(IntPtr hDev, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sn, ref uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSGetTotalSizeFn(IntPtr hDev, out uint size);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HSGetFreeSizeFn(IntPtr hDev, out uint size);

    // HDCOS_LNCA.dll 层（完全格式化 / 重设 PIN）
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint SetDllDirectory(string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate IntPtr HdOpenFn(uint port);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdCloseFn(IntPtr hCard);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdIcResetFn(IntPtr hCard, [In, Out] byte[] atr);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdClearDirFn(IntPtr hCard);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ReloadPinFn(IntPtr hCard, uint len, [In] byte[] data, IntPtr reserved);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdChangePinFn(IntPtr hCard, [In] byte[] oldNew, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdVerifyPinFn(IntPtr hCard, [In] byte[] pin, uint len);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdGetBcdSnFn(IntPtr hCard, [In, Out] byte[] sn);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdGetSnFn(IntPtr hCard, [In, Out] byte[] sn);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int HdReadContainerListFn(IntPtr hCard, IntPtr outBuf);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int GetChallengeFn(IntPtr hCard, uint len, [In, Out] byte[] outBuf, out ushort sw);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ExternalAuthFn(IntPtr hCard, uint p1, [In] byte[] resp8, out ushort sw);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int ClearDfFn(IntPtr hCard, out ushort sw);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int SelectFileFn(IntPtr hCard, uint a, uint b, uint c, uint d, out ushort sw);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int VerifyAdminPinFn(IntPtr hCard, [In] byte[] key, uint keyLen);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int JitReloadPinFn(IntPtr hCard, [In] byte[] key, uint keyLen, [In] byte[] newPin, uint newPinLen);

    static T Get<T>(IntPtr h, string name) where T : Delegate
    {
        var addr = GetProcAddress(h, name);
        if (addr == IntPtr.Zero) { Console.WriteLine($"[!] 未找到导出 {name}"); return null; }
        return Marshal.GetDelegateForFunctionPointer<T>(addr);
    }

    static int Main(string[] args)
    {
        // --dump <dll> [filter] 模式：dump 导出表
        if (args.Length >= 2 && args[0] == "--dump")
        {
            string filter = args.Length >= 3 ? args[2] : null;
            ExportDump.Dump(args[1], filter);
            return 0;
        }

        // --hardapi 模式：实测 HD_HardAPI.dll 层（连接/验证/删除文件/擦除）
        if (args.Length >= 1 && args[0] == "--hardapi")
        {
            string hardApiPin = args.Length >= 2 ? args[1] : "123456";
            return HardApiProbe(hardApiPin);
        }

        // --unblock 模式：用华大通用层的 INS 0x24（PUK 计数）尝试解锁
        if (args.Length >= 2 && args[0] == "--unblock")
        {
            var data = Convert.FromHexString(args[1].Replace(" ", ""));
            byte up2 = args.Length > 2 ? Convert.ToByte(args[2].Replace("0x", ""), 16) : (byte)0;
            uint uport = args.Length > 3 && uint.TryParse(args[3], out var up0) ? up0 : 0;
            return UnblockProbe(data, up2, uport);
        }

        // --key 模式：在 P1=0 通道（不锁定）验证候选传输密钥
        if (args.Length >= 2 && args[0] == "--key")
        {
            var ks = args.Skip(1).Where(a => !a.StartsWith("--port")).ToArray();
            uint kp = 0;
            var pi = Array.IndexOf(args, "--port");
            if (pi >= 0 && pi + 1 < args.Length) uint.TryParse(args[pi + 1], out kp);
            ks = ks.Where(a => a != kp.ToString()).ToArray();
            return KeyProbe(kp, ks);
        }

        // --apdu 模式：发送任意 APDU（hex）并打印 SW
        if (args.Length >= 2 && args[0] == "--apdu")
        {
            uint ap = args.Length > 2 && uint.TryParse(args[2], out var ap1) ? ap1 : 0;
            return SendApdu(ap, Convert.FromHexString(args[1].Replace(" ", "")));
        }

        // --refs 模式：探测 ISO VERIFY 参考数据（不消耗重试次数）
        if (args.Length >= 1 && args[0] == "--refs")
        {
            uint rp = args.Length > 1 && uint.TryParse(args[1], out var rp0) ? rp0 : 0;
            return ProbeRefs(rp);
        }

        // --verify 模式：用指定 P2 测试一个 PIN 候选（会消耗一次重试）
        //   用法：--verify <p2hex> <pin> [port]
        if (args.Length >= 3 && args[0] == "--verify")
        {
            byte vp2 = Convert.ToByte(args[1].Replace("0x", ""), 16);
            string vpin = args[2];
            uint vport = args.Length > 3 && uint.TryParse(args[3], out var vp0) ? vp0 : 0;
            return VerifyCandidate(vport, vp2, vpin);
        }

        // --mf 模式：用 GP_COS_LNCA.dll 的内部函数 ExternalAuthMF(RVA 0xE160) 验证「MF 外部认证」能否通过
        //   （InitialCard 的第一步就是它；只认证、不写入，属于安全探测）
        //   用法：--mf [port=0]
        if (args.Length >= 1 && args[0] == "--mf")
        {
            uint mp = args.Length > 1 && uint.TryParse(args[1], out var mp0) ? mp0 : 0;
            return MfAuthProbe(mp);
        }

        // --authcnt 模式：连续多次发起外部认证，观察状态字是否递减（判断认证计数器是否真正生效）
        //   用法：--authcnt [port=0] [p1=0] [次数=5]
        if (args.Length >= 1 && args[0] == "--authcnt")
        {
            uint ap = args.Length > 1 && uint.TryParse(args[1], out var ap0) ? ap0 : 0;
            uint p1 = args.Length > 2 && uint.TryParse(args[2], out var p10) ? p10 : 0;
            int n = args.Length > 3 && int.TryParse(args[3], out var n0) ? n0 : 5;
            return AuthCountProbe(ap, p1, n);
        }

        // --adminpin 模式：用「调用方提供的管理员口令」做外部认证（P1=2），验证是否为该卡的管理员口令
        //   用法：--adminpin <口令> [more...]   （支持 hex: 前缀直接给出原始字节）
        if (args.Length >= 2 && args[0] == "--adminpin")
            return AdminPinProbe(args.Skip(1).ToArray());

        // --deep 模式：逐层定位「完全格式化」失败点
        //   顺序：HD_Open → HD_IC_RESET → Get_Challenge → External_Authentication(P1=0) → Clear_DF
        //   用法：--deep [port=0] [--noerase]
        if (args.Length >= 1 && args[0] == "--deep")
        {
            bool noErase = args.Any(a => a == "--noerase");
            var r2 = args.Skip(1).Where(a => a != "--noerase").ToArray();
            uint dp = r2.Length > 0 && uint.TryParse(r2[0], out var dp0) ? dp0 : 0;
            return DeepProbe(dp, noErase);
        }

        // --jitstate 模式：只读 JIT 层快照（设备数 / 序列号 / 状态 / 证书是否存在），不验证 PIN
        if (args.Length >= 1 && args[0] == "--jitstate")
            return JitStateProbe();

        // --state 模式：只读状态快照（序列号 + 容器列表 + 卡片认证态），用于格式化前后对比
        //   用法：--state [port=0]
        if (args.Length >= 1 && args[0] == "--state")
        {
            uint sp = args.Length > 1 && uint.TryParse(args[1], out var sp0) ? sp0 : 0;
            return StateProbe(sp);
        }

        // --format 模式：实测「完全格式化 + 重设 PIN」链路
        //   用法：--format [port=0] [newPin=12345678] [sopin] [puk] [--dry]
        //   sopin：管理员口令（SO PIN），内置默认传输密钥失效时必须提供
        //   puk  ：解锁码，用于 INS 0x5E 解锁已锁定的用户 PIN
        //   --dry：只做只读探测（HD_Open/IC_RESET/序列号 + HD_VerifyPin 探测），不执行格式化
        if (args.Length >= 1 && args[0] == "--format")
        {
            bool dry = args.Any(a => a == "--dry");
            var rest = args.Skip(1).Where(a => a != "--dry").ToArray();
            uint port = rest.Length > 0 && uint.TryParse(rest[0], out var p0) ? p0 : 0;
            string newPin = rest.Length > 1 ? rest[1] : "12345678";
            string sopin = rest.Length > 2 ? rest[2] : null;
            string puk = rest.Length > 3 ? rest[3] : null;
            return FormatProbe(port, newPin, sopin, puk, dry);
        }

        string dllPath = args.Length > 0 ? args[0] : Path.Combine(ResolveLncDir(), "JIT_USBKEY_HD.dll");
        string pin = args.Length > 1 ? args[1] : "123456";

        Console.WriteLine("=== LNCA 驱动探针 ===");
        Console.WriteLine($"DLL: {dllPath}  PIN: {pin}");
        // 必须先把 DLL 目录设为搜索目录，否则 JIT 层动态加载 HDCOS_LNCA/GP_COS_LNCA 会失败(126)
        SetDllDirectory(Path.GetDirectoryName(dllPath));
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

    /// <summary>
    /// 用 ISO VERIFY 通道测试单个 PIN 候选（<c>00 20 00 P2 Lc &lt;PIN&gt;</c>）。
    /// <para>⚠️ 每次错误都会消耗一次该参考数据的重试计数，返回 SW=0x63Cx 可见剩余次数。</para>
    /// </summary>
    static int VerifyCandidate(uint port, byte p2, string pin)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var verify = Get<VerifyPinRawFn>(h, "Verify_Pin");

        IntPtr hCard = open(port);
        if (hCard == IntPtr.Zero) { Console.WriteLine("[!] HD_Open 失败"); FreeLibrary(h); return 2; }

        try
        {
            var data = Encoding.ASCII.GetBytes(pin);
            int rc = verify(hCard, p2, (uint)data.Length, data, out var sw);
            Console.WriteLine($"ISO VERIFY(P2=0x{p2:X2}, \"{pin}\") → rc={rc} sw=0x{sw:X4}  {SwMeaning(sw)}");
            return sw == 0x9000 ? 0 : 3;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
        }
    }

    /// <summary>
    /// HD_Application_Manager(int hCard, uint apduLen, byte* apdu, byte* respBuf, ushort* sw)
    /// —— COS 层的通用 APDU 通道（ret 0x14，5 参数），可直接发送任意 APDU 并读取 SW。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int AppMgrFn(IntPtr hCard, uint apduLen, [In] byte[] apdu, [In, Out] byte[] resp, out ushort sw);

    /// <summary>
    /// 发送任意 APDU 并打印状态字（用于验证 DLL 未暴露的标准命令：0x24 改参考数据 / 0x2C 解锁 等）。
    /// <para>用法：--apdu &lt;hex&gt; [port]</para>
    /// </summary>
    static int SendApdu(uint port, byte[] apdu)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine($"=== 发送 APDU: {Convert.ToHexString(apdu)} ===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var mgr = Get<AppMgrFn>(h, "HD_Application_Manager");

        IntPtr hCard = open(port);
        if (hCard == IntPtr.Zero) { Console.WriteLine("[!] HD_Open 失败"); FreeLibrary(h); return 2; }

        try
        {
            var resp = new byte[512];
            int rc = mgr(hCard, (uint)apdu.Length, apdu, resp, out var sw);
            Console.WriteLine($"→ rc={rc}  sw=0x{sw:X4}  {SwMeaning(sw)}  resp={Convert.ToHexString(resp, 0, 16)}");
            return 0;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>HD_hdcos480.dll 层成员（华大通用 COS，含 LNCA 定制版被砍掉的解锁命令）。</summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr LoadLibraryW(string path);

    /// <summary>Pin_Unblock(int hCard, byte p2, uint len, byte* data, ushort* sw) —— 84 24 00 P2 Lc（ret 0x14）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int PinUnblockFn(IntPtr hCard, byte p2, uint len, [In] byte[] data, out ushort sw);

    /// <summary>Get_Info(int hCard, byte* outBuf, ushort* sw) —— BF C8 00 00 0F（ret 0xC）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int GetInfoFn(IntPtr hCard, [In, Out] byte[] outBuf, out ushort sw);

    /// <summary>
    /// 用华大通用层 <c>HD_hdcos480.dll</c> 的 <c>Pin_Unblock</c>（INS 0x24，<b>走 PUK 计数器</b>）尝试解锁/重设 PIN。
    /// <para>用法：--unblock &lt;数据hex&gt; [p2=0] [port=0]</para>
    /// <para>SW=0x63Cx → 剩余重试次数；SW=0x9000 → 成功；SW=0x6983 → 已锁。</para>
    /// </summary>
    static int UnblockProbe(byte[] data, byte p2, uint port)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine($"=== 华大 Pin_Unblock(84 24 00 {p2:X2} {data.Length:X2} {Convert.ToHexString(data)}) ===");

        IntPtr h = LoadLibraryW(Path.Combine(dir, "HD_hdcos480.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] HD_hdcos480.dll 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var unblock = Get<PinUnblockFn>(h, "Pin_Unblock");
        var info = Get<GetInfoFn>(h, "Get_Info");

        IntPtr hCard = open(port);
        Console.WriteLine($"[1] HD_hdcos480!HD_Open({port}) → hCard=0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            if (info != null)
            {
                var buf = new byte[64];
                int irc = info(hCard, buf, out var isw);
                Console.WriteLine($"[2] Get_Info → rc={irc} sw=0x{isw:X4} data={Convert.ToHexString(buf, 0, 16)}");
            }
            int rc = unblock(hCard, p2, (uint)data.Length, data, out var sw);
            Console.WriteLine($"[3] Pin_Unblock → rc={rc} sw=0x{sw:X4}  {SwMeaning(sw)}");
            return sw == 0x9000 ? 0 : 3;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>sub_8D10(byte* buf, int len) —— 内部变换（cdecl）：低位置 1 的字节翻转 bit7。</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int TransformFn(byte[] buf, int len);

    /// <summary>sub_8DC0(byte* in, int inLen, byte* out, byte* key, int mode) —— 内部挑战应答计算（cdecl）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int ComputeRespFn(byte[] input, int inLen, byte[] output, byte[] key, int mode);

    /// <summary>
    /// 用「调用方提供的候选密钥」在 <b>P1=0 通道</b>（从未锁定）做挑战应答认证。
    /// <para>实现方式：按 RVA 调用 HDCOS_LNCA.dll 内部函数 sub_8D10 / sub_8DC0 自行计算响应，
    /// 再用 External_Authentication(P1=0) 提交。SW=0x9000 即密钥正确。</para>
    /// <para>用法：--key &lt;候选1&gt; [候选2 ...] [--hex:xxxx]</para>
    /// </summary>
    static int KeyProbe(uint port, string[] keys)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine("=== P1=0 通道候选密钥验证 ===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var challenge = Get<GetChallengeFn>(h, "Get_Challenge");
        var extAuth = Get<ExternalAuthFn>(h, "External_Authentication");
        var transform = (TransformFn)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(h, 0x8D10), typeof(TransformFn));
        var compute = (ComputeRespFn)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(h, 0x8DC0), typeof(ComputeRespFn));

        IntPtr hCard = open(port);
        if (hCard == IntPtr.Zero) { Console.WriteLine("[!] HD_Open 失败"); FreeLibrary(h); return 2; }

        try
        {
            foreach (var raw in keys)
            {
                var kb = raw.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)
                    ? Convert.FromHexString(raw.Substring(4).Replace(" ", ""))
                    : Encoding.ASCII.GetBytes(raw);

                // 两种形态都试：①原样 ②经 sub_8D10 变换（对应不同调用路径）
                for (int form = 0; form < 2; form++)
                {
                    // 用 64 字节缓冲承载候选：既可测裸密钥，也可测「描述符+密钥」结构体
                    var key16 = new byte[64];
                    Array.Copy(kb, key16, Math.Min(kb.Length, 64));
                    var ch = new byte[16];
                    int rcC = challenge(hCard, 8, ch, out var swC);
                    if (rcC < 0 || swC != 0x9000) { Console.WriteLine($"  Get_Challenge 失败 sw=0x{swC:X4}"); return 3; }

                    if (form == 1) transform(key16, Math.Min(kb.Length, 64));

                    var resp = new byte[16];
                    int rcCalc = compute(ch, 8, resp, key16, 0);
                    int rc = extAuth(hCard, 0, resp, out var sw);
                    Console.WriteLine($"  key(len={kb.Length}{(form == 1 ? ",已变换" : ",原样")}) calc={rcCalc} → rc={rc} sw=0x{sw:X4}  {SwMeaning(sw)}");
                    if (sw == 0x9000)
                    {
                        Console.WriteLine($"  *** 密钥正确：{raw}（形态：{(form == 1 ? "变换" : "原样")}） ***");
                        return 0;
                    }
                }
            }
            return 4;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>Verify_Pin(int hCard, byte p2, uint len, byte* data, ushort* sw) —— ISO VERIFY 通道（ret 0x14）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int VerifyPinRawFn(IntPtr hCard, byte p2, uint len, [In] byte[] data, out ushort sw);

    /// <summary>Change_Pin(int hCard, byte p2, uint len, byte* data, ushort* sw) —— 80 5E 01 P2（ret 0x14）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ChangePinRawFn(IntPtr hCard, byte p2, uint len, [In] byte[] data, out ushort sw);

    static string SwMeaning(ushort sw) => sw switch
    {
        0x9000 => "成功",
        0x6700 => "长度错误（参考数据存在！）",
        0x6982 => "安全状态不满足",
        0x6983 => "参考数据已被锁定",
        0x6A80 => "数据域参数错误（参考数据存在）",
        0x6A82 => "文件未找到",
        0x6A83 => "记录未找到",
        0x6A86 => "P1/P2 不正确",
        0x6A88 => "参考数据未找到",
        0x6D00 => "指令不支持",
        _ => (sw & 0xFFF0) == 0x63C0 ? $"PIN 错误，剩余重试 {sw & 0xF} 次（参考数据存在且未锁！）" : "其他"
    };

    /// <summary>
    /// 探测 ISO VERIFY 参考数据（P2）的存在与状态：对每个 P2 发送 <c>00 20 00 P2 00</c>（Lc=0）。
    /// <para>用零长度数据探测通常返回 0x6700/0x6A88，**不消耗 PIN 重试次数**，可安全枚举。</para>
    /// </summary>
    static int ProbeRefs(uint port)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine("=== ISO VERIFY 参考数据探测（Lc=0，不消耗重试次数）===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var verify = Get<VerifyPinRawFn>(h, "Verify_Pin");

        IntPtr hCard = open(port);
        Console.WriteLine($"[1] HD_Open({port}) → hCard=0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            var candidates = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x20, 0x80, 0x81, 0x82, 0x83, 0x84, 0x88, 0x0A, 0x0B };
            var empty = Array.Empty<byte>();
            foreach (var p2 in candidates)
            {
                int rc = verify(hCard, p2, 0, empty, out var sw);
                Console.WriteLine($"  P2=0x{p2:X2} → rc={rc,3}  sw=0x{sw:X4}  {SwMeaning(sw)}");
            }
            return 0;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>ExternalAuthMF(int hCard) —— GP_COS_LNCA.dll 内部函数（RVA 0xE160，__stdcall，1 参数）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ExternalAuthMFn(IntPtr hCard);

    /// <summary>
    /// 安全探测：调用 GP_COS_LNCA.dll 内部的 <c>ExternalAuthMF(hCard)</c>（RVA 0xE160），
    /// 它是 <c>InitialCard</c> 的第一步（MF 主文件外部认证）。只认证、不写入任何数据。
    /// <para>返回 0 = 外置默认传输密钥被该卡接受（→ InitialCard 可行）；-1 = 不接受。</para>
    /// </summary>
    static int MfAuthProbe(uint port)
    {
        string dir = ResolveLncDir();
        Console.WriteLine("=== GP_COS_LNCA：MF 外部认证探测（安全，只认证不写入）===");

        // 厂商的 ExternalAuthMF 硬编码 LoadLibrary("GP_IFD.dll")，但 SDK 里只有 GP_IFD_LNCA.dll
        // （两者导出同一套 HD_OpenPort/HD_ApduT0/HD_GetDescriptor/HD_ClosePort）。
        // 因此在 %TEMP% 下建工作目录：拷贝全部 LNCA DLL，并把 GP_IFD_LNCA.dll 额外拷一份为 GP_IFD.dll，
        // 让该链路能正常加载 —— 不修改 SDK 目录中的任何文件。
        var work = Path.Combine(Path.GetTempPath(), "lnca_gpifd_shim");
        Directory.CreateDirectory(work);
        foreach (var f in Directory.GetFiles(dir, "*.dll"))
            File.Copy(f, Path.Combine(work, Path.GetFileName(f)), true);
        File.Copy(Path.Combine(dir, "GP_IFD_LNCA.dll"), Path.Combine(work, "GP_IFD.dll"), true);

        SetDllDirectory(work);
        IntPtr h = LoadLibrary(Path.Combine(work, "GP_COS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] GP_COS_LNCA.dll 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        // 内部函数：HMODULE 即模块基址，按 RVA 取地址
        var mf = (ExternalAuthMFn)Marshal.GetDelegateForFunctionPointer(
            IntPtr.Add(h, 0xE160), typeof(ExternalAuthMFn));

        IntPtr hCard = open(port);
        Console.WriteLine($"[1] GP_COS_LNCA!HD_Open({port}) → hCard=0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            int rc = mf(hCard);
            Console.WriteLine($"[2] ExternalAuthMF(hCard) → {rc}  " +
                              (rc == 0 ? "<== MF 外部认证通过（InitialCard 链路可行！）" : "(失败：传输密钥不匹配)"));
            return rc == 0 ? 0 : 3;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>
    /// 连续多次发起外部认证（全 0 响应），观察返回的 SW 是否随失败次数递减
    /// （0x63Cx 的末位 = 剩余重试次数）。用于判断「认证计数器是否真正生效」。
    /// </summary>
    static int AuthCountProbe(uint port, uint p1, int count)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine($"=== 认证计数器测试：P1={p1}，连续 {count} 次（每次都用错误响应）===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var extAuth = Get<ExternalAuthFn>(h, "External_Authentication");
        var challenge = Get<GetChallengeFn>(h, "Get_Challenge");

        IntPtr hCard = open(port);
        if (hCard == IntPtr.Zero) { Console.WriteLine("[!] HD_Open 失败"); FreeLibrary(h); return 2; }

        try
        {
            for (int i = 1; i <= count; i++)
            {
                // 每次先取新挑战（贴近真实流程），再送错误响应
                var ch = new byte[16];
                int crc = challenge(hCard, 8, ch, out var csw);
                int rc = extAuth(hCard, p1, new byte[8], out var sw);
                string meaning = (sw & 0xFFF0) == 0x63C0
                    ? $"剩余重试 {sw & 0xF} 次"
                    : sw switch
                    {
                        0x9000 => "通过",
                        0x6982 => "安全状态不满足",
                        0x6983 => "认证方式被锁定",
                        0x9303 => "认证方式被锁定(9303)",
                        _ => "其他"
                    };
                Console.WriteLine($"[{i}] Get_Challenge rc=0x{crc:X} sw=0x{csw:X4} | External_Auth rc=0x{rc:X} sw=0x{sw:X4}  ({meaning})");
            }
            return 0;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>
    /// 用调用方提供的口令做「管理员外部认证」（HDJIT_VerifyAdminPin → External_Authentication P1=2）。
    /// <para>返回 0 = 该口令正确；返回 -1 = 不匹配（会消耗一次 P1=2 认证计数，故命令行必须显式给出候选）。</para>
    /// </summary>
    static int AdminPinProbe(string[] pins)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine("=== LNCA 管理员口令验证（P1=2 外部认证）===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var verifyAdmin = Get<VerifyAdminPinFn>(h, "HDJIT_VerifyAdminPin");

        foreach (var pin in pins)
        {
            IntPtr hCard = open(0);
            if (hCard == IntPtr.Zero) { Console.WriteLine("[!] HD_Open 失败"); FreeLibrary(h); return 2; }
            try
            {
                // 支持 hex:6379... 形式直接给出原始密钥字节（用于测试 DLL 内置常量等）
                var kb = pin.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)
                    ? Convert.FromHexString(pin.Substring(4).Replace(" ", ""))
                    : Encoding.ASCII.GetBytes(pin);
                int rc = verifyAdmin(hCard, kb, (uint)kb.Length);
                Console.WriteLine($"[*] 密钥长度 {kb.Length} ({Convert.ToHexString(kb)}) → rc={rc}  {(rc == 0 ? "<== 认证通过！" : "(不匹配)")}");
                if (rc == 0) return 0;
            }
            finally { close(hCard); }
        }
        FreeLibrary(h);
        Console.WriteLine("=== 完成 ===");
        return 3;
    }

    /// <summary>
    /// 逐层定位「完全格式化」失败点：HD_Open → HD_IC_RESET → Get_Challenge →
    /// External_Authentication(P1=0, 全 0 响应) → Clear_DF(hCard,&amp;sw)，每一步打印 rc 与 SW。
    /// <para>因为 External_Authentication 用全 0 响应必然失配，所以本模式仅用于判断
    /// 「Clear_DF 是否真的需要外部认证」以及各层 SW 语义。</para>
    /// </summary>
    static int DeepProbe(uint port, bool noErase)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine($"=== LNCA 完全格式化链路逐层定位（noErase={noErase}）===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var icReset = Get<HdIcResetFn>(h, "HD_IC_RESET");
        var challenge = Get<GetChallengeFn>(h, "Get_Challenge");
        var extAuth = Get<ExternalAuthFn>(h, "External_Authentication");
        var clearDf = Get<ClearDfFn>(h, "Clear_DF");
        var selectFile = Get<SelectFileFn>(h, "Select_File");
        var clearDir = Get<HdClearDirFn>(h, "HD_ClearDir");

        IntPtr hCard = open(port);
        Console.WriteLine($"[1] HD_Open({port}) → 0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            var atr = new byte[64];
            Console.WriteLine($"[2] HD_IC_RESET → 0x{icReset(hCard, atr):X}");

            // 3) Get_Challenge
            var ch = new byte[16];
            ushort swC = 0;
            int rcC = challenge(hCard, 8, ch, out swC);
            Console.WriteLine($"[3] Get_Challenge(len=8) → rc=0x{rcC:X}  sw=0x{swC:X4}  ch={Convert.ToHexString(ch, 0, 8)}");

            // 4) Select_File(0,0,0,0) —— 观察 SW（判断是否已有会话/需要选文件）
            ushort swS = 0;
            int rcS = selectFile(hCard, 0, 0, 0, 0, out swS);
            Console.WriteLine($"[4] Select_File(0,0,0,0) → rc=0x{rcS:X}  sw=0x{swS:X4}");

            // 5) External_Authentication(P1=0, 全 0 响应)：预期失配，仅用于确认认证环节是否可通
            var resp = new byte[8];
            ushort swA = 0;
            int rcA = extAuth(hCard, 0, resp, out swA);
            Console.WriteLine($"[5] External_Authentication(P1=0, 全0响应) → rc=0x{rcA:X}  sw=0x{swA:X4}");

            if (!noErase)
            {
                // 6) 直接 Clear_DF（私有 APDU BF CE 00 00 00）——真正的数据区格式化
                ushort swD = 0;
                int rcD = clearDf(hCard, out swD);
                Console.WriteLine($"[6] Clear_DF(直接调用) → rc=0x{rcD:X}  sw=0x{swD:X4}");
            }

            // 7) 再次 HD_ClearDir，观察返回是否变化
            Console.WriteLine($"[7] HD_ClearDir → 0x{clearDir(hCard):X}");
            return 0;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>
    /// 只读 JIT 层快照：ListKey → Connect → GetKeySN → GetDevState → ReadCert(0/1) → Disconnect。
    /// <para>不调用 VerifyPin / UserLogin，因此不会消耗 PIN 重试次数，可安全用于格式化前后对比。</para>
    /// </summary>
    static int JitStateProbe()
    {
        string dll = Path.Combine(ResolveLncDir(), "JIT_USBKEY_HD.dll");
        SetDllDirectory(Path.GetDirectoryName(dll));
        Console.WriteLine("=== LNCA JIT 层只读快照 ===");

        IntPtr h = LoadLibrary(dll);
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var listKey = Get<ListKeyFn>(h, "USBKey_ListKey");
        var connect = Get<ConnectFn>(h, "USBKey_Connect");
        var disconnect = Get<DisconnectFn>(h, "USBKey_Disconnect");
        var getSN = Get<GetKeySNFn>(h, "USBKey_GetKeySN");
        var getState = Get<GetDevStateFn>(h, "USBKey_GetDevState");
        var readCert = Get<ReadCertFn>(h, "USBKey_ReadCert");
        var rFileLen = Get<RFileLenFn>(h, "USBKey_RFileLen");

        uint cnt = 0xFFFFFFFF;
        int rc = listKey(out cnt);
        Console.WriteLine($"[1] ListKey → 0x{rc:X}  count={cnt}");

        IntPtr hKey = IntPtr.Zero;
        rc = connect(0, 0, out hKey);
        Console.WriteLine($"[2] Connect(0) → 0x{rc:X}  hKey=0x{hKey.ToInt64():X}");
        if (rc != 0 || hKey == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            var sb = new StringBuilder(64); uint snLen = 64;
            Console.WriteLine($"[3] GetKeySN → 0x{getSN(hKey, sb, ref snLen):X}  sn=\"{sb}\"");
            uint st = 0;
            Console.WriteLine($"[4] GetDevState → 0x{getState(hKey, out st):X}  state=0x{st:X} ({StateName(st)})");
            for (uint type = 0; type <= 1; type++)
            {
                var cert = new byte[8192]; uint clen = (uint)cert.Length;
                int crc = readCert(hKey, type, cert, ref clen);
                string extra = "";
                if (crc == 0 && clen > 0)
                {
                    try
                    {
                        var der = new byte[Math.Min(clen, (uint)cert.Length)];
                        Array.Copy(cert, der, der.Length);
                        var x = new System.Security.Cryptography.X509Certificates.X509Certificate2(der);
                        extra = $"  subject=\"{x.Subject}\"";
                    }
                    catch (Exception ex) { extra = $"  (X509 解析失败: {ex.Message})"; }
                }
                Console.WriteLine($"[5] ReadCert(type={type}) → 0x{crc:X}  len={clen}{extra}");
            }
            // 关键数据文件长度（证书/密钥记录是否已写入）
            foreach (var f in new[] { "Cert_0", "Cert_1", "K0", "K1" })
            {
                uint flen = 0;
                int frc = rFileLen(hKey, f, (uint)f.Length, out flen);
                Console.WriteLine($"[6] RFileLen(\"{f}\") → 0x{frc:X}  len={flen}");
            }
        }
        finally
        {
            disconnect(ref hKey);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
        return 0;
    }

    /// <summary>
    /// 只读状态快照：HD_Open → 序列号 → 容器列表（HD_ReadContainerListInfo）→ HD_Close。
    /// 不做任何验证/修改，可安全地用于「格式化前 / 格式化后」对比。
    /// </summary>
    static int StateProbe(uint port)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine("=== LNCA 只读状态快照 ===");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var getBcd = Get<HdGetBcdSnFn>(h, "HD_GET_BCDSN");
        var getSn = Get<HdGetSnFn>(h, "HD_GET_SN");
        var listInfo = Get<HdReadContainerListFn>(h, "HD_ReadContainerListInfo");

        IntPtr hCard = open(port);
        Console.WriteLine($"[1] HD_Open({port}) → hCard=0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            var bcd = new byte[64];
            Console.WriteLine($"[2] HD_GET_BCDSN → 0x{getBcd(hCard, bcd):X}  sn=\"{ToAscii(bcd)}\"");
            var sn = new byte[64];
            Console.WriteLine($"[3] HD_GET_SN → 0x{getSn(hCard, sn):X}  sn=\"{ToAscii(sn)}\"");

            // 容器列表：[0:4]=count，随后每个记录 0x80 字节
            IntPtr buf = Marshal.AllocHGlobal(0x400);
            for (int i = 0; i < 0x400; i++) Marshal.WriteByte(buf, i, 0);
            int rc = listInfo(hCard, buf);
            int cnt = Marshal.ReadInt32(buf);
            Console.WriteLine($"[4] HD_ReadContainerListInfo → 0x{rc:X}  count={cnt}");
            for (int i = 0; i < Math.Min(Math.Max(cnt, 0), 3); i++)
            {
                int off = 4 + i * 0x80;
                var rec = new byte[0x80];
                Marshal.Copy(IntPtr.Add(buf, off), rec, 0, rec.Length);
                Console.WriteLine($"     容器[{i + 1}] {ToAscii(rec)}");
                Console.WriteLine($"              hex={Convert.ToHexString(rec, 0, 32)}");
            }
            Marshal.FreeHGlobal(buf);
            return 0;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    /// <summary>
    /// 实测「完全格式化 + 重设 PIN」链路（对应 LncaProvider.ResetDevice 的实现顺序）：
    ///   HD_Open → (HD_GET_BCDSN) → HD_IC_RESET → HD_ClearDir(完全格式化)
    ///     → Reload_Pin / HD_ChangePin(重设 PIN) → HD_VerifyPin(验证) → HD_Close
    /// 加 --dry 时只执行到 HD_IC_RESET 与一次 HD_VerifyPin 探测，不做任何破坏性操作。
    /// </summary>
    static int FormatProbe(uint port, string newPin, string sopin, string puk, bool dry)
    {
        string dir = ResolveLncDir();
        SetDllDirectory(dir);
        Console.WriteLine("=== LNCA 完全格式化 + 重设 PIN 探针 ===");
        Console.WriteLine($"port={port}  newPin=\"***\"  SO口令={(string.IsNullOrEmpty(sopin) ? "(未提供)" : "***")}  " +
                          $"PUK={(string.IsNullOrEmpty(puk) ? "(未提供)" : "***")}  dry={dry}");

        IntPtr h = LoadLibrary(Path.Combine(dir, "HDCOS_LNCA.dll"));
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] HDCOS_LNCA.dll 加载失败 err={Marshal.GetLastWin32Error()}"); return 1; }

        var open = Get<HdOpenFn>(h, "HD_Open");
        var close = Get<HdCloseFn>(h, "HD_Close");
        var icReset = Get<HdIcResetFn>(h, "HD_IC_RESET");
        var clearDir = Get<HdClearDirFn>(h, "HD_ClearDir");
        var reloadPin = Get<ReloadPinFn>(h, "Reload_Pin");
        var changePin = Get<HdChangePinFn>(h, "HD_ChangePin");
        var verifyPin = Get<HdVerifyPinFn>(h, "HD_VerifyPin");
        var getSn = Get<HdGetBcdSnFn>(h, "HD_GET_BCDSN");
        var challenge = Get<GetChallengeFn>(h, "Get_Challenge");
        var selectFile = Get<SelectFileFn>(h, "Select_File");
        var extAuth = Get<ExternalAuthFn>(h, "External_Authentication");
        var clearDf = Get<ClearDfFn>(h, "Clear_DF");
        var verifyAdmin = Get<VerifyAdminPinFn>(h, "HDJIT_VerifyAdminPin");
        var jitReload = Get<JitReloadPinFn>(h, "HDJIT_ReloadPin");

        // 1) 打开设备
        IntPtr hCard = open(port);
        Console.WriteLine($"[1] HD_Open({port}) → hCard=0x{hCard.ToInt64():X}");
        if (hCard == IntPtr.Zero) { FreeLibrary(h); return 2; }

        try
        {
            // 2) 序列号
            var sn = new byte[64];
            Console.WriteLine($"[2] HD_GET_BCDSN → 0x{getSn(hCard, sn):X}  sn=\"{ToAscii(sn)}\"");

            // 3) 卡片复位
            var atr = new byte[64];
            Console.WriteLine($"[3] HD_IC_RESET → 0x{icReset(hCard, atr):X}  atr={Convert.ToHexString(atr, 0, Math.Min(16, atr.Length))}");

            if (dry)
            {
                var drc = verifyPin(hCard, Encoding.ASCII.GetBytes("123456"), 6);
                Console.WriteLine($"[dry] HD_VerifyPin(\"123456\") → {drc}（仅探测，不做任何修改）");
                return 0;
            }

            // 4) 完全格式化（首选：内置默认传输密钥）
            int rcClear = clearDir(hCard);
            Console.WriteLine($"[4] HD_ClearDir(内置密钥链路) → 0x{rcClear:X}  {(rcClear == 0 ? "(成功)" : "(失败)")}");

            bool formatted = rcClear == 0;

            if (!formatted)
            {
                // 4b) 逐层诊断：把真实 SW 打出来（0x63Cx 末位 = 剩余重试次数）
                var ch = new byte[16];
                Console.WriteLine($"     诊断 Get_Challenge → rc=0x{challenge(hCard, 8, ch, out var sw1):X} sw=0x{sw1:X4} ch={Convert.ToHexString(ch, 0, 8)}");
                Console.WriteLine($"     诊断 Select_File    → rc=0x{selectFile(hCard, 0, 0, 0, 0, out var sw2):X} sw=0x{sw2:X4}");
                Console.WriteLine($"     诊断 External_Auth(P1=0,试探) → rc=0x{extAuth(hCard, 0, new byte[8], out var sw3):X} sw=0x{sw3:X4}");

                // 4c) 备用链路：SO 口令 → 管理员认证(P1=2) → 直接 Clear_DF
                if (!string.IsNullOrEmpty(sopin))
                {
                    var kb = Encoding.ASCII.GetBytes(sopin);
                    int arc = verifyAdmin(hCard, kb, (uint)kb.Length);
                    Console.WriteLine($"[4c] HDJIT_VerifyAdminPin(SO 口令) → {arc}  {(arc == 0 ? "(管理员认证通过)" : "(口令不匹配)")}");
                    if (arc == 0)
                    {
                        int drc2 = clearDf(hCard, out var dfsw);
                        Console.WriteLine($"[4d] Clear_DF(管理员会话内) → rc=0x{drc2:X} sw=0x{dfsw:X4}");
                        formatted = drc2 >= 0 && dfsw == 0x9000;
                    }
                }
                else
                {
                    Console.WriteLine("[4c] 未提供 SO 口令 → 无法完成 COS 层格式化（本卡默认传输密钥已失效）。");
                }
            }

            if (!formatted)
            {
                Console.WriteLine("[!] COS 层完全格式化未完成，后续 PIN 重设无意义，提前结束。");
                return 4;
            }

            // 5) 重设 PIN：SO 口令路径优先（管理员认证后写入）
            if (!string.IsNullOrEmpty(sopin) && jitReload != null)
            {
                var kb = Encoding.ASCII.GetBytes(sopin);
                if (verifyAdmin(hCard, kb, (uint)kb.Length) == 0)
                {
                    var nb = Encoding.ASCII.GetBytes(newPin);
                    Console.WriteLine($"[5a] HDJIT_ReloadPin(SO 认证后写入新 PIN) → {jitReload(hCard, kb, (uint)kb.Length, nb, (uint)nb.Length)}");
                }
            }

            // 5b) Reload_Pin（INS 0x5E；注意该函数不检查 SW，rc 无成功语义）
            if (!string.IsNullOrEmpty(puk))
            {
                var d1 = Encoding.ASCII.GetBytes(puk + newPin);
                Console.WriteLine($"[5b] Reload_Pin(PUK+新PIN, {d1.Length}B) → 0x{reloadPin(hCard, (uint)d1.Length, d1, IntPtr.Zero):X}");
            }
            var d2 = Encoding.ASCII.GetBytes(newPin);
            Console.WriteLine($"[5c] Reload_Pin(仅新PIN, {d2.Length}B) → 0x{reloadPin(hCard, (uint)d2.Length, d2, IntPtr.Zero):X}");

            // 6) 重设 PIN：HD_ChangePin（旧 0xFF 新）
            foreach (var oldPin in new[] { sopin, puk, "123456" }.Where(s => !string.IsNullOrEmpty(s)).Distinct())
            {
                var ob = Encoding.ASCII.GetBytes(oldPin);
                var nb = Encoding.ASCII.GetBytes(newPin);
                var buf = new byte[ob.Length + 1 + nb.Length];
                Array.Copy(ob, 0, buf, 0, ob.Length);
                buf[ob.Length] = 0xFF;
                Array.Copy(nb, 0, buf, ob.Length + 1, nb.Length);
                Console.WriteLine($"[6] HD_ChangePin(旧长度={ob.Length} + 0xFF + 新) → 0x{changePin(hCard, buf, (uint)buf.Length):X}");
            }

            // 7) 验证新 PIN（唯一判定依据）
            int vrc = verifyPin(hCard, Encoding.ASCII.GetBytes(newPin), (uint)newPin.Length);
            Console.WriteLine($"[7] HD_VerifyPin(新 PIN) → {vrc}  {(vrc == 0 ? "<== 新 PIN 已生效" : "(未生效：0=成功, -1=PIN已锁定/计数耗尽, -1000=其他失败)")}");
            return vrc == 0 ? 0 : 3;
        }
        finally
        {
            close(hCard);
            FreeLibrary(h);
            Console.WriteLine("=== 完成 ===");
        }
    }

    static string ToAscii(byte[] buf)
    {
        int end = Array.IndexOf(buf, (byte)0);
        if (end < 0) end = buf.Length;
        return Encoding.ASCII.GetString(buf, 0, end).Trim();
    }

    static string StateName(uint st) => st switch
    {
        0 => "KEY_OFFLINE",
        1 => "KEY_LOGIN/ONLINE",
        2 => "KEY_ONLINE/LOGIN",
        _ => "?"
    };

    /// <summary>
    /// 实测 HD_HardAPI.dll：连接 → 验证 PIN → 查序列号/容量 → 文件操作 → 擦除。
    /// 用于动态确认 HS 层函数签名与「删除证书 / 初始化重置」的正确调用。
    /// </summary>
    static int HardApiProbe(string pin)
    {
        string dll = Path.Combine(ResolveLncDir(), "HD_HardAPI.dll");
        Console.WriteLine("=== HD_HardAPI 探针 ===");
        Console.WriteLine($"DLL: {dll}  PIN: {pin}");
        IntPtr h = LoadLibrary(dll);
        if (h == IntPtr.Zero) { Console.WriteLine($"[!] LoadLibrary 失败 err={Marshal.GetLastWin32Error()}"); return 1; }
        Console.WriteLine($"[+] LoadLibrary OK handle=0x{h:X}");

        var connect = Get<HSConnectDevFn>(h, "HSConnectDev");
        var disconnect = Get<HSDisconnectDevFn>(h, "HSDisconnectDev");
        var erase = Get<HSEraseFn>(h, "HSErase");
        var verifyPin = Get<HSVerifyUserPinFn>(h, "HSVerifyUserPin");
        var verifySo = Get<HSVerifySOPinFn>(h, "HSVerifySOPin");
        var changePin = Get<HSChangeUserPinFn>(h, "HSChangeUserPin");
        var getSerial = Get<HSGetSerialFn>(h, "HSGetSerial");
        var getTotal = Get<HSGetTotalSizeFn>(h, "HSGetTotalSize");
        var getFree = Get<HSGetFreeSizeFn>(h, "HSGetFreeSize");
        var hasFile = Get<HSHasFileExistFn>(h, "HSHasFileExist");
        var delFile = Get<HSDeleteFileFn>(h, "HSDeleteFile");
        var createFile = Get<HSCreateFileFn>(h, "HSCreateFile");
        var writeFile = Get<HSWriteFileFn>(h, "HSWriteFile");
        var readFile = Get<HSReadFileFn>(h, "HSReadFile");

        // 1) 连接（尝试多个 devIndex）
        IntPtr hDev = IntPtr.Zero;
        int rc = -1;
        for (uint i = 0; i < 8; i++)
        {
            rc = connect(i, out hDev);
            Console.WriteLine($"[1] HSConnectDev(idx={i}) rc=0x{rc:X} hDev=0x{hDev:X}");
            if (rc == 0 && hDev != IntPtr.Zero) break;
        }
        if (rc != 0 || hDev == IntPtr.Zero) { Console.WriteLine("[!] Connect 失败"); FreeLibrary(h); return 2; }

        // 2) 序列号 / 容量
        var sb = new StringBuilder(64); uint snLen = 64;
        rc = getSerial(hDev, sb, ref snLen);
        Console.WriteLine($"[2] HSGetSerial rc=0x{rc:X} sn=\"{sb}\" len={snLen}");
        uint total = 0, free = 0;
        rc = getTotal(hDev, out total);
        Console.WriteLine($"[3] HSGetTotalSize rc=0x{rc:X} total={total}");
        rc = getFree(hDev, out free);
        Console.WriteLine($"[4] HSGetFreeSize rc=0x{rc:X} free={free}");

        // 3) 验证用户 PIN（登录态，删除/擦除前置条件）
        rc = verifyPin(hDev, pin);
        Console.WriteLine($"[5] HSVerifyUserPin rc=0x{rc:X}");

        // 4) 探测常见文件名是否存在（证书可能以固定文件名存储）
        foreach (var name in new[] { "Cert_0", "Cert_1", "0", "1", "c0", "c1", "cert0", "cert1", "k0", "k1" })
        {
            uint exist = 0xFFFFFFFF;
            int r2 = hasFile(hDev, name, out exist);
            Console.WriteLine($"[6] HSHasFileExist(\"{name}\") rc=0x{r2:X} exist={exist}");
        }

        // 5) 创建一个测试文件并删除（验证 HSCreateFile/HSWriteFile/HSDeleteFile 签名）
        const string testFile = "probe_test";
        rc = createFile(hDev, testFile, (uint)testFile.Length, 32, 0, 0);
        Console.WriteLine($"[7] HSCreateFile(\"{testFile}\", size=32) rc=0x{rc:X}");
        var wdata = new byte[] { 1, 2, 3, 4 };
        rc = writeFile(hDev, testFile, wdata, (uint)wdata.Length);
        Console.WriteLine($"[8] HSWriteFile rc=0x{rc:X}");
        var rdata = new byte[32]; uint rlen = 32;
        rc = readFile(hDev, testFile, rdata, ref rlen);
        Console.WriteLine($"[9] HSReadFile rc=0x{rc:X} len={rlen} data={Convert.ToHexString(rdata, 0, (int)Math.Min(rlen, rdata.Length))}");
        rc = delFile(hDev, testFile);
        Console.WriteLine($"[10] HSDeleteFile(\"{testFile}\") rc=0x{rc:X}");

        // 6) 断开
        rc = disconnect(hDev);
        Console.WriteLine($"[11] HSDisconnectDev rc=0x{rc:X}");

        FreeLibrary(h);
        Console.WriteLine("=== HardAPI 完成 ===");
        return 0;
    }
}
