using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace GM3000Probe;

/// <summary>
/// GM3000（龙脉 Longmai）SDK 独立探针。
/// 目的：在集成进 USBKey.Manager 之前，用最小风险的方式确认
/// 「哪一套 DLL 能枚举到当前设备」以及各导出接口的真实语义。
/// 全部调用都用裸缓冲区，避免结构体布局猜错导致崩溃。
/// </summary>
internal static class Program
{
    private static int _fail;

    private static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine($"=== GM3000 Probe === x86={!Environment.Is64BitProcess} " +
                          $"bits={IntPtr.Size * 8} pid={Environment.ProcessId}");
        Console.WriteLine();

        const string sdk = @"g:\Codes\USBKeyDriver\Library\Longmai GM3000 SDK";
        var p11_16 = Path.Combine(sdk, @"GM3000_2.1.1.0\gm3000_pkcs11.dll");
        var p11_22 = Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll");
        var skf_16 = Path.Combine(sdk, @"GM3000_2.1.1.0\mtoken_GM.dll");
        var skf_22 = Path.Combine(sdk, @"GM3000_2.2.19\mtoken_gm3000.dll.old");
        var tm_16 = Path.Combine(sdk, @"GM3000_2.1.1.0\TokenMgr.dll");
        var tm_22 = Path.Combine(sdk, @"GM3000_2.2.19\tokenmgr.dll");

        var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
        try
        {
            switch (mode)
            {
                case "scan":
                    Scan(args.Length > 1 ? args[1] : null);
                    break;
                case "p11":
                    ProbePkcs11(args[1], false);
                    break;
                case "p11init":
                    ProbePkcs11(args[1], true);
                    break;
                case "wins":
                    ProbeWindows(args.Length > 1 ? args[1] : "GM3000Admin");
                    break;
                case "devinfo":
                    ProbeDevInfo(args.Length > 1 ? args[1] : skf_16);
                    break;
                case "skf":
                    ProbeSkf(args[1]);
                    break;
                case "skfpin":
                    ProbeSkfPin(args.Length > 1 ? args[1] : skf_16,
                                args.Length > 2 ? uint.Parse(args[2]) : 0u,
                                args.Length > 3 ? args[3] : "");
                    break;
                case "initflow":
                    ProbeInitFlow(args.Length > 1
                                      ? args[1]
                                      : Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll"),
                                  args.Length > 2 ? args[2] : "admin",
                                  args.Length > 3 ? args[3] : "12345678");
                    break;
                case "skfhandle":
                    ProbeSkfHandle(args.Length > 1 ? args[1] : skf_16,
                                   args.Length > 2 ? args[2] : null);
                    break;
                case "tm":
                    ProbeTokenMgr(args[1], args[2]);
                    break;
                case "tmfix":
                    ProbeTmFix(args.Length > 1 ? args[1] : tm_22,
                               args.Length > 2 ? args[2] : p11_22,
                               args.Length > 3 ? args[3] : "admin");
                    break;
                case "ckobj":
                    ProbeCkObjects(args.Length > 1
                                       ? args[1]
                                       : Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll"),
                                   args.Length > 2 ? args[2] : "ZZOBJTEST");
                    break;
                case "provider":
                    ProbeProvider();
                    break;
                case "tmstyle":
                    ProbeTokenMgrStyle(args[1]);
                    break;
                case "tables":
                    ProbeTables(args[1]);
                    break;
                case "shimabi":
                    ProbeShimAbi(args.Length > 1
                                     ? args[1]
                                     : Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll"),
                                 args.Length > 2 ? args[2] : null);
                    break;
                case "sectors":
                    ProbeSectors(args.Length > 1
                                     ? args[1]
                                     : Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll"),
                                 args.Length > 2 ? uint.Parse(args[2]) : 0u);
                    break;
                case "skfcerts":
                    ProbeSkfCerts(args.Length > 1 ? args[1] : skf_16,
                                  args.Length > 2 ? args[2] : "GM3000APP");
                    break;
                case "skfcont":
                    ProbeSkfContainer(args.Length > 1 ? args[1] : skf_16,
                                      args.Length > 2 ? args[2] : "admin",
                                      args.Length > 3 ? args[3] : "12345678");
                    break;
                case "adminfix":
                    ProbeAdminFix(args.Length > 1
                                      ? args[1]
                                      : Path.Combine(sdk, @"GM3000_2.2.19\gm3000_pkcs11.dll"),
                                  args.Length > 2
                                      ? args[2]
                                      : Path.Combine(sdk, @"GM3000_2.2.19\mtoken_gm3000.dll"),
                                  args.Length > 3 ? args[3] : "admin");
                    break;
                case "all":
                    ProbePkcs11(p11_16, false);
                    ProbePkcs11(p11_16, true);
                    ProbePkcs11(p11_22, false);
                    ProbePkcs11(p11_22, true);
                    ProbeSkf(skf_16);
                    ProbeSkf(skf_22);
                    ProbeTokenMgr(tm_16, p11_16);
                    ProbeTokenMgr(tm_22, p11_22);
                    break;
                default:
                    Console.WriteLine("用法: GM3000Probe [scan [dir] | p11 <dll> | p11init <dll> | skf <dll> | tm <tokenmgr.dll> <pkcs11.dll> | all]");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"!! 异常: {ex.Message}");
            _fail++;
        }

        Console.WriteLine();
        Console.WriteLine($"完成（失败项 {_fail}）。");
    }

    // ------------------------------------------------------------ 扫描

    /// <summary>直接调用 Manager 的 <c>Gm3000Provider</c>，验证真实代码路径（只读操作）。</summary>
    private static void ProbeProvider()
    {
        Console.WriteLine("---- Gm3000Provider（Manager 真实实现，只读路径）");
        using var p = new USBKey.Core.UsbKey.Gm3000Provider(
            Path.Combine(AppContext.BaseDirectory, "Library"), null);

        Console.WriteLine($"   PlatformName={p.PlatformName}  IsAvailable={p.IsAvailable}");
        p.Initialize();

        var devs = p.Enumerate();
        Console.WriteLine($"   设备数={devs.Count}");
        foreach (var d in devs)
        {
            Console.WriteLine($"   == {d}");
            Console.WriteLine($"      Vendor={d.VendorName} Model={d.Model} SN={d.SerialNumber} " +
                              $"FW={d.FirmwareVersion} Notes={d.Notes}");
            p.GetDetail(d);
            Console.WriteLine($"      GetDetail → Notes={d.Notes}");
            var conts = p.ListContainers(d);
            Console.WriteLine($"      容器数={conts.Count}");
            foreach (var c in conts)
                Console.WriteLine($"         {c.ContainerName} | {c.Name} | {c.Subject} | {c.KeyUsage}");
        }
        Console.WriteLine("   （只读验证：未执行任何 PIN/解锁/重置/导入写操作）");
    }

    private static IEnumerable<string> CandidateDlls(string extraDir)
    {
        const string sdk = @"g:\Codes\USBKeyDriver\Library\Longmai GM3000 SDK";
        var dirs = new List<string>
        {
            Path.Combine(sdk, "GM3000_2.1.1.0"),
            Path.Combine(sdk, "GM3000_2.2.19"),
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64",
        };
        if (!string.IsNullOrWhiteSpace(extraDir)) dirs.Insert(0, extraDir);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in dirs)
        {
            if (!Directory.Exists(d)) continue;
            foreach (var f in Directory.EnumerateFiles(d, "*.dll"))
            {
                var n = Path.GetFileName(f);
                if (n is "gm3000_pkcs11.dll" or "mtoken_gm3000.dll" or "mtoken_GM.dll"
                    or "TokenMgr.dll" or "tokenmgr.dll" or "GM3000HZTWCSP.dll")
                {
                    if (seen.Add(f)) yield return f;
                }
            }
        }
    }

    private static void Scan(string extraDir)
    {
        foreach (var dll in CandidateDlls(extraDir))
        {
            Console.WriteLine($"---- {dll}");
            var h = Native.Load(dll);
            if (h == IntPtr.Zero)
            {
                Console.WriteLine($"   [x] LoadLibrary 失败 (err={Marshal.GetLastWin32Error()})");
                _fail++;
                continue;
            }
            try
            {
                var isSkf = Native.Proc(h, "SKF_EnumDev") != IntPtr.Zero;
                var isP11 = Native.Proc(h, "C_GetSlotList") != IntPtr.Zero;
                var isTm = Native.Proc(h, "token_find") != IntPtr.Zero;
                Console.WriteLine($"   导出: SKF={(isSkf ? "Y" : "-")} PKCS11={(isP11 ? "Y" : "-")} TokenMgr={(isTm ? "Y" : "-")}");
                if (isSkf) TrySkfEnum(h, "      ");
                if (isP11) Slots(h, "      ");
            }
            finally { Native.Free(h); }
        }
    }

    // ------------------------------------------------------------ SKF

    /// <summary>
    /// 零风险判定「各 SKF 函数要求哪种句柄」。本厂商的 SKF 会校验句柄种类：
    /// 传错种类返回 <c>SAR_INVALIDHANDLEERR = 0xA000005</c>（报告 §九-5 已实测：
    /// <c>SKF_GetPINInfo</c> 传设备句柄即返回该码，必须传应用句柄）。
    /// 探针刻意选用两个**无副作用且不消耗 PIN 重试次数**的函数：
    /// <c>SKF_ClearSecureState</c>（仅清除已认证状态）与 <c>SKF_GenRandom</c>（仅取随机数）。
    /// 结论用于修正垫片与 Manager 中 <c>VerifyPIN / ChangePIN / UnblockPIN</c> 所传句柄。
    /// </summary>
    private static void ProbeSkfHandle(string dll, string pin)
    {
        Console.WriteLine($"---- SKF 句柄种类判定：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var enumApp = Native.Del<SkfEnumAppFn>(h, "SKF_EnumApplication");
            var openApp = Native.Del<SkfOpenAppFn>(h, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(h, "SKF_CloseApplication");
            var genRandom = Native.Del<SkfGenRandomFn>(h, "SKF_GenRandom");
            var pinInfo = Native.Del<SkfGetPINInfoFn>(h, "SKF_GetPINInfo");
            var clearState = Native.Del<SkfClearSecureStateFn>(h, "SKF_ClearSecureState");
            var verifyPin = Native.Del<SkfVerifyPinFn>(h, "SKF_VerifyPIN");
            if (enumDev == null || connect == null) { Console.WriteLine("   [x] 缺少枚举/连接导出"); _fail++; return; }

            var names = EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 未枚举到设备"); _fail++; return; }

            var crc = connect(names[0], out var hDev);
            Console.WriteLine($"   ConnectDev rc=0x{crc:X8} hDev=0x{hDev:X}");
            if (crc != 0 || hDev == IntPtr.Zero) { _fail++; return; }

            try
            {
                var appList = Marshal.AllocHGlobal(0x400);
                var hApp = IntPtr.Zero;
                try
                {
                    uint sz = 0x400;
                    var erc = enumApp(hDev, appList, ref sz);
                    var appName = Ansi(appList, 64);
                    Console.WriteLine($"   EnumApplication rc=0x{erc:X8} app='{appName}'");
                    if (openApp != null)
                    {
                        var orc = openApp(hDev, appName, out hApp);
                        Console.WriteLine($"   OpenApplication('{appName}') rc=0x{orc:X8} hApp=0x{hApp:X}");
                    }
                    if (hApp == IntPtr.Zero) { _fail++; return; }

                    var buf = new byte[16];
                    if (clearState != null)
                    {
                        Console.WriteLine($"   ClearSecureState(hDev) rc=0x{clearState(hDev):X8}   <- 0xA000005 即「种类不符，需要应用句柄」");
                        Console.WriteLine($"   ClearSecureState(hApp) rc=0x{clearState(hApp):X8}   <- 0x0 即「应用句柄正确」");
                    }
                    if (genRandom != null)
                    {
                        // GenRandom(hApp) 会直接崩溃（0xC0000005）：本厂商对「不校验句柄种类」的函数
                        // 按句柄直接解引用。因此绝不能用错种类去盲试，必须实测确认后再调用。
                        Console.WriteLine($"   GenRandom(hDev) rc=0x{genRandom(hDev, buf, 16):X8}   <- 设备句柄正确（传应用句柄会崩）");
                    }
                    if (pinInfo != null)
                    {
                        uint a = 0, b = 0, c = 0;
                        Console.WriteLine($"   GetPINInfo(hDev,0) rc=0x{pinInfo(hDev, 0, ref a, ref b, ref c):X8}");
                        a = 0; b = 0; c = 0;
                        var prc = pinInfo(hApp, 0, ref a, ref b, ref c);
                        Console.WriteLine($"   GetPINInfo(hApp,0) rc=0x{prc:X8} 剩余={a}/{b} 默认口令={c}");
                    }

                    // VerifyPIN 本身要哪种句柄？仅在显式给了口令时才测，避免误消耗重试次数。
                    // 说明：用「正确口令」测，正确则两次都不扣次数；若口令本就错误，
                    // 传应用句柄的那次会真实消耗 1 次（传错句柄那次返回 0xA000005，不扣）。
                    if (verifyPin != null && !string.IsNullOrEmpty(pin))
                    {
                        uint r1 = 999, r2 = 999;
                        var v1 = verifyPin(hDev, 1, pin, ref r1);
                        Console.WriteLine($"   VerifyPIN(hDev, pinType=1/SO) rc=0x{v1:X8} retry={r1}");
                        var v2 = verifyPin(hApp, 1, pin, ref r2);
                        Console.WriteLine($"   VerifyPIN(hApp, pinType=1/SO) rc=0x{v2:X8} retry={r2}");
                        if (clearState != null) Console.WriteLine($"   ClearSecureState(hApp) 复位 rc=0x{clearState(hApp):X8}");
                    }
                }
                finally { Marshal.FreeHGlobal(appList); }
                if (hApp != IntPtr.Zero && closeApp != null) closeApp(hApp);
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 单次 PIN 验证实验：<c>skfpin &lt;dll&gt; &lt;pinType&gt; &lt;pin&gt;</c>。
    /// 验证前后各打印一次「pinType=0 / pinType=1」的剩余次数，用于精确归因：
    /// 哪一次尝试扣减了哪一个槽位，从而判定 pinType 数字含义（0/1 谁是管理员）。
    /// 注意：口令不正确会真实消耗 1 次重试（出厂各 10 次）。
    /// </summary>
    private static void ProbeSkfPin(string dll, uint pinType, string pin)
    {
        Console.WriteLine($"---- SKF 单次验证：{dll}  pinType={pinType} pin={(string.IsNullOrEmpty(pin) ? "(空)" : "***")}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var enumApp = Native.Del<SkfEnumAppFn>(h, "SKF_EnumApplication");
            var openApp = Native.Del<SkfOpenAppFn>(h, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(h, "SKF_CloseApplication");
            var pinInfo = Native.Del<SkfGetPINInfoFn>(h, "SKF_GetPINInfo");
            var verifyPin = Native.Del<SkfVerifyPinFn>(h, "SKF_VerifyPIN");
            var clearState = Native.Del<SkfClearSecureStateFn>(h, "SKF_ClearSecureState");

            var names = EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 未枚举到设备"); _fail++; return; }
            if (connect(names[0], out var hDev) != 0 || hDev == IntPtr.Zero) { _fail++; return; }

            try
            {
                var appList = Marshal.AllocHGlobal(0x400);
                var hApp = IntPtr.Zero;
                try
                {
                    uint sz = 0x400;
                    enumApp(hDev, appList, ref sz);
                    var appName = Ansi(appList, 64);
                    if (openApp != null && openApp(hDev, appName, out hApp) != 0) hApp = IntPtr.Zero;
                    Console.WriteLine($"   设备已连接 hDev=0x{hDev:X} 应用='{appName}' hApp=0x{hApp:X}");
                    if (hApp == IntPtr.Zero) { _fail++; return; }

                    void ShowCounts(string tag)
                    {
                        uint a0 = 0, b0 = 0, c0 = 0, a1 = 0, b1 = 0, c1 = 0;
                        var r0 = pinInfo(hApp, 0, ref a0, ref b0, ref c0);
                        var r1 = pinInfo(hApp, 1, ref a1, ref b1, ref c1);
                        Console.WriteLine($"   {tag}: pinType=0 rc=0x{r0:X8} 剩余={a0}/{b0} 默认={c0} ; " +
                                          $"pinType=1 rc=0x{r1:X8} 剩余={a1}/{b1} 默认={c1}");
                    }

                    ShowCounts("验证前");
                    uint retry = 999;
                    var rc = verifyPin(hApp, pinType, pin, ref retry);
                    Console.WriteLine($"   VerifyPIN(hApp, pinType={pinType}) rc=0x{rc:X8}  (报错时 retry={retry})");
                    ShowCounts("验证后");

                    if (clearState != null) clearState(hApp);
                }
                finally { Marshal.FreeHGlobal(appList); }
                if (hApp != IntPtr.Zero && closeApp != null) closeApp(hApp);
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 复刻 GM3000Admin 的「初始化」调用序列（由 TokenMgr 反汇编确认）：
    /// <c>C_Login(CKU_SO) → 扩展表[4] M_FormatToken(handle, arg2) → C_InitPIN(新用户口令) → C_Logout</c>。
    /// 默认用出厂用户口令 <c>12345678</c> 当「新用户口令」，即保持口令不变，避免误改。
    /// </summary>
    private static void ProbeInitFlow(string dll, string soPin, string newUserPin)
    {
        Console.WriteLine($"---- 初始化流程复刻：{dll}");
        Console.WriteLine($"   SO 口令长度={soPin.Length}  新用户口令长度={newUserPin.Length}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var getExt = Native.Del<M_GetExtListFn1>(h, "M_GetExtFunctionList");
            var pList = IntPtr.Zero;
            getList(ref pList);
            var init = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(Marshal.ReadIntPtr(pList, 2));
            Console.WriteLine($"   C_Initialize → rc=0x{init(IntPtr.Zero):X8}");

            var openSess = Marshal.GetDelegateForFunctionPointer<C_OpenSessionFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 12));
            uint sess = 0;
            Console.WriteLine($"   C_OpenSession(0, flags=6) → rc=0x{openSess(0, 6, IntPtr.Zero, IntPtr.Zero, ref sess):X8} session={sess}");

            var login = Marshal.GetDelegateForFunctionPointer<C_LoginFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 18));
            Console.WriteLine($"   C_Login(CKU_SO, len={soPin.Length}) → rc=0x{login(sess, 0, soPin, (uint)soPin.Length):X8}");

            var ext = IntPtr.Zero;
            getExt(ref ext);
            var fn4 = Marshal.ReadIntPtr(ext, 4 + 4 * 4);
            var fn0 = Marshal.ReadIntPtr(ext, 4 + 4 * 0);
            var format = Marshal.GetDelegateForFunctionPointer<M_FormatTokenFn>(fn4);
            Console.WriteLine($"   ext[4] M_FormatToken(handle=0, arg2=0) → rc=0x{format(0, IntPtr.Zero):X8}");

            var initPin = Marshal.GetDelegateForFunctionPointer<C_InitPinFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 10));
            Console.WriteLine($"   C_InitPIN(session={sess}, len={newUserPin.Length}) → rc=0x{initPin(sess, newUserPin, (uint)newUserPin.Length):X8}");

            var logout = Marshal.GetDelegateForFunctionPointer<C_LogoutFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 19));
            Console.WriteLine($"   C_Logout(session={sess}) → rc=0x{logout(sess):X8}");

            // 收尾核对：两种口令的剩余次数与锁定标志
            var pinState = Marshal.GetDelegateForFunctionPointer<M_GetUserInfoFn>(fn0);
            var st = Marshal.AllocHGlobal(12);
            try
            {
                foreach (var pt in new uint[] { 0, 1 })
                {
                    for (var i = 0; i < 12; i++) Marshal.WriteByte(st, i, 0xEE);
                    var rc = pinState(0, pt, st);
                    Console.WriteLine($"   收尾核对 ext[0](pinType={pt}) rc=0x{rc:X8} " +
                                      $"剩余={Marshal.ReadInt32(st, 0)} 上限={Marshal.ReadInt32(st, 4)} " +
                                      $"已锁定={Marshal.ReadByte(st, 10)}");
                }
            }
            finally { Marshal.FreeHGlobal(st); }
        }
        finally { Native.Free(h); }
    }

    // ------------------------------------------------------------ 窗口枚举（读上层对话框/标签文本）

    private delegate bool EnumWindowsProc(IntPtr h, IntPtr p);

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);

    /// <summary>
    /// 枚举目标进程的顶层窗口与子控件文本，用来在无法截图的环境里读上层（Admin/TokenMgr）
    /// 弹出的对话框与标签内容。
    /// </summary>
    private static void ProbeWindows(string processName)
    {
        var procs = System.Diagnostics.Process.GetProcessesByName(processName);
        if (procs.Length == 0) { Console.WriteLine($"   [x] 未找到进程 {processName}"); _fail++; return; }
        var pids = new HashSet<uint>(procs.Select(p => (uint)p.Id));
        Console.WriteLine($"---- 窗口枚举：{processName} 进程数={procs.Length}");
        EnumWindows((h, _) =>
        {
            GetWindowThreadProcessId(h, out var pid);
            if (pids.Contains(pid)) DumpWindow(h, 0);
            return true;
        }, IntPtr.Zero);
    }

    private static void DumpWindow(IntPtr h, int depth)
    {
        var sb = new StringBuilder(512);
        GetWindowTextW(h, sb, 512);
        var cn = new StringBuilder(256);
        GetClassNameW(h, cn, 256);
        var txt = sb.ToString();
        var cls = cn.ToString();
        var vis = IsWindowVisible(h) ? "可见" : "隐藏";
        // 只打印有文本的控件 + 所有顶层窗口，避免刷屏
        if (txt.Length > 0 || depth == 0)
            Console.WriteLine($"{new string(' ', depth * 2)}[{vis}] {cls} '{txt}'");
        EnumChildWindows(h, (c, _) => { DumpWindow(c, depth + 1); return true; }, IntPtr.Zero);
    }

    /// <summary>
    /// 转储设备 DEVINFO（<c>SKF_GetDevInfo</c>）原始字节，用于定位
    /// 「总/剩余空间、硬件/固件版本、最小密码长度」等字段的真实偏移。
    /// </summary>
    private static void ProbeDevInfo(string dll)
    {
        Console.WriteLine($"---- DEVINFO 转储：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var devInfo = Native.Del<SkfGetDevInfoFn>(h, "SKF_GetDevInfo");
            var names = EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 未枚举到设备"); _fail++; return; }
            if (connect(names[0], out var hDev) != 0 || hDev == IntPtr.Zero) { _fail++; return; }
            try
            {
                const int n = 320;
                var buf = Marshal.AllocHGlobal(n);
                try
                {
                    for (var i = 0; i < n; i++) Marshal.WriteByte(buf, i, 0);
                    var rc = devInfo(hDev, buf);
                    Console.WriteLine($"   SKF_GetDevInfo rc=0x{rc:X8}");
                    if (rc != 0) return;
                    for (var off = 0; off < n; off += 16)
                    {
                        var hex = new StringBuilder();
                        var asc = new StringBuilder();
                        for (var i = 0; i < 16 && off + i < n; i++)
                        {
                            var b = Marshal.ReadByte(buf, off + i);
                            hex.Append(b.ToString("X2")).Append(' ');
                            asc.Append(b >= 0x20 && b < 0x7f ? (char)b : '.');
                        }
                        Console.WriteLine($"   +0x{off:X3}  {hex,-48} {asc}");
                    }
                    // 顺手把几个候选值按不同偏移解释出来
                    Console.WriteLine("   ---- 候选：32 位整数 == 131072(128KB) 的偏移 ----");
                    for (var off = 0; off + 4 <= n; off++)
                        if ((uint)Marshal.ReadInt32(buf, off) == 131072u)
                            Console.WriteLine($"      +0x{off:X3} = 0x20000");
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(h); }
    }

    private static void ProbeSkf(string dll)
    {
        Console.WriteLine($"---- SKF {dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var devInfo = Native.Del<SkfGetDevInfoFn>(h, "SKF_GetDevInfo");
            var devState = Native.Del<SkfGetDevStateFn>(h, "SKF_GetDevState");
            var enumCont = Native.Del<SkfEnumContainerFn>(h, "SKF_EnumContainer");
            var genRandom = Native.Del<SkfGenRandomFn>(h, "SKF_GenRandom");
            var pinInfo = Native.Del<SkfGetPINInfoFn>(h, "SKF_GetPINInfo");
            var enumApp = Native.Del<SkfEnumAppFn>(h, "SKF_EnumApplication");
            var openApp = Native.Del<SkfOpenAppFn>(h, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(h, "SKF_CloseApplication");
            var openCont = Native.Del<SkfOpenContFn>(h, "SKF_OpenContainer");
            var closeCont = Native.Del<SkfCloseContFn>(h, "SKF_CloseContainer");
            var contType = Native.Del<SkfGetContainerTypeFn>(h, "SKF_GetContainerType");
            var exportCert = Native.Del<SkfExportCertFn>(h, "SKF_ExportCertificate");

            var names = enumDev == null ? new List<string>() : EnumDevNames(enumDev, "   ");
            Console.WriteLine($"   设备数={names.Count}");
            if (names.Count == 0) { _fail++; return; }

            foreach (var name in names)
            {
                Console.WriteLine($"   == 设备名: {name}");
                if (devState != null)
                {
                    var rc = devState(name, out var st);
                    Console.WriteLine($"      GetDevState rc=0x{rc:X8} state={st}");
                }
                if (connect == null) continue;
                var crc = connect(name, out var hDev);
                Console.WriteLine($"      ConnectDev rc=0x{crc:X8} hDev=0x{hDev:X}");
                if (crc != 0 || hDev == IntPtr.Zero) continue;

                try
                {
                    if (devInfo != null)
                    {
                        using var ub = new UB(1024);
                        var rc = devInfo(hDev, ub.Ptr);
                        ub.ReadBack();
                        Console.WriteLine($"      GetDevInfo rc=0x{rc:X8}");
                        Console.WriteLine("        可读串: " + JoinStrings(ub.Data));
                        File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "devinfo.bin"), ub.Data);
                    }
                    if (pinInfo != null)
                    {
                        uint a = 0, b = 0, c = 0;
                        var rc = pinInfo(hDev, 0, ref a, ref b, ref c);
                        Console.WriteLine($"      GetPINInfo(hDev,pinType=0) rc=0x{rc:X8} a={a} b={b} c={c}");
                    }
                    if (genRandom != null)
                    {
                        var rnd = new byte[16];
                        var rc = genRandom(hDev, rnd, 16);
                        Console.WriteLine($"      GenRandom rc=0x{rc:X8} {BitConverter.ToString(rnd)}");
                    }

                    // ---- 标准 SKF：应用 → 容器 → 证书 ----
                    var apps = new List<string>();
                    if (enumApp != null)
                    {
                        using var ub = new UB(4096);
                        uint size = (uint)ub.Data.Length;
                        var rc = enumApp(hDev, ub.Ptr, ref size);
                        ub.ReadBack();
                        Console.WriteLine($"      EnumApplication rc=0x{rc:X8} size={size}");
                        apps = ReadMultiString(ub.Data, (int)Math.Min(size, (uint)ub.Data.Length));
                        foreach (var s in apps) Console.WriteLine($"        应用: {s}");
                    }

                    foreach (var app in apps.DefaultIfEmpty(""))
                    {
                        if (openApp == null) break;
                        var arc = openApp(hDev, app, out var hApp);
                        Console.WriteLine($"      OpenApplication('{app}') rc=0x{arc:X8} hApp=0x{hApp:X}");
                        if (arc != 0 || hApp == IntPtr.Zero) continue;

                        if (pinInfo != null)
                        {
                            uint a = 0, b = 0, c = 0;
                            var rc = pinInfo(hApp, 0, ref a, ref b, ref c);
                            Console.WriteLine($"      GetPINInfo(hApp,pinType=0) rc=0x{rc:X8} a={a} b={b} c={c}");
                        }

                        var conts = new List<string>();
                        if (enumCont != null)
                        {
                            using var ub = new UB(4096);
                            uint size = (uint)ub.Data.Length;
                            var rc = enumCont(hApp, ub.Ptr, ref size);
                            ub.ReadBack();
                            Console.WriteLine($"      EnumContainer rc=0x{rc:X8} size={size}");
                            conts = ReadMultiString(ub.Data, (int)Math.Min(size, (uint)ub.Data.Length));
                            foreach (var s in conts) Console.WriteLine($"        容器: {s}");
                        }

                        foreach (var c in conts)
                        {
                            if (openCont == null) break;
                            var crc2 = openCont(hApp, c, out var hCont);
                            Console.WriteLine($"      OpenContainer('{c}') rc=0x{crc2:X8} hCont=0x{hCont:X}");
                            if (crc2 != 0 || hCont == IntPtr.Zero) continue;

                            if (contType != null)
                            {
                                var trc = contType(hCont, out var ct);
                                Console.WriteLine($"         GetContainerType rc=0x{trc:X8} type={ct}");
                            }
                            if (exportCert != null)
                            {
                                foreach (var sign in new[] { false, true })
                                {
                                    using var ub = new UB(8192);
                                    uint len = (uint)ub.Data.Length;
                                    var erc = exportCert(hCont, sign, ub.Ptr, ref len);
                                    ub.ReadBack();
                                    Console.WriteLine($"         ExportCertificate(sign={sign}) rc=0x{erc:X8} len={len}");
                                    if (erc == 0 && len > 4)
                                        Console.WriteLine($"           DER 头: {BitConverter.ToString(ub.Data, 0, Math.Min(12, (int)len))}");
                                }
                            }
                            closeCont?.Invoke(hCont);
                        }
                        closeApp?.Invoke(hApp);
                    }
                }
                finally
                {
                    var drc = disconnect?.Invoke(hDev) ?? -1;
                    Console.WriteLine($"      DisConnectDev rc=0x{drc:X8}");
                }
            }
        }
        finally { Native.Free(h); }
    }

    private static bool TrySkfEnum(IntPtr h, string indent)
    {
        var fn = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
        if (fn == null) { Console.WriteLine($"{indent}SKF_EnumDev 解析失败"); return false; }
        var names = EnumDevNames(fn, indent);
        Console.WriteLine($"{indent}SKF_EnumDev 设备数={names.Count}");
        foreach (var n in names) Console.WriteLine($"{indent}  -> {n}");
        return names.Count > 0;
    }

    private static List<string> EnumDevNames(SkfEnumDevFn fn, string indent)
    {
        using var ub = new UB(0x2000);
        uint size = (uint)ub.Data.Length;
        var rc = fn(true, ub.Ptr, ref size);
        ub.ReadBack();
        Console.WriteLine($"{indent}EnumDev rc=0x{rc:X8} size={size}");
        if (rc != 0) return new List<string>();
        return ReadMultiString(ub.Data, (int)Math.Min(size, (uint)ub.Data.Length));
    }

    private static List<string> ReadMultiString(byte[] buf, int len)
    {
        var res = new List<string>();
        int start = 0;
        for (int i = 0; i < len; i++)
        {
            if (buf[i] != 0) continue;
            if (i == start) break;
            res.Add(Encoding.ASCII.GetString(buf, start, i - start));
            start = i + 1;
        }
        return res;
    }

    private static string JoinStrings(byte[] buf)
    {
        var parts = new List<string>();
        int start = -1;
        for (int i = 0; i < buf.Length; i++)
        {
            var printable = buf[i] >= 0x20 && buf[i] < 0x7f;
            if (printable && start < 0) start = i;
            else if (!printable && start >= 0)
            {
                if (i - start >= 3) parts.Add(Encoding.ASCII.GetString(buf, start, i - start));
                start = -1;
            }
            if (parts.Count >= 12) break;
        }
        return string.Join(" | ", parts);
    }

    // ------------------------------------------------------------ PKCS#11

    /// <summary>
    /// 确定 <c>SKF_CreateContainer</c> 的前置条件：本设备究竟要求哪种口令的「已验证」状态。
    /// 依次尝试「不验证 / 先验用户口令 / 先验管理员口令」，每轮前后用 ClearSecureState 复位，
    /// 逐步打印返回码——用于判定垫片里「建容器返回未登录(0x0A00002D)」是设备要求还是垫片缺陷。
    /// </summary>
    private static void ProbeSkfContainer(string dll, string soPin, string userPin)
    {
        Console.WriteLine($"---- SKF 建容器前置条件：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var enumApp = Native.Del<SkfEnumAppFn>(h, "SKF_EnumApplication");
            var openApp = Native.Del<SkfOpenAppFn>(h, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(h, "SKF_CloseApplication");
            var verify = Native.Del<SkfVerifyPinFn>(h, "SKF_VerifyPIN");
            var clear = Native.Del<SkfClearSecureStateFn>(h, "SKF_ClearSecureState");
            var create = Native.Del<SkfCreateContFn>(h, "SKF_CreateContainer");
            var del = Native.Del<SkfDeleteContFn>(h, "SKF_DeleteContainer");
            var enumCont = Native.Del<SkfEnumContainerFn>(h, "SKF_EnumContainer");

            var names = enumDev == null ? new List<string>() : EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 无设备"); _fail++; return; }
            var crc0 = connect(names[0], out var hDev);
            Console.WriteLine($"   ConnectDev('{names[0]}') rc=0x{crc0:X8}");
            if (crc0 != 0) { _fail++; return; }
            try
            {
                var apps = new List<string>();
                if (enumApp != null)
                {
                    using var ub = new UB(4096);
                    uint sz = (uint)ub.Data.Length;
                    var rc = enumApp(hDev, ub.Ptr, ref sz);
                    ub.ReadBack();
                    apps = ReadMultiString(ub.Data, (int)Math.Min(sz, (uint)ub.Data.Length));
                    Console.WriteLine($"   EnumApplication rc=0x{rc:X8} 应用=[{string.Join(",", apps)}]");
                }
                var appName = apps.Count > 0 ? apps[0] : "";
                var arc = openApp(hDev, appName, out var hApp);
                Console.WriteLine($"   OpenApplication('{appName}') rc=0x{arc:X8} hApp=0x{hApp:X}");
                if (arc != 0 || hApp == IntPtr.Zero) { _fail++; return; }
                try
                {
                    var cases = new (string Label, int PinType, string Pin)[]
                    {
                        ("不验证口令",        -1, ""),
                        ("先验用户口令(1)",    1, userPin),
                        ("先验管理员口令(0)",  0, soPin),
                    };
                    foreach (var (label, pinType, pin) in cases)
                    {
                        Console.WriteLine($"   == {label}");
                        if (clear != null) Console.WriteLine($"      ClearSecureState rc=0x{clear(hApp):X8}");
                        if (pinType >= 0 && verify != null)
                        {
                            var retry = 0u;
                            var vrc = verify(hApp, (uint)pinType, pin, ref retry);
                            Console.WriteLine($"      VerifyPIN(pinType={pinType}, len={pin.Length}) rc=0x{vrc:X8} retry={retry}");
                        }
                        if (create == null) continue;
                        var hCont = IntPtr.Zero;
                        var crc = create(hApp, "SKFT1", out hCont);
                        Console.WriteLine($"      CreateContainer('SKFT1') rc=0x{crc:X8}" +
                                          (crc == 0 ? "  ✅ 建容器成功" : ""));
                        if (crc != 0) { _fail++; }
                        else
                        {
                            if (enumCont != null)
                            {
                                using var ub = new UB(4096);
                                uint sz = (uint)ub.Data.Length;
                                var erc = enumCont(hApp, ub.Ptr, ref sz);
                                ub.ReadBack();
                                var lst = ReadMultiString(ub.Data, (int)Math.Min(sz, (uint)ub.Data.Length));
                                Console.WriteLine($"         EnumContainer rc=0x{erc:X8} 容器=[{string.Join(",", lst)}]");
                            }
                            if (del != null)
                                Console.WriteLine($"         DeleteContainer('SKFT1') rc=0x{del(hApp, "SKFT1"):X8}");
                        }
                        if (clear != null) clear(hApp);
                    }
                }
                finally { if (closeApp != null) closeApp(hApp); }
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 直接驱动 TokenMgr 的「改名 / 改 SO PIN」入口（Admin 点按钮时走的就是这两个函数），
    /// 复现报错并观察它们到底调用了哪个扩展槽位。
    /// 注意：这两个函数开头都有「令牌状态检查」—— 索引越界或 token+0xCC 的
    /// 「已连接」标志为 0 时，**在调用垫片之前**就直接返回 1（Admin 显示的 ErrorCode=0x1 即出自这里）。
    /// </summary>
    private static void ProbeTmFix(string tokenMgrDll, string pkcs11Path, string soPin)
    {
        Console.WriteLine($"---- TokenMgr 改名/改密入口：{tokenMgrDll}");
        var h = Native.Load(tokenMgrDll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var init1 = Native.Del<TmInitFn>(h, "init_pkcs11");
            var tokenFind = Native.Del<TokenFindFn>(h, "token_find");
            var tokenConnect = Native.Del<TokenConnectFn>(h, "token_connect");
            var tokenGetInfo = Native.Del<TokenGetInfoFn>(h, "token_get_info");
            var setLabel = Native.Del<TmSetLabelFn>(h, "token_set_label");
            var chgSo = Native.Del<TmChangePinFn>(h, "token_change_sopin");
            var pinState = Native.Del<TmPinStateFn>(h, "token_get_pin_state");

            if (init1 != null) Console.WriteLine($"   init_pkcs11(path) rc=0x{init1(pkcs11Path):X8}");
            if (tokenFind == null) { Console.WriteLine("   [x] 缺 token_find"); _fail++; return; }

            var ids = new uint[32];
            uint cnt = (uint)ids.Length;
            var frc = tokenFind(ids, ref cnt);
            Console.WriteLine($"   token_find rc=0x{frc:X8} count={cnt}");
            if (frc != 0 || cnt == 0) { _fail++; return; }
            var id = ids[0];

            // 隔离实验：连接**之前**先试一次改 SO PIN，用于确认 token_change_sopin 的
            // 状态检查（token[index]+0xCC「已连接」标志）到底卡在哪一步。
            if (chgSo != null)
            {
                var preRc = chgSo(id, soPin, soPin);
                Console.WriteLine($"   [连接前] token_change_sopin({id}, 旧=新) → 0x{preRc:X8}" +
                                  (preRc == 1 ? "（符合「未连接 → 直接返回 1」）" : ""));
            }

            if (tokenConnect != null)
                Console.WriteLine($"   token_connect({id}) rc=0x{tokenConnect(id):X8}");

            // 连接后**立刻**再试一次（中间不夹任何其它调用）
            if (chgSo != null)
            {
                var postRc = chgSo(id, soPin, soPin);
                Console.WriteLine($"   [连接后立刻] token_change_sopin({id}, 旧=新) → 0x{postRc:X8}" +
                                  (postRc == 0 ? "  ✅ 通过" : "  ❌ 仍失败"));
            }

            // 直接读 TokenMgr 的静态数据，看「就绪」标志到底是什么值。
            // 布局（由反汇编确认）：0x1001EBD4 = g_tokenCount，0x1001EBD8 起每 0xE0 字节一个令牌结构，
            // 令牌结构内：+0x00 slotID、+0x04 会话句柄、+0x10 函数表对象、+0xCC 「已连接」标志。
            var baseAddr = (long)h;
            var flag = Marshal.ReadInt32((IntPtr)(baseAddr + 0x1ECA4));
            var count = Marshal.ReadInt32((IntPtr)(baseAddr + 0x1EBD4));
            var tok0 = (IntPtr)(baseAddr + 0x1EBD8);
            Console.WriteLine($"   [内存] g_tokenCount={count}  token[0]+0xCC(就绪标志)={flag}  " +
                              $"token[0]: slot={Marshal.ReadInt32(tok0, 0)} " +
                              $"session=0x{Marshal.ReadInt32(tok0, 4):X} " +
                              $"fnlistObj=0x{Marshal.ReadInt32(tok0, 0x10):X}");
            for (var off = 0xCC; off <= 0xDC; off += 4)
                Console.WriteLine($"      token[0]+0x{off:X2} = 0x{Marshal.ReadInt32(tok0, off):X8}");

            var bufs = new List<UB>();
            void ReadInfo(string tag)
            {
                foreach (var b in bufs) b.Dispose();
                bufs.Clear();
                for (var k = 0; k < 13; k++) bufs.Add(new UB(256));
                var grc = tokenGetInfo(id, bufs[0].Ptr, bufs[1].Ptr, bufs[2].Ptr, bufs[3].Ptr,
                    bufs[4].Ptr, bufs[5].Ptr, bufs[6].Ptr, bufs[7].Ptr, bufs[8].Ptr,
                    bufs[9].Ptr, bufs[10].Ptr, bufs[11].Ptr, bufs[12].Ptr);
                foreach (var b in bufs) b.ReadBack();
                Console.WriteLine($"   token_get_info({tag}) rc=0x{grc:X8} 名称='{FirstString(bufs[1].Data)}' " +
                                  $"型号='{FirstString(bufs[3].Data)}'");
            }
            try
            {
                ReadInfo("改名前");

                // ① 改名（Admin 的「修改名称」按钮）
                if (setLabel == null) Console.WriteLine("   [x] 缺 token_set_label");
                else
                {
                    var rc = setLabel(id, "ZZTESTZZ");
                    Console.WriteLine($"   token_set_label({id}, 'ZZTESTZZ') → 0x{rc:X8}" +
                                      (rc == 0 ? "  ✅" : "  ❌"));
                    ReadInfo("改名后");
                    var back = setLabel(id, "GM3000");
                    Console.WriteLine($"   token_set_label({id}, 'GM3000') 恢复 → 0x{back:X8}");
                    ReadInfo("恢复后");
                }

                // ② 改 SO PIN（旧=新，值不变，安全）
                if (chgSo == null) Console.WriteLine("   [x] 缺 token_change_sopin");
                else
                {
                    // 必须先以 SO 身份登录：worker 会先调 C_GetSessionInfo 并要求
                    // state == CKS_RW_SO_FUNCTIONS(4)，否则直接返回 1。
                    var loginSo = Native.Del<TmLoginSoFn>(h, "token_login_so");
                    if (loginSo != null)
                    {
                        var retryBuf = Marshal.AllocHGlobal(8);
                        try
                        {
                            Marshal.WriteInt32(retryBuf, 0);
                            var lrc = loginSo(id, soPin, retryBuf);
                            Console.WriteLine($"   token_login_so({id}, len={soPin.Length}) → 0x{lrc:X8}" +
                                              (lrc == 0 ? "  ✅ SO 登录通过" : "  ❌") +
                                              $" 剩余试次={Marshal.ReadInt32(retryBuf)}");
                            if (lrc != 0) _fail++;
                        }
                        finally { Marshal.FreeHGlobal(retryBuf); }
                    }
                    var rc = chgSo(id, soPin, soPin);
                    Console.WriteLine($"   token_change_sopin({id}, 旧=新, len={soPin.Length}) → 0x{rc:X8}" +
                                      (rc == 0 ? "  ✅ 通过" : "  ❌ 期望 0x0（Admin 报的就是这个码）"));
                    if (rc != 0) _fail++;
                }

                // ③ PIN 状态（6 个出参）
                if (pinState != null)
                {
                    // token_get_pin_state 是 `ret 0x20`：index + **7** 个参数
                    var outs = new IntPtr[7];
                    for (var i = 0; i < 7; i++)
                    {
                        outs[i] = Marshal.AllocHGlobal(16);
                        for (var k = 0; k < 16; k++) Marshal.WriteByte(outs[i], k, 0xEE);
                    }
                    try
                    {
                        var prc = pinState(id, outs[0], outs[1], outs[2], outs[3], outs[4], outs[5], outs[6]);
                        Console.WriteLine($"   token_get_pin_state({id}) rc=0x{prc:X8} " +
                                          $"out0={Marshal.ReadInt32(outs[0])} out1={Marshal.ReadInt32(outs[1])} " +
                                          $"b2={Marshal.ReadByte(outs[2])} b3={Marshal.ReadByte(outs[3])} " +
                                          $"b4={Marshal.ReadByte(outs[4])} b5={Marshal.ReadByte(outs[5])} " +
                                          $"b6={Marshal.ReadByte(outs[6])}");
                    }
                    finally { foreach (var p in outs) Marshal.FreeHGlobal(p); }
                }
            }
            finally { foreach (var b in bufs) b.Dispose(); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 验证扇区透传（下载 ISO 用的槽位 9/10）。测试是**幂等**的：
    /// 先读 0 号扇区（2048 字节），再把读到的那份数据**原样写回**同一扇区，最后再读一次比对。
    /// 这样即使写通了，设备上的内容也没有被改动。
    /// </summary>
    private static void ProbeSectors(string dll, uint startSector)
    {
        Console.WriteLine($"---- 扇区透传验证（槽位 9/10）：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getExt = Native.Del<M_GetExtListFn1>(h, "M_GetExtFunctionList");
            var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var pList = IntPtr.Zero;
            getList(ref pList);
            var init = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(Marshal.ReadIntPtr(pList, 2));
            Console.WriteLine($"   C_Initialize → 0x{init(IntPtr.Zero):X8}");

            var pExt = IntPtr.Zero;
            var erc = getExt(ref pExt);
            Console.WriteLine($"   M_GetExtFunctionList → 0x{erc:X8} 表=0x{pExt:X}");
            if (erc != 0 || pExt == IntPtr.Zero) { _fail++; return; }

            var readSec = Marshal.GetDelegateForFunctionPointer<M_SectorsFn>(Marshal.ReadIntPtr(pExt, 4 + 4 * 10));
            var writeSec = Marshal.GetDelegateForFunctionPointer<M_SectorsFn>(Marshal.ReadIntPtr(pExt, 4 + 4 * 9));

            var buf = Marshal.AllocHGlobal(2048);
            var bak = new byte[2048];
            try
            {
                for (var i = 0; i < 2048; i++) Marshal.WriteByte(buf, i, 0xCC);

                var rc = readSec(1, startSector, 1, buf);
                Marshal.Copy(buf, bak, 0, 2048);
                var head = BitConverter.ToString(bak, 0, 24).Replace("-", "");
                var allZero = bak.All(b => b == 0);
                Console.WriteLine($"   ext[10] M_ReadSectors(start={startSector}, count=1) → 0x{rc:X8} " +
                                  $"head={head}{(allZero ? "（该扇区当前全 0）" : "")}");
                if (rc != 0)
                {
                    Console.WriteLine("   ❌ 读扇区未通过 → 帧格式或透传口不匹配，写入更不可能成功");
                    _fail++;
                    return;
                }

                for (var i = 0; i < 2048; i++) Marshal.WriteByte(buf, i, bak[i]);
                var wrc = writeSec(1, startSector, 1, buf);
                Console.WriteLine($"   ext[9]  M_WriteSectors(start={startSector}, count=1, 原样写回) → 0x{wrc:X8}" +
                                  (wrc == 0 ? "  ✅" : "  ❌"));
                if (wrc != 0) _fail++;

                var buf2 = Marshal.AllocHGlobal(2048);
                try
                {
                    for (var i = 0; i < 2048; i++) Marshal.WriteByte(buf2, i, 0xCC);
                    var rc2 = readSec(1, startSector, 1, buf2);
                    var back = new byte[2048];
                    Marshal.Copy(buf2, back, 0, 2048);
                    var same = back.AsSpan().SequenceEqual(bak);
                    Console.WriteLine($"   ext[10] 回读比对 → rc=0x{rc2:X8} " +
                                      (same ? "✅ 与写回内容一致" : "❌ 内容不一致"));
                    if (rc2 != 0 || !same) _fail++;
                }
                finally { Marshal.FreeHGlobal(buf2); }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 清点设备上**每个容器内实际存了几张证书**：分别按「签名证书(sign=1)」「密钥交互证书(sign=0)」
    /// 导出，打印长度与 SHA-256 前 8 字节，并列出容器内文件名。
    /// 用于判定「导入后同时出现签名证书与密钥交互证书」到底是设备真存了两张，还是上层显示逻辑重复。
    /// </summary>
    private static void ProbeSkfCerts(string dll, string appName)
    {
        Console.WriteLine($"---- 容器内证书清点：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(h, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(h, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(h, "SKF_DisConnectDev");
            var enumApp = Native.Del<SkfEnumAppFn>(h, "SKF_EnumApplication");
            var openApp = Native.Del<SkfOpenAppFn>(h, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(h, "SKF_CloseApplication");
            var enumCont = Native.Del<SkfEnumContainerFn>(h, "SKF_EnumContainer");
            var openCont = Native.Del<SkfOpenContainerFn>(h, "SKF_OpenContainer");
            var closeCont = Native.Del<SkfCloseContainerFn>(h, "SKF_CloseContainer");
            var exportCert = Native.Del<SkfExportCertFn>(h, "SKF_ExportCertificate");
            var enumFiles = Native.Del<SkfEnumFilesFn>(h, "SKF_EnumFiles");

            var names = enumDev == null ? new List<string>() : EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 无设备"); _fail++; return; }
            if (connect(names[0], out var hDev) != 0) { Console.WriteLine("   [x] ConnectDev 失败"); _fail++; return; }
            try
            {
                var apps = new List<string>();
                if (enumApp != null)
                {
                    using var ub = new UB(4096);
                    uint sz = (uint)ub.Data.Length;
                    var rc = enumApp(hDev, ub.Ptr, ref sz);
                    ub.ReadBack();
                    apps = ReadMultiString(ub.Data, (int)Math.Min(sz, (uint)ub.Data.Length));
                }
                var aName = apps.Count > 0 ? apps[0] : appName;
                if (openApp(hDev, aName, out var hApp) != 0) { Console.WriteLine($"   [x] OpenApplication('{aName}') 失败"); _fail++; return; }
                try
                {
                    Console.WriteLine($"   应用 '{aName}'");
                    var conts = new List<string>();
                    using (var ub = new UB(8192))
                    {
                        uint sz = (uint)ub.Data.Length;
                        var rc = enumCont(hApp, ub.Ptr, ref sz);
                        ub.ReadBack();
                        conts = ReadMultiString(ub.Data, (int)Math.Min(sz, (uint)ub.Data.Length));
                        Console.WriteLine($"   EnumContainer rc=0x{rc:X8} 容器[{conts.Count}]=[{string.Join(", ", conts)}]");
                    }
                    foreach (var cn in conts)
                    {
                        Console.WriteLine($"   == 容器 '{cn}'");
                        if (openCont == null || openCont(hApp, cn, out var hCont) != 0)
                        {
                            Console.WriteLine("      OpenContainer 失败");
                            _fail++;
                            continue;
                        }
                        try
                        {
                            foreach (var (label, sign) in new[] { ("签名证书(sign=1)", 1), ("密钥交互证书(sign=0)", 0) })
                            {
                                if (exportCert == null) continue;
                                using var ob = new UB(0x8000);
                                uint len = (uint)ob.Data.Length;
                                var rc = exportCert(hCont, sign != 0, ob.Ptr, ref len);
                                ob.ReadBack();
                                var head = len > 0 ? BitConverter.ToString(ob.Data, 0, (int)Math.Min(16, len)).Replace("-", "")
                                                   : "";
                                var sha = len > 0
                                    ? BitConverter.ToString(SHA256.HashData(ob.Data.AsSpan(0, (int)len))).Replace("-", "")[..16]
                                    : "";
                                Console.WriteLine($"      {label} rc=0x{rc:X8} len={len} sha256[0..8]={sha} head={head}");
                            }
                            if (enumFiles != null)
                            {
                                using var fb = new UB(0x4000);
                                uint fsz = (uint)fb.Data.Length;
                                var rc = enumFiles(hCont, fb.Ptr, ref fsz);
                                fb.ReadBack();
                                var files = ReadMultiString(fb.Data, (int)Math.Min(fsz, (uint)fb.Data.Length));
                                Console.WriteLine($"      容器内文件 rc=0x{rc:X8} 共 {files.Count} 个" +
                                                  (files.Count > 0 ? $": [{string.Join(", ", files)}]" : ""));
                            }
                        }
                        finally { if (closeCont != null) closeCont(hCont); }
                    }
                }
                finally { if (closeApp != null) closeApp(hApp); }
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 在 PKCS#11 ABI 层复刻厂商 Admin 的「三步导入」：先建公钥对象、再建私钥对象、最后建证书对象。
    /// 目的：验证前两类「记账对象」现在能被回查（此前 C_FindObjectsInit 忽略模板、只回容器证书，
    /// Admin 查不到刚建的对象 → 判定失败 → ErrorCode=0x4，证书那一步永远走不到）。
    /// 证书那一步会真的去调 SKF_ImportCertificate（需要用户角色，未登录时设备会拒，属预期）。
    /// </summary>
    private static void ProbeCkObjects(string dll, string containerName)
    {
        Console.WriteLine($"---- PKCS#11 对象记账（复刻 Admin 三步导入）：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var pList = IntPtr.Zero;
            getList(ref pList);
            var init = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(Marshal.ReadIntPtr(pList, 2));
            var openSess = Marshal.GetDelegateForFunctionPointer<C_OpenSessionFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 12));
            var createObj = Marshal.GetDelegateForFunctionPointer<C_CreateObjectFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 20));
            var getAttr = Marshal.GetDelegateForFunctionPointer<C_GetAttributeValueFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 24));
            var findInit = Marshal.GetDelegateForFunctionPointer<C_FindObjectsInitFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 26));
            var find = Marshal.GetDelegateForFunctionPointer<C_FindObjectsFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 27));
            var findFinal = Marshal.GetDelegateForFunctionPointer<C_FindObjectsFinalFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 28));

            Console.WriteLine($"   C_Initialize → 0x{init(IntPtr.Zero):X8}");
            uint sess = 0;
            Console.WriteLine($"   C_OpenSession → 0x{openSess(0, 6, IntPtr.Zero, IntPtr.Zero, ref sess):X8} session={sess}");

            var (name, idLen) = (containerName, containerName.Length + 1);

            // 模板：CKA_CLASS / CKA_ID / CKA_KEY_TYPE / CKA_MODULUS / CKA_PUBLIC_EXPONENT
            var mod = new byte[256];
            for (var i = 0; i < mod.Length; i++) mod[i] = (byte)(0x80 + (i & 0x3F));
            mod[0] = 0xC1; mod[1] = 0x9D;
            var exp = new byte[] { 0x01, 0x00, 0x01 };
            var cls = new byte[] { 2, 0, 0, 0 };      /* CKO_PUBLIC_KEY = 2（小端 DWORD） */
            var keyType = new byte[] { 0, 0, 0, 0 };  /* CKK_RSA = 0 */
            var idBuf = Encoding.ASCII.GetBytes(name + "\0");

            IntPtr MakeTemplate(out IntPtr[] holders, params (uint Type, byte[] Value)[] attrs)
            {
                var t = Marshal.AllocHGlobal(attrs.Length * 12);
                holders = new IntPtr[attrs.Length * 2];
                for (var i = 0; i < attrs.Length; i++)
                {
                    var vp = Marshal.AllocHGlobal(Math.Max(attrs[i].Value.Length, 1));
                    Marshal.Copy(attrs[i].Value, 0, vp, attrs[i].Value.Length);
                    holders[i * 2] = vp;
                    Marshal.WriteInt32(t, i * 12 + 0, (int)attrs[i].Type);
                    Marshal.WriteIntPtr(t, i * 12 + 4, vp);
                    Marshal.WriteInt32(t, i * 12 + 8, attrs[i].Value.Length);
                }
                return t;
            }
            void FreeTemplate(IntPtr t, IntPtr[] holders)
            {
                foreach (var p in holders) if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
                Marshal.FreeHGlobal(t);
            }
            int CountFound(uint findClass)
            {
                var clsBytes = BitConverter.GetBytes(findClass);
                var t = MakeTemplate(out var hs, (0x00000000u, clsBytes), (0x00000102u, idBuf));
                try
                {
                    var rc = findInit(sess, t, 2);
                    var ph = Marshal.AllocHGlobal(4 * 8);
                    uint n = 0;
                    var rc2 = find(sess, ph, 8, ref n);
                    findFinal(sess);
                    Marshal.FreeHGlobal(ph);
                    if (rc != 0 || rc2 != 0) Console.WriteLine($"      [warn] FindInit=0x{rc:X8} Find=0x{rc2:X8}");
                    return (int)n;
                }
                finally { FreeTemplate(t, hs); }
            }
            void DumpAttr(uint obj, string tag)
            {
                var aCls = BitConverter.GetBytes((uint)0);
                var aBits = BitConverter.GetBytes((uint)0);
                var vendName = new byte[128];
                var vendFlag = new byte[4];
                var t = MakeTemplate(out var hs, (0x00000000u, aCls), (0x00000121u, aBits), (0x00000102u, idBuf),
                    (0x80000066u, vendName), (0x80000067u, vendFlag));
                try
                {
                    var rc = getAttr(sess, obj, t, 5);
                    var clsV = Marshal.ReadInt32(t, 0 * 12 + 8);
                    var bitsV = Marshal.ReadInt32(t, 1 * 12 + 8);
                    var clsByte = Marshal.ReadInt32(Marshal.ReadIntPtr(t, 0 * 12 + 4));
                    var idStr = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(t, 2 * 12 + 4)) ?? "";
                    var vName = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(t, 3 * 12 + 4)) ?? "";
                    var vNameLen = Marshal.ReadInt32(t, 3 * 12 + 8);
                    var vFlag = Marshal.ReadInt32(Marshal.ReadIntPtr(t, 4 * 12 + 4));
                    var vFlagLen = Marshal.ReadInt32(t, 4 * 12 + 8);
                    Console.WriteLine($"      {tag} GetAttributeValue → 0x{rc:X8} class=0x{clsByte:X}({clsV}B) " +
                                      $"modulusBits={bitsV} id='{idStr}'");
                    Console.WriteLine($"         厂商私有 0x80000066(容器名)={vNameLen}B '{vName}'  " +
                                      $"0x80000067(签名/密钥交互)={vFlagLen}B 值={vFlag}");
                }
                finally { FreeTemplate(t, hs); }
            }

            // ---------- 第一步：公钥对象（CKO_PUBLIC_KEY） ----------
            var tPub = MakeTemplate(out var hsPub,
                (0x00000102u, idBuf), (0x00000000u, cls), (0x00000100u, keyType),
                (0x00000120u, mod), (0x00000122u, exp));
            try
            {
                uint hObj = 0;
                var rc = createObj(sess, tPub, 5, ref hObj);
                Console.WriteLine($"   ① C_CreateObject(CKO_PUBLIC_KEY, 5 属性) → 0x{rc:X8} 句柄={hObj}" +
                                  (rc == 0 ? "  ✅" : "  ❌"));
                if (rc != 0) _fail++;
                var found = CountFound(2);
                Console.WriteLine($"      C_FindObjectsInit(CKA_CLASS=CKO_PUBLIC_KEY) → 查到 {found} 个" +
                                  (found == 1 ? "  ✅ 回查得到（Admin 就靠这一步）" : "  ❌ 回查不到"));
                if (found != 1) _fail++;
                if (hObj != 0) DumpAttr(hObj, "公钥");
            }
            finally { FreeTemplate(tPub, hsPub); }

            // ---------- 第二步：私钥对象（CKO_PRIVATE_KEY） ----------
            var clsPriv = new byte[] { 3, 0, 0, 0 };
            var privPart = new byte[128];
            for (var i = 0; i < privPart.Length; i++) privPart[i] = (byte)(0x40 + (i & 0x3F));
            var tPrv = MakeTemplate(out var hsPrv,
                (0x00000000u, clsPriv), (0x00000102u, idBuf), (0x00000100u, keyType),
                (0x00000120u, mod), (0x00000122u, exp), (0x00000123u, privPart),
                (0x00000124u, privPart), (0x00000125u, privPart));
            try
            {
                uint hObj = 0;
                var rc = createObj(sess, tPrv, 8, ref hObj);
                Console.WriteLine($"   ② C_CreateObject(CKO_PRIVATE_KEY, 8 属性) → 0x{rc:X8} 句柄={hObj}" +
                                  (rc == 0 ? "  ✅（不阻断，证书随后导入）" : "  ❌"));
                if (rc != 0) _fail++;
                var found = CountFound(3);
                Console.WriteLine($"      C_FindObjectsInit(CKA_CLASS=CKO_PRIVATE_KEY) → 查到 {found} 个" +
                                  (found == 1 ? "  ✅" : "  ❌"));
                if (found != 1) _fail++;
                if (hObj != 0) DumpAttr(hObj, "私钥");
            }
            finally { FreeTemplate(tPrv, hsPrv); }

            // ---------- 第三步：证书对象（CKO_CERTIFICATE）—— 会真的调 SKF_ImportCertificate ----------
            var clsCert = new byte[] { 1, 0, 0, 0 };
            var dummyDer = new byte[64];
            for (var i = 0; i < dummyDer.Length; i++) dummyDer[i] = (byte)i;
            var tCert = MakeTemplate(out var hsCert,
                (0x00000000u, clsCert), (0x00000102u, idBuf), (0x00000011u, dummyDer));
            try
            {
                uint hObj = 0;
                var rc = createObj(sess, tCert, 3, ref hObj);
                Console.WriteLine($"   ③ C_CreateObject(CKO_CERTIFICATE, 3 属性, DER {dummyDer.Length} 字节) → 0x{rc:X8}" +
                                  (rc == 0 ? "  ✅ 已写入设备"
                                           : rc == 0x54 ? "  ❌ 仍返回「不支持」" : "  （设备侧拒绝：未登录/无效证书，属预期）"));
                if (rc == 0x54) _fail++;
            }
            finally { FreeTemplate(tCert, hsCert); }
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 两项现场取证（都用真实设备，不靠猜）：
    /// ① 改 SO 口令链路：C_Login(CKU_SO) → C_SetPIN(旧值=新值，值不变，避免真的改掉口令)，
    ///    逐步打印返回码，用于定位 Admin 报的 ErrorCode=0x1 出自哪一步。
    /// ② 改名链路：调用 SKF_SetLabel 后**逐字节比对 DEVINFO**，定位「标签」字段的真实偏移，
    ///    并分别用设备句柄 / 应用句柄各试一次，确认哪个句柄才有效；最后自动恢复原标签。
    /// </summary>
    private static void ProbeAdminFix(string shimDll, string skfDll, string soPin)
    {
        // ---------------------------------------------------------- ① 改 SO 口令
        Console.WriteLine($"---- ① 改 SO 口令链路：{shimDll}");
        var h = Native.Load(shimDll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 垫片加载失败"); _fail++; }
        else
        {
            try
            {
                var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
                var pList = IntPtr.Zero;
                getList(ref pList);
                var init = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(Marshal.ReadIntPtr(pList, 2));
                var openSess = Marshal.GetDelegateForFunctionPointer<C_OpenSessionFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 12));
                var login = Marshal.GetDelegateForFunctionPointer<C_LoginFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 18));
                var setPin = Marshal.GetDelegateForFunctionPointer<C_SetPinFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 11));

                Console.WriteLine($"   C_Initialize → 0x{init(IntPtr.Zero):X8}");
                uint sess = 0;
                Console.WriteLine($"   C_OpenSession → 0x{openSess(0, 6, IntPtr.Zero, IntPtr.Zero, ref sess):X8} session={sess}");
                var lrc = login(sess, 0 /*CKU_SO*/, soPin, (uint)soPin.Length);
                Console.WriteLine($"   C_Login(CKU_SO, len={soPin.Length}) → 0x{lrc:X8}");
                // 旧口令 == 新口令：等价于「改密码但值不变」，不会真的改变设备口令
                var src = setPin(sess, soPin, (uint)soPin.Length, soPin, (uint)soPin.Length);
                Console.WriteLine($"   C_SetPIN(旧=新, len={soPin.Length}) → 0x{src:X8}" +
                                  (src == 0 ? "  ✅ 通过" : "  ❌ 这就是 Admin 报的那个码？"));
                if (src != 0) _fail++;
            }
            finally { Native.Free(h); }
        }

        // ---------------------------------------------------------- ② 改名 → 标签字段
        Console.WriteLine($"---- ② 改名链路：{skfDll}");
        var hs = Native.Load(skfDll);
        if (hs == IntPtr.Zero) { Console.WriteLine("   [x] SKF 加载失败"); _fail++; return; }
        try
        {
            var enumDev = Native.Del<SkfEnumDevFn>(hs, "SKF_EnumDev");
            var connect = Native.Del<SkfConnectDevFn>(hs, "SKF_ConnectDev");
            var disconnect = Native.Del<SkfDisconnectDevFn>(hs, "SKF_DisConnectDev");
            var devInfo = Native.Del<SkfGetDevInfoFn>(hs, "SKF_GetDevInfo");
            var setLabel = Native.Del<SkfSetLabelFn>(hs, "SKF_SetLabel");
            var openApp = Native.Del<SkfOpenAppFn>(hs, "SKF_OpenApplication");
            var closeApp = Native.Del<SkfCloseAppFn>(hs, "SKF_CloseApplication");

            var names = enumDev == null ? new List<string>() : EnumDevNames(enumDev, "   ");
            if (names.Count == 0) { Console.WriteLine("   [x] 无设备"); _fail++; return; }
            var crc = connect(names[0], out var hDev);
            if (crc != 0 || hDev == IntPtr.Zero) { Console.WriteLine($"   [x] ConnectDev rc=0x{crc:X8}"); _fail++; return; }
            try
            {
                byte[] ReadDevInfo()
                {
                    using var ub = new UB(512);
                    var rc = devInfo(hDev, ub.Ptr);
                    ub.ReadBack();
                    if (rc != 0) Console.WriteLine($"      [warn] GetDevInfo rc=0x{rc:X8}");
                    return (byte[])ub.Data.Clone();
                }

                var before = ReadDevInfo();
                Console.WriteLine("   改名前 DEVINFO 可读串: " + JoinStrings(before));

                const string probeName = "ZZTESTZZ";
                var rc1 = setLabel == null ? -1 : setLabel(hDev, probeName);
                Console.WriteLine($"   SetLabel(hDev, '{probeName}') → 0x{rc1:X8}" + (rc1 == 0 ? "  ✅" : ""));
                var after = ReadDevInfo();
                var runs = DiffBytes(before, after);
                if (runs.Count == 0)
                    Console.WriteLine("   ⚠ DEVINFO 完全没有变化 —— 说明「名称」不在 DEVINFO 里，"
                                      + "或 SetLabel 传设备句柄无效");
                foreach (var (off, len, olds, news) in runs)
                    Console.WriteLine($"   DEVINFO 变化 @0x{off:X3} len={len}: '{olds}' → '{news}'");

                // 试用**应用句柄**再改一次，看是否才是正确句柄
                var hApp = IntPtr.Zero;
                if (openApp != null && openApp(hDev, "GM3000APP", out hApp) == 0 && hApp != IntPtr.Zero)
                {
                    try
                    {
                        var rc2 = setLabel == null ? -1 : setLabel(hApp, probeName + "2");
                        Console.WriteLine($"   SetLabel(hApp, '{probeName}2') → 0x{rc2:X8}" + (rc2 == 0 ? "  ✅ 应用句柄也接受" : "  ❌ 应用句柄不接受"));
                        var after2 = ReadDevInfo();
                        var runs2 = DiffBytes(after, after2);
                        foreach (var (off, len, olds, news) in runs2)
                            Console.WriteLine($"   DEVINFO 变化(应用句柄) @0x{off:X3} len={len}: '{olds}' → '{news}'");
                    }
                    finally { if (closeApp != null) closeApp(hApp); }
                }

                // 恢复：把改名前的原始标签写回去（用 before 里那段原始文本）
                if (runs.Count > 0 && setLabel != null)
                {
                    var (off, len, orig, _) = runs[0];
                    var origStr = System.Text.Encoding.ASCII.GetString(before, off, len).TrimEnd('\0');
                    var rrc = setLabel(hDev, origStr);
                    var back = ReadDevInfo();
                    Console.WriteLine($"   恢复 SetLabel('{origStr}') → 0x{rrc:X8}；与改前一致=" +
                                      (DiffBytes(before, back).Count == 0 ? "是 ✅" : "否 ⚠"));
                }
            }
            finally { if (disconnect != null) disconnect(hDev); }
        }
        finally { Native.Free(hs); }
    }

    /// <summary>逐字节比对，返回连续差异段（偏移、长度、原串、新串）。</summary>
    private static List<(int Off, int Len, string Old, string New)> DiffBytes(byte[] a, byte[] b)
    {
        var res = new List<(int, int, string, string)>();
        var n = Math.Min(a.Length, b.Length);
        var i = 0;
        while (i < n)
        {
            if (a[i] == b[i]) { i++; continue; }
            var start = i;
            while (i < n && a[i] != b[i]) i++;
            // 差异段向外扩到可打印串边界，便于看出字符串整体
            var s = start;
            while (s > 0 && a[s - 1] != 0 && b[s - 1] != 0) s--;
            var e = i;
            while (e < n && a[e] != 0 && b[e] != 0) e++;
            res.Add((s, e - s, Printable(a, s, e - s), Printable(b, s, e - s)));
        }
        return res;
    }

    private static string Printable(byte[] d, int off, int len)
    {
        var sb = new System.Text.StringBuilder();
        for (var i = off; i < off + len && i < d.Length; i++)
            sb.Append(d[i] >= 0x20 && d[i] < 0x7f ? (char)d[i] : (d[i] == 0 ? '\u00b7' : '?'));
        return sb.ToString();
    }

    private static void ProbePkcs11(string dll, bool vendorInit)
    {
        Console.WriteLine($"---- PKCS11 {dll} vendorInit={vendorInit}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            if (vendorInit)
            {
                var init1 = Native.Del<P11Init1Fn>(h, "init_pkcs11");
                var init4 = Native.Del<P11Init4Fn>(h, "init_pkcs11_ex");
                Console.WriteLine($"   导出 init_pkcs11={(init1 != null)} init_pkcs11_ex={(init4 != null)}");
                if (init1 != null)
                    Console.WriteLine($"   init_pkcs11(path) rc=0x{init1(dll):X8}");
                if (init4 != null)
                    Console.WriteLine($"   init_pkcs11_ex(0,0,0,path) rc=0x{init4(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, dll):X8}");
            }
            Slots(h, "   ");
        }
        finally { Native.Free(h); }
    }

    private static bool Slots(IntPtr h, string indent)
    {
        var init = Native.Del<C_InitializeFn>(h, "C_Initialize");
        var getSlotList = Native.Del<C_GetSlotListFn>(h, "C_GetSlotList");
        var getTokenInfo = Native.Del<C_GetTokenInfoFn>(h, "C_GetTokenInfo");
        if (getSlotList == null || getTokenInfo == null)
        {
            Console.WriteLine($"{indent}PKCS#11 导出不完整");
            return false;
        }

        if (init != null)
            Console.WriteLine($"{indent}C_Initialize rc=0x{init(IntPtr.Zero):X8}");

        var any = false;
        for (var present = 0; present <= 1; present++)
        {
            uint count = 0;
            var rc = getSlotList((byte)present, null, ref count);
            Console.WriteLine($"{indent}C_GetSlotList(present={present}) rc=0x{rc:X8} count={count}");
            if (rc != 0 || count == 0) continue;
            any = true;

            var slots = new uint[count];
            rc = getSlotList((byte)present, slots, ref count);
            if (rc != 0) continue;

            for (int i = 0; i < count; i++)
            {
                using var ub = new UB(256);
                rc = getTokenInfo(slots[i], ub.Ptr);
                ub.ReadBack();
                if (rc != 0) { Console.WriteLine($"{indent}  slot={slots[i]} TokenInfo rc=0x{rc:X8}"); continue; }
                Console.WriteLine($"{indent}  slot={slots[i]} label='{Padded(ub.Data, 0, 32)}' " +
                                  $"mfr='{Padded(ub.Data, 32, 32)}' model='{Padded(ub.Data, 64, 16)}' " +
                                  $"sn='{Padded(ub.Data, 80, 16)}' flags=0x{BitConverter.ToUInt32(ub.Data, 96):X8}");
            }
        }
        return any;
    }

    private static string Padded(byte[] b, int off, int len) =>
        Encoding.UTF8.GetString(b, off, len).TrimEnd('\0', ' ');

    // ------------------------------------------------------------ 函数表结构解析

    /// <summary>解析已加载模块的导出表：RVA → 导出名。</summary>
    private static SortedDictionary<int, string> ExportMap(IntPtr h)
    {
        var res = new SortedDictionary<int, string>();
        try
        {
            var e_lfanew = Marshal.ReadInt32(h, 0x3C);
            var nt = IntPtr.Add(h, e_lfanew);
            var coff = IntPtr.Add(nt, 4);
            var optSize = (ushort)Marshal.ReadInt16(coff, 16);
            var opt = IntPtr.Add(coff, 20);
            var magic = (ushort)Marshal.ReadInt16(opt, 0);
            var is64 = magic == 0x20B;
            var dd = IntPtr.Add(opt, is64 ? 112 : 96);
            var expRva = Marshal.ReadInt32(dd, 0);
            if (expRva == 0) return res;
            var expDir = IntPtr.Add(h, expRva);
            var nfunc = Marshal.ReadInt32(expDir, 20);
            var nname = Marshal.ReadInt32(expDir, 24);
            var addrNames = Marshal.ReadInt32(expDir, 28);
            var addrOrds = Marshal.ReadInt32(expDir, 32);
            var addrFuncs = Marshal.ReadInt32(expDir, 36);
            for (var i = 0; i < nname; i++)
            {
                var nr = Marshal.ReadInt32(IntPtr.Add(h, addrNames), i * 4);
                var ord = (ushort)Marshal.ReadInt16(IntPtr.Add(h, addrOrds), i * 2);
                if (ord >= nfunc) continue;
                var name = Marshal.PtrToStringAnsi(IntPtr.Add(h, nr)) ?? "";
                var frva = Marshal.ReadInt32(IntPtr.Add(h, addrFuncs), ord * 4);
                res[frva] = name;
            }
        }
        catch (Exception ex) { Console.WriteLine($"   导出表解析失败: {ex.Message}"); }
        return res;
    }

    private static int ImageSize(IntPtr h)
    {
        var e_lfanew = Marshal.ReadInt32(h, 0x3C);
        var opt = IntPtr.Add(h, e_lfanew + 4 + 20);
        var magic = (ushort)Marshal.ReadInt16(opt, 0);
        return Marshal.ReadInt32(opt, magic == 0x20B ? 56 : 56);
    }

    /// <summary>转储函数表：把落在模块内的指针解析为导出名。</summary>
    private static void DumpTable(string title, IntPtr h, IntPtr table, int startOffset, int stride, int count)
    {
        var map = ExportMap(h);
        var size = ImageSize(h);
        Console.WriteLine($"   {title}: 基址=0x{table:X} 模块基址=0x{h:X} 映像大小=0x{size:X}");
        for (var i = 0; i < count; i++)
        {
            var off = startOffset + i * stride;
            var v = Marshal.ReadIntPtr(table, off);
            long rva = v.ToInt64() - h.ToInt64();
            var tag = "";
            if (rva > 0 && rva < size)
            {
                tag = map.TryGetValue((int)rva, out var nm) ? $"  <= {nm}" : "  <= (模块内非导出)";
            }
            else if (v == IntPtr.Zero) tag = "  (null)";
            Console.WriteLine($"      [{i,3}] off+0x{off:X3} = 0x{v:X8}{tag}");
        }
    }

    /// <summary>
    /// 解析厂商 PKCS#11 的两张函数表（TokenMgr 绑定契约的核心）：
    /// ① <c>C_GetFunctionList</c> 返回的 CK_FUNCTION_LIST；② <c>M_GetExtFunctionList</c> 返回的扩展表。
    /// 通过「指针落点 → 导出名」反查，确定表内每一项的真实函数与偏移，判定紧凑/自然布局。
    /// </summary>
    private static void ProbeTables(string dll)
    {
        Console.WriteLine($"---- 函数表解析：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var getExt = Native.Del<M_GetExtListFn1>(h, "M_GetExtFunctionList");
            if (getList == null) { Console.WriteLine("   [x] 无 C_GetFunctionList"); _fail++; return; }

            var p = IntPtr.Zero;
            var rc = getList(ref p);
            Console.WriteLine($"   C_GetFunctionList → rc=0x{rc:X8} p=0x{p:X}");
            if (p != IntPtr.Zero)
            {
                Console.WriteLine("   ---- 假设紧凑布局（CK_VERSION 2 字节，函数自 +2 起，步长 4）");
                DumpTable("CK_FUNCTION_LIST(packed)", h, IntPtr.Add(p, 2), 0, 4, 20);
                Console.WriteLine("   ---- 假设自然布局（函数自 +4 起）");
                DumpTable("CK_FUNCTION_LIST(natural)", h, IntPtr.Add(p, 4), 0, 4, 20);
            }

            if (getExt != null)
            {
                var q = IntPtr.Zero;
                var erc = getExt(ref q);
                Console.WriteLine($"   M_GetExtFunctionList → rc=0x{erc:X8} q=0x{q:X}");
                if (q != IntPtr.Zero)
                {
                    DumpTable("M_EXT_TABLE(step4)", h, q, 0, 4, 40);
                }
            }
        }
        finally { Native.Free(h); }
    }
    /// <summary>
    /// 复刻 TokenMgr 的中间件绑定序列（反汇编确认）：
    /// <c>LoadLibrary(path) → GetProcAddress("C_GetFunctionList") 并调用 → GetProcAddress("M_GetExtFunctionList") 并调用
    /// → 再从函数表取 C_Initialize 调用（容忍 CKR_CRYPTOKI_ALREADY_INITIALIZED=0x191）</c>。
    /// 用于判断「PKCS#11 层是否只有在完成厂商特有初始化后才认得到设备」。
    /// </summary>
    private static void ProbeTokenMgrStyle(string dll)
    {
        Console.WriteLine($"---- TokenMgr 风格初始化：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getFnList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var getExt = Native.Del<M_GetExtListFn1>(h, "M_GetExtFunctionList");
            Console.WriteLine($"   C_GetFunctionList={(getFnList != null)} M_GetExtFunctionList={(getExt != null)}");
            if (getFnList == null) { _fail++; return; }

            var pList = IntPtr.Zero;
            var rc = getFnList(ref pList);
            Console.WriteLine($"   C_GetFunctionList → rc=0x{rc:X8} pList=0x{pList:X}");
            if (pList == IntPtr.Zero) { _fail++; return; }

            // CK_FUNCTION_LIST 为紧凑布局：CK_VERSION(2B) 之后紧跟函数指针
            var cInit = Marshal.ReadIntPtr(pList, 2);
            if (cInit != IntPtr.Zero)
            {
                var initFn = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(cInit);
                var irc = initFn(IntPtr.Zero);
                Console.WriteLine($"   函数表[+0x2] C_Initialize → rc=0x{irc:X8}" +
                                  (irc == 0x191 ? "（已初始化）" : ""));
            }
            else
            {
                Console.WriteLine("   函数表[+0x2] 为空");
            }

            if (getExt != null)
            {
                var slot = IntPtr.Zero;
                try
                {
                    var erc = getExt(ref slot);
                    Console.WriteLine($"   M_GetExtFunctionList(&p) → rc=0x{erc:X8} p=0x{slot:X}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   M_GetExtFunctionList(1 参数) 调用异常：{ex.Message}");
                }
            }

            Console.WriteLine("   之后枚举槽位：");
            Slots(h, "      ");
        }
        finally { Native.Free(h); }
    }

    /// <summary>
    /// 在 ABI 层复刻 TokenMgr 对 PKCS#11 中间件的调用序列，用于在不启动 Admin 界面的前提下
    /// 验证垫片修复（尤其是「USBKey已锁定」问题）：
    /// <c>C_GetFunctionList → C_Initialize → C_GetSlotList → C_OpenSession(flags=6)
    /// → 扩展表槽位 17 M_GetApplicationInfo(handle, out64, p3..p7)
    /// → 扩展表槽位 0  M_GetUserInfo(handle, pinType, out12)</c>。
    /// 参数形状、调用约定（cdecl）与实参格式均按 TokenMgr 反汇编结果复刻。
    /// </summary>
    private static void ProbeShimAbi(string dll, string userPin = null)
    {
        Console.WriteLine($"---- 垫片 ABI 复刻（TokenMgr 调用序列）：{dll}");
        var h = Native.Load(dll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var getList = Native.Del<C_GetFunctionListFn>(h, "C_GetFunctionList");
            var getExt = Native.Del<M_GetExtListFn1>(h, "M_GetExtFunctionList");
            if (getList == null) { Console.WriteLine("   [x] 无 C_GetFunctionList"); _fail++; return; }

            var pList = IntPtr.Zero;
            var lrc = getList(ref pList);
            Console.WriteLine($"   C_GetFunctionList → rc=0x{lrc:X8} pList=0x{pList:X}");
            if (pList == IntPtr.Zero) { _fail++; return; }

            // CK_FUNCTION_LIST 紧凑布局：CK_VERSION(2B) 之后 fn[i] 位于 2 + 4*i
            var init = Marshal.GetDelegateForFunctionPointer<C_InitializeFn>(Marshal.ReadIntPtr(pList, 2));
            Console.WriteLine($"   C_Initialize → rc=0x{init(IntPtr.Zero):X8}");

            var getSlots = Marshal.GetDelegateForFunctionPointer<C_GetSlotListFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 4));
            uint count = 0;
            Console.WriteLine($"   C_GetSlotList(NULL) → rc=0x{getSlots(1, null, ref count):X8} count={count}");
            uint[] slots = null;
            if (count > 0)
            {
                slots = new uint[count];
                Console.WriteLine($"   C_GetSlotList(buf)  → rc=0x{getSlots(1, slots, ref count):X8} slots=[{string.Join(",", slots)}]");
            }

            var openSess = Marshal.GetDelegateForFunctionPointer<C_OpenSessionFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 12));
            uint sess = 0;
            Console.WriteLine($"   C_OpenSession(slot=0, flags=6) → rc=0x{openSess(0, 6, IntPtr.Zero, IntPtr.Zero, ref sess):X8} session={sess}");

            var getTokInfo = Marshal.GetDelegateForFunctionPointer<C_GetTokenInfoFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 6));
            var tok = Marshal.AllocHGlobal(256);
            try
            {
                for (var i = 0; i < 256; i++) Marshal.WriteByte(tok, i, 0);
                var rc = getTokInfo(0, tok);
                Console.WriteLine($"   C_GetTokenInfo(slot=0) → rc=0x{rc:X8}");
                if (rc == 0)
                {
                    Console.WriteLine($"      label='{Ansi(tok, 32)}' 制造商='{Ansi(tok + 32, 32)}' " +
                                      $"型号='{Ansi(tok + 64, 16)}' 序列号='{Ansi(tok + 80, 16)}' " +
                                      $"flags=0x{Marshal.ReadInt32(tok, 96):X8}");
                }
            }
            finally { Marshal.FreeHGlobal(tok); }

            // Admin 报「口令验证不正确」时实际发起的就是这一次调用：
            // C_Login(session, CKU_SO=0, <SO 口令>) —— 修复前垫片传错句柄+编号，
            // 返回 0x3（SAR_INVALIDHANDLEERR 映射）；口令根本没送到设备。
            var login = Marshal.GetDelegateForFunctionPointer<C_LoginFn>(Marshal.ReadIntPtr(pList, 2 + 4 * 18));
            var soPin = "admin";
            var soRc = login(sess, 0, soPin, (uint)soPin.Length);
            Console.WriteLine($"   C_Login(CKU_SO, pinLen={soPin.Length}) → rc=0x{soRc:X8}" +
                              (soRc == 0 ? "  ✅ 管理员口令验证通过" : "  ❌ 期望 0x0"));

            if (getExt == null) { Console.WriteLine("   [x] 无 M_GetExtFunctionList"); _fail++; return; }
            var ext = IntPtr.Zero;
            var erc = getExt(ref ext);
            var fn0 = Marshal.ReadIntPtr(ext, 4 + 4 * 0);
            var fn17 = Marshal.ReadIntPtr(ext, 4 + 4 * 17);
            Console.WriteLine($"   M_GetExtFunctionList → rc=0x{erc:X8} table=0x{ext:X} " +
                              $"fn[0]=0x{fn0:X} fn[17]=0x{fn17:X}");

            // 槽位 17：M_GetApplicationInfo(handle, char out[64], p3..p7) —— 与 TokenMgr 同样传 7 个实参
            var nameBuf = Marshal.AllocHGlobal(64);
            var a3 = Marshal.AllocHGlobal(16);
            var a4 = Marshal.AllocHGlobal(16);
            var a5 = Marshal.AllocHGlobal(16);
            var a6 = Marshal.AllocHGlobal(16);
            var a7 = Marshal.AllocHGlobal(16);
            try
            {
                for (var i = 0; i < 64; i++) Marshal.WriteByte(nameBuf, i, 0);
                Marshal.WriteInt32(a3, 4);      // TokenMgr 传 0x4
                Marshal.WriteInt32(a4, 0x10);   // TokenMgr 传 0x10
                Marshal.WriteInt32(a5, 0);
                Marshal.WriteInt32(a6, 0);
                Marshal.WriteInt32(a7, 0);
                var f17 = Marshal.GetDelegateForFunctionPointer<M_GetApplicationInfoFn>(fn17);
                var rc = f17(0, nameBuf, a3, a4, a5, a6, a7);
                Console.WriteLine($"   ext[17] M_GetApplicationInfo → rc=0x{rc:X8} 应用名='{Ansi(nameBuf, 64)}'");
                if (rc != 0) _fail++;
            }
            finally
            {
                foreach (var p in new[] { nameBuf, a3, a4, a5, a6, a7 }) Marshal.FreeHGlobal(p);
            }

            // 槽位 0：M_GetUserInfo(handle, pinType, M_PIN_STATE* out12)
            var st = Marshal.AllocHGlobal(12);
            try
            {
                var f0 = Marshal.GetDelegateForFunctionPointer<M_GetUserInfoFn>(fn0);
                foreach (var pt in new uint[] { 1, 0 })
                {
                    for (var i = 0; i < 12; i++) Marshal.WriteByte(st, i, 0xEE);
                    var rc = f0(0, pt, st);
                    Console.WriteLine($"   ext[0] M_GetUserInfo(pinType={pt}) → rc=0x{rc:X8} " +
                                      $"剩余={Marshal.ReadInt32(st, 0)} 上限={Marshal.ReadInt32(st, 4)} " +
                                      $"已用过={Marshal.ReadByte(st, 8)} 仅剩1次={Marshal.ReadByte(st, 9)} " +
                                      $"已锁定={Marshal.ReadByte(st, 10)} 默认口令={Marshal.ReadByte(st, 11)}" +
                                      (pt == 0 ? "   （pinType=0 为管理员/SO）" : "   （pinType=1 为用户）"));
                    if (rc != 0) _fail++;
                }
            }
            finally { Marshal.FreeHGlobal(st); }

            // 槽位 11：M_ReloadObjects(handle, …) —— 导入流程把它夹在「登录」与「建容器」中间。
            // 它曾经触发 RefreshDevices()→UnbindContext()，把 SKF 的「已验证」状态连同应用句柄
            // 一起丢掉，导致随后的建容器恒报 SAR_USER_NOT_LOGGED_IN。
            // 判据：日志里 "BindContext(slot=0) ok" 只应出现一次（上下文不再被中途解绑重连）。
            var fn11 = Marshal.ReadIntPtr(ext, 4 + 4 * 11);
            var f11 = Marshal.GetDelegateForFunctionPointer<M_ReloadObjectsFn>(fn11);
            Console.WriteLine($"   ext[11] M_ReloadObjects(0) → rc=0x{f11(0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero):X8}");

            // ------------------------------------------------ 导入证书要走的容器链
            // 由 2.2.19 厂商扩展表（rva 0x7BB30，25 项）确认的槽位：
            //   3=M_SetTokenLabel(handle,name)  5=M_CreateContainer(handle,name)
            //   6=M_DeleteContainer(handle,name) 7=M_EnumContainer(handle,list,pulSize)
            //   20=M_ForceLogout(handle)
            var fn3 = Marshal.ReadIntPtr(ext, 4 + 4 * 3);
            var fn5 = Marshal.ReadIntPtr(ext, 4 + 4 * 5);
            var fn6 = Marshal.ReadIntPtr(ext, 4 + 4 * 6);
            var fn7 = Marshal.ReadIntPtr(ext, 4 + 4 * 7);
            var fn20 = Marshal.ReadIntPtr(ext, 4 + 4 * 20);

            var f20 = Marshal.GetDelegateForFunctionPointer<M_ForceLogoutFn>(fn20);
            Console.WriteLine($"   ext[20] M_ForceLogout(0) → rc=0x{f20(0):X8}");

            // 实测结论（tools\GM3000Probe skfcont，裸 SKF 直测）：本设备 SKF_CreateContainer
            // 要求**用户**角色的已验证状态——只在管理员口令下调用，设备一律回
            // SAR_USER_NOT_LOGGED_IN(0x0A00002D)，与垫片无关。
            // 因此这里先用用户口令登录；未提供用户口令时只验证「槽位已实现 + 错误码被正确映射」。
            var userLogged = false;
            if (userPin != null)
            {
                var urc = login(sess, 1 /*CKU_USER*/, userPin, (uint)userPin.Length);
                userLogged = urc == 0;
                Console.WriteLine($"   C_Login(CKU_USER, pinLen={userPin.Length}) → rc=0x{urc:X8}" +
                                  (userLogged ? "  ✅ 用户口令验证通过" : "  ❌ 用户口令不正确"));
                if (!userLogged) _fail++;
            }
            else
            {
                Console.WriteLine("   注：未提供用户口令（第 2 个参数），容器创建只做到「槽位已实现」这一层；" +
                                  "要完整验证请运行：shimabi <dll> <用户PIN>");
            }

            var f7 = Marshal.GetDelegateForFunctionPointer<M_EnumContainerFn>(fn7);
            var list = Marshal.AllocHGlobal(0x2000);
            try
            {
                var sz = (uint)0x2000;
                for (var i = 0; i < 0x2000; i++) Marshal.WriteByte(list, i, 0);
                var rc = f7(0, list, ref sz);
                var names = ParseNameList(list, sz);
                Console.WriteLine($"   ext[7] M_EnumContainer(建前) → rc=0x{rc:X8} 长度={sz} " +
                                  $"容器[{names.Count}]=[{string.Join(",", names)}]");
                if (rc != 0) _fail++;

                const string testName = "SHIMTEST";
                var f5 = Marshal.GetDelegateForFunctionPointer<M_CreateContainerFn>(fn5);
                var crc = f5(0, testName);
                if (crc == 0)
                {
                    Console.WriteLine($"   ext[5] M_CreateContainer('{testName}') → rc=0x00000000  ✅ 容器已建");

                    sz = (uint)0x2000;
                    for (var i = 0; i < 0x2000; i++) Marshal.WriteByte(list, i, 0);
                    rc = f7(0, list, ref sz);
                    names = ParseNameList(list, sz);
                    var created = names.Contains(testName);
                    Console.WriteLine($"   ext[7] M_EnumContainer(建后) → rc=0x{rc:X8} 长度={sz} " +
                                      $"容器[{names.Count}]=[{string.Join(",", names)}]" +
                                      (created ? "  ✅ 新容器已在列表中" : "  ❌ 未看到新容器"));
                    if (rc != 0 || !created) _fail++;

                    var f6 = Marshal.GetDelegateForFunctionPointer<M_DeleteContainerFn>(fn6);
                    var drc = f6(0, testName);
                    Console.WriteLine($"   ext[6] M_DeleteContainer('{testName}') → rc=0x{drc:X8}" +
                                      (drc == 0 ? "  ✅" : "  ❌ 期望 0x0"));
                    if (drc != 0) _fail++;

                    sz = (uint)0x2000;
                    for (var i = 0; i < 0x2000; i++) Marshal.WriteByte(list, i, 0);
                    rc = f7(0, list, ref sz);
                    names = ParseNameList(list, sz);
                    Console.WriteLine($"   ext[7] M_EnumContainer(删后) → rc=0x{rc:X8} " +
                                      $"容器[{names.Count}]=[{string.Join(",", names)}]" +
                                      (names.Contains(testName) ? "  ❌ 测试容器仍在" : "  ✅ 已清理"));
                    if (names.Contains(testName)) _fail++;
                }
                else if (crc == 0x101 && !userLogged)
                {
                    Console.WriteLine($"   ext[5] M_CreateContainer('{testName}') → rc=0x00000101  " +
                                      "（CKR_USER_NOT_LOGGED_IN → 设备要求用户角色，未提供用户口令时预期如此）" +
                                      "  ✅ 槽位已实现且错误码已正确映射");
                }
                else
                {
                    Console.WriteLine($"   ext[5] M_CreateContainer('{testName}') → rc=0x{crc:X8}  ❌ 期望 0x0" +
                                      (crc == 0x54 ? "（仍是「不支持」——槽位未生效？）" : ""));
                    _fail++;
                }

                // 缓冲不足时应返回 CKR_BUFFER_TOO_SMALL(0x21)，并把所需长度回写
                var small = Marshal.AllocHGlobal(4);
                try
                {
                    for (var i = 0; i < 4; i++) Marshal.WriteByte(small, i, 0);
                    var need = (uint)4;
                    var src = f7(0, small, ref need);
                    Console.WriteLine($"   ext[7] M_EnumContainer(缓冲仅 4 字节) → rc=0x{src:X8} " +
                                      $"所需={need}" + (src == 0x21 ? "  ✅ 与厂商一致(0x21)" : "  ⚠ 期望 0x21"));
                }
                finally { Marshal.FreeHGlobal(small); }
            }
            finally { Marshal.FreeHGlobal(list); }

            // ------------------------------------------------ 文件槽位（「下载ISO」走的这条链）
            // 12=M_CreateFile(handle,name,size,rd,wr) 5 参；14=M_WriteFile(handle,name,off,data,size) 5 参；
            // 15=M_ReadFile(handle,name,off,size,out,outLen) 6 参；16=M_GetFileInfo；13=M_DeleteFile
            var fn12 = Marshal.ReadIntPtr(ext, 4 + 4 * 12);
            var fn13 = Marshal.ReadIntPtr(ext, 4 + 4 * 13);
            var fn14 = Marshal.ReadIntPtr(ext, 4 + 4 * 14);
            var fn15 = Marshal.ReadIntPtr(ext, 4 + 4 * 15);
            var fn16 = Marshal.ReadIntPtr(ext, 4 + 4 * 16);
            var fCreate = Marshal.GetDelegateForFunctionPointer<M_CreateFileFn>(fn12);
            var fDelete = Marshal.GetDelegateForFunctionPointer<M_DeleteFileFn>(fn13);
            var fWrite = Marshal.GetDelegateForFunctionPointer<M_WriteFileFn>(fn14);
            var fRead = Marshal.GetDelegateForFunctionPointer<M_ReadFileFn>(fn15);
            var fInfo = Marshal.GetDelegateForFunctionPointer<M_GetFileInfoFn>(fn16);

            const string testFile = "ZZTEST.DAT";
            var payload = Encoding.ASCII.GetBytes("HELLO-USBKEY-1234");
            var wbuf = Marshal.AllocHGlobal(payload.Length);
            var rbuf = Marshal.AllocHGlobal(64);
            var outLen = Marshal.AllocHGlobal(4);
            var fInfoBuf = Marshal.AllocHGlobal(32);
            try
            {
                for (var i = 0; i < payload.Length; i++) Marshal.WriteByte(wbuf, i, payload[i]);
                var crc = fCreate(0, testFile, (uint)payload.Length, 0, 0);
                Console.WriteLine($"   ext[12] M_CreateFile('{testFile}', size={payload.Length}) → rc=0x{crc:X8}");
                var wrc = fWrite(0, testFile, 0, wbuf, (uint)payload.Length);
                Console.WriteLine($"   ext[14] M_WriteFile(off=0, size={payload.Length}) → rc=0x{wrc:X8}");
                Marshal.WriteInt32(outLen, 64);
                var rrc = fRead(0, testFile, 0, 64, rbuf, outLen);
                var got = Marshal.PtrToStringAnsi(rbuf, Math.Min(Marshal.ReadInt32(outLen), 64)) ?? "";
                Console.WriteLine($"   ext[15] M_ReadFile → rc=0x{rrc:X8} 读回 {Marshal.ReadInt32(outLen)} 字节 " +
                                  $"'{got}'" + (got == Encoding.ASCII.GetString(payload) ? "  ✅ 与写入一致" : "  ⚠ 不一致"));
                var irc = fInfo(0, testFile, fInfoBuf);
                Console.WriteLine($"   ext[16] M_GetFileInfo → rc=0x{irc:X8}");
                var drc2 = fDelete(0, testFile);
                Console.WriteLine($"   ext[13] M_DeleteFile('{testFile}') → rc=0x{drc2:X8}");
                if (crc != 0 || wrc != 0 || rrc != 0 || drc2 != 0) _fail++;
            }
            finally
            {
                foreach (var p in new[] { wbuf, rbuf, outLen, fInfoBuf }) Marshal.FreeHGlobal(p);
            }

            // 槽位 3：M_SetTokenLabel(handle, label) —— 设成当前值，不改变设备状态
            var f3 = Marshal.GetDelegateForFunctionPointer<M_SetTokenLabelFn>(fn3);
            var lblRc = f3(0, "GM3000");
            Console.WriteLine($"   ext[3] M_SetTokenLabel('GM3000') → rc=0x{lblRc:X8}" +
                              (lblRc == 0 ? "  ✅" : "  ❌ 期望 0x0"));
            if (lblRc != 0) _fail++;
        }
        finally { Native.Free(h); }
    }

    /// <summary>解析 SKF/扩展表那种「多个以 NUL 结尾的名字首尾相接」的列表缓冲。</summary>
    private static List<string> ParseNameList(IntPtr buf, uint total)
    {
        var res = new List<string>();
        var pos = 0;
        while (pos < total)
        {
            var s = Marshal.PtrToStringAnsi(buf + pos) ?? "";
            if (s.Length == 0) break;
            res.Add(s);
            pos += s.Length + 1;
        }
        return res;
    }

    private static string Ansi(IntPtr p, int max)
    {
        var s = Marshal.PtrToStringAnsi(p, max) ?? "";
        var z = s.IndexOf('\0');
        return (z >= 0 ? s.Substring(0, z) : s).TrimEnd(' ');
    }

    // ------------------------------------------------------------ TokenMgr

    private static void ProbeTokenMgr(string tokenMgrDll, string pkcs11Path)
    {
        Console.WriteLine($"---- TokenMgr {tokenMgrDll}");
        var h = Native.Load(tokenMgrDll);
        if (h == IntPtr.Zero) { Console.WriteLine("   [x] 加载失败"); _fail++; return; }
        try
        {
            var init1 = Native.Del<TmInitFn>(h, "init_pkcs11");
            var init4 = Native.Del<TmInit4Fn>(h, "init_pkcs11_ex");
            var tokenFind = Native.Del<TokenFindFn>(h, "token_find");
            var tokenConnect = Native.Del<TokenConnectFn>(h, "token_connect");
            var tokenDisconnect = Native.Del<TokenDisconnectFn>(h, "token_disconnect");
            var tokenGetInfo = Native.Del<TokenGetInfoFn>(h, "token_get_info");

            if (init1 != null)
                Console.WriteLine($"   init_pkcs11(path) rc=0x{init1(pkcs11Path):X8}");
            else if (init4 != null)
                Console.WriteLine($"   init_pkcs11_ex rc=0x{init4(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, pkcs11Path):X8}");

            if (tokenFind == null) { Console.WriteLine("   [x] token_find 缺失"); _fail++; return; }

            var ids = new uint[32];
            uint cnt = (uint)ids.Length;
            var rc = tokenFind(ids, ref cnt);
            Console.WriteLine($"   token_find rc=0x{rc:X8} count={cnt}");
            if (rc != 0 || cnt == 0) { _fail++; return; }

            for (uint i = 0; i < cnt && i < 4; i++)
            {
                Console.WriteLine($"   == token[{i}] id={ids[i]}");
                if (tokenConnect != null)
                    Console.WriteLine($"      connect rc=0x{tokenConnect(ids[i]):X8}");
                if (tokenGetInfo != null)
                {
                    var bufs = new List<UB>();
                    try
                    {
                        for (int k = 0; k < 13; k++) bufs.Add(new UB(256));
                        var grc = tokenGetInfo(ids[i],
                            bufs[0].Ptr, bufs[1].Ptr, bufs[2].Ptr, bufs[3].Ptr,
                            bufs[4].Ptr, bufs[5].Ptr, bufs[6].Ptr, bufs[7].Ptr,
                            bufs[8].Ptr, bufs[9].Ptr, bufs[10].Ptr, bufs[11].Ptr, bufs[12].Ptr);
                        Console.WriteLine($"      token_get_info rc=0x{grc:X8}");
                        for (int k = 0; k < bufs.Count; k++)
                        {
                            bufs[k].ReadBack();
                            if (!bufs[k].Data.Any(b => b != 0)) continue;
                            Console.WriteLine($"         out[{k}] d0=0x{BitConverter.ToUInt32(bufs[k].Data, 0):X8} " +
                                              $"d1=0x{BitConverter.ToUInt32(bufs[k].Data, 4):X8} " +
                                              $"str='{FirstString(bufs[k].Data)}'");
                        }
                    }
                    finally { foreach (var b in bufs) b.Dispose(); }
                }
                if (tokenDisconnect != null)
                    Console.WriteLine($"      disconnect rc=0x{tokenDisconnect(ids[i]):X8}");
            }
        }
        finally { Native.Free(h); }
    }

    private static string FirstString(byte[] b)
    {
        int end = Array.IndexOf<byte>(b, 0);
        if (end <= 0) end = Math.Min(32, b.Length);
        return Encoding.ASCII.GetString(b, 0, end);
    }

    // ------------------------------------------------------------ 非托管缓冲

    private sealed class UB : IDisposable
    {
        public byte[] Data;
        public IntPtr Ptr;

        public UB(int n)
        {
            Data = new byte[n];
            Ptr = Marshal.AllocHGlobal(n);
            for (int i = 0; i < n; i++) Marshal.WriteByte(Ptr, i, 0);
        }

        public void ReadBack() => Marshal.Copy(Ptr, Data, 0, Data.Length);

        public void Dispose()
        {
            if (Ptr != IntPtr.Zero) Marshal.FreeHGlobal(Ptr);
            Ptr = IntPtr.Zero;
        }
    }

    // ------------------------------------------------------------ 委托

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfEnumDevFn([MarshalAs(UnmanagedType.Bool)] bool present, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfConnectDevFn(string name, out IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfDisconnectDevFn(IntPtr hDev);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfGetDevInfoFn(IntPtr hDev, IntPtr devInfo);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfGetDevStateFn(string name, out uint state);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfEnumContainerFn(IntPtr hDev, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfGenRandomFn(IntPtr hDev, byte[] buf, uint len);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfClearSecureStateFn(IntPtr h);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfVerifyPinFn(IntPtr h, uint pinType, string pin, ref uint retry);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfGetPINInfoFn(IntPtr hDev, uint pinType, ref uint a, ref uint b, ref uint c);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfEnumAppFn(IntPtr hDev, IntPtr nameList, ref uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfOpenAppFn(IntPtr hDev, string appName, out IntPtr hApp);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfCloseAppFn(IntPtr hApp);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int SkfOpenContFn(IntPtr hApp, string contName, out IntPtr hCont);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfCloseContFn(IntPtr hCont);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfGetContainerTypeFn(IntPtr hCont, out uint type);
    private delegate int SkfSetLabelFn(IntPtr h, string label);
    private delegate int TmSetLabelFn(uint index, string label);
    private delegate int TmChangePinFn(uint index, string oldPin, string newPin);
    private delegate int TmLoginSoFn(uint index, string pin, IntPtr retry);
    private delegate int TmPinStateFn(uint index, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4,
                                      IntPtr a5, IntPtr a6, IntPtr a7);
    private delegate int C_SetPinFn(uint session, string oldPin, uint oldLen, string newPin, uint newLen);
    private delegate int SkfCreateContFn(IntPtr hApp, string name, out IntPtr hCont);
    private delegate int SkfDeleteContFn(IntPtr hApp, string name);
    private delegate int SkfOpenContainerFn(IntPtr hApp, string name, out IntPtr hCont);
    private delegate int SkfCloseContainerFn(IntPtr hCont);
    private delegate int SkfEnumFilesFn(IntPtr hCont, IntPtr pBuf, ref uint pulLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int SkfExportCertFn(IntPtr hCont, [MarshalAs(UnmanagedType.Bool)] bool sign, IntPtr cert, ref uint len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_InitializeFn(IntPtr args);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_GetSlotListFn(byte tokenPresent, uint[] slotList, ref uint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_GetTokenInfoFn(uint slot, IntPtr info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_GetFunctionListFn(ref IntPtr list);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int M_GetExtListFn1(ref IntPtr list);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_OpenSessionFn(uint slot, uint flags, IntPtr app, IntPtr notify, ref uint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private delegate int C_LoginFn(uint session, uint userType, string pin, uint pinLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private delegate int C_InitPinFn(uint session, string pin, uint pinLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int C_LogoutFn(uint session);

    // 扩展表槽位 4：M_FormatToken(handle, arg2) —— 2 参纯 cdecl（厂商导出层实测）
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int M_FormatTokenFn(uint handle, IntPtr arg2);

    // 扩展表槽位 17：M_GetApplicationInfo(handle, char out[64], p3..p7) —— 7 参纯 cdecl
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int M_GetApplicationInfoFn(uint handle, IntPtr name64, IntPtr p3, IntPtr p4,
                                               IntPtr p5, IntPtr p6, IntPtr p7);

    // 扩展表槽位 0：M_GetUserInfo(handle, pinType, M_PIN_STATE* out12) —— 3 参纯 cdecl
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int M_GetUserInfoFn(uint handle, uint pinType, IntPtr out12);

    // 导入证书鏈路用到的扩展槽位（2.2.19 厂商表 rva 0x7BB30 确认的槽位与参数个数）
    private delegate int M_SetTokenLabelFn(uint handle, string label);
    private delegate int M_CreateContainerFn(uint handle, string name);
    private delegate int M_DeleteContainerFn(uint handle, string name);
    private delegate int M_EnumContainerFn(uint handle, IntPtr nameList, ref uint pulSize);
    private delegate int M_ReloadObjectsFn(uint handle, IntPtr a2, IntPtr a3, IntPtr a4);
    private delegate int M_SectorsFn(uint handle, uint startSector, uint sectorCount, IntPtr buf);
    private delegate int M_CreateFileFn(uint handle, string name, uint size, uint readRights, uint writeRights);
    private delegate int M_DeleteFileFn(uint handle, string name);
    private delegate int M_WriteFileFn(uint handle, string name, uint offset, IntPtr data, uint size);
    private delegate int M_ReadFileFn(uint handle, string name, uint offset, uint size, IntPtr outData, IntPtr outLen);
    private delegate int M_GetFileInfoFn(uint handle, string name, IntPtr fileInfo);
    private delegate int C_CreateObjectFn(uint session, IntPtr pTemplate, uint count, ref uint phObject);
    private delegate int C_FindObjectsInitFn(uint session, IntPtr pTemplate, uint count);
    private delegate int C_FindObjectsFn(uint session, IntPtr phObject, uint maxCount, ref uint foundCount);
    private delegate int C_FindObjectsFinalFn(uint session);
    private delegate int C_GetAttributeValueFn(uint session, uint hObject, IntPtr pTemplate, uint count);
    private delegate int M_ForceLogoutFn(uint handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int P11Init1Fn(string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int P11Init4Fn(IntPtr a, IntPtr b, IntPtr c, string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int TmInitFn(string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    private delegate int TmInit4Fn(IntPtr a, IntPtr b, IntPtr c, string path);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TokenFindFn(uint[] ids, ref uint count);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TokenConnectFn(uint index);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TokenDisconnectFn(uint index);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int TokenGetInfoFn(uint index, IntPtr a1, IntPtr a2, IntPtr a3, IntPtr a4,
                                        IntPtr a5, IntPtr a6, IntPtr a7, IntPtr a8,
                                        IntPtr a9, IntPtr a10, IntPtr a11, IntPtr a12, IntPtr a13);

    // ------------------------------------------------------------ 原生加载

    internal static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "LoadLibraryExW")]
        private static extern IntPtr LoadLibraryEx(string path, IntPtr h, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "LoadLibraryW")]
        private static extern IntPtr LoadLibraryRaw(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "SetDllDirectoryW")]
        private static extern bool SetDllDirectoryRaw(string path);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr h);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string name);

        private const uint LoadWithAlteredSearchPath = 0x8;

        public static IntPtr Load(string path)
        {
            if (!File.Exists(path)) return IntPtr.Zero;
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir)) SetDllDirectoryRaw(dir);
            var h = LoadLibraryEx(path, IntPtr.Zero, LoadWithAlteredSearchPath);
            if (h == IntPtr.Zero) h = LoadLibraryRaw(path);
            return h;
        }

        public static void Free(IntPtr h) { if (h != IntPtr.Zero) FreeLibrary(h); }
        public static IntPtr Proc(IntPtr h, string n) => GetProcAddress(h, n);

        public static T Del<T>(IntPtr h, string name) where T : Delegate
        {
            var p = GetProcAddress(h, name);
            return p == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(p);
        }
    }
}
