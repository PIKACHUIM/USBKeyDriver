using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using USBKey.Core.Native;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 北京数字认证（BJCA）USB Key 客户端组件 <c>XTXAppCOM.dll</c> 的原生调用封装。
///
/// <para><b>逆向结论（依据：DLL 内嵌 TypeLib、导出表、反汇编实测，详见
/// <c>Roadmap/07-BJCA逆向分析与对接.md</c>）：</b></para>
/// <list type="number">
/// <item>组件是 in-proc（ThreadingModel=Apartment）COM 服务器；
///       CoClass <c>XTXAppCOM.XTXApp.1</c> 的 CLSID 为 <c>{3F367B74-92D9-4C5E-AB93-234F8A91D5E6}</c>，
///       而 <c>IXTXApp</c> 的 IID 为 <c>{6C12D5B5-343C-4D55-B37E-7E7A151DCE71}</c>。
///       （随包发布的 <c>Program\COM.idl</c> 把 CLSID 误写成了 IXTXApp 的 uuid，实际以 DLL 内嵌 TypeLib 为准。）</item>
/// <item>DLL 导出 <c>DllGetClassObject</c>，因此 <b>无需 regsvr32 注册</b>，
///       直接 LoadLibrary → DllGetClassObject → IClassFactory::CreateInstance(IID_IXTXApp) 即可拿到对象。</item>
/// <item>IXTXApp 是 <b>dual/dispatch</b> 接口，方法 <c>[id(N)]</c> 即 dispid；
///       实测 <c>GetIDsOfNames</c> 可解析全部方法名，<c>IDispatch::Invoke</c> 可正常调用并取值。</item>
/// <item>因此本封装统一走 <b>IDispatch::Invoke（按 dispid）</b>：
///       参数经 DISPPARAMS/VARIANT 传递，由组件自身解释，<b>不依赖 C++ 导出函数的真实入参 ABI</b>，
///       即使随包 COM.idl 与二进制不一致也不会造成栈损坏。</item>
/// <item>接口方法<b>直接返回业务值</b>（<c>LONG</c>/<c>VARIANT_BOOL</c>/<c>BSTR</c>），不是
///       <c>HRESULT + [out,retval]</c>；调用成功时 Invoke 的 HRESULT 恒为 S_OK，
///       业务失败需看返回值（FALSE/0/空串）并结合 <c>SOF_GetLastError</c>/<c>SOF_GetLastErrMsg</c>。</item>
/// <item>组件内部使用 UI/智能卡资源（如 <c>SOF_SelectFile</c> 会弹出文件选择框），
///       故所有调用都在固定的 <b>STA 工作线程</b> 上串行执行。</item>
/// </list>
/// </summary>
internal static class BjcaNative
{
    /// <summary>32 位宿主使用的组件名（管理器为 x86 进程）。</summary>
    internal const string DllNameX86 = "XTXAppCOM.dll";

    /// <summary>64 位宿主使用的组件名。</summary>
    internal const string DllNameX64 = "XTXAppCOM_x64.dll";

    internal static readonly Guid ClsidXtxApp = new("3F367B74-92D9-4C5E-AB93-234F8A91D5E6");
    internal static readonly Guid IidXtxApp = new("6C12D5B5-343C-4D55-B37E-7E7A151DCE71");
    internal static readonly Guid IidClassFactory = new("00000001-0000-0000-C000-000000000046");

    /// <summary><c>InitDevice</c> 内部使用的出厂默认用户 PIN（反汇编常量 0x10236AE0 / 0x18038C590）。</summary>
    internal const string DefaultUserPin = "111111";

    /// <summary><c>InitDevice</c> 内部使用的默认密钥标签（反汇编常量 0x10236AD0 / 0x18038C580）。</summary>
    internal const string DefaultKeyLabel = "BJCA-UserKey";

    internal const int S_OK = 0;

    // ------------------------------------------------------------ 方法 dispid（== COM.idl 的 [id(N)]）
    internal const int DispSofGetUserList = 5;
    internal const int DispSofExportUserCert = 6;
    internal const int DispSofLogin = 7;
    internal const int DispSofGetPinRetryCount = 8;
    internal const int DispSofChangePassWd = 9;
    internal const int DispSofGetCertInfo = 10;
    internal const int DispSofGetCertInfoByOid = 11;
    internal const int DispSofGenRandom = 26;
    internal const int DispSofGetLastError = 31;
    internal const int DispGetDeviceCount = 32;
    internal const int DispGetAllDeviceSn = 33;
    internal const int DispGetDeviceSnByIndex = 34;
    internal const int DispGetDeviceInfo = 35;
    internal const int DispChangeAdminPass = 36;
    internal const int DispUnlockUserPass = 37;
    internal const int DispGenerateKeyPair = 38;
    internal const int DispExportPubKey = 39;
    internal const int DispImportSignCert = 40;
    internal const int DispIsContainerExist = 44;
    internal const int DispDeleteContainer = 45;
    internal const int DispExportPkcs10 = 46;
    internal const int DispInitDevice = 47;
    internal const int DispSofGetVersion = 56;
    internal const int DispSofExportExChangeUserCert = 57;
    internal const int DispSofValidateCert = 58;
    internal const int DispGetEnvSn = 59;
    internal const int DispSetEnvSn = 60;
    internal const int DispIsDeviceExist = 61;
    internal const int DispGetContainerCount = 62;
    internal const int DispSofGetLastErrMsg = 67;
    internal const int DispSofBase64Encode = 68;
    internal const int DispSofBase64Decode = 69;
    internal const int DispUnlockUserPassEx = 72;
    internal const int DispDeleteOldContainer = 73;
    internal const int DispSofGetRetryCount = 78;
    internal const int DispSofGetAllContainerName = 79;
    internal const int DispSofLogout = 85;
    internal const int DispOtpGetChallengeCode = 89;
    internal const int DispSofGetCertEntity = 91;
    internal const int DispInitDeviceEx = 95;
    internal const int DispSofBase64BinaryEncode = 109;
    internal const int DispSofBase64BinaryDecode = 110;
    internal const int DispImportPfxToDevice = 113;
    internal const int DispGetDeviceCountEx = 116;
    internal const int DispGetAllDeviceSnEx = 117;
    internal const int DispOtpGetChallengeCodeEx = 120;
    internal const int DispEnumFilesInDevice = 122;
    internal const int DispSofIsLogin = 131;
    internal const int DispSofLoginEx = 132;
    internal const int DispEnumSupportDeviceList = 133;
    internal const int DispSofGetProductVersion = 161;

    // ------------------------------------------------------------ VARIANT 类型
    internal const short VT_I2 = 2;
    internal const short VT_I4 = 3;
    internal const short VT_BSTR = 8;
    internal const short VT_BOOL = 11;

    // ------------------------------------------------------------ Win32 / COM

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllGetClassObjectFn(ref Guid rclsid, ref Guid riid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateInstanceFn(IntPtr self, IntPtr pUnkOuter, ref Guid riid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ReleaseFn(IntPtr self);

    [StructLayout(LayoutKind.Sequential)]
    internal struct DISPPARAMS
    {
        public IntPtr rgvarg;
        public IntPtr rgdispidNamedArgs;
        public int cArgs;
        public int cNamedArgs;
    }

    [ComImport, Guid("00020400-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDispatch
    {
        [PreserveSig] int GetTypeInfoCount(out uint pctinfo);

        [PreserveSig] int GetTypeInfo(uint iTInfo, uint lcid, out IntPtr ppTInfo);

        [PreserveSig] int GetIDsOfNames(ref Guid riid,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] rgszNames,
            uint cNames, uint lcid, [MarshalAs(UnmanagedType.LPArray)] int[] rgDispId);

        [PreserveSig] int Invoke(int dispIdMember, ref Guid riid, uint lcid, ushort wFlags,
            ref DISPPARAMS pDispParams, IntPtr pVarResult, IntPtr pExcepInfo, IntPtr puArgErr);
    }

    private static T VTableDelegate<T>(IntPtr comPtr, int slot) where T : Delegate
    {
        IntPtr vt = Marshal.ReadIntPtr(comPtr);
        IntPtr fn = Marshal.ReadIntPtr(vt, slot * IntPtr.Size);
        if (fn == IntPtr.Zero) throw new InvalidOperationException($"vtable[{slot}] 为空");
        return Marshal.GetDelegateForFunctionPointer<T>(fn);
    }

    private static void ReleaseCom(IntPtr p)
    {
        if (p == IntPtr.Zero) return;
        try { VTableDelegate<ReleaseFn>(p, 2)(p); } catch { /* 忽略 */ }
    }
}

/// <summary>
/// BJCA XTXAppCOM 调用会话：内部固定 STA 工作线程，串行执行所有 IDispatch 调用。
/// </summary>
internal sealed class BjcaSession : IDisposable
{
    private readonly BlockingCollection<Action> _queue = new();
    private readonly Thread _worker;
    private readonly ManualResetEventSlim _ready = new(false);
    private Exception? _initError;
    private IntPtr _module;
    private IntPtr _self;
    private BjcaNative.IDispatch? _disp;
    private bool _disposed;

    /// <summary>已加载的组件完整路径。</summary>
    public string DllPath { get; }

    /// <summary>组件版本（SOF_GetVersion）。</summary>
    public string Version { get; private set; } = "";

    /// <summary>产品版本（SOF_GetProductVersion）。</summary>
    public string ProductVersion { get; private set; } = "";

    /// <summary>支持的设备类型列表（EnumSupportDeviceList，形如 6588_1514&&&）。</summary>
    public string SupportDeviceList { get; private set; } = "";

    public bool IsReady => _initError == null && _self != IntPtr.Zero;
    public string InitError => _initError?.Message ?? string.Empty;

    public BjcaSession(string dllPath)
    {
        DllPath = dllPath;
        _worker = new Thread(WorkerLoop) { IsBackground = true, Name = "BJCA-XTXApp-STA" };
        _worker.SetApartmentState(ApartmentState.STA);
        _worker.Start();

        if (!_ready.Wait(TimeSpan.FromSeconds(30)))
            throw new TimeoutException($"初始化 BJCA 组件超时：{dllPath}");
        if (_initError != null)
            throw new InvalidOperationException($"初始化 BJCA 组件失败：{_initError.Message}", _initError);
        if (_self == IntPtr.Zero)
            throw new InvalidOperationException("初始化 BJCA 组件失败：未取得 XTXApp 对象");

        // 读取版本信息（失败不影响可用性）
        try
        {
            Version = GetVersion().Value ?? "";
            ProductVersion = GetProductVersion().Value ?? "";
            SupportDeviceList = EnumSupportDeviceList().Value ?? "";
        }
        catch { /* 忽略 */ }
    }

    private void WorkerLoop()
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(DllPath));
            if (!string.IsNullOrEmpty(dir)) SetDllDirectorySafe(dir);

            _module = LoadLibraryEx(DllPath, IntPtr.Zero, 0x8 /*LOAD_WITH_ALTERED_SEARCH_PATH*/);
            if (_module == IntPtr.Zero) _module = LoadLibrary(DllPath);
            if (_module == IntPtr.Zero)
                throw new InvalidOperationException(
                    $"无法加载 {Path.GetFileName(DllPath)}（Win32 错误 {Marshal.GetLastWin32Error()}）：请确认位数与宿主一致且依赖 DLL 齐全");

            IntPtr pGetClassObject = GetProcAddress(_module, "DllGetClassObject");
            if (pGetClassObject == IntPtr.Zero)
                throw new InvalidOperationException("组件未导出 DllGetClassObject，可能不是 XTXAppCOM");

            var getClassObject = Marshal.GetDelegateForFunctionPointer<DllGetClassObjectFn>(pGetClassObject);
            var clsid = BjcaNative.ClsidXtxApp;
            var iidCf = BjcaNative.IidClassFactory;
            int hr = getClassObject(ref clsid, ref iidCf, out IntPtr pcf);
            if (hr != 0 || pcf == IntPtr.Zero) throw new COMException($"DllGetClassObject 失败 hr=0x{hr:X8}", hr);

            try
            {
                var createInstance = VTableDelegateCreateInstance(pcf);
                var iid = BjcaNative.IidXtxApp;
                hr = createInstance(pcf, IntPtr.Zero, ref iid, out _self);
                if (hr != 0 || _self == IntPtr.Zero)
                    throw new COMException($"CreateInstance(IXTXApp) 失败 hr=0x{hr:X8}", hr);
            }
            finally
            {
                ReleaseCom(pcf);
            }

            _disp = (BjcaNative.IDispatch)Marshal.GetObjectForIUnknown(_self);
        }
        catch (Exception ex)
        {
            _initError = ex;
        }
        finally
        {
            _ready.Set();
        }

        if (_initError != null) return;

        foreach (var action in _queue.GetConsumingEnumerable())
        {
            try { action(); } catch { /* 由 Invoke 内部捕获并回抛 */ }
        }

        // 收尾顺序很关键，否则进程退出时会 Fatal error / ExecutionEngineException (0x80131506)。
        //
        // _disp 来自 Marshal.GetObjectForIUnknown，它是一个 RCW（运行时可调用包装），
        // 内部持有一份**独立于 _self 的 COM 引用**，且这份引用要等 RCW 被 GC 终结时才归还。
        // 若此处只 ReleaseCom(_self) 就 FreeLibrary 卸载组件，等 GC 稍后在终结器线程上
        // 去调 Release() —— 那已经是已卸载内存里的代码，必然崩。
        //
        // 因此在 DLL 尚未卸载、且仍在 STA 工作线程上时，先显式把 RCW 放掉。
        var disp = _disp;
        _disp = null;
        if (disp is not null)
        {
            try { Marshal.ReleaseComObject(disp); }
            catch { /* 释放失败不阻断后续清理 */ }
        }

        ReleaseCom(_self);
        _self = IntPtr.Zero;
        if (_module != IntPtr.Zero) { FreeLibrarySafe(_module); _module = IntPtr.Zero; }
    }

    private static CreateInstanceFn VTableDelegateCreateInstance(IntPtr pcf)
    {
        IntPtr vt = Marshal.ReadIntPtr(pcf);
        IntPtr fn = Marshal.ReadIntPtr(vt, 3 * IntPtr.Size);
        return Marshal.GetDelegateForFunctionPointer<CreateInstanceFn>(fn);
    }

    private static void ReleaseCom(IntPtr p)
    {
        if (p == IntPtr.Zero) return;
        try
        {
            IntPtr vt = Marshal.ReadIntPtr(p);
            IntPtr fn = Marshal.ReadIntPtr(vt, 2 * IntPtr.Size);
            var rel = Marshal.GetDelegateForFunctionPointer<ReleaseFn>(fn);
            rel(p);
        }
        catch { }
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ReleaseFn(IntPtr self);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int DllGetClassObjectFn(ref Guid rclsid, ref Guid riid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateInstanceFn(IntPtr self, IntPtr pUnkOuter, ref Guid riid, out IntPtr ppv);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    private static void SetDllDirectorySafe(string dir) { try { SetDllDirectory(dir); } catch { } }
    private static void FreeLibrarySafe(IntPtr h) { try { FreeLibrary(h); } catch { } }

    // ------------------------------------------------------------ 调度

    private T InvokeOnSta<T>(Func<T> func)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        T result = default!;
        Exception? error = null;
        using var done = new ManualResetEventSlim(false);
        _queue.Add(() =>
        {
            try { result = func(); }
            catch (Exception ex) { error = ex; }
            finally { done.Set(); }
        });
        done.Wait();
        if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
        return result;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            _queue.CompleteAdding();
            _worker.Join(TimeSpan.FromSeconds(10));
        }
        catch { }
        _ready.Dispose();
    }

    // ------------------------------------------------------------ DISPPARAMS 构造与调用

    /// <summary>调用参数（[in] 参数，不含返回值）。</summary>
    private readonly struct Arg
    {
        public readonly short Vt;
        public readonly object? Value;
        public Arg(short vt, object? value) { Vt = vt; Value = value; }
        public static Arg Bstr(string? s) => new(BjcaNative.VT_BSTR, s ?? "");
        public static Arg I4(int v) => new(BjcaNative.VT_I4, v);
        public static Arg Bool(bool v) => new(BjcaNative.VT_BOOL, v);
    }

    /// <summary>调用结果。Value 为 string/int/bool。</summary>
    public readonly struct Result
    {
        public readonly int Hr;
        public readonly string? Value;
        public readonly int IntValue;
        public readonly bool BoolValue;
        public readonly short RetVt;
        public Result(int hr, string? value, int intValue, bool boolValue, short retVt)
        { Hr = hr; Value = value; IntValue = intValue; BoolValue = boolValue; RetVt = retVt; }
    }

    private Result Call(int dispid, short retVt, params Arg[] args)
    {
        return InvokeOnSta(() =>
        {
            if (_disp == null) throw new InvalidOperationException("组件未初始化");

            IntPtr argMem = IntPtr.Zero;
            IntPtr resultMem = Marshal.AllocHGlobal(32);
            var allocatedBstrs = new List<IntPtr>();
            try
            {
                for (int i = 0; i < 32; i++) Marshal.WriteByte(resultMem, i, 0);

                if (args.Length > 0)
                {
                    int size = args.Length * 16;
                    argMem = Marshal.AllocHGlobal(size + 16);
                    for (int i = 0; i < size + 16; i++) Marshal.WriteByte(argMem, i, 0);
                    // DISPPARAMS 参数按逆序排列
                    for (int i = 0; i < args.Length; i++)
                    {
                        var a = args[args.Length - 1 - i];
                        IntPtr p = argMem + i * 16;
                        Marshal.WriteInt16(p, 0, a.Vt);
                        switch (a.Vt)
                        {
                            case BjcaNative.VT_BSTR:
                                IntPtr b = Marshal.StringToBSTR((string?)a.Value ?? "");
                                allocatedBstrs.Add(b);
                                Marshal.WriteIntPtr(p, 8, b);
                                break;
                            case BjcaNative.VT_I4:
                                Marshal.WriteInt32(p, 8, Convert.ToInt32(a.Value));
                                break;
                            case BjcaNative.VT_I2:
                                Marshal.WriteInt16(p, 8, (short)Convert.ToInt32(a.Value));
                                break;
                            case BjcaNative.VT_BOOL:
                                Marshal.WriteInt16(p, 8, (short)(Convert.ToBoolean(a.Value) ? -1 : 0));
                                break;
                        }
                    }
                }

                var dp = new BjcaNative.DISPPARAMS
                {
                    rgvarg = argMem,
                    rgdispidNamedArgs = IntPtr.Zero,
                    cArgs = args.Length,
                    cNamedArgs = 0,
                };

                var iid = Guid.Empty;
                int hr = _disp!.Invoke(dispid, ref iid, 0x0804 /*zh-CN*/, 0x1 /*DISPATCH_METHOD*/,
                    ref dp, resultMem, IntPtr.Zero, IntPtr.Zero);

                short outVt = Marshal.ReadInt16(resultMem, 0);
                string? str = null;
                int iv = 0;
                bool bv = false;
                switch (outVt)
                {
                    case BjcaNative.VT_BSTR:
                        IntPtr sp = Marshal.ReadIntPtr(resultMem, 8);
                        if (sp != IntPtr.Zero) str = Marshal.PtrToStringBSTR(sp);
                        break;
                    case BjcaNative.VT_I4:
                    case 22: // VT_INT
                        iv = Marshal.ReadInt32(resultMem, 8);
                        break;
                    case BjcaNative.VT_I2:
                        iv = Marshal.ReadInt16(resultMem, 8);
                        break;
                    case BjcaNative.VT_BOOL:
                        bv = Marshal.ReadInt16(resultMem, 8) != 0;
                        iv = Marshal.ReadInt16(resultMem, 8);
                        break;
                }

                // 让 Value 对非字符串返回也有可读文本（日志/报告统一取 Value）
                if (str == null)
                {
                    str = outVt switch
                    {
                        BjcaNative.VT_I4 or 22 => iv.ToString(),
                        BjcaNative.VT_I2 => iv.ToString(),
                        BjcaNative.VT_BOOL => bv ? "TRUE" : "FALSE",
                        _ => "",
                    };
                }

                // 释放出参 BSTR 与结果 VARIANT 内的 BSTR
                if (outVt == BjcaNative.VT_BSTR)
                {
                    IntPtr sp = Marshal.ReadIntPtr(resultMem, 8);
                    if (sp != IntPtr.Zero) { try { Marshal.FreeBSTR(sp); } catch { } Marshal.WriteIntPtr(resultMem, 8, IntPtr.Zero); }
                }

                return new Result(hr, str, iv, bv, outVt);
            }
            finally
            {
                foreach (var b in allocatedBstrs) { try { Marshal.FreeBSTR(b); } catch { } }
                if (argMem != IntPtr.Zero) Marshal.FreeHGlobal(argMem);
                Marshal.FreeHGlobal(resultMem);
            }
        });
    }

    // ------------------------------------------------------------ 业务方法封装（dispid + 类型均来自 DLL 内嵌 TypeLib）

    /// <summary>SOF_GetVersion() -> BSTR</summary>
    public Result GetVersion() => Call(BjcaNative.DispSofGetVersion, BjcaNative.VT_BSTR);

    /// <summary>SOF_GetProductVersion() -> BSTR</summary>
    public Result GetProductVersion() => Call(BjcaNative.DispSofGetProductVersion, BjcaNative.VT_BSTR);

    /// <summary>EnumSupportDeviceList() -> BSTR（形如 "6588_1514&&&6588_1506&&&"）</summary>
    public Result EnumSupportDeviceList() => Call(BjcaNative.DispEnumSupportDeviceList, BjcaNative.VT_BSTR);

    /// <summary>GetDeviceCount() -> LONG</summary>
    public Result GetDeviceCount() => Call(BjcaNative.DispGetDeviceCount, BjcaNative.VT_I4);

    /// <summary>GetAllDeviceSN() -> BSTR（形如 "5303201812001784;"）</summary>
    public Result GetAllDeviceSN() => Call(BjcaNative.DispGetAllDeviceSn, BjcaNative.VT_BSTR);

    /// <summary>GetAllDeviceSNEx(type) -> BSTR</summary>
    public Result GetAllDeviceSNEx(int type) => Call(BjcaNative.DispGetAllDeviceSnEx, BjcaNative.VT_BSTR, Arg.I4(type));

    /// <summary>GetDeviceCountEx(type) -> LONG</summary>
    public Result GetDeviceCountEx(int type) => Call(BjcaNative.DispGetDeviceCountEx, BjcaNative.VT_I4, Arg.I4(type));

    /// <summary>GetDeviceSNByIndex(iIndex) -> BSTR</summary>
    public Result GetDeviceSNByIndex(int index) => Call(BjcaNative.DispGetDeviceSnByIndex, BjcaNative.VT_BSTR, Arg.I4(index));

    /// <summary>GetDeviceInfo(sDeviceSN, iType) -> BSTR</summary>
    public Result GetDeviceInfo(string sn, int type) =>
        Call(BjcaNative.DispGetDeviceInfo, BjcaNative.VT_BSTR, Arg.Bstr(sn), Arg.I4(type));

    /// <summary>IsDeviceExist(sDeviceSN) -> VARIANT_BOOL</summary>
    public Result IsDeviceExist(string sn) =>
        Call(BjcaNative.DispIsDeviceExist, BjcaNative.VT_BOOL, Arg.Bstr(sn));

    /// <summary>InitDevice(sDeviceSN, sAdminPass) -> VARIANT_BOOL（重置并清空，出厂默认用户 PIN/标签）</summary>
    public Result InitDevice(string sn, string adminPass) =>
        Call(BjcaNative.DispInitDevice, BjcaNative.VT_BOOL, Arg.Bstr(sn), Arg.Bstr(adminPass));

    /// <summary>
    /// InitDeviceEx(sDeviceSN, sAdminPass, sUserPin, sKeyLabel, adminPinMaxRetry, userPinMaxRetry) -> VARIANT_BOOL
    /// 「重置 USBKey + 清空内容 + 重设管理口令/用户 PIN」一步到位。
    /// </summary>
    public Result InitDeviceEx(string sn, string adminPass, string userPin, string keyLabel,
                               int adminPinMaxRetry, int userPinMaxRetry) =>
        Call(BjcaNative.DispInitDeviceEx, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(adminPass), Arg.Bstr(userPin), Arg.Bstr(keyLabel),
            Arg.I4(adminPinMaxRetry), Arg.I4(userPinMaxRetry));

    /// <summary>ChangeAdminPass(sDeviceSN, sOldPass, sNewPass) -> VARIANT_BOOL</summary>
    public Result ChangeAdminPass(string sn, string oldPass, string newPass) =>
        Call(BjcaNative.DispChangeAdminPass, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(oldPass), Arg.Bstr(newPass));

    /// <summary>UnlockUserPass(sDeviceSN, sAdminPass, sNewUserPass) -> VARIANT_BOOL</summary>
    public Result UnlockUserPass(string sn, string adminPass, string newUserPass) =>
        Call(BjcaNative.DispUnlockUserPass, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(adminPass), Arg.Bstr(newUserPass));

    /// <summary>UnlockUserPassEx(sDeviceSN, sAdminPin, sNewUserPass) -> VARIANT_BOOL</summary>
    public Result UnlockUserPassEx(string sn, string adminPin, string newUserPass) =>
        Call(BjcaNative.DispUnlockUserPassEx, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(adminPin), Arg.Bstr(newUserPass));

    /// <summary>GetContainerCount(sDeviceSN) -> LONG</summary>
    public Result GetContainerCount(string sn) =>
        Call(BjcaNative.DispGetContainerCount, BjcaNative.VT_I4, Arg.Bstr(sn));

    /// <summary>SOF_GetAllContainerName(sDeviceSN) -> BSTR</summary>
    public Result GetAllContainerName(string sn) =>
        Call(BjcaNative.DispSofGetAllContainerName, BjcaNative.VT_BSTR, Arg.Bstr(sn));

    /// <summary>EnumFilesInDevice(sDeviceSN) -> BSTR</summary>
    public Result EnumFilesInDevice(string sn) =>
        Call(BjcaNative.DispEnumFilesInDevice, BjcaNative.VT_BSTR, Arg.Bstr(sn));

    /// <summary>DeleteContainer(sDeviceSN, sContainerName) -> VARIANT_BOOL</summary>
    public Result DeleteContainer(string sn, string containerName) =>
        Call(BjcaNative.DispDeleteContainer, BjcaNative.VT_BOOL, Arg.Bstr(sn), Arg.Bstr(containerName));

    /// <summary>DeleteOldContainer(sDeviceSN) -> VARIANT_BOOL</summary>
    public Result DeleteOldContainer(string sn) =>
        Call(BjcaNative.DispDeleteOldContainer, BjcaNative.VT_BOOL, Arg.Bstr(sn));

    /// <summary>IsContainerExist(sDeviceSN, sContainerName) -> VARIANT_BOOL</summary>
    public Result IsContainerExist(string sn, string containerName) =>
        Call(BjcaNative.DispIsContainerExist, BjcaNative.VT_BOOL, Arg.Bstr(sn), Arg.Bstr(containerName));

    /// <summary>GetENVSN(sDeviceSN) -> BSTR</summary>
    public Result GetEnvSn(string sn) => Call(BjcaNative.DispGetEnvSn, BjcaNative.VT_BSTR, Arg.Bstr(sn));

    /// <summary>SetENVSN(sDeviceSN, sEnvsn) -> VARIANT_BOOL</summary>
    public Result SetEnvSn(string sn, string envSn) =>
        Call(BjcaNative.DispSetEnvSn, BjcaNative.VT_BOOL, Arg.Bstr(sn), Arg.Bstr(envSn));

    /// <summary>SOF_GetUserList() -> BSTR（证书/容器 ID 列表）</summary>
    public Result GetUserList() => Call(BjcaNative.DispSofGetUserList, BjcaNative.VT_BSTR);

    /// <summary>SOF_ExportUserCert(CertID) -> BSTR（base64 或 PEM）</summary>
    public Result ExportUserCert(string certId) =>
        Call(BjcaNative.DispSofExportUserCert, BjcaNative.VT_BSTR, Arg.Bstr(certId));

    /// <summary>SOF_Login(CertID, PassWd) -> VARIANT_BOOL</summary>
    public Result Login(string certId, string password) =>
        Call(BjcaNative.DispSofLogin, BjcaNative.VT_BOOL, Arg.Bstr(certId), Arg.Bstr(password));

    /// <summary>SOF_LoginEx(CertID, PassWd, updateFlag) -> VARIANT_BOOL</summary>
    public Result LoginEx(string certId, string password, int updateFlag) =>
        Call(BjcaNative.DispSofLoginEx, BjcaNative.VT_BOOL,
            Arg.Bstr(certId), Arg.Bstr(password), Arg.I4(updateFlag));

    /// <summary>SOF_Logout(CertID) -> VARIANT_BOOL</summary>
    public Result Logout(string certId) =>
        Call(BjcaNative.DispSofLogout, BjcaNative.VT_BOOL, Arg.Bstr(certId));

    /// <summary>SOF_IsLogin(CertID) -> VARIANT_BOOL</summary>
    public Result IsLogin(string certId) =>
        Call(BjcaNative.DispSofIsLogin, BjcaNative.VT_BOOL, Arg.Bstr(certId));

    /// <summary>SOF_ChangePassWd(CertID, oldPass, newPass) -> VARIANT_BOOL</summary>
    public Result ChangePassWd(string certId, string oldPass, string newPass) =>
        Call(BjcaNative.DispSofChangePassWd, BjcaNative.VT_BOOL,
            Arg.Bstr(certId), Arg.Bstr(oldPass), Arg.Bstr(newPass));

    /// <summary>SOF_GetPinRetryCount(CertID) -> LONG</summary>
    public Result GetPinRetryCount(string certId) =>
        Call(BjcaNative.DispSofGetPinRetryCount, BjcaNative.VT_I4, Arg.Bstr(certId));

    /// <summary>SOF_GetRetryCount(CertID) -> LONG</summary>
    public Result GetRetryCount(string certId) =>
        Call(BjcaNative.DispSofGetRetryCount, BjcaNative.VT_I4, Arg.Bstr(certId));

    /// <summary>SOF_GetCertInfo(Cert, type) -> BSTR</summary>
    public Result GetCertInfo(string cert, short type) =>
        Call(BjcaNative.DispSofGetCertInfo, BjcaNative.VT_BSTR, Arg.Bstr(cert), new Arg(BjcaNative.VT_I2, (int)type));

    /// <summary>SOF_GetCertInfoByOid(Cert, Oid) -> BSTR</summary>
    public Result GetCertInfoByOid(string cert, string oid) =>
        Call(BjcaNative.DispSofGetCertInfoByOid, BjcaNative.VT_BSTR, Arg.Bstr(cert), Arg.Bstr(oid));

    /// <summary>SOF_ValidateCert(Cert) -> LONG</summary>
    public Result ValidateCert(string cert) =>
        Call(BjcaNative.DispSofValidateCert, BjcaNative.VT_I4, Arg.Bstr(cert));

    /// <summary>SOF_GetCertEntity(sCert) -> BSTR</summary>
    public Result GetCertEntity(string cert) =>
        Call(BjcaNative.DispSofGetCertEntity, BjcaNative.VT_BSTR, Arg.Bstr(cert));

    /// <summary>SOF_ExportExChangeUserCert(CertID) -> BSTR</summary>
    public Result ExportExchangeUserCert(string certId) =>
        Call(BjcaNative.DispSofExportExChangeUserCert, BjcaNative.VT_BSTR, Arg.Bstr(certId));

    /// <summary>GenerateKeyPair(sDeviceSN, sContainerName, iKeyType, bSign) -> VARIANT_BOOL</summary>
    public Result GenerateKeyPair(string sn, string containerName, int keyType, bool sign) =>
        Call(BjcaNative.DispGenerateKeyPair, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(containerName), Arg.I4(keyType), Arg.Bool(sign));

    /// <summary>ExportPubKey(sDeviceSN, sContainerName, bSign) -> BSTR</summary>
    public Result ExportPubKey(string sn, string containerName, bool sign) =>
        Call(BjcaNative.DispExportPubKey, BjcaNative.VT_BSTR,
            Arg.Bstr(sn), Arg.Bstr(containerName), Arg.Bool(sign));

    /// <summary>ExportPKCS10(sDeviceSN, sContainerName, sDN, bSign) -> BSTR</summary>
    public Result ExportPkcs10(string sn, string containerName, string dn, bool sign) =>
        Call(BjcaNative.DispExportPkcs10, BjcaNative.VT_BSTR,
            Arg.Bstr(sn), Arg.Bstr(containerName), Arg.Bstr(dn), Arg.Bool(sign));

    /// <summary>ImportSignCert(sDeviceSN, sContainerName, sCert) -> VARIANT_BOOL</summary>
    public Result ImportSignCert(string sn, string containerName, string cert) =>
        Call(BjcaNative.DispImportSignCert, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(containerName), Arg.Bstr(cert));

    /// <summary>ImportPfxToDevice(sDeviceSN, sContainerName, bSign, strPfx, strPfxPass) -> VARIANT_BOOL</summary>
    public Result ImportPfxToDevice(string sn, string containerName, bool sign, string pfxBase64, string pfxPassword) =>
        Call(BjcaNative.DispImportPfxToDevice, BjcaNative.VT_BOOL,
            Arg.Bstr(sn), Arg.Bstr(containerName), Arg.Bool(sign), Arg.Bstr(pfxBase64), Arg.Bstr(pfxPassword));

    /// <summary>OTP_GetChallengeCode(sCertID) -> BSTR</summary>
    public Result GetChallengeCode(string certId) =>
        Call(BjcaNative.DispOtpGetChallengeCode, BjcaNative.VT_BSTR, Arg.Bstr(certId));

    /// <summary>SOF_GenRandom(RandomLen) -> BSTR</summary>
    public Result GenRandom(int len) =>
        Call(BjcaNative.DispSofGenRandom, BjcaNative.VT_BSTR, Arg.I4(len));

    /// <summary>SOF_Base64Encode(sInData) -> BSTR</summary>
    public Result Base64Encode(string data) =>
        Call(BjcaNative.DispSofBase64Encode, BjcaNative.VT_BSTR, Arg.Bstr(data));

    /// <summary>SOF_Base64Decode(sInData) -> BSTR</summary>
    public Result Base64Decode(string data) =>
        Call(BjcaNative.DispSofBase64Decode, BjcaNative.VT_BSTR, Arg.Bstr(data));

    /// <summary>SOF_GetLastError() -> LONG</summary>
    public Result GetLastError() => Call(BjcaNative.DispSofGetLastError, BjcaNative.VT_I4);

    /// <summary>SOF_GetLastErrMsg() -> BSTR</summary>
    public Result GetLastErrMsg() => Call(BjcaNative.DispSofGetLastErrMsg, BjcaNative.VT_BSTR);

    /// <summary>最近一次业务错误描述（调用失败时用于拼错误信息）。</summary>
    public string DescribeLastError()
    {
        try
        {
            var code = GetLastError();
            var msg = GetLastErrMsg();
            var parts = new List<string>();
            if (code.RetVt == BjcaNative.VT_I4 && code.IntValue != 0)
                parts.Add($"错误码 {(uint)code.IntValue}(0x{code.IntValue:X8})");
            if (!string.IsNullOrWhiteSpace(msg.Value)) parts.Add(msg.Value!.Trim());
            return parts.Count == 0 ? "" : string.Join("，", parts);
        }
        catch
        {
            return "";
        }
    }
}
