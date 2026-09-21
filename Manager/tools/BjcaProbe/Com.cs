using System.Runtime.InteropServices;

namespace BjcaProbe;

/// <summary>
/// 最小 COM 互操作基础设施：XTXAppCOM.dll 的免注册（DllGetClassObject）激活，
/// 以及基于 IDispatch::Invoke 的「ABI 无关」方法调用。
///
/// 之所以用 IDispatch::Invoke：DLL 的实际 C++ 导出 ABI（参数个数/顺序）可能与
/// 随包发布的 COM.idl 不一致，直接按导出名做 P/Invoke 一旦参数不符就会栈损坏；
/// 而 IDispatch::Invoke 走 DISPPARAMS（VARIANT 数组），由对象自身解释，
/// 不存在 ABI 错配导致崩溃的风险。
/// </summary>
public static class Com
{
    /// <summary>CoClass XTXApp 的 CLSID（内嵌 typelib 中 TKIND_COCLASS 的 GUID）。</summary>
    public static readonly Guid ClsidXtxApp = new("3F367B74-92D9-4C5E-AB93-234F8A91D5E6");

    /// <summary>
    /// IXTXApp 的 IID。注意：COM.idl 里把 CLSID 误写成了 IXTXApp 的 uuid，
    /// 而 DLL 内嵌 typelib 显示 IXTXApp 的 IID 实为 {6C12D5B5-...}。
    /// </summary>
    public static readonly Guid IidXtxApp = new("6C12D5B5-343C-4D55-B37E-7E7A151DCE71");

    public static readonly Guid IidClassFactory = new("00000001-0000-0000-C000-000000000046");
    public static readonly Guid IidNull = Guid.Empty;

    public const ushort DISPATCH_METHOD = 0x1;
    public const ushort DISPATCH_PROPERTYGET = 0x2;

    // VARIANT vt 常量
    public const short VT_I2 = 2;
    public const short VT_I4 = 3;
    public const short VT_BSTR = 8;
    public const short VT_DISPATCH = 9;
    public const short VT_BOOL = 11;
    public const short VT_VARIANT = 12;
    public const short VT_UNKNOWN = 13;
    public const short VT_BYREF = 0x4000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetDllDirectory(string lpPathName);

    [DllImport("oleaut32.dll", PreserveSig = true)]
    public static extern int VariantClear(IntPtr pvarg);

    public const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x8;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int DllGetClassObjectFn(ref Guid rclsid, ref Guid riid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int CreateInstanceFn(IntPtr self, IntPtr pUnkOuter, ref Guid riid, out IntPtr ppv);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int ReleaseFn(IntPtr self);

    /// <summary>
    /// 按名字导出的 <c>SOF_Initialize(LPCTSTR appName)</c>。
    /// 它<b>不是</b> IDispatch 成员（内嵌 TypeLib 里没有、无 dispid），只能按导出名调用；
    /// 反汇编显示它转发到 <c>SOF_InitializeEx(arg1, 0, 0)</c>，内部创建 CKM 实例与 tokenman 上下文。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int SofInitializeFn(IntPtr appName);

    [StructLayout(LayoutKind.Sequential)]
    public struct DISPPARAMS
    {
        public IntPtr rgvarg;
        public IntPtr rgdispidNamedArgs;
        public int cArgs;
        public int cNamedArgs;
    }

    [ComImport, Guid("00020400-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IDispatch
    {
        [PreserveSig] int GetTypeInfoCount(out uint pctinfo);

        [PreserveSig] int GetTypeInfo(uint iTInfo, uint lcid, out IntPtr ppTInfo);

        [PreserveSig] int GetIDsOfNames(ref Guid riid,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] rgszNames,
            uint cNames, uint lcid, [MarshalAs(UnmanagedType.LPArray)] int[] rgDispId);

        [PreserveSig] int Invoke(int dispIdMember, ref Guid riid, uint lcid, ushort wFlags,
            ref DISPPARAMS pDispParams, IntPtr pVarResult, IntPtr pExcepInfo, IntPtr puArgErr);
    }

    /// <summary>VARIANT 尺寸（x86/x64 均为 16 字节）。</summary>
    public static int VariantSize => 16;

    public static T VTableDelegate<T>(IntPtr comPtr, int slot) where T : Delegate
    {
        IntPtr vt = Marshal.ReadIntPtr(comPtr);
        IntPtr fn = Marshal.ReadIntPtr(vt, slot * IntPtr.Size);
        if (fn == IntPtr.Zero) throw new InvalidOperationException($"vtable[{slot}] 为空");
        return Marshal.GetDelegateForFunctionPointer<T>(fn);
    }

    public static void Release(IntPtr p)
    {
        if (p == IntPtr.Zero) return;
        VTableDelegate<ReleaseFn>(p, 2)(p);
    }

    /// <summary>加载 DLL 并创建 IXTXApp 对象（免注册）。</summary>
    public static (IntPtr Module, IntPtr Self) CreateXtxApp(string dllPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(dllPath));
        if (!string.IsNullOrEmpty(dir)) SetDllDirectory(dir);

        var h = LoadLibraryEx(dllPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (h == IntPtr.Zero)
        {
            h = LoadLibrary(dllPath);
            if (h == IntPtr.Zero)
                throw new InvalidOperationException($"LoadLibrary 失败，Win32Error={Marshal.GetLastWin32Error()}");
        }

        var p = GetProcAddress(h, "DllGetClassObject");
        if (p == IntPtr.Zero) throw new InvalidOperationException("未找到 DllGetClassObject");
        var getClassObject = Marshal.GetDelegateForFunctionPointer<DllGetClassObjectFn>(p);

        var clsid = ClsidXtxApp;
        var iidCf = IidClassFactory;
        int hr = getClassObject(ref clsid, ref iidCf, out IntPtr pcf);
        if (hr != 0 || pcf == IntPtr.Zero) throw new COMException($"DllGetClassObject hr=0x{hr:X8}", hr);

        try
        {
            var createInstance = VTableDelegate<CreateInstanceFn>(pcf, 3);
            var iid = IidXtxApp;
            hr = createInstance(pcf, IntPtr.Zero, ref iid, out IntPtr self);
            if (hr != 0 || self == IntPtr.Zero) throw new COMException($"CreateInstance hr=0x{hr:X8}", hr);
            return (h, self);
        }
        finally
        {
            Release(pcf);
        }
    }

    // ------------------------------------------------------------ VARIANT 手工构造
    public sealed class VariantBlock : IDisposable
    {
        private readonly IntPtr _mem;
        private readonly List<IntPtr> _inner = new();
        public int Count { get; }
        public IntPtr Ptr => _mem;

        public VariantBlock(int count)
        {
            Count = count;
            _mem = Marshal.AllocHGlobal(Math.Max(1, count * 16) + 16);
            for (int i = 0; i < count * 16 + 16; i++) Marshal.WriteByte(_mem, i, 0);
        }

        /// <summary>写入第 i 个 VARIANT：按值（BSTR/I4/BOOL）。</summary>
        public void SetByValue(int i, short vt, object value)
        {
            IntPtr p = _mem + i * 16;
            Marshal.WriteInt16(p, 0, vt);
            switch (vt)
            {
                case VT_BSTR:
                    Marshal.WriteIntPtr(p, 8, Marshal.StringToBSTR((string)value));
                    break;
                case VT_I4:
                    Marshal.WriteInt32(p, 8, Convert.ToInt32(value));
                    break;
                case VT_I2:
                    Marshal.WriteInt16(p, 8, (short)Convert.ToInt32(value));
                    break;
                case VT_BOOL:
                    Marshal.WriteInt16(p, 8, (short)(Convert.ToBoolean(value) ? -1 : 0));
                    break;
                default:
                    throw new NotSupportedException($"未支持的按值 vt={vt}");
            }
        }

        /// <summary>写入第 i 个 VARIANT：按引用（*BSTR / *I4 / *BOOL），返回可读回值的槽位。</summary>
        public IntPtr SetByRef(int i, short baseVt)
        {
            IntPtr slot = Marshal.AllocHGlobal(8);
            Marshal.WriteInt64(slot, 0);
            _inner.Add(slot);
            IntPtr p = _mem + i * 16;
            Marshal.WriteInt16(p, 0, (short)(baseVt | VT_BYREF));
            Marshal.WriteIntPtr(p, 8, slot);
            return slot;
        }

        public string ReadBstrSlot(IntPtr slot)
        {
            IntPtr s = Marshal.ReadIntPtr(slot);
            if (s == IntPtr.Zero) return "";
            try { return Marshal.PtrToStringBSTR(s) ?? ""; }
            finally { Marshal.FreeBSTR(s); }
        }

        public int ReadIntSlot(IntPtr slot) => Marshal.ReadInt32(slot);
        public short ReadBoolSlot(IntPtr slot) => Marshal.ReadInt16(slot);

        public void FreeBstrValues()
        {
            for (int i = 0; i < Count; i++)
            {
                IntPtr p = _mem + i * 16;
                if (Marshal.ReadInt16(p, 0) == VT_BSTR)
                {
                    IntPtr s = Marshal.ReadIntPtr(p, 8);
                    if (s != IntPtr.Zero) { Marshal.FreeBSTR(s); Marshal.WriteIntPtr(p, 8, IntPtr.Zero); }
                }
            }
        }

        public void Dispose()
        {
            FreeBstrValues();
            foreach (var s in _inner) Marshal.FreeHGlobal(s);
            Marshal.FreeHGlobal(_mem);
        }
    }

    /// <summary>
    /// 通过 IDispatch::Invoke 调用方法。
    /// <paramref name="args"/> 只包含 [in]/[out] 参数（不含 [out,retval]，其经 pVarResult 返回）。
    /// </summary>
    public static (int Hr, object RetVal, string Err) Invoke(IDispatch disp, int dispid,
        (short Vt, object Value)[] args, short retVt)
    {
        using var block = new VariantBlock(args.Length);
        // DISPPARAMS 参数为逆序
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[args.Length - 1 - i];
            block.SetByValue(i, a.Vt, a.Value);
        }

        IntPtr pResult = Marshal.AllocHGlobal(32);
        try
        {
            for (int i = 0; i < 32; i++) Marshal.WriteByte(pResult, i, 0);
            Marshal.WriteInt16(pResult, 0, retVt);

            var dp = new DISPPARAMS
            {
                rgvarg = block.Ptr,
                rgdispidNamedArgs = IntPtr.Zero,
                cArgs = args.Length,
                cNamedArgs = 0,
            };
            var iid = IidNull;
            int hr = disp.Invoke(dispid, ref iid, 0x0804 /*zh-CN*/, DISPATCH_METHOD, ref dp, pResult, IntPtr.Zero, IntPtr.Zero);

            object ret = retVt switch
            {
                VT_BSTR => Marshal.PtrToStringBSTR(Marshal.ReadIntPtr(pResult, 8)) ?? "",
                VT_I4 => Marshal.ReadInt32(pResult, 8),
                VT_I2 => (int)Marshal.ReadInt16(pResult, 8),
                VT_BOOL => (int)Marshal.ReadInt16(pResult, 8),
                _ => null,
            };
            if (Marshal.ReadInt16(pResult, 0) == VT_BSTR)
            {
                IntPtr s = Marshal.ReadIntPtr(pResult, 8);
                if (s != IntPtr.Zero) { Marshal.FreeBSTR(s); Marshal.WriteIntPtr(pResult, 8, IntPtr.Zero); }
            }
            return (hr, ret, "");
        }
        finally
        {
            Marshal.FreeHGlobal(pResult);
        }
    }

    /// <summary>通过 GetIDsOfNames 解析名称 → dispid（验证对象是否支持名称分发）。</summary>
    public static (int Hr, int Dispid) GetDispid(IDispatch disp, string name)
    {
        var iid = IidNull;
        var ids = new int[1];
        int hr = disp.GetIDsOfNames(ref iid, new[] { name }, 1, 0x0804, ids);
        return (hr, ids[0]);
    }
}
