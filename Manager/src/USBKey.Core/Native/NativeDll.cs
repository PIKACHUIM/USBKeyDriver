using System.Runtime.InteropServices;

namespace USBKey.Core.Native;

/// <summary>
/// 底层非托管 DLL 加载与导出函数调用帮助器。
/// 支持按函数名或按导出序号（ordinal）解析地址，并以无方式参数调用。
/// </summary>
public static class NativeDll
{
    private const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x8;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    /// <summary>基于序号的调用形式（序 1 对应 "#1"）。</summary>
    private static IntPtr GetProcAddressOrdinal(IntPtr hModule, ushort ordinal)
    {
        // 序号形式为 "#" + ordinal 字符串
        return GetProcAddress(hModule, "#" + ordinal);
    }

    /// <summary>加载的句柄。按名字解析。</summary>
    public sealed class Module : IDisposable
    {
        public IntPtr Handle { get; }
        internal Module(IntPtr handle) { Handle = handle; }

        /// <summary>按函数名获取委托。否则返回 null。</summary>
        public T? GetDelegate<T>(string procName) where T : Delegate
        {
            var addr = GetProcAddress(Handle, procName);
            if (addr == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer<T>(addr);
        }

        /// <summary>按导出序号获取委托。序号从 1 起。</summary>
        public T? GetDelegateByOrdinal<T>(ushort ordinal) where T : Delegate
        {
            var addr = GetProcAddressOrdinal(Handle, ordinal);
            if (addr == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer<T>(addr);
        }

        public bool HasExport(string procName) => GetProcAddress(Handle, procName) != IntPtr.Zero;
        public bool HasExport(ushort ordinal) => GetProcAddressOrdinal(Handle, ordinal) != IntPtr.Zero;

        public void Dispose() => FreeLibrary(Handle);
    }

    /// <summary>加载 DLL。supportOrdinal 无参数。返回模块或 null。</summary>
    public static Module? Load(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            // 关键：把 DLL 所在目录加入进程 DLL 搜索路径（SetDllDirectory）。
            // LOAD_WITH_ALTERED_SEARCH_PATH 只能让 Windows 解析被加载 DLL 的「静态」依赖，
            // 但 LNCA 驱动（JIT_USBKEY_HD.dll -> HDCOS_LNCA.dll -> GP_COS_LNCA.dll ->
            // GP_IFD_LNCA.dll -> HDIFD20B.dll ...）里的下游 DLL 是在运行时用相对名
            // LoadLibrary 动态加载的，走的是进程默认搜索路径（CWD），不包含 DLL 目录，
            // 会导致 IFD/读卡器层加载失败、USBKey_ListKey 返回 0 台设备。
            // 先 SetDllDirectory 后，所有静态与动态依赖都能在 DLL 目录内被解析。
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir))
                SetDllDirectory(dir);

            var h = LoadLibraryEx(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (h == IntPtr.Zero)
            {
                // 依赖 DLL 可能在同一目录，退回普通加载
                h = LoadLibrary(path);
                if (h == IntPtr.Zero) return null;
            }
            return new Module(h);
        }
        catch { return null; }
    }
}
