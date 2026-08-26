using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey;

/// <summary>
/// GP_IFD_LNCA.dll 原生接口（官方工具使用的 DLL）
/// </summary>
public static class GpIfdNative
{
    private const string DllName = "GP_IFD_LNCA.dll";

    // 常见的智能卡 IFD (Interface Device) 函数
    // 参考 PC/SC 标准和 CCID 规范
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int IFD_Init();
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int IFD_Exit();
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int IFD_EnumDevice(
        [Out] byte[] deviceList,
        ref int length
    );
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int IFD_Connect(
        int deviceIndex,
        out IntPtr handle
    );
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int IFD_Disconnect(IntPtr handle);
    
    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern int IFD_GetATR(
        IntPtr handle,
        [Out] byte[] atr,
        ref int atrLen
    );
}
