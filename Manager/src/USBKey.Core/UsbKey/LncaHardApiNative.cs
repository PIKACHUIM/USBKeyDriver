using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey;

/// <summary>
/// LNCA 硬件 API 层 <c>HD_HardAPI.dll</c> 的原生接口委托定义。
/// <para>
/// 逆向结论（详见 Roadmap/05-LNCA逆向分析案例.md 与 tools/disasm_*.py）：
/// 高层 SDK <c>JIT_USBKEY_HD.dll</c> 的 <c>USBKey_InitKey</c>/<c>USBKey_Reset</c> 在该版本
/// 中为「调试空壳」（仅打印日志并返回 0，未调用任何真实设备操作）。真正的
/// 「设备初始化 / 擦除」能力由 <c>HD_HardAPI.dll</c> 提供，其内部通过
/// LoadLibrary("HD_SortDev.dll") 动态转发到 <c>HS_Erase</c> 等底层实现。
/// </para>
/// <para>
/// 关键约束：
/// - DLL 为 32 位（pei-i386），宿主进程必须以 x86 运行；
/// - 所有导出均为 __stdcall，返回 int（0 = 成功，非 0 = 错误码）；
/// - 句柄为 IntPtr，由 <c>HSConnectDev</c> 输出，后续操作携带。
/// </para>
/// </summary>
internal static class LncaHardApiNative
{
    /// <summary>
    /// HSConnectDev(int devIndex, int* phDev)
    /// 连接指定索引的设备，返回其句柄。ret 8（2 参数）。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ConnectDevFn(int devIndex, out IntPtr phDev);

    /// <summary>
    /// HSDisconnectDev(int hDev)
    /// 断开设备。ret 4（1 参数）。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int DisconnectDevFn(IntPtr hDev);

    /// <summary>
    /// HSErase(int hDev)
    /// 擦除设备（恢复出厂 / 重置初始化）。内部发送 COS 擦除 APDU 并校验 SW=0x9000。
    /// ret 4（1 参数）。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int EraseFn(IntPtr hDev);

    /// <summary>
    /// HSVerifyUserPin(int hDev, char* lpPin, uint len)
    /// 校验用户 PIN。用于擦除前/后的权限校验（ret 0xc，3 参数）。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int VerifyUserPinFn(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpPin, uint lpPinLen);

    /// <summary>
    /// HSVerifySOPin(int hDev, char* lpPin, uint len)
    /// 校验 SO（管理员）PIN。擦除操作通常需要 SO PIN 权限。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int VerifySOPinFn(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpPin, uint lpPinLen);

    /// <summary>
    /// HSChangeUserPin(int hDev, char* lpOldPin, char* lpNewPin)
    /// 修改用户 PIN。注意：逆向确认为 ret 0xc（3 参数），不传长度，DLL 内部用 strlen。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ChangeUserPinFn(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpOldPin,
        [MarshalAs(UnmanagedType.LPStr)] string lpNewPin);

    /// <summary>
    /// HSReWriteUserPin(int hDev, char* lpOldPin, char* lpNewPin)
    /// 重写用户 PIN（ret 0xc，3 参数；DLL 内部用 strlen，旧 PIN 长度 1~16、新 PIN 长度 2~16）。
    /// 注意：逆向确认其内部仍会先校验「旧 PIN」，因此不能用于「旧 PIN 未知」的场景。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ReWriteUserPinFn(IntPtr hDev,
        [MarshalAs(UnmanagedType.LPStr)] string lpOldPin,
        [MarshalAs(UnmanagedType.LPStr)] string lpNewPin);

    /// <summary>
    /// HSCheckStructure(int hDev)
    /// 检查设备文件系统结构（初始化后可调用以确认结构有效）。
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int CheckStructureFn(IntPtr hDev);
}
