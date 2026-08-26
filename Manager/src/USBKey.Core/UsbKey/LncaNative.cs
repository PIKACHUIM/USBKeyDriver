using System.Runtime.InteropServices;
using System.Text;

namespace USBKey.Core.UsbKey;

/// <summary>
/// LNCA 厂商驱动 JIT_USBKEY_HD.dll 的原生接口委托定义。
/// <para>
/// 逆向结论（详见 docs/LNCA-逆向分析.md）：
/// - DLL 为 32 位（pei-i386），因此宿主进程必须以 x86 运行；
/// - 所有导出均为 __stdcall 调用约定，返回 int（0 = 成功，非 0 = 错误码）；
/// - 字符串参数为 ANSI（char*，GBK 环境）；
/// - 句柄 hKey 为 IntPtr，由 <c>USBKey_Connect</c> 输出，其后所有操作携带。
/// </para>
/// </summary>
internal static class LncaNative
{
    // ============ 设备连接 / 会话 ============

    /// <summary>USBKey_Connect(uint dwKeyIndex, uint bandRate, int* phKey)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ConnectFn(uint dwKeyIndex, uint bandRate, out IntPtr phKey);

    /// <summary>USBKey_Disconnect(int* phKey)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int DisconnectFn(ref IntPtr phKey);

    /// <summary>USBKey_UserLogin(int hKey, char* lpPinStr, uint lpPinStrLen)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int UserLoginFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpPinStr, uint lpPinStrLen);

    /// <summary>User_Exit(int hKey)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int UserExitFn(IntPtr hKey);

    // ============ PIN / 解锁 / 重置 ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ChangePinFn(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string lpOldPin, uint lpOldPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string lpNewPin, uint lpNewPinLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int UnlockPinFn(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string lpUnlockPin, uint lpUnlockPinLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int UserUnlockPinFn(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string lpUnlockPin, uint lpUnlockPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string lpUserPin, uint lpUserPinLen);

    /// <summary>USBKey_VerifyPin(int hKey, uint type, char* lpPinStr, uint len)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int VerifyPinFn(IntPtr hKey, uint type,
        [MarshalAs(UnmanagedType.LPStr)] string lpPinStr, uint lpPinStrLen);

    /// <summary>USBKey_InitKey(hKey, userPin, userPinLen, operPin, operPinLen, unlockPin, unlockPinLen)</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int InitKeyFn(IntPtr hKey,
        [MarshalAs(UnmanagedType.LPStr)] string lpUserPin, uint lpUserPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string lpOperPin, uint lpOperPinLen,
        [MarshalAs(UnmanagedType.LPStr)] string lpUnlockPin, uint lpUnlockPinLen);

    // ============ 设备信息 ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetDevStateFn(IntPtr hKey, out uint pKeyStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetKeySNFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] StringBuilder lpKeySN, ref uint lpKeySNLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetDevicePortFn([MarshalAs(UnmanagedType.LPStr)] string szDeviceName, out uint pnPort);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ResetFn(IntPtr hKey, IntPtr rData, uint rLen);

    // ============ 证书 / 容器 ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int WriteCertFn(IntPtr hKey, uint dwCertType, [In] byte[] pbCert, uint dwCertLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ReadCertFn(IntPtr hKey, uint dwCertType, [In, Out] byte[] pbCert, ref uint pdwCertLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int RegisterCertFn(IntPtr hKey, uint dwCertType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ListKeyFn(out uint count);

    // ============ Key 内文件系统（证书/数据存储） ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int CreatFileFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpFileName, uint lpFileNameLen, uint lpFileLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int WriteFileFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpFileName, uint lpFileNameLen, [In] byte[] lpWdata, uint lpWdataLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ReadFileFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpFileName, uint lpFileNameLen, uint lpRdataLen, [In, Out] byte[] lpRdata, ref uint lpOutDataLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int DelFileFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpFileName, uint lpFileNameLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int RFileLenFn(IntPtr hKey, [MarshalAs(UnmanagedType.LPStr)] string lpFileName, uint lpFileNameLen, out uint pFileLen);

    // ============ 密钥运算（证书导入/签名） ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetRandomFn(IntPtr hKey, uint randomStrLen, [Out] byte[] lpRandomStr);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GenRSAKeyPairFn(IntPtr hKey, uint pubKeyType,
        [In, Out] byte[] lpPubKey, ref uint lpPubKeyLen,
        [In, Out] byte[] lpPriKey, ref uint lpPriKeyLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int SignDataFn(IntPtr hKey, uint algID,
        [In] byte[] lpInData, uint lpInDataLen,
        [In, Out] byte[] lpOutData, ref uint lpOutDataLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int WritePubPriKeyFn(IntPtr hKey, uint dEnKeyIndex,
        [In] byte[] lpPriKey, uint dPriKeyLen,
        [In] byte[] lpPubEncKey, uint dPubEncKeyLen, uint dAlgID);

    // ============ 通知 ============

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int RegisterNotificationFn(uint hWindowsHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int UnRegisterNotificationFn();
}
