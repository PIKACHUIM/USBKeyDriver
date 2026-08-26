using System.Text.Json;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 平台驱动对接映射（api_map）。通过外部 JSON 描述“某平台 → 驱动DLL → 导出序号”，
/// 使逆向得到的接口结果无需重新编译即可应用到管理端（当前 LncaProvider 已直接按名字
/// 绑定，本类保留用于后续多厂商/多版本 DLL 的配置化扩展）。
/// </summary>
public class LncaApiMap
{
    public string Platform { get; set; } = "lnca";
    /// <summary>相对/绝对路径的 DLL 文件。</summary>
    public string Module { get; set; } = "";
    /// <summary>后备 DLL（若主 DLL 未加载）。</summary>
    public string FallbackModule { get; set; } = "";
}

/// <summary>
/// LNCA 平台函数序号 → 函数名映射（逆向确认，见 docs/LNCA-逆向分析.md）。
/// <para>
/// 注意：早期误判这些 DLL 为“纯序号导出”，实际上它们均有名字导出，可直接按名 GetProcAddress。
/// 本映射表仅作逆向成果记录与诊断用。
/// </para>
/// </summary>
public static class LncaOrdinals
{
    // ===== JIT_USBKEY_HD.dll（44 导出，序号 101-144） =====
    public const ushort Connect = 101;               // USBKey_Connect
    public const ushort Disconnect = 102;            // USBKey_Disconnect
    public const ushort UserLogin = 103;             // USBKey_UserLogin
    public const ushort UserExit = 104;              // User_Exit
    public const ushort ChangePin = 105;             // USBKey_ChangePin
    public const ushort UnlockPin = 106;             // USBKey_UnlockPin
    public const ushort CreatFile = 107;             // USBKey_CreatFile
    public const ushort WriteFile = 108;             // USBKey_WriteFile
    public const ushort ReadFile = 109;              // USBKey_ReadFile
    public const ushort DelFile = 110;               // USBKey_DelFile
    public const ushort RFileLen = 111;              // USBKey_RFileLen
    public const ushort DeEnDecryptData = 112;       // USBKey_DeEnDecryptData
    public const ushort GenRSAKeyPair = 113;         // USBKey_GenRSAKeyPair
    public const ushort SignData = 114;              // USBKey_SignData
    public const ushort VerifySign = 115;            // USBKey_VerifySign
    public const ushort RsEnDecryptData = 116;       // USBKey_RsEnDecryptData
    public const ushort RsOutKey = 117;              // USBKey_RsOutKey
    public const ushort RsInKey = 118;               // USBKey_RsInKey
    public const ushort GetRandom = 119;             // USBKey_GetRandom
    public const ushort GenKey = 120;                // USBKey_GenKey
    public const ushort SignPriKeyProc = 121;        // USBKey_SignPriKeyProc
    public const ushort WritePubPriKey = 122;        // USBKey_WritePubPriKey
    public const ushort PriKeyProc = 123;            // USBKey_PriKeyProc
    public const ushort WriteCert = 124;             // USBKey_WriteCert
    public const ushort ReadCert = 125;              // USBKey_ReadCert
    public const ushort InitKey = 126;               // USBKey_InitKey
    public const ushort VerifyPin = 127;             // USBKey_VerifyPin
    public const ushort UserUnlockPin = 128;         // USBKey_UserUnlockPin
    public const ushort GetDevState = 129;           // USBKey_GetDevState
    public const ushort EKeyCopy = 130;              // USBKey_EKeyCopy
    public const ushort ListKey = 131;               // USBKey_ListKey
    public const ushort Reset = 132;                 // USBKey_Reset
    public const ushort ReadFileHD = 133;            // USBKey_ReadFile_HD
    // 134-139 为空导出（rva = 0）
    public const ushort GetKeySN = 140;              // USBKey_GetKeySN
    public const ushort RegisterNotification = 141;  // USBKey_RegisterNotification
    public const ushort UnRegisterNotification = 142;// USBKey_UnRegisterNotification
    public const ushort GetDevicePort = 143;         // USBKey_GetDevicePort
    public const ushort RegisterCert = 144;          // USBKey_RegisterCert

    // ===== HD_HardAPI.dll（17 导出，序号 1-17） =====
    public const ushort HSConnectDev = 1;
    public const ushort HSDisconnectDev = 2;
    public const ushort HSCreateFile = 3;
    public const ushort HSWriteFile = 4;
    public const ushort HSReadFile = 5;
    public const ushort HSDeleteFile = 6;
    public const ushort HSHasFileExist = 7;
    public const ushort HSVerifyUserPin = 8;
    public const ushort HSChangeUserPin = 9;
    public const ushort HSVerifySOPin = 10;
    public const ushort HSChangeSOPin = 11;
    public const ushort HSReWriteUserPin = 12;
    public const ushort HSGetSerial = 13;
    public const ushort HSGetTotalSize = 14;
    public const ushort HSGetFreeSize = 15;
    public const ushort HSErase = 16;
    public const ushort HSCheckStructure = 17;
}
