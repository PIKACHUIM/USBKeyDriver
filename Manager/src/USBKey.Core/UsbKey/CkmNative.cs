using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey;

/// <summary>
/// PKCS#11 (Cryptoki) 原生层：常量、结构与函数委托定义。
/// <para>
/// 对接目标：恒宝（HengBao）民生银行 U 宝的 <c>CMBCp.dll</c>
/// （32 位标准 PKCS#11 实现，源码路径 <c>Src\Pkcs11\Windows\pkcs11</c>，
/// P11Frame/implglue.cpp + token_comm.cpp），以及飞天 ePass3003 的
/// <c>HCCBCSP11.dll</c>。两者均为 32 位，宿主进程必须以 x86 运行。
/// </para>
/// <para>
/// <b>调用约定（已逆向确认，2026-09-20）</b>：两个 DLL 的 68 个 <c>C_*</c> 导出
/// 全部编译为 <c>__cdecl</c>（IDA 反汇编显示函数尾均为裸 <c>retn</c>，
/// 而 <c>DllMain</c> 为 <c>retn 0Ch</c>）。因此委托必须使用
/// <see cref="CallingConvention.Cdecl"/>，用 <c>StdCall</c> 会导致栈失衡、
/// 调用返回随机错误码（例如 C_OpenSession 返回 CKR_FUNCTION_FAILED）。
/// </para>
/// <para>
/// <b>关键类型约定</b>：PKCS#11 的 <c>CK_ULONG</c> 在 Windows 上是 4 字节
/// （unsigned long，LLP64 模型），因此句柄/属性类型/长度均映射为 C# 的
/// <c>uint</c>。而 <c>CK_SLOT_ID</c> 在本厂实现中是<b>不透明句柄</b>：
/// CMBCp.dll 的 C_GetSlotList 返回的其实是「设备路径字符串指针」
/// （见 IDA 中 EnumSlots → sub_1002156A 把 NUL 分隔的设备名写入全局缓冲区、
/// 再把每个字符串的地址写回调用方数组），所以槽位必须以 <see cref="IntPtr"/>
/// 原样保存并回传给 C_OpenSession / C_GetTokenInfo，不能当作数值索引。
/// </para>
/// </summary>
public static class CkmNative
{
    // ================= 基础类型 =================
    public const uint CKA_CLASS = 0x00000000;
    public const uint CKA_TOKEN = 0x00000001;
    public const uint CKA_PRIVATE = 0x00000002;
    public const uint CKA_LABEL = 0x00000003;
    public const uint CKA_UNIQUE_ID = 0x00000004;
    public const uint CKA_VALUE = 0x00000011;
    public const uint CKA_CERTIFICATE_TYPE = 0x00000080;
    public const uint CKA_ISSUER = 0x00000081;
    public const uint CKA_SERIAL_NUMBER = 0x00000082;
    public const uint CKA_CERTIFICATE_CATEGORY = 0x00000087;
    public const uint CKA_KEY_TYPE = 0x00000100;
    public const uint CKA_SUBJECT = 0x00000101;
    public const uint CKA_ID = 0x00000102;
    public const uint CKA_SENSITIVE = 0x00000103;
    public const uint CKA_MODULUS = 0x00000120;
    public const uint CKA_MODULUS_BITS = 0x00000121;
    public const uint CKA_PUBLIC_EXPONENT = 0x00000122;
    public const uint CKA_PRIVATE_EXPONENT = 0x00000123;
    public const uint CKA_PRIME_1 = 0x00000124;
    public const uint CKA_PRIME_2 = 0x00000125;
    public const uint CKA_EXPONENT_1 = 0x00000126;
    public const uint CKA_EXPONENT_2 = 0x00000127;
    public const uint CKA_COEFFICIENT = 0x00000128;
    public const uint CKA_VALUE_LEN = 0x00000161;
    public const uint CKA_EXTRACTABLE = 0x00000162;
    // 用途布尔属性（导入密钥对时按 PKCS#11 标准给出）
    public const uint CKA_ENCRYPT = 0x00000104;
    public const uint CKA_DECRYPT = 0x00000105;
    public const uint CKA_WRAP = 0x00000106;
    public const uint CKA_UNWRAP = 0x00000107;
    public const uint CKA_SIGN = 0x00000108;
    public const uint CKA_VERIFY = 0x0000010A;

    // 对象类别
    public const uint CKO_DATA = 0x00000000;
    public const uint CKO_CERTIFICATE = 0x00000001;
    public const uint CKO_PUBLIC_KEY = 0x00000002;
    public const uint CKO_PRIVATE_KEY = 0x00000003;

    // 证书类型 / 类别
    public const uint CKC_X_509 = 0x00000000;
    public const uint CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0;
    public const uint CK_CERTIFICATE_CATEGORY_TOKEN_USER = 1;
    public const uint CK_CERTIFICATE_CATEGORY_AUTHORITY = 2;
    public const uint CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3;

    // 密钥类型
    public const uint CKK_RSA = 0x00000000;
    public const uint CKK_EC = 0x00000003;
    public const uint CKK_VENDOR_DEFINED = 0x80000000;

    // 用户类型
    public const uint CKU_SO = 0;
    public const uint CKU_USER = 1;
    /// <summary>上下文特定用户（PKCS#11 v2.40）。恒宝 CMBCp.dll 未实现，仅作常量保留。</summary>
    public const uint CKU_CONTEXT_SPECIFIC = 2;

    // 会话标志
    public const uint CKF_RW_SESSION = 0x00000002;
    public const uint CKF_SERIAL_SESSION = 0x00000004;

    // Token 标志
    public const uint CKF_RNG = 0x00000001;
    public const uint CKF_WRITE_PROTECTED = 0x00000002;
    public const uint CKF_LOGIN_REQUIRED = 0x00000004;
    public const uint CKF_USER_PIN_INITIALIZED = 0x00000008;
    public const uint CKF_TOKEN_INITIALIZED = 0x00000400;
    public const uint CKF_USER_PIN_LOCKED = 0x00040000;
    public const uint CKF_USER_PIN_FINAL_TRY = 0x00020000;
    public const uint CKF_USER_PIN_COUNT_LOW = 0x00010000;

    // ================= 返回值 =================
    public const uint CKR_OK = 0x00000000;
    public const uint CKR_CANCEL = 0x00000001;
    public const uint CKR_HOST_MEMORY = 0x00000002;
    public const uint CKR_SLOT_ID_INVALID = 0x00000003;
    public const uint CKR_GENERAL_ERROR = 0x00000005;
    public const uint CKR_FUNCTION_FAILED = 0x00000006;
    public const uint CKR_ARGUMENTS_BAD = 0x00000007;
    public const uint CKR_ATTRIBUTE_READ_ONLY = 0x00000010;
    public const uint CKR_ATTRIBUTE_SENSITIVE = 0x00000011;
    public const uint CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012;
    public const uint CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013;
    public const uint CKR_DATA_INVALID = 0x00000020;
    public const uint CKR_DATA_LEN_RANGE = 0x00000021;
    public const uint CKR_DEVICE_ERROR = 0x00000030;
    public const uint CKR_DEVICE_MEMORY = 0x00000031;
    public const uint CKR_DEVICE_REMOVED = 0x00000032;
    public const uint CKR_FUNCTION_NOT_SUPPORTED = 0x00000054;
    public const uint CKR_KEY_HANDLE_INVALID = 0x00000060;
    public const uint CKR_KEY_TYPE_INCONSISTENT = 0x00000063;
    public const uint CKR_MECHANISM_INVALID = 0x00000070;
    public const uint CKR_MECHANISM_PARAM_INVALID = 0x00000071;
    public const uint CKR_OBJECT_HANDLE_INVALID = 0x00000082;
    public const uint CKR_OPERATION_NOT_INITIALIZED = 0x00000091;
    public const uint CKR_PIN_INCORRECT = 0x000000A0;
    public const uint CKR_PIN_INVALID = 0x000000A1;
    public const uint CKR_PIN_LEN_RANGE = 0x000000A2;
    public const uint CKR_PIN_EXPIRED = 0x000000A3;
    public const uint CKR_PIN_LOCKED = 0x000000A4;
    public const uint CKR_SESSION_HANDLE_INVALID = 0x000000B3;
    public const uint CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x00000180;
    public const uint CKR_SESSION_READ_ONLY = 0x000000B5;
    public const uint CKR_TOKEN_NOT_PRESENT = 0x000000E0;
    public const uint CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1;
    public const uint CKR_TOKEN_WRITE_PROTECTED = 0x000000E2;
    public const uint CKR_USER_ALREADY_LOGGED_IN = 0x00000100;
    public const uint CKR_USER_NOT_LOGGED_IN = 0x00000101;
    public const uint CKR_USER_PIN_NOT_INITIALIZED = 0x00000102;
    public const uint CKR_USER_TYPE_INVALID = 0x00000103;
    public const uint CKR_BUFFER_TOO_SMALL = 0x00000150;
    public const uint CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190;
    public const uint CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191;

    // ================= 机制 =================
    public const uint CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
    public const uint CKM_RSA_PKCS = 0x00000001;
    public const uint CKM_RSA_X_509 = 0x00000003;
    public const uint CKM_MD5_RSA_PKCS = 0x00000005;
    public const uint CKM_SHA1_RSA_PKCS = 0x00000006;
    public const uint CKM_SHA256_RSA_PKCS = 0x00000040;
    public const uint CKM_SHA1 = 0x00000220;
    public const uint CKM_SHA256 = 0x00000250;
    public const uint CKM_ECDSA = 0x00001041;
    public const uint CKM_ECDSA_SHA1 = 0x00001042;
    public const uint CKM_ECDSA_SHA256 = 0x00001045;

    // ================= 信息结构体 =================
    [StructLayout(LayoutKind.Sequential)]
    public struct CK_VERSION
    {
        public byte major;
        public byte minor;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_INFO
    {
        public CK_VERSION cryptokiVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] manufacturerID;
        public uint flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] libraryDescription;
        public CK_VERSION libraryVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_SLOT_INFO
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] slotDescription;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] manufacturerID;
        public uint flags;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;
    }

    /// <summary>
    /// CK_TOKEN_INFO（标准 160 字节布局）。
    /// 恒宝 CMBCp.dll 的实际填充：label@0 / manufacturerID@32 / model@64 /
    /// serialNumber@80 / flags@96 / … / hardwareVersion@140 / firmwareVersion@142 / utcTime@144。
    /// 其中 <c>ulSessionCount</c>（偏移 104）被厂商复用为「PIN 剩余尝试次数」。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CK_TOKEN_INFO
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] label;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] manufacturerID;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] model;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] serialNumber;
        public uint flags;
        public uint ulMaxSessionCount;
        public uint ulSessionCount;
        public uint ulMaxRwSessionCount;
        public uint ulRwSessionCount;
        public uint ulMaxPinLen;
        public uint ulMinPinLen;
        public uint ulTotalPublicMemory;
        public uint ulFreePublicMemory;
        public uint ulTotalPrivateMemory;
        public uint ulFreePrivateMemory;
        public CK_VERSION hardwareVersion;
        public CK_VERSION firmwareVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] utcTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_ATTRIBUTE
    {
        public uint type;
        public IntPtr pValue;
        public uint ulValueLen;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_MECHANISM
    {
        public uint mechanism;
        public IntPtr pParameter;
        public uint ulParameterLen;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_SESSION_INFO
    {
        public IntPtr slotID;
        public uint state;
        public uint flags;
        public uint ulDeviceError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CK_FUNCTION_LIST
    {
        public CK_VERSION version;
        public IntPtr C_Initialize;
        public IntPtr C_Finalize;
        public IntPtr C_GetInfo;
        public IntPtr C_GetFunctionList;
        public IntPtr C_GetSlotList;
        public IntPtr C_GetSlotInfo;
        public IntPtr C_GetTokenInfo;
        public IntPtr C_GetMechanismList;
        public IntPtr C_GetMechanismInfo;
        public IntPtr C_InitToken;
        public IntPtr C_InitPIN;
        public IntPtr C_SetPIN;
        public IntPtr C_OpenSession;
        public IntPtr C_CloseSession;
        public IntPtr C_CloseAllSessions;
        public IntPtr C_GetSessionInfo;
        public IntPtr C_GetOperationState;
        public IntPtr C_SetOperationState;
        public IntPtr C_Login;
        public IntPtr C_Logout;
        public IntPtr C_CreateObject;
        public IntPtr C_CopyObject;
        public IntPtr C_DestroyObject;
        public IntPtr C_GetObjectSize;
        public IntPtr C_GetAttributeValue;
        public IntPtr C_SetAttributeValue;
        public IntPtr C_FindObjectsInit;
        public IntPtr C_FindObjects;
        public IntPtr C_FindObjectsFinal;
        public IntPtr C_EncryptInit;
        public IntPtr C_Encrypt;
        public IntPtr C_EncryptUpdate;
        public IntPtr C_EncryptFinal;
        public IntPtr C_DecryptInit;
        public IntPtr C_Decrypt;
        public IntPtr C_DecryptUpdate;
        public IntPtr C_DecryptFinal;
        public IntPtr C_DigestInit;
        public IntPtr C_Digest;
        public IntPtr C_DigestUpdate;
        public IntPtr C_DigestKey;
        public IntPtr C_DigestFinal;
        public IntPtr C_SignInit;
        public IntPtr C_Sign;
        public IntPtr C_SignUpdate;
        public IntPtr C_SignFinal;
        public IntPtr C_SignRecoverInit;
        public IntPtr C_SignRecover;
        public IntPtr C_VerifyInit;
        public IntPtr C_Verify;
        public IntPtr C_VerifyUpdate;
        public IntPtr C_VerifyFinal;
        public IntPtr C_VerifyRecoverInit;
        public IntPtr C_VerifyRecover;
        public IntPtr C_DigestEncryptUpdate;
        public IntPtr C_DecryptDigestUpdate;
        public IntPtr C_SignEncryptUpdate;
        public IntPtr C_DecryptVerifyUpdate;
        public IntPtr C_GenerateKey;
        public IntPtr C_GenerateKeyPair;
        public IntPtr C_WrapKey;
        public IntPtr C_UnwrapKey;
        public IntPtr C_DeriveKey;
        public IntPtr C_SeedRandom;
        public IntPtr C_GenerateRandom;
        public IntPtr C_GetFunctionStatus;
        public IntPtr C_CancelFunction;
        public IntPtr C_WaitForSlotEvent;
    }

    // ================= 函数委托（导出形式） =================
    // 注意：恒宝 CMBCp.dll 与飞天 HCCBCSP11.dll 均为 __cdecl（见类注释的逆向证据）。
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_InitializeFn(IntPtr pInitArgs);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_FinalizeFn(IntPtr pReserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetInfoFn(ref CK_INFO pInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetFunctionListFn(out IntPtr ppFunctionList);

    /// <summary>
    /// C_GetSlotList。pSlotList 传 null 时仅返回数量。
    /// <para>
    /// 返回的每个元素是<b>不透明槽位句柄</b>：恒宝 CMBCp.dll 实际返回的是「设备路径字符串指针」
    /// （见 IDA 中 EnumSlots → sub_1002156A 把 NUL 分隔的设备名写进全局缓冲区、
    /// 再把每个字符串地址写回调用方数组），因此调用方必须把这些值<b>原样</b>回传给
    /// C_OpenSession / C_GetTokenInfo，绝不能当作 0/1/2 这样的索引重新构造。
    /// 在 Win32 上指针就是 32 位，与标准 CK_SLOT_ID(CK_ULONG) 同为 4 字节，
    /// 故此处统一用 <c>uint</c> 承载（不影响 ePass3003 等返回数值槽位的库）。
    /// </para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetSlotListFn(byte tokenPresent, [In, Out] uint[]? pSlotList, ref uint pulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetSlotInfoFn(uint slotID, ref CK_SLOT_INFO pInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetTokenInfoFn(uint slotID, ref CK_TOKEN_INFO pInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetMechanismListFn(uint slotID, [In, Out] uint[]? pMechanismList, ref uint pulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_OpenSessionFn(uint slotID, uint flags, IntPtr pApplication, IntPtr notify, ref uint phSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_CloseSessionFn(uint hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_CloseAllSessionsFn(uint slotID);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetSessionInfoFn(uint hSession, ref CK_SESSION_INFO pInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_LoginFn(uint hSession, uint userType, byte[]? pPin, uint ulPinLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_LogoutFn(uint hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_SetPINFn(uint hSession, byte[] pOldPin, uint ulOldLen, byte[] pNewPin, uint ulNewLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_InitPINFn(uint hSession, byte[] pPin, uint ulPinLen);

    /// <summary>恒宝 CMBCp.dll 中为桩函数，恒返回 CKR_FUNCTION_NOT_SUPPORTED(0x54)。</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_InitTokenFn(uint slotID, byte[] pPin, uint ulPinLen, byte[] pLabel);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GetAttributeValueFn(uint hSession, uint hObject, CK_ATTRIBUTE[] pTemplate, uint ulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_SetAttributeValueFn(uint hSession, uint hObject, CK_ATTRIBUTE[] pTemplate, uint ulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_FindObjectsInitFn(uint hSession, CK_ATTRIBUTE[]? pTemplate, uint ulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_FindObjectsFn(uint hSession, uint[] phObject, uint ulMaxObjectCount, ref uint pulObjectCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_FindObjectsFinalFn(uint hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_CreateObjectFn(uint hSession, CK_ATTRIBUTE[] pTemplate, uint ulCount, ref uint phObject);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_DestroyObjectFn(uint hSession, uint hObject);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GenerateKeyPairFn(uint hSession, ref CK_MECHANISM pMechanism,
        CK_ATTRIBUTE[] pPublicKeyTemplate, uint ulPublicKeyAttributeCount,
        CK_ATTRIBUTE[] pPrivateKeyTemplate, uint ulPrivateKeyAttributeCount,
        ref uint phPublicKey, ref uint phPrivateKey);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_GenerateRandomFn(uint hSession, byte[] pRandomData, uint ulRandomLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_SignInitFn(uint hSession, ref CK_MECHANISM pMechanism, uint hKey);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate uint C_SignFn(uint hSession, byte[] pData, uint ulDataLen, byte[]? pSignature, ref uint pulSignatureLen);

    // ================= 帮助函数 =================

    /// <summary>将定长字节数组（可能含尾随 0x00 或 0x20）转换为字符串。</summary>
    public static string PaddedToString(byte[]? data)
    {
        if (data == null) return "";
        int end = data.Length;
        while (end > 0 && (data[end - 1] == 0x00 || data[end - 1] == 0x20)) end--;
        if (end == 0) return "";
        return System.Text.Encoding.UTF8.GetString(data, 0, end).Trim();
    }

    /// <summary>将错误码转换为可读描述。</summary>
    public static string ErrorString(uint rv) => rv switch
    {
        CKR_OK => "成功",
        CKR_CANCEL => "操作被取消",
        CKR_HOST_MEMORY => "主机内存不足",
        CKR_SLOT_ID_INVALID => "槽位句柄无效",
        CKR_GENERAL_ERROR => "一般错误",
        CKR_FUNCTION_FAILED => "功能执行失败（设备通信失败或设备未就绪）",
        CKR_ARGUMENTS_BAD => "参数错误",
        CKR_ATTRIBUTE_READ_ONLY => "属性只读",
        CKR_ATTRIBUTE_SENSITIVE => "属性不可读",
        CKR_ATTRIBUTE_TYPE_INVALID => "属性类型无效",
        CKR_ATTRIBUTE_VALUE_INVALID => "属性值无效",
        CKR_DEVICE_ERROR => "设备错误",
        CKR_DEVICE_MEMORY => "设备存储空间不足",
        CKR_DEVICE_REMOVED => "设备已拔出",
        CKR_FUNCTION_NOT_SUPPORTED => "该设备不支持此功能",
        CKR_KEY_HANDLE_INVALID => "密钥句柄无效",
        CKR_MECHANISM_INVALID => "机制无效",
        CKR_OBJECT_HANDLE_INVALID => "对象句柄无效",
        CKR_OPERATION_NOT_INITIALIZED => "操作未初始化",
        CKR_PIN_INCORRECT => "PIN 错误",
        CKR_PIN_INVALID => "PIN 非法",
        CKR_PIN_LEN_RANGE => "PIN 长度不合法",
        CKR_PIN_EXPIRED => "PIN 已过期",
        CKR_PIN_LOCKED => "PIN 已锁定",
        CKR_SESSION_HANDLE_INVALID => "会话句柄无效",
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => "会话不支持并行（需 CKF_SERIAL_SESSION）",
        CKR_SESSION_READ_ONLY => "会话只读",
        CKR_TOKEN_NOT_PRESENT => "令牌不存在",
        CKR_TOKEN_NOT_RECOGNIZED => "令牌无法识别",
        CKR_TOKEN_WRITE_PROTECTED => "令牌写保护",
        CKR_USER_ALREADY_LOGGED_IN => "已登录",
        CKR_USER_NOT_LOGGED_IN => "未登录",
        CKR_USER_PIN_NOT_INITIALIZED => "用户 PIN 未初始化",
        CKR_USER_TYPE_INVALID => "用户类型无效（本设备仅支持 CKU_USER）",
        CKR_BUFFER_TOO_SMALL => "缓冲区过小",
        CKR_CRYPTOKI_NOT_INITIALIZED => "Cryptoki 未初始化",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "Cryptoki 已初始化",
        _ => $"未知错误(0x{rv:X})",
    };
}
