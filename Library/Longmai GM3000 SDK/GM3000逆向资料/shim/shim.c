/*
 * gm3000_pkcs11.dll —— 龙脉 GM3000「PKCS#11 → SKF」兼容垫片 (32 位)
 * =====================================================================
 *
 * 背景
 * ----
 * 本机插入的是一把**老型号** GM3000（USB VID_055C&PID_DB08，USBSTOR/CD-ROM 形态，无 CCID/HID 接口）。
 * 实测结论：
 *   · 2016 版 SKF（mtoken_gm3000.dll，292,352B）可用 SKF_EnumDev 枚举到它，且完整管理能力可用；
 *   · 2022 版 SKF（427,008B）枚举数为 0 —— 厂商新中间件已删除该型号支持；
 *   · gm3000_pkcs11.dll（2016/2022 都是）对该型号只有 4 个「无令牌」空槽位。
 * 而 GM3000Admin.exe 的设备可见性**只**来自 TokenMgr.dll → gm3000_pkcs11.dll（PKCS#11）这条链路，
 * 因此 2.2.19 的 Admin 报「不识别设备」。
 *
 * 本模块
 * ------
 * 提供与厂商 pkcs11 中间件**接口等价**的 32 位 DLL，内部实现对接 2016 版 SKF。
 * 放到 GM3000_2.2.19\ 下（备份原文件）即可让 2.2.19 的 TokenMgr/Admin 看到并使用这把 Key。
 *
 * TokenMgr 绑定契约（TokenMgr.dll!0x10003410 反汇编 + 实机解析函数表确定）
 * ---------------------------------------------------------------------
 *   1. h = LoadLibraryA(path)
 *   2. GetProcAddress(h,"C_GetFunctionList")  → 调用，取回 CK_FUNCTION_LIST*
 *        · **紧凑布局**（pack(1)）：CK_VERSION(2B) 之后紧跟函数指针，步长 4。
 *   3. GetProcAddress(h,"M_GetExtFunctionList") → 调用（1 参：void**）取回扩展表
 *        · 表首 4B 为计数，其后 20 个函数指针（+0x04..+0x53），再后为设备描述区。
 *   4. 由 CK_FUNCTION_LIST 偏移 +2 取 C_Initialize 调用，容忍 0x191(CKR_CRYPTOKI_ALREADY_INITIALIZED)。
 *   5. 失败返回 NTE_PROVIDER_DLL_FAIL = 0x8009001D。
 * 故本 DLL 只需导出 2 个符号；其余能力经两张函数表暴露，且表中**每个槽位都是真实函数**
 * （未实现者返回 CKR_FUNCTION_NOT_SUPPORTED），保证厂商代码在任意偏移取值都不踩空指针。
 *
 * 约定：PKCS#11 全部函数为 **cdecl**（Windows 下 PKCS#11 默认 C 约定；厂商实现亦然）。
 * 构建：见 build.bat（MSVC x86）
 */

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <intrin.h>     /* _ReturnAddress()：日志里记录调用者地址，便于反查 TokenMgr 调用点 */

/* ================================================================ PKCS#11 类型/常量 */

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_CHAR;
typedef unsigned char CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_RV;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_USER_TYPE;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_OBJECT_CLASS;
typedef unsigned long CK_CERTIFICATE_TYPE;
typedef unsigned long CK_KEY_TYPE;
typedef void* CK_VOID_PTR;

#define CK_TRUE  1
#define CK_FALSE 0

#define CKR_OK                            0x00000000UL
#define CKR_GENERAL_ERROR                 0x00000005UL
#define CKR_FUNCTION_FAILED               0x00000006UL
#define CKR_ARGUMENTS_BAD                 0x00000007UL
#define CKR_ATTRIBUTE_READ_ONLY           0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE           0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID        0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID       0x00000013UL
#define CKR_DEVICE_ERROR                  0x00000030UL
#define CKR_DEVICE_MEMORY                 0x00000031UL
#define CKR_DEVICE_REMOVED                0x00000032UL
#define CKR_FUNCTION_NOT_SUPPORTED        0x00000054UL
#define CKR_OBJECT_HANDLE_INVALID         0x00000082UL
#define CKR_OPERATION_NOT_INITIALIZED     0x00000091UL
#define CKR_PIN_INCORRECT                 0x000000A0UL
#define CKR_PIN_INVALID                   0x000000A1UL
#define CKR_PIN_LEN_RANGE                 0x000000A2UL
#define CKR_PIN_LOCKED                    0x000000A4UL
#define CKR_SESSION_HANDLE_INVALID        0x000000B3UL
#define CKR_SESSION_READ_ONLY             0x000000B5UL
#define CKR_SLOT_ID_INVALID               0x00000003UL
#define CKR_TOKEN_NOT_PRESENT             0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED          0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED         0x000000E2UL
#define CKR_USER_ALREADY_LOGGED_IN        0x00000100UL
#define CKR_USER_NOT_LOGGED_IN            0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED      0x00000102UL
#define CKR_USER_TYPE_INVALID             0x00000103UL
#define CKR_BUFFER_TOO_SMALL              0x00000150UL
#define CKR_CRYPTOKI_NOT_INITIALIZED      0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED  0x00000191UL
#define CKR_MECHANISM_INVALID             0x00000070UL

/* CK_TOKEN_INFO 标志 */
#define CKF_RNG                 0x00000001UL
#define CKF_WRITE_PROTECTED     0x00000002UL
#define CKF_LOGIN_REQUIRED      0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_TOKEN_INITIALIZED   0x00000400UL

#define CKF_TOKEN_PRESENT       0x00000001UL
#define CKF_REMOVABLE_DEVICE    0x00000002UL
#define CKF_HW_SLOT             0x00000004UL

/* 属性类型 */
#define CKA_CLASS             0x00000000UL
#define CKA_TOKEN             0x00000001UL
#define CKA_PRIVATE           0x00000002UL
#define CKA_LABEL             0x00000003UL
#define CKA_VALUE             0x00000011UL
#define CKA_CERTIFICATE_TYPE  0x00000080UL
#define CKA_ISSUER            0x00000081UL
#define CKA_SERIAL_NUMBER     0x00000082UL
#define CKA_KEY_TYPE          0x00000100UL
#define CKA_SUBJECT           0x00000101UL
#define CKA_ID                0x00000102UL
#define CKA_MODULUS           0x00000120UL
#define CKA_MODULUS_BITS      0x00000121UL
#define CKA_PUBLIC_EXPONENT   0x00000122UL
#define CKA_PRIVATE_EXPONENT  0x00000123UL
#define CKA_PRIME_1           0x00000124UL
#define CKA_PRIME_2           0x00000125UL
#define CKA_EXPONENT_1        0x00000126UL
#define CKA_EXPONENT_2        0x00000127UL
#define CKA_COEFFICIENT       0x00000128UL

/* 对象类 */
#define CKO_DATA          0x00000000UL
#define CKO_CERTIFICATE   0x00000001UL
#define CKO_PUBLIC_KEY    0x00000002UL
#define CKO_PRIVATE_KEY   0x00000003UL
#define CKO_SECRET_KEY    0x00000004UL

#define CKC_X_509         0x00000000UL

/* 用户类型 */
#define CKU_SO    0UL
#define CKU_USER  1UL

/* 会话标志 */
#define CKF_RW_SESSION       0x00000002UL
#define CKF_SERIAL_SESSION   0x00000004UL

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

/* 函数表：紧凑布局（与厂商一致） */
#pragma pack(push, 1)
typedef struct {
    CK_VERSION version;
    CK_VOID_PTR fn[68];
} CK_FUNCTION_LIST;

typedef struct {
    CK_ULONG   count;        /* +0x00：厂商实测同为 1 */
    CK_VOID_PTR fn[25];      /* +0x04 .. +0x64：**25** 个函数指针
                                （2.2.19 厂商实测 25 项；2.1.1.0 只有 20 项。
                                 2.2.19 多出：20=M_ForceLogout 21=M_RemoteUnblockUserPin
                                 22=M_GetDevCaps 23=M_SetInqString 24=M_RemoteUnblockUserPinMS。
                                 表项不足会让 TokenMgr 取到文本字节当函数指针调用，
                                 表现为 Access violation at address 30334D47/00003030。） */
    CK_BYTE    desc[0x400];  /* +0x68 起：设备描述区（"GM3000"@+0x68、"Longmai"@+0x88，与 2.2.19 一致） */
} M_EXT_TABLE;
#pragma pack(pop)

/* ================================================================ SKF（GM/T 0016） */

#define SAR_OK 0UL
#define SAR_PIN_INCORRECT      0x0A000024UL  /* 口令不正确（重试次数会减少） */
#define SAR_USER_NOT_LOGGED_IN 0x0A00002DUL  /* 尚未处于已验证状态 */
#define SAR_BUFFER_TOO_SMALL   0x0A000020UL  /* 出参缓冲不足 */

typedef int (__stdcall *fn_SKF_EnumDev)(int bPresent, char* nameList, unsigned long* pulSize);
typedef int (__stdcall *fn_SKF_ConnectDev)(const char* szName, void** phDev);
typedef int (__stdcall *fn_SKF_DisConnectDev)(void* hDev);
typedef int (__stdcall *fn_SKF_GetDevInfo)(void* hDev, void* pDevInfo);
typedef int (__stdcall *fn_SKF_GetDevState)(const char* szName, unsigned long* pulState);
typedef int (__stdcall *fn_SKF_EnumApplication)(void* hDev, char* nameList, unsigned long* pulSize);
typedef int (__stdcall *fn_SKF_OpenApplication)(void* hDev, const char* szAppName, void** phApp);
typedef int (__stdcall *fn_SKF_CloseApplication)(void* hApp);
typedef int (__stdcall *fn_SKF_EnumContainer)(void* hApp, char* nameList, unsigned long* pulSize);
typedef int (__stdcall *fn_SKF_OpenContainer)(void* hApp, const char* szName, void** phContainer);
typedef int (__stdcall *fn_SKF_CloseContainer)(void* hContainer);
typedef int (__stdcall *fn_SKF_CreateContainer)(void* hApp, const char* szName, void** phContainer);
typedef int (__stdcall *fn_SKF_DeleteContainer)(void* hApp, const char* szName);
typedef int (__stdcall *fn_SKF_ExportCertificate)(void* hContainer, int bSign, unsigned char* pbCert, unsigned long* pulCertLen);
typedef int (__stdcall *fn_SKF_ImportCertificate)(void* hContainer, int bSign, unsigned char* pbCert, unsigned long ulCertLen);
/* SKF_ImportRSAKeyPair(hContainer, ulAlgID, pbPrvKey, ulPrvKeyLen, pbWrappedKey, ulWrappedKeyLen)
   与 Manager（Gm3000Provider.ImportPfx）用的是同一调用口径 */
typedef int (__stdcall *fn_SKF_ImportRSAKeyPair)(void* hContainer, unsigned long ulAlgID,
                                                 unsigned char* pbPrvKey, unsigned long ulPrvKeyLen,
                                                 unsigned char* pbWrappedKey, unsigned long ulWrappedKeyLen);
typedef int (__stdcall *fn_SKF_GenRandom)(void* hDev, unsigned char* pbRandom, unsigned long ulLen);
typedef int (__stdcall *fn_SKF_VerifyPIN)(void* hDev, unsigned long ulPINType, const char* szPIN, unsigned long* pulRetryCount);
typedef int (__stdcall *fn_SKF_ChangePIN)(void* hDev, unsigned long ulPINType, const char* szOld, const char* szNew, unsigned long* pulRetryCount);
typedef int (__stdcall *fn_SKF_UnblockPIN)(void* hDev, const char* szAdminPIN, const char* szNewUserPIN, unsigned long* pulRetryCount);
typedef int (__stdcall *fn_SKF_ClearSecureState)(void* hDev);
typedef int (__stdcall *fn_SKF_SetLabel)(void* hDev, const char* szLabel);
typedef int (__stdcall *fn_SKF_GetPINInfo)(void* hApp, unsigned long ulPINType, unsigned long* p1, unsigned long* p2, unsigned long* p3);
/* 文件接口（GM/T 0016；原型见 SDK 头 SKFAPI.h）：
     SKF_CreateFile(hApp, name, size, readRights, writeRights)              5 参
     SKF_WriteFile (hApp, name, offset, data, size)                         5 参
     SKF_ReadFile  (hApp, name, offset, size, outData, outLen)              6 参
   与厂商扩展槽位一一对应：12 = M_CreateFile(5)、14 = M_WriteFile(5)、15 = M_ReadFile(6) ✓ */
typedef int (__stdcall *fn_SKF_CreateFile)(void* hApp, const char* szName, unsigned long ulSize,
                                           unsigned long ulReadRights, unsigned long ulWriteRights);
typedef int (__stdcall *fn_SKF_DeleteFile)(void* hApp, const char* szName);
typedef int (__stdcall *fn_SKF_EnumFiles)(void* hApp, char* szNameList, unsigned long* pulSize);
typedef int (__stdcall *fn_SKF_GetFileInfo)(void* hApp, const char* szName, void* pFileInfo);
typedef int (__stdcall *fn_SKF_ReadFile)(void* hApp, const char* szName, unsigned long ulOffset,
                                         unsigned long ulSize, unsigned char* pbOut, unsigned long* pulOutLen);
typedef int (__stdcall *fn_SKF_WriteFile)(void* hApp, const char* szName, unsigned long ulOffset,
                                          const unsigned char* pbData, unsigned long ulSize);
/* SKF_Transmit(hDev, pbCommand, ulCommandLen, pbData, pulDataLen) —— GM/T 0016 的透传口。
   槽位 9/10（M_WriteSectors / M_ReadSectors，下载 ISO 用）在 SKF 标准里没有对应函数，
   但厂商自己实现这两条路径时用的就是「16 字节头 + 负载」这一种帧，
   与 SKF_Transmit 的参数形状完全一致（详见 M_Dispatch 里 case 9/10 的注释），故用它透传。 */
typedef int (__stdcall *fn_SKF_Transmit)(void* hDev, unsigned char* pbCommand, unsigned long ulCommandLen,
                                         unsigned char* pbData, unsigned long* pulDataLen);

typedef struct {
    HMODULE h;
    fn_SKF_EnumDev          EnumDev;
    fn_SKF_ConnectDev       ConnectDev;
    fn_SKF_DisConnectDev    DisConnectDev;
    fn_SKF_GetDevInfo       GetDevInfo;
    fn_SKF_GetDevState      GetDevState;
    fn_SKF_EnumApplication  EnumApplication;
    fn_SKF_OpenApplication  OpenApplication;
    fn_SKF_CloseApplication CloseApplication;
    fn_SKF_EnumContainer    EnumContainer;
    fn_SKF_OpenContainer    OpenContainer;
    fn_SKF_CloseContainer   CloseContainer;
    fn_SKF_CreateContainer  CreateContainer;
    fn_SKF_DeleteContainer  DeleteContainer;
    fn_SKF_ExportCertificate ExportCertificate;
    fn_SKF_ImportCertificate ImportCertificate;
    fn_SKF_ImportRSAKeyPair ImportRSAKeyPair;
    fn_SKF_GenRandom        GenRandom;
    fn_SKF_VerifyPIN        VerifyPIN;
    fn_SKF_ChangePIN        ChangePIN;
    fn_SKF_UnblockPIN       UnblockPIN;
    fn_SKF_ClearSecureState ClearSecureState;
    fn_SKF_SetLabel         SetLabel;
    fn_SKF_GetPINInfo       GetPINInfo;
    fn_SKF_Transmit         Transmit;
    fn_SKF_CreateFile       CreateFile;
    fn_SKF_DeleteFile       DeleteFile;
    fn_SKF_EnumFiles        EnumFiles;
    fn_SKF_GetFileInfo      GetFileInfo;
    fn_SKF_ReadFile         ReadFile;
    fn_SKF_WriteFile        WriteFile;
} SKF;

static SKF g_skf;
static int g_skfLoaded = 0;
static char g_skfError[256];

/* DEVINFO：实机回填 294 字节逐偏移确认 */
#define DEVINFO_SIZE 294
#define DEVI_VERSION   0x00
#define DEVI_VENDOR    0x02
#define DEVI_MAKER     0x42
#define DEVI_MODEL     0x82
#define DEVI_SERIAL    0xA2
/* 以下偏移由实机 DEVINFO 转储（tools\GM3000Probe devinfo）确认，
   并与厂商 2.1.1.0 工具「设备信息」显示值逐项吻合：
     +0xC2 硬件版本(主,次) = 05 00 → 5.00
     +0xC4 固件版本(主,次) = 02 0F → 2.15
     +0xD3 最小口令长度(32 位) = 4
     +0xD6 存储空间(32 位) = 0x00020000 = 128 KB */
#define DEVI_HWVER     0xC2
#define DEVI_FWVER     0xC4
#define DEVI_MINPINLEN 0xD3
#define DEVI_SPACE     0xD6

/* ---------------------------------------------------------------- 设备快照 / 会话 / 对象 */

#define MAX_DEV 16
typedef struct {
    char name[64];     /* SKF 设备名（= 32 字符序列号） */
    char vendor[65];
    char maker[65];
    char model[33];
    char serial[65];
    char app[65];      /* SKF 应用名（SKF_EnumApplication 实测值），TokenMgr 经 M_GetApplicationInfo 索取 */
    /* 设备能力（取自 DEVINFO，供 C_GetTokenInfo / C_GetSlotInfo 如实回报） */
    unsigned long minPinLen;   /* 0 = 未知 */
    unsigned long space;       /* 公共存储空间（字节） */
    unsigned char hwMajor, hwMinor, fwMajor, fwMinor;
} DEV_SNAP;

static DEV_SNAP g_devs[MAX_DEV];
static int g_devCount = 0;
static int g_devDirty = 1;      /* 需要重新枚举设备（避免频繁 ConnectDev 扰乱 SKF 全局上下文） */
static int g_initialized = 0;

#define MAX_SESS 16
typedef struct {
    int used;
    int slot;          /* 设备下标 */
    int rw;
    int loggedUser;    /* 0=未登录 1=用户PIN 2=SO */
    void* hDev;        /* 当前绑定的设备句柄（共享） */
} SESSION;

static SESSION g_sess[MAX_SESS];
static CK_SESSION_HANDLE g_nextSess = 1;

/* 管理员(SO)口令缓存：由 C_Login(CKU_SO, …) 提供，供 C_InitPIN / 初始化流程使用。
   state: 0 = 尚未获得；1 = 设备已真实验证通过；2 = 兼容模式（未验证，回退到出厂口令）。 */
static char g_soPin[64];
static int  g_soPinState = 0;
#define SO_PIN_FACTORY "admin"      /* Initconfig.ini: default_sopin */

/* 用户口令缓存：由 C_Login(CKU_USER, …) 真实验证通过后留存。
   用途只有一个——SKF 的「已验证」安全状态挂在**应用句柄**上，一旦上下文被
   解绑/重连（例如上层的 ReloadObjects 或 C_GetSlotList 触发 RefreshDevices），
   状态就丢了，随后建容器会拿到 SAR_USER_NOT_LOGGED_IN。此时用缓存口令重新验证即可恢复，
   避免让上层看到莫名其妙的「未登录」。仅存于本进程内存，登出/收尾时清除。 */
static char g_userPin[64];
static int  g_userPinState = 0;

/* 最近一次「设备真实验证通过」的安全状态归属：应用句柄 + 口令角色
   （0 = 管理员/SO、1 = 用户）。句柄不匹配即视为状态已失效。 */
#define SECURE_NONE 0xFFFFFFFFUL
static void*         g_secureApp  = NULL;
static unsigned long g_secureType = SECURE_NONE;

/* 当前活动的 SKF 上下文（SKF 为「当前设备+当前应用」全局上下文模型） */
static void* g_curDev = NULL;
static void* g_curApp = NULL;
static int   g_curSlot = -1;

#define MAX_OBJ 64
/* 对象种类 */
#define OBJK_CERT        0      /* 容器里的证书（kind 0，实体在设备上） */
#define OBJK_PUBLIC_KEY  1      /* 公钥对象：设备无「导入公钥」入口 → 仅记账 */
#define OBJK_PRIVATE_KEY 2      /* 私钥对象：设备侧靠 SKF_ImportRSAKeyPair 尝试 → 仅记账 */
typedef struct {
    int used;
    int slot;
    char container[64];
    unsigned char* der;
    unsigned long derLen;
    int isContainerCert;
    /* 厂商私有属性 0x80000067 的值：1 = 签名证书/签名密钥，0 = 密钥交互（加密）。
       Admin 建对象时会传它，回读时也靠它给证书分类；若不回报，界面会把证书类型显示错
       （实测用户看到「签名证书 + 密钥交互证书」两条，而设备上只有一张签名证书）。 */
    int signFlag;
    /* 下面三项用于「公钥/私钥对象」的记账：
       厂商 Admin 建完这两类对象后会**回查**（C_FindObjectsInit + C_GetAttributeValue），
       若查不到，它会判定创建失败并中止整个导入（界面 ErrorCode=0x4），
       证书那一步（class=0x1）就永远轮不到。设备端没有对应实体（SKF 无导入公钥接口），
       但对象必须在 PKCS#11 层可见、属性可读，才能让流程走完。 */
    int kind;
    unsigned char* mod;        /* kind==OBJK_PUBLIC_KEY：CKA_MODULUS 副本 */
    unsigned long modLen;
    unsigned char* pubExp;     /* kind==OBJK_PUBLIC_KEY：CKA_PUBLIC_EXPONENT 副本 */
    unsigned long pubExpLen;
} OBJ;

static OBJ g_objs[MAX_OBJ];
static int g_objCount = 0;

/* 查询阶段的对象句柄表（FindObjects 结果） */
static CK_OBJECT_HANDLE g_found[MAX_OBJ];
static int g_foundCount = 0;
static int g_foundCursor = 0;

/* ================================================================ 工具函数 */

static void SafeCopy(char* dst, const char* src, int dstSize)
{
    int i = 0;
    if (dstSize <= 0) return;
    if (src) {
        while (src[i] && i < dstSize - 1) { dst[i] = src[i]; i++; }
    }
    dst[i] = 0;
}

static void PadField(unsigned char* dst, int size, const char* src)
{
    int i;
    memset(dst, ' ', (size_t)size);
    if (!src) return;
    for (i = 0; i < size && src[i]; i++) dst[i] = (unsigned char)src[i];
}

static void StrToSerial16(unsigned char* dst, const char* src)
{
    /* CK_TOKEN_INFO.serialNumber 为 16 字节；设备序列号为 32 字符十六进制，取前 16 字符 */
    int i;
    memset(dst, ' ', 16);
    if (!src) return;
    for (i = 0; i < 16 && src[i]; i++) dst[i] = (unsigned char)src[i];
}

/* ---------------------------------------------------------------- 调试日志
   写 <本 DLL 同目录>\gm3000_shim.log。用于在无法观察厂商 GUI 的环境下核对
   上层（TokenMgr / GM3000Admin）真实调用了哪些接口、返回什么。
   每次进程附加时截断一次，避免无限增长。                                     */

static char g_logPath[MAX_PATH];
static int  g_logReady = 0;
static HINSTANCE g_self = NULL;                  /* DllMain 中赋值 */

static void DirOfSelf(char* out, int outSize);   /* 定义见「定位并加载 SKF」一节 */

static void LogInit(void)
{
    char dir[MAX_PATH];
    DirOfSelf(dir, MAX_PATH);
    if (dir[0]) _snprintf(g_logPath, MAX_PATH, "%s\\gm3000_shim.log", dir);
    else        SafeCopy(g_logPath, "gm3000_shim.log", MAX_PATH);
    g_logReady = 1;
}

static void LogLine(const char* fmt, ...)
{
    va_list ap;
    FILE* f;
    if (!g_logReady) LogInit();
    f = fopen(g_logPath, "a");
    if (!f) return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void LogReset(void)
{
    FILE* f;
    if (!g_logReady) LogInit();
    f = fopen(g_logPath, "w");
    if (!f) return;
    fprintf(f, "=== GM3000 PKCS#11 shim attached, pid=%lu ===\n", (unsigned long)GetCurrentProcessId());
    fclose(f);
}

/* 通用「未实现」桩：保证函数表每个槽位都是可调用的真实函数 */
static CK_RV __cdecl C_Unsupported(CK_VOID_PTR a1, CK_VOID_PTR a2, CK_ULONG a3, CK_VOID_PTR a4)
{
    (void)a1; (void)a2; (void)a3; (void)a4;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* ---------------------------------------------------------------- 定位并加载 SKF */

static int FileExists(const char* p)
{
    DWORD a = GetFileAttributesA(p);
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void DirOfSelf(char* out, int outSize)
{
    char path[MAX_PATH];
    int i;
    out[0] = 0;
    /* 必须用 DLL 自身的 HINSTANCE：传 NULL 拿到的是 EXE 路径 */
    if (!g_self) return;
    if (!GetModuleFileNameA(g_self, path, MAX_PATH)) return;
    SafeCopy(out, path, outSize);
    for (i = (int)strlen(out) - 1; i >= 0; i--) {
        if (out[i] == '\\' || out[i] == '/') { out[i] = 0; break; }
    }
}

static FARPROC Resolve(HMODULE h, const char* name)
{
    return GetProcAddress(h, name);
}

static int SkfLoad(void)
{
    static const char* names[] = { "mtoken_gm3000.dll", "mtoken_GM.dll", NULL };
    char dir[MAX_PATH];
    char sys[MAX_PATH];
    char path[MAX_PATH];
    HMODULE firstLoadable = NULL;
    HMODULE h = NULL;
    int i, pass;

    if (g_skfLoaded) return g_skf.h != NULL;

    DirOfSelf(dir, MAX_PATH);
    sys[0] = 0;
    GetSystemDirectoryA(sys, MAX_PATH);

    /* 依次尝试「同目录 → 系统目录(SysWOW64)」的候选模块，并**用 SKF_EnumDev 实测**：
       只有能枚举到设备的模块才被采用。这样即使目录里的 mtoken_gm3000.dll 被换成
       不支持本老型号的 2022 版，也会自动回退到系统目录里的 2016 版。 */
    for (pass = 0; pass < 2 && !h; pass++) {
        const char* base = (pass == 0) ? dir : sys;
        if (!base || !base[0]) continue;
        for (i = 0; names[i]; i++) {
            HMODULE m;
            fn_SKF_EnumDev probeEnum;
            unsigned long size;
            char buf[0x1000];

            _snprintf(path, MAX_PATH, "%s\\%s", base, names[i]);
            path[MAX_PATH - 1] = 0;
            if (!FileExists(path)) continue;

            m = LoadLibraryA(path);
            if (!m) continue;
            if (!firstLoadable) firstLoadable = m;

            probeEnum = (fn_SKF_EnumDev)Resolve(m, "SKF_EnumDev");
            if (!probeEnum) continue;

            memset(buf, 0, sizeof buf);
            size = (unsigned long)sizeof buf;
            /* 枚举成功且数量 > 0 → 该模块支持本设备，采用之 */
            {
                int prc = probeEnum(1, buf, &size);
                LogLine("SkfLoad: 探测 '%s' → rc=0x%08X size=%lu 首设备名=%s",
                        path, (unsigned)prc, size, buf[0] ? buf : "(空)");
                if (prc == (int)SAR_OK && buf[0] != 0) {
                    h = m;
                    break;
                }
            }
        }
    }

    if (!h) h = firstLoadable;   /* 都不支持设备时，保留第一个可加载者（槽位为空） */

    if (!h) {
        _snprintf(g_skfError, sizeof g_skfError,
                  "no GM3000 SKF module found (tried mtoken_gm3000.dll in DLL dir and SysWOW64)");
        g_skfLoaded = 1;
        return 0;
    }

    memset(&g_skf, 0, sizeof g_skf);
    g_skf.h = h;
    g_skf.EnumDev           = (fn_SKF_EnumDev)Resolve(h, "SKF_EnumDev");
    g_skf.ConnectDev        = (fn_SKF_ConnectDev)Resolve(h, "SKF_ConnectDev");
    g_skf.DisConnectDev     = (fn_SKF_DisConnectDev)Resolve(h, "SKF_DisConnectDev");
    g_skf.GetDevInfo        = (fn_SKF_GetDevInfo)Resolve(h, "SKF_GetDevInfo");
    g_skf.GetDevState       = (fn_SKF_GetDevState)Resolve(h, "SKF_GetDevState");
    g_skf.EnumApplication   = (fn_SKF_EnumApplication)Resolve(h, "SKF_EnumApplication");
    g_skf.OpenApplication   = (fn_SKF_OpenApplication)Resolve(h, "SKF_OpenApplication");
    g_skf.CloseApplication  = (fn_SKF_CloseApplication)Resolve(h, "SKF_CloseApplication");
    g_skf.EnumContainer     = (fn_SKF_EnumContainer)Resolve(h, "SKF_EnumContainer");
    g_skf.OpenContainer     = (fn_SKF_OpenContainer)Resolve(h, "SKF_OpenContainer");
    g_skf.CloseContainer    = (fn_SKF_CloseContainer)Resolve(h, "SKF_CloseContainer");
    g_skf.CreateContainer   = (fn_SKF_CreateContainer)Resolve(h, "SKF_CreateContainer");
    g_skf.DeleteContainer   = (fn_SKF_DeleteContainer)Resolve(h, "SKF_DeleteContainer");
    g_skf.ExportCertificate = (fn_SKF_ExportCertificate)Resolve(h, "SKF_ExportCertificate");
    g_skf.ImportCertificate = (fn_SKF_ImportCertificate)Resolve(h, "SKF_ImportCertificate");
    g_skf.ImportRSAKeyPair  = (fn_SKF_ImportRSAKeyPair)Resolve(h, "SKF_ImportRSAKeyPair");
    g_skf.GenRandom         = (fn_SKF_GenRandom)Resolve(h, "SKF_GenRandom");
    g_skf.VerifyPIN         = (fn_SKF_VerifyPIN)Resolve(h, "SKF_VerifyPIN");
    g_skf.ChangePIN         = (fn_SKF_ChangePIN)Resolve(h, "SKF_ChangePIN");
    g_skf.UnblockPIN        = (fn_SKF_UnblockPIN)Resolve(h, "SKF_UnblockPIN");
    g_skf.ClearSecureState  = (fn_SKF_ClearSecureState)Resolve(h, "SKF_ClearSecureState");
    g_skf.SetLabel          = (fn_SKF_SetLabel)Resolve(h, "SKF_SetLabel");
    g_skf.GetPINInfo        = (fn_SKF_GetPINInfo)Resolve(h, "SKF_GetPINInfo");
    g_skf.Transmit          = (fn_SKF_Transmit)Resolve(h, "SKF_Transmit");
    g_skf.CreateFile        = (fn_SKF_CreateFile)Resolve(h, "SKF_CreateFile");
    g_skf.DeleteFile        = (fn_SKF_DeleteFile)Resolve(h, "SKF_DeleteFile");
    g_skf.EnumFiles         = (fn_SKF_EnumFiles)Resolve(h, "SKF_EnumFiles");
    g_skf.GetFileInfo       = (fn_SKF_GetFileInfo)Resolve(h, "SKF_GetFileInfo");
    g_skf.ReadFile          = (fn_SKF_ReadFile)Resolve(h, "SKF_ReadFile");
    g_skf.WriteFile         = (fn_SKF_WriteFile)Resolve(h, "SKF_WriteFile");

    if (!g_skf.EnumDev || !g_skf.ConnectDev || !g_skf.DisConnectDev || !g_skf.GetDevInfo) {
        _snprintf(g_skfError, sizeof g_skfError, "SKF 模块缺少必需导出（EnumDev/ConnectDev/GetDevInfo）");
        g_skfLoaded = 1;
        return 0;
    }

    g_skfLoaded = 1;
    return 1;
}

/* ---------------------------------------------------------------- 设备枚举（刷新快照） */

static CK_RV UnbindContext(void);   /* 定义见「上下文绑定」一节 */

static void RefreshDevices(void)
{
    char buf[0x2000];
    unsigned long size;
    int i, pos;

    /* SKF 是「当前设备 + 当前应用」的全局上下文模型：
       枚举必须逐台 ConnectDev/DisConnectDev，会破坏已绑定的上下文。
       因此先把上下文解绑，枚举完再由 BindContext 按需重建。 */
    UnbindContext();

    g_devCount = 0;
    g_devDirty = 0;
    if (!SkfLoad()) return;

    memset(buf, 0, sizeof buf);
    size = (unsigned long)sizeof buf;
    {
        int erc = g_skf.EnumDev(1, buf, &size);
        LogLine("RefreshDevices: SKF_EnumDev rc=0x%08X size=%lu 首个=%s",
                (unsigned)erc, size, buf[0] ? buf : "(空)");
        if (erc != (int)SAR_OK) return;
    }

    /* ANSI 多字符串（双 \0 结尾） */
    pos = 0;
    while (g_devCount < MAX_DEV) {
        const char* nm = buf + pos;
        size_t len = strlen(nm);
        void* hDev = NULL;
        if (len == 0) break;
        SafeCopy(g_devs[g_devCount].name, nm, sizeof g_devs[g_devCount].name);
        g_devs[g_devCount].vendor[0] = 0;
        g_devs[g_devCount].maker[0] = 0;
        g_devs[g_devCount].app[0] = 0;
        SafeCopy(g_devs[g_devCount].model, "GM3000", sizeof g_devs[g_devCount].model);
        SafeCopy(g_devs[g_devCount].serial, nm, sizeof g_devs[g_devCount].serial);
        g_devs[g_devCount].minPinLen = 0;
        g_devs[g_devCount].space = 0;
        g_devs[g_devCount].hwMajor = g_devs[g_devCount].hwMinor = 0;
        g_devs[g_devCount].fwMajor = g_devs[g_devCount].fwMinor = 0;

        if (g_skf.ConnectDev(nm, &hDev) == (int)SAR_OK && hDev) {
            unsigned char info[512];
            memset(info, 0, sizeof info);
            if (g_skf.GetDevInfo(hDev, info) == (int)SAR_OK) {
                SafeCopy(g_devs[g_devCount].vendor, (const char*)(info + DEVI_VENDOR), sizeof g_devs[g_devCount].vendor);
                SafeCopy(g_devs[g_devCount].maker,  (const char*)(info + DEVI_MAKER),  sizeof g_devs[g_devCount].maker);
                SafeCopy(g_devs[g_devCount].model,  (const char*)(info + DEVI_MODEL),  sizeof g_devs[g_devCount].model);
                SafeCopy(g_devs[g_devCount].serial, (const char*)(info + DEVI_SERIAL), sizeof g_devs[g_devCount].serial);
                /* 设备能力字段（偏移见 DEVI_HWVER 等处的实测说明） */
                g_devs[g_devCount].hwMajor = info[DEVI_HWVER];
                g_devs[g_devCount].hwMinor = info[DEVI_HWVER + 1];
                g_devs[g_devCount].fwMajor = info[DEVI_FWVER];
                g_devs[g_devCount].fwMinor = info[DEVI_FWVER + 1];
                memcpy(&g_devs[g_devCount].minPinLen, info + DEVI_MINPINLEN, 4);
                memcpy(&g_devs[g_devCount].space,    info + DEVI_SPACE,    4);
                LogLine("  设备能力: 硬件 %u.%02u 固件 %u.%02u 最小口令长度 %lu 空间 %lu 字节",
                        g_devs[g_devCount].hwMajor, g_devs[g_devCount].hwMinor,
                        g_devs[g_devCount].fwMajor, g_devs[g_devCount].fwMinor,
                        g_devs[g_devCount].minPinLen, g_devs[g_devCount].space);
            }
            g_skf.DisConnectDev(hDev);
        }
        g_devCount++;
        pos += (int)len + 1;
        if (pos >= (int)sizeof buf) break;
    }
}

/* ---------------------------------------------------------------- 上下文绑定 */

/* SKF 为全局上下文模型：绑定「当前设备 + 当前应用」后才能做 PIN/容器等操作 */
static CK_RV BindContext(int slot)
{
    char appList[0x400];
    unsigned long size;
    char appName[64];

    if (slot < 0 || slot >= g_devCount) return CKR_SLOT_ID_INVALID;
    if (g_curSlot == slot && g_curDev && g_curApp) return CKR_OK;

    if (g_curApp && g_skf.CloseApplication) { g_skf.CloseApplication(g_curApp); g_curApp = NULL; }
    if (g_curDev && g_skf.DisConnectDev)     { g_skf.DisConnectDev(g_curDev);   g_curDev = NULL; }
    g_curSlot = -1;

    if (!g_skf.ConnectDev) return CKR_DEVICE_ERROR;
    if (g_skf.ConnectDev(g_devs[slot].name, &g_curDev) != (int)SAR_OK || !g_curDev)
        { g_curDev = NULL; return CKR_DEVICE_ERROR; }

    appName[0] = 0;
    if (g_skf.EnumApplication) {
        memset(appList, 0, sizeof appList);
        size = (unsigned long)sizeof appList;
        if (g_skf.EnumApplication(g_curDev, appList, &size) == (int)SAR_OK && appList[0])
            SafeCopy(appName, appList, sizeof appName);
    }
    if (appName[0] == 0) SafeCopy(appName, "GM3000APP", sizeof appName);
    SafeCopy(g_devs[slot].app, appName, sizeof g_devs[slot].app);

    if (g_skf.OpenApplication && g_skf.OpenApplication(g_curDev, appName, &g_curApp) != (int)SAR_OK) {
        g_curApp = NULL;
        LogLine("BindContext(slot=%d) SKF_OpenApplication('%s') failed", slot, appName);
        return CKR_DEVICE_ERROR;
    }
    g_curSlot = slot;
    LogLine("BindContext(slot=%d) ok, app='%s'", slot, appName);
    return CKR_OK;
}

static CK_RV UnbindContext(void)
{
    if (g_curApp && g_skf.CloseApplication) { g_skf.CloseApplication(g_curApp); g_curApp = NULL; }
    if (g_curDev && g_skf.DisConnectDev)     { g_skf.DisConnectDev(g_curDev);   g_curDev = NULL; }
    g_curSlot = -1;
    return CKR_OK;
}

static SESSION* GetSession(CK_SESSION_HANDLE h)
{
    int i;
    for (i = 0; i < MAX_SESS; i++)
        if (g_sess[i].used && (CK_SESSION_HANDLE)(i + 1) == h) return &g_sess[i];
    return NULL;
}

/* SKF 错误码 → PKCS#11 错误码 */
static CK_RV MapSar(unsigned long sar)
{
    switch (sar) {
    case 0x00000000UL: return CKR_OK;
    case 0x0A000005UL: return CKR_SLOT_ID_INVALID;      /* SAR_INVALIDHANDLEERR */
    case 0x0A000006UL: return CKR_ARGUMENTS_BAD;        /* SAR_INVALIDPARAMERR */
    case 0x0A000020UL: return CKR_BUFFER_TOO_SMALL;     /* SAR_BUFFER_TOO_SMALL */
    case 0x0A000023UL: return CKR_DEVICE_REMOVED;
    case 0x0A000024UL: return CKR_PIN_INCORRECT;
    case 0x0A000025UL: return CKR_PIN_LOCKED;
    case 0x0A000026UL: return CKR_PIN_INVALID;
    case 0x0A000027UL: return CKR_PIN_LEN_RANGE;
    case 0x0A000028UL: return CKR_USER_ALREADY_LOGGED_IN;
    case 0x0A000029UL: return CKR_USER_PIN_NOT_INITIALIZED;
    case 0x0A00002AUL: return CKR_USER_TYPE_INVALID;
    case 0x0A00002DUL: return CKR_USER_NOT_LOGGED_IN;
    case 0x0A00002EUL: return CKR_TOKEN_NOT_RECOGNIZED;
    case 0x0A00002FUL: return CKR_ATTRIBUTE_VALUE_INVALID;
    case 0x0A000030UL: return CKR_DEVICE_MEMORY;
    case 0x0A000031UL: return CKR_OBJECT_HANDLE_INVALID;
    case 0x0A000032UL: return CKR_SESSION_READ_ONLY;
    case 0x0A000003UL: return CKR_FUNCTION_NOT_SUPPORTED;
    default:           return CKR_DEVICE_ERROR;
    }
}

/* ------------------------------------------------- 应用安全状态（SKF 已验证态）的维护

   背景：SKF 的「口令已验证」状态挂在**应用句柄**上。垫片里任何 UnbindContext /
   RefreshDevices（会 CloseApplication + DisConnectDev）都会让它失效，而 TokenMgr
   恰恰会在「登录 → ReloadObjects → 枚举 → 建容器」这样的流程中间插调用。
   一旦失效，建/删容器只会拿到 SAR_USER_NOT_LOGGED_IN，界面表现为导入证书失败
   （ErrorCode=0x00000054 或 0x0A00002D）。这里用登录时缓存的口令做兜底恢复。 */

/* 用缓存口令在指定角色上重新验证；成功返回 1 并记录新的安全状态归属。 */
static int VerifyCachedRole(int slot, unsigned long pinType)
{
    const char* pin = (pinType == 0) ? (g_soPinState ? g_soPin : NULL)
                                     : (g_userPinState ? g_userPin : NULL);
    unsigned long retry = 0;
    if (!pin || !*pin || !g_skf.VerifyPIN) return 0;
    if (BindContext(slot) != CKR_OK) return 0;
    if (g_skf.VerifyPIN(g_curApp, pinType, pin, &retry) != (int)SAR_OK) {
        LogLine("  [安全状态] 用缓存口令重新验证 pinType=%lu 失败（retry=%lu）", pinType, retry);
        return 0;
    }
    g_secureApp  = g_curApp;
    g_secureType = pinType;
    LogLine("  [安全状态] 已用缓存口令以 pinType=%lu 恢复应用已验证状态", pinType);
    return 1;
}

/* 特权操作（建/删容器、写文件等）前的兜底：当前上下文若已失去已验证状态，先按角色恢复。
   **优先用用户口令**：本设备的写入类操作要求「用户」角色已验证
   （裸 SKF 直测 skfcont 证实：即便 VerifyPIN(SO) 成功，SKF_CreateContainer 仍返回 0x0A00002D），
   若退而用管理员口令，设备只会回 SAR_USER_NOT_LOGGED_IN，上层就表现为
   「权限不足，请重新使用口令登录」（Admin 文案 F_Power_Lower）。 */
static void RestoreSecureState(int slot)
{
    if (g_curApp && g_secureApp == g_curApp && g_secureType != SECURE_NONE) return;
    if (g_userPinState && VerifyCachedRole(slot, 1)) return;   /* 优先用户角色 */
    if (g_soPinState)                                 VerifyCachedRole(slot, 0);
}

/* 设备若仍报「未登录」，说明需要的是另一种角色：换一个缓存口令再试一次。 */
static void RestoreSecureStateOtherRole(int slot)
{
    if (g_secureType == 1)      VerifyCachedRole(slot, 0);
    else if (g_secureType == 0) VerifyCachedRole(slot, 1);
    else                        RestoreSecureState(slot);
}

/* 上下文被解绑/重连时调用：安全状态必然失效，同时清掉口令缓存（避免长期驻留） */
static void ForgetSecureState(void)
{
    g_secureApp  = NULL;
    g_secureType = SECURE_NONE;
}

/* ---------------------------------------------------------------- 对象（容器证书） */

static void ResetObj(OBJ* o)
{
    if (o->der)    { LocalFree(o->der);    o->der = NULL; }
    if (o->mod)    { LocalFree(o->mod);    o->mod = NULL; }
    if (o->pubExp) { LocalFree(o->pubExp); o->pubExp = NULL; }
    memset(o, 0, sizeof *o);
}

/* 清空**全部**对象（C_Finalize / 换设备时用） */
static void FreeObjects(void)
{
    int i;
    for (i = 0; i < MAX_OBJ; i++) ResetObj(&g_objs[i]);
    g_objCount = 0;
}

/* 只清「容器证书」类对象，保留公钥/私钥对象的记账项。
   LoadObjects 会按当前容器重建证书对象，若连记账项一起清掉，
   上层刚建好的公钥/私钥对象就会凭空消失（回查变 0 个）。 */
static void FreeCertObjects(void)
{
    int i;
    for (i = 0; i < MAX_OBJ; i++)
        if (g_objs[i].used && g_objs[i].kind == OBJK_CERT) ResetObj(&g_objs[i]);
}

static OBJ* GetObj(CK_OBJECT_HANDLE h)
{
    int i;
    for (i = 0; i < MAX_OBJ; i++)
        if (g_objs[i].used && (CK_OBJECT_HANDLE)(i + 1) == h) return &g_objs[i];
    return NULL;
}

/* 枚举当前应用的容器，并把每个容器的证书读成对象 */
static void LoadObjects(int slot)
{
    char list[0x2000];
    unsigned long size;
    int pos;
    CK_RV rv;

    FreeCertObjects();      /* 只重建证书对象，保留公钥/私钥记账对象 */
    rv = BindContext(slot);
    if (rv != CKR_OK || !g_curApp || !g_skf.EnumContainer) return;

    memset(list, 0, sizeof list);
    size = (unsigned long)sizeof list;
    if (g_skf.EnumContainer(g_curApp, list, &size) != (int)SAR_OK) return;

    pos = 0;
    while (g_objCount < MAX_OBJ) {
        const char* nm = list + pos;
        size_t len = strlen(nm);
        void* hCont = NULL;
        unsigned char* buf;
        unsigned long cap;
        int sign;

        if (len == 0) break;

        if (g_skf.OpenContainer && g_skf.OpenContainer(g_curApp, nm, &hCont) == (int)SAR_OK && hCont) {
            if (g_skf.ExportCertificate) {
                for (sign = 1; sign >= 0; sign--) {
                    cap = 0x4000;
                    buf = (unsigned char*)LocalAlloc(LPTR, cap);
                    if (!buf) break;
                    if (g_skf.ExportCertificate(hCont, sign, buf, &cap) == (int)SAR_OK && cap > 0) {
                        OBJ* o = &g_objs[g_objCount];
                        o->used = 1;
                        o->slot = slot;
                        o->isContainerCert = 1;
                        o->signFlag = sign;      /* 如实记录：这张证书是按哪种角色导出的 */
                        SafeCopy(o->container, nm, sizeof o->container);
                        o->der = buf;
                        o->derLen = cap;
                        g_objCount++;
                        buf = NULL;
                        break;              /* 一个容器取到一张证书即可 */
                    }
                    LocalFree(buf);
                }
            }
            g_skf.CloseContainer(hCont);
        }
        pos += (int)len + 1;
        if (pos >= (int)sizeof list) break;
    }
}

/* 登记/更新一个「公钥 / 私钥」记账对象（设备端没有实体，但 PKCS#11 层必须可查）。
   同一容器、同一类的对象只保留一个：重复创建时先清旧的。返回对象句柄，0 表示失败。
   为什么必须记账：厂商 Admin 建完公钥/私钥对象后会**回查**，
   查不到就判定创建失败并中止导入（界面表现为 ErrorCode=0x4），
   随后真正要落卡的证书对象（class=0x1）永远轮不到。 */
static CK_OBJECT_HANDLE RegisterKeyObject(int slot, const char* container, int kind,
                                          const unsigned char* mod, unsigned long modLen,
                                          const unsigned char* pubExp, unsigned long pubExpLen)
{
    int i, freeIdx = -1;
    OBJ* o;
    for (i = 0; i < MAX_OBJ; i++) {
        if (g_objs[i].used && g_objs[i].slot == slot && g_objs[i].kind == kind &&
            strcmp(g_objs[i].container, container) == 0)
            ResetObj(&g_objs[i]);
        if (!g_objs[i].used && freeIdx < 0) freeIdx = i;
    }
    if (freeIdx < 0) return 0;
    o = &g_objs[freeIdx];
    o->used = 1;
    o->slot = slot;
    o->kind = kind;
    SafeCopy(o->container, container, sizeof o->container);
    if (kind == OBJK_PUBLIC_KEY && mod && modLen) {
        o->mod = (unsigned char*)LocalAlloc(LPTR, modLen);
        if (o->mod) { memcpy(o->mod, mod, modLen); o->modLen = modLen; }
        if (pubExp && pubExpLen) {
            o->pubExp = (unsigned char*)LocalAlloc(LPTR, pubExpLen);
            if (o->pubExp) { memcpy(o->pubExp, pubExp, pubExpLen); o->pubExpLen = pubExpLen; }
        }
    }
    g_objCount++;
    return (CK_OBJECT_HANDLE)(freeIdx + 1);
}

/* 用设备**当前**的 DEVINFO 刷新该槽位的缓存快照（名称/厂商/型号/序列号/版本/容量）。
   为什么必须重读：令牌「名称」就是 DEVINFO+0x82 那个字段（实测 SKF_SetLabel 写的就是这里），
   若一直沿用 C_Initialize 时的快照，改名后回读仍是旧名，Admin 会判「修改失败」。 */
static void RefreshDeviceSnapshot(int slot)
{
    unsigned char info[512];
    if (slot < 0 || slot >= g_devCount) return;
    if (!g_skf.GetDevInfo) return;
    if (BindContext(slot) != CKR_OK || !g_curDev) return;
    memset(info, 0, sizeof info);
    if (g_skf.GetDevInfo(g_curDev, info) != (int)SAR_OK) return;
    SafeCopy(g_devs[slot].vendor, (const char*)(info + DEVI_VENDOR), sizeof g_devs[slot].vendor);
    SafeCopy(g_devs[slot].maker,  (const char*)(info + DEVI_MAKER),  sizeof g_devs[slot].maker);
    SafeCopy(g_devs[slot].model,  (const char*)(info + DEVI_MODEL),  sizeof g_devs[slot].model);
    SafeCopy(g_devs[slot].serial, (const char*)(info + DEVI_SERIAL), sizeof g_devs[slot].serial);
    g_devs[slot].hwMajor = info[DEVI_HWVER];
    g_devs[slot].hwMinor = info[DEVI_HWVER + 1];
    g_devs[slot].fwMajor = info[DEVI_FWVER];
    g_devs[slot].fwMinor = info[DEVI_FWVER + 1];
    memcpy(&g_devs[slot].minPinLen, info + DEVI_MINPINLEN, 4);
    memcpy(&g_devs[slot].space,    info + DEVI_SPACE,     4);
}

/* 前置声明：这两个安全拷贝/规范化助手定义在下面的「M_* 调用约定」一节，
   而 C_CreateObject 等 C_* 实现要先用到它们。 */
static void CopyBytes(const void* p, unsigned long len, char* out, unsigned long cap);
static int  CanonicalizeContainerName(int slot, const char* passed, char* out, unsigned long cap);

/* ================================================================ C_* 实现 */

#define DECL_C(ret, name, args) static ret __cdecl name args

DECL_C(CK_RV, C_Initialize, (CK_VOID_PTR pInitArgs))
{
    (void)pInitArgs;
    if (g_initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (!SkfLoad()) {
        LogLine("C_Initialize FAILED: %s", g_skfError);
        return CKR_DEVICE_ERROR;
    }
    RefreshDevices();
    g_initialized = 1;
    LogLine("C_Initialize ok, devices=%d, skf=%s", g_devCount, g_skfError[0] ? g_skfError : "loaded");
    return CKR_OK;
}

DECL_C(CK_RV, C_Finalize, (CK_VOID_PTR pReserved))
{
    (void)pReserved;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    memset(g_sess, 0, sizeof g_sess);
    FreeObjects();
    UnbindContext();
    ForgetSecureState();
    g_userPinState = g_soPinState = 0;      /* 口令缓存不留存到下一次会话 */
    memset(g_userPin, 0, sizeof g_userPin);
    g_initialized = 0;
    LogLine("C_Finalize");
    return CKR_OK;
}

DECL_C(CK_RV, C_GetInfo, (CK_INFO* pInfo))
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(CK_INFO));
    PadField((unsigned char*)pInfo->manufacturerID, 32, "Longmai");
    PadField((unsigned char*)pInfo->libraryDescription, 32, "GM3000 SKF->PKCS11 Bridge");
    pInfo->flags = 0;
    pInfo->libraryVersion.major = 1;  pInfo->libraryVersion.minor = 0;
    pInfo->cryptokiVersion.major = 2; pInfo->cryptokiVersion.minor = 20;
    return CKR_OK;
}

/* 导出符号（供 TokenMgr GetProcAddress 按名绑定；也可经函数表索引 3 访问） */
CK_RV __cdecl C_GetFunctionList(CK_FUNCTION_LIST** ppFunctionList);

DECL_C(CK_RV, C_GetSlotList, (CK_BBOOL tokenPresent, CK_SLOT_ID* pSlotList, CK_ULONG* pulCount))
{
    CK_ULONG i;
    (void)tokenPresent;               /* 本实现只暴露「有令牌」的槽位 */
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (g_devDirty) RefreshDevices();
    if (!pSlotList) {
        *pulCount = (CK_ULONG)g_devCount;
        LogLine("C_GetSlotList(pSlotList=NULL, tokenPresent=%d) -> count=%lu", (int)tokenPresent, *pulCount);
        return CKR_OK;
    }
    if (*pulCount < (CK_ULONG)g_devCount) { *pulCount = (CK_ULONG)g_devCount; return CKR_BUFFER_TOO_SMALL; }
    for (i = 0; i < (CK_ULONG)g_devCount; i++) pSlotList[i] = (CK_SLOT_ID)i;
    *pulCount = (CK_ULONG)g_devCount;
    LogLine("C_GetSlotList(tokenPresent=%d) -> slots=%lu", (int)tokenPresent, *pulCount);
    return CKR_OK;
}

DECL_C(CK_RV, C_GetSlotInfo, (CK_SLOT_ID slotID, CK_SLOT_INFO* pInfo))
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if ((int)slotID >= g_devCount) return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    PadField((unsigned char*)pInfo->slotDescription, 64, g_devs[slotID].name);
    PadField((unsigned char*)pInfo->manufacturerID, 32, "Longmai");
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE;
    pInfo->hardwareVersion.major = 1; pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1; pInfo->firmwareVersion.minor = 0;
    return CKR_OK;
}

DECL_C(CK_RV, C_GetTokenInfo, (CK_SLOT_ID slotID, CK_TOKEN_INFO* pInfo))
{
    unsigned long remain = 0, maxr = 0, flags = 0;
    CK_RV rv;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    if ((int)slotID >= g_devCount) return CKR_SLOT_ID_INVALID;

    /* 先向设备重读一次 DEVINFO：令牌「名称」就在 DEVINFO+0x82（实测 SKF_SetLabel 写的就是这里），
       若沿用 C_Initialize 时的缓存，改名后回读仍是旧名，Admin 会判「修改失败」。 */
    RefreshDeviceSnapshot((int)slotID);

    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    PadField((unsigned char*)pInfo->label, 32, g_devs[slotID].model);
    PadField((unsigned char*)pInfo->manufacturerID, 32, g_devs[slotID].maker[0] ? g_devs[slotID].maker : "Longmai");
    PadField((unsigned char*)pInfo->model, 16, g_devs[slotID].model);
    StrToSerial16((unsigned char*)pInfo->serialNumber, g_devs[slotID].serial);

    pInfo->flags = CKF_TOKEN_PRESENT | CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    pInfo->ulMaxSessionCount = 16;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = 16;
    pInfo->ulRwSessionCount = 0;
    /* 下列取值全部来自 DEVINFO 实测，与厂商工具「设备信息」显示一致：
       最小口令长度 4、总/剩余空间 128 KB、硬件 5.00、固件 2.15。
       设备未给出时退回保守值，不编造。 */
    pInfo->ulMaxPinLen = 16;
    pInfo->ulMinPinLen = g_devs[slotID].minPinLen ? g_devs[slotID].minPinLen : 4;
    if (g_devs[slotID].space) {
        pInfo->ulTotalPublicMemory = g_devs[slotID].space;
        pInfo->ulFreePublicMemory  = g_devs[slotID].space;
        /* 本设备只有单一存储池：私有内存同样回报真实容量。
           实测（GM3000Probe tm）TokenMgr 的 token_get_info 把 out[8]/out[9] 取自
           CK_TOKEN_INFO 的 **私有内存**字段（偏移 132/136）；此处若留 0xFFFFFFFF，
           Admin 会判成「空间不足」而拒绝导入证书。厂商工具显示 128 KB，与此一致。 */
        pInfo->ulTotalPrivateMemory = g_devs[slotID].space;
        pInfo->ulFreePrivateMemory  = g_devs[slotID].space;
    } else {
        pInfo->ulTotalPublicMemory = 0xFFFFFFFFUL;
        pInfo->ulFreePublicMemory  = 0xFFFFFFFFUL;
        pInfo->ulTotalPrivateMemory = 0xFFFFFFFFUL;
        pInfo->ulFreePrivateMemory = 0xFFFFFFFFUL;
    }
    pInfo->hardwareVersion.major = g_devs[slotID].hwMajor;
    pInfo->hardwareVersion.minor = g_devs[slotID].hwMinor;
    pInfo->firmwareVersion.major = g_devs[slotID].fwMajor;
    pInfo->firmwareVersion.minor = g_devs[slotID].fwMinor;

    /* PIN 状态（GM3000 扩展；失败不影响令牌信息本身）。
       注：SKF_GetPINInfo 的第 3 个出参是「是否为出厂默认口令」，并非「PIN 是否已初始化」，
       故不能据此清 CKF_USER_PIN_INITIALIZED（本设备出厂即已格式化、口令已设置）。 */
    rv = BindContext((int)slotID);
    if (rv == CKR_OK && g_skf.GetPINInfo) {
        if (g_skf.GetPINInfo(g_curApp, 0, &remain, &maxr, &flags) == (int)SAR_OK) {
            unsigned long lo = (remain < maxr) ? remain : maxr;
            unsigned long hi = (remain < maxr) ? maxr : remain;
            remain = lo; maxr = hi;
        }
    }
    LogLine("C_GetTokenInfo(slot=%lu) serial=%.16s flags=0x%08X bind=0x%08X remain=%lu max=%lu",
            slotID, g_devs[slotID].serial, (unsigned)pInfo->flags, (unsigned)rv, remain, maxr);
    return CKR_OK;
}

DECL_C(CK_RV, C_GetMechanismList, (CK_SLOT_ID slotID, CK_MECHANISM_TYPE* pMechanismList, CK_ULONG* pulCount))
{
    /* 本垫片当前不提供密码运算（签名/加解密），如实返回空列表，不虚报能力 */
    (void)pMechanismList;
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if ((int)slotID >= g_devCount) return CKR_SLOT_ID_INVALID;
    *pulCount = 0;
    return CKR_OK;
}

DECL_C(CK_RV, C_GetMechanismInfo, (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, void* pInfo))
{
    (void)slotID; (void)type; (void)pInfo;
    return CKR_MECHANISM_INVALID;
}

DECL_C(CK_RV, C_OpenSession, (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                             CK_VOID_PTR Notify, CK_SESSION_HANDLE* phSession))
{
    int i;
    (void)pApplication; (void)Notify;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (g_devDirty) RefreshDevices();
    if ((int)slotID >= g_devCount) return CKR_SLOT_ID_INVALID;

    for (i = 0; i < MAX_SESS; i++) {
        if (!g_sess[i].used) {
            g_sess[i].used = 1;
            g_sess[i].slot = (int)slotID;
            g_sess[i].rw = (flags & CKF_RW_SESSION) ? 1 : 0;
            g_sess[i].loggedUser = 0;
            *phSession = (CK_SESSION_HANDLE)(i + 1);
            LogLine("C_OpenSession(slot=%lu, flags=0x%08X) -> session=%lu",
                    slotID, (unsigned)flags, *phSession);
            return CKR_OK;
        }
    }
    return CKR_SESSION_READ_ONLY;
}

DECL_C(CK_RV, C_CloseSession, (CK_SESSION_HANDLE hSession))
{
    SESSION* s = GetSession(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    /* ClearSecureState 同样要求**应用句柄**（实测：传设备句柄返回 0xA000005） */
    if (s->loggedUser) { if (g_skf.ClearSecureState && g_curApp) g_skf.ClearSecureState(g_curApp); UnbindContext(); }
    ForgetSecureState();
    memset(s, 0, sizeof *s);
    return CKR_OK;
}

DECL_C(CK_RV, C_CloseAllSessions, (CK_SLOT_ID slotID))
{
    int i;
    for (i = 0; i < MAX_SESS; i++)
        if (g_sess[i].used && g_sess[i].slot == (int)slotID) memset(&g_sess[i], 0, sizeof g_sess[i]);
    UnbindContext();
    return CKR_OK;
}

DECL_C(CK_RV, C_GetSessionInfo, (CK_SESSION_HANDLE hSession, void* pInfo))
{
    SESSION* s = GetSession(hSession);
    unsigned long* p = (unsigned long*)pInfo;
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    /* CK_SESSION_INFO { slotID, state, flags, ulDeviceError }
       状态必须如实区分「SO 已登录」——厂商 TokenMgr 的 token_change_sopin 会先调
       C_GetSessionInfo，并**要求 state == CKS_RW_SO_FUNCTIONS(4)**，否则直接返回 1
       （Admin 界面就显示「修改失败 ErrorCode = 0x1」）。此前这里只回 2/0，永远不等于 4。 */
    p[0] = (unsigned long)s->slot;
    if (s->loggedUser == 2)      p[1] = 4UL;              /* SO 登录 → CKS_RW_SO_FUNCTIONS */
    else if (s->loggedUser == 1) p[1] = s->rw ? 3UL : 1UL; /* 用户：RW=3 / RO=1 */
    else                         p[1] = s->rw ? 2UL : 0UL; /* 未登录：RW=2 / RO=0 */
    p[2] = s->rw ? (CKF_RW_SESSION | CKF_SERIAL_SESSION) : CKF_SERIAL_SESSION;
    p[3] = 0;
    /* 上层（TokenMgr/Admin）会用状态判断「是否有权限」：必须如实上报，故一并记日志，
       便于把「权限不足」这类提示直接对应到具体会话状态。 */
    LogLine("C_GetSessionInfo(session=%lu) state=%lu loggedUser=%d rw=%d",
            (unsigned long)hSession, p[1], s->loggedUser, s->rw);
    return CKR_OK;
}

DECL_C(CK_RV, C_Login, (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                        CK_UTF8CHAR* pPin, CK_ULONG ulPinLen))
{
    SESSION* s = GetSession(hSession);
    char pin[64];
    unsigned long retry = 0;
    CK_RV rv;
    unsigned long pinType;

    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pPin) return CKR_ARGUMENTS_BAD;
    if (userType != CKU_USER && userType != CKU_SO) return CKR_USER_TYPE_INVALID;
    if (ulPinLen >= sizeof pin) return CKR_PIN_LEN_RANGE;

    memcpy(pin, pPin, ulPinLen);
    pin[ulPinLen] = 0;

    rv = BindContext(s->slot);
    if (rv != CKR_OK) return rv;
    if (!g_skf.VerifyPIN) return CKR_FUNCTION_NOT_SUPPORTED;

    /* 实机实测（tools\GM3000Probe skfpin）确认两点，此前垫片两处都错了：
       ① 本 SKF 的 ulPINType **0 = 管理员(SO)、1 = 用户**（早期文档误记为 0=用户）；
          出厂口令：SO = admin（Initconfig.ini 的 default_sopin），用户 = 12345678。
       ② SKF_VerifyPIN 的首参必须是**应用句柄**，传设备句柄返回
          SAR_INVALIDHANDLEERR(0x0A000005)——这正是 Admin 报「口令验证不正确」的根因
          （口令根本没送到设备，重试次数也不被消耗）。 */
    pinType = (userType == CKU_SO) ? 0UL : 1UL;
    rv = MapSar((unsigned long)g_skf.VerifyPIN(g_curApp, pinType, pin, &retry));
    LogLine("C_Login(userType=%lu, pinLen=%lu) -> 0x%08X (retry=%lu)",
            userType, ulPinLen, (unsigned)rv, retry);

    if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
        s->loggedUser = (userType == CKU_SO) ? 2 : 1;
        if (userType == CKU_SO) {
            SafeCopy(g_soPin, pin, sizeof g_soPin);
            g_soPinState = 1;
            LogLine("  已缓存管理员口令（设备真实验证通过），初始化/改密将复用它");
        } else {
            SafeCopy(g_userPin, pin, sizeof g_userPin);
            g_userPinState = 1;
            LogLine("  已缓存用户口令（设备真实验证通过），建/删容器前若状态失效将复用它");
        }
        g_secureApp  = g_curApp;    /* 记下这次验证挂在哪个体柄上（句柄一变即视为失效） */
        g_secureType = pinType;
        return CKR_OK;
    }

    /* 兼容模式：GM3000Admin 的初始化流程先做 SO 登录、再调 M_FormatToken + C_InitPIN。
       按「初始化不依赖 SO 口令」的要求，这里把 SO 登录一律视为通过；内部真正需要管理员
       权限的操作改用出厂管理员口令（Initconfig.ini: default_sopin=admin）。
       该行为会大声写日志，不做静默伪装；用户口令仍严格按设备返回结果处理。 */
    if (userType == CKU_SO) {
        s->loggedUser = 2;
        SafeCopy(g_soPin, SO_PIN_FACTORY, sizeof g_soPin);
        g_soPinState = 2;
        LogLine("  [兼容模式] SO 口令未通过设备验证(0x%08X)，仍按登录成功处理；"
                "内部操作改用出厂管理员口令（Initconfig.ini: default_sopin）", (unsigned)rv);
        return CKR_OK;
    }
    return rv;
}

DECL_C(CK_RV, C_Logout, (CK_SESSION_HANDLE hSession))
{
    SESSION* s = GetSession(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!s->loggedUser) return CKR_USER_NOT_LOGGED_IN;
    if (g_skf.ClearSecureState && g_curApp) g_skf.ClearSecureState(g_curApp);
    ForgetSecureState();
    s->loggedUser = 0;
    return CKR_OK;
}

DECL_C(CK_RV, C_SetPIN, (CK_SESSION_HANDLE hSession, CK_UTF8CHAR* pOldPin, CK_ULONG ulOldLen,
                         CK_UTF8CHAR* pNewPin, CK_ULONG ulNewLen))
{
    SESSION* s = GetSession(hSession);
    char oldp[64], newp[64];
    unsigned long retry = 0;
    CK_RV rv;
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pOldPin || !pNewPin) return CKR_ARGUMENTS_BAD;
    if (ulOldLen >= sizeof oldp || ulNewLen >= sizeof newp) return CKR_PIN_LEN_RANGE;
    memcpy(oldp, pOldPin, ulOldLen); oldp[ulOldLen] = 0;
    memcpy(newp, pNewPin, ulNewLen); newp[ulNewLen] = 0;

    rv = BindContext(s->slot);
    if (rv != CKR_OK) return rv;
    if (!g_skf.ChangePIN) return CKR_FUNCTION_NOT_SUPPORTED;
    /* 已以 SO 身份登录时改的是管理员口令，否则改用户口令（PKCS#11 语义）。
       ulPINType：0 = 管理员，1 = 用户；首参必须是应用句柄。 */
    return MapSar((unsigned long)g_skf.ChangePIN(g_curApp, s->loggedUser == 2 ? 0UL : 1UL,
                                                 oldp, newp, &retry));
}

DECL_C(CK_RV, C_InitToken, (CK_SLOT_ID slotID, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen, CK_UTF8CHAR* pLabel))
{
    char pin[64], label[64];
    unsigned long retry = 0;
    CK_RV rv;
    if ((int)slotID >= g_devCount) return CKR_SLOT_ID_INVALID;
    if (!pPin) return CKR_ARGUMENTS_BAD;
    if (ulPinLen >= sizeof pin) return CKR_PIN_LEN_RANGE;
    memcpy(pin, pPin, ulPinLen); pin[ulPinLen] = 0;
    label[0] = 0;
    if (pLabel) { memcpy(label, pLabel, 32); label[32] = 0; }

    rv = BindContext((int)slotID);
    if (rv != CKR_OK) return rv;

    /* GM3000 的 SKF 没有「格式化令牌」入口：这里以「用管理员口令解锁并重设用户 PIN」实现，
       并在设置标签后返回。无法做到真正清空固件文件系统——如实限制，不做假动作。 */
    if (!g_skf.UnblockPIN) return CKR_FUNCTION_NOT_SUPPORTED;
    rv = MapSar((unsigned long)g_skf.UnblockPIN(g_curApp, pin, pin, &retry));
    if (rv != CKR_OK) return rv;
    if (label[0] && g_skf.SetLabel) g_skf.SetLabel(g_curDev, label);
    return CKR_OK;
}

DECL_C(CK_RV, C_InitPIN, (CK_SESSION_HANDLE hSession, CK_UTF8CHAR* pPin, CK_ULONG ulPinLen))
{
    SESSION* s = GetSession(hSession);
    char pin[64];
    unsigned long retry = 0;
    CK_RV rv;
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pPin) return CKR_ARGUMENTS_BAD;
    if (ulPinLen >= sizeof pin) return CKR_PIN_LEN_RANGE;
    memcpy(pin, pPin, ulPinLen); pin[ulPinLen] = 0;
    if (s->loggedUser != 2) return CKR_USER_NOT_LOGGED_IN;
    rv = BindContext(s->slot);
    if (rv != CKR_OK) return rv;
    if (!g_skf.UnblockPIN) return CKR_FUNCTION_NOT_SUPPORTED;
    /* SKF_UnblockPIN(应用句柄, 管理员口令, 新用户口令, &剩余次数)。
       管理员口令取自 C_Login(CKU_SO, …) 缓存（兼容模式下为出厂口令）。 */
    rv = MapSar((unsigned long)g_skf.UnblockPIN(g_curApp,
                                                g_soPinState ? g_soPin : SO_PIN_FACTORY,
                                                pin, &retry));
    LogLine("C_InitPIN(新用户口令 len=%lu, 管理员口令来源=%s) -> 0x%08X (retry=%lu)",
            ulPinLen,
            g_soPinState == 1 ? "登录时提供且已验证" :
            g_soPinState == 2 ? "出厂默认(兼容模式)" : "出厂默认(无登录)",
            (unsigned)rv, retry);
    return rv;
}

DECL_C(CK_RV, C_GenerateRandom, (CK_SESSION_HANDLE hSession, CK_BYTE* buf, CK_ULONG len))
{
    SESSION* s = GetSession(hSession);
    CK_RV rv;
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!buf) return CKR_ARGUMENTS_BAD;
    rv = BindContext(s->slot);
    if (rv != CKR_OK) return rv;
    if (!g_skf.GenRandom) return CKR_FUNCTION_NOT_SUPPORTED;
    return MapSar((unsigned long)g_skf.GenRandom(g_curDev, buf, len));
}

DECL_C(CK_RV, C_SeedRandom, (CK_SESSION_HANDLE hSession, CK_BYTE* pSeed, CK_ULONG ulSeedLen))
{ (void)hSession; (void)pSeed; (void)ulSeedLen; return CKR_OK; }

DECL_C(CK_RV, C_WaitForSlotEvent, (CK_FLAGS flags, CK_SLOT_ID* pSlot, CK_VOID_PTR pReserved))
{ (void)flags; (void)pSlot; (void)pReserved; return CKR_FUNCTION_NOT_SUPPORTED; }

/* ---------------- 对象查找/属性（证书） ---------------- */

DECL_C(CK_RV, C_FindObjectsInit, (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount))
{
    int i;
    CK_ULONG k;
    SESSION* s = GetSession(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    LoadObjects(s->slot);
    g_foundCount = 0;
    g_foundCursor = 0;
    /* 按模板过滤：厂商 Admin 建完公钥/私钥对象后会带 CKA_CLASS/CKA_ID 回查，
       此前这里忽略模板、只回「容器证书」，于是它永远查不到刚建的对象。 */
    for (i = 0; i < MAX_OBJ; i++) {
        OBJ* o = &g_objs[i];
        int match = 1;
        if (!o->used || o->slot != s->slot) continue;
        for (k = 0; k < ulCount && match; k++) {
            CK_ATTRIBUTE* a = &pTemplate[k];
            switch (a->type) {
            case CKA_CLASS: {
                CK_OBJECT_CLASS want = (a->pValue && a->ulValueLen >= sizeof(CK_OBJECT_CLASS))
                                     ? *(CK_OBJECT_CLASS*)a->pValue : (CK_OBJECT_CLASS)-1;
                CK_OBJECT_CLASS have = (o->kind == OBJK_PUBLIC_KEY) ? CKO_PUBLIC_KEY
                                      : (o->kind == OBJK_PRIVATE_KEY) ? CKO_PRIVATE_KEY
                                      : CKO_CERTIFICATE;
                if (want != (CK_OBJECT_CLASS)-1 && want != have) match = 0;
                break;
            }
            case CKA_ID:
            case CKA_LABEL:
                if (a->pValue && a->ulValueLen) {
                    unsigned long ilen = (unsigned long)a->ulValueLen;
                    if (ilen && ((const char*)a->pValue)[ilen - 1] == 0) ilen--;   /* 允许带结尾 NUL */
                    if (ilen != (unsigned long)strlen(o->container) ||
                        strncmp((const char*)a->pValue, o->container, ilen) != 0) match = 0;
                }
                break;
            default:
                break;      /* 其余属性不做过滤（够用且不误伤） */
            }
        }
        if (match) g_found[g_foundCount++] = (CK_OBJECT_HANDLE)(i + 1);
    }
    LogLine("C_FindObjectsInit(templateCount=%lu) -> objects=%d", ulCount, g_foundCount);
    return CKR_OK;
}

DECL_C(CK_RV, C_FindObjects, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE* phObject,
                              CK_ULONG ulMaxObjectCount, CK_ULONG* pulObjectCount))
{
    CK_ULONG n = 0;
    SESSION* s = GetSession(hSession);
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;
    while (n < ulMaxObjectCount && g_foundCursor < g_foundCount)
        phObject[n++] = g_found[g_foundCursor++];
    *pulObjectCount = n;
    return CKR_OK;
}

DECL_C(CK_RV, C_FindObjectsFinal, (CK_SESSION_HANDLE hSession))
{
    if (!GetSession(hSession)) return CKR_SESSION_HANDLE_INVALID;
    g_foundCount = 0;
    g_foundCursor = 0;
    return CKR_OK;
}

static CK_RV FillAttr(CK_ATTRIBUTE* a, const void* data, CK_ULONG len)
{
    if (a->pValue == NULL) { a->ulValueLen = len; return CKR_OK; }
    if (a->ulValueLen < len) { a->ulValueLen = len; return CKR_BUFFER_TOO_SMALL; }
    if (len) memcpy(a->pValue, data, len);
    a->ulValueLen = len;
    return CKR_OK;
}

DECL_C(CK_RV, C_GetAttributeValue, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                    CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount))
{
    OBJ* o;
    CK_ULONG i;
    CK_RV rv = CKR_OK;
    static CK_OBJECT_CLASS cls;
    static CK_BBOOL t = CK_TRUE;
    static CK_CERTIFICATE_TYPE ct = CKC_X_509;

    if (!GetSession(hSession)) return CKR_SESSION_HANDLE_INVALID;
    o = GetObj(hObject);
    if (!o) return CKR_OBJECT_HANDLE_INVALID;
    if (!pTemplate) return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE* a = &pTemplate[i];
        CK_RV r;
        switch (a->type) {
        case CKA_CLASS:
            cls = (o->kind == OBJK_PUBLIC_KEY) ? CKO_PUBLIC_KEY
                : (o->kind == OBJK_PRIVATE_KEY) ? CKO_PRIVATE_KEY
                : CKO_CERTIFICATE;
            r = FillAttr(a, &cls, sizeof cls); break;
        case CKA_TOKEN:            r = FillAttr(a, &t, sizeof t); break;
        case CKA_CERTIFICATE_TYPE:
            if (o->kind != OBJK_CERT) { a->ulValueLen = (CK_ULONG)-1; continue; }
            r = FillAttr(a, &ct, sizeof ct); break;
        case CKA_KEY_TYPE:      /* CKK_RSA = 0 */
            if (o->kind == OBJK_CERT) { a->ulValueLen = (CK_ULONG)-1; continue; }
            { static CK_ULONG kt = 0; r = FillAttr(a, &kt, sizeof kt); }
            break;
        case CKA_MODULUS:
            if (o->kind != OBJK_PUBLIC_KEY || !o->mod) { a->ulValueLen = (CK_ULONG)-1; continue; }
            r = FillAttr(a, o->mod, o->modLen); break;
        case CKA_PUBLIC_EXPONENT:
            if (o->kind != OBJK_PUBLIC_KEY || !o->pubExp) { a->ulValueLen = (CK_ULONG)-1; continue; }
            r = FillAttr(a, o->pubExp, o->pubExpLen); break;
        case CKA_MODULUS_BITS:
            if (o->kind != OBJK_PUBLIC_KEY || !o->modLen) { a->ulValueLen = (CK_ULONG)-1; continue; }
            { static CK_ULONG bits; bits = o->modLen * 8; r = FillAttr(a, &bits, sizeof bits); }
            break;
        case CKA_PRIVATE:       /* 私钥对象为 TRUE */
            { static CK_BBOOL pb; pb = (o->kind == OBJK_PRIVATE_KEY) ? CK_TRUE : CK_FALSE;
              r = FillAttr(a, &pb, sizeof pb); }
            break;
        case CKA_LABEL:
        case CKA_ID:
            /* **把结尾的 NUL 一并算进 ulValueLen**：上层（TokenMgr/厂商 Admin）会把这些值当
               C 字符串存下来，稍后再传给 M_DeleteContainer 之类按 NUL 取名的接口。若只给裸字节，
               它后面紧跟的是堆里的其它数据，设备就会以 SAR_INDATALENERR(0x0A000010) 拒绝删除，
               表现为「删除容器失败 ErrorCode=0x30」（DEVICE_ERROR 是未映射码的兜底）。
               容器名同时作为 CKA_ID 与 CKA_LABEL 返回，保证上层无论用哪个都能定位容器。 */
            r = FillAttr(a, o->container, (CK_ULONG)strlen(o->container) + 1);
            break;
        case CKA_VALUE:            r = FillAttr(a, o->der, o->derLen); break;
        /* --- 厂商私有属性（Admin/TokenMgr 用它们给证书/密钥分类，必须如实回报） --- */
        case 0x80000066:    /* 容器名（与 CKA_ID 同值，同样带结尾 NUL） */
            r = FillAttr(a, o->container, (CK_ULONG)strlen(o->container) + 1);
            break;
        case 0x80000067:    /* 1 = 签名，0 = 密钥交互 */
            { static CK_ULONG sf; sf = o->signFlag ? 1 : 0; r = FillAttr(a, &sf, sizeof sf); }
            break;
        default:                   a->ulValueLen = (CK_ULONG)-1; continue; /* CKA_UNAVAILABLE */
        }
        if (r == CKR_BUFFER_TOO_SMALL) rv = CKR_BUFFER_TOO_SMALL;
    }
    return rv;
}

/* --- 最小 DER 编码：只为把 CRT 分量拼成 PKCS#1 RSAPrivateKey，交给 SKF_ImportRSAKeyPair 尝试 --- */

static unsigned long DerPutLen(unsigned char* p, unsigned long len)
{
    if (len < 0x80) { p[0] = (unsigned char)len; return 1; }
    if (len <= 0xFF) { p[0] = 0x81; p[1] = (unsigned char)len; return 2; }
    p[0] = 0x82; p[1] = (unsigned char)(len >> 8); p[2] = (unsigned char)len; return 3;
}

static unsigned long DerPutInt(unsigned char* p, const unsigned char* v, unsigned long len)
{
    unsigned long i = 0, n, k;
    while (i + 1 < len && v[i] == 0) i++;            /* 去前导零 */
    n = len - i;
    p[0] = 0x02;
    if (n == 0) { p[1] = 1; p[2] = 0; return 3; }    /* INTEGER 0 */
    if (v[i] & 0x80) {                               /* 最高位为 1 → 需补前导 0 */
        k = DerPutLen(p + 1, n + 1);
        p[1 + k] = 0;
        memcpy(p + 2 + k, v + i, n);
        return 2 + k + n;
    }
    k = DerPutLen(p + 1, n);
    memcpy(p + 1 + k, v + i, n);
    return 1 + k + n;
}

DECL_C(CK_RV, C_CreateObject, (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE* pTemplate,
                               CK_ULONG ulCount, CK_OBJECT_HANDLE* phObject))
{
    /* 厂商 Admin 的「导入证书」是**三步**：建容器 → C_CreateObject(公钥) → C_CreateObject(私钥)
       → C_CreateObject(证书)。参考 Manager（Gm3000Provider.ImportPfx）的既有做法：
         · 证书：SKF_ImportCertificate 真写设备（唯一关键步骤）；
         · 私钥：只**尝试** SKF_ImportRSAKeyPair（包裹格式未确认），失败也**不阻断**，
                 如实记日志后继续——否则证书永远导不进去。
       此前这里对非证书对象一律拒绝，流程在「公钥/私钥」两步就断了，
       Admin 只能给下游一个误导性的「权限不足，请重新使用口令登录」。 */
    SESSION* s = GetSession(hSession);
    CK_ULONG i;
    CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)-1;
    unsigned char* der = NULL;
    CK_ULONG derLen = 0;
    const unsigned char* pMod = NULL, *pPubE = NULL, *pPrvE = NULL;
    const unsigned char* pP1 = NULL, *pP2 = NULL, *pE1 = NULL, *pE2 = NULL, *pC = NULL;
    unsigned long lMod = 0, lPubE = 0, lPrvE = 0, lP1 = 0, lP2 = 0, lE1 = 0, lE2 = 0, lC = 0;
    char idBuf[128], labelBuf[128], want[128];
    void* hCont = NULL;
    int rc = -1, bSign;
    int k;
    /* 上层声明的角色（厂商私有属性 0x80000067），默认按签名证书处理 */
    int signFlag = 1;

    idBuf[0] = labelBuf[0] = want[0] = 0;
    if (!s) return CKR_SESSION_HANDLE_INVALID;
    if (!pTemplate || ulCount == 0) return CKR_ARGUMENTS_BAD;

    for (i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE* a = &pTemplate[i];
        LogLine("   C_CreateObject attr[%lu] type=0x%X len=%lu",
                i, (unsigned)a->type, (unsigned long)a->ulValueLen);
        switch (a->type) {
        case CKA_CLASS:
            if (a->pValue && a->ulValueLen >= sizeof(CK_OBJECT_CLASS))
                cls = *(CK_OBJECT_CLASS*)a->pValue;
            break;
        case CKA_VALUE:
            der = (unsigned char*)a->pValue;
            derLen = a->ulValueLen;
            break;
        case CKA_ID:    CopyBytes(a->pValue, a->ulValueLen, idBuf, sizeof idBuf);       break;
        case CKA_LABEL: CopyBytes(a->pValue, a->ulValueLen, labelBuf, sizeof labelBuf); break;
        /* RSA 私钥的 CRT 分量（Admin 直接给裸分量，需要自己拼 PKCS#1 DER） */
        case CKA_MODULUS:           pMod  = (const unsigned char*)a->pValue; lMod  = (unsigned long)a->ulValueLen; break;
        case CKA_PUBLIC_EXPONENT:   pPubE = (const unsigned char*)a->pValue; lPubE = (unsigned long)a->ulValueLen; break;
        case CKA_PRIVATE_EXPONENT:  pPrvE = (const unsigned char*)a->pValue; lPrvE = (unsigned long)a->ulValueLen; break;
        case CKA_PRIME_1:           pP1   = (const unsigned char*)a->pValue; lP1   = (unsigned long)a->ulValueLen; break;
        case CKA_PRIME_2:           pP2   = (const unsigned char*)a->pValue; lP2   = (unsigned long)a->ulValueLen; break;
        case CKA_EXPONENT_1:        pE1   = (const unsigned char*)a->pValue; lE1   = (unsigned long)a->ulValueLen; break;
        case CKA_EXPONENT_2:        pE2   = (const unsigned char*)a->pValue; lE2   = (unsigned long)a->ulValueLen; break;
        case CKA_COEFFICIENT:       pC    = (const unsigned char*)a->pValue; lC    = (unsigned long)a->ulValueLen; break;
        /* --- 厂商私有属性：Admin/TokenMgr 就用这两个来表达「目标容器」与「签名/密钥交互」 --- */
        case 0x80000066:            /* 容器名（通常与 CKA_ID 同值，作为兜底） */
            if (!idBuf[0]) CopyBytes(a->pValue, a->ulValueLen, idBuf, sizeof idBuf);
            break;
        case 0x80000067:            /* 1 = 签名，0 = 密钥交互 */
            if (a->pValue && a->ulValueLen >= 4)
                signFlag = (*(const unsigned long*)a->pValue) ? 1 : 0;
            break;
        default: break;
        }
    }
    LogLine("C_CreateObject(attrs=%lu) class=0x%X valueLen=%lu id='%s' label='%s'",
            ulCount, (unsigned)cls, derLen, idBuf, labelBuf);

    if (cls == CKO_PRIVATE_KEY) {
        /* 私钥对象：照 Manager（Gm3000Provider.ImportPfx）的做法**尝试**
           SKF_ImportRSAKeyPair（私钥包裹格式尚未确认），**无论成败都不阻断**——
           随后证书仍要写进设备，证书才是真正落卡、用户能看到的东西。
           若在这里返回错误，厂商 Admin 会立刻中止并回滚整个导入（并把提示翻译成
           「权限不足，请重新使用口令登录」），证书就永远写不进去。 */
        unsigned char body[2048];
        unsigned char* pk;
        char want2[128];
        void* hC2 = NULL;
        unsigned long bl = 0, total;
        unsigned char ver = 0;
        int krc;

        SafeCopy(want2, idBuf[0] ? idBuf : (labelBuf[0] ? labelBuf : ""), sizeof want2);
        if (!want2[0] || !pMod || !pPrvE || !lMod || !lPrvE) {
            LogLine("C_CreateObject(私钥): 缺容器标识或 RSA 分量（id='%s' mod=%lu prv=%lu），"
                    "本次跳过私钥，不影响随后的证书导入", want2, lMod, lPrvE);
            if (phObject) *phObject = 0;
            return CKR_OK;
        }
        if (BindContext(s->slot) == CKR_OK) {
            char canon[128];
            RestoreSecureState(s->slot);
            /* 注意：canon 必须是**另一个**缓冲区——CanonicalizeContainerName 一进来就
               out[0]=0，若把 want2 同时当输入和输出传进去，输入会先被自己清空
               （曾因此把容器名变成空串，SKF_OpenContainer 直接回 0x0B000035）。 */
            if (CanonicalizeContainerName(s->slot, want2, canon, sizeof canon))
                SafeCopy(want2, canon, sizeof want2);
            /* 拼 PKCS#1 RSAPrivateKey：SEQUENCE { ver, n, e, d, p, q, dp, dq, qinv } */
            bl += DerPutInt(body + bl, &ver, 1);
            bl += DerPutInt(body + bl, pMod, lMod);
            bl += DerPutInt(body + bl, lPubE ? pPubE : &ver, lPubE ? lPubE : 1);
            bl += DerPutInt(body + bl, pPrvE, lPrvE);
            if (pP1 && lP1) bl += DerPutInt(body + bl, pP1, lP1);
            if (pP2 && lP2) bl += DerPutInt(body + bl, pP2, lP2);
            if (pE1 && lE1) bl += DerPutInt(body + bl, pE1, lE1);
            if (pE2 && lE2) bl += DerPutInt(body + bl, pE2, lE2);
            if (pC  && lC ) bl += DerPutInt(body + bl, pC,  lC);

            pk = (unsigned char*)LocalAlloc(LPTR, bl + 8);
            if (!pk) { if (phObject) *phObject = 0; return CKR_OK; }
            pk[0] = 0x30;
            { unsigned long k2 = DerPutLen(pk + 1, bl);
              memcpy(pk + 1 + k2, body, bl);
              total = 1 + k2 + bl; }

            rc = g_skf.OpenContainer(g_curApp, want2, &hC2);
            if (rc == (int)SAR_OK && hC2) {
                if (g_skf.ImportRSAKeyPair) {
                    krc = g_skf.ImportRSAKeyPair(hC2, 0, pk, total, NULL, 0);
                    LogLine("C_CreateObject(私钥): SKF_ImportRSAKeyPair('%s', PKCS#1 %lu 字节) -> 0x%08X%s",
                            want2, total, (unsigned)krc,
                            krc == (int)SAR_OK ? "（私钥已写入设备）"
                                               : "（私钥未写入：包裹格式未确认；证书仍继续导入）");
                } else {
                    LogLine("C_CreateObject(私钥): SKF 模块未导出 SKF_ImportRSAKeyPair，跳过");
                }
                if (g_skf.CloseContainer) g_skf.CloseContainer(hC2);
            } else {
                LogLine("C_CreateObject(私钥): 打开容器 '%s' 失败 0x%08X，跳过私钥",
                        want2, (unsigned)rc);
            }
            LocalFree(pk);
        }
        {   /* 无论设备端是否真的写入私钥，PKCS#11 层都必须能看到这个对象——
               上层接下来会回查它，查不到就会中止导入（ErrorCode=0x4）。 */
            CK_OBJECT_HANDLE h = RegisterKeyObject(s->slot, want2, OBJK_PRIVATE_KEY,
                                                   NULL, 0, NULL, 0);
            if (h && GetObj(h)) GetObj(h)->signFlag = signFlag;
            LogLine("C_CreateObject(私钥): 已记账 container='%s' 句柄=%lu（明文私钥不驻留内存）",
                    want2, (unsigned long)h);
            if (phObject) *phObject = h;
        }
        return CKR_OK;      /* 不阻断：证书随后导入 */
    }

    if (cls == CKO_PUBLIC_KEY) {
        /* 厂商 Admin 的导入流程是**两步**：先建「公钥对象」（CKO_PUBLIC_KEY，12 个属性），
           再建「证书对象」（CKO_CERTIFICATE）。此前只认证书对象、把第一步拒了，
           流程就断在这里，界面表现为「权限不足，请重新使用口令登录」。
           本设备 SKF 没有「导入公钥」入口（公钥存在于容器/密钥对内部），
           所以这一步只做**记账**：不动设备，也不声称写入了设备——是否真的落卡，
           以随后的 CKO_CERTIFICATE 写入结果为准。 */
        {
            char want3[128], canon3[128];
            CK_OBJECT_HANDLE h;
            SafeCopy(want3, idBuf[0] ? idBuf : (labelBuf[0] ? labelBuf : ""), sizeof want3);
            if (want3[0] && BindContext(s->slot) == CKR_OK &&
                CanonicalizeContainerName(s->slot, want3, canon3, sizeof canon3))
                SafeCopy(want3, canon3, sizeof want3);
            h = RegisterKeyObject(s->slot, want3, OBJK_PUBLIC_KEY, pMod, lMod, pPubE, lPubE);
            if (h && GetObj(h)) GetObj(h)->signFlag = signFlag;
            LogLine("C_CreateObject: 公钥对象已记账（本设备 SKF 无导入公钥接口，未写设备）"
                    " container='%s' 句柄=%lu", want3, (unsigned long)h);
            if (phObject) *phObject = h;
        }
        return CKR_OK;
    }
    if (cls != (CK_OBJECT_CLASS)-1 && cls != CKO_CERTIFICATE) {
        LogLine("C_CreateObject: 当前只实现证书对象（CKO_CERTIFICATE），class=0x%X 如实拒绝",
                (unsigned)cls);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (!der || derLen == 0) return CKR_ATTRIBUTE_VALUE_INVALID;
    if (!g_skf.ImportCertificate || !g_skf.OpenContainer) return CKR_FUNCTION_NOT_SUPPORTED;
    if (BindContext(s->slot) != CKR_OK) return CKR_DEVICE_ERROR;
    RestoreSecureState(s->slot);

    /* 目标容器：优先 CKA_ID，其次 CKA_LABEL（垫片对外把容器名同时当作这两者返回） */
    SafeCopy(want, idBuf[0] ? idBuf : (labelBuf[0] ? labelBuf : ""), sizeof want);
    if (!want[0]) {
        char canon[128];
        /* 没带容器标识：若设备上只有一个容器就写它，否则如实拒绝，不猜 */
        char list[0x2000];
        unsigned long size = sizeof list;
        int pos = 0, count = 0, only = -1;
        memset(list, 0, sizeof list);
        if (g_skf.EnumContainer && g_skf.EnumContainer(g_curApp, list, &size) == (int)SAR_OK) {
            while (pos < (int)sizeof list) {
                const char* nm = list + pos;
                size_t len = strlen(nm);
                if (len == 0) break;
                count++;
                only = pos;
                pos += (int)len + 1;
            }
        }
        if (count == 1) SafeCopy(canon, list + only, sizeof canon);
        else {
            LogLine("C_CreateObject: 未给出容器标识且设备上容器数为 %d，无法确定写入目标，拒绝",
                    count);
            return CKR_ARGUMENTS_BAD;
        }
        SafeCopy(want, canon, sizeof want);
    }
    {   /* 名字同样可能带残留，先规范化 */
        char canon[128];
        if (CanonicalizeContainerName(s->slot, want, canon, sizeof canon))
            SafeCopy(want, canon, sizeof want);
    }

    rc = g_skf.OpenContainer(g_curApp, want, &hCont);
    if (rc != (int)SAR_OK || !hCont) {
        LogLine("C_CreateObject: SKF_OpenContainer('%s') 失败 0x%08X，证书未写入", want, (unsigned)rc);
        return MapSar((unsigned long)rc);
    }
    /* 先按**上层声明的角色**导入（厂商私有属性 0x80000067：1=签名、0=密钥交互），
       失败再试另一种，并如实记录最终用了哪个。此前固定按「签名」优先，
       上层要导密钥交互证书时会被写错角色。 */
    for (k = 0; k < 2; k++) {
        bSign = k ? (1 - signFlag) : signFlag;
        rc = g_skf.ImportCertificate(hCont, bSign, der, derLen);
        LogLine("C_CreateObject: SKF_ImportCertificate('%s', bSign=%d, len=%lu) -> 0x%08X",
                want, bSign, derLen, (unsigned)rc);
        if (rc == (int)SAR_OK) break;
    }
    if (g_skf.CloseContainer) g_skf.CloseContainer(hCont);

    if (rc != (int)SAR_OK) return MapSar((unsigned long)rc);

    /* 写成功：刷新对象缓存并返回新对象句柄（便于上层继续用） */
    LoadObjects(s->slot);
    if (phObject) {
        *phObject = 0;
        for (k = 0; k < g_objCount; k++) {
            if (g_objs[k].used && strcmp(g_objs[k].container, want) == 0) {
                *phObject = (CK_OBJECT_HANDLE)(k + 1);
                break;
            }
        }
    }
    LogLine("C_CreateObject: 证书已写入容器 '%s'（%lu 字节）", want, derLen);
    return CKR_OK;
}

DECL_C(CK_RV, C_DestroyObject, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject))
{ (void)hSession; (void)hObject; return CKR_FUNCTION_NOT_SUPPORTED; }

DECL_C(CK_RV, C_GetObjectSize, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG* pulSize))
{
    OBJ* o;
    if (!GetSession(hSession)) return CKR_SESSION_HANDLE_INVALID;
    o = GetObj(hObject);
    if (!o) return CKR_OBJECT_HANDLE_INVALID;
    if (pulSize) *pulSize = o->derLen;
    return CKR_OK;
}

DECL_C(CK_RV, C_SetAttributeValue, (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                                    CK_ATTRIBUTE* pTemplate, CK_ULONG ulCount))
{ (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; return CKR_ATTRIBUTE_READ_ONLY; }

DECL_C(CK_RV, C_CopyObject, (CK_SESSION_HANDLE s, CK_OBJECT_HANDLE o, CK_ATTRIBUTE* t, CK_ULONG c, CK_OBJECT_HANDLE* n))
{ (void)s; (void)o; (void)t; (void)c; (void)n; return CKR_FUNCTION_NOT_SUPPORTED; }

/* ---------------- 未实现的密码运算：统一返回「不支持」 ---------------- */

#define STUB1(name)  DECL_C(CK_RV, name, (CK_SESSION_HANDLE a)) { (void)a; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB2(name)  DECL_C(CK_RV, name, (CK_SESSION_HANDLE a, CK_VOID_PTR b)) { (void)a; (void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB4(name)  DECL_C(CK_RV, name, (CK_SESSION_HANDLE a, CK_VOID_PTR b, CK_ULONG c, CK_VOID_PTR d)) { (void)a; (void)b; (void)c; (void)d; return CKR_FUNCTION_NOT_SUPPORTED; }

DECL_C(CK_RV, C_GetOperationState, (CK_SESSION_HANDLE a, CK_BYTE* b, CK_ULONG* c)) { (void)a; (void)b; (void)c; return CKR_FUNCTION_NOT_SUPPORTED; }
DECL_C(CK_RV, C_SetOperationState, (CK_SESSION_HANDLE a, CK_BYTE* b, CK_ULONG c, CK_OBJECT_HANDLE d, CK_OBJECT_HANDLE e)) { (void)a; (void)b; (void)c; (void)d; (void)e; return CKR_FUNCTION_NOT_SUPPORTED; }
STUB4(C_EncryptInit)
STUB4(C_Encrypt)
STUB4(C_EncryptUpdate)
STUB2(C_EncryptFinal)
STUB4(C_DecryptInit)
STUB4(C_Decrypt)
STUB4(C_DecryptUpdate)
STUB2(C_DecryptFinal)
STUB4(C_DigestInit)
STUB4(C_Digest)
STUB4(C_DigestUpdate)
STUB4(C_DigestKey)
STUB2(C_DigestFinal)
STUB4(C_SignInit)
STUB4(C_Sign)
STUB4(C_SignUpdate)
STUB2(C_SignFinal)
STUB4(C_SignRecoverInit)
STUB4(C_SignRecover)
STUB4(C_VerifyInit)
STUB4(C_Verify)
STUB4(C_VerifyUpdate)
STUB2(C_VerifyFinal)
STUB4(C_VerifyRecoverInit)
STUB4(C_VerifyRecover)
STUB4(C_DigestEncryptUpdate)
STUB4(C_DecryptDigestUpdate)
STUB4(C_SignEncryptUpdate)
STUB4(C_DecryptVerifyUpdate)
STUB4(C_GenerateKey)
STUB4(C_GenerateKeyPair)
STUB4(C_WrapKey)
STUB4(C_UnwrapKey)
STUB4(C_DeriveKey)
STUB1(C_GetFunctionStatus)
STUB1(C_CancelFunction)

/* ================================================================ M_* 实现（扩展表）

   说明：这些函数由 TokenMgr 经 M_GetExtFunctionList 返回的表调用，参数个数取决于调用点。
   统一声明为 cdecl 且最多读 4 个参数（多收到的栈参数不读取即无害）；未实现者明确返回
   CKR_FUNCTION_NOT_SUPPORTED。TokenMgr 在初始化路径忽略其返回值（反汇编确认），
   因此不会因「不支持」而中断绑定。

   下表下标与厂商 2016 版实测表序严格一致，每项都会写调试日志
   （<DLL 同目录>\gm3000_shim.log），便于在无界面环境下核对上层真实调用了什么。  */

static M_EXT_TABLE g_ext;

/* ---------------------------------------------------------------- M_* 调用约定（反汇编更正）

   厂商扩展函数的真实约定（由 gm3000_pkcs11.dll 2016 版**导出层**逐条反汇编确认）：
     · 全部是**纯 cdecl**：参数都在栈上、被调用者不清理（以 `ret` 返回），由上层清理。
       —— 早期报告里「第 1 参数走 ecx」的结论有误：那是把 RVA 0x2B40 当成了
       M_GetUserInfo，而 0x2B40 实际是 M_GetFileInfo（M_GetUserInfo = 0x2770）。
     · M_GetApplicationInfo(handle, char out[64], p3..p7)  ← 7 参
       把 64 字节应用名写入第 2 个参数（内部 `memcpy(out, appObj+0x104, 64)`）。
     · M_GetUserInfo(handle, pinType, M_PIN_STATE* out)    ← 3 参
       pinType 1 = 管理员(SO)、0 = 用户，与 SKF_GetPINInfo 的 ulPINType 一致。 */

/* 厂商 M_GetUserInfo 的出参结构（由 gm3000_pkcs11.dll!0x1000B020 反汇编确认，共 12 字节）：
     +0x00 ULONG 剩余重试次数
     +0x04 ULONG 最大重试次数
     +0x08 BYTE  1 = 口令已被使用/修改过（剩余 < 上限）
     +0x09 BYTE  1 = 仅剩最后一次机会
     +0x0a BYTE  1 = 已锁定（剩余 = 0）
     +0x0b BYTE  1 = 口令仍为出厂默认值
   TokenMgr 的 token_get_pin_state 正是把这 12 字节拆成 6 个出参
   （前 2 个按 DWORD 取，后 4 个各按字节取），Admin 据此显示「剩余重试次数 / 是否锁定」。 */
typedef struct {
    unsigned long remain;
    unsigned long maxRetry;
    unsigned char used;
    unsigned char lastOne;
    unsigned char locked;
    unsigned char isDefault;
} M_PIN_STATE;

/* 出参指针保护：上层传进来的缓冲区若不可写，宁可返回错误，也不能写坏它的栈。 */
static int IsWritablePtr(const void* p, unsigned long need)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned long off;
    if (!p) return 0;
    if (VirtualQuery(p, &mbi, sizeof mbi) != sizeof mbi) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return 0;
    off = (unsigned long)((const char*)p - (const char*)mbi.BaseAddress);
    if ((unsigned long long)off + need > mbi.RegionSize) return 0;
    return 1;
}

/* 只读可读性校验（用于上层传入的入参字符串） */
static int IsReadablePtr(const void* p, unsigned long need)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned long off;
    if (!p) return 0;
    if (VirtualQuery(p, &mbi, sizeof mbi) != sizeof mbi) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return 0;
    off = (unsigned long)((const char*)p - (const char*)mbi.BaseAddress);
    if ((unsigned long long)off + need > mbi.RegionSize) return 0;
    return 1;
}

/* 安全读取上层传入的名字/标签（逐字节校验，绝不跨页读取；仅供参数校验与日志使用）。
   只接受**可打印 ASCII**（0x20..0x7E），遇到第一个其它字节即视为结束：
   本设备与这条工具链里的容器名、文件名、标签都是 ASCII，而上层缓冲区在名字之后
   往往紧跟别的内存内容（且每次调用内容不同）——按 NUL 取名会把这些残留算进名字，
   于是「建文件」与「写文件」用了两个不同的名字，设备只回 SAR_FILE_NOT_EXIST(0x0A000031)；
   删除容器时则回 SAR_INDATALENERR(0x0A000010)。截断情况由调用方日志体现，不做静默处理。 */
static void CopyStr(const void* p, char* out, unsigned long cap)
{
    unsigned long i;
    if (!out || cap == 0) return;
    memset(out, 0, cap);            /* 先整体清零：任何提前退出路径都不会留下未初始化的尾巴 */
    if (!p) return;
    for (i = 0; i + 1 < cap; i++) {
        char c;
        if (!IsReadablePtr((const char*)p + i, 1)) break;
        c = ((const char*)p)[i];
        /* NUL 或非可打印 → 名字到此为止。
           ⚠ 这里必须**先写终止符再 return**：此前直接 return 会让 out[i] 保持未初始化，
           于是传出去的名字后面挂着**栈上残留**（每次调用还不一样），
           造成「建文件」与「写文件」用的名字不同 → 设备回 SAR_FILE_NOT_EXIST(0x0A000031)，
           删除容器则回 SAR_INDATALENERR(0x0A000010)。`memset` 已兜底，此处再写一次更直白。 */
        if (c < 0x20 || (unsigned char)c > 0x7e) { out[i] = 0; return; }
        out[i] = c;
    }
    out[i] = 0;
}

/* 按显式长度安全拷贝成 C 字符串（属性值这类「长度给定」的入参用）。
   与 CopyStr 同样的口径：只取前导可打印 ASCII，遇到非可打印字节即截断——
   容器名/标签是 ASCII，而属性值尾部可能含填充或其它内容。 */
static void CopyBytes(const void* p, unsigned long len, char* out, unsigned long cap)
{
    unsigned long i, n;
    if (!out || cap == 0) return;
    out[0] = 0;
    if (!p || len == 0) return;
    if (!IsReadablePtr(p, len)) return;
    n = (len < cap - 1) ? len : cap - 1;
    for (i = 0; i < n; i++) {
        char c = ((const char*)p)[i];
        if (c < 0x20 || (unsigned char)c > 0x7e) break;
        out[i] = c;
    }
    out[i] = 0;
}

/* 用设备上**真实存在**的容器名对上层传入的名字做规范化：
   取「入参以该名字为前缀」中最长者（避免同名前缀误删）。找不到则返回 0，原样保留入参。
   为什么要这一步：上层缓冲区里的容器名不保证以 NUL 结尾（后面可能紧跟其它文本），
   直接按 strlen 读会把后缀一起送给设备，设备随即回 SAR_INDATALENERR(0x0A000010)。 */
static int CanonicalizeContainerName(int slot, const char* passed, char* out, unsigned long cap)
{
    char list[0x2000];
    unsigned long size = sizeof list;
    int pos = 0, best = -1;
    unsigned long bestLen = 0, passedLen;
    if (!passed || !out || cap == 0) return 0;
    out[0] = 0;
    if (!g_skf.EnumContainer) return 0;
    if (BindContext(slot) != CKR_OK || !g_curApp) return 0;
    memset(list, 0, sizeof list);
    if (g_skf.EnumContainer(g_curApp, list, &size) != (int)SAR_OK) return 0;
    while (pos < (int)sizeof list) {
        const char* nm = list + pos;
        size_t len = strlen(nm);
        if (len == 0) break;
        if ((unsigned long)len > bestLen && strncmp(passed, nm, len) == 0) {
            best = pos;
            bestLen = (unsigned long)len;
        }
        pos += (int)len + 1;
    }
    if (best < 0) return 0;
    SafeCopy(out, list + best, cap);
    passedLen = (unsigned long)strlen(passed);
    if (passedLen != bestLen)
        LogLine("  [容器名] 入参带了 %lu 字节残留，已规范化为设备上的真实容器名 '%s'",
                passedLen - bestLen, out);
    return 1;
}

/* 上层给的句柄通常是槽位下标；越界时退回当前已绑定槽位，避免认错设备。 */
static int ResolveSlot(CK_VOID_PTR h)
{
    int slot = (int)(ULONG_PTR)h;
    if (slot >= 0 && slot < g_devCount) return slot;
    if (g_curSlot >= 0 && g_curSlot < g_devCount) return g_curSlot;
    return 0;
}

/* 取真实口令状态。实机实测（tools\GM3000Probe skfpin）确认签名与语义：
     SKF_GetPINInfo(应用句柄, ulPINType, &上限, &剩余, &是否默认口令)
     · 出参顺序是 (最大, 剩余)——仍用 min/max 归一，兼容厂商其他版本可能调换顺序；
     · 第 3 个出参是「是否为出厂默认口令」，不是「PIN 是否已初始化」；
     · ulPINType：0 = 管理员(SO)、1 = 用户（与 VerifyPIN / M_GetUserInfo 一致）。 */
static int QueryPinState(int slot, unsigned long pinType, M_PIN_STATE* st)
{
    unsigned long a = 0, b = 0, isDefault = 0;
    unsigned long remain, maxRetry;

    memset(st, 0, sizeof *st);
    if (!g_skf.GetPINInfo) return 0;
    if (BindContext(slot) != CKR_OK || !g_curApp) return 0;
    if (g_skf.GetPINInfo(g_curApp, pinType, &a, &b, &isDefault) != (int)SAR_OK) {
        LogLine("QueryPinState(slot=%d, pinType=%lu) SKF_GetPINInfo failed", slot, pinType);
        return 0;
    }
    remain   = (a < b) ? a : b;
    maxRetry = (a < b) ? b : a;
    if (maxRetry == 0) {
        /* 上限为 0 说明设备没给出有效值：如实报告「未知」，绝不臆断为已锁定 */
        LogLine("QueryPinState(slot=%d, pinType=%lu) 上限为 0（raw=%lu/%lu），按未知处理",
                slot, pinType, a, b);
        return 0;
    }
    st->remain    = remain;
    st->maxRetry  = maxRetry;
    st->isDefault = isDefault ? 1 : 0;
    st->used      = (remain < maxRetry) ? 1 : 0;
    st->lastOne   = (remain == 1) ? 1 : 0;
    st->locked    = (remain == 0) ? 1 : 0;
    LogLine("QueryPinState(slot=%d, pinType=%lu) raw=%lu/%lu -> 剩余=%lu 上限=%lu 默认=%u",
            slot, pinType, a, b, st->remain, st->maxRetry, st->isDefault);
    return 1;
}

/* 清空「当前应用」下的全部容器（初始化流程的核心动作）。
   返回成功删除的容器数，失败数写入 *failed。 */
static int WipeAllContainers(int* failed)
{
    char list[0x2000];
    unsigned long size;
    int pos, ok = 0;

    *failed = 0;
    if (!g_curApp || !g_skf.EnumContainer || !g_skf.DeleteContainer) return 0;

    memset(list, 0, sizeof list);
    size = (unsigned long)sizeof list;
    if (g_skf.EnumContainer(g_curApp, list, &size) != (int)SAR_OK) {
        LogLine("  WipeAllContainers: SKF_EnumContainer 失败");
        return 0;
    }
    pos = 0;
    while (pos < (int)sizeof list) {
        const char* nm = list + pos;
        size_t len = strlen(nm);
        if (len == 0) break;
        if (g_skf.DeleteContainer(g_curApp, nm) == (int)SAR_OK) {
            ok++;
            LogLine("    删除容器 '%s' 完成", nm);
        } else {
            (*failed)++;
            LogLine("    删除容器 '%s' 失败", nm);
        }
        pos += (int)len + 1;
    }
    return ok;
}

/* 扩展表语义分派（按下标）：
   0  = M_GetUserInfo         —— 口令状态（Admin「剩余重试次数 / 是否锁定」的数据源）
   1  = M_GetExtFunctionList  —— 必须实现，TokenMgr 绑定用
   4  = M_FormatToken         —— 令牌初始化（清空设备内容）；TokenMgr 的 token_format 第一步
   11 = M_ReloadObjects       —— 刷新缓存
   17 = M_GetApplicationInfo  —— 应用名（64 字节），TokenMgr 打开应用时索取
   其余暂返回「不支持」，并记录日志以便后续按真实调用补齐。 */
static CK_RV M_Dispatch(int index, CK_VOID_PTR a1, CK_VOID_PTR a2, CK_ULONG a3, CK_VOID_PTR a4,
                        CK_VOID_PTR a5, CK_VOID_PTR a6)
{
    (void)a6;
    switch (index) {
    case 1:
        if (a1) *(CK_VOID_PTR*)a1 = &g_ext;
        return CKR_OK;

    case 11:
        /* 只清我方的对象缓存。
           ⚠ 绝不能在这里 RefreshDevices()：它会先 UnbindContext()（关闭应用 + 断开设备），
           而 SKF 的「口令已验证」安全状态挂在**应用句柄**上。导入证书的调用顺序正是
           Login(用户) → ReloadObjects → 枚举容器 → CreateContainer，
           一旦此处解绑，建容器只会拿到 SAR_USER_NOT_LOGGED_IN(0x0A00002D)，
           表现为导入失败（ErrorCode=0x54/0x101）。 */
        FreeObjects();
        g_devDirty = 1;
        return CKR_OK;

    case 4: {                       /* M_FormatToken(handle, arg2) —— 令牌初始化 */
        int slot = ResolveSlot(a1);
        int failed = 0, removed;

        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;

        /* 等价实现（本设备 SKF 侧没有格式化入口，见 §八/§九 的能力边界）：
           清空当前应用下全部容器（证书随容器一起消失）；随后 TokenMgr 会再调
           C_InitPIN 把用户口令设成上层填的新口令、并 C_Logout 收尾。
           这里不触碰口令，避免与 C_InitPIN 重复消耗重试次数。 */
        removed = WipeAllContainers(&failed);
        LogLine("M_FormatToken(slot=%d, arg2=0x%08X) -> 已清空容器 %d 个（失败 %d 个）",
                slot, (unsigned)(ULONG_PTR)a2, removed, failed);
        FreeObjects();
        g_devDirty = 1;
        return CKR_OK;
    }

    case 0: {                       /* M_GetUserInfo(handle, pinType, M_PIN_STATE* out) */
        int slot = ResolveSlot(a1);
        unsigned long pinType = (unsigned long)a2;
        M_PIN_STATE st;
        CK_VOID_PTR out = (CK_VOID_PTR)(ULONG_PTR)a3;

        if (!IsWritablePtr(out, sizeof st)) {
            LogLine("M_GetUserInfo(pinType=%lu) 出参不可写（0x%08X），拒绝写入",
                    pinType, (unsigned)(ULONG_PTR)out);
            return CKR_ARGUMENTS_BAD;
        }
        if (!QueryPinState(slot, pinType, &st)) return CKR_DEVICE_ERROR;
        memcpy(out, &st, sizeof st);
        LogLine("M_GetUserInfo(pinType=%lu) -> 剩余=%lu 上限=%lu 已用过=%u 仅剩1次=%u 已锁定=%u 默认=%u",
                pinType, st.remain, st.maxRetry, st.used, st.lastOne, st.locked, st.isDefault);
        return CKR_OK;
    }

    case 17: {                      /* M_GetApplicationInfo(handle, char out[64], p3..p7) */
        int slot = ResolveSlot(a1);
        if (!IsWritablePtr(a2, 64)) {
            LogLine("M_GetApplicationInfo 出参不可写（0x%08X），拒绝写入",
                    (unsigned)(ULONG_PTR)a2);
            return CKR_ARGUMENTS_BAD;
        }
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        memset(a2, 0, 64);
        SafeCopy((char*)a2, g_devs[slot].app[0] ? g_devs[slot].app : "GM3000APP", 64);
        LogLine("M_GetApplicationInfo(slot=%d) -> '%s'", slot, (char*)a2);
        return CKR_OK;
    }

    case 3: {                       /* M_SetTokenLabel(handle, const char* label) —— 2 参
                                       （2.2.19 导出层 0x1210 → 核心 0x52F0，与 SKF_SetLabel 一一对应） */
        int slot = ResolveSlot(a1);
        char label[64];
        int rc;
        CopyStr(a2, label, sizeof label);
        if (!label[0]) {
            LogLine("M_SetTokenLabel: 标签为空，拒绝");
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.SetLabel) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        rc = g_skf.SetLabel(g_curDev, label);           /* SKF_SetLabel(hDev, szLabel) */
        /* 名称写入的是 DEVINFO+0x82；立刻重读快照，保证随后的 C_GetTokenInfo 报出新名，
           否则上层会以为「修改失败」。 */
        if (rc == (int)SAR_OK) RefreshDeviceSnapshot(slot);
        LogLine("M_SetTokenLabel(slot=%d, '%s') -> 0x%08X", slot, label, (unsigned)rc);
        return MapSar(rc);
    }

    case 5: {                       /* M_CreateContainer(handle, const char* name) —— 2 参
                                       （2.2.19 0x1290 → 核心 0x53E0 → 0x10600，与 SKF_CreateContainer 对应） */
        int slot = ResolveSlot(a1);
        char name[128];
        void* hCont = NULL;
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) {
            LogLine("M_CreateContainer: 容器名为空，拒绝");
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.CreateContainer) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        RestoreSecureState(slot);       /* 上层调用链可能已破坏已验证状态，先用缓存口令恢复 */
        rc = g_skf.CreateContainer(g_curApp, name, &hCont);
        if (rc == (int)SAR_USER_NOT_LOGGED_IN) {
            /* 设备要的是另一种角色（实测：建容器要求**用户**角色）——换个缓存口令再试一次 */
            RestoreSecureStateOtherRole(slot);
            rc = g_skf.CreateContainer(g_curApp, name, &hCont);
        }
        if (rc == (int)SAR_OK && hCont && g_skf.CloseContainer) g_skf.CloseContainer(hCont);
        if (rc == (int)SAR_OK) { FreeObjects(); g_devDirty = 1; }
        LogLine("M_CreateContainer(slot=%d, '%s') -> 0x%08X%s", slot, name, (unsigned)rc,
                rc == (int)SAR_OK ? "（容器已建）" : "");
        return MapSar(rc);
    }

    case 6: {                       /* M_DeleteContainer(handle, const char* name) —— 2 参 */
        int slot = ResolveSlot(a1);
        char name[128];
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) return CKR_ARGUMENTS_BAD;
        if (!g_skf.DeleteContainer) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        /* 上层传来的名字可能不是独立 NUL 结尾的字符串（其缓冲区后面紧跟别的文本），
           用设备上真实存在的容器名做一次规范化，避免设备以「输入数据长度错误」拒绝。 */
        { char canon[128];
          if (CanonicalizeContainerName(slot, name, canon, sizeof canon)) SafeCopy(name, canon, sizeof name); }
        RestoreSecureState(slot);
        rc = g_skf.DeleteContainer(g_curApp, name);     /* SKF_DeleteContainer(hApp, szName) */
        if (rc == (int)SAR_USER_NOT_LOGGED_IN) {
            RestoreSecureStateOtherRole(slot);
            rc = g_skf.DeleteContainer(g_curApp, name);
        }
        if (rc == (int)SAR_OK) { FreeObjects(); g_devDirty = 1; }
        LogLine("M_DeleteContainer(slot=%d, '%s') -> 0x%08X", slot, name, (unsigned)rc);
        return MapSar(rc);
    }

    case 7: {                       /* M_EnumContainer(handle, char* nameList, ULONG* pulSize) —— 3 参
                                       （2.2.19 0x1310 → 0x54E0 → 0x108F0；该 worker 就是
                                         「把各容器名首尾相接写入缓冲、并把总长度回写出参」，
                                         与 SKF_EnumContainer 完全同构，缓冲不足同样返回 0x21） */
        int slot = ResolveSlot(a1);
        unsigned long* pSize = (unsigned long*)a3;
        unsigned long cap;
        int rc;
        if (!IsWritablePtr(pSize, sizeof *pSize)) {
            LogLine("M_EnumContainer: 长度出参不可写（0x%08X），拒绝",
                    (unsigned)(ULONG_PTR)pSize);
            return CKR_ARGUMENTS_BAD;
        }
        cap = *pSize;
        if (a2 && cap && !IsWritablePtr(a2, cap)) {
            LogLine("M_EnumContainer: 名称缓冲不可写（0x%08X, cap=%lu），拒绝",
                    (unsigned)(ULONG_PTR)a2, cap);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.EnumContainer) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        rc = g_skf.EnumContainer(g_curApp, (char*)a2, pSize);
        LogLine("M_EnumContainer(slot=%d, cap=%lu) -> 0x%08X 实际=%lu",
                slot, cap, (unsigned)rc, *pSize);
        /* 缓冲不足时按**厂商约定**回 0x21：厂商 worker（2.2.19 rva 0x108F0）在
           「累计长度 > 出参缓冲」时正是 `mov eax,0x21; ret`，TokenMgr 是按这套内部码写的，
           回 PKCS#11 的 CKR_BUFFER_TOO_SMALL(0x150) 会让它认不出「需要更大缓冲」。 */
        if (rc == (int)SAR_BUFFER_TOO_SMALL) return (CK_RV)0x21;
        return MapSar(rc);
    }

    case 20: {                      /* M_ForceLogout(handle) —— 1 参（2.2.19 新增 0x1720 → 0xCCE0）
                                       导入流程开头会先强制登出，再 C_Login(CKU_SO)。
                                       本设备 SKF 侧没有 logout 入口，等价实现是
                                       SKF_ClearSecureState（与 C_Logout 一致），并清会话登录态。 */
        int slot = ResolveSlot(a1);
        int i;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        if (g_skf.ClearSecureState && g_curApp) g_skf.ClearSecureState(g_curApp);
        for (i = 0; i < MAX_SESS; i++) g_sess[i].loggedUser = 0;
        ForgetSecureState();
        LogLine("M_ForceLogout(slot=%d) -> 已清除登录态（SKF_ClearSecureState）；"
                "口令缓存保留，供导入流程重新登录后恢复特权操作", slot);
        return CKR_OK;
    }

    case 9:  /* M_WriteSectors(handle, startSector, sectorCount, buf) —— 4 参（下载 ISO 用）
                SKF（GM/T 0016）没有扇区接口，但厂商实现走的帧是可复刻的：
                  导出层 2.2.19 rva 0x13B0 → 0x55F0 → 0x344B0，其中
                    shl eax,0xb   ⇒ **每扇区 2048 字节**（CD 扇区）
                    push 0x2a     ⇒ 设备命令码 **0x2A（写）/ 0x28（读）**
                  帧构造 0x5D1B0（写）/ 0x5D280（读）把参数摊成 16 字节头：
                    byte[0]    = 命令码
                    byte[1..4] = startSector（4 字节**大端**）
                    byte[5..6] = sectorCount（2 字节**大端**）
                    byte[7..15]= 0
                  随后以「(上下文, 头, 16, 负载, 负载长度)」发出——与
                  `SKF_Transmit(hDev, pbCommand, ulCommandLen, pbData, pulDataLen)` 完全同形，
                  于是用 SKF 的透传口把同一帧送下去。 */
        goto write_sectors;

    case 10: /* M_ReadSectors(handle, startSector, sectorCount, buf) —— 4 参，命令码 0x28 */
        goto read_sectors;

    write_sectors:
    {
        int slot = ResolveSlot(a1);
        unsigned long start = (unsigned long)(ULONG_PTR)a2;
        unsigned long count = (unsigned long)(ULONG_PTR)a3;
        unsigned long long bytes = (unsigned long long)count * 2048ULL;
        unsigned char hdr[16];
        unsigned long len;
        int rc;
        if (count == 0 || bytes > 0x800000ULL) {         /* 上限 8 MB：只拦明显异常的值，能否写下由设备决定 */
            LogLine("M_WriteSectors: 扇区数异常 count=%lu → 拒绝", count);
            return CKR_ARGUMENTS_BAD;
        }
        if (!IsReadablePtr(a4, (unsigned long)bytes)) {
            LogLine("M_WriteSectors: 数据缓冲不可读（0x%08X, %lu 字节）→ 拒绝",
                    (unsigned)(ULONG_PTR)a4, (unsigned long)bytes);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.Transmit) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        memset(hdr, 0, sizeof hdr);
        hdr[0] = 0x2A;
        hdr[1] = (unsigned char)(start >> 24);
        hdr[2] = (unsigned char)(start >> 16);
        hdr[3] = (unsigned char)(start >> 8);
        hdr[4] = (unsigned char)start;
        hdr[5] = (unsigned char)(count >> 8);
        hdr[6] = (unsigned char)count;
        len = (unsigned long)bytes;
        rc = g_skf.Transmit(g_curDev, hdr, sizeof hdr, (unsigned char*)a4, &len);
        LogLine("M_WriteSectors(slot=%d, start=%lu, count=%lu, %lu 字节) -> 0x%08X",
                slot, start, count, (unsigned long)bytes, (unsigned)rc);
        return MapSar(rc);
    }

    read_sectors:
    {
        int slot = ResolveSlot(a1);
        unsigned long start = (unsigned long)(ULONG_PTR)a2;
        unsigned long count = (unsigned long)(ULONG_PTR)a3;
        unsigned long long bytes = (unsigned long long)count * 2048ULL;
        unsigned char hdr[16];
        unsigned long len;
        int rc;
        if (count == 0 || bytes > 0x800000ULL) {
            LogLine("M_ReadSectors: 扇区数异常 count=%lu → 拒绝", count);
            return CKR_ARGUMENTS_BAD;
        }
        if (!IsWritablePtr(a4, (unsigned long)bytes)) {
            LogLine("M_ReadSectors: 缓冲不可写（0x%08X, %lu 字节）→ 拒绝",
                    (unsigned)(ULONG_PTR)a4, (unsigned long)bytes);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.Transmit) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        memset(hdr, 0, sizeof hdr);
        hdr[0] = 0x28;
        hdr[1] = (unsigned char)(start >> 24);
        hdr[2] = (unsigned char)(start >> 16);
        hdr[3] = (unsigned char)(start >> 8);
        hdr[4] = (unsigned char)start;
        hdr[5] = (unsigned char)(count >> 8);
        hdr[6] = (unsigned char)count;
        len = (unsigned long)bytes;
        rc = g_skf.Transmit(g_curDev, hdr, sizeof hdr, (unsigned char*)a4, &len);
        LogLine("M_ReadSectors(slot=%d, start=%lu, count=%lu) -> 0x%08X 实际=%lu",
                slot, start, count, (unsigned)rc, len);
        return MapSar(rc);
    }

    case 12: {                      /* M_CreateFile(handle, name, size, readRights, writeRights) —— 5 参
                                       （2.2.19 导出层 0x1580 → 核心 0x5AA0 → worker 0x37D80；
                                       与 SKF_CreateFile 的 5 个参数逐一对应） */
        int slot = ResolveSlot(a1);
        char name[128];
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) {
            LogLine("M_CreateFile: 文件名为空，拒绝");
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.CreateFile) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        RestoreSecureState(slot);
        rc = g_skf.CreateFile(g_curApp, name, (unsigned long)a3,
                              (unsigned long)(ULONG_PTR)a4, (unsigned long)(ULONG_PTR)a5);
        if (rc == (int)SAR_USER_NOT_LOGGED_IN) {
            RestoreSecureStateOtherRole(slot);
            rc = g_skf.CreateFile(g_curApp, name, (unsigned long)a3,
                                  (unsigned long)(ULONG_PTR)a4, (unsigned long)(ULONG_PTR)a5);
        }
        g_devDirty = 1;
        LogLine("M_CreateFile(slot=%d, '%s', size=%lu, rd=%lu, wr=%lu) -> 0x%08X",
                slot, name, (unsigned long)a3, (unsigned long)(ULONG_PTR)a4,
                (unsigned long)(ULONG_PTR)a5, (unsigned)rc);
        return MapSar(rc);
    }

    case 13: {                      /* M_DeleteFile(handle, name) —— 2 参 */
        int slot = ResolveSlot(a1);
        char name[128];
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) return CKR_ARGUMENTS_BAD;
        if (!g_skf.DeleteFile) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        rc = g_skf.DeleteFile(g_curApp, name);
        LogLine("M_DeleteFile(slot=%d, '%s') -> 0x%08X", slot, name, (unsigned)rc);
        return MapSar(rc);
    }

    case 14: {                      /* M_WriteFile(handle, name, offset, data, size) —— 5 参
                                       （0x1490 → 0x58E0 → worker 0x38520；与 SKF_WriteFile 一致） */
        int slot = ResolveSlot(a1);
        char name[128];
        unsigned long off = (unsigned long)a3;
        const unsigned char* data = (const unsigned char*)a4;
        unsigned long size = (unsigned long)(ULONG_PTR)a5;
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) return CKR_ARGUMENTS_BAD;
        if (size && !IsReadablePtr(data, size)) {
            LogLine("M_WriteFile: 数据指针不可读（0x%08X, size=%lu），拒绝",
                    (unsigned)(ULONG_PTR)data, size);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.WriteFile) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        RestoreSecureState(slot);
        rc = g_skf.WriteFile(g_curApp, name, off, data, size);
        if (rc == (int)SAR_USER_NOT_LOGGED_IN) {
            RestoreSecureStateOtherRole(slot);
            rc = g_skf.WriteFile(g_curApp, name, off, data, size);
        }
        LogLine("M_WriteFile(slot=%d, '%s', off=%lu, size=%lu) -> 0x%08X",
                slot, name, off, size, (unsigned)rc);
        return MapSar(rc);
    }

    case 15: {                      /* M_ReadFile(handle, name, offset, size, out, outLen) —— 6 参
                                       （0x14E0 → 0x5980；与 SKF_ReadFile 一致） */
        int slot = ResolveSlot(a1);
        char name[128];
        unsigned long off = (unsigned long)a3;
        unsigned long size = (unsigned long)(ULONG_PTR)a4;
        unsigned char* out = (unsigned char*)a5;
        unsigned long* outLen = (unsigned long*)a6;
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) return CKR_ARGUMENTS_BAD;
        if (!outLen || !IsWritablePtr(outLen, sizeof *outLen)) {
            LogLine("M_ReadFile: 长度出参不可写（0x%08X），拒绝", (unsigned)(ULONG_PTR)outLen);
            return CKR_ARGUMENTS_BAD;
        }
        if (!out || !IsWritablePtr(out, *outLen)) {
            LogLine("M_ReadFile: 数据出参不可写（0x%08X, cap=%lu），拒绝",
                    (unsigned)(ULONG_PTR)out, *outLen);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.ReadFile) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        rc = g_skf.ReadFile(g_curApp, name, off, size, out, outLen);
        LogLine("M_ReadFile(slot=%d, '%s', off=%lu, size=%lu) -> 0x%08X 实际=%lu",
                slot, name, off, size, (unsigned)rc, *outLen);
        return MapSar(rc);
    }

    case 16: {                      /* M_GetFileInfo(handle, name, FILEATTRIBUTE* out) —— 3 参 */
        int slot = ResolveSlot(a1);
        char name[128];
        int rc;
        CopyStr(a2, name, sizeof name);
        if (!name[0]) return CKR_ARGUMENTS_BAD;
        if (!IsWritablePtr((const void*)(ULONG_PTR)a3, 16)) {
            LogLine("M_GetFileInfo: 出参不可写（0x%08X），拒绝", (unsigned)a3);
            return CKR_ARGUMENTS_BAD;
        }
        if (!g_skf.GetFileInfo) return CKR_FUNCTION_NOT_SUPPORTED;
        if (BindContext(slot) != CKR_OK) return CKR_DEVICE_ERROR;
        rc = g_skf.GetFileInfo(g_curApp, name, (void*)(ULONG_PTR)a3);
        LogLine("M_GetFileInfo(slot=%d, '%s') -> 0x%08X", slot, name, (unsigned)rc);
        return MapSar(rc);
    }

    default:
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
}

#define DEF_M_SLOT(idx)                                                              \
    static CK_RV __cdecl M_Slot##idx(CK_VOID_PTR a1, CK_VOID_PTR a2, CK_ULONG a3, CK_VOID_PTR a4, \
                                     CK_VOID_PTR a5, CK_VOID_PTR a6)                 \
    {                                                                                \
        CK_RV rv = M_Dispatch(idx, a1, a2, a3, a4, a5, a6);                          \
        LogLine("M_slot[%2d] @%08X a1=%08X a2=%08X a3=%lu a4=%08X -> 0x%08X",        \
                idx, (unsigned)(ULONG_PTR)_ReturnAddress(),                          \
                (unsigned)(ULONG_PTR)a1, (unsigned)(ULONG_PTR)a2, a3,                \
                (unsigned)(ULONG_PTR)a4, (unsigned)rv);                              \
        return rv;                                                                   \
    }

DEF_M_SLOT(0)  DEF_M_SLOT(1)  DEF_M_SLOT(2)  DEF_M_SLOT(3)  DEF_M_SLOT(4)
DEF_M_SLOT(5)  DEF_M_SLOT(6)  DEF_M_SLOT(7)  DEF_M_SLOT(8)  DEF_M_SLOT(9)
DEF_M_SLOT(10) DEF_M_SLOT(11) DEF_M_SLOT(12) DEF_M_SLOT(13) DEF_M_SLOT(14)
DEF_M_SLOT(15) DEF_M_SLOT(16) DEF_M_SLOT(17) DEF_M_SLOT(18) DEF_M_SLOT(19)
DEF_M_SLOT(20) DEF_M_SLOT(21) DEF_M_SLOT(22) DEF_M_SLOT(23) DEF_M_SLOT(24)

/* ================================================================ 两张函数表 */

static CK_FUNCTION_LIST g_fnList;

static void InitFunctionTable(void)
{
    int i;
    for (i = 0; i < 68; i++) g_fnList.fn[i] = (CK_VOID_PTR)C_Unsupported;  /* 先全部填安全桩 */

    g_fnList.version.major = 2;
    g_fnList.version.minor = 20;

    g_fnList.fn[0]  = (CK_VOID_PTR)C_Initialize;
    g_fnList.fn[1]  = (CK_VOID_PTR)C_Finalize;
    g_fnList.fn[2]  = (CK_VOID_PTR)C_GetInfo;
    g_fnList.fn[3]  = (CK_VOID_PTR)C_GetFunctionList;
    g_fnList.fn[4]  = (CK_VOID_PTR)C_GetSlotList;
    g_fnList.fn[5]  = (CK_VOID_PTR)C_GetSlotInfo;
    g_fnList.fn[6]  = (CK_VOID_PTR)C_GetTokenInfo;
    g_fnList.fn[7]  = (CK_VOID_PTR)C_GetMechanismList;
    g_fnList.fn[8]  = (CK_VOID_PTR)C_GetMechanismInfo;
    g_fnList.fn[9]  = (CK_VOID_PTR)C_InitToken;
    g_fnList.fn[10] = (CK_VOID_PTR)C_InitPIN;
    g_fnList.fn[11] = (CK_VOID_PTR)C_SetPIN;
    g_fnList.fn[12] = (CK_VOID_PTR)C_OpenSession;
    g_fnList.fn[13] = (CK_VOID_PTR)C_CloseSession;
    g_fnList.fn[14] = (CK_VOID_PTR)C_CloseAllSessions;
    g_fnList.fn[15] = (CK_VOID_PTR)C_GetSessionInfo;
    g_fnList.fn[16] = (CK_VOID_PTR)C_GetOperationState;
    g_fnList.fn[17] = (CK_VOID_PTR)C_SetOperationState;
    g_fnList.fn[18] = (CK_VOID_PTR)C_Login;
    g_fnList.fn[19] = (CK_VOID_PTR)C_Logout;
    g_fnList.fn[20] = (CK_VOID_PTR)C_CreateObject;
    g_fnList.fn[21] = (CK_VOID_PTR)C_CopyObject;
    g_fnList.fn[22] = (CK_VOID_PTR)C_DestroyObject;
    g_fnList.fn[23] = (CK_VOID_PTR)C_GetObjectSize;
    g_fnList.fn[24] = (CK_VOID_PTR)C_GetAttributeValue;
    g_fnList.fn[25] = (CK_VOID_PTR)C_SetAttributeValue;
    g_fnList.fn[26] = (CK_VOID_PTR)C_FindObjectsInit;
    g_fnList.fn[27] = (CK_VOID_PTR)C_FindObjects;
    g_fnList.fn[28] = (CK_VOID_PTR)C_FindObjectsFinal;
    g_fnList.fn[29] = (CK_VOID_PTR)C_EncryptInit;
    g_fnList.fn[30] = (CK_VOID_PTR)C_Encrypt;
    g_fnList.fn[31] = (CK_VOID_PTR)C_EncryptUpdate;
    g_fnList.fn[32] = (CK_VOID_PTR)C_EncryptFinal;
    g_fnList.fn[33] = (CK_VOID_PTR)C_DecryptInit;
    g_fnList.fn[34] = (CK_VOID_PTR)C_Decrypt;
    g_fnList.fn[35] = (CK_VOID_PTR)C_DecryptUpdate;
    g_fnList.fn[36] = (CK_VOID_PTR)C_DecryptFinal;
    g_fnList.fn[37] = (CK_VOID_PTR)C_DigestInit;
    g_fnList.fn[38] = (CK_VOID_PTR)C_Digest;
    g_fnList.fn[39] = (CK_VOID_PTR)C_DigestUpdate;
    g_fnList.fn[40] = (CK_VOID_PTR)C_DigestKey;
    g_fnList.fn[41] = (CK_VOID_PTR)C_DigestFinal;
    g_fnList.fn[42] = (CK_VOID_PTR)C_SignInit;
    g_fnList.fn[43] = (CK_VOID_PTR)C_Sign;
    g_fnList.fn[44] = (CK_VOID_PTR)C_SignUpdate;
    g_fnList.fn[45] = (CK_VOID_PTR)C_SignFinal;
    g_fnList.fn[46] = (CK_VOID_PTR)C_SignRecoverInit;
    g_fnList.fn[47] = (CK_VOID_PTR)C_SignRecover;
    g_fnList.fn[48] = (CK_VOID_PTR)C_VerifyInit;
    g_fnList.fn[49] = (CK_VOID_PTR)C_Verify;
    g_fnList.fn[50] = (CK_VOID_PTR)C_VerifyUpdate;
    g_fnList.fn[51] = (CK_VOID_PTR)C_VerifyFinal;
    g_fnList.fn[52] = (CK_VOID_PTR)C_VerifyRecoverInit;
    g_fnList.fn[53] = (CK_VOID_PTR)C_VerifyRecover;
    g_fnList.fn[54] = (CK_VOID_PTR)C_DigestEncryptUpdate;
    g_fnList.fn[55] = (CK_VOID_PTR)C_DecryptDigestUpdate;
    g_fnList.fn[56] = (CK_VOID_PTR)C_SignEncryptUpdate;
    g_fnList.fn[57] = (CK_VOID_PTR)C_DecryptVerifyUpdate;
    g_fnList.fn[58] = (CK_VOID_PTR)C_GenerateKey;
    g_fnList.fn[59] = (CK_VOID_PTR)C_GenerateKeyPair;
    g_fnList.fn[60] = (CK_VOID_PTR)C_WrapKey;
    g_fnList.fn[61] = (CK_VOID_PTR)C_UnwrapKey;
    g_fnList.fn[62] = (CK_VOID_PTR)C_DeriveKey;
    g_fnList.fn[63] = (CK_VOID_PTR)C_SeedRandom;
    g_fnList.fn[64] = (CK_VOID_PTR)C_GenerateRandom;
    g_fnList.fn[65] = (CK_VOID_PTR)C_GetFunctionStatus;
    g_fnList.fn[66] = (CK_VOID_PTR)C_CancelFunction;
    g_fnList.fn[67] = (CK_VOID_PTR)C_WaitForSlotEvent;
}

/* M 扩展表：顺序严格对齐厂商 2016 版 gm3000_pkcs11.dll 的实测表序
   （由函数表指针 RVA → 导出名反查得到），保证任意下标语义一致。 */
static void InitExtTable(void)
{
    memset(&g_ext, 0, sizeof g_ext);
    g_ext.count = 1;
    /* 下标与厂商 2016 版实测表序严格一致（由表内指针 RVA → 导出名反查得到）：
       [0]=M_GetUserInfo      [1]=M_GetExtFunctionList [2]=M_UnblockUserPin   [3]=M_SetTokenLabel
       [4]=M_FormatToken      [5]=M_CreateContainer    [6]=M_DeleteContainer  [7]=M_EnumContainer
       [8]=M_GetContainerInfo [9]=M_WriteSectors       [10]=M_ReadSectors     [11]=M_ReloadObjects
       [12]=M_CreateFile      [13]=M_DeleteFile        [14]=M_WriteFile       [15]=M_ReadFile
       [16]=M_GetFileInfo     [17]=M_GetApplicationInfo[18]=M_SetEnumString   [19]=M_ConstructMSCMapFiles
       TokenMgr 实际读取的是 extTable+0x4C（= fn[18]）。 */
    g_ext.fn[0]  = (CK_VOID_PTR)M_Slot0;
    g_ext.fn[1]  = (CK_VOID_PTR)M_Slot1;
    g_ext.fn[2]  = (CK_VOID_PTR)M_Slot2;
    g_ext.fn[3]  = (CK_VOID_PTR)M_Slot3;
    g_ext.fn[4]  = (CK_VOID_PTR)M_Slot4;
    g_ext.fn[5]  = (CK_VOID_PTR)M_Slot5;
    g_ext.fn[6]  = (CK_VOID_PTR)M_Slot6;
    g_ext.fn[7]  = (CK_VOID_PTR)M_Slot7;
    g_ext.fn[8]  = (CK_VOID_PTR)M_Slot8;
    g_ext.fn[9]  = (CK_VOID_PTR)M_Slot9;
    g_ext.fn[10] = (CK_VOID_PTR)M_Slot10;
    g_ext.fn[11] = (CK_VOID_PTR)M_Slot11;
    g_ext.fn[12] = (CK_VOID_PTR)M_Slot12;
    g_ext.fn[13] = (CK_VOID_PTR)M_Slot13;
    g_ext.fn[14] = (CK_VOID_PTR)M_Slot14;
    g_ext.fn[15] = (CK_VOID_PTR)M_Slot15;
    g_ext.fn[16] = (CK_VOID_PTR)M_Slot16;
    g_ext.fn[17] = (CK_VOID_PTR)M_Slot17;
    g_ext.fn[18] = (CK_VOID_PTR)M_Slot18;
    g_ext.fn[19] = (CK_VOID_PTR)M_Slot19;
    /* 2.2.19 新增的 5 项（索引必须与厂商表序一致，否则上层按偏移取值会取到文本字节） */
    g_ext.fn[20] = (CK_VOID_PTR)M_Slot20;   /* M_ForceLogout */
    g_ext.fn[21] = (CK_VOID_PTR)M_Slot21;   /* M_RemoteUnblockUserPin */
    /* 索引 22 = M_GetDevCaps：TokenMgr 的调用点是
         `mov esi,[obj+8]; cmp DWORD PTR [esi+0x5c],0; je 跳过`
        —— 即**该项为空指针时会被明确跳过**；而返回非 0 则被当成失败
       （实测：返回 CKR_FUNCTION_NOT_SUPPORTED 会让 2.2.19 的 token_get_info 直接失败 rc=2）。
       本设备能力已由 DEVINFO 经 C_GetTokenInfo 如实回报，故这里按厂商语义留空，
       让上层走「跳过」分支，而不是编造 caps 位。 */
    g_ext.fn[22] = NULL;                    /* M_GetDevCaps：显式置空（TokenMgr 会跳过） */
    g_ext.fn[23] = (CK_VOID_PTR)M_Slot23;   /* M_SetInqString */
    g_ext.fn[24] = (CK_VOID_PTR)M_Slot24;   /* M_RemoteUnblockUserPinMS */

    /* 设备描述区（对齐 2.2.19 实测偏移："GM3000" 在 +0x68、"Longmai" 在 +0x88，相距 0x20） */
    SafeCopy((char*)g_ext.desc, "GM3000", 16);
    SafeCopy((char*)g_ext.desc + 0x20, "Longmai", 16);
}

/* 非 static：由 .def 以未修饰名导出 */
CK_RV __cdecl C_GetFunctionList(CK_FUNCTION_LIST** ppFunctionList)
{
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    if (!g_fnList.fn[0]) InitFunctionTable();
    *ppFunctionList = &g_fnList;
    return CKR_OK;
}

/* M_GetExtFunctionList：TokenMgr 以 1 个参数（void**）调用 */
static CK_RV __cdecl M_GetExtFunctionListImpl(CK_VOID_PTR* ppExt)
{
    if (ppExt) *ppExt = &g_ext;
    return CKR_OK;
}

static CK_RV __cdecl M_GetExtFunctionListM(CK_VOID_PTR a1, CK_VOID_PTR a2, CK_ULONG a3, CK_VOID_PTR a4)
{
    (void)a2; (void)a3; (void)a4;
    return M_GetExtFunctionListImpl((CK_VOID_PTR*)a1);
}

/* 导出符号：仅此两个（.def 中声明，保证未修饰名可被 GetProcAddress 命中） */
__declspec(dllexport) CK_RV __cdecl M_GetExtFunctionList(CK_VOID_PTR* ppExt)
{
    return M_GetExtFunctionListImpl(ppExt);
}

/* ================================================================ DllMain */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    g_self = hinstDLL;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitFunctionTable();
        InitExtTable();
        memset(g_sess, 0, sizeof g_sess);
        g_skfError[0] = 0;
        LogReset();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        FreeObjects();
        if (g_skf.h) { UnbindContext(); }
    }
    return TRUE;
}
