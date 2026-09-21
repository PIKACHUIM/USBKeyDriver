using System;
using System.Runtime.InteropServices;
using System.Reflection;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr hModule);

    // PKCS#11 标准函数
    static string[] Pkcs11Functions = new string[]
    {
        "C_Initialize",
        "C_Finalize",
        "C_GetInfo",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
        "C_GetMechanismList",
        "C_GetMechanismInfo",
        "C_InitToken",
        "C_InitPIN",
        "C_SetPIN",
        "C_OpenSession",
        "C_CloseSession",
        "C_CloseAllSessions",
        "C_GetSessionInfo",
        "C_GetOperationState",
        "C_SetOperationState",
        "C_Login",
        "C_Logout",
        "C_CreateObject",
        "C_CopyObject",
        "C_DestroyObject",
        "C_GetObjectSize",
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_FindObjectsInit",
        "C_FindObjects",
        "C_FindObjectsFinal",
        "C_EncryptInit",
        "C_Encrypt",
        "C_EncryptUpdate",
        "C_EncryptFinal",
        "C_DecryptInit",
        "C_Decrypt",
        "C_DecryptUpdate",
        "C_DecryptFinal",
        "C_DigestInit",
        "C_Digest",
        "C_DigestUpdate",
        "C_DigestKey",
        "C_DigestFinal",
        "C_SignInit",
        "C_Sign",
        "C_SignUpdate",
        "C_SignFinal",
        "C_SignRecoverInit",
        "C_SignRecover",
        "C_VerifyInit",
        "C_Verify",
        "C_VerifyUpdate",
        "C_VerifyFinal",
        "C_VerifyRecoverInit",
        "C_VerifyRecover",
        "C_DigestEncryptUpdate",
        "C_DecryptDigestUpdate",
        "C_SignEncryptUpdate",
        "C_DecryptVerifyUpdate",
        "C_GenerateKey",
        "C_GenerateKeyPair",
        "C_WrapKey",
        "C_UnwrapKey",
        "C_DeriveKey",
        "C_SeedRandom",
        "C_GenerateRandom",
        "C_GetFunctionStatus",
        "C_CancelFunction",
        "C_WaitForSlotEvent"
    };

    static void Main(string[] args)
    {
        string dllPath = @"C:\WINDOWS\SysWOW64\HCCBCSP11.dll";
        
        Console.WriteLine($"正在分析 DLL: {dllPath}");
        Console.WriteLine();

        IntPtr hModule = LoadLibrary(dllPath);
        if (hModule == IntPtr.Zero)
        {
            Console.WriteLine($"错误: 无法加载 DLL (错误码: {Marshal.GetLastWin32Error()})");
            return;
        }

        Console.WriteLine("✓ DLL 加载成功");
        Console.WriteLine();
        Console.WriteLine("检测到的 PKCS#11 函数:");
        Console.WriteLine("----------------------------------------");

        int foundCount = 0;
        foreach (string funcName in Pkcs11Functions)
        {
            IntPtr funcPtr = GetProcAddress(hModule, funcName);
            if (funcPtr != IntPtr.Zero)
            {
                Console.WriteLine($"✓ {funcName,-30} @ 0x{funcPtr.ToString("X")}");
                foundCount++;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"总共找到 {foundCount}/{Pkcs11Functions.Length} 个标准 PKCS#11 函数");

        FreeLibrary(hModule);
    }
}
