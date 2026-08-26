// Hook JIT_USBKEY_HD.dll 的 USBKey_Reset 函数
// 编译: cl /LD hook_reset.cpp /Fe:JIT_USBKEY_HD.dll

#include <windows.h>
#include <stdio.h>

// 原始 DLL 路径
static HMODULE g_hOrigDll = NULL;

// 原始函数指针
typedef int (__stdcall *USBKey_ResetFn)(void* hKey, unsigned char* pData, unsigned int dataLen);
static USBKey_ResetFn g_pOrigReset = NULL;

// Hook 函数
extern "C" __declspec(dllexport) int __stdcall USBKey_Reset(void* hKey, unsigned char* pData, unsigned int dataLen)
{
    // 记录调用参数
    FILE* fp = fopen("C:\\Temp\\usbkey_reset_log.txt", "a");
    if (fp) {
        fprintf(fp, "=== USBKey_Reset 被调用 ===\n");
        fprintf(fp, "hKey: 0x%p\n", hKey);
        fprintf(fp, "pData: 0x%p\n", pData);
        fprintf(fp, "dataLen: %u\n", dataLen);
        
        if (pData && dataLen > 0) {
            fprintf(fp, "数据内容: ");
            for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                fprintf(fp, "%02X ", pData[i]);
            }
            fprintf(fp, "\n");
        }
        
        fclose(fp);
    }
    
    // 调用原始函数
    if (g_pOrigReset) {
        int ret = g_pOrigReset(hKey, pData, dataLen);
        
        // 记录返回值
        fp = fopen("C:\\Temp\\usbkey_reset_log.txt", "a");
        if (fp) {
            fprintf(fp, "返回值: 0x%X\n\n", ret);
            fclose(fp);
        }
        
        return ret;
    }
    
    return -1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 加载原始 DLL
        char origPath[MAX_PATH];
        GetModuleFileNameA(hinstDLL, origPath, MAX_PATH);
        
        // 假设原始 DLL 备份为 JIT_USBKEY_HD_orig.dll
        char* p = strrchr(origPath, '\\');
        if (p) {
            strcpy(p + 1, "JIT_USBKEY_HD_orig.dll");
            g_hOrigDll = LoadLibraryA(origPath);
            
            if (g_hOrigDll) {
                g_pOrigReset = (USBKey_ResetFn)GetProcAddress(g_hOrigDll, "USBKey_Reset");
            }
        }
    }
    
    return TRUE;
}

// 转发其他所有导出函数...
// (这里需要添加所有其他函数的转发)
