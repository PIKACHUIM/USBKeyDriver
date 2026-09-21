"""列出指定 PID 进程的 32 位模块（跨 WOW64 正确枚举）。

用法:
    python gm_modules.py <pid>
    python gm_modules.py --start <exe> [workdir] [wait_seconds]
"""
import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time

TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
LIST_MODULES_32BIT = 0x01
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD),
                ('th32ProcessID', wt.DWORD), ('GlblcntUsage', wt.DWORD),
                ('ProccntUsage', wt.DWORD), ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
                ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE),
                ('szModule', ctypes.c_char * 256), ('szExePath', ctypes.c_char * 260)]


def modules_via_toolhelp(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1:
        return []
    out = []
    try:
        me = MODULEENTRY32()
        me.dwSize = ctypes.sizeof(MODULEENTRY32)
        ok = k32.Module32First(snap, ctypes.byref(me))
        while ok:
            out.append((me.szModule.decode('latin1'), me.szExePath.decode('latin1')))
            ok = k32.Module32Next(snap, ctypes.byref(me))
    finally:
        k32.CloseHandle(snap)
    return out


def modules_via_psapi(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return []
    try:
        arr = (ctypes.c_void_p * 1024)()
        need = wt.DWORD()
        if not psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr),
                                          ctypes.byref(need), LIST_MODULES_32BIT):
            return []
        n = need.value // ctypes.sizeof(ctypes.c_void_p)
        out = []
        for i in range(n):
            buf = ctypes.create_unicode_buffer(1024)
            buf2 = ctypes.create_unicode_buffer(1024)
            psapi.GetModuleBaseNameW(h, arr[i], buf, 1024)
            psapi.GetModuleFileNameExW(h, arr[i], buf2, 1024)
            out.append((buf.value, buf2.value))
        return out
    finally:
        k32.CloseHandle(h)


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    args = sys.argv[1:]
    if args and args[0] == '--start':
        exe = args[1]
        wd = args[2] if len(args) > 2 else None
        wait = float(args[3]) if len(args) > 3 else 6.0
        p = subprocess.Popen([exe], cwd=wd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(wait)
        pid = p.pid
        print(f'launched pid={pid}')
    else:
        pid = int(args[0])

    mods = modules_via_toolhelp(pid)
    src = 'Toolhelp32'
    if len(mods) < 5:
        mods = modules_via_psapi(pid)
        src = 'PSAPI'
    print(f'== pid={pid} 模块数={len(mods)} (via {src})')
    for name, path in mods:
        print(f'  {name:<28} {path}')


if __name__ == '__main__':
    main()
