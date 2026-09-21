import pefile
import sys

dll_path = sys.argv[1] if len(sys.argv) > 1 else r"G:\Codes\USBKeyDriver\Library\HengBao USB Manage\CMBCp.dll"

try:
    pe = pefile.PE(dll_path)
    
    print(f"=== {dll_path} PE 分析 ===\n")
    print(f"架构: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
    print(f"Machine: 0x{pe.FILE_HEADER.Machine:X}")
    print(f"\n=== 导入的 DLL 和函数 ===")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            print(f"\n[{dll_name}]")
            
            # 只显示关键 API
            important_apis = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                    # 过滤关键的设备/通信 API
                    if any(keyword in func_name.lower() for keyword in [
                        'setupdi', 'device', 'hid', 'createfile', 'readfile', 'writefile',
                        'deviceiocontrol', 'winscard', 'scardconnect', 'scardtransmit',
                        'usb', 'serial', 'comm', 'port'
                    ]):
                        important_apis.append(func_name)
            
            if important_apis:
                for api in important_apis:
                    print(f"  - {api}")
            else:
                # 如果没有关键 API，显示前 5 个
                count = 0
                for imp in entry.imports:
                    if imp.name and count < 5:
                        print(f"  - {imp.name.decode('utf-8')}")
                        count += 1
                if len(entry.imports) > 5:
                    print(f"  ... 共 {len(entry.imports)} 个函数")
    else:
        print("未找到导入表")
    
    print(f"\n=== 导出函数（前 20 个）===")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for i, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols):
            if i >= 20:
                print(f"... 共 {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} 个导出")
                break
            name = exp.name.decode('utf-8') if exp.name else f"#{exp.ordinal}"
            print(f"  {exp.ordinal:4d}  {name}")
    else:
        print("未找到导出表")
        
except Exception as e:
    print(f"错误: {e}")
