import pefile
import sys

dll_path = r"G:\Codes\USBKeyDriver\Library\LNCA\JIT_USBKEY_HD.dll"

try:
    pe = pefile.PE(dll_path)
    
    print(f"分析: {dll_path}\n")
    
    # 查找 USBKey_Reset 导出函数的 RVA
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and b'Reset' in exp.name:
                print(f"导出函数: {exp.name.decode()}")
                print(f"  RVA: 0x{exp.address:X}")
                print(f"  File Offset: 0x{pe.get_offset_from_rva(exp.address):X}")
                
                # 读取函数开头的字节码
                offset = pe.get_offset_from_rva(exp.address)
                data = pe.get_data(exp.address, 64)
                
                print(f"  前64字节汇编:")
                for i in range(0, 64, 16):
                    hex_str = ' '.join(f'{b:02X}' for b in data[i:i+16])
                    print(f"    {hex_str}")
                print()
    
except Exception as e:
    print(f"错误: {e}")
    print("\n需要安装 pefile: pip install pefile")
