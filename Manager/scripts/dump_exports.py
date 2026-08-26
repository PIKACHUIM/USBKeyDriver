import pefile
import sys

if len(sys.argv) < 2:
    print("Usage: python dump_exports.py <dll_path>")
    sys.exit(1)

dll_path = sys.argv[1]
pe = pefile.PE(dll_path)

print(f"\n[{dll_path}] 导出函数:\n")
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            print(f"  {exp.name.decode('utf-8')}")
else:
    print("  无导出函数")
