"""Extract strings from GP_ADM_LNCA.exe and find init-related function names / APDU references."""
import re

for exe in [r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\GP_ADM_LNCA.exe",
            r"g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\GP_CLT_LNCA.exe"]:
    data = open(exe,'rb').read()
    print("="*80)
    print(exe.split('\\')[-1])
    print("="*80)
    # ASCII strings >= 4
    strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    seen = set()
    for s in strings:
        t = s.decode('ascii')
        low = t.lower()
        if any(k in low for k in ('init','reset','clear','def','sipwd','spwd','card','ic_','format','factory','出厂','初始')):
            if t not in seen:
                seen.add(t)
                print("  " + t)
