import struct

DLL = r'g:\Codes\USBKeyDriver\Library\LNCA USBKey Manage\JIT_USBKEY_HD.dll'
data = open(DLL, 'rb').read()

# extract printable ASCII + GBK strings
import re
# find ASCII strings
strings = []
i = 0
n = len(data)
cur = bytearray()
while i < n:
    b = data[i]
    if 0x20 <= b <= 0x7e:
        cur.append(b)
    else:
        if len(cur) >= 4:
            strings.append(cur.decode('ascii', 'replace'))
        cur = bytearray()
    i += 1
if len(cur) >= 4:
    strings.append(cur.decode('ascii', 'replace'))

# filter interesting keywords
kw = ['PIN', 'pin', 'Pass', 'pass', '口令', '失败', 'fail', 'Fail', 'Login', 'login', 'Verify', 'verify', 'error', 'Error', '0x3E', '1001', '1002', '1006', 'KEYMAX', 'locked', 'Lock', 'block', 'Block']
for s in strings:
    if any(k in s for k in kw):
        print(s)
