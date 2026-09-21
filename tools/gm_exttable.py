#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
读取 Longmai gm3000_pkcs11.dll 的**扩展函数表**（M_GetExtFunctionList 返回的静态表），
把每个槽位的函数指针解析成导出名 —— 这是厂商权威的槽位顺序。

用法：
  gm_exttable.py <dll> <table_rva> [条目数=25] [--auto]
     --auto : 先用导出的 M_GetExtFunctionList 反汇编自动找表地址（rva 由导出表查）
"""
import sys, struct

def load(path):
    return open(path, 'rb').read()

def pe_sections(d):
    e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
    assert d[e_lfanew:e_lfanew+4] == b'PE\0\0', 'not PE'
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', d, coff+2)[0]
    optsz = struct.unpack_from('<H', d, coff+16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', d, opt)[0]
    assert magic == 0x10b, 'not PE32'
    # data directory: PE32 -> opt+96
    dd = opt + 96
    exp_rva, exp_sz = struct.unpack_from('<II', d, dd)
    secs = []
    so = opt + optsz
    for i in range(nsec):
        b = so + i*40
        name = d[b:b+8].rstrip(b'\0').decode('ascii', 'replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', d, b+8)
        secs.append((name, va, vsz, ro, rsz))
    return secs, (exp_rva, exp_sz)

def rva2off(secs, rva):
    for name, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None

def exports(d, secs, exp):
    exp_rva, _ = exp
    off = rva2off(secs, exp_rva)
    if off is None:
        return {}
    nfun, nnam = struct.unpack_from('<II', d, off+20)
    addr_rva, nam_rva, ord_rva = struct.unpack_from('<III', d, off+28)
    addr_off = rva2off(secs, addr_rva)
    nam_off = rva2off(secs, nam_rva)
    ord_off = rva2off(secs, ord_rva)
    out = {}
    if nam_off is None or addr_off is None or ord_off is None:
        return out
    for i in range(nnam):
        s = struct.unpack_from('<I', d, nam_off + i*4)[0]
        so = rva2off(secs, s)
        name = d[so:d.index(b'\0', so)].decode('ascii', 'replace')
        idx = struct.unpack_from('<H', d, ord_off + i*2)[0]
        # 规范：AddressOfNameOrdinals 存的是 **0 基下标**（不是序号）
        if (idx + 1) * 4 > nfun * 4:
            continue
        frva = struct.unpack_from('<I', d, addr_off + idx*4)[0]
        if frva:
            out[frva] = name
    return out

def main():
    dll = sys.argv[1]
    d = load(dll)
    secs, exp = pe_sections(d)
    exps = exports(d, secs, exp)
    # 反查 M_GetExtFunctionList
    ext_rva = None
    for rva, nm in exps.items():
        if nm == 'M_GetExtFunctionList':
            ext_rva = rva
    if len(sys.argv) > 2 and sys.argv[2].isdigit():
        table_rva = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2])
    else:
        table_rva = int(sys.argv[2], 16)
    cnt = 25
    for a in sys.argv[3:]:
        if a.isdigit():
            cnt = int(a)
    # 自动模式：从 M_GetExtFunctionList 的实现里找 `mov DWORD PTR [reg], imm`
    if '--auto' in sys.argv and ext_rva is not None:
        off = rva2off(secs, ext_rva)
        blob = d[off:off+0x80]
        for i in range(len(blob)-6):
            if blob[i] == 0xC7 and (blob[i+1] & 0xC0) == 0x00 and (blob[i+1] & 7) == 0:
                imm = struct.unpack_from('<I', blob, i+2)[0]
                if 0x10000000 <= imm < 0x11000000:
                    print('[auto] 表地址 = 0x%08X (rva 0x%X)' % (imm, imm-0x10000000))
                    table_rva = imm - 0x10000000
                    break
    # 读表：先按 count 字段，再摊开指针
    toff = rva2off(secs, table_rva)
    print('DLL      : %s' % dll)
    print('表 rva   : 0x%X  file_off 0x%X' % (table_rva, toff))
    print('M_GetExtFunctionList rva = %s' % (('0x%X' % ext_rva) if ext_rva else '?'))
    print()
    raw = d[toff:toff+4+4*cnt]
    first = struct.unpack_from('<I', raw, 0)[0]
    print('+0x00 = 0x%08X' % first)
    print()
    print('%-6s %-10s %s' % ('槽位', 'RVA', '导出名'))
    print('-'*52)
    for i in range(cnt):
        p = struct.unpack_from('<I', raw, 4 + i*4)[0]
        if p == 0:
            print('%-6d %-10s %s' % (i, '-', '(空)'))
            continue
        rva = p - 0x10000000
        nm = exps.get(rva, '')
        if not nm:
            # 就近查找（指针可能指向 thunk）
            cand = [(abs(r-rva), n) for r, n in exps.items() if abs(r-rva) <= 0x40]
            if cand:
                cand.sort()
                nm = '%s (+0x%X)' % (cand[0][1], cand[0][0])
            else:
                nm = '??'
        print('%-6d 0x%-8X %s' % (i, rva, nm))

if __name__ == '__main__':
    main()
