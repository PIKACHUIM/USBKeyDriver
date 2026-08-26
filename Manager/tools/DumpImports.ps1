param(
    [string]$Path = "c:\USBKey\Library\LNCA"
)
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

public static class PEImports {
    public static List<string> GetImports(string path) {
        var result = new List<string>();
        try {
            var b = File.ReadAllBytes(path);
            if (b.Length < 0x40 || Encoding.ASCII.GetString(b,0,2)!="MZ") return result;
            int pe = BitConverter.ToInt32(b,0x3C);
            int opt = pe + 24;
            ushort magic = BitConverter.ToUInt16(b,opt);
            bool plus = magic==0x20B;
            int optSize = BitConverter.ToUInt16(b, pe+20);
            long sects = BitConverter.ToUInt16(b, pe+6);
            long sectOff = pe + 24 + optSize;
            // import directory index 1 (offset 104 for rva)
            int impRva = BitConverter.ToInt32(b, opt + 104);
            string impName = "";
            // find import name of DLL: first IMAGE_IMPORT_DESCRIPTOR
            int off = FileOff(b, impRva, sectOff, sects);
            if (off < 0) return result;
            int nameRva = BitConverter.ToInt32(b, off + 12);
            int no = FileOff(b, nameRva, sectOff, sects);
            impName = ReadStr(b, no);
            result.Add("IMPORTED_DLL:" + impName);
            // Iterate IAT thunk names
            for (int i = 0; ; i++) {
                int ent = off + i*20;
                int oft = BitConverter.ToInt32(b, ent);     // original first thunk
                int xft = BitConverter.ToInt32(b, ent + 16);// first thunk
                if (oft==0 && xft==0) break;
                long thunk = oft!=0 ? oft : xft;
                int thunkOff = FileOff(b, (int)thunk, sectOff, sects);
                if (thunkOff < 0) continue;
                for (int k = 0; k < 500; k++) {
                    long byVa = plus ? BitConverter.ToInt64(b, thunkOff + k*8) : BitConverter.ToUInt32(b, thunkOff + k*4);
                    ulong val = plus ? (ulong)BitConverter.ToInt64(b, thunkOff+k*8) : BitConverter.ToUInt32(b, thunkOff+k*4);
                    if (val == 0) break;
                    if ((val & (plus ? 0x8000000000000000UL : 0x80000000UL)) != 0) {
                        result.Add("   (ordinal set)");
                    } else {
                        int fnRva = (int)(val & 0x7FFFFFFF);
                        int fnOff = FileOff(b, fnRva, sectOff, sects);
                        if (fnOff > 0) {
                            // hint at +0, name at +2
                            int nameOff = fnOff + 2;
                            result.Add("   import:" + ReadStr(b, nameOff));
                        }
                    }
                }
            }
        } catch (Exception e) { result.Add("ERR:"+e.Message); }
        return result;
    }
    static int FileOff(byte[] b,int rva,long sectOff,long sects){
        if(rva<=0)return -1;
        for(int i=0;i<sects;i++){
            int vs=BitConverter.ToInt32(b,(int)sectOff+i*40+8);
            int vr=BitConverter.ToInt32(b,(int)sectOff+i*40+12);
            int rs=BitConverter.ToInt32(b,(int)sectOff+i*40+16);
            int rf=BitConverter.ToInt32(b,(int)sectOff+i*40+20);
            if(rva>=vr && rva<vr+Math.Max(vs,rs)){int o=rva-vr+rf;if(o>=0&&o<b.Length)return o;}
        }
        return -1;
    }
    static string ReadStr(byte[] b,int off){
        if(off<0||off>=b.Length)return "";
        int end=off; try{ while(end<b.Length&&b[end]!=0&&end-off<512)end++;}catch{}
        if(end==off)return "";
        try{return Encoding.ASCII.GetString(b,off,end-off).Trim();}catch{return "";}
    }
}
"@
Get-ChildItem -Path $Path -Filter "*.exe" | ForEach-Object {
    Write-Host "`n===== $($_.Name) imports ====="
    $imp = [PEImports]::GetImports($_.FullName)
    $imp | ForEach-Object { Write-Host "  $_" }
}
