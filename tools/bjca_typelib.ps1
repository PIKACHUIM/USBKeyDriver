# bjca_typelib.ps1 - 读取 PE 文件内嵌 TypeLib，导出接口/方法/参数签名（权威 ABI 来源）
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File bjca_typelib.ps1 <dll路径> [接口名过滤] [方法名过滤]
param(
    [Parameter(Mandatory = $true)][string]$DllPath,
    [string]$Filter = "",
    [string]$FuncFilter = ""
)

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using C = System.Runtime.InteropServices.ComTypes;

public static class BjcaTlb
{
    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    private static extern void LoadTypeLibEx(string szFile, int regKind, out C.ITypeLib pptlib);

    private const short VT_BYREF = 0x4000;
    private const short VT_ARRAY = 0x2000;

    private static readonly Dictionary<int, string> VtNames = new Dictionary<int, string>
    {
        {0,"VT_EMPTY"},{1,"VT_NULL"},{2,"VT_I2"},{3,"VT_I4"},{4,"VT_R4"},{5,"VT_R8"},
        {6,"VT_CY"},{7,"VT_DATE"},{8,"VT_BSTR"},{9,"VT_DISPATCH"},{10,"VT_ERROR"},
        {11,"VT_BOOL"},{12,"VT_VARIANT"},{13,"VT_UNKNOWN"},{14,"VT_DECIMAL"},{16,"VT_I1"},
        {17,"VT_UI1"},{18,"VT_UI2"},{19,"VT_UI4"},{20,"VT_I8"},{21,"VT_UI8"},{22,"VT_INT"},
        {23,"VT_UINT"},{24,"VT_VOID"},{25,"VT_HRESULT"},{26,"VT_PTR"},{27,"VT_SAFEARRAY"},
        {28,"VT_CARRAY"},{29,"VT_USERDEFINED"},{30,"VT_LPSTR"},{31,"VT_LPWSTR"},{36,"VT_RECORD"},
        {37,"VT_INT_PTR"},{38,"VT_UINT_PTR"}
    };

    private static string VtName(short vt)
    {
        int b = vt & 0x0FFF;
        string s;
        if (!VtNames.TryGetValue(b, out s)) s = "VT_" + b;
        if ((vt & VT_BYREF) != 0) s += "|BYREF";
        if ((vt & VT_ARRAY) != 0) s += "|ARRAY";
        return s;
    }

    public static string[] Dump(string path, string ifFilter, string fnFilter)
    {
        var lines = new List<string>();
        C.ITypeLib tl;
        LoadTypeLibEx(path, 0, out tl);
        int n = tl.GetTypeInfoCount();
        lines.Add("TypeLib 接口数量: " + n);
        for (int i = 0; i < n; i++)
        {
            C.ITypeInfo ti;
            tl.GetTypeInfo(i, out ti);
            string name, doc, help;
            int ctx;
            ti.GetDocumentation(-1, out name, out doc, out ctx, out help);
            if (ifFilter.Length > 0 && name.IndexOf(ifFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;

            IntPtr ap;
            ti.GetTypeAttr(out ap);
            var a = (C.TYPEATTR)Marshal.PtrToStructure(ap, typeof(C.TYPEATTR));
            ti.ReleaseTypeAttr(ap);

            lines.Add("");
            lines.Add(string.Format("=== {0}  kind={1}  methods={2}  GUID={3} ===", name, a.typekind, a.cFuncs, a.guid));
            for (int f = 0; f < a.cFuncs; f++)
            {
                IntPtr fp;
                ti.GetFuncDesc(f, out fp);
                var fd = (C.FUNCDESC)Marshal.PtrToStructure(fp, typeof(C.FUNCDESC));
                var names = new string[fd.cParams + 1];
                int got;
                try { ti.GetNames(fd.memid, names, names.Length, out got); } catch { }
                string fname = names.Length > 0 ? names[0] : "?";
                if (fnFilter.Length > 0 && fname.IndexOf(fnFilter, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    ti.ReleaseFuncDesc(fp);
                    continue;
                }
                var sb = new StringBuilder();
                int elemSize = Marshal.SizeOf(typeof(C.ELEMDESC));
                for (int p = 0; p < fd.cParams; p++)
                {
                    IntPtr ep = new IntPtr(fd.lprgelemdescParam.ToInt64() + p * elemSize);
                    var ed = (C.ELEMDESC)Marshal.PtrToStructure(ep, typeof(C.ELEMDESC));
                    int flags = (int)ed.paramdesc.wParamFlags.ToInt64();
                    var fl = new List<string>();
                    if ((flags & 0x01) != 0) fl.Add("in");
                    if ((flags & 0x02) != 0) fl.Add("out");
                    if ((flags & 0x08) != 0) fl.Add("retval");
                    if ((flags & 0x04) != 0) fl.Add("lcid");
                    if ((flags & 0x10) != 0) fl.Add("opt");
                    if ((flags & 0x40) != 0) fl.Add("hasdef");
                    string pn = (p + 1) < names.Length ? names[p + 1] : "";
                    if (p > 0) sb.Append(", ");
                    sb.Append(string.Format("{0} {1} {2}", VtName(ed.tdesc.vt), string.Join("|", fl.ToArray()), pn));
                }
                lines.Add(string.Format("  id={0,-4} {1}  invkind={2} callconv={3}  ({4})  -> {5}",
                    fd.memid, fname, fd.invkind, fd.callconv, sb.ToString(), VtName(fd.elemdescFunc.tdesc.vt)));
                ti.ReleaseFuncDesc(fp);
            }
        }
        return lines.ToArray();
    }
}
'@

$lines = [BjcaTlb]::Dump((Resolve-Path $DllPath).Path, $Filter, $FuncFilter)
$lines | ForEach-Object { Write-Output $_ }
