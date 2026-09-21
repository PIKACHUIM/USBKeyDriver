using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using C = System.Runtime.InteropServices.ComTypes;

namespace BjcaProbe;

/// <summary>
/// 读取 DLL 内嵌 TypeLib，导出接口/方法/参数的权威签名。
/// 说明：DLL 内嵌 typelib 是判定 COM 接口真实 ABI 的最可信来源
/// （随 DLL 一起发布，可能比同目录下的 COM.idl 更新或更旧）。
/// </summary>
public static class TypeLibDump
{
    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    private static extern void LoadTypeLibEx(string szFile, int regKind, out C.ITypeLib pptlib);

    // 按 OAIdl.h 原生布局自行定义，避免 ComTypes 中 ELEMDESC/PARAMDESC 字段名与顺序的差异
    [StructLayout(LayoutKind.Sequential)]
    public struct TypeDesc
    {
        public IntPtr lpValue;
        public short vt;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ParamDesc
    {
        public IntPtr unionField;
        public short wParamFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ElemDesc
    {
        public TypeDesc tdesc;
        public ParamDesc paramdesc;
    }

    private const short VT_BYREF = 0x4000;
    private const short VT_ARRAY = 0x2000;

    private static readonly Dictionary<int, string> VtNames = new()
    {
        { 0, "VT_EMPTY" }, { 1, "VT_NULL" }, { 2, "VT_I2" }, { 3, "VT_I4" }, { 4, "VT_R4" }, { 5, "VT_R8" },
        { 6, "VT_CY" }, { 7, "VT_DATE" }, { 8, "VT_BSTR" }, { 9, "VT_DISPATCH" }, { 10, "VT_ERROR" },
        { 11, "VT_BOOL" }, { 12, "VT_VARIANT" }, { 13, "VT_UNKNOWN" }, { 14, "VT_DECIMAL" }, { 16, "VT_I1" },
        { 17, "VT_UI1" }, { 18, "VT_UI2" }, { 19, "VT_UI4" }, { 20, "VT_I8" }, { 21, "VT_UI8" }, { 22, "VT_INT" },
        { 23, "VT_UINT" }, { 24, "VT_VOID" }, { 25, "VT_HRESULT" }, { 26, "VT_PTR" }, { 27, "VT_SAFEARRAY" },
        { 28, "VT_CARRAY" }, { 29, "VT_USERDEFINED" }, { 30, "VT_LPSTR" }, { 31, "VT_LPWSTR" }, { 36, "VT_RECORD" },
        { 37, "VT_INT_PTR" }, { 38, "VT_UINT_PTR" },
    };

    public static string VtName(short vt)
    {
        int b = vt & 0x0FFF;
        if (!VtNames.TryGetValue(b, out var s)) s = "VT_" + b;
        if ((vt & VT_BYREF) != 0) s += "|BYREF";
        if ((vt & VT_ARRAY) != 0) s += "|ARRAY";
        return s;
    }

    public static IEnumerable<string> Dump(string path, string ifFilter, string fnFilter)
    {
        LoadTypeLibEx(path, 0, out C.ITypeLib tl);
        int n = tl.GetTypeInfoCount();
        yield return $"TypeLib 接口数量: {n}";

        for (int i = 0; i < n; i++)
        {
            tl.GetTypeInfo(i, out C.ITypeInfo ti);
            ti.GetDocumentation(-1, out string name, out string doc, out int ctx, out string help);
            if (ifFilter.Length > 0 && name.IndexOf(ifFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;

            ti.GetTypeAttr(out IntPtr ap);
            var a = (C.TYPEATTR)Marshal.PtrToStructure(ap, typeof(C.TYPEATTR));
            ti.ReleaseTypeAttr(ap);

            yield return "";
            yield return $"=== {name}  kind={a.typekind}  methods={a.cFuncs}  GUID={a.guid} ===";

            int elemSize = Marshal.SizeOf(typeof(ElemDesc));
            for (int f = 0; f < a.cFuncs; f++)
            {
                ti.GetFuncDesc(f, out IntPtr fp);
                var fd = (C.FUNCDESC)Marshal.PtrToStructure(fp, typeof(C.FUNCDESC));
                var names = new string[fd.cParams + 1];
                try { ti.GetNames(fd.memid, names, names.Length, out _); } catch { }
                string fname = names.Length > 0 ? names[0] : "?";

                if (fnFilter.Length == 0 || fname.IndexOf(fnFilter, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var sb = new StringBuilder();
                    for (int p = 0; p < fd.cParams; p++)
                    {
                        IntPtr ep = new IntPtr(fd.lprgelemdescParam.ToInt64() + p * elemSize);
                        var ed = (ElemDesc)Marshal.PtrToStructure(ep, typeof(ElemDesc));
                        int flags = ed.paramdesc.wParamFlags;
                        var fl = new List<string>();
                        if ((flags & 0x01) != 0) fl.Add("in");
                        if ((flags & 0x02) != 0) fl.Add("out");
                        if ((flags & 0x08) != 0) fl.Add("retval");
                        if ((flags & 0x10) != 0) fl.Add("opt");
                        string pn = (p + 1) < names.Length ? names[p + 1] : "";
                        if (p > 0) sb.Append(", ");
                        sb.Append($"{VtName(ed.tdesc.vt)} {string.Join("|", fl)} {pn}");
                    }
                    yield return $"  id={fd.memid,-4} {fname}  invkind={fd.invkind} callconv={fd.callconv}  ({sb})  -> {VtName(fd.elemdescFunc.tdesc.vt)}";
                }
                ti.ReleaseFuncDesc(fp);
            }
        }
    }
}
