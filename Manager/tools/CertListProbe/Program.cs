using System.Text;
using USBKey.Core.Configuration;
using USBKey.Core.UsbKey;

namespace CertListProbe;

/// <summary>
/// <b>只读</b>探针：枚举设备并列出容器/证书，打印新引入的「内容类型」
/// （证书 / 仅密钥 / 空容器）。
///
/// <para>与 <c>SkfProbe</c> 不同，本工具<b>不登录、不建容器、不写卡</b>，
/// 仅用于核对 <c>ListContainers</c> 的展示逻辑，可安全反复运行。</para>
///
/// <para>用法：<code>CertListProbe [skf|bjca]</code>（缺省 skf）</para>
/// </summary>
internal static class Program
{
    private static bool _verifyAdmin;
    private static bool _probeDeletePerm;
    private static bool _asUser;
    private static bool _probeImport;
    private static bool _probeImportCall;
    private static bool _probeImportReal;
    private static string _adminPin = "111111";
    private static string _userPin = "123456";

    private static void Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        var rest = args.ToList();
        _verifyAdmin = rest.Remove("--verify-admin");
        _probeDeletePerm = rest.Remove("--probe-delete-perm");
        _asUser = rest.Remove("--as-user");
        _probeImport = rest.Remove("--probe-import");
        _probeImportCall = rest.Remove("--probe-import-call");
        _probeImportReal = rest.Remove("--probe-import-real");
        int ai = rest.IndexOf("--admin-pin");
        if (ai >= 0 && ai + 1 < rest.Count)
        {
            _adminPin = rest[ai + 1];
            rest.RemoveRange(ai, 2);          // 连同其取值一起移除，避免被当成平台名
        }

        var which = (rest.FirstOrDefault(a => !a.StartsWith("--")) ?? "skf").ToLowerInvariant();
        var root = FindLibraryRoot();

        Console.WriteLine($"Library 根目录 : {root}");
        Console.WriteLine($"目标平台       : {which}");
        Console.WriteLine(new string('-', 78));

        try
        {
            if (which == "bjca") RunBjca(root);
            else RunSkf(root);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"失败：{ex.Message}");
        }
    }

    private static void RunSkf(string root)
    {
        var defs = new List<UsbDeviceDef>
        {
            new() { Name = "林果 LG3073（SKF）", Vid = "6588", Pid = "1514", Dll = "lgu3073_p1514_gm.dll" },
        };
        using var prov = new SkfProvider(root, defs);
        if (!prov.IsAvailable) { Console.WriteLine("SKF 中间件不可用（未找到 lgu3073_p1514_gm.dll）"); return; }
        prov.Initialize();

        Dump(prov);

        // 只读校验：删除容器的前置条件「管理口令认证」（SKF_VerifyPIN type=0）能否通过。
        // 不做任何写操作，可安全运行。
        if (_verifyAdmin)
        {
            Console.WriteLine();
            Console.WriteLine("== 管理口令认证校验（删除容器的前置条件，只读）==");
            foreach (var d in prov.Enumerate())
            {
                try
                {
                    prov.VerifyAdminPin(d, _adminPin);
                    Console.WriteLine($"   {d.SerialNumber}：SKF_VerifyPIN(type=0) 认证通过 ✔");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   {d.SerialNumber}：认证失败 ✘ {ex.Message}");
                }
            }
        }

        if (_probeDeletePerm) ProbeDeletePermission(prov);
        if (_asUser) ProbeDeleteAsUser(prov);
        if (_probeImport)
        {
            Console.WriteLine();
            Console.WriteLine("== 方案A 可行性探测：SKF 导入密钥对的先决条件（只读）==");
            foreach (var d in prov.Enumerate())
            {
                try { Console.WriteLine(prov.ProbeImportCapability(d)); }
                catch (Exception ex) { Console.WriteLine("   探测失败：" + ex.Message); }
            }
        }
        if (_probeImportCall)
        {
            Console.WriteLine();
            Console.WriteLine("== 方案A 实测：SKF_ImportRSAKeyPair 空负载调用（会建/删临时容器）==");
            foreach (var d in prov.Enumerate())
            {
                try { Console.WriteLine(prov.ProbeImportKeyPairCall(d, _adminPin)); }
                catch (Exception ex) { Console.WriteLine("   调用探测失败：" + ex.Message); }
            }
        }
        if (_probeImportReal)
        {
            Console.WriteLine();
            Console.WriteLine("== 方案A 实测：按国标构造真实参数导入 RSA 密钥对（会建/删临时容器）==");
            foreach (var d in prov.Enumerate())
            {
                try { Console.WriteLine(prov.ProbeImportRealKeyPair(d, _adminPin)); }
                catch (Exception ex) { Console.WriteLine("   真实参数探测失败：" + ex.Message); }
            }
        }
    }

    /// <summary>
    /// <b>零写入</b>对照实验：分别在「未认证」与「已认证管理口令」两种会话状态下，
    /// 调用 <c>SKF_DeleteContainer</c> 删除一个<b>卡上不存在</b>的容器名，比较两者返回码，
    /// 用来判定「删除容器是否真的要求先做 SO PIN 认证」。
    ///
    /// <para>因为容器名不存在，卡上不会创建、删除或修改任何数据，可安全反复运行。</para>
    /// </summary>
    private static void ProbeDeletePermission(SkfProvider prov)
    {
        const string ghost = "ZZ_NOEXIST_PROBE";
        Console.WriteLine();
        Console.WriteLine("== 删除容器的权限要求 · 对照实验（零写入）==");
        Console.WriteLine($"   探测容器名：{ghost}（卡上不存在；本实验不修改任何数据）");
        Console.WriteLine();

        foreach (var d in prov.Enumerate())
        {
            var fake = new KeyContainer { ContainerName = ghost, Name = ghost };

            Console.WriteLine($"   [{d.SerialNumber}] ① 未认证状态 → SKF_DeleteContainer");
            TryDelete(prov, d, fake, "        ");

            Console.WriteLine();
            Console.WriteLine($"   [{d.SerialNumber}] ② 先认证【管理口令 type=0】 → SKF_DeleteContainer");
            try
            {
                prov.VerifyAdminPin(d, _adminPin);
                Console.WriteLine("        认证：成功");
                TryDelete(prov, d, fake, "        ");
            }
            catch (Exception ex)
            {
                Console.WriteLine("        认证：失败 " + ex.Message);
            }
        }
    }

    /// <summary>
    /// 单场景实验：<b>先认证用户 PIN（type=1）再删</b>同一个不存在的容器名，
    /// 用来判定「用户 PIN 认证是否足以删除容器」（与管理口令认证对照）。
    /// </summary>
    private static void ProbeDeleteAsUser(SkfProvider prov)
    {
        const string ghost = "ZZ_NOEXIST_PROBE";
        Console.WriteLine();
        Console.WriteLine("== 对照实验：以【用户 PIN type=1】认证后删除容器 ==");
        Console.WriteLine($"   探测容器名：{ghost}（卡上不存在；不修改任何数据）");
        Console.WriteLine();

        foreach (var d in prov.Enumerate())
        {
            var fake = new KeyContainer { ContainerName = ghost, Name = ghost };
            try
            {
                prov.Login(d, _userPin);
                Console.WriteLine($"   [{d.SerialNumber}] 用户 PIN 认证：成功");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   [{d.SerialNumber}] 用户 PIN 认证：失败 {ex.Message}");
                continue;
            }
            TryDelete(prov, d, fake, "        ");
        }
    }

    private static void TryDelete(SkfProvider prov, UsbKeyDevice dev, KeyContainer fake, string indent)
    {
        try
        {
            prov.DeleteContainer(dev, fake);
            Console.WriteLine(indent + "结果：调用成功（意外 —— 说明该状态可以直接删除）");
        }
        catch (Exception ex)
        {
            Console.WriteLine(indent + "结果：" + ex.Message);
        }
    }

    private static void RunBjca(string root)
    {
        var defs = new List<UsbDeviceDef> { new() { Name = "BJCA USBKey", Vid = "", Pid = "" } };
        using var prov = new BjcaProvider(root, defs);
        if (!prov.IsAvailable) { Console.WriteLine("BJCA 组件不可用（未找到 XTXAppCOM.dll）"); return; }
        prov.Initialize();

        Dump(prov);
    }

    private static void Dump(IKeyProvider prov)
    {
        var devs = prov.Enumerate();
        Console.WriteLine($"枚举到设备：{devs.Count} 台");
        foreach (var d in devs)
            Console.WriteLine($"  · {d.SerialNumber}  Model={d.Model}  Vendor={d.VendorName}  " +
                              $"VID/PID={(d.Vid > 0 ? $"{d.Vid:X4}:{d.Pid:X4}" : "—")}  Notes={d.Notes}");

        foreach (var d in devs)
        {
            Console.WriteLine();
            Console.WriteLine($"== {d.SerialNumber} 的容器 / 证书 ==");
            try
            {
                var list = prov.ListContainers(d);
                Console.WriteLine($"   共 {list.Count} 项");
                Console.WriteLine($"   {"类型",-8} {"容器名",-24} {"算法",-22} {"证书CN",-20} {"有效期",-24} 已注册");
                foreach (var c in list)
                {
                    Console.WriteLine($"   {c.ContentText,-8} {Trunc(c.ContainerName, 24),-24} " +
                                      $"{Trunc(c.Algorithm, 22),-22} {Trunc(c.Name, 20),-20} " +
                                      $"{Trunc(c.ValidityText, 24),-24} {(c.IsRegisteredInCsp ? "是" : "")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"   列容器失败：{ex.Message}");
            }
        }
    }

    private static string Trunc(string? s, int n)
    {
        s ??= "";
        return s.Length <= n ? s : s[..(n - 1)] + "…";
    }

    private static string FindLibraryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "Library");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return @"G:\Codes\USBKeyDriver\Library";
    }
}
