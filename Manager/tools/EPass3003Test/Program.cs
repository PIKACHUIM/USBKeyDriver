using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Crypto;
using USBKey.Core.Native;
using USBKey.Core.UsbKey;

namespace EPass3003Test;

/// <summary>
/// ePass3003（HZCA / HCCB 定制版）实机探针。
/// <para>
/// 用途：不启动界面即可验证「槽位号解析 / 登录 / 证书列表 / 导入证书」，
/// 用于回归「打开会话失败：槽位句柄无效」「无法导入证书」这类问题。
/// </para>
/// <para>
/// 用法：
/// <list type="bullet">
/// <item><c>EPass3003Test</c>：只读枚举（不碰 PIN，不消耗重试次数）</item>
/// <item><c>EPass3003Test keytest &lt;用户PIN&gt;</c>：会话级<b>试写</b>私钥对象（CKA_TOKEN=false，不落盘），验证本卡是否接受导入式写入</item>
/// <item><c>EPass3003Test import &lt;pfx路径&gt; &lt;pfx密码&gt; &lt;用户PIN&gt;</c>：真正导入 PFX（写入卡内，可用界面删除）</item>
/// </list>
/// 环境变量 <c>EPass3003_LIB</c> 可指定 Library 根目录（默认 exe 目录下的 Library）。
/// </para>
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { /* 控制台可能不支持 */ }

        var libRoot = Environment.GetEnvironmentVariable("EPass3003_LIB");
        if (string.IsNullOrWhiteSpace(libRoot)) libRoot = AppPaths.LibraryDir;

        Console.WriteLine("================ ePass3003 (HZCA) 探针 ================");
        Console.WriteLine($"进程位数: {(Environment.Is64BitProcess ? "x64" : "x86")}（HCCBCSP11.dll 为 32 位，必须 x86）");
        Console.WriteLine($"Library 根目录: {libRoot}");

        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "";

        if (cmd == "keytest")
        {
            if (args.Length < 2) { Console.WriteLine("用法: EPass3003Test keytest <用户PIN>"); return 1; }
            KeyTest(libRoot, args[1]);
        }
        else if (cmd == "import")
        {
            if (args.Length < 4)
            {
                Console.WriteLine("用法: EPass3003Test import <pfx路径> <pfx密码> <用户PIN>");
                return 1;
            }
            RunProvider(libRoot, args[3], args[1], args[2]);
        }
        else if (cmd == "pfxinfo")
        {
            if (args.Length < 3)
            {
                Console.WriteLine("用法: EPass3003Test pfxinfo <pfx路径> <pfx密码>   （只用 .NET 读文件，不碰设备、不需要 PIN）");
                return 1;
            }
            PfxInfo(args[1], args[2]);
        }
        else if (cmd == "pfxtest")
        {
            PfxRoundTrip(args.Length > 1 ? args[1] : "123456");
        }
        else if (cmd == "dump")
        {
            DumpObjects(libRoot, args.Length > 1 ? args[1] : null);
        }
        else
        {
            DumpRawSlots(libRoot);
            RunProvider(libRoot, null, null, null);
            Console.WriteLine("\n其它用法：keytest <PIN> ｜ import <pfx> <pfx密码> <PIN> ｜ pfxinfo <pfx> <pfx密码>");
        }

        if (!Console.IsInputRedirected)
        {
            Console.WriteLine("\n按任意键退出…");
            Console.ReadKey(true);
        }
        return 0;
    }

    // ------------------------------------------------------------- PFX 诊断

    /// <summary>
    /// 只检查 PFX 本身（不碰设备、不需要 PIN）：定位"不支持请求的操作"这类失败到底出在哪一步。
    /// 依次尝试三种装载方式，再看能不能取出 RSA 私钥，并打印算法/提供程序等关键信息。
    /// </summary>
    private static void PfxInfo(string path, string password)
    {
        Console.WriteLine("\n--- PFX 诊断（不需要设备） ---");
        Console.WriteLine($"文件: {path}");
        if (!File.Exists(path)) { Console.WriteLine("文件不存在。"); return; }
        Console.WriteLine($"大小: {new FileInfo(path).Length} 字节");

        // 直接走导入时使用的同一条链路（PfxKeyReader）：装载 → 取 RSA 私钥参数。
        // 导入失败时，这里能一次性区分是"装载失败"、"无 RSA 私钥"还是"私钥不允许导出"。
        X509Certificate2? cert = null;
        try
        {
            cert = PfxKeyReader.Load(path, password);
            Console.WriteLine("  装载 → 成功（Exportable|EphemeralKeySet，失败自动回退 Exportable）");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  装载 → 失败 {ex.GetType().Name}: {ex.Message} (HResult=0x{ex.HResult:X8})");
        }

        if (cert == null)
        {
            Console.WriteLine("\n结论：Windows/.NET 无法装载该 PFX —— 常见于：");
            Console.WriteLine("  · 密码错误；");
            Console.WriteLine("  · PFX 由国密/厂商 CSP（如杭州银行 CSP）生成，私钥 blob 不是标准 RSA；");
            Console.WriteLine("  · 文件不是 PKCS#12（比如被改了扩展名的 .cer/.p12 变体）。");
            Console.WriteLine("这类 PFX 请直接用厂商工具 HZBANK_certd3003.exe 导入；本通道（PKCS#11）暂时无法处理。");
            return;
        }

        using (cert)
        {
            Console.WriteLine($"  主题: {cert.Subject}");
            Console.WriteLine($"  颁发者: {cert.Issuer}");
            Console.WriteLine($"  有效期: {cert.NotBefore:yyyy-MM-dd} ~ {cert.NotAfter:yyyy-MM-dd}");
            Console.WriteLine($"  公钥算法: {cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value} ({cert.PublicKey.Oid.Value})");
            Console.WriteLine($"  私钥存在: {cert.HasPrivateKey}");

            try
            {
                using var rsa = cert.GetRSAPrivateKey();
                if (rsa == null)
                {
                    Console.WriteLine("  RSA 私钥: 无（GetRSAPrivateKey 返回 null）");
                    try { Console.WriteLine($"  ECDsa 私钥: {(cert.GetECDsaPrivateKey() != null ? "有" : "无")}"); } catch { }
                }
                else
                {
                    try
                    {
                        var direct = rsa.ExportParameters(true);
                        Console.WriteLine($"  直接 ExportParameters(true) → 成功，模长 {direct.Modulus!.Length * 8} 位");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  直接 ExportParameters(true) → 失败 {ex.Message} (0x{ex.HResult:X8})" +
                                          "（Windows CNG 只给 AllowExport、不给 AllowPlaintextExport，属正常）");
                    }

                    var p = PfxKeyReader.ExportRsaPrivateKey(rsa);
                    Console.WriteLine($"  ✓ 兜底链路取私钥参数 → 成功，模长 {p.Modulus!.Length * 8} 位（加密 PKCS#8 中转）");
                    Console.WriteLine("\n结论：该 PFX 可以导入 —— 证书与私钥参数都能取出。");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  ✗ 取私钥参数失败：{ex.GetType().Name}: {ex.Message}");
                Console.WriteLine("\n结论：该 PFX 无法导入（私钥不可用/不可导出）。请改用厂商工具导入。");
            }

            // 私钥是否挂在某个 CSP 上（能看出是不是厂商 CSP 托管）
            // X509Certificate2.PrivateKey 已标记过时，但它是唯一能拿到 CspKeyContainerInfo 的入口，诊断用无妨。
#pragma warning disable SYSLIB0028
            try
            {
                var legacy = cert.PrivateKey;
                if (legacy is RSACryptoServiceProvider csp)
                    Console.WriteLine($"  私钥提供程序: {csp.CspKeyContainerInfo.ProviderName}" +
                                      $"，容器 {csp.CspKeyContainerInfo.KeyContainerName}");
                else if (legacy != null)
                    Console.WriteLine($"  私钥类型: {legacy.GetType().FullName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  读取私钥提供程序失败: {ex.Message}");
            }
#pragma warning restore SYSLIB0028
        }
    }

    // ------------------------------------------------------------- 对象 dump

    /// <summary>
    /// 把卡上的 PKCS#11 对象原样 dump 出来（匿名会话 + 可选登录后各一遍）。
    /// 用于回答"证书明明导进去了，为什么列不出来"：到底是没找到、还是被过滤掉了。
    /// 用法：<c>dump [用户PIN]</c>（不给 PIN 只做匿名枚举，不消耗重试次数）。
    /// </summary>
    private static void DumpObjects(string libRoot, string? pin)
    {
        Console.WriteLine("\n--- 卡上对象 dump ---");
        var path = FindDll(libRoot);
        if (path == null) { Console.WriteLine("未找到 HCCBCSP11.dll。"); return; }

        using var mod = NativeDll.Load(path);
        if (mod == null) { Console.WriteLine("DLL 加载失败。"); return; }

        var init = mod.GetDelegate<CkmNative.C_InitializeFn>("C_Initialize");
        var getSlots = mod.GetDelegate<CkmNative.C_GetSlotListFn>("C_GetSlotList");
        var open = mod.GetDelegate<CkmNative.C_OpenSessionFn>("C_OpenSession");
        var login = mod.GetDelegate<CkmNative.C_LoginFn>("C_Login");
        var findInit = mod.GetDelegate<CkmNative.C_FindObjectsInitFn>("C_FindObjectsInit");
        var find = mod.GetDelegate<CkmNative.C_FindObjectsFn>("C_FindObjects");
        var findFinal = mod.GetDelegate<CkmNative.C_FindObjectsFinalFn>("C_FindObjectsFinal");
        var getAttr = mod.GetDelegate<CkmNative.C_GetAttributeValueFn>("C_GetAttributeValue");
        var close = mod.GetDelegate<CkmNative.C_CloseSessionFn>("C_CloseSession");
        if (init == null || getSlots == null || open == null || findInit == null || find == null ||
            findFinal == null || getAttr == null)
        {
            Console.WriteLine("关键导出缺失。");
            return;
        }

        init(IntPtr.Zero);
        uint count = 0;
        getSlots(1, null!, ref count);
        if (count == 0) { Console.WriteLine("没有可用槽位。"); return; }
        var slots = new uint[count];
        getSlots(1, slots, ref count);

        uint session = 0;
        var rc = open(slots[0], CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION,
            IntPtr.Zero, IntPtr.Zero, ref session);
        if (rc != CkmNative.CKR_OK) { Console.WriteLine($"开会话失败 0x{rc:X}"); return; }

        try
        {
            Console.WriteLine("\n[匿名会话（未登录）]");
            DumpAll(findInit, find, findFinal, getAttr, session);

            if (string.IsNullOrEmpty(pin))
            {
                Console.WriteLine("\n（未传 PIN：跳过登录后的枚举。加 PIN 再跑一次可看私有对象）");
                return;
            }

            var pinBytes = Encoding.UTF8.GetBytes(pin);
            rc = login!(session, CkmNative.CKU_USER, pinBytes, (uint)pinBytes.Length);
            Console.WriteLine($"\n[已登录] C_Login → 0x{rc:X} {CkmNative.ErrorString(rc)}");
            if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_USER_ALREADY_LOGGED_IN) return;

            DumpAll(findInit, find, findFinal, getAttr, session);
        }
        finally
        {
            close?.Invoke(session);
        }
    }

    private static void DumpAll(CkmNative.C_FindObjectsInitFn findInit, CkmNative.C_FindObjectsFn find,
        CkmNative.C_FindObjectsFinalFn findFinal, CkmNative.C_GetAttributeValueFn getAttr, uint session)
    {
        // 三种查找条件对比：空模板 / 只按类 / 类+证书类型（界面 ListContainers 用的就是第三种）
        Search(findInit, find, findFinal, getAttr, session, "空模板(全部对象)", null);
        var certs = Search(findInit, find, findFinal, getAttr, session, "CKA_CLASS=CKO_CERTIFICATE",
            new[] { (CkmNative.CKA_CLASS, CkmNative.CKO_CERTIFICATE) });
        Search(findInit, find, findFinal, getAttr, session, "CKA_CLASS + CKA_CERTIFICATE_TYPE（界面用）",
            new[] { (CkmNative.CKA_CLASS, CkmNative.CKO_CERTIFICATE),
                    (CkmNative.CKA_CERTIFICATE_TYPE, CkmNative.CKC_X_509) });
        Search(findInit, find, findFinal, getAttr, session, "CKA_CLASS=CKO_PRIVATE_KEY",
            new[] { (CkmNative.CKA_CLASS, CkmNative.CKO_PRIVATE_KEY) });

        // 长度语义探测：卡不按标准回填 ulValueLen，必须摸清它到底怎么判"缓冲区够不够"
        foreach (var h in certs.Take(2))
        {
            ProbeLength(getAttr, session, h, CkmNative.CKA_VALUE, "CKA_VALUE");
            ProbeLength(getAttr, session, h, CkmNative.CKA_ID, "CKA_ID");
        }
    }

    /// <summary>用不同大小的缓冲区反复读同一属性，看返回码与回填的 ulValueLen，判断长度语义。</summary>
    private static void ProbeLength(CkmNative.C_GetAttributeValueFn getAttr, uint session, uint handle,
        uint type, string name)
    {
        Console.WriteLine($"    长度探测 handle={handle} {name}:");
        foreach (var cap in new[] { 8192, 4096, 2048, 1600, 1400, 1200, 1024, 512, 64, 4, 1 })
        {
            var ptr = Marshal.AllocHGlobal(cap);
            try
            {
                var a = new CkmNative.CK_ATTRIBUTE { type = type, pValue = ptr, ulValueLen = (uint)cap };
                var rc = getAttr(session, handle, new[] { a }, 1);
                var head = "";
                if (rc == CkmNative.CKR_OK && cap >= 4)
                {
                    var b = new byte[8];
                    Marshal.Copy(ptr, b, 0, b.Length);
                    head = " head=" + Convert.ToHexString(b);
                }
                Console.WriteLine($"        cap={cap,5} → rc=0x{rc:X} ulValueLen={a.ulValueLen}{head}");
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
    }

    private static List<uint> Search(CkmNative.C_FindObjectsInitFn findInit, CkmNative.C_FindObjectsFn find,
        CkmNative.C_FindObjectsFinalFn findFinal, CkmNative.C_GetAttributeValueFn getAttr,
        uint session, string title, (uint Type, uint Value)[]? filter)
    {
        var attrs = new CkmNative.CK_ATTRIBUTE[filter?.Length ?? 0];
        var bufs = new IntPtr[attrs.Length];
        try
        {
            for (int i = 0; i < attrs.Length; i++)
            {
                bufs[i] = Marshal.AllocHGlobal(4);
                Marshal.WriteInt32(bufs[i], (int)filter![i].Value);
                attrs[i] = new CkmNative.CK_ATTRIBUTE { type = filter[i].Type, pValue = bufs[i], ulValueLen = 4 };
            }

            var rc = findInit(session, attrs, (uint)attrs.Length);
            if (rc != CkmNative.CKR_OK)
            {
                Console.WriteLine($"  {title}: C_FindObjectsInit → 0x{rc:X} {CkmNative.ErrorString(rc)}");
                return new List<uint>();
            }

            var handles = new uint[64];
            uint found = 0;
            var list = new List<uint>();
            while (true)
            {
                rc = find(session, handles, (uint)handles.Length, ref found);
                if (rc != CkmNative.CKR_OK || found == 0) break;
                for (uint i = 0; i < found; i++) list.Add(handles[i]);
            }
            findFinal(session);

            Console.WriteLine($"  {title}: 命中 {list.Count} 个对象");
            foreach (var h in list)
                Console.WriteLine($"      handle={h} {DescribeObject(getAttr, session, h)}");
            return list;
        }
        finally
        {
            foreach (var b in bufs) if (b != IntPtr.Zero) Marshal.FreeHGlobal(b);
        }
    }

    private static string DescribeObject(CkmNative.C_GetAttributeValueFn getAttr, uint session, uint handle)
    {
        var parts = new List<string>();
        foreach (var (name, type) in new (string, uint)[]
                 {
                     ("class", CkmNative.CKA_CLASS),
                     ("certType", CkmNative.CKA_CERTIFICATE_TYPE),
                     ("keyType", CkmNative.CKA_KEY_TYPE),
                     ("private", CkmNative.CKA_PRIVATE),
                     ("token", CkmNative.CKA_TOKEN),
                     ("label", CkmNative.CKA_LABEL),
                     ("id", CkmNative.CKA_ID),
                     ("value", CkmNative.CKA_VALUE),
                     ("modBits", CkmNative.CKA_MODULUS_BITS),
                 })
        {
            var b = ReadBytes(getAttr, session, handle, type, out var rc);
            parts.Add($"{name}[{Render(type, b, rc)}]");
        }
        return string.Join(" ", parts);
    }

    /// <summary>把属性值渲染成人能读的形式（本卡不回填 ulValueLen，所以只显示缓冲区头部）。</summary>
    private static string Render(uint type, byte[]? b, uint rc)
    {
        if (rc != CkmNative.CKR_OK) return $"rc=0x{rc:X}({CkmNative.ErrorString(rc)})";
        if (b == null || b.Length == 0) return "空";

        return type switch
        {
            CkmNative.CKA_CLASS or CkmNative.CKA_CERTIFICATE_TYPE or CkmNative.CKA_KEY_TYPE
                or CkmNative.CKA_PRIVATE or CkmNative.CKA_TOKEN or CkmNative.CKA_MODULUS_BITS
                => BitConverter.ToUInt32(b, 0).ToString(),
            CkmNative.CKA_LABEL => $"'{CkmNative.PaddedToString(b.AsSpan(0, Math.Min(64, b.Length)).ToArray())}'",
            CkmNative.CKA_ID => "0x" + Convert.ToHexString(b.AsSpan(0, Math.Min(64, b.Length))),
            CkmNative.CKA_VALUE => $"buf={b.Length} head={Convert.ToHexString(b.AsSpan(0, 8))}",
            _ => $"buf={b.Length} head={Convert.ToHexString(b.AsSpan(0, Math.Min(8, b.Length)))}",
        };
    }

    /// <summary>
    /// 读一个属性。先按 PKCS#11 标准两步法（pValue=NULL 问长度）；本卡对这一步一律回 0，
    /// 因此再退化为"给足缓冲区一次读"。把两次的返回码都带出来便于判断。
    /// </summary>
    private static byte[]? ReadBytes(CkmNative.C_GetAttributeValueFn getAttr, uint session, uint handle,
        uint type, out uint rc)
    {
        // A) 标准两步法
        var attr = new CkmNative.CK_ATTRIBUTE { type = type, pValue = IntPtr.Zero, ulValueLen = 0 };
        rc = getAttr(session, handle, new[] { attr }, 1);
        if (rc != CkmNative.CKR_OK) return null;

        if (attr.ulValueLen != 0 && attr.ulValueLen != 0xFFFFFFFF)
        {
            var n = (int)attr.ulValueLen;
            var p1 = Marshal.AllocHGlobal(n);
            try
            {
                attr.pValue = p1;
                rc = getAttr(session, handle, new[] { attr }, 1);
                if (rc != CkmNative.CKR_OK) return null;
                var b1 = new byte[n];
                Marshal.Copy(p1, b1, 0, n);
                return b1;
            }
            finally { Marshal.FreeHGlobal(p1); }
        }

        // B) 退化为"大缓冲区一次读"（本卡实际需要这种方式）
        const int cap = 4096;
        var p2 = Marshal.AllocHGlobal(cap);
        try
        {
            var a2 = new CkmNative.CK_ATTRIBUTE { type = type, pValue = p2, ulValueLen = cap };
            rc = getAttr(session, handle, new[] { a2 }, 1);
            if (rc != CkmNative.CKR_OK) return null;
            var len = a2.ulValueLen == 0xFFFFFFFF ? 0u : a2.ulValueLen;
            if (len == 0 || len > cap) return Array.Empty<byte>();
            var b2 = new byte[len];
            Marshal.Copy(p2, b2, 0, (int)len);
            return b2;
        }
        finally { Marshal.FreeHGlobal(p2); }
    }

    /// <summary>
    /// PFX 往返自测：本地生成 RSA → 自签 → 导出 PKCS#12 → 再导入 → 尝试导出完整私钥。
    /// 用来区分"这台机器/这个运行环境不允许导出 PFX 私钥"与"某个具体 PFX 的密钥不可导出"。
    /// </summary>
    private static void PfxRoundTrip(string pwd)
    {
        Console.WriteLine("\n--- PFX 往返自测（不碰设备） ---");

        using var rsa = RSA.Create(2048);
        var gen = rsa.ExportParameters(true);
        Console.WriteLine($"1) 进程内生成 RSA2048：D 长度 {gen.D!.Length}（本身可导出）");

        using (var self = new CertificateRequest("CN=pfx-roundtrip", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                   .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
        {
            Console.WriteLine($"2) 自签证书 OK：{self.Subject}");

            var pfx = self.Export(X509ContentType.Pfx, pwd);
            Console.WriteLine($"3) 导出 PKCS#12：{pfx.Length} 字节（密码 {pwd}）");

            var modes = new (string Name, X509KeyStorageFlags Flags)[]
            {
                ("Exportable", X509KeyStorageFlags.Exportable),
                ("Exportable|EphemeralKeySet", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet),
                ("DefaultKeySet", X509KeyStorageFlags.DefaultKeySet),
            };

            foreach (var (name, flags) in modes)
            {
                try
                {
                    using var re = new X509Certificate2(pfx, pwd, flags);
                    using var r2 = re.GetRSAPrivateKey();
                    if (r2 == null) { Console.WriteLine($"   [{name}] 无 RSA 私钥"); continue; }

                    try
                    {
                        var p = r2.ExportParameters(true);
                        Console.WriteLine($"   [{name}] 完整私钥导出成功，D 长度 {p.D!.Length} ✓");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"   [{name}] 完整私钥导出失败：{ex.Message} (0x{ex.HResult:X8})");
                    }

                    if (r2 is RSACng { Key: { } cngKey })
                    {
                        try { Console.WriteLine($"        Provider = {cngKey.Provider?.Provider}"); }
                        catch (Exception ex) { Console.WriteLine($"        读 Provider 失败：{ex.Message}"); }
                        try { Console.WriteLine($"        ExportPolicy = {cngKey.ExportPolicy}"); }
                        catch (Exception ex) { Console.WriteLine($"        读 ExportPolicy 失败：{ex.Message}"); }
                        try
                        {
                            var blob = cngKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                            Console.WriteLine($"        CngKey.Export(Pkcs8PrivateBlob) → 成功 {blob.Length} 字节");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"        CngKey.Export(Pkcs8PrivateBlob) → 失败 {ex.Message} (0x{ex.HResult:X8})");
                        }
                    }

                    try
                    {
                        var pkcs1 = r2.ExportRSAPrivateKey();
                        Console.WriteLine($"        ExportRSAPrivateKey() → 成功 {pkcs1.Length} 字节");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"        ExportRSAPrivateKey() → 失败 {ex.Message} (0x{ex.HResult:X8})");
                    }

                    try
                    {
                        var pkcs8 = r2.ExportPkcs8PrivateKey();
                        Console.WriteLine($"        ExportPkcs8PrivateKey() → 成功 {pkcs8.Length} 字节");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"        ExportPkcs8PrivateKey() → 失败 {ex.Message} (0x{ex.HResult:X8})");
                    }

                    // 关键试探：CNG 的 AllowExport 允许"再导出为加密 PKCS#8"吗？
                    // 若可以，就能绕开明文导出限制（导出→托管导入→再取参数）。
                    try
                    {
                        var enc = r2.ExportEncryptedPkcs8PrivateKey("probe",
                            new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 1));
                        Console.WriteLine($"        ExportEncryptedPkcs8PrivateKey() → 成功 {enc.Length} 字节");

                        using var r3 = RSA.Create();
                        r3.ImportEncryptedPkcs8PrivateKey("probe", enc, out _);
                        var p3 = r3.ExportParameters(true);
                        Console.WriteLine($"        加密 PKCS#8 往返 → 明文参数可取，D 长度 {p3.D!.Length} ✓（这条链路可用）");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"        ExportEncryptedPkcs8PrivateKey() → 失败 {ex.Message} (0x{ex.HResult:X8})");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   [{name}] 装载失败：{ex.Message} (0x{ex.HResult:X8})");
                }
            }
        }
    }

    // ---------------------------------------------------------------- 原生层

    private static string? FindDll(string libRoot)
    {
        var sys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "HCCBCSP11.dll");
        if (File.Exists(sys)) return sys;
        var sdk = Path.Combine(libRoot, "ePass3003 HZCA SDK", "SysWOW64", "HCCBCSP11.dll");
        return File.Exists(sdk) ? sdk : null;
    }

    /// <summary>直接 P/Invoke：打印真实槽位号与令牌原始字段（不经过 Provider）。</summary>
    private static void DumpRawSlots(string libRoot)
    {
        Console.WriteLine("\n--- 1) 原始 PKCS#11：槽位号 / CK_TOKEN_INFO ---");
        var path = FindDll(libRoot);
        if (path == null) { Console.WriteLine("未找到 HCCBCSP11.dll，跳过。"); return; }
        Console.WriteLine($"DLL: {path}");

        using var mod = NativeDll.Load(path);
        if (mod == null) { Console.WriteLine("DLL 加载失败。"); return; }

        var init = mod.GetDelegate<CkmNative.C_InitializeFn>("C_Initialize");
        var getSlots = mod.GetDelegate<CkmNative.C_GetSlotListFn>("C_GetSlotList");
        var getToken = mod.GetDelegate<CkmNative.C_GetTokenInfoFn>("C_GetTokenInfo");
        var open = mod.GetDelegate<CkmNative.C_OpenSessionFn>("C_OpenSession");
        var close = mod.GetDelegate<CkmNative.C_CloseSessionFn>("C_CloseSession");
        if (init == null || getSlots == null || getToken == null || open == null)
        {
            Console.WriteLine("关键导出缺失（C_Initialize / C_GetSlotList / C_GetTokenInfo / C_OpenSession）。");
            return;
        }

        var rc = init(IntPtr.Zero);
        Console.WriteLine($"C_Initialize → 0x{rc:X}（0=成功，0x191=已初始化）");

        uint count = 0;
        rc = getSlots(1, null!, ref count);
        Console.WriteLine($"C_GetSlotList(仅含令牌) → 0x{rc:X}, count={count}");
        if (rc != CkmNative.CKR_OK || count == 0) return;

        var slots = new uint[count];
        rc = getSlots(1, slots, ref count);
        if (rc != CkmNative.CKR_OK) { Console.WriteLine($"取槽位列表失败: 0x{rc:X}"); return; }

        for (int i = 0; i < count; i++)
        {
            var ti = new CkmNative.CK_TOKEN_INFO();
            var trc = getToken(slots[i], ref ti);
            Console.WriteLine($"  [索引 {i}] 槽位号={slots[i]} (0x{slots[i]:X8})  C_GetTokenInfo → 0x{trc:X}");
            if (trc != CkmNative.CKR_OK) continue;

            Console.WriteLine($"      label='{CkmNative.PaddedToString(ti.label)}' " +
                              $"mfr='{CkmNative.PaddedToString(ti.manufacturerID)}' " +
                              $"model='{CkmNative.PaddedToString(ti.model)}' " +
                              $"sn='{CkmNative.PaddedToString(ti.serialNumber)}'");
            Console.WriteLine($"      flags=0x{ti.flags:X8} hw={ti.hardwareVersion.major}.{ti.hardwareVersion.minor} " +
                              $"fw={ti.firmwareVersion.major}.{ti.firmwareVersion.minor}");

            uint s = 0;
            var orc = open(slots[i], CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION,
                IntPtr.Zero, IntPtr.Zero, ref s);
            Console.WriteLine($"      C_OpenSession(槽位号) → 0x{orc:X} {CkmNative.ErrorString(orc)}");
            if (orc == CkmNative.CKR_OK) close?.Invoke(s);

            DumpMechanisms(mod, slots[i]);
        }
    }

    /// <summary>
    /// 列出卡支持的机制（只读，不需要 PIN）。用于判断备用路径是否可行：
    /// 若支持 <c>CKM_RSA_PKCS_KEY_PAIR_GEN</c>，则还能走「卡内生成密钥 + CSR」的证书登记流程。
    /// </summary>
    private static void DumpMechanisms(NativeDll.Module mod, uint slot)
    {
        var getList = mod.GetDelegate<CkmNative.C_GetMechanismListFn>("C_GetMechanismList");
        if (getList == null) return;

        uint n = 0;
        if (getList(slot, null, ref n) != CkmNative.CKR_OK || n == 0)
        {
            Console.WriteLine("      机制列表：空");
            return;
        }

        var mechs = new uint[n];
        if (getList(slot, mechs, ref n) != CkmNative.CKR_OK) return;

        var names = new List<string>();
        foreach (var m in mechs)
            names.Add(m switch
            {
                CkmNative.CKM_RSA_PKCS_KEY_PAIR_GEN => $"0x{m:X8}(RSA密钥对生成)",
                CkmNative.CKM_RSA_PKCS => $"0x{m:X8}(RSA)",
                CkmNative.CKM_SHA1_RSA_PKCS => $"0x{m:X8}(SHA1-RSA)",
                CkmNative.CKM_SHA256_RSA_PKCS => $"0x{m:X8}(SHA256-RSA)",
                _ => $"0x{m:X8}",
            });
        Console.WriteLine($"      机制列表({n}): {string.Join("、", names)}");
    }

    // ------------------------------------------------------- 会话级试写（安全）

    /// <summary>
    /// 会话级试写：以用户 PIN 登录后，用与 ImportPfx 完全相同的模板创建一个
    /// <c>CKA_TOKEN=false</c> 的私钥对象（只存在于会话中，不断电写卡），随即销毁。
    /// 用来判定"本卡是否接受导入式私钥写入"，而不在卡上留下任何数据。
    /// </summary>
    private static void KeyTest(string libRoot, string pin)
    {
        Console.WriteLine("\n--- 会话级试写私钥对象（不落盘） ---");
        var path = FindDll(libRoot);
        if (path == null) { Console.WriteLine("未找到 HCCBCSP11.dll。"); return; }

        using var mod = NativeDll.Load(path);
        if (mod == null) { Console.WriteLine("DLL 加载失败。"); return; }

        var init = mod.GetDelegate<CkmNative.C_InitializeFn>("C_Initialize");
        var getSlots = mod.GetDelegate<CkmNative.C_GetSlotListFn>("C_GetSlotList");
        var open = mod.GetDelegate<CkmNative.C_OpenSessionFn>("C_OpenSession");
        var login = mod.GetDelegate<CkmNative.C_LoginFn>("C_Login");
        var create = mod.GetDelegate<CkmNative.C_CreateObjectFn>("C_CreateObject");
        var destroy = mod.GetDelegate<CkmNative.C_DestroyObjectFn>("C_DestroyObject");
        var close = mod.GetDelegate<CkmNative.C_CloseSessionFn>("C_CloseSession");
        if (init == null || getSlots == null || open == null || login == null || create == null)
        {
            Console.WriteLine("关键导出缺失。");
            return;
        }

        init(IntPtr.Zero);

        uint count = 0;
        getSlots(1, null!, ref count);
        if (count == 0) { Console.WriteLine("没有可用槽位。"); return; }
        var slots = new uint[count];
        getSlots(1, slots, ref count);

        uint session = 0;
        var rc = open(slots[0], CkmNative.CKF_SERIAL_SESSION | CkmNative.CKF_RW_SESSION,
            IntPtr.Zero, IntPtr.Zero, ref session);
        Console.WriteLine($"C_OpenSession(槽位 {slots[0]}) → 0x{rc:X} {CkmNative.ErrorString(rc)}");
        if (rc != CkmNative.CKR_OK) return;

        try
        {
            var pinBytes = Encoding.UTF8.GetBytes(pin);
            rc = login(session, CkmNative.CKU_USER, pinBytes, (uint)pinBytes.Length);
            Console.WriteLine($"C_Login(CKU_USER, {pinBytes.Length} 字节) → 0x{rc:X} {CkmNative.ErrorString(rc)}" +
                              (rc == CkmNative.CKR_PIN_INCORRECT ? "  ← 注意：这次失败会消耗一次重试机会" : ""));
            if (rc != CkmNative.CKR_OK && rc != CkmNative.CKR_USER_ALREADY_LOGGED_IN) return;

            // 本地生成一把 2048 位 RSA，用与真实导入相同的模板试写（仅把 CKA_TOKEN 改成 false）
            using var rsa = RSA.Create(2048);
            var p = rsa.ExportParameters(true);
            using var tmp = SelfSignedCert(rsa);

            var template = EPass3003Provider.PrivateKeyTemplate(p, new byte[] { 0x01, 0x02, 0x03, 0x04 }, "probe-keytest", tmp)
                .Select(a => a.Item1 == CkmNative.CKA_TOKEN ? (a.Item1, new byte[] { 0 }) : a)
                .ToArray();

            uint h = 0;
            var crc = CreateObject(create, session, template, ref h);
            Console.WriteLine($"C_CreateObject(私钥, CKA_TOKEN=false) → 0x{crc:X} {CkmNative.ErrorString(crc)}");

            if (crc == CkmNative.CKR_OK)
            {
                Console.WriteLine("✓ 本卡接受导入式私钥模板（真实导入应当可行）");
                if (destroy != null)
                {
                    var drc = destroy(session, h);
                    Console.WriteLine($"C_DestroyObject → 0x{drc:X} {CkmNative.ErrorString(drc)}（会话对象，断开会话即消失）");
                }
            }
            else
            {
                Console.WriteLine("✗ 本卡拒绝了该属性组合：需要按报错调整模板（属性无效/模板不一致）");
            }
        }
        finally
        {
            close?.Invoke(session);
        }
    }

    private static uint CreateObject(CkmNative.C_CreateObjectFn fn, uint session,
        (uint Type, byte[] Value)[] template, ref uint handle)
    {
        var attrs = new CkmNative.CK_ATTRIBUTE[template.Length];
        var buffers = new IntPtr[template.Length];
        try
        {
            for (int i = 0; i < template.Length; i++)
            {
                buffers[i] = Marshal.AllocHGlobal(template[i].Value.Length);
                Marshal.Copy(template[i].Value, 0, buffers[i], template[i].Value.Length);
                attrs[i] = new CkmNative.CK_ATTRIBUTE
                {
                    type = template[i].Type,
                    pValue = buffers[i],
                    ulValueLen = (uint)template[i].Value.Length
                };
            }
            return fn(session, attrs, (uint)attrs.Length, ref handle);
        }
        finally
        {
            foreach (var b in buffers) if (b != IntPtr.Zero) Marshal.FreeHGlobal(b);
        }
    }

    /// <summary>自签一张临时证书（仅用于提供 CKA_SUBJECT，不写入卡）。</summary>
    private static X509Certificate2 SelfSignedCert(RSA rsa) =>
        new CertificateRequest("CN=probe-keytest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

    // -------------------------------------------------------------- Provider

    /// <summary>走 Provider（与界面完全同源）验证枚举 / 登录 / 证书列表 / 导入。</summary>
    private static void RunProvider(string libRoot, string? pin, string? pfxPath, string? pfxPwd)
    {
        Console.WriteLine("\n--- 2) Provider（界面同源链路） ---");

        var provider = new EPass3003Provider(libRoot, new[]
        {
            new UsbDeviceDef { Name = "EnterSafe ePass3003", Vid = "096E", Pid = "0703" }
        });

        try
        {
            provider.Initialize();
            var devices = provider.Enumerate();
            Console.WriteLine($"枚举到 {devices.Count} 台设备");
            foreach (var d in devices)
            {
                Console.WriteLine($"  平台={PlatformInfo.DisplayName(d.Platform)}");
                Console.WriteLine($"  厂商/型号={d.VendorName} / {d.Model}");
                Console.WriteLine($"  序列号={d.SerialNumber} VID:PID={d.Vid:X4}:{d.Pid:X4} 固件={d.FirmwareVersion} 备注='{d.Notes}'");
            }
            if (devices.Count == 0) return;

            var dev = devices[0];

            // 模拟界面行为：点「登录」前/后界面都会再枚举一次
            // （早期实现会在重新枚举时把已打开的会话句柄覆盖成 0，导致后续全部报会话句柄无效）
            provider.Enumerate();

            if (string.IsNullOrEmpty(pin))
            {
                Console.WriteLine("（未传 PIN：只做只读枚举，跳过登录）");
                try
                {
                    var anon = provider.ListContainers(dev);
                    Console.WriteLine($"✓ 未登录即可列出 {anon.Count} 项（该卡允许匿名枚举）");
                    foreach (var c in anon)
                        Console.WriteLine($"    [{c.ContentText}] {c.Name} | {c.Subject} | {c.ValidityText} | {c.Algorithm}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  未登录列证书 → {ex.Message}");
                    Console.WriteLine("  （期望「未登录」；出现「会话句柄无效 / 槽位句柄无效」即为回归）");
                }
                return;
            }

            provider.Login(dev, pin);
            Console.WriteLine($"✓ 登录成功 IsLoggedIn={dev.IsLoggedIn}");

            var certs = provider.ListContainers(dev);
            Console.WriteLine($"✓ 证书/容器 {certs.Count} 项");
            foreach (var c in certs)
                Console.WriteLine($"    [{c.ContentText}] {c.Name} | {c.Subject} | {c.ValidityText} | {c.Algorithm}");

            if (!string.IsNullOrEmpty(pfxPath))
            {
                Console.WriteLine($"\n导入 PFX: {pfxPath}");
                provider.ImportPfx(dev, pfxPath, pfxPwd ?? "");
                Console.WriteLine("✓ 导入调用成功，重新列容器：");
                foreach (var c in provider.ListContainers(dev))
                    Console.WriteLine($"    [{c.ContentText}] {c.Name} | {c.Subject} | {c.ValidityText} | {c.Algorithm}");
            }

            provider.Logout(dev);
            Console.WriteLine($"✓ 已登出 IsLoggedIn={dev.IsLoggedIn}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ 失败：{ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            provider.Dispose();
        }
    }
}
