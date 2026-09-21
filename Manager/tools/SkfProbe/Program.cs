using System.Text;
using USBKey.Core.UsbKey;

Console.OutputEncoding = Encoding.UTF8;
var log = new StringBuilder();
var logPath = Path.Combine(AppContext.BaseDirectory, "skf_probe_out.txt");
void W(string s = "")
{
    Console.WriteLine(s);
    log.AppendLine(s);
    try { File.AppendAllText(logPath, s + Environment.NewLine, Encoding.UTF8); } catch { }
}
try { File.WriteAllText(logPath, "", Encoding.UTF8); } catch { }

try
{
    var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "probe";
    switch (mode)
    {
        case "probe":
            Probe(W, args.Length > 1 ? args[1] : null);
            break;
        case "flow":
            Flow(W, args);
            break;
        case "delapp":
            DelApp(W, args);
            break;
        default:
            W("用法: SkfProbe probe [skfDll路径]");
            W("      SkfProbe flow [用户PIN] [管理口令] [--reset] [--keep]");
            break;
    }
}
catch (Exception ex) { W("[异常] " + ex); }

/// <summary>
/// 找出「SKF_DeleteApplication / SKF_CreateApplication」所需的安全状态前置条件。
/// 逐个组合尝试；任一组合删除成功即立刻重建应用并验证，然后停止。
/// </summary>
static void DelApp(Action<string> w, string[] args)
{
    var userPin = args.Length > 1 ? args[1] : "123456";
    var adminPin = args.Length > 2 ? args[2] : "111111";
    const string app = "BJCA-Application";

    var dll = FindSkfDll(null);
    w($"SKF 中间件 : {dll}");
    using var s = new SkfSession(dll);
    var (_, names) = s.EnumDev();
    if (names.Count == 0) { w("无设备"); return; }
    var sn = names[0];
    var (rcC, hDev) = s.ConnectDev(sn);
    w($"ConnectDev → {SkfNative.Describe(rcC)}");

    var combos = new (string Name, Func<IntPtr, uint> Prepare)[]
    {
        ("A) 打开应用→管理口令认证→关闭应用→删除", h =>
        {
            var (rcO, hApp) = s.OpenApplication(h, app);
            w($"     OpenApplication → {SkfNative.Describe(rcO)}");
            if (rcO != SkfNative.SAR_OK) return rcO;
            var (rcV, _) = s.VerifyPin(hApp, 0, adminPin);
            w($"     VerifyPIN(admin) → {SkfNative.Describe(rcV)}");
            var rcCl = s.CloseApplication(hApp);
            w($"     CloseApplication → {SkfNative.Describe(rcCl)}");
            return SkfNative.SAR_OK;
        }),
        ("B) 打开应用→管理口令认证→直接删除", h =>
        {
            var (rcO, hApp) = s.OpenApplication(h, app);
            if (rcO != SkfNative.SAR_OK) return rcO;
            var (rcV, _) = s.VerifyPin(hApp, 0, adminPin);
            w($"     VerifyPIN(admin) → {SkfNative.Describe(rcV)}");
            return SkfNative.SAR_OK;
        }),
        ("C) 打开应用→用户PIN认证→直接删除", h =>
        {
            var (rcO, hApp) = s.OpenApplication(h, app);
            if (rcO != SkfNative.SAR_OK) return rcO;
            var (rcV, _) = s.VerifyPin(hApp, 1, userPin);
            w($"     VerifyPIN(user) → {SkfNative.Describe(rcV)}");
            return SkfNative.SAR_OK;
        }),
        ("D) 在设备句柄上做管理口令认证→删除", h =>
        {
            var (rcV, _) = s.VerifyPin(h, 0, adminPin);
            w($"     VerifyPIN(hDev, admin) → {SkfNative.Describe(rcV)}");
            return SkfNative.SAR_OK;
        }),
        ("E) 不认证直接删除", _ => SkfNative.SAR_OK),
    };

    foreach (var (name, prepare) in combos)
    {
        w("");
        w($"第 {name}");
        try
        {
            prepare(hDev);
            var rcDel = s.DeleteApplication(hDev, app);
            w($"     SKF_DeleteApplication(\"{app}\") → {SkfNative.Describe(rcDel)}");
            if (rcDel != SkfNative.SAR_OK) continue;

            w("     ✔ 删除成功，立即重建应用 ...");
            var (rcCr, hNew) = s.CreateApplication(hDev, app, adminPin, 10, userPin, 10, 0x02);
            w($"     SKF_CreateApplication → {SkfNative.Describe(rcCr)}");
            try { if (hNew != IntPtr.Zero) s.CloseApplication(hNew); } catch { }

            // 复验
            var (rcO2, hApp2) = s.OpenApplication(hDev, app);
            w($"     OpenApplication（重建后）→ {SkfNative.Describe(rcO2)}");
            if (rcO2 == SkfNative.SAR_OK)
            {
                var (rcV1, r1) = s.VerifyPin(hApp2, 0, adminPin);
                w($"     复验管理口令 → {SkfNative.Describe(rcV1)}（剩余 {r1}）");
                s.ClearSecureState(hApp2);
                var (rcV2, r2) = s.VerifyPin(hApp2, 1, userPin);
                w($"     复验用户 PIN → {SkfNative.Describe(rcV2)}（剩余 {r2}）");
                s.ClearSecureState(hApp2);
                var (_, cons) = s.EnumContainer(hApp2);
                w($"     容器数 = {cons.Count}");
                s.CloseApplication(hApp2);
            }
            break;
        }
        catch (Exception ex) { w($"     异常：{ex.Message}"); }
    }

    s.DisConnectDev(hDev);
    w("");
    w("done.");
}

/// <summary>
/// 生产实现（SkfProvider）全链路实机验证：
/// 枚举 → 登录 → 建容器 → 生成密钥对 → 导出公钥 → 列表 → 改密 → 解锁 → 删容器 →（可选）重置。
/// </summary>
static void Flow(Action<string> w, string[] args)
{
    var userPin = args.Length > 1 && !args[1].StartsWith("--") ? args[1] : "123456";
    var adminPin = args.Length > 2 && !args[2].StartsWith("--") ? args[2] : "111111";
    var doReset = args.Any(a => a == "--reset");
    var keep = args.Any(a => a == "--keep");
    const string cn = "SKFTEST";

    var libRoot = FindLibraryRoot();
    using var prov = new SkfProvider(libRoot, new[]
    {
        new USBKey.Core.Configuration.UsbDeviceDef
        {
            Name = "林果 LG3073（SKF）", Vid = "6588", Pid = "1514", Dll = "lgu3073_p1514_gm.dll",
        },
    });

    w($"Library 根目录 : {libRoot}");
    w($"IsAvailable    : {prov.IsAvailable}");
    w($"SKF 中间件     : {prov.LocateDll()}");
    w($"ResetRequiresCurrentPin : {prov.ResetRequiresCurrentPin}");
    prov.Initialize();

    var devs = prov.Enumerate();
    w($"枚举到设备     : {devs.Count} 台");
    foreach (var d in devs)
        w($"  · {d}  Model={d.Model}  Vendor={d.VendorName}  固件={d.FirmwareVersion}  VID/PID={d.Vid:X4}/{d.Pid:X4}  Notes={d.Notes}");
    if (devs.Count == 0) { w("无设备，结束。"); return; }
    var dev = devs[0];

    void Step(string title) { w(""); w($"== {title} =="); w(""); }
    void Try(string what, Action act)
    {
        try { act(); w($"  ✔ {what}"); }
        catch (Exception ex) { w($"  ✘ {what}：{ex.Message}"); }
    }

    Step("1) 登录（用户 PIN）");
    Try($"Login(PIN={new string('*', userPin.Length)})", () => prov.Login(dev, userPin));
    TellContainers(w, prov, dev);

    Step("2) 建容器 + 生成密钥对");
    Try($"CreateContainer({cn})", () => prov.CreateContainer(dev, cn));
    Try("GenerateKeyPair(RSA 1024，卡内生成较慢)", () => prov.GenerateKeyPair(dev, cn, ecc: false, bitsOrAlg: 1024));
    Try("ExportPublicKey → 原始 blob", () =>
    {
        var blob = prov.ExportPublicKey(dev, cn, true);
        w($"     公钥 blob 长度={blob.Length}");
        for (int i = 0; i < Math.Min(blob.Length, 288); i += 16)
        {
            var hx = string.Join(" ", blob.Skip(i).Take(16).Select(b => b.ToString("X2")));
            w($"      {i:X3}  {hx}");
        }
    });
    TellContainers(w, prov, dev);

    Step("2b) 用容器公钥构造证书 → 本机测试 CA 签发 → 导入（SKF_ImportCertificate）");
    try
    {
        var blob = prov.ExportPublicKey(dev, cn, true);
        // 实测 blob 布局：前 8 字节头（4B 保留 + ULONG 位数），随后 Modulus[256]（小密钥右对齐）、Exponent[4]（大端）
        var bits = BitConverter.ToUInt32(blob, 4);
        var modLen = (int)(bits / 8);
        var modulus = blob.Skip(8 + 256 - modLen).Take(modLen).ToArray();
        var exponent = blob.Skip(8 + 256).Take(4).Reverse().ToArray();
        w($"     公钥位数={bits} Modulus={modLen}B Exponent=0x{Convert.ToHexString(exponent)}");

        using var rsaPub = System.Security.Cryptography.RSA.Create(
            new System.Security.Cryptography.RSAParameters { Modulus = modulus, Exponent = exponent });
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=SKFTEST,OU=Test,O=USBKeyDriver,C=CN", rsaPub,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        using var caKey = System.Security.Cryptography.RSA.Create(2048);
        var caReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=SKF Probe Test CA", caKey, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(10));

        var serial = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(serial);
        using var issued = req.Create(caCert, DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1), serial);
        var der = issued.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
        w($"     本机测试 CA 已为容器公钥签发出 {der.Length}B 证书，正在导入 ...");
        prov.ImportCertificate(dev, cn, der, sign: true);
        w("  ✔ SKF_ImportCertificate");

        var cons = prov.ListContainers(dev);
        var target = cons.FirstOrDefault(c => c.ContainerName == cn);
        w($"     回读：CN={target?.Name} 算法={target?.Algorithm} 有效期={target?.ValidityText} 指纹={target?.Thumbprint}");
        var ok = target?.CertRaw != null && Convert.ToBase64String(target.CertRaw) == Convert.ToBase64String(der);
        w($"     回读证书与导入证书一致性：{(ok ? "一致 ✔" : "不一致")}");
    }
    catch (Exception ex) { w($"  ✘ 证书导入链路：{ex.Message}"); }
    TellContainers(w, prov, dev);

    Step("3) 改密（SKF_ChangePIN type=1）");
    var newPin = userPin == "123456" ? "654321" : "123456";
    Try($"ChangePin({new string('*', userPin.Length)} → {new string('*', newPin.Length)})", () => prov.ChangePin(dev, userPin, newPin));
    Try($"用新 PIN 复验登录", () => { prov.Logout(dev); prov.Login(dev, newPin); });
    Try($"改回原 PIN", () => { prov.Logout(dev); prov.ChangePin(dev, newPin, userPin); prov.Login(dev, userPin); });

    Step("4) 解锁（SKF_UnblockPIN：管理口令 + 新用户 PIN）");
    Try($"Unlock(AdminKey, 管理口令, 新用户PIN={new string('*', newPin.Length)})", () => prov.Unlock(dev, UnlockMethod.AdminKey, adminPin, newPin));
    Try($"用解锁后的 PIN 登录", () => { prov.Logout(dev); prov.Login(dev, newPin); });
    Try($"再用管理口令解锁回原 PIN", () => { prov.Logout(dev); prov.Unlock(dev, UnlockMethod.AdminKey, adminPin, userPin); prov.Login(dev, userPin); });

    Step("5) 删除容器");
    try
    {
        var cons = prov.ListContainers(dev);
        var target = cons.FirstOrDefault(c => c.ContainerName == cn);
        if (target != null) { prov.DeleteContainer(dev, target); w($"  ✔ 已删除容器 {cn}"); }
        else w("  （未找到测试容器）");
    }
    catch (Exception ex) { w($"  ✘ 删除容器：{ex.Message}"); }
    TellContainers(w, prov, dev);

    if (doReset)
    {
        Step("6) 重置（清空容器/文件 + 重设管理口令与用户 PIN）");
        Try($"ResetDevice(新用户PIN={new string('*', userPin.Length)}, 当前管理口令, 新管理口令=当前)",
            () => prov.ResetDevice(dev, userPin, null, adminPin, adminPin));
        w("");
        w("执行报告:");
        w(prov.LastResetReport ?? "(无)");
        TellContainers(w, prov, dev);
    }
    else if (!keep)
    {
        w("");
        w("（未指定 --reset，跳过重置；测试容器已清理）");
    }

    w("");
    w("done.");
}

static void TellContainers(Action<string> w, SkfProvider prov, UsbKeyDevice dev)
{
    try
    {
        var cons = prov.ListContainers(dev);
        w($"     容器数={cons.Count}");
        foreach (var c in cons)
            w($"       - {c.ContainerName}  算法={c.Algorithm}  CN={c.Name}  有效期={c.ValidityText}  指纹={c.Thumbprint}");
    }
    catch (Exception ex) { w($"     容器枚举失败：{ex.Message}"); }
}

static string FindLibraryRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir != null)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, "Library"))) return Path.Combine(dir.FullName, "Library");
        dir = dir.Parent;
    }
    throw new DirectoryNotFoundException("未找到 Library 目录");
}

static string FindSkfDll(string explicitPath)
{
    if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath)) return explicitPath;

    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    string root = null;
    while (dir != null)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, "Library"))) { root = Path.Combine(dir.FullName, "Library"); break; }
        dir = dir.Parent;
    }
    if (root == null) throw new DirectoryNotFoundException("未找到 Library 目录");

    var candidates = new[]
    {
        @"BJCA USBKEY DRIVER\BJCAClient\CertAppEnvV3.7.418.0052\Driver\x86\lgu3073_p1514_gm.dll",
        @"Linguo USB Key DLL\lgu3073_p1514_gm.dll",
    };
    foreach (var c in candidates)
    {
        var p = Path.Combine(root, c);
        if (File.Exists(p)) return p;
    }
    var hits = new DirectoryInfo(root).GetFiles("lgu3073_p1514_gm.dll", SearchOption.AllDirectories);
    if (hits.Length == 0) throw new FileNotFoundException("未找到 lgu3073_p1514_gm.dll");
    return hits.OrderByDescending(f => f.FullName.Contains("x86")).First().FullName;
}

static void Probe(Action<string> w, string dllArg)
{
    var dll = FindSkfDll(dllArg);
    w($"SKF 中间件 : {dll}");
    w($"进程位数  : {(Environment.Is64BitProcess ? "x64" : "x86")}");
    w(new string('-', 90));

    using var s = new SkfSession(dll);
    w($"SKF_EnumDev 导出存在: {s.HasExport("SKF_EnumDev")}");

    // 1) 枚举设备（同时看名字列表的原始编码）
    var (rc, names) = s.EnumDev();
    w($"SKF_EnumDev → {SkfNative.Describe(rc)}，设备数={names.Count}");
    foreach (var n in names) w($"    · 设备名 = [{n}]（长度 {n.Length}）");

    if (names.Count == 0) { w("没有设备，结束。"); return; }
    var devName = names[0];

    // 2) 设备状态 / 连接
    var (rcSt, st) = s.GetDevState(devName);
    w($"SKF_GetDevState → rc={SkfNative.Describe(rcSt)} state={st}（1=已插入 2=已锁定）");

    var (rcC, hDev) = s.ConnectDev(devName);
    w($"SKF_ConnectDev → {SkfNative.Describe(rcC)}  hDev=0x{hDev:X}");
    if (rcC != SkfNative.SAR_OK) return;

    try
    {
        var (rcI, info) = s.GetDevInfo(hDev);
        w($"SKF_GetDevInfo → {SkfNative.Describe(rcI)}");
        if (info != null) w($"    {info}");

        // 原始字节转储：用于核对厂商 DEVINFO 结构体偏移（国标偏移在本 DLL 上似乎差 2 字节）
        var (rcRaw, raw) = s.GetDevInfoRaw(hDev);
        w($"SKF_GetDevInfo 原始转储（rc={SkfNative.Describe(rcRaw)}，仅显示前 256 字节）:");
        for (int i = 0; i < 256 && i + 16 <= raw.Length; i += 16)
        {
            var hx = string.Join(" ", raw.Skip(i).Take(16).Select(b => b.ToString("X2")));
            var tx = new string(raw.Skip(i).Take(16).Select(b => b >= 32 && b < 127 ? (char)b : '.').ToArray());
            w($"      {i:X3}  {hx,-47}  {tx}");
        }

        // 3) 枚举应用
        var (rcA, apps) = s.EnumApplication(hDev);
        w($"SKF_EnumApplication → {SkfNative.Describe(rcA)}，应用数={apps.Count}");
        foreach (var a in apps) w($"    · 应用名 = [{a}]");

        // 4) 打开 BJCA 应用
        foreach (var appName in new[] { "BJCA-Application" }.Concat(apps).Distinct())
        {
            var (rcO, hApp) = s.OpenApplication(hDev, appName);
            w($"SKF_OpenApplication({appName}) → {SkfNative.Describe(rcO)}  hApp=0x{hApp:X}");
            if (rcO != SkfNative.SAR_OK) continue;

            try
            {
                // 5) PIN 信息（扫描 PIN 类型常量，确定哪一个是用户 PIN）
                for (uint t = 0; t <= 5; t++)
                {
                    var (rcP, max, remain, def) = s.GetPinInfo(hApp, t);
                    w($"      SKF_GetPINInfo(type={t}) → {SkfNative.Describe(rcP)} 最大重试={max} 剩余={remain} 是否出厂={def}");
                }

                // 5b) 用已知口令试探 PIN 类型（管理口令 111111 / 用户 PIN 123456 由设备重置时设定）
                //     ⚠️ 失败会消耗重试次数（当前 10/10），只试少量组合
                foreach (var (t, pin, who) in new[]
                         {
                             (0u, "111111", "管理口令"), (0u, "123456", "用户PIN"),
                             (1u, "111111", "管理口令"), (1u, "123456", "用户PIN"),
                         })
                {
                    var (rcV, remain) = s.VerifyPin(hApp, t, pin);
                    w($"      SKF_VerifyPIN(type={t}, {who}={new string('*', pin.Length)}) → {SkfNative.Describe(rcV)} 剩余重试={remain}");
                    s.ClearSecureState(hApp);
                }

                // 6) 枚举容器
                var (rcE, cons) = s.EnumContainer(hApp);
                w($"      SKF_EnumContainer → {SkfNative.Describe(rcE)}，容器数={cons.Count}");
                foreach (var c in cons)
                {
                    var (rcOc, hCon) = s.OpenContainer(hApp, c);
                    if (rcOc != SkfNative.SAR_OK)
                    {
                        w($"        · {c}：OpenContainer 失败 {SkfNative.Describe(rcOc)}");
                        continue;
                    }
                    try
                    {
                        var (rcT, type) = s.GetContainerType(hCon);
                        var (rcCert, cert) = s.ExportCertificate(hCon, true);
                        var (rcPub, pub) = s.ExportPublicKey(hCon, true);
                        w($"        · {c}：类型={type}（2=RSA 3=ECC） 签名证书={cert.Length}B({SkfNative.Describe(rcCert)}) " +
                          $"公钥={pub.Length}B({SkfNative.Describe(rcPub)})");
                    }
                    finally { s.CloseContainer(hCon); }
                }

                s.ClearSecureState(hApp);
            }
            finally { s.CloseApplication(hApp); }
        }
    }
    finally { s.DisConnectDev(hDev); }

    w("done.");
}
