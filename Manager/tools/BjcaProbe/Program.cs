using System.Runtime.InteropServices;
using System.Text;
using BjcaProbe;

Console.OutputEncoding = Encoding.UTF8;
var log = new StringBuilder();
var logPath = Path.Combine(AppContext.BaseDirectory, "bjca_probe_out.txt");
void W(string s = "")
{
    Console.WriteLine(s);
    log.AppendLine(s);
    // 逐行落盘：便于定位在某次调用上卡死的位置
    try { File.AppendAllText(logPath, s + Environment.NewLine, Encoding.UTF8); } catch { }
}
try { File.WriteAllText(logPath, "", Encoding.UTF8); } catch { }

try
{
    var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "help";
    switch (mode)
    {
        case "typelib":
            DumpTypeLib(W, args.Length > 1 ? args[1] : "", args.Length > 2 ? args[2] : "");
            break;
        case "probe":
            Probe(W, args.Length > 1 ? args[1] : null);
            break;
        case "readonly":
            ReadOnlyExplore(W, args.Length > 1 ? args[1] : null);
            break;
        case "provider":
            ProviderSmoke(W);
            break;
        case "reset":
            ResetTest(W, args);
            break;
        case "certtest":
            CertTest(W, args);
            break;
        case "pfximport":
            PfxImportTest(W, args);
            break;
        default:
            W("用法:");
            W("  BjcaProbe typelib [接口名过滤] [方法名过滤]   # 导出 DLL 内嵌 TypeLib 的权威签名");
            W("  BjcaProbe probe [dll路径]                    # 免注册激活 XTXApp 并做连通性测试");
            W("  BjcaProbe readonly [dll路径]                 # 只读方式探测设备信息/容器/证书/重试次数");
            W("  BjcaProbe provider                          # 联调生产实现 BjcaProvider（枚举/详情/容器）");
            W("  BjcaProbe reset <新用户PIN> [管理口令] [标签] [--yes]   # 重置设备（清空内容+重设口令，不可撤销）");
            W("  BjcaProbe certtest [用户PIN] [--cleanup]     # 实测证书链路：建容器→取公钥/P10→导入证书/PFX→登录→清理");
            W("  BjcaProbe pfximport <pfx路径> [口令] [--cleanup]  # 专项实测 ImportPfxToDevice 对不同 PFX 编码(PBES1/PBES2)的接受情况");
            break;
    }
}
catch (Exception ex)
{
    W("[异常] " + ex);
}
finally
{
    try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "bjca_probe_out.txt"), log.ToString(), Encoding.UTF8); }
    catch { }
}

static string FindDll(string explicitPath)
{
    if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath)) return explicitPath;

    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    string root = null;
    while (dir != null)
    {
        if (Directory.Exists(Path.Combine(dir.FullName, "Library"))) { root = dir.FullName; break; }
        dir = dir.Parent;
    }
    if (root == null) throw new DirectoryNotFoundException("未找到 Library 目录");

    var lib = Path.Combine(root, "Library");
    var hits = Directory.GetFiles(lib, "XTXAppCOM.dll", SearchOption.AllDirectories);
    if (hits.Length == 0) hits = Directory.GetFiles(lib, "XTXAppCOM_x64.dll", SearchOption.AllDirectories);
    if (hits.Length == 0) throw new FileNotFoundException($"在 {lib} 下未找到 XTXAppCOM.dll");
    // 优先取位于 ...\Program\ 下的（与 Driver\、Common\ 同级的正式布局）
    Array.Sort(hits, (a, b) => Score(b).CompareTo(Score(a)));
    return hits[0];

    static int Score(string p) => p.Contains(@"\Program\", StringComparison.OrdinalIgnoreCase) ? 2
        : p.Contains(@"BJCAClient", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
}

static void DumpTypeLib(Action<string> w, string ifFilter, string fnFilter)
{
    var dll = FindDll(null);
    w($"DLL: {dll}");
    w(new string('-', 100));
    foreach (var line in TypeLibDump.Dump(dll, ifFilter, fnFilter)) w(line);
}

static void Probe(Action<string> w, string dllArg)
{
    var dll = FindDll(dllArg);
    w($"DLL: {dll}");
    w($"进程位数: {(Environment.Is64BitProcess ? "x64" : "x86")}");
    w(new string('-', 100));

    var (module, self) = Com.CreateXtxApp(dll);
    w($"LoadLibrary         : OK (hModule=0x{module:X8})");
    w($"CreateInstance IXTXApp: OK (pUnk=0x{self:X8})");

    // 1) 校验「按名字导出」与「vtable 槽位」是否指向同一实现（slot = 6 + dispid）
    w("");
    w("== 导出地址 vs vtable 槽位（slot = 6 + dispid）==");
    (string Name, int Id)[] checks =
    {
        ("GetDeviceCount", 32), ("GetAllDeviceSN", 33), ("GetDeviceSNByIndex", 34),
        ("ChangeAdminPass", 36), ("UnlockUserPass", 37), ("UnlockUserPassEx", 72),
        ("InitDevice", 47), ("InitDeviceEx", 95), ("SOF_Login", 7), ("SOF_ChangePassWd", 9),
        ("DeleteContainer", 45), ("SOF_GetAllContainerName", 79), ("ImportPfxToDevice", 113),
        ("SOF_GetVersion", 56), ("SOF_GetLastError", 31),
    };
    IntPtr vt = Marshal.ReadIntPtr(self);
    int match = 0, total = 0;
    foreach (var (name, id) in checks)
    {
        IntPtr byName = Com.GetProcAddress(module, name);
        IntPtr bySlot = Marshal.ReadIntPtr(vt, (6 + id) * IntPtr.Size);
        total++;
        bool ok = byName == bySlot && byName != IntPtr.Zero;
        if (ok) match++;
        w($"  {name,-26} export=0x{byName:X8}  vtable[{6 + id}]=0x{bySlot:X8}  {(ok ? "一致" : "不一致")}");
    }
    w($"  => {match}/{total} 一致");

    // 2) 名称分发（GetIDsOfNames）验证
    var disp = (Com.IDispatch)Marshal.GetObjectForIUnknown(self);
    w("");
    w("== GetIDsOfNames 名称 -> dispid ==");
    foreach (var name in new[] { "GetDeviceCount", "InitDevice", "InitDeviceEx", "ChangeAdminPass", "UnlockUserPassEx", "SOF_Login", "SOF_GetVersion", "SOF_ChangePassWd", "GetAllDeviceSN", "EnumSupportDeviceList" })
    {
        var (hr, id) = Com.GetDispid(disp, name);
        w($"  {name,-26} hr=0x{hr:X8}  dispid={(hr == 0 ? id.ToString() : "-")}");
    }

    // 3) 调用几个无副作用的方法（IDispatch，ABI 无关，安全）
    w("");
    w("== 只读方法调用（IDispatch::Invoke）==");
    Call(w, disp, "GetDeviceCount", 32, Array.Empty<(short, object)>(), Com.VT_I4);
    Call(w, disp, "GetAllDeviceSN", 33, Array.Empty<(short, object)>(), Com.VT_BSTR);
    Call(w, disp, "SOF_GetVersion", 56, Array.Empty<(short, object)>(), Com.VT_BSTR);
    Call(w, disp, "SOF_GetProductVersion", 161, Array.Empty<(short, object)>(), Com.VT_BSTR);
    Call(w, disp, "EnumSupportDeviceList", 133, Array.Empty<(short, object)>(), Com.VT_BSTR);
    Call(w, disp, "SOF_GetLastError", 31, Array.Empty<(short, object)>(), Com.VT_I4);
    Call(w, disp, "SOF_GetLastErrMsg", 67, Array.Empty<(short, object)>(), Com.VT_BSTR);

    Com.Release(self);
    w("");
    w("done.");
}

static void Call(Action<string> w, Com.IDispatch disp, string name, int dispid,
                 (short Vt, object Value)[] args, short retVt)
{
    try
    {
        var (hr, ret, _) = Com.Invoke(disp, dispid, args, retVt);
        w($"  {name,-24} dispid={dispid,-4} hr=0x{hr:X8}  返回={(ret is string s ? $"[{s}]" : ret?.ToString() ?? "null")}");
    }
    catch (Exception ex)
    {
        w($"  {name,-24} dispid={dispid,-4} 异常: {ex.GetType().Name}: {ex.Message}");
    }
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

// ============================================================ 生产实现联调

static void ProviderSmoke(Action<string> w)
{
    var lib = FindLibraryRoot();
    using var prov = new USBKey.Core.UsbKey.BjcaProvider(lib);
    w($"Library        : {lib}");
    w($"IsAvailable    : {prov.IsAvailable}");
    w($"定位到的组件   : {prov.LocateDll()}");

    prov.Initialize();
    w($"组件版本       : {prov.ComponentVersion}（产品 {prov.ProductVersion}）");
    w($"支持设备类型   : {prov.SupportDeviceList}");
    w($"ResetRequiresCurrentPin : {prov.ResetRequiresCurrentPin}");

    var devs = prov.Enumerate();
    w($"枚举到设备     : {devs.Count} 台");
    foreach (var d in devs)
    {
        w($"  · {d}  Model={d.Model}  SN={d.SerialNumber}  VID/PID={d.Vid:X4}/{d.Pid:X4}  " +
          $"容量={(d.CapacityKb > 0 ? d.CapacityKb + "KB" : "-")}  固件={d.FirmwareVersion}");
        w($"    Notes: {d.Notes}");
        try
        {
            var cs = prov.ListContainers(d);
            w($"    容器/证书: {cs.Count} 个");
            foreach (var c in cs)
                w($"      - Name={c.Name}  ContainerName={c.ContainerName}  Subject={c.Subject}  " +
                  $"有效期={c.ValidityText}  算法={c.Algorithm}  指纹={c.Thumbprint}");
        }
        catch (Exception ex)
        {
            w($"    容器枚举失败: {ex.Message}");
        }
    }
    w("done.");
}

static void ResetTest(Action<string> w, string[] args)
{
    if (args.Length < 2)
    {
        w("用法: BjcaProbe reset <新用户PIN> [管理口令] [设备标签] --yes");
        return;
    }
    var newPin = args[1];
    var admin = args.Length > 2 && !args[2].StartsWith("--") ? args[2] : null;
    var label = args.Length > 3 && !args[3].StartsWith("--") ? args[3] : null;
    var confirmed = args.Any(a => string.Equals(a, "--yes", StringComparison.OrdinalIgnoreCase));

    var lib = FindLibraryRoot();
    using var prov = new USBKey.Core.UsbKey.BjcaProvider(lib);
    prov.Initialize();

    var devs = prov.Enumerate();
    if (devs.Count == 0) { w("未找到设备，已取消。"); return; }
    var dev = devs[0];

    w($"目标设备: {dev.SerialNumber}（{dev.Model}）");
    w($"新用户PIN: {new string('*', newPin.Length)}   管理口令: {(admin == null ? "(默认)" : new string('*', admin.Length))}   标签: {label ?? "(默认)"}");
    if (!confirmed)
    {
        w("这是**不可撤销**的操作（清空全部容器/证书/密钥并重设口令）。");
        w("确认无误请在命令末尾追加 --yes 重新执行。");
        return;
    }

    w("开始重置 ...");
    try
    {
        prov.ResetDevice(dev, newPin, label, admin, null);
        w("重置返回：成功");
    }
    catch (Exception ex)
    {
        w("重置失败: " + ex.Message);
    }
    w("");
    w("执行报告:");
    w(prov.LastResetReport ?? "(无)");

    var after = prov.Enumerate();
    foreach (var d in after)
        w($"重置后设备: {d.SerialNumber}  Model={d.Model}  Notes={d.Notes}");
    try
    {
        var cs = prov.ListContainers(dev);
        w($"重置后容器/证书数: {cs.Count}");
    }
    catch (Exception ex) { w("重置后容器枚举失败: " + ex.Message); }
    w("done.");
}

/// <summary>
/// 实测证书链路（会真实改写设备内容，默认在结束时清理自己创建的容器）：
/// 建容器 → 取公钥/PKCS#10 → 导入证书(ImportSignCert) → 导入 PFX(ImportPfxToDevice)
/// → SOF_Login 验证 → 改密(SOF_ChangePassWd) → 删除容器。
/// </summary>
static void CertTest(Action<string> w, string[] args)
{
    var userPin = args.Length > 1 && !args[1].StartsWith("--") ? args[1] : "123456";
    var cleanup = args.Any(a => string.Equals(a, "--cleanup", StringComparison.OrdinalIgnoreCase));
    var scan = args.Any(a => string.Equals(a, "--scan", StringComparison.OrdinalIgnoreCase));
    const string cn = "BJCATEST";
    var usedKeyType = -1;

    var dll = FindDll(null);
    var (module, self) = Com.CreateXtxApp(dll);
    var disp = (Com.IDispatch)Marshal.GetObjectForIUnknown(self);
    var B = Com.VT_BSTR; var I4 = Com.VT_I4; var BOOL = Com.VT_BOOL;

    object Call(int id, short retVt, params (short, object)[] a)
    {
        var (hr, ret, _) = Com.Invoke(disp, id, a, retVt);
        return hr == 0 ? ret : $"<Invoke 失败 hr=0x{hr:X8}>";
    }
    string S(int id, params (short, object)[] a) => Call(id, B, a) as string ?? "";
    int N(int id, params (short, object)[] a) => Call(id, I4, a) is int v ? v : -1;
    bool V(int id, params (short, object)[] a) => Call(id, BOOL, a) is int v && v != 0;
    void Show(string tag, object o) => w($"    {tag} = [{o}]");

    var all = S(33);
    var sn = all.Split(new[] { ';', '|', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";
    w($"设备 SN: {sn}");
    if (sn.Length == 0) { w("未找到设备"); return; }

    void DumpState(string title)
    {
        w($"-- {title} --");
        Show("GetContainerCount", N(62, (B, sn)));
        Show("SOF_GetAllContainerName", S(79, (B, sn)));
        Show("SOF_GetUserList", S(5));
        Show("EnumFilesInDevice", S(122, (B, sn)));
    }
    DumpState("初始状态");

    // ---------- 0) 试调用「非 IDispatch」的 SOF_Initialize（按导出名） ----------
    // 反汇编显示它内部建立 CKM/tokenman 上下文；若 SOF 系列 API 需要它先初始化，
    // SOF_GetUserList 之前一直为空就可能与此有关。
    w("");
    w("== 0) SOF_Initialize（按导出名调用，非 IDispatch）==");
    try
    {
        var pInit = Com.GetProcAddress(module, "SOF_Initialize");
        if (pInit == IntPtr.Zero)
        {
            w("    未找到 SOF_Initialize 导出");
        }
        else
        {
            var fn = (Com.SofInitializeFn)Marshal.GetDelegateForFunctionPointer(pInit, typeof(Com.SofInitializeFn));
            var appName = Marshal.StringToBSTR("USBKeyManager");
            var rc = fn(appName);
            Marshal.FreeBSTR(appName);
            w($"    SOF_Initialize(\"USBKeyManager\") → {rc}（0xC9=失败 / 0=成功）");
        }
    }
    catch (Exception ex) { w("    SOF_Initialize 调用异常: " + ex.Message); }
    w($"    SOF_Initialize 后 GetUserList=[{S(5)}]  GetDeviceCount={N(32)}");
    DumpState("SOF_Initialize 后");

    // ---------- 1) 建容器（卡上生成密钥对；RSA 生成较慢，默认只建一个） ----------
    w("");
    w("== 1) GenerateKeyPair（在卡内生成密钥对/建容器）==");
    if (scan)
    {
        var keyTypeResult = new List<string>();
        for (int kt = 0; kt <= 6; kt++)
        {
            var name = cn + kt;                       // 每个 keyType 用独立容器名，互不影响
            V(45, (B, sn), (B, name));
            var r = V(38, (B, sn), (B, name), (I4, kt), (BOOL, true));
            keyTypeResult.Add($"{kt}={(r ? "OK" : "-")}");
            if (!r) continue;
            if (usedKeyType < 0) usedKeyType = kt;
            else V(45, (B, sn), (B, name));            // 只保留第一个成功的
        }
        w("    keyType 扫描（bSign=true）: " + string.Join("  ", keyTypeResult));
        if (usedKeyType >= 0)
        {
            V(45, (B, sn), (B, cn));
            w($"    以 keyType={usedKeyType} 重建正式测试容器 [{cn}] → {(V(38, (B, sn), (B, cn), (I4, usedKeyType), (BOOL, true)) ? "成功" : "失败")}");
        }
    }
    else
    {
        w($"    清理同名容器 DeleteContainer({cn}) ...");
        V(45, (B, sn), (B, cn));
        w("    正在调用 GenerateKeyPair(dispid=38) —— 卡内生成密钥约 30~90 秒；");
        w("    若 BJCA 弹出自己的密码输入框（标题 inputpasswdui），请在该窗口输入用户 PIN。");
        var r = V(38, (B, sn), (B, cn), (I4, 1), (BOOL, true));   // keyType=1（卡上实测可用，RSA）
        w($"    GenerateKeyPair(keyType=1, bSign=true) → {(r ? "成功" : "失败")}");
        if (r) usedKeyType = 1;
    }

    if (usedKeyType < 0)
    {
        w("    建容器失败，后续步骤无法进行。");
        Com.Release(self);
        return;
    }
    w($"    使用 keyType={usedKeyType} 的容器 [{cn}]");
    DumpState("建容器后");

    // ---------- 2) 取公钥 / PKCS#10 ----------
    w("");
    w("== 2) ExportPubKey / ExportPKCS10 ==");
    var pub = S(39, (B, sn), (B, cn), (BOOL, true));
    w($"    ExportPubKey 长度={pub.Length}  前 120 字符: {Head(pub, 120)}");
    try
    {
        var pk = System.Security.Cryptography.X509Certificates.PublicKey
            .CreateFromSubjectPublicKeyInfo(Convert.FromBase64String(pub), out _);
        var desc = pk.Oid.FriendlyName ?? pk.Oid.Value;
        var rsaPub = pk.GetRSAPublicKey();
        if (rsaPub != null) desc += $"，RSA {rsaPub.KeySize} bit";
        w($"    公钥算法: {desc}");
    }
    catch (Exception ex) { w("    公钥解析失败: " + ex.Message); }
    var p10 = S(46, (B, sn), (B, cn), (B, "CN=BJCATEST,OU=Test,O=USBKeyDriver,C=CN"), (BOOL, true));
    w($"    ExportPKCS10 长度={p10.Length}  前 120 字符: {Head(p10, 120)}");

    // ---------- 3) 本机测试 CA 为设备 CSR 签发证书并导入 ----------
    w("");
    w("== 3) ImportSignCert（导入「本机测试 CA 为设备 CSR 签发」的证书）==");
    byte[] issuedDer = null;
    if (p10.Length == 0)
    {
        w("    没有拿到 PKCS#10，跳过。");
    }
    else
    {
        // 说明：这里刻意不调用 CertificateRequest.LoadSigningRequest —— 它要求 CSR 自带签名可在
        // 本机验证（设备未登录时私钥未必解锁，签名可能是占位值），且 RSA 场景还需正确的 padding 重载。
        // 测试 CA 关心的是「主体 + 公钥」，因此直接解析 CSR 结构即可。
        System.Security.Cryptography.X509Certificates.CertificateRequest csr = null;

        // 若 CSR 自带签名无法验证（例如卡未登录、私钥未解锁导致签名为占位值），
        // 退化为「只取 CSR 的主体与公钥，由测试 CA 直接签发」——这也是真实 CA 的常规做法
        // （CA 校验 CSR 签名仅为防篡改，导入到卡上的关键是公钥与卡内私钥匹配）。
        if (csr == null)
        {
            var parsed = ParseCsrWithoutVerify(Convert.FromBase64String(p10));
            if (parsed == null)
            {
                w("    CSR 无法解析，跳过导入。");
            }
            else
            {
                w($"    CSR 自带签名未通过本机校验，改用「仅取主体+公钥」方式签发（主体={parsed.Value.Subject.Name}）");
                csr = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    parsed.Value.Subject, parsed.Value.Key,
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            }
        }

        if (csr != null)
        {
            try
            {
                using var caKey = System.Security.Cryptography.RSA.Create(2048);
                var caReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    "CN=BJCA Probe Test CA", caKey,
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                caReq.CertificateExtensions.Add(
                    new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
                caReq.CertificateExtensions.Add(
                    new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                        System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyCertSign |
                        System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.CrlSign, true));
                using var caCert = caReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(10));

                var serial = new byte[8];
                System.Security.Cryptography.RandomNumberGenerator.Fill(serial);
                using var issued = csr.Create(caCert, DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddYears(1), serial);
                issuedDer = issued.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
                w($"    测试 CA 已为设备 CSR 签发出 {issuedDer.Length} 字节证书");
            }
            catch (Exception ex)
            {
                w($"    用测试 CA 签发证书失败: {ex.Message.Split('\n')[0]}");
            }
        }
    }

    if (issuedDer != null)
    {
        var b64 = Convert.ToBase64String(issuedDer);
        var ok1 = V(40, (B, sn), (B, cn), (B, b64));
        w($"    ImportSignCert（base64 DER）→ {(ok1 ? "成功" : "失败")}");
        if (!ok1 && S(5).Length == 0)
        {
            var pem = "-----BEGIN CERTIFICATE-----\n" + string.Join("\n", Chunk(b64, 64)) + "\n-----END CERTIFICATE-----\n";
            w($"    ImportSignCert（PEM）→ {(V(40, (B, sn), (B, cn), (B, pem)) ? "成功" : "失败")}");
        }
        if (ok1)
        {
            // 导入后尝试刷新证书缓存（SOF_UpdateCert，dispid 118），看是否能让 SOF_GetUserList 出现条目
            Show($"    SOF_UpdateCert({cn}, type=0)", N(118, (B, cn), (I4, 0)));
            Show($"    SOF_UpdateCert({cn}, type=1)", N(118, (B, cn), (I4, 1)));

            // 以「证书内容（base64）」为入参的接口不需要 CertID，可直接验证证书解析能力
            w("    —— 以「证书内容」为入参的接口（无需 CertID）——");
            for (short t = 0; t <= 20; t++)
            {
                var v = S(10, (B, b64), (Com.VT_I2, (int)t));
                if (v.Length > 0) Show($"      SOF_GetCertInfo(type={t})", Head(v, 90));
            }
            Show("      SOF_ValidateCert", N(58, (B, b64)));
            Show("      SOF_GetCertEntity", Head(S(91, (B, b64)), 100));
            Show("      SOF_GetCertInfoByOid(2.5.4.3)", Head(S(11, (B, b64), (B, "2.5.4.3")), 80));
            Show("      SOF_GetLastLoginCertID", S(151));

            // 用 GetPinRetryCount 当「CertID 是否有效」的廉价探针（有效则返回非负重试次数）
            w("    —— CertID 格式试探（用 SOF_GetPinRetryCount 判定有效性：-8 表示 CertID 无效）——");
            foreach (var cand in new[]
                     {
                         cn, cn + "|0", cn + ":0", cn + "_0", cn + "0",
                         "0", "1", "2", sn + ":" + cn, sn + "|" + cn,
                         b64.Substring(0, Math.Min(64, b64.Length)),
                     })
                w($"      试探 '{Head(cand, 40),-42}' → GetPinRetryCount = {N(8, (B, cand))}");
        }
        DumpState("导入证书后");
    }

    // SOF_GetUserList 在实测中始终为空，因此把「容器名」也作为 CertID 候选一并尝试
    var idCandidates = new List<string>();
    foreach (var part in S(5).Split(new[] { ';', '|', ',', '&' }, StringSplitOptions.RemoveEmptyEntries))
    {
        var t = part.Trim();
        if (t.Length > 0 && !idCandidates.Contains(t)) idCandidates.Add(t);
    }
    foreach (var part in S(79, (B, sn)).Split(new[] { '&', ';', '|', ',' }, StringSplitOptions.RemoveEmptyEntries))
    {
        var t = part.Trim();
        if (t.Length > 0 && !idCandidates.Contains(t)) idCandidates.Add(t);
    }
    if (issuedDer != null) idCandidates.Add(Convert.ToBase64String(issuedDer)); // 也试试直接给证书内容
    w($"    CertID 候选（GetUserList ∪ 容器名 ∪ 证书内容）: {(idCandidates.Count == 0 ? "(空)" : string.Join(" / ", idCandidates.Select(x => Head(x, 32))))}");

    foreach (var id in idCandidates)
    {
        var exported = S(6, (B, id));
        w($"    SOF_ExportUserCert({id}) 长度={exported.Length}  前 80 字符: {Head(exported, 80)}");
        if (issuedDer != null && exported.Length > 0)
        {
            var back = SafeCert(exported);
            w($"      与导入证书一致性: {(back != null && back.Equals(Convert.ToBase64String(issuedDer)) ? "一致 ✔" : "不一致")}" +
              (back == null ? "（回读内容无法解析为 X.509）" : ""));
        }
        if (exported.Length > 0)
        {
            w($"      SOF_GetCertEntity → {Head(S(91, (B, exported)), 100)}");
            for (short t = 0; t <= 8; t++)
                Show($"  GetCertInfo(type={t})", Head(S(10, (B, exported), (Com.VT_I2, (int)t)), 90));
        }
        Show($"  SOF_GetPinRetryCount({id})", N(8, (B, id)));
    }

    // ---------- 4) 导入 PFX（ImportPfxToDevice，用全新容器名） ----------
    w("");
    w("== 4) ImportPfxToDevice（导入 PFX，容器名 BJCAPFX）==");
    const string pfxCn = "BJCAPFX";
    int beforePfxCount = N(62, (B, sn));
    string pfxB64;
    try
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=BJCATEST", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
        var pfx = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "1234");
        pfxB64 = Convert.ToBase64String(pfx);
        w($"    本地生成测试 PFX：{pfx.Length} 字节（口令 1234）");
        // 用全新容器名试（避免与已有容器/密钥冲突）
        V(45, (B, sn), (B, pfxCn));
        var ok = V(113, (B, sn), (B, pfxCn), (BOOL, true), (B, pfxB64), (B, "1234"));
        w($"    容器不存在时 ImportPfxToDevice(bSign=true) → {(ok ? "成功" : "失败")}");
        if (!ok)
            w($"    改 bSign=false 再试 → {(V(113, (B, sn), (B, pfxCn), (BOOL, false), (B, pfxB64), (B, "1234")) ? "成功" : "失败")}");
        var afterPfxCount = N(62, (B, sn));
        w($"    容器数 前={beforePfxCount} 后={afterPfxCount}；新容器名列表={S(79, (B, sn))}");
        w($"    PFX 容器内是否形成可用证书（SOF_GetUserList）={S(5)}");
        DumpState("导入 PFX 后");
    }
    catch (Exception ex) { w("    生成本地 PFX 失败: " + ex.Message); }

    // ---------- 5) 登录 / 改密（依次尝试每个 CertID 候选） ----------
    w("");
    w("== 5) SOF_Login / SOF_ChangePassWd ==");
    var loggedInId = "";
    var pinCandidates = new List<string> { userPin };
    if (userPin != "111111") pinCandidates.Add("111111");   // BJCA 出厂默认用户 PIN
    foreach (var id in idCandidates)
    {
        w($"    尝试 CertID = {Head(id, 40)}");
        Show("      SOF_GetPinRetryCount", N(8, (B, id)));
        foreach (var p in pinCandidates)
        {
            var login = V(7, (B, id), (B, p));
            w($"      SOF_Login(PIN={new string('*', p.Length)}) → {(login ? "成功" : "失败")}  GetLastErrMsg={S(67)}");
            if (login) { loggedInId = id; break; }
        }
        if (loggedInId.Length > 0)
        {
            Show("      SOF_IsLogin", V(131, (B, id)));
            break;
        }
    }

    if (loggedInId.Length > 0)
    {
        var newPin = userPin == "123456" ? "654321" : "123456";
        var cp = V(9, (B, loggedInId), (B, userPin), (B, newPin));
        w($"    SOF_ChangePassWd({new string('*', userPin.Length)} → {new string('*', newPin.Length)}) → {(cp ? "成功" : "失败")}");
        if (cp)
        {
            Show("      改后复验(新PIN)", V(7, (B, loggedInId), (B, newPin)));
            Show("      改回原PIN", V(9, (B, loggedInId), (B, newPin), (B, userPin)));
        }
        Show("    SOF_Logout", V(85, (B, loggedInId)));
    }
    else if (idCandidates.Count == 0)
    {
        w("    没有可用的 CertID 候选，无法测试登录/改密");
    }
    else
    {
        w("    所有 CertID 候选登录均失败");
    }

    // ---------- 6) 删除 / 清理 ----------
    w("");
    w("== 6) DeleteContainer ==");
    if (cleanup)
    {
        foreach (var name in new[] { cn, pfxCn })
        {
            w($"    IsContainerExist({name}) = {V(44, (B, sn), (B, name))}");
            w($"    DeleteContainer({name}) → {(V(45, (B, sn), (B, name)) ? "成功" : "失败")}");
        }
        w($"    DeleteOldContainer → {(V(73, (B, sn)) ? "成功" : "失败")}");
        DumpState("清理后");
    }
    else
    {
        w($"    跳过（未指定 --cleanup）。测试容器 [{cn}]/[{pfxCn}] 保留在设备上，如需删除请加 --cleanup 重跑。");
    }

    Com.Release(self);
    w("done.");
}

/// <summary>
/// 专项实测 <c>ImportPfxToDevice</c> 对不同 PFX 编码格式的接受情况。
///
/// <para><b>动机</b>：07 文档记的结论是「BJCA 不支持导入外部 PFX（含私钥）」，
/// 但那是从一次失败倒推出来的；而组件 trace 日志显示失败点其实是内部
/// <c>PKCS12_parse</c>（<b>解析</b>阶段），根本没走到「卡是否肯写入」这一步。
/// 原测试代码用 <c>X509Certificate2.Export(X509ContentType.Pfx, pwd)</c>，
/// 它在 .NET 5+ 上默认产出 <b>PBES2（PBKDF2 + AES-256 + SHA256）</b>，
/// 而 <c>PKCS12_parse</c> 属 OpenSSL 老 API，不认 PBES2。</para>
///
/// <para>因此这里用<b>同样内容、但编码为 PBES1（3DES + SHA1）</b>的老式 PFX 重试，
/// 以判定究竟是「PFX 编码格式问题」还是「设备确实不支持导入私钥」。</para>
///
/// <para>用法：<c>BjcaProbe pfximport &lt;pfx路径&gt; [口令] [--cleanup]</c></para>
/// </summary>
static void PfxImportTest(Action<string> w, string[] args)
{
    var pfxPath = args.Length > 1 ? args[1] : "";
    var pwd = args.Length > 2 && !args[2].StartsWith("--") ? args[2] : "1234";
    var cleanup = args.Any(a => string.Equals(a, "--cleanup", StringComparison.OrdinalIgnoreCase));
    if (!File.Exists(pfxPath)) { w($"找不到 PFX 文件：{pfxPath}"); return; }

    var dll = FindDll(null);
    var (module, self) = Com.CreateXtxApp(dll);
    var disp = (Com.IDispatch)Marshal.GetObjectForIUnknown(self);
    var B = Com.VT_BSTR; var I4 = Com.VT_I4; var BOOL = Com.VT_BOOL;

    object Call(int id, short retVt, params (short, object)[] a)
    {
        var (hr, ret, _) = Com.Invoke(disp, id, a, retVt);
        return ret;
    }
    string S(int id, params (short, object)[] a) => Call(id, B, a) as string ?? "";
    int N(int id, params (short, object)[] a) => Call(id, I4, a) is int v ? v : -1;
    bool V(int id, params (short, object)[] a) => Call(id, BOOL, a) is int v && v != 0;

    var sn = S(33).Split(new[] { ';', '|', ',' }, StringSplitOptions.RemoveEmptyEntries)
                  .FirstOrDefault()?.Trim() ?? "";
    w($"设备 SN: {sn}");
    if (sn.Length == 0) { w("未找到设备"); return; }

    const string pfxCn = "BJCAPFXTEST";
    var pfx = File.ReadAllBytes(pfxPath);
    var b64 = Convert.ToBase64String(pfx);
    w($"PFX      : {Path.GetFileName(pfxPath)}  {pfx.Length} 字节  口令={new string('*', pwd.Length)}");
    w($"目标容器 : {pfxCn}");
    w($"导入前   : 容器数={N(62, (B, sn))}  GetAllContainerName=[{S(79, (B, sn))}]");

    w("");
    w("== ImportPfxToDevice(bSign=true) ==");
    var ok = V(113, (B, sn), (B, pfxCn), (BOOL, true), (B, b64), (B, pwd));
    w($"结果 = {(ok ? "成功" : "失败")}   GetLastError={N(31)}   GetLastErrMsg=[{S(67)}]");

    if (!ok)
    {
        w("");
        w("== ImportPfxToDevice(bSign=false) 再试 ==");
        var ok2 = V(113, (B, sn), (B, pfxCn), (BOOL, false), (B, b64), (B, pwd));
        w($"结果 = {(ok2 ? "成功" : "失败")}   GetLastErrMsg=[{S(67)}]");
    }

    w("");
    w($"导入后   : 容器数={N(62, (B, sn))}  GetAllContainerName=[{S(79, (B, sn))}]");
    w($"           SOF_GetUserList=[{S(5)}]");

    if (cleanup)
    {
        w("");
        w("== 清理 ==");
        w($"  IsContainerExist({pfxCn}) = {V(44, (B, sn), (B, pfxCn))}");
        w($"  DeleteContainer({pfxCn}) → {(V(45, (B, sn), (B, pfxCn)) ? "成功" : "失败")}");
        w($"  清理后容器数 = {N(62, (B, sn))}  GetAllContainerName=[{S(79, (B, sn))}]");
    }
    else
    {
        w("");
        w("未指定 --cleanup；若已建出测试容器会留在卡上（名字见上）。");
    }

    Com.Release(self);
    w("done.");
}

static string Head(string s, int n) => s == null ? "" : (s.Length <= n ? s : s[..n] + "…");

/// <summary>
/// 不校验签名，仅从 PKCS#10 中取出「主体名」与「公钥」。
/// 用于设备产出的 CSR 自带签名无法在本机验证（例如未登录导致签名为占位值）的场景。
/// </summary>
static (System.Security.Cryptography.X509Certificates.X500DistinguishedName Subject,
        System.Security.Cryptography.X509Certificates.PublicKey Key)? ParseCsrWithoutVerify(byte[] der)
{
    try
    {
        var reader = new System.Formats.Asn1.AsnReader(der, System.Formats.Asn1.AsnEncodingRules.DER);
        var top = reader.ReadSequence();                 // CertificationRequest
        var cri = top.ReadSequence();                    // CertificationRequestInfo
        cri.ReadInteger();                               // version
        var subjectDer = cri.PeekEncodedValue().ToArray();
        cri.ReadEncodedValue();
        var spkiDer = cri.PeekEncodedValue().ToArray();
        cri.ReadEncodedValue();

        var subject = new System.Security.Cryptography.X509Certificates.X500DistinguishedName(subjectDer);
        var key = System.Security.Cryptography.X509Certificates.PublicKey
            .CreateFromSubjectPublicKeyInfo(spkiDer, out _);
        return (subject, key);
    }
    catch
    {
        return null;
    }
}

/// <summary>把证书文本（裸 base64 / PEM）规整为规范 base64 DER，用于一致性比对；失败返回 null。</summary>
static string SafeCert(string text)
{
    try
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        if (t.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            var sb = new System.Text.StringBuilder();
            foreach (var line in t.Split('\n'))
            {
                var l = line.Trim();
                if (l.Length == 0 || l.StartsWith("-----", StringComparison.Ordinal)) continue;
                sb.Append(l);
            }
            t = sb.ToString();
        }
        t = new string(t.Where(c => !char.IsWhiteSpace(c)).ToArray());
        using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(Convert.FromBase64String(t));
        return Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
    }
    catch { return null; }
}

static IEnumerable<string> Chunk(string s, int n)
{
    for (int i = 0; i < s.Length; i += n) yield return s.Substring(i, Math.Min(n, s.Length - i));
}

static void ReadOnlyExplore(Action<string> w, string dllArg)
{
    var dll = FindDll(dllArg);
    w($"DLL: {dll}");
    w("正在激活组件...");
    var (module, self) = Com.CreateXtxApp(dll);
    w($"激活成功 pUnk=0x{self:X8}");
    var disp = (Com.IDispatch)Marshal.GetObjectForIUnknown(self);

    void C(string name, int dispid, (short, object)[] a, short retVt)
    {
        w($"  -> 调用 {name} ...");
        try
        {
            var (hr, ret, _) = Com.Invoke(disp, dispid, a, retVt);
            var txt = ret is string s ? s : ret?.ToString() ?? "null";
            w($"     {name}(dispid={dispid}) hr=0x{hr:X8} => [{txt}]");
        }
        catch (Exception ex)
        {
            w($"     {name}(dispid={dispid}) 异常: {ex.Message}");
        }
    }

    var bstr = Com.VT_BSTR;
    C("SOF_GetVersion", 56, Array.Empty<(short, object)>(), bstr);
    C("SOF_GetProductVersion", 161, Array.Empty<(short, object)>(), bstr);
    C("EnumSupportDeviceList", 133, Array.Empty<(short, object)>(), bstr);
    C("GetDeviceCount", 32, Array.Empty<(short, object)>(), Com.VT_I4);
    C("GetAllDeviceSN", 33, Array.Empty<(short, object)>(), bstr);
    C("GetDeviceCountEx(0)", 116, new (short, object)[] { (Com.VT_I4, 0) }, Com.VT_I4);
    C("GetDeviceCountEx(1)", 116, new (short, object)[] { (Com.VT_I4, 1) }, Com.VT_I4);
    C("GetAllDeviceSNEx(0)", 117, new (short, object)[] { (Com.VT_I4, 0) }, bstr);

    string allSn = null;
    try { allSn = (string)Com.Invoke(disp, 33, Array.Empty<(short, object)>(), bstr).RetVal; } catch { }
    var snList = (allSn ?? "").Split(new[] { ';', ',', '|', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                              .Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
    w($"解析到序列号 {snList.Count} 个: {string.Join(" / ", snList)}");

    foreach (var sn in snList.Take(3))
    {
        w("");
        w($"---- 设备 {sn} ----");
        C("IsDeviceExist", 61, new (short, object)[] { (bstr, sn) }, Com.VT_BOOL);
        for (int t = 0; t <= 8; t++)
            C($"GetDeviceInfo(type={t})", 35, new (short, object)[] { (bstr, sn), (Com.VT_I4, t) }, bstr);
        C("GetContainerCount", 62, new (short, object)[] { (bstr, sn) }, Com.VT_I4);
        C("SOF_GetAllContainerName", 79, new (short, object)[] { (bstr, sn) }, bstr);
        C("EnumFilesInDevice", 122, new (short, object)[] { (bstr, sn) }, bstr);
        C("GetENVSN", 59, new (short, object)[] { (bstr, sn) }, bstr);
    }

    w("");
    w("---- 用户/证书（不登录）----");
    C("SOF_GetUserList", 5, Array.Empty<(short, object)>(), bstr);
    C("SOF_SelectFile", 96, Array.Empty<(short, object)>(), bstr);
    C("SOF_IsLogin", 131, new (short, object)[] { (bstr, "") }, Com.VT_BOOL);
    C("SOF_GetLastError", 31, Array.Empty<(short, object)>(), Com.VT_I4);
    C("SOF_GetLastErrMsg", 67, Array.Empty<(short, object)>(), bstr);

    Com.Release(self);
    w("");
    w("done.");
}
