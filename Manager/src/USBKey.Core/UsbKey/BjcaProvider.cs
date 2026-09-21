using System.Security.Cryptography.X509Certificates;
using System.Text;
using USBKey.Core.Common;
using USBKey.Core.Configuration;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 北京数字认证（BJCA）USB Key 平台对接实现。
///
/// <para><b>对接目标</b>：<c>XTXAppCOM.dll</c>（32 位）/ <c>XTXAppCOM_x64.dll</c>（64 位），
/// 即随 BJCA「证书助手/客户端（CertAppEnv）」分发的统一客户端组件。</para>
///
/// <para><b>能力来源</b>：该组件面向应用层暴露了一套与厂商无关的 USB Key 管理接口
/// （<c>IXTXApp</c>，见 <c>Roadmap/07-BJCA逆向分析与对接.md</c>），因此一个 provider 即可覆盖
/// BJCA 所支持的全部设备型号（中孚、飞天、林果、天地融、握奇… by <c>Driver\driver.ini</c> 自动分派）。</para>
///
/// <para><b>关键约束</b>：驱动 DLL 分 32/64 位；管理器宿主为 x86，故默认加载 <c>XTXAppCOM.dll</c>。
/// 组件线程模型为 Apartment，所有调用在 <see cref="BjcaSession"/> 的 STA 工作线程上串行执行。</para>
/// </summary>
public sealed class BjcaProvider : IKeyProvider
{
    /// <summary>平台名（config.json 的 platform / keyslist 键名）。</summary>
    public const string Platform = "bjca";

    /// <summary>厂商显示名。</summary>
    public const string VendorDisplay = "北京数字认证（BJCA）";

    /// <summary>
    /// 未提供管理口令时使用的默认「管理口令（SO PIN）」。
    /// <para>
    /// BJCA 组件 <c>InitDevice</c> 内部固定使用用户 PIN <c>111111</c> 与标签 <c>BJCA-UserKey</c>
    /// （反汇编常量，见 <c>Roadmap/07-BJCA逆向分析与对接.md</c>）；管理口令出厂值未在二进制中固化，
    /// 这里取与之一致的 <c>111111</c> 作为默认值，调用失败时会在异常信息中给出真实返回码，
    /// 提示用户显式填写管理口令。
    /// </para>
    /// </summary>
    public const string DefaultAdminPin = "111111";

    /// <summary>默认用户 PIN 长度上限（XTXAppCOM.ini 的 PinRules 为 ^.{6,16}$）。</summary>
    private const int PinMaxLen = 16;

    private const int PinMinLen = 6;

    private readonly string _libraryRoot;
    private readonly List<UsbDeviceDef> _whitelist;

    private BjcaSession? _session;
    private string _dllPath = "";
    private string? _resolvedDll;
    private readonly object _sync = new();

    /// <summary>序列号 → 最近一次登录使用的 CertID（登出/改密需要）。</summary>
    private readonly Dictionary<string, string> _loginCert = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>最近一次「重置（初始化）」的报告，供 UI 展示。</summary>
    public string? LastResetReport { get; private set; }

    public string PlatformName => Platform;

    /// <summary>BJCA 为 SO PIN（管理口令）模型：真正的令牌初始化，无需当前用户 PIN。</summary>
    public bool ResetRequiresCurrentPin => false;

    /// <summary>
    /// 导入 PFX 只用「序列号 + PFX 密码」（SOF_ImportPfxToDevice），不依赖登录会话：
    /// 空卡上用户 PIN 无从校验，但导入本身是允许尝试的。
    /// </summary>
    public bool ImportRequiresLogin => false;

    /// <summary>支持「卡内生成密钥对 → 导出 PKCS#10 → 导回 CA 签发证书」的建证流程。</summary>
    public bool SupportsKeyEnrollment => true;

    /// <param name="libraryRoot">驱动 DLL 根目录（通常是软件的 <c>Library</c> 目录）。</param>
    /// <param name="whitelist">config.keyslist.bjca 的 VID/PID 白名单（为空则不按 VID/PID 过滤）。</param>
    public BjcaProvider(string libraryRoot, IEnumerable<UsbDeviceDef>? whitelist = null)
    {
        _libraryRoot = libraryRoot ?? "";
        _whitelist = whitelist?.ToList() ?? new List<UsbDeviceDef>();
    }

    /// <summary>组件版本（SOF_GetVersion）。</summary>
    public string ComponentVersion => _session?.Version ?? "";

    /// <summary>产品版本（SOF_GetProductVersion，如 3.7.418.0052）。</summary>
    public string ProductVersion => _session?.ProductVersion ?? "";

    /// <summary>组件声明的支持设备类型（如 <c>6588_1514&amp;&amp;&amp;</c>）。</summary>
    public string SupportDeviceList => _session?.SupportDeviceList ?? "";

    // ============================================================ 定位与初始化

    public bool IsAvailable
    {
        get
        {
            if (_session != null) return true;
            return LocateDll() != null;
        }
    }

    /// <summary>
    /// 定位组件 DLL。查找顺序：
    /// <list type="number">
    /// <item><b>注册表已安装的 BJCA 客户端</b>（<c>HKLM\SOFTWARE\BJCA\InstallPath</c>，由官方安装包写入）——
    /// 设备的读卡/驱动栈本身就要求先安装厂商客户端，优先复用最稳妥；</item>
    /// <item><c>&lt;Library&gt;\BJCA\XTXAppCOM[_x64].dll</c>（随软件分发的绿色目录）；</item>
    /// <item>递归查找 <c>&lt;Library&gt;</c> 下同名文件，优先 <c>...\Program\</c> 正式安装布局。</item>
    /// </list>
    /// </summary>
    public string? LocateDll()
    {
        if (_resolvedDll != null) return _resolvedDll;
        lock (_sync)
        {
            if (_resolvedDll != null) return _resolvedDll;
            _resolvedDll = LocateDllCore();
            return _resolvedDll;
        }
    }

    private string? LocateDllCore()
    {
        var name = Environment.Is64BitProcess ? BjcaNative.DllNameX64 : BjcaNative.DllNameX86;

        // 1) 注册表中已安装的 BJCA 客户端
        var installed = TryRegistryDll(name);
        if (installed != null) return installed;

        // 2) Library 下的约定目录
        var roots = new List<string>();
        if (!string.IsNullOrWhiteSpace(_libraryRoot))
        {
            roots.Add(Path.Combine(_libraryRoot, "BJCA"));
            roots.Add(_libraryRoot);
            roots.Add(Path.Combine(_libraryRoot, "BJCA USBKEY DRIVER"));
        }
        roots.Add(AppPaths.LibraryDir);

        foreach (var r in roots)
        {
            var direct = Path.Combine(r, name);
            if (File.Exists(direct)) return direct;
        }

        // 3) 递归查找
        foreach (var root in roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            FileInfo[] hits;
            try { hits = new DirectoryInfo(root).GetFiles(name, SearchOption.AllDirectories); }
            catch { continue; }
            if (hits.Length == 0) continue;
            return hits
                .OrderByDescending(f => f.FullName.Contains(@"\Program\", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(f => f.FullName.Contains("CertAppEnv", StringComparison.OrdinalIgnoreCase))
                .First().FullName;
        }
        return null;
    }

    /// <summary>读取注册表 <c>HKLM\SOFTWARE\BJCA\InstallPath</c>（32 位进程自动重定向到 WOW6432Node）。</summary>
    private static string? TryRegistryDll(string dllName)
    {
        foreach (var sub in new[] { @"SOFTWARE\BJCA\InstallPath", @"SOFTWARE\WOW6432Node\BJCA\InstallPath" })
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(sub);
                if (key?.GetValue("InstallPath") is not string path || string.IsNullOrWhiteSpace(path)) continue;
                foreach (var rel in new[] { "Program", "" })
                {
                    var full = Path.Combine(path, rel, dllName);
                    if (File.Exists(full)) return full;
                }
            }
            catch { /* 忽略并继续 */ }
        }
        return null;
    }

    public void Initialize()
    {
        if (_session != null) return;
        var path = LocateDll()
            ?? throw new FileNotFoundException(
                $"未找到 BJCA 客户端组件 {(Environment.Is64BitProcess ? BjcaNative.DllNameX64 : BjcaNative.DllNameX86)}。" +
                "请把 BJCA「证书助手（CertAppEnv）」的 Program 与 Driver 目录放到 Library\\BJCA\\ 下。");

        _dllPath = path;
        var session = new BjcaSession(path);
        session.GetDeviceCount(); // 触发一次真实调用，尽早暴露问题
        _session = session;

        Log.Write($"[BJCA] 组件已加载：{path}");
        Log.Write($"[BJCA] 版本 {session.Version}（产品 {session.ProductVersion}），支持设备 {session.SupportDeviceList}");
    }

    private BjcaSession Session
    {
        get
        {
            if (_session == null) Initialize();
            return _session!;
        }
    }

    // ============================================================ 设备枚举 / 详情

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var result = new List<UsbKeyDevice>();
        var s = Session;

        var count = s.GetDeviceCount();
        var all = s.GetAllDeviceSN();
        var snList = SplitList(all.Value);

        if (count.RetVt == BjcaNative.VT_I4 && count.IntValue > snList.Count)
        {
            for (int i = snList.Count; i < count.IntValue; i++)
            {
                var one = s.GetDeviceSNByIndex(i);
                if (!string.IsNullOrWhiteSpace(one.Value)) snList.Add(one.Value!.Trim());
            }
        }

        foreach (var sn in snList.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try { result.Add(BuildDevice(s, sn)); }
            catch (Exception ex) { Log.Error(ex, $"[BJCA] 读取设备 {sn} 信息失败"); }
        }

        // VID/PID 白名单过滤（config.keyslist.bjca 只填了非零 VID/PID 时才生效）
        var wl = _whitelist.Where(w => w.VidInt > 0 || w.PidInt > 0)
                           .Select(w => (w.VidInt, w.PidInt)).ToList();
        if (wl.Count > 0)
            result = result.Where(d => wl.Any(x => (x.VidInt == 0 || x.VidInt == d.Vid) &&
                                                   (x.PidInt == 0 || x.PidInt == d.Pid))).ToList();
        return result;
    }

    private static UsbKeyDevice BuildDevice(BjcaSession s, string sn)
    {
        var dev = new UsbKeyDevice
        {
            Platform = Platform,
            VendorName = VendorDisplay,
            SerialNumber = sn,
            Handle = 0,
        };

        // GetDeviceInfo 的 iType 语义为实测推断（见 Roadmap 文档 § 设备信息字段）
        var label = s.GetDeviceInfo(sn, 1).Value;
        var capacity = s.GetDeviceInfo(sn, 2).Value;
        var alg = s.GetDeviceInfo(sn, 4).Value;
        var adminRetry = s.GetDeviceInfo(sn, 5).Value;
        var userRetry = s.GetDeviceInfo(sn, 6).Value;
        var hardType = s.GetDeviceInfo(sn, 7).Value;
        var driverDll = s.GetDeviceInfo(sn, 8).Value;

        dev.Model = string.IsNullOrWhiteSpace(label) ? "BJCA USBKey" : label!;
        dev.FirmwareVersion = string.IsNullOrWhiteSpace(hardType) ? "" : hardType!;
        if (long.TryParse(capacity, out var bytes) && bytes > 0)
            dev.CapacityKb = bytes / 1024;

        var notes = new List<string>();
        if (!string.IsNullOrWhiteSpace(alg)) notes.Add($"算法 {alg}");
        if (!string.IsNullOrWhiteSpace(driverDll)) notes.Add($"驱动 {driverDll}");
        if (!string.IsNullOrWhiteSpace(adminRetry)) notes.Add($"管理口令重试 {adminRetry}");
        if (!string.IsNullOrWhiteSpace(userRetry)) notes.Add($"用户口令重试 {userRetry}");
        dev.Notes = string.Join("；", notes);

        // 从驱动 DLL 名（如 lgu3073_p1514_gm.dll）推断 PID，配合支持列表推断 VID
        var (vid, pid) = GuessVidPid(s.SupportDeviceList, driverDll);
        dev.Vid = vid;
        dev.Pid = pid;
        return dev;
    }

    /// <summary>从支持列表（形如 6588_1514&amp;&amp;&amp;）与驱动 DLL 名推断 VID/PID。</summary>
    private static (int Vid, int Pid) GuessVidPid(string? supportList, string? driverDll)
    {
        int vid = 0, pid = 0;
        // 驱动 DLL 名里的 _pNNNN_ / _PIDNNNN_ 给出 PID
        if (!string.IsNullOrWhiteSpace(driverDll))
        {
            var m = System.Text.RegularExpressions.Regex.Match(driverDll!, @"[_-]p(?:id)?([0-9a-fA-F]{4})[_-]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success) pid = Convert.ToInt32(m.Groups[1].Value, 16);
        }

        foreach (var item in SplitList(supportList))
        {
            var parts = item.Split('_');
            if (parts.Length < 2) continue;
            if (!int.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber, null, out var v)) continue;
            if (!int.TryParse(parts[1], System.Globalization.NumberStyles.HexNumber, null, out var p)) continue;
            if (pid == 0 || p == pid) { vid = v; pid = p; break; }
            if (vid == 0) { vid = v; pid = p; }
        }
        return (vid, pid);
    }

    /// <summary>BJCA 的列表串分隔符不统一（设备序列号用 ';'，支持列表用 '&amp;&amp;&amp;'），做容错切分。</summary>
    internal static List<string> SplitList(string? raw)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(raw)) return list;
        var s = raw.Replace("&&&", ";").Replace("\r", ";").Replace("\n", ";")
                   .Replace("|", ";").Replace(",", ";").Replace("\t", ";");
        foreach (var part in s.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = part.Trim();
            if (t.Length > 0 && !list.Contains(t, StringComparer.OrdinalIgnoreCase)) list.Add(t);
        }
        return list;
    }

    public UsbKeyDevice Open(int handleOrSerial)
    {
        var devs = Enumerate();
        if (devs.Count == 0) throw new InvalidOperationException("未找到已连接的 BJCA USB Key");
        if (handleOrSerial >= 0 && handleOrSerial < devs.Count) return devs[handleOrSerial];
        return devs[0];
    }

    public UsbKeyDevice GetDetail(UsbKeyDevice device)
    {
        var s = Session;
        if (string.IsNullOrWhiteSpace(device.SerialNumber)) return device;
        var fresh = BuildDevice(s, device.SerialNumber);
        device.Model = fresh.Model;
        device.Notes = fresh.Notes;
        device.CapacityKb = fresh.CapacityKb;
        device.FirmwareVersion = fresh.FirmwareVersion;
        device.Vid = fresh.Vid;
        device.Pid = fresh.Pid;
        return device;
    }

    // ============================================================ 登录 / 登出

    /// <summary>
    /// PIN 登录。BJCA 的 PIN 校验是「按证书/容器」进行的：先用 <c>SOF_GetUserList</c>
    /// 取得设备上的证书 ID，再用 <c>SOF_Login(CertID, PIN)</c> 验证。
    /// </summary>
    public void Login(UsbKeyDevice device, string pin)
    {
        Validators.EnsurePin(pin);
        var s = Session;
        var certIds = GetCertIds(s, device.SerialNumber);
        if (certIds.Count == 0)
            throw new InvalidOperationException(
                "该 USB Key 上还没有证书/容器，无法登录。\n\n" +
                "原因：BJCA 的用户 PIN 是「按证书/容器」逐个校验的（SOF_Login(CertID, PIN)），\n" +
                "空卡上没有任何可认证的对象，所以此时不需要（也无法）登录。\n\n" +
                "下一步（都不需要先登录）：\n" +
                "  · 初始化这张新卡 → 点「重置设备」；\n" +
                "  · 给卡上建证书 → 点「证书登记」：卡内生成密钥 → 导出 PKCS#10 交 CA 签发 → 导回证书。\n" +
                "    注意：本设备的私钥在卡内生成、不可导入，因此「导入证书(PFX)」通常不适用。");

        var errors = new List<string>();
        foreach (var id in certIds)
        {
            var r = s.Login(id, pin);
            if (r.BoolValue)
            {
                _loginCert[device.SerialNumber] = id;
                device.IsLoggedIn = true;
                Log.Write($"[BJCA] {device.SerialNumber} 登录成功（CertID={id}）");
                return;
            }
            var retry = s.GetPinRetryCount(id);
            var diag = s.DescribeLastError();
            errors.Add($"{id}：剩余重试 {retry.Value}" + (string.IsNullOrEmpty(diag) ? "" : $"，{diag}"));
        }

        var remain = s.GetPinRetryCount(certIds[0]);
        throw new InvalidOperationException(
            $"PIN 认证失败（剩余重试次数 {remain.Value}）。" + Environment.NewLine +
            string.Join(Environment.NewLine, errors));
    }

    public void Logout(UsbKeyDevice device)
    {
        if (_session == null) { device.IsLoggedIn = false; return; }
        if (_loginCert.TryGetValue(device.SerialNumber, out var id))
        {
            try { _session.Logout(id); } catch (Exception ex) { Log.Error(ex, "[BJCA] 登出失败"); }
            _loginCert.Remove(device.SerialNumber);
        }
        device.IsLoggedIn = false;
    }

    /// <summary>取设备上的证书/容器 ID 列表（SOF_GetUserList，为空时退回 GetAllContainerName）。</summary>
    private static List<string> GetCertIds(BjcaSession s, string sn)
    {
        var ids = SplitList(s.GetUserList().Value);
        if (ids.Count == 0) ids = SplitList(s.GetAllContainerName(sn).Value);
        return ids;
    }

    /// <summary>
    /// 把「证书 ID / 容器名」归一成<b>容器身份</b>，用于跨两个数据源去重。
    /// <para>
    /// 踩过的坑：<c>SOF_GetUserList</c> 返回的条目形如 <c>UserKey/5303201812001784</c>
    /// （容器名 + '/' + 设备序列号），而 <c>SOF_GetAllContainerName</c> 返回的是纯容器名
    /// <c>UserKey</c>。两者直接比较永远不相等，于是<b>同一个容器会被列出两次</b>：
    /// 一条带证书，另一条标成"容器（无证书）"。
    /// 界面上表现为"只建了一个证书，却看到多个条目"。
    /// </para>
    /// </summary>
    private static string ContainerKey(string? idOrName)
    {
        var v = (idOrName ?? "").Trim();
        var slash = v.IndexOf('/');
        return slash > 0 ? v[..slash].Trim() : v;
    }

    // ============================================================ 证书 / 容器

    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device)
    {
        var s = Session;
        var sn = device.SerialNumber;
        var result = new List<KeyContainer>();
        // 去重键用「归一后的容器身份」，避免 "UserKey/序列号" 与 "UserKey" 被当成两个容器
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 原始数据先落日志：这两套列表的条目格式不一致（见 ContainerKey 的说明），
        // 现场排查"一个证书显示成多个容器"时必须能看到卡上真正返回了什么。
        var userListRaw = s.GetUserList().Value ?? "";
        var containerRaw = s.GetAllContainerName(sn).Value ?? "";
        Log.Write($"[BJCA] {sn} 原始列表：SOF_GetUserList=\"{userListRaw}\" / " +
                  $"SOF_GetAllContainerName=\"{containerRaw}\"");
        // 卡上真实存在的容器实体（用于识别"悬空条目"，见步骤 3）
        var realContainers = SplitList(containerRaw);

        // 1) 证书 ID（来自 SOF_GetUserList）：能导出证书，信息最完整
        var certIds = SplitList(userListRaw);
        if (certIds.Count == 0) certIds = SplitList(containerRaw);
        foreach (var id in certIds)
        {
            KeyContainer c;
            try
            {
                var b64 = s.ExportUserCert(id).Value;
                var der = TryDecodeCertificate(b64);
                if (der != null)
                {
                    c = BuildContainer(der, id);
                    c.Content = KeyContainerContent.Certificate;
                }
                else
                {
                    // 有 CertID 却取不到证书内容：条目确实存在，但内容不可读
                    c = new KeyContainer { Name = "", ContainerName = id, ContainerUuid = id, Content = KeyContainerContent.Unknown };
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"[BJCA] 导出证书 {id} 失败");
                c = new KeyContainer { Name = "", ContainerName = id, ContainerUuid = id, Content = KeyContainerContent.Unknown };
            }
            c.ContainerName = id;
            if (string.IsNullOrEmpty(c.ContainerUuid)) c.ContainerUuid = id;
            if (string.IsNullOrEmpty(c.Algorithm)) c.Algorithm = s.GetDeviceInfo(sn, 4).Value ?? "";
            seen.Add(ContainerKey(id));
            result.Add(c);
        }

        // 2) 容器列表（有容器实体：先按 CertID 约定尝试取证书，取不到才退化为「未知」）
        foreach (var cn in realContainers)
        {
            if (seen.Contains(ContainerKey(cn))) continue;
            seen.Add(ContainerKey(cn));

            // 兜底：SOF_GetUserList 实测会返回空（本卡如此），此时一个证书 ID 都拿不到，
            // 列表只能退化成「容器（无证书）」—— 明明卡上有证书却显示不出来，非常误导。
            // 但 BJCA 的 CertID 构成方式是确定的：「容器名/设备序列号」
            // （现场 trace 日志中 CXTXApp::SOF_ExportUserCert 收到的正是 UserKey/5303201812001784）。
            // 因此按该约定自行构造 CertID 再导出证书，即可绕开那个不靠谱的列表接口。
            var byConvention = TryExportCertificateByConvention(s, cn, sn);
            if (byConvention != null)
            {
                result.Add(byConvention);
                continue;
            }

            // 确实取不到证书。注意：BJCA 组件未暴露「容器内是否已有密钥」的查询接口
            // （可作为判据的只有 IsContainerExist / GetContainerCount，都不涉及密钥）；
            // 而 ExportPubKey 之类探测在组件需要口令时会弹出它自带的密码框
            // （见 Roadmap/07 §8.5），不适合在列表枚举里调用。
            // 因此这里诚实标为「未知」，只在算法列写明「容器（无证书）」；
            // 需要精确区分「仅密钥 / 空容器」时，切到 SKF 链路查看同一张卡。
            result.Add(new KeyContainer
            {
                Name = "",
                ContainerName = cn,
                ContainerUuid = cn,
                Content = KeyContainerContent.Unknown,
                Algorithm = "容器（无证书）",
            });
        }

        // 3) 过滤「悬空条目」
        //
        // 实测本卡：SOF_GetUserList = "Test User||UserKey/5303201812001784"，
        // 而 SOF_GetAllContainerName = "UserKey"。裸名 "Test User" 出现在用户列表里，
        // 却没有任何对应的容器实体、也导不出证书内容 —— 这是早先导入 PFX 失败留下的残留
        // （当时拿 PFX 的 CN 当容器名去建容器，失败后用户列表条目没被清掉，
        //   见 ImportPfx / CleanupEmptyContainer）。
        // 它既不是证书也不是容器，列出来只会让人以为"多了一个证书"。
        //
        // 2026-09-21 复测修正：原先这里有个 `realContainers.Count > 0` 的前置条件
        // （当时担心 GetAllContainerName 本身不可靠时把有效条目一并误删），
        // 但它带来一个更糟的后果：**卡内容器被清空后（realContainers 为空）过滤整体失效**，
        // 残留条目会重新出现在列表里。
        //
        // 现场表现即为「用 SKF 删掉容器后，BJCA 下仍然列出证书」：
        //   SOF_GetUserList        = "Test User||UserKey/5303201812001784&&&"   ← 不随卡内容器变化
        //   SOF_GetAllContainerName = ""                                        ← 卡上已无容器
        // 这两条都是「BJCA 自己那份记录」的产物，卡上其实什么都没有；而且拿它们去删除必然失败
        // （MainForm 的回退逻辑会在 SKF 侧找不到同名容器而报 0x0A00002E），非常误导。
        //
        // 改为始终过滤，判据只保留两条，且刻意不用「名字里是否含 "/"」来豁免：
        // 现场实测 SOF_GetUserList 的缓存条目正是 "UserKey/5303201812001784" 这种含 "/" 的形式，
        // 一旦卡内容器被删除，它同样属于残留 —— 若按旧规则豁免就永远清不掉。
        // 安全网：
        //   1) 能成功导出证书的条目会被标为 Certificate，永不进入过滤（这是最关键的一道）；
        //   2) realContainers 来自 SOF_GetAllContainerName，实测是实时读卡的真值
        //      （SKF 删掉容器后它立即变空），因此可用作「卡上是否真有该容器」的判据。
        // 被过滤的条目不静默丢弃，写日志便于现场追查。
        var dangling = result
            .Where(c => c.Content != KeyContainerContent.Certificate
                        && !realContainers.Contains(ContainerKey(c.ContainerName), StringComparer.OrdinalIgnoreCase))
            .ToList();
        foreach (var c in dangling)
        {
            Log.Write($"[BJCA] {sn} 跳过悬空条目 \"{c.ContainerName}\"（卡上无对应容器、也导不出证书，多为失败操作残留）");
            result.Remove(c);
        }

        foreach (var c in result)
        {
            if (!string.IsNullOrEmpty(c.Thumbprint))
                c.IsRegisteredInCsp = Crypto.CertHelper.IsRegistered(c.Thumbprint);
        }
        return result;
    }

    /// <summary>
    /// 按 BJCA 的 CertID 约定「容器名/设备序列号」构造 CertID 并尝试导出证书。
    ///
    /// <para><b>为什么需要它</b>：证书 ID 的正规来源是 <c>SOF_GetUserList</c>，
    /// 但实测本卡该接口返回空（同一组件在不同进程里时而返回内容、时而返回空，不可依赖）。
    /// 一旦为空，列表就只能退化成「容器（无证书）」—— 卡上明明有证书却显示不出来。
    /// 而 CertID 的构成方式是确定的：现场 trace 日志
    /// （<c>C:\BJCAROOT\BJCAlog\xtx\XTXAppCOM.log</c>）里
    /// <c>CXTXApp::SOF_ExportUserCert</c> 收到的就是 <c>UserKey/5303201812001784</c>，
    /// 即「容器名 + '/' + 设备序列号」。据此自行构造即可绕开那个不靠谱的列表接口。</para>
    ///
    /// <para>失败返回 <c>null</c>（容器内确实没有证书），由调用方继续走兜底显示。</para>
    /// </summary>
    private static KeyContainer? TryExportCertificateByConvention(BjcaSession s, string containerName, string sn)
    {
        var certId = $"{ContainerKey(containerName)}/{sn}";
        try
        {
            var der = TryDecodeCertificate(s.ExportUserCert(certId).Value);
            if (der == null) return null;
            var c = BuildContainer(der, certId);
            c.Content = KeyContainerContent.Certificate;
            Log.Write($"[BJCA] {sn} 经 CertID 约定取到证书：{certId}");
            return c;
        }
        catch (Exception ex)
        {
            Log.Write($"[BJCA] {sn} 按约定 {certId} 取证书未成功（属正常：该容器可能确实无证书）：{ex.Message}");
            return null;
        }
    }

    private static KeyContainer BuildContainer(byte[] certDer, string containerName)
    {
        using var cert = new X509Certificate2(certDer);
        return new KeyContainer
        {
            Name = cert.GetNameInfo(X509NameType.SimpleName, false),
            ContainerName = containerName,
            ContainerUuid = containerName,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            Algorithm = $"{cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value}",
            KeyUsage = "数字签名",
            ExtendedKeyUsage = "—",
            CertRaw = certDer,
        };
    }

    /// <summary>BJCA 的证书输出可能是裸 base64，也可能是 PEM，这里做兼容解码。</summary>
    internal static byte[]? TryDecodeCertificate(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            var t = text.Trim();
            if (t.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                var sb = new StringBuilder();
                foreach (var line in t.Split('\n'))
                {
                    var l = line.Trim();
                    if (l.Length == 0 || l.StartsWith("-----", StringComparison.Ordinal)) continue;
                    sb.Append(l);
                }
                t = sb.ToString();
            }
            t = new string(t.Where(ch => !char.IsWhiteSpace(ch)).ToArray());
            var der = Convert.FromBase64String(t);
            using var _ = new X509Certificate2(der); // 校验确实是证书
            return der;
        }
        catch
        {
            return null;
        }
    }

    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword)
    {
        var s = Session;
        var pfx = File.ReadAllBytes(pfxPath);
        string containerName;
        bool sign = true;
        try
        {
            using var cert = new X509Certificate2(pfx, pfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            containerName = cert.GetNameInfo(X509NameType.SimpleName, false);
            if (string.IsNullOrWhiteSpace(containerName)) containerName = cert.Thumbprint;
            var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            // 仅有 KeyEncipherment 的证书按加密证书导入
            if (ku != null && (ku.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                sign = false;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("读取 PFX 失败：" + ex.Message, ex);
        }

        var b64 = Convert.ToBase64String(pfx);
        var r = s.ImportPfxToDevice(device.SerialNumber, containerName, sign, b64, pfxPassword);
        if (!r.BoolValue)
        {
            var r2 = s.ImportPfxToDevice(device.SerialNumber, containerName, !sign, b64, pfxPassword);
            if (!r2.BoolValue)
            {
                // 实机（林果 LG3073）结论：ImportPfxToDevice 失败时仍可能在设备上留下一个「空容器」，
                // 必须清理，否则会污染设备状态。
                CleanupEmptyContainer(s, device.SerialNumber, containerName);

                var hasCert = !string.IsNullOrWhiteSpace(s.GetUserList().Value);
                if (!hasCert)
                {
                    throw new NotSupportedException(
                        "该 BJCA USBKey 不支持把「外部 PFX（含私钥）」导入卡内，导入返回失败：" + Describe(s) +
                        Environment.NewLine + Environment.NewLine +
                        "原因：USBKey 的私钥在卡内生成、不可导出也不可导入（安全设计）。" + Environment.NewLine +
                        Environment.NewLine +
                        "正确做法：点操作栏的「证书登记」，按向导走三步 ——" + Environment.NewLine +
                        "  ① 在卡内生成密钥对（RSA 2048，约 30~90 秒）；" + Environment.NewLine +
                        "  ② 导出 PKCS#10 证书请求（CSR），交给 CA 签发；" + Environment.NewLine +
                        "  ③ 把 CA 签发的证书导回卡内（SOF_ImportSignCert）。");
                }
                throw new InvalidOperationException("导入 PFX 失败：" + Describe(s));
            }
        }
        Log.Write($"[BJCA] 已导入 PFX → 容器 {containerName}（sign={sign}）");
    }

    /// <summary>删除失败操作留下的空容器（仅当容器内没有形成证书时）。</summary>
    private static void CleanupEmptyContainer(BjcaSession s, string sn, string containerName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(containerName)) return;
            if (!s.IsContainerExist(sn, containerName).BoolValue) return;
            s.DeleteContainer(sn, containerName);
            Log.Write($"[BJCA] 已清理导入失败留下的空容器 {containerName}");
        }
        catch (Exception ex) { Log.Error(ex, "[BJCA] 清理空容器失败"); }
    }

    // ============================================================ 卡内密钥 / 证书请求（BJCA 的正确「导入证书」流程）

    /// <summary>
    /// 在设备内生成密钥对（建容器）。<b>该操作在卡内生成 RSA 密钥，耗时约 30~90 秒</b>；
    /// 若组件需要用户 PIN，它会弹出<b>自身的密码输入框</b>（窗口类 <c>#32770</c>，标题 <c>inputpasswdui</c>），
    /// 因此必须在有界面的进程中调用（无界面/服务场景会被阻塞）。
    /// </summary>
    /// <param name="containerName">容器名（建议英文/数字，长度不宜过长）。</param>
    /// <param name="keyType">密钥类型：实测 林果 LG3073 上 1/2/3 可用、0/4/5/6 失败（1 为 RSA）。</param>
    /// <param name="sign">true=签名密钥，false=加密密钥。</param>
    public void GenerateKeyPair(UsbKeyDevice device, string containerName, int keyType = 1, bool sign = true)
    {
        var s = Session;
        var r = s.GenerateKeyPair(device.SerialNumber, containerName, keyType, sign);
        if (!r.BoolValue)
            throw new InvalidOperationException($"在设备内生成密钥对失败（keyType={keyType}）：" + Describe(s));
        Log.Write($"[BJCA] 已生成密钥对 → 容器 {containerName}（keyType={keyType}, sign={sign}）");
    }

    /// <summary>导出设备内密钥对的公钥（base64，SubjectPublicKeyInfo）。</summary>
    public string ExportPublicKey(UsbKeyDevice device, string containerName, bool sign = true)
    {
        var r = Session.ExportPubKey(device.SerialNumber, containerName, sign);
        if (string.IsNullOrWhiteSpace(r.Value))
            throw new InvalidOperationException("导出公钥失败：" + Describe(Session));
        return r.Value!;
    }

    /// <summary>
    /// 导出 PKCS#10 证书请求（base64 DER）。把 CSR 交给 CA 签发后，
    /// 用 <see cref="ImportCertificate"/> 把证书导回设备，即完成「导入证书」。
    /// </summary>
    public string ExportPkcs10(UsbKeyDevice device, string containerName, string dn, bool sign = true)
    {
        var r = Session.ExportPkcs10(device.SerialNumber, containerName, dn, sign);
        if (string.IsNullOrWhiteSpace(r.Value))
            throw new InvalidOperationException("导出 PKCS#10 失败：" + Describe(Session));
        return r.Value!;
    }

    /// <summary>
    /// 导入证书到指定容器（base64 DER，或 PEM 文本）。
    /// 证书公钥必须与容器内密钥对匹配，否则组件会拒绝（实测确认）。
    /// </summary>
    public void ImportCertificate(UsbKeyDevice device, string containerName, string certBase64OrPem)
    {
        var r = Session.ImportSignCert(device.SerialNumber, containerName, certBase64OrPem);
        if (!r.BoolValue)
        {
            var r2 = Session.ImportSignCert(device.SerialNumber, containerName, certBase64OrPem.Trim());
            if (!r2.BoolValue)
                throw new InvalidOperationException("导入证书失败（证书公钥需与容器内密钥匹配）：" + Describe(Session));
        }
        Log.Write($"[BJCA] 已导入证书 → 容器 {containerName}");
    }

    /// <summary>删除设备上的容器（清空其实体密钥与证书）。</summary>
    public void RemoveContainer(UsbKeyDevice device, string containerName)
    {
        var r = Session.DeleteContainer(device.SerialNumber, containerName);
        if (!r.BoolValue)
            throw new InvalidOperationException($"删除容器 {containerName} 失败：" + Describe(Session));
    }

    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath)
    {
        var der = container.CertRaw;
        if (der == null)
        {
            var b64 = Session.ExportUserCert(container.ContainerName).Value;
            der = TryDecodeCertificate(b64);
        }
        if (der == null) throw new InvalidOperationException("无法获取证书内容（设备返回为空或格式无法解析）");
        File.WriteAllBytes(outputPath, der);
    }

    public void ViewCertificate(KeyContainer container)
    {
        var der = container.CertRaw;
        if (der == null)
        {
            der = TryDecodeCertificate(Session.ExportUserCert(container.ContainerName).Value);
        }
        if (der == null) throw new InvalidOperationException("无法获取证书内容");
        var tmp = Path.Combine(Path.GetTempPath(), $"bjca_{Guid.NewGuid():N}.cer");
        File.WriteAllBytes(tmp, der);
        Crypto.CertHelper.ViewCertificateFile(tmp);
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container)
    {
        var r = Session.DeleteContainer(device.SerialNumber, container.ContainerName);
        if (!r.BoolValue)
        {
            // BJCA 组件只对「本通道创建的容器」有删除权：对由 SKF 通道创建、或出厂/银行预置的容器，
            // 组件会直接拒绝并置 SOF_GetLastErrMsg = "删除容器失败"。
            // 其官方错误码表（BjcaCertAide/errorinfo.json → 0x0B000028）给出的处置建议即为
            // 「是否有此容器；没有此容器删除权限，需厂商删除」，可佐证这不是参数问题而是权限问题。
            throw new InvalidOperationException(
                $"删除容器「{container.ContainerName}」失败：{Describe(Session)}" + Environment.NewLine +
                Environment.NewLine +
                "原因：BJCA 组件的删除权限仅覆盖「该通道自己创建的容器」。" + Environment.NewLine +
                "· 若该容器是经「SKF 通用」通道创建的（同一张卡的另一个链路），此通道删不掉；" + Environment.NewLine +
                "· 若为出厂/银行预置容器，则需厂商权限。" + Environment.NewLine +
                Environment.NewLine +
                "建议：同一张卡若有「SKF 通用」平台条目，改到该平台下删除（SKF_DeleteContainer 权限完整，已实测可用）。");
        }
        Log.Write($"[BJCA] 已删除容器 {container.ContainerName}");
    }

    public void RegisterToCsp(KeyContainer container)
    {
        if (container.CertRaw == null) throw new InvalidOperationException("证书数据不可用");
        Crypto.CertHelper.Register(container.CertRaw, container.Name);
        container.IsRegisteredInCsp = true;
    }

    public void UnregisterFromCsp(KeyContainer container)
    {
        if (!string.IsNullOrEmpty(container.Thumbprint))
            Crypto.CertHelper.UnregisterByThumbprint(container.Thumbprint);
        container.IsRegisteredInCsp = false;
    }

    // ============================================================ 口令 / 解锁 / 重置

    /// <summary>修改用户 PIN（对应 BJCA 的 SOF_ChangePassWd，按 CertID 生效）。</summary>
    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin)
    {
        Validators.EnsurePin(newPin);
        var s = Session;
        var certIds = _loginCert.TryGetValue(device.SerialNumber, out var cur)
            ? new List<string> { cur }
            : GetCertIds(s, device.SerialNumber);
        if (certIds.Count == 0)
            throw new InvalidOperationException("设备上未找到证书/容器，无法修改用户 PIN");

        var errs = new List<string>();
        foreach (var id in certIds)
        {
            var r = s.ChangePassWd(id, oldPin, newPin);
            if (r.BoolValue) { Log.Write($"[BJCA] {device.SerialNumber} 用户 PIN 已修改（CertID={id}）"); return; }
            errs.Add($"{id}：剩余重试 {s.GetPinRetryCount(id).Value}，{Describe(s)}");
        }
        throw new InvalidOperationException("修改用户 PIN 失败：" + Environment.NewLine + string.Join(Environment.NewLine, errs));
    }

    /// <summary>
    /// 解锁（重设）用户 PIN。BJCA 使用「管理口令」通道：<c>UnlockUserPassEx(sn, 管理口令, 新PIN)</c>。
    /// </summary>
    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin)
    {
        Validators.EnsurePin(newPin);
        var s = Session;
        switch (method)
        {
            case UnlockMethod.Puk:
            case UnlockMethod.AdminKey:
                {
                    var r = s.UnlockUserPassEx(device.SerialNumber, credential, newPin);
                    if (!r.BoolValue) r = s.UnlockUserPass(device.SerialNumber, credential, newPin);
                    if (!r.BoolValue)
                        throw new InvalidOperationException("解锁失败（管理口令不正确或设备不支持）：" + Describe(s));
                    device.IsLoggedIn = true;
                    Log.Write($"[BJCA] {device.SerialNumber} 用户 PIN 已通过管理口令重设");
                    return;
                }
            case UnlockMethod.Challenge:
                throw new NotSupportedException(
                    "挑战码解锁仅 BJCA OTP/蓝牙 Key 型号支持（OTP_GetChallengeCodeEx + OTP_GetSyncCode），" +
                    "当前设备不支持。");
            default:
                throw new ArgumentOutOfRangeException(nameof(method));
        }
    }

    public string GenerateChallenge(UsbKeyDevice device)
    {
        var s = Session;
        var certIds = GetCertIds(s, device.SerialNumber);
        if (certIds.Count == 0) throw new InvalidOperationException("设备上未找到证书/容器，无法生成挑战码");
        var r = s.GetChallengeCode(certIds[0]);
        if (string.IsNullOrWhiteSpace(r.Value))
            throw new NotSupportedException("该设备未返回挑战码（仅 OTP 类 USBKey 支持）：" + Describe(s));
        return r.Value!;
    }

    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin)
    {
        throw new NotSupportedException("挑战码响应解锁需设备侧同步码（OTP_GetSyncCode），当前型号未开放此通道。");
    }

    /// <summary>
    /// 重置（初始化）设备：<b>清空全部容器/证书/密钥</b>并<b>重设管理口令与用户 PIN</b>。
    ///
    /// <para><b>实现</b>：调用 BJCA 的 <c>InitDeviceEx(sn, 管理口令, 用户PIN, 标签, 管理口令重试上限, 用户PIN重试上限)</c>，
    /// 失败时回退到 <c>InitDevice(sn, 管理口令)</c>（内部固定使用用户 PIN <c>111111</c> 与标签 <c>BJCA-UserKey</c>）。</para>
    ///
    /// <para><b>入参映射</b>：<paramref name="adminKey"/>（管理口令/SO PIN）
    /// → <c>sAdminPass</c>；<paramref name="newPin"/> → <c>sUserPin</c>；
    /// <paramref name="puk"/> 若提供则作为 <c>sKeyLabel</c>（设备标签）使用；
    /// <paramref name="currentPin"/> 仅在未给 <paramref name="adminKey"/> 时作为管理口令的候选值。</para>
    /// </summary>
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null,
        string? currentPin = null)
    {
        Validators.EnsurePin(newPin);
        if (newPin.Length > PinMaxLen)
            throw new InvalidOperationException($"新 PIN 长度不能超过 {PinMaxLen} 位（BJCA 组件 PinRules 为 {{{PinMinLen},{PinMaxLen}}}）");

        var s = Session;
        var sn = device.SerialNumber;
        var label = string.IsNullOrWhiteSpace(puk) ? BjcaNative.DefaultKeyLabel : puk!.Trim();

        var adminCandidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(adminKey)) adminCandidates.Add(adminKey!.Trim());
        if (!string.IsNullOrWhiteSpace(currentPin) && !adminCandidates.Contains(currentPin!.Trim()))
            adminCandidates.Add(currentPin!.Trim());
        if (adminCandidates.Count == 0) adminCandidates.Add(DefaultAdminPin);

        var report = new List<string>
        {
            $"设备序列号 : {sn}",
            $"密钥标签   : {label}",
            $"用户 PIN   : {Mask(newPin)}",
        };

        var before = s.GetContainerCount(sn);
        var beforeCert = s.GetAllContainerName(sn).Value ?? "";
        report.Add($"重置前容器数: {before.Value}" + (string.IsNullOrEmpty(beforeCert) ? "" : $"（{beforeCert}）"));

        var failures = new List<string>();
        foreach (var admin in adminCandidates)
        {
            report.Add($"使用管理口令: {Mask(admin)}");

            var r = s.InitDeviceEx(sn, admin, newPin, label, 10, 10);
            report.Add($"  InitDeviceEx(sn, 管理口令, 用户PIN, 标签, 10, 10) → {(r.BoolValue ? "成功" : "失败")} {Describe(s)}");
            if (r.BoolValue) { ResetOk(); return; }

            var r2 = s.InitDevice(sn, admin);
            report.Add($"  InitDevice(sn, 管理口令) → {(r2.BoolValue ? "成功" : "失败")} {Describe(s)}");
            if (r2.BoolValue) { ResetOk(); return; }

            failures.Add($"管理口令 {Mask(admin)} 失败：{Describe(s)}");
        }

        LastResetReport = string.Join(Environment.NewLine, report);
        var afterFail = s.GetContainerCount(sn);
        report.Add($"重置后容器数: {afterFail.Value}");
        throw new InvalidOperationException(
            "重置设备失败：管理口令不正确，或该型号不支持远程初始化。" + Environment.NewLine +
            string.Join(Environment.NewLine, failures) + Environment.NewLine +
            "提示：请在重置对话框中显式填写该 USBKey 的「管理口令（SO PIN）」。");

        void ResetOk()
        {
            var afterCount = s.GetContainerCount(sn);
            var afterNames = s.GetAllContainerName(sn).Value ?? "";
            report.Add($"重置后容器数: {afterCount.Value}" + (string.IsNullOrEmpty(afterNames) ? "" : $"（{afterNames}）"));

            // 用新用户 PIN 复验一次（BJCA 无容器时无法用 SOF_Login 验证，此时仅记录）
            var certIds = GetCertIds(s, sn);
            if (certIds.Count > 0)
            {
                var v = s.Login(certIds[0], newPin);
                report.Add($"新用户 PIN 复验（SOF_Login）→ {(v.BoolValue ? "成功" : "失败")} {Describe(s)}");
            }
            else
            {
                report.Add("新用户 PIN 复验: 设备上已无容器，用户 PIN 将在首次创建容器时生效");
            }

            _loginCert.Remove(sn);
            device.IsLoggedIn = true;
            LastResetReport = string.Join(Environment.NewLine, report);
            Log.Write("[BJCA] 重置完成：" + Environment.NewLine + LastResetReport);
        }
    }

    private static string Describe(BjcaSession s)
    {
        var d = s.DescribeLastError();
        return string.IsNullOrEmpty(d) ? "" : $"[{d}]";
    }

    private static string Mask(string secret) => new string('*', Math.Max(1, secret.Length));

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
