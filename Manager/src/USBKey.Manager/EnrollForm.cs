using System.Text;
using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.UsbKey;

namespace USBKey.Manager;

/// <summary>
/// 证书登记向导：<b>卡内生成密钥对 → 导出 PKCS#10/公钥 → 把 CA 签发的证书导回设备</b>。
/// <para>
/// 为什么需要这个界面：BJCA / SKF 这类 USBKey 的私钥在卡内生成、<b>不可导出也不可导入</b>，
/// 所以"导入 PFX"对它们本来就不是可行路径（SKF 直接不支持）。
/// 之前界面只给了「导入证书(PFX)」和「登录」两个入口，
/// 于是空卡上必然陷入「登录失败 → 导入按钮灰掉 → 无路可走」的死锁。
/// 这里把真正可用的三步流程显式给出来。
/// </para>
/// <para>
/// 注意：这些调用必须在<b>有消息泵的 UI 线程</b>上执行——BJCA 组件在生成密钥时会弹出
/// 自己的密码输入框（窗口类 #32770），在无界面线程上会被阻塞。
/// </para>
/// </summary>
internal sealed class EnrollForm : Form
{
    private readonly IKeyProvider _prov;
    private readonly UsbKeyDevice _dev;

    private readonly TextBox _txtContainer = new();
    private readonly TextBox _txtDn = new();
    private readonly CheckBox _chkSign = new();
    private readonly CheckBox _chkEcc = new();
    private readonly ComboBox _cmbBits = new();
    private readonly Button _btnGen = new(), _btnExport = new(), _btnImport = new(), _btnClose = new();
    private readonly TextBox _log = new();

    public EnrollForm(IKeyProvider prov, UsbKeyDevice dev)
    {
        _prov = prov;
        _dev = dev;

        Text = "证书登记（卡内生成密钥 → 交给 CA 签发 → 导回设备）";
        ClientSize = new Size(660, 520);
        MinimumSize = new Size(660, 520);
        Font = new Font("Microsoft YaHei UI", 9F);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        BuildUi();
        Write($"设备：{PlatformInfo.DisplayName(dev.Platform)} · {dev.SerialNumber}（{dev.Model}）");
        Write($"平台能力：导入外部 PFX = {(_prov.SupportsImportPfx ? "支持" : "不支持（私钥卡内生成，不可导入）")}");
        Write($"本次流程：{(IsBjca ? "BJCA：生成密钥对 → 导出 PKCS#10 → 导入签发证书" : "SKF：创建容器 → 生成密钥对 → 导入签发证书")}");
        Write("");
        Write("提示：生成密钥对在卡内完成，通常需要 30~90 秒，期间请勿拔卡。");
    }

    private bool IsBjca => _prov is BjcaProvider;
    private bool IsSkf => _prov is SkfProvider;

    private void BuildUi()
    {
        int y = 10;

        // ---- 容器名 ----
        Controls.Add(new Label { Text = "容器名:", Left = 12, Top = y + 3, Width = 62 });
        _txtContainer.Left = 78; _txtContainer.Top = y; _txtContainer.Width = 200;
        _txtContainer.Text = "UserKey";
        Controls.Add(_txtContainer);

        _chkSign.Text = "签名证书";
        _chkSign.Checked = true;
        _chkSign.Left = 292; _chkSign.Top = y + 2; _chkSign.Width = 88;
        Controls.Add(_chkSign);

        Controls.Add(new Label { Text = "密钥:", Left = 386, Top = y + 3, Width = 34 });
        _cmbBits.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbBits.Left = 422; _cmbBits.Top = y; _cmbBits.Width = 96;
        _cmbBits.Items.AddRange(new object[] { "RSA 2048", "RSA 1024" });
        _cmbBits.SelectedIndex = 0;
        Controls.Add(_cmbBits);

        _chkEcc.Text = "ECC/SM2";
        _chkEcc.Left = 526; _chkEcc.Top = y + 2; _chkEcc.Width = 90;
        _chkEcc.Enabled = IsSkf; // BJCA 组件未暴露 ECC 建密钥接口
        Controls.Add(_chkEcc);

        y += 32;

        // ---- 步骤 1 ----
        Controls.Add(new Label
        {
            Text = "① 在卡内生成密钥对",
            Left = 12, Top = y, Width = 300,
            Font = new Font(Font, FontStyle.Bold),
        });
        y += 24;
        _btnGen.Text = "生成密钥对";
        _btnGen.Left = 12; _btnGen.Top = y; _btnGen.Width = 110; _btnGen.Height = 30;
        _btnGen.Click += (s, e) => DoGenerate();
        Controls.Add(_btnGen);
        Controls.Add(new Label
        {
            Text = IsSkf ? "（会先创建容器再生成密钥，耗时 30~90 秒）" : "（耗时 30~90 秒，组件可能弹出自己的密码框）",
            Left = 130, Top = y + 7, Width = 500, ForeColor = Color.Gray,
        });
        y += 42;

        // ---- 步骤 2 ----
        Controls.Add(new Label
        {
            Text = IsBjca ? "② 导出 PKCS#10 证书请求，交给 CA 签发" : "② 导出公钥（SKF 无 PKCS#10 接口）",
            Left = 12, Top = y, Width = 420,
            Font = new Font(Font, FontStyle.Bold),
        });
        y += 24;
        Controls.Add(new Label { Text = "主体 DN:", Left = 12, Top = y + 3, Width = 62 });
        _txtDn.Left = 78; _txtDn.Top = y; _txtDn.Width = 300;
        _txtDn.Text = "CN=Test User,O=Test Org,C=CN";
        _txtDn.Enabled = IsBjca;
        Controls.Add(_txtDn);
        _btnExport.Text = IsBjca ? "导出 P10..." : "导出公钥...";
        _btnExport.Left = 386; _btnExport.Top = y - 3; _btnExport.Width = 110; _btnExport.Height = 30;
        _btnExport.Click += (s, e) => DoExport();
        Controls.Add(_btnExport);
        y += 42;

        // ---- 步骤 3 ----
        Controls.Add(new Label
        {
            Text = "③ 把 CA 签发的证书导回设备（证书公钥必须与卡内密钥匹配）",
            Left = 12, Top = y, Width = 560,
            Font = new Font(Font, FontStyle.Bold),
        });
        y += 24;
        _btnImport.Text = "导入签发证书...";
        _btnImport.Left = 12; _btnImport.Top = y; _btnImport.Width = 130; _btnImport.Height = 30;
        _btnImport.Click += (s, e) => DoImport();
        Controls.Add(_btnImport);
        Controls.Add(new Label
        {
            Text = "支持 PEM(.crt/.pem) 与 DER(.cer/.der) 两种格式",
            Left = 150, Top = y + 7, Width = 400, ForeColor = Color.Gray,
        });
        y += 42;

        // ---- 日志 ----
        _log.Left = 12; _log.Top = y; _log.Width = 636; _log.Height = ClientSize.Height - y - 52;
        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.WordWrap = true;
        _log.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        _log.BackColor = Color.FromArgb(0x1E, 0x1E, 0x1E);
        _log.ForeColor = Color.FromArgb(0xD4, 0xD4, 0xD4);
        _log.Font = new Font("Consolas", 8.5F);
        Controls.Add(_log);

        _btnClose.Text = "关闭";
        _btnClose.Width = 90; _btnClose.Height = 30;
        _btnClose.Left = ClientSize.Width - 102;
        _btnClose.Top = ClientSize.Height - 40;
        _btnClose.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        _btnClose.DialogResult = DialogResult.OK;
        Controls.Add(_btnClose);
        CancelButton = _btnClose;

        AcceptButton = null;
    }

    private void Write(string s)
    {
        _log.AppendText(s + Environment.NewLine);
        _log.SelectionStart = _log.TextLength;
        _log.ScrollToCaret();
    }

    private string ContainerName()
    {
        var name = _txtContainer.Text.Trim();
        if (name.Length == 0) throw new InvalidOperationException("请先填写容器名。");
        return name;
    }

    private uint Bits() => _cmbBits.SelectedIndex == 1 ? 1024u : 2048u;

    /// <summary>统一在 UI 线程执行并保证异常不打断向导（厂商组件可能弹自己的模态框）。</summary>
    private void Run(string title, Action work)
    {
        UseWaitCursor = true;
        SetButtons(false);
        Write($"── {title} ──");
        try
        {
            work();
        }
        catch (Exception ex)
        {
            Write($"[失败] {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            SetButtons(true);
            UseWaitCursor = false;
            Write("");
        }
    }

    private void SetButtons(bool enabled)
    {
        _btnGen.Enabled = _btnExport.Enabled = _btnImport.Enabled = enabled;
        _btnClose.Enabled = true;
    }

    /// <summary>
    /// 确保 SKF 会话已完成 PIN 认证（建容器/生成密钥的前置条件）。
    ///
    /// <para>若设备已通过「登录」按钮认证过，则直接复用该会话，不重复索要口令。
    /// 否则弹框索要<b>用户 PIN</b>。选用户 PIN 而不是管理口令，依据是
    /// <c>Roadmap/08</c> §4 的实机流程：<c>SKF_VerifyPIN(type=1, 用户PIN)</c> 之后
    /// <c>SKF_CreateContainer</c> 即成功。</para>
    ///
    /// <para>注意：口令错误会真实消耗一次重试次数，因此这里<b>只尝试一次</b>，失败即中止。</para>
    /// </summary>
    private void EnsureSkfAuthenticated(SkfProvider skf)
    {
        if (_dev.IsLoggedIn)
        {
            Write("[认证] 复用当前已认证的会话。");
            return;
        }

        var pin = InputDialog.Ask(this, "需要先认证",
            "SKF 在卡内创建容器需要先完成 PIN 认证。\n" +
            "（实测：未认证时 SKF_CreateContainer 直接返回「用户没有登录 0x0A00002D」。）\n" +
            "\n" +
            "请输入该 USBKey 的用户 PIN：",
            masked: true);
        if (pin == null) throw new OperationCanceledException("已取消：建容器前必须先完成认证。");

        skf.Login(_dev, pin);
        Write("[认证] 用户 PIN 认证成功。");
    }

    private void DoGenerate()
    {
        Run("生成密钥对", () =>
        {
            var name = ContainerName();
            if (_prov is BjcaProvider bjca)
            {
                // 实测 林果 LG3073：keyType=1 为 RSA，1/2/3 可用
                bjca.GenerateKeyPair(_dev, name, keyType: 1, sign: _chkSign.Checked);
            }
            else if (_prov is SkfProvider skf)
            {
                // 建容器属「结构」操作，本中间件要求先完成认证：未认证时 SKF_CreateContainer
                // 直接返回 0x0A00002D「用户没有登录」（与 SKF_DeleteContainer 行为一致，均为实测）。
                // Roadmap/08 §4 的完整流程同样是「先 SKF_VerifyPIN(用户PIN) 再建容器」。
                EnsureSkfAuthenticated(skf);
                skf.CreateContainer(_dev, name);
                skf.GenerateKeyPair(_dev, name, ecc: _chkEcc.Checked, bitsOrAlg: Bits());
            }
            else
            {
                throw new NotSupportedException(
                    $"{PlatformInfo.DisplayName(_dev.Platform)} 未实现「卡内生成密钥对」。");
            }
            Write("[完成] 密钥对已在卡内生成。下一步：导出证书请求并交给 CA。");
        });
    }

    private void DoExport()
    {
        Run("导出证书请求 / 公钥", () =>
        {
            var name = ContainerName();
            if (_prov is BjcaProvider bjca)
            {
                var dn = _txtDn.Text.Trim();
                var p10 = bjca.ExportPkcs10(_dev, name, dn, _chkSign.Checked);
                using var sfd = new SaveFileDialog
                {
                    Filter = "PKCS#10 证书请求(*.p10;*.csr)|*.p10;*.csr|文本(*.txt)|*.txt",
                    FileName = name + ".p10",
                };
                if (sfd.ShowDialog(this) != DialogResult.OK) { Write("[取消] 未保存。"); return; }
                // 组件返回 base64 DER，落盘时补上 PEM 头尾，便于直接交给 CA
                var pem = "-----BEGIN CERTIFICATE REQUEST-----" + Environment.NewLine +
                          ToPemBody(p10) +
                          Environment.NewLine + "-----END CERTIFICATE REQUEST-----";
                File.WriteAllText(sfd.FileName, pem, Encoding.ASCII);
                Write($"[完成] PKCS#10 已保存：{sfd.FileName}");
                Write("        请把它提交给 CA 签发，拿到证书后再执行第 ③ 步。");
            }
            else if (_prov is SkfProvider skf)
            {
                var blob = skf.ExportPublicKey(_dev, name, _chkSign.Checked);
                using var sfd = new SaveFileDialog
                {
                    Filter = "公钥(*.pub;*.bin)|*.pub;*.bin|所有文件|*.*",
                    FileName = name + ".pub",
                };
                if (sfd.ShowDialog(this) != DialogResult.OK) { Write("[取消] 未保存。"); return; }
                File.WriteAllBytes(sfd.FileName, blob);
                Write($"[完成] 公钥已保存：{sfd.FileName}（{blob.Length} 字节，SKF 私有结构）");
                Write("[注意] SKF（GM/T 0016）没有 PKCS#10 接口，无法直接产出标准 CSR；");
                Write("        若需要标准 CSR，请改用该设备的「北京CA」平台执行本向导。");
            }
            else
            {
                throw new NotSupportedException("当前平台未实现导出证书请求。");
            }
        });
    }

    private void DoImport()
    {
        Run("导入 CA 签发的证书", () =>
        {
            var name = ContainerName();
            using var ofd = new OpenFileDialog
            {
                Filter = "证书(*.cer;*.crt;*.pem;*.der)|*.cer;*.crt;*.pem;*.der|所有文件|*.*",
                Title = "选择 CA 签发的证书",
            };
            if (ofd.ShowDialog(this) != DialogResult.OK) { Write("[取消] 未选择文件。"); return; }

            var der = ReadCertDer(ofd.FileName);
            Write($"证书已读取：{Path.GetFileName(ofd.FileName)}（DER {der.Length} 字节）");

            if (_prov is BjcaProvider bjca)
                bjca.ImportCertificate(_dev, name, Convert.ToBase64String(der));
            else if (_prov is SkfProvider skf)
                skf.ImportCertificate(_dev, name, der, _chkSign.Checked);
            else
                throw new NotSupportedException("当前平台未实现导入签发证书。");

            Write("[完成] 证书已写入容器。关闭本窗口后点「刷新设备」即可在列表看到证书。");
        });
    }

    /// <summary>把 base64 串按 64 字符折行（PEM 规范）。</summary>
    private static string ToPemBody(string base64)
    {
        var s = base64.Replace("\r", "").Replace("\n", "").Trim();
        var sb = new StringBuilder();
        for (int i = 0; i < s.Length; i += 64)
            sb.AppendLine(s.Substring(i, Math.Min(64, s.Length - i)));
        return sb.ToString().TrimEnd();
    }

    /// <summary>读取证书文件并统一转成 DER：PEM 文本取 base64 主体，二进制则原样返回。</summary>
    private static byte[] ReadCertDer(string path)
    {
        var raw = File.ReadAllBytes(path);
        var text = Encoding.ASCII.GetString(raw);
        if (text.Contains("-----BEGIN", StringComparison.Ordinal))
        {
            var body = string.Concat(
                text.Split('\n')
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith("-----", StringComparison.Ordinal)));
            return Convert.FromBase64String(body);
        }
        return raw;
    }
}
