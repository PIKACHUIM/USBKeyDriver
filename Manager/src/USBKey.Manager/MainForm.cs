using System.Diagnostics;
using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.UsbKey;

namespace USBKey.Manager;

/// <summary>
/// USB Key 管理端 主窗体（880x520）。
/// 左侧为操作按钮 + 设备/证书详情；右侧为当前 Key 上的证书列表。
/// </summary>
internal sealed class MainForm : Form
{
    private readonly AppContext _ctx;
    private NotifyIcon? _tray;
    private ContextMenuStrip? _trayMenu;

    // 顶部：厂商/设备选择
    private readonly ComboBox _cmbPlatform = new();
    private readonly ComboBox _cmbDevice = new();
    private readonly Button _btnRefresh = new();
    private readonly Button _btnLogin = new();
    private readonly Button _btnSettings = new();

    // 操作按钮（图标展示）
    private readonly Dictionary<string, Button> _actionButtons = new();
    private readonly ToolTip _toolTip = new();

    // 详情标签
    private readonly Label _lblDeviceSeq = new(), _lblDeviceFw = new(), _lblDeviceCap = new(), _lblDeviceSoft = new();
    private readonly Label _lblCertSubject = new(), _lblCertAlgo = new(), _lblCertUsage = new(), _lblCertEku = new(), _lblCertValidity = new(), _lblCertUuid = new();
    private readonly Label _lblStatus = new();

    // 证书列表（TreeView 树形展示）
    private readonly TreeView _certTree = new();
    private readonly System.Windows.Forms.Timer _sessionTimer;

    public MainForm(AppContext ctx)
    {
        _ctx = ctx;
        Text = AppConfig.SoftwareName + (ctx.IsAdminMode ? "  [管理模式]" : "  [用户模式]");
        ClientSize = new Size(880, 520);
        MinimumSize = new Size(880, 520);
        Font = new Font("Microsoft YaHei UI", 8.75F);
        Shown += OnShown;
        FormClosing += OnFormClosing;

        BuildUi();
        RegisterTray();
        _ctx.OnStateChanged += () => BeginInvoke(RefreshAll);
        _sessionTimer = new System.Windows.Forms.Timer();
        _sessionTimer.Interval = 30_000;
        _sessionTimer.Tick += (s, e) => RefreshLoginState();
        _sessionTimer.Start();
    }

    private void BuildUi()
    {
        // ===== 顶部工具条 =====
        var top = new Panel { Dock = DockStyle.Top, Height = 46, Padding = new Padding(8, 8, 8, 4) };
        _cmbPlatform.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbPlatform.FlatStyle = FlatStyle.Flat;
        _cmbPlatform.Width = 118;
        _cmbPlatform.Top = 9; _cmbPlatform.Left = 8;
        _cmbPlatform.SelectedIndexChanged += (s, e) => ReloadDevices();

        _cmbDevice.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbDevice.FlatStyle = FlatStyle.Flat;
        _cmbDevice.Width = 176;
        _cmbDevice.Top = 9; _cmbDevice.Left = 134;
        _cmbDevice.SelectedIndexChanged += (s, e) => OnDeviceSelected();

        _btnRefresh.Text = "🔄";
        _btnRefresh.Width = 32; _btnRefresh.Height = 28; _btnRefresh.Top = 8; _btnRefresh.Left = 318;
        _btnRefresh.FlatStyle = FlatStyle.Flat;
        _btnRefresh.Font = new Font("Segoe UI Emoji", 10F);
        _btnRefresh.Click += (s, e) => ReloadDevices();
        _toolTip.SetToolTip(_btnRefresh, "刷新设备列表");

        _btnSettings.Text = "设置";
        _btnSettings.Width = 60; _btnSettings.Height = 28; _btnSettings.Top = 8;
        _btnSettings.Left = 356;
        _btnSettings.FlatStyle = FlatStyle.Flat;
        _btnSettings.Click += (s, e) => {
            using var f = new SettingsForm(_ctx);
            f.ShowDialog(this);
        };

        _btnLogin.Text = "登录";
        _btnLogin.Width = 64; _btnLogin.Height = 28; _btnLogin.Top = 8; _btnLogin.Left = 424;
        _btnLogin.FlatStyle = FlatStyle.Flat;
        _btnLogin.Click += (s, e) => ToggleLogin();

        top.Controls.Add(_cmbPlatform);
        top.Controls.Add(_cmbDevice);
        top.Controls.Add(_btnRefresh);
        top.Controls.Add(_btnLogin);
        top.Controls.Add(_btnSettings);
        Controls.Add(top);

        // ===== 左侧操作按钮区 + 详情 =====
        var left = new Panel { Dock = DockStyle.Left, Width = 380, Padding = new Padding(8) };

        // 操作按钮：一行图标按钮（悬停显示操作信息）
        var actions = new (string key, string label, string tip, string icon)[]
        {
            (FeatureKeys.Login, "登录", "PIN认证登录解锁", "\uE8D7"),
            (FeatureKeys.CloudImport, "云导入", "云端导入证书(未开通)", "\uE753"),
            (FeatureKeys.ImportCert, "导入", "本地导入PFX证书", "\uE896"),
            (FeatureKeys.ViewCert, "查看", "查看证书详情", "\uE890"),
            (FeatureKeys.ExportCert, "导出", "导出证书(不含私钥)", "\uE898"),
            (FeatureKeys.DeleteCert, "删除", "删除证书", "\uE74D"),
            (FeatureKeys.RegisterCert, "注册", "注册/注销证书", "\uE73E"),
            (FeatureKeys.ChangePin, "改密", "修改密码", "\uE72E"),
            (FeatureKeys.UnlockDevice, "解锁", "解锁设备(PUK/挑战码)", "\uE785"),
            (FeatureKeys.ResetDevice, "重置", "初始化设备", "\uE72C"),
        };
        int x = 0;
        foreach (var (key, label, tip, icon) in actions)
        {
            var b = new Button
            {
                Text = icon,
                Width = 34,
                Height = 34,
                FlatStyle = FlatStyle.Flat,
                Location = new Point(8 + x * 36, 6),
                Tag = key,
                Font = new Font("Segoe MDL2 Assets", 12F),
                Cursor = Cursors.Hand,
            };
            b.FlatAppearance.BorderSize = 0;
            b.FlatAppearance.MouseOverBackColor = Color.FromArgb(0xE8, 0xF0, 0xFB);
            _toolTip.SetToolTip(b, label + "：" + tip);
            b.Click += (s, e) => OnActionClicked((string)((Button)s!).Tag!);
            _actionButtons[key] = b;
            left.Controls.Add(b);
            x++;
        }

        // 设备详情
        var g1 = new GroupBox { Text = "USB Key 详情", Left = 8, Top = 118, Width = 360, Height = 86 };
        AddDetail(g1, _lblDeviceSeq, "序列号:", 18);
        AddDetail(g1, _lblDeviceFw, "软件版本:", 42);
        AddDetail(g1, _lblDeviceCap, "容量:", 66);
        left.Controls.Add(g1);

        // 证书详情
        var g2 = new GroupBox { Text = "所选证书详情", Left = 8, Top = 212, Width = 360, Height = 210 };
        AddDetail(g2, _lblCertSubject, "主题:", 18);
        AddDetail(g2, _lblCertAlgo, "算法:", 42);
        AddDetail(g2, _lblCertUsage, "密钥用途:", 66);
        AddDetail(g2, _lblCertEku, "扩展用途:", 90);
        AddDetail(g2, _lblCertValidity, "有效期:", 114);
        AddDetail(g2, _lblCertUuid, "容器UUID:", 138);
        left.Controls.Add(g2);

        // 底部状态
        _lblStatus.Dock = DockStyle.Bottom; _lblStatus.Height = 24; _lblStatus.ForeColor = System.Drawing.Color.DimGray;
        left.Controls.Add(_lblStatus);
        left.Controls.SetChildIndex(_lblStatus, 0);

        Controls.Add(left);

        // ===== 右侧证书列表（圆角卡片 + TreeView 树形表格） =====
        var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(6) };
        var card = new RoundedPanel
        {
            Dock = DockStyle.Fill,
            CornerRadius = 12,
            BorderColor = Color.FromArgb(0xD9, 0xDE, 0xE5),
            Padding = new Padding(6),
        };
        _certTree.Dock = DockStyle.Fill;
        _certTree.BorderStyle = BorderStyle.None;
        _certTree.BackColor = Color.White;
        _certTree.HideSelection = false;
        _certTree.FullRowSelect = true;
        _certTree.ShowLines = true;
        _certTree.ShowPlusMinus = true;
        _certTree.ShowRootLines = true;
        _certTree.ItemHeight = 22;
        _certTree.Indent = 18;
        _certTree.AfterSelect += (s, e) => OnCertSelected();
        _certTree.NodeMouseDoubleClick += (s, e) =>
        {
            if (SelectedCert() != null) OnActionClicked(FeatureKeys.ViewCert);
        };
        card.Controls.Add(_certTree);
        right.Controls.Add(card);
        Controls.Add(right);

        RefreshVendorList();
    }

    private static void AddDetail(Control parent, Label lbl, string caption, int top)
    {
        var c = new Label { Text = caption, Left = 14, Top = top, Width = 70, AutoSize = false, ForeColor = System.Drawing.Color.Gray };
        lbl.Left = 88; lbl.Top = top; lbl.Width = parent.Width - 96; lbl.AutoEllipsis = true;
        parent.Controls.Add(c);
        parent.Controls.Add(lbl);
    }

    private void RegisterTray()
    {
        _trayMenu = new ContextMenuStrip();
        _trayMenu.Items.Add("显示主界面", null, (s, e) => ShowMainWindow());
        _trayMenu.Items.Add(new ToolStripSeparator());
        _trayMenu.Items.Add("查看/弹出 USB Key", null, (s, e) => ViewEjectKey());
        _trayMenu.Items.Add("退出", null, (s, e) =>
        {
            if (_tray != null) _tray.Visible = false;
            System.Windows.Forms.Application.Exit();
        });

        _tray = new NotifyIcon
        {
            Text = AppConfig.SoftwareName,
            Icon = System.Drawing.SystemIcons.Shield,
            ContextMenuStrip = _trayMenu,
            Visible = true,
        };
        _tray.DoubleClick += (s, e) => ShowMainWindow();
    }

    private void ShowMainWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void ViewEjectKey()
    {
        var devs = _ctx.Keys.EnumerateAll();
        if (devs.Count == 0) { MessageBox.Show("未检测到 USB Key 设备。", AppConfig.SoftwareName); return; }
        // 弹出：尝试安全移除（调用 Shell 的弹出）——演示用，仅提示
        var names = devs.Select(d => d.TrayLabel).ToArray();
        using var dlg = new ChoiceDialog("USB Key 设备", "选择要查看的设备：", names);
        if (dlg.ShowDialog(this) == DialogResult.OK)
        {
            try
            {
                var dev = devs[dlg.SelectedIndex];
                MessageBox.Show("设备信息：" + dev.TrayLabel + Environment.NewLine +
                                "VID/PID: " + dev.Vid.ToString("X4") + ":" + dev.Pid.ToString("X4") + Environment.NewLine +
                                "固件: " + dev.FirmwareVersion, "设备详情");
            }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
        }
    }

    private void OnShown(object? s, EventArgs e)
    {
        RefreshVendorList();
        RefreshAll();
        _lblStatus.Text = _ctx.IsAdminMode ? "管理模式 · " + LicenseText() : "用户模式";
    }

    private string LicenseText() => _ctx.License?.IsValid == true
        ? "已授权 · 有效期至 " + _ctx.License!.ValidUntilUtc.ToString("yyyy-MM-dd")
        : "未授权";

    private void RefreshVendorList()
    {
        var op = _cmbPlatform.Items.Cast<string>().Select(x => x.ToString()).ToList();
        _cmbPlatform.BeginUpdate();
        _cmbPlatform.Items.Clear();
        foreach (var p in _ctx.Config.Platform ?? new()) _cmbPlatform.Items.Add(p);
        if (_cmbPlatform.Items.Count > 0) _cmbPlatform.SelectedIndex = 0;
        _cmbPlatform.EndUpdate();
    }

    private void ReloadDevices()
    {
        if (_cmbPlatform.SelectedItem == null) return;
        var platform = _cmbPlatform.SelectedItem.ToString()!;
        _ctx.SelectedPlatform = platform;
        _cmbDevice.BeginUpdate();
        _cmbDevice.Items.Clear();
        IReadOnlyList<UsbKeyDevice> devs;
        try { devs = _ctx.Keys.EnumerateAll(); }
        catch { devs = new List<UsbKeyDevice>(); }
        foreach (var d in devs) _cmbDevice.Items.Add(d.TrayLabel + (d.IsLoggedIn ? " [已解锁]" : ""));
        if (_cmbDevice.Items.Count > 0) _cmbDevice.SelectedIndex = 0;
        _cmbDevice.EndUpdate();
        OnDeviceSelected();
    }

    private void OnDeviceSelected()
    {
        RefreshDeviceDetails();
        RefreshCertList();
        RefreshButtons();
    }

    private UsbKeyDevice? SelectedDevice()
    {
        if (_cmbDevice.SelectedIndex < 0) return null;
        var devs = _ctx.Keys.EnumerateAll();
        return _cmbDevice.SelectedIndex < devs.Count ? devs[_cmbDevice.SelectedIndex] : null;
    }

    private void RefreshDeviceDetails()
    {
        var dev = SelectedDevice();
        if (dev == null)
        {
            _lblDeviceSeq.Text = "—"; _lblDeviceFw.Text = "—"; _lblDeviceCap.Text = "—"; _lblDeviceSoft.Text = "—";
            return;
        }
        _lblDeviceSeq.Text = dev.SerialNumber;
        _lblDeviceFw.Text = dev.FirmwareVersion;
        _lblDeviceCap.Text = dev.CapacityKb > 0 ? (dev.CapacityKb / 1024).ToString("0.#") + " MB" : "—";
        _lblDeviceSoft.Text = "VID:" + dev.Vid.ToString("X4") + " PID:" + dev.Pid.ToString("X4");
        _btnLogin.Text = dev.IsLoggedIn ? "登出" : "登录";
    }

    private void RefreshCertList()
    {
        _certTree.BeginUpdate();
        _certTree.Nodes.Clear();
        var dev = SelectedDevice();
        if (dev != null)
        {
            var root = new TreeNode("USB Key · " + dev.SerialNumber + (dev.IsLoggedIn ? "  [已解锁]" : "  [未解锁]"));
            if (dev.IsLoggedIn)
            {
                try
                {
                    foreach (var c in _ctx.Keys.GetProvider(_ctx.SelectedPlatform)?.ListContainers(dev) ?? new List<KeyContainer>())
                    {
                        var certNode = new TreeNode(c.Name) { Tag = c };
                        certNode.Nodes.Add("主题：" + Truncate(c.Subject, 60));
                        certNode.Nodes.Add("算法：" + c.Algorithm);
                        certNode.Nodes.Add("密钥用途：" + c.KeyUsage);
                        certNode.Nodes.Add("有效期：" + c.ValidityText);
                        certNode.Nodes.Add("容器：" + Truncate(c.ContainerUuid, 36));
                        root.Nodes.Add(certNode);
                    }
                }
                catch (Exception ex) { _lblStatus.Text = "加载证书失败：" + ex.Message; }
            }
            _certTree.Nodes.Add(root);
            root.Expand();
        }
        _certTree.EndUpdate();
        OnCertSelected();
    }

    private KeyContainer? SelectedCert()
    {
        var node = _certTree.SelectedNode;
        while (node != null && node.Tag is not KeyContainer)
            node = node.Parent;
        return node?.Tag as KeyContainer;
    }

    private void OnCertSelected()
    {
        var c = SelectedCert();
        if (c == null)
        {
            _lblCertSubject.Text = _lblCertAlgo.Text = _lblCertUsage.Text = _lblCertEku.Text = _lblCertValidity.Text = _lblCertUuid.Text = "—";
        }
        else
        {
            _lblCertSubject.Text = Truncate(c.Subject, 48);
            _lblCertAlgo.Text = c.Algorithm;
            _lblCertUsage.Text = c.KeyUsage;
            _lblCertEku.Text = Truncate(c.ExtendedKeyUsage, 40);
            _lblCertValidity.Text = c.ValidityText;
            _lblCertUuid.Text = Truncate(c.ContainerUuid, 36);
        }
        RefreshButtons();
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";

    /// <summary>根据配置的 features + 当前状态刷新按钮可用/可见性。</summary>
    private void RefreshButtons()
    {
        bool logged = _ctx.IsLoggedIn;
        bool hasCert = SelectedCert() != null;
        bool hasDevice = SelectedDevice() != null;
        bool admin = _ctx.IsAdminMode;

        foreach (var (key, btn) in _actionButtons)
        {
            var st = _ctx.Config.GetFeatureState(key);
            // 用户模式下，导入/重置不可用（置灰，而非隐藏）
            if (!admin && (key == FeatureKeys.ImportCert || key == FeatureKeys.ResetDevice))
                st = FeatureState.Disabled;

            // 按钮始终可见，禁用时置灰（不可点击），不再消失
            btn.Visible = true;
            btn.Enabled = st == FeatureState.Enabled;

            bool needKey = key is FeatureKeys.Login or FeatureKeys.CloudImport or FeatureKeys.ImportCert
                or FeatureKeys.ChangePin or FeatureKeys.UnlockDevice or FeatureKeys.ResetDevice;
            bool needCert = key is FeatureKeys.ViewCert or FeatureKeys.ExportCert
                or FeatureKeys.DeleteCert or FeatureKeys.RegisterCert;
            if (st == FeatureState.Enabled)
            {
                if (needKey && !hasDevice) btn.Enabled = false;
                if (needCert && !hasCert) btn.Enabled = false;
                // 重置和解锁不需要登录（恰恰是用来恢复设备的）
                if ((key is FeatureKeys.ImportCert or FeatureKeys.ChangePin or FeatureKeys.CloudImport) && !logged)
                    btn.Enabled = false;
            }
        }
        _btnLogin.Enabled = hasDevice;
    }

    private void ToggleLogin()
    {
        var dev = SelectedDevice();
        if (dev == null) return;
        if (dev.IsLoggedIn)
        {
            try { _ctx.Keys.GetProvider(_ctx.SelectedPlatform)?.Logout(dev); }
            catch (Exception ex) { MessageBox.Show(ex.Message); }
            _ctx.MarkLoggedOut();
            return;
        }
        var pin = InputDialog.Ask(this, "登录", "请输入 PIN 进行认证：");
        if (pin == null) return;
        try
        {
            _ctx.Keys.GetProvider(_ctx.SelectedPlatform)?.Login(dev, pin);
            dev.IsLoggedIn = true;
            _ctx.MarkLoggedIn(dev);
            _lblStatus.Text = "已登录（解锁）";
            RefreshAll();
        }
        catch (Exception ex) { MessageBox.Show("登录失败：" + ex.Message, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void OnActionClicked(string key)
    {
        var dev = SelectedDevice();
        var cert = SelectedCert();
        var prov = _ctx.Keys.GetProvider(_ctx.SelectedPlatform);

        // 管理模式：导入/重置/解锁 是敏感操作，需再次校验授权
        if (_ctx.IsAdminMode && key is FeatureKeys.ImportCert or FeatureKeys.ResetDevice or FeatureKeys.UnlockDevice)
        {
            if (!_ctx.AuthorizeSensitiveOperation())
            {
                MessageBox.Show("授权无效或已过期，无法执行该操作。请在系统设置中更新授权。", AppConfig.SoftwareName,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }

        try
        {
            switch (key)
            {
                case FeatureKeys.CloudImport:
                    MessageUnavailable("云端导入功能暂未开通。");
                    break;
                case FeatureKeys.ImportCert:
                    DoImportPfx(prov!, dev!);
                    break;
                case FeatureKeys.ViewCert:
                    if (prov != null) prov.ViewCertificate(cert!);
                    break;
                case FeatureKeys.ExportCert:
                    DoExportCert(prov!, cert!);
                    break;
                case FeatureKeys.DeleteCert:
                    DoDeleteCert(prov!, dev!, cert!);
                    break;
                case FeatureKeys.RegisterCert:
                    DoRegisterToggle(prov!, cert!);
                    break;
                case FeatureKeys.ChangePin:
                    DoChangePin(prov!, dev!);
                    break;
                case FeatureKeys.UnlockDevice:
                    DoUnlock(prov!, dev!);
                    break;
                case FeatureKeys.ResetDevice:
                    DoReset(prov!, dev!);
                    break;
            }
        }
        catch (NotSupportedException ex)
        {
            MessageBox.Show(ex.Message + Environment.NewLine + "该功能需要完成驱动接口逆向对接后可用（见软件文档）。",
                AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("操作失败：" + ex.Message, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void DoImportPfx(IKeyProvider prov, UsbKeyDevice dev)
    {
        using var ofd = new OpenFileDialog { Filter = "PFX 证书(*.pfx;*.p12)|*.pfx;*.p12|所有文件|*.*", Title = "选择要导入的 PFX 文件" };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;
        var pwd = InputDialog.Ask(this, "导入证书", "请输入 PFX 文件密码：", masked: true);
        if (pwd == null) return;
        prov.ImportPfx(dev, ofd.FileName, pwd);
        MessageBox.Show("证书导入成功。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        RefreshCertList();
    }

    private void DoExportCert(IKeyProvider prov, KeyContainer cert)
    {
        using var sfd = new SaveFileDialog { Filter = "证书(*.cer)|*.cer|证书(*.crt)|*.crt", FileName = cert.Name + ".cer" };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        prov.ExportCertificate(SelectedDevice()!, cert, sfd.FileName);
        MessageBox.Show("证书已导出（仅公钥部分，不含私钥）。", AppConfig.SoftwareName);
    }

    private void DoDeleteCert(IKeyProvider prov, UsbKeyDevice dev, KeyContainer cert)
    {
        if (MessageBox.Show($"确认从 USB Key 删除证书「{cert.Name}」？", "删除证书",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        // 若已注册到 CSP，先注销
        if (cert.IsRegisteredInCsp) { try { prov.UnregisterFromCsp(cert); } catch { } }
        prov.DeleteContainer(dev, cert);
        MessageBox.Show("证书已删除。", AppConfig.SoftwareName);
        RefreshCertList();
    }

    private void DoRegisterToggle(IKeyProvider prov, KeyContainer cert)
    {
        if (cert.IsRegisteredInCsp)
        {
            prov.UnregisterFromCsp(cert);
            MessageBox.Show("已从系统证书库注销。", AppConfig.SoftwareName);
        }
        else
        {
            prov.RegisterToCsp(cert);
            MessageBox.Show("已注册到系统 CSP 证书库。", AppConfig.SoftwareName);
        }
        RefreshCertList();
    }

    private void DoChangePin(IKeyProvider prov, UsbKeyDevice dev)
    {
        var oldPin = InputDialog.Ask(this, "修改密码", "请输入当前 PIN：");
        if (oldPin == null) return;
        var newPin = InputDialog.Ask(this, "修改密码", "请输入新 PIN（6 位起）：");
        if (newPin == null) return;
        var confirm = InputDialog.Ask(this, "修改密码", "请再次输入新 PIN：");
        if (confirm == null) return;
        if (newPin != confirm) { MessageBox.Show("两次输入的新 PIN 不一致。"); return; }
        Validators.EnsurePin(newPin);
        prov.ChangePin(dev, oldPin, newPin);
        MessageBox.Show("密码修改成功。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void DoUnlock(IKeyProvider prov, UsbKeyDevice dev)
    {
        using var dlg = new ChoiceDialog("解锁设备", "选择解锁方式：", new[] { "PUK 解锁", "Admin Key 解锁", "挑战码解锁" });
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        if (dlg.SelectedIndex == 2) // 挑战码
        {
            string challenge;
            try
            {
                challenge = _ctx.IsAdminMode
                    ? prov.GenerateChallenge(dev)
                    : "（请管理员在管理模式生成挑战码）";
            }
            catch (Exception ex) { challenge = "（生成失败：" + ex.Message + "）"; }
            var resp = InputDialog.Ask(this, "挑战码解锁", "管理员挑战码：" + challenge + Environment.NewLine + "请输入挑战码响应：");
            if (resp == null) return;
            var newPin = InputDialog.Ask(this, "挑战码解锁", "请输入新的 PIN：");
            if (newPin == null) return;
            prov.UnlockByChallenge(dev, challenge, resp, newPin);
            MessageBox.Show("解锁成功，PIN 已重置。", AppConfig.SoftwareName);
        }
        else
        {
            var cred = InputDialog.Ask(this, "解锁设备", dlg.SelectedIndex == 0 ? "请输入 PUK：" : "请输入 Admin Key：");
            if (cred == null) return;
            var newPin = InputDialog.Ask(this, "解锁设备", "请输入新的 PIN：");
            if (newPin == null) return;
            Validators.EnsurePin(newPin);
            prov.Unlock(dev, (UnlockMethod)dlg.SelectedIndex, cred, newPin);
            MessageBox.Show("解锁成功，PIN 已重置。", AppConfig.SoftwareName);
        }
        RefreshAll();
    }

    private void DoReset(IKeyProvider prov, UsbKeyDevice dev)
    {
        var msg = "将初始化（重置）此 USB Key，所有证书将被清除。是否继续？";
        if (MessageBox.Show(msg, "重置设备", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        var newPin = InputDialog.Ask(this, "重置设备", "设置新的 PIN（6 位起）：");
        if (newPin == null) return;
        Validators.EnsurePin(newPin);
        var usePuk = AskPuk();
        string? puk = null, admin = null;
        if (usePuk)
        {
            puk = InputDialog.Ask(this, "重置设备", "设置 PUK（留空则随机生成）：");
            if (string.IsNullOrEmpty(puk)) puk = Validators.RandomPassword(8);
            var hasAdmin = MessageBox.Show("是否同时设置 Admin Key？", "重置设备", MessageBoxButtons.YesNo) == DialogResult.Yes;
            if (hasAdmin)
            {
                admin = InputDialog.Ask(this, "重置设备", "设置 Admin Key（留空则随机生成）：");
                if (string.IsNullOrEmpty(admin)) admin = Validators.RandomPassword(16);
            }
        }
        prov.ResetDevice(dev, newPin, puk, admin);
        dev.IsLoggedIn = true;
        _ctx.MarkLoggedIn(dev);
        MessageBox.Show("设备已初始化。" + (usePuk ? Environment.NewLine + "请妥善保管重置信息。" : ""), AppConfig.SoftwareName);
        RefreshAll();
    }

    private bool AskPuk() =>
        MessageBox.Show("是否设置 PUK？\n（留空或不设置时将随机生成，重置时需使用 PUK/Admin Key）", "重置设备",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;

    private void MessageUnavailable(string msg) =>
        MessageBox.Show(msg, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);

    private void RefreshAll()
    {
        if (IsDisposed) return;
        // 保持厂商列表与设备选择同步
        ReloadDevices();
        RefreshButtons();
    }

    private void RefreshLoginState()
    {
        if (_ctx.CurrentDevice != null && !_ctx.IsLoggedIn)
        {
            _lblStatus.Text = "会话已超时，请重新登录";
            _ctx.MarkLoggedOut();
        }
    }

    private void OnFormClosing(object? s, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            // 最小化到托盘：拦截右上角关闭
            if (_tray != null)
            {
                e.Cancel = true;
                Hide();
                _tray.ShowBalloonTip(1200, AppConfig.SoftwareName, "程序已最小化到托盘。右击图标可退出。", ToolTipIcon.Info);
                return;
            }
        }
        _sessionTimer.Stop();
        _tray?.Dispose();
        _toolTip.Dispose();
    }
}
