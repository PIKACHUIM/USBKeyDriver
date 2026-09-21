using System.Collections.Concurrent;
using System.Diagnostics;
using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Crypto;
using USBKey.Core.UsbKey;

namespace USBKey.Manager;

/// <summary>
/// USB Key 管理端 主窗体。
/// <para>
/// 布局（自上而下，TableLayoutPanel 固定行高，避免 Dock 顺序歧义）：
/// 工具条 → 设备表格 → 证书表格 → 详情 → 操作按钮 → 日志面板 → 状态栏。
/// </para>
/// <para>
/// 性能约定（旧实现在这里吃了大亏）：
/// 设备列表与容器列表都<b>只在显式刷新/切换平台/热插拔时枚举一次并缓存</b>，
/// 任何"取当前选中设备"的调用都直接读缓存，
/// 绝不在 SelectedDevice() 之类的属性里重新扫描（旧代码一次刷新会触发 4+ 次全平台枚举）。
/// </para>
/// </summary>
internal sealed class MainForm : Form
{
    private readonly AppContext _ctx;
    private NotifyIcon? _tray;
    private ContextMenuStrip? _trayMenu;

    // ---------- 顶部工具条 ----------
    private readonly ComboBox _cmbPlatform = new();
    private readonly Button _btnRefresh = new();
    private readonly Button _btnLogin = new();
    private readonly Button _btnSettings = new();
    private readonly Button _btnLogToggle = new();

    // ---------- 表格 ----------
    private readonly DataGridView _gridDevices = new();
    private readonly DataGridView _gridCerts = new();
    /// <summary>证书区外框：标题上直接显示"空卡"等状态，避免用户以为是刷新没生效。</summary>
    private readonly GroupBox _gbCerts = new();

    // ---------- 详情 ----------
    private readonly Label _lblDevPlatform = new(), _lblDevModel = new(), _lblDevSerial = new();
    private readonly Label _lblDevVidPid = new(), _lblDevFw = new(), _lblDevCap = new();
    private readonly Label _lblCertSubject = new(), _lblCertAlgo = new(), _lblCertUsage = new();
    private readonly Label _lblCertEku = new(), _lblCertValidity = new(), _lblCertUuid = new();

    // ---------- 操作按钮 ----------
    private readonly Dictionary<string, Button> _actionButtons = new();
    private readonly ToolTip _toolTip = new();

    // ---------- 日志面板 ----------
    private readonly TableLayoutPanel _root = new();
    private readonly Panel _logPanel = new();
    private readonly TextBox _logBox = new();
    private readonly Queue<string> _logQueue = new();
    private readonly System.Windows.Forms.Timer _logTimer;
    private string _lastLogLine = "";
    private int _lastLogRepeat;
    private const int MaxLogLines = 1500;
    private int _logRowHeight = 170;
    private bool _logVisible;

    // ---------- 状态栏 ----------
    private readonly Label _lblStatus = new();

    // ---------- 状态 ----------
    /// <summary>当前平台枚举到的设备（缓存；表格行 Tag 直接指向这里的对象）。</summary>
    private readonly List<UsbKeyDevice> _devices = new();
    /// <summary>当前选中设备的容器（缓存）。</summary>
    private readonly List<KeyContainer> _containers = new();

    /// <summary>
    /// 按平台分锁：<b>不同平台可并行访问，同一平台内串行</b>。
    /// <para>
    /// 原来只有一把全局 <c>_ioLock</c> 且枚举是串行的：恒宝 U 宝探测一次要 60 秒以上，
    /// 会把其它平台的设备一起拖住，界面白等一分多钟才出结果。
    /// 分成按平台的门之后，慢平台只影响它自己。
    /// </para>
    /// </summary>
    private readonly ConcurrentDictionary<string, object> _platformGates = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>单平台扫描等待预算（毫秒）：超过就先放行，该平台转后台继续扫，结果到了再上屏。</summary>
    private const int PlatformScanTimeoutMs = 8_000;

    /// <summary>扫描代数：每次重新扫描自增，用于丢弃过期扫描/慢平台迟到的结果。</summary>
    private int _scanGeneration;

    private bool _busy;
    private bool _enumerating;
    /// <summary>枚举进行中又收到刷新请求时置位，等本轮结束再补一次。</summary>
    private bool _pendingReload;
    /// <summary>抑制平台下拉在重建列表期间触发的变更（否则会多扫一遍"全部平台"）。</summary>
    private bool _suppressPlatformChanged;
    /// <summary>重建表格期间抑制 SelectionChanged，由调用方显式刷新一次，避免重复读卡。</summary>
    private bool _suppressDeviceSel;
    private bool _suppressCertSel;
    private readonly System.Windows.Forms.Timer _sessionTimer;
    private readonly System.Windows.Forms.Timer _refreshDebounce;

    private const string PlatformAll = "__ALL__";

    // ---------- 证书注册记录 / 自动注册 ----------
    /// <summary>
    /// 证书注册记录 + 自动注册器。
    /// <para>
    /// 注册动作本身写在系统证书库里，但"这条证书来自哪台卡、私钥绑的是哪个容器"只有记录文件知道，
    /// 因此每次注册都落盘；启动/插卡时按记录把缺失的证书补注册回来。
    /// </para>
    /// </summary>
    private readonly CertAutoRegistrar _registrar;
    /// <summary>上一次已处理的设备指纹（平台:序列号），用于判断"插了新卡 / 首次启动"。</summary>
    private string _lastDeviceSignature = "";
    /// <summary>自动注册是否在跑（防止重入）。</summary>
    private bool _autoRegisterRunning;

    public MainForm(AppContext ctx)
    {
        _ctx = ctx;
        _registrar = new CertAutoRegistrar(ctx.Config, CertRegistrationStore.Load(AppPaths.CertRegistrationFile));
        Text = AppConfig.SoftwareName + (ctx.IsAdminMode ? "  [管理模式]" : "  [用户模式]");
        ClientSize = new Size(1500, 860);
        // 最小宽度要保证操作按钮一整行放得下（11 个按钮 ≈ 1160px）且证书名称列不挤，否则会被横向裁剪
        MinimumSize = new Size(1300, 740);
        Font = new Font("Microsoft YaHei UI", 9F);
        StartPosition = FormStartPosition.CenterScreen;
        Shown += OnShown;
        FormClosing += OnFormClosing;

        // 日志面板节流刷新：高频日志不再逐条重绘（旧实现直接卡顿）
        _logTimer = new System.Windows.Forms.Timer { Interval = 250 };
        _logTimer.Tick += (s, e) => FlushLog();
        _logTimer.Start();

        BuildUi();
        RegisterTray();
        Log.Line += OnLogLine;

        _ctx.OnStateChanged += () => BeginInvoke(OnCtxStateChanged);

        // 会话超时检查
        _sessionTimer = new System.Windows.Forms.Timer { Interval = 30_000 };
        _sessionTimer.Tick += (s, e) => RefreshLoginState();
        _sessionTimer.Start();

        // 热插拔防抖：短时间内多次变化只重新枚举一次
        _refreshDebounce = new System.Windows.Forms.Timer { Interval = 500 };
        _refreshDebounce.Tick += (s, e) =>
        {
            _refreshDebounce.Stop();
            ReloadDevices();
        };
        if (_ctx.Watcher != null)
            _ctx.Watcher.Changed += () => BeginInvoke(() =>
            {
                _refreshDebounce.Stop();
                _refreshDebounce.Start();
            });
    }

    // ============================================================ 界面构建

    private void BuildUi()
    {
        _root.Dock = DockStyle.Fill;
        _root.ColumnCount = 1;
        _root.RowCount = 7;
        _root.Padding = new Padding(8, 8, 8, 6);
        _root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 44F));   // 0 工具条
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 252F));  // 1 设备表格（加高，尽量多显示几行设备）
        _root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));   // 2 证书表格（吃剩余空间，窗口变小时优先被压缩）
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 104F));  // 3 详情
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 54F));   // 4 操作按钮（容纳 32px 高按钮）
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 0F));    // 5 日志（默认收起）
        _root.RowStyles.Add(new RowStyle(SizeType.Absolute, 26F));   // 6 状态栏

        _root.Controls.Add(BuildToolbar(), 0, 0);
        _root.Controls.Add(BuildDeviceGridSection(), 0, 1);
        _root.Controls.Add(BuildCertGridSection(), 0, 2);
        _root.Controls.Add(BuildDetailPanel(), 0, 3);
        _root.Controls.Add(BuildActionBar(), 0, 4);
        _root.Controls.Add(BuildLogPanel(), 0, 5);
        _root.Controls.Add(BuildStatusBar(), 0, 6);

        Controls.Add(_root);
        ReloadPlatformList();
    }

    private Control BuildToolbar()
    {
        var p = new Panel { Dock = DockStyle.Fill };

        p.Controls.Add(new Label { Text = "厂商平台:", Left = 0, Top = 11, Width = 64, ForeColor = Color.DimGray });

        _cmbPlatform.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbPlatform.FlatStyle = FlatStyle.Flat;
        _cmbPlatform.Left = 68; _cmbPlatform.Top = 7; _cmbPlatform.Width = 210;
        _cmbPlatform.SelectedIndexChanged += (s, e) =>
        {
            if (_suppressPlatformChanged) return;
            ReloadDevices();
        };
        p.Controls.Add(_cmbPlatform);

        _btnRefresh.Text = "刷新设备";
        _btnRefresh.Left = 286; _btnRefresh.Top = 6; _btnRefresh.Width = 80; _btnRefresh.Height = 28;
        _btnRefresh.Click += (s, e) => ReloadDevices();
        _toolTip.SetToolTip(_btnRefresh, "重新扫描当前平台的 USB Key（快捷键 F5）");
        p.Controls.Add(_btnRefresh);

        _btnLogin.Text = "登录";
        _btnLogin.Left = 372; _btnLogin.Top = 6; _btnLogin.Width = 70; _btnLogin.Height = 28;
        _btnLogin.Click += (s, e) => ToggleLogin();
        p.Controls.Add(_btnLogin);

        _btnLogToggle.Text = "显示日志";
        _btnLogToggle.Left = 448; _btnLogToggle.Top = 6; _btnLogToggle.Width = 80; _btnLogToggle.Height = 28;
        _btnLogToggle.Click += (s, e) => ToggleLogPanel();
        _toolTip.SetToolTip(_btnLogToggle, "展开/收起运行日志（不必再去 logs 目录翻文件）");
        p.Controls.Add(_btnLogToggle);

        _btnSettings.Text = "设置";
        _btnSettings.Left = 534; _btnSettings.Top = 6; _btnSettings.Width = 70; _btnSettings.Height = 28;
        _btnSettings.Click += (s, e) =>
        {
            using var f = new SettingsForm(_ctx);
            f.ShowDialog(this);
        };
        p.Controls.Add(_btnSettings);

        KeyPreview = true;
        KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.F5) { ReloadDevices(); e.Handled = true; }
        };
        return p;
    }

    private Control BuildDeviceGridSection()
    {
        var gb = new GroupBox { Dock = DockStyle.Fill, Text = "设备列表", Padding = new Padding(6, 4, 6, 6) };
        ConfigGrid(_gridDevices);
        _gridDevices.Columns.Add(NewCol("平台", 90));
        _gridDevices.Columns.Add(NewCol("厂商 / 型号", 150));
        _gridDevices.Columns.Add(NewCol("序列号", 190));
        _gridDevices.Columns.Add(NewCol("VID:PID", 90));
        _gridDevices.Columns.Add(NewCol("固件", 110));
        _gridDevices.Columns.Add(NewCol("容量", 90));
        _gridDevices.Columns.Add(NewCol("状态", 90));
        _gridDevices.SelectionChanged += (s, e) =>
        {
            if (_suppressDeviceSel) return;
            OnDeviceSelected();
        };
        gb.Controls.Add(_gridDevices);
        return gb;
    }

    private Control BuildCertGridSection()
    {
        _gbCerts.Dock = DockStyle.Fill;
        _gbCerts.Text = "证书 / 容器";
        _gbCerts.Padding = new Padding(6, 4, 6, 6);
        ConfigGrid(_gridCerts);
        _gridCerts.Columns.Add(NewCol("类型", 70));   // 证书 / 仅密钥 / 空容器
        // 名称（CN）是用户最常看的一列，权重给足；主体(Subject) 很长但可以靠悬停提示
        _gridCerts.Columns.Add(NewCol("名称", 260));
        _gridCerts.Columns.Add(NewCol("主体(Subject)", 300));
        _gridCerts.Columns.Add(NewCol("算法", 150));
        _gridCerts.Columns.Add(NewCol("密钥用途", 110));
        _gridCerts.Columns.Add(NewCol("有效期", 170));
        _gridCerts.Columns.Add(NewCol("容器 UUID", 210));
        // 只有"注册了 / 没注册"两种状态：卡上的证书必然带卡内私钥，注册时私钥容器会一并写入
        _gridCerts.Columns.Add(NewCol("已注册", 70));
        _gridCerts.CellDoubleClick += (s, e) =>
        {
            if (e.RowIndex >= 0 && SelectedCert() != null) OnActionClicked(FeatureKeys.ViewCert);
        };
        _gridCerts.SelectionChanged += (s, e) =>
        {
            if (_suppressCertSel) return;
            OnCertSelected();
        };
        _gbCerts.Controls.Add(_gridCerts);
        return _gbCerts;
    }

    private static void ConfigGrid(DataGridView g)
    {
        g.Dock = DockStyle.Fill;
        g.BackgroundColor = Color.White;
        g.BorderStyle = BorderStyle.None;
        g.AllowUserToAddRows = false;
        g.AllowUserToDeleteRows = false;
        g.AllowUserToResizeRows = false;
        g.ReadOnly = true;
        g.MultiSelect = false;
        g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        g.RowHeadersVisible = false;
        g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        g.ColumnHeadersHeight = 28;
        g.RowTemplate.Height = 24;
        g.EnableHeadersVisualStyles = false;
        g.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(0xF3, 0xF5, 0xF8);
        g.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(0x33, 0x33, 0x33);
        g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(0xF3, 0xF5, 0xF8);
        g.ColumnHeadersDefaultCellStyle.SelectionForeColor = Color.FromArgb(0x33, 0x33, 0x33);
        g.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0xE1, 0xEC, 0xFC);
        g.DefaultCellStyle.SelectionForeColor = Color.FromArgb(0x11, 0x11, 0x11);
        g.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(0xFA, 0xFB, 0xFC);
        g.AdvancedCellBorderStyle.All = DataGridViewAdvancedCellBorderStyle.Single;
        g.GridColor = Color.FromArgb(0xE6, 0xE9, 0xEE);
    }

    private static DataGridViewTextBoxColumn NewCol(string header, int minWidth) => new()
    {
        HeaderText = header,
        MinimumWidth = minWidth,
        FillWeight = minWidth,
        SortMode = DataGridViewColumnSortMode.Automatic,
        DefaultCellStyle = new DataGridViewCellStyle { Padding = new Padding(4, 0, 0, 0) },
    };

    private Control BuildDetailPanel()
    {
        var gb = new GroupBox { Dock = DockStyle.Fill, Text = "详情", Padding = new Padding(6, 4, 6, 6) };
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 6,
            RowCount = 3,
            Padding = new Padding(0),
        };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 62F));   // 设备标签
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38F));    // 设备值
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 62F));   // 证书标签
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62F));    // 证书值
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 62F));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 0F));
        for (int i = 0; i < 3; i++) t.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3F));

        AddDetailPair(t, 0, 0, "平台:", _lblDevPlatform, 2, 0, "证书主题:", _lblCertSubject);
        AddDetailPair(t, 0, 1, "序列号:", _lblDevSerial, 2, 1, "算法:", _lblCertAlgo);
        AddDetailPair(t, 0, 2, "型号:", _lblDevModel, 2, 2, "有效期:", _lblCertValidity);
        AddDetailPair(t, 3, 0, "VID:PID:", _lblDevVidPid, 4, 0, "密钥用途:", _lblCertUsage);
        AddDetailPair(t, 3, 1, "固件:", _lblDevFw, 4, 1, "扩展用途:", _lblCertEku);
        AddDetailPair(t, 3, 2, "容量:", _lblDevCap, 4, 2, "容器UUID:", _lblCertUuid);

        gb.Controls.Add(t);
        return gb;
    }

    private static void AddDetailPair(TableLayoutPanel t, int labelCol, int row, string caption, Label value,
        int capCol2, int row2, string caption2, Label value2)
    {
        t.Controls.Add(new Label { Text = caption, Dock = DockStyle.Fill, ForeColor = Color.Gray, TextAlign = ContentAlignment.MiddleLeft }, labelCol, row);
        value.Dock = DockStyle.Fill;
        value.AutoEllipsis = true;
        value.TextAlign = ContentAlignment.MiddleLeft;
        t.Controls.Add(value, labelCol + 1, row);

        t.Controls.Add(new Label { Text = caption2, Dock = DockStyle.Fill, ForeColor = Color.Gray, TextAlign = ContentAlignment.MiddleLeft }, capCol2, row2);
        value2.Dock = DockStyle.Fill;
        value2.AutoEllipsis = true;
        value2.TextAlign = ContentAlignment.MiddleLeft;
        t.Controls.Add(value2, capCol2 + 1, row2);
    }

    private Control BuildActionBar()
    {
        // 用 FlowLayoutPanel 承载而不是手工算坐标：
        // 旧实现把按钮固定成 78px，而「登录/登出」「导入证书 ✕」这类标题在 9pt 雅黑下要 60~70px，
        // 再加上按钮左右内边距就被裁成三个字。这里按文字实测宽度 + 内边距反算按钮宽度，
        // 保证任何标题都能完整显示；放不下时整行横向滚动，而不是把文字截断。
        var p = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            AutoScroll = true,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 9, 0, 0),
        };
        var actions = new (string key, string label, string tip)[]
        {
            (FeatureKeys.Login, "登录/登出", "PIN 认证登录解锁"),
            (FeatureKeys.CloudImport, "云导入", "云端导入证书(未开通)"),
            (FeatureKeys.ImportCert, "导入证书", "本地导入 PFX 证书（私钥可导入的平台才可用）"),
            (FeatureKeys.EnrollCert, "证书登记", "卡内生成密钥 → 导出 P10 → 导回 CA 签发证书"),
            (FeatureKeys.ViewCert, "查看证书", "查看证书详情"),
            (FeatureKeys.ExportCert, "导出证书", "导出证书(不含私钥)"),
            (FeatureKeys.DeleteCert, "删除容器", "删除设备上的证书/容器（含「仅密钥」与「空容器」条目）"),
            (FeatureKeys.RegisterCert, "注册/注销", "注册到系统 CSP 证书库"),
            (FeatureKeys.ChangePin, "修改密码", "修改用户 PIN"),
            (FeatureKeys.UnlockDevice, "解锁设备", "PUK / AdminKey / 挑战码解锁"),
            (FeatureKeys.ResetDevice, "重置设备", "清空内容并重设口令"),
        };
        foreach (var (key, label, tip) in actions)
        {
            // 宽度取「文字宽度 + 左右内边距」，并给一个下限，避免按钮过窄显得长短不一
            var textWidth = TextRenderer.MeasureText(label, Font).Width;
            var b = new Button
            {
                Text = label,
                Width = Math.Max(96, textWidth + 26),
                Height = 32,
                Margin = new Padding(0, 0, 6, 0),
                FlatStyle = FlatStyle.Flat,
                Tag = key,
                Cursor = Cursors.Hand,
                BackColor = Color.FromArgb(0xFA, 0xFB, 0xFC),
            };
            b.FlatAppearance.BorderColor = Color.FromArgb(0xD9, 0xDE, 0xE5);
            b.Click += (s, e) => OnActionClicked((string)((Button)s!).Tag!);
            _toolTip.SetToolTip(b, label + "：" + tip);
            _actionButtons[key] = b;
            p.Controls.Add(b);
        }
        // 登录按钮与操作区的「登录/登出」是同一个动作，隐藏重复项
        _actionButtons[FeatureKeys.Login].Text = "登录/登出";
        return p;
    }

    private Control BuildLogPanel()
    {
        _logPanel.Dock = DockStyle.Fill;
        _logPanel.Visible = false;

        var gb = new GroupBox { Dock = DockStyle.Fill, Text = "运行日志", Padding = new Padding(6, 4, 6, 6) };
        _logBox.Dock = DockStyle.Fill;
        _logBox.Multiline = true;
        _logBox.ReadOnly = true;
        _logBox.ScrollBars = ScrollBars.Both;
        _logBox.WordWrap = false;
        _logBox.BackColor = Color.FromArgb(0x1E, 0x1E, 0x1E);
        _logBox.ForeColor = Color.FromArgb(0xD4, 0xD4, 0xD4);
        _logBox.Font = new Font("Consolas", 8.5F);
        _logBox.BorderStyle = BorderStyle.None;
        _logBox.TabStop = false;
        gb.Controls.Add(_logBox);
        _logPanel.Controls.Add(gb);
        return _logPanel;
    }

    private Control BuildStatusBar()
    {
        _lblStatus.Dock = DockStyle.Fill;
        _lblStatus.ForeColor = Color.DimGray;
        _lblStatus.TextAlign = ContentAlignment.MiddleLeft;
        _lblStatus.Padding = new Padding(2, 0, 0, 0);
        return _lblStatus;
    }

    private void ToggleLogPanel()
    {
        _logVisible = !_logVisible;
        _logPanel.Visible = _logVisible;
        _root.RowStyles[5].Height = _logVisible ? _logRowHeight : 0F;
        _btnLogToggle.Text = _logVisible ? "隐藏日志" : "显示日志";
        if (_logVisible) FlushLog();
    }

    // ============================================================ 日志

    private void OnLogLine(string line)
    {
        lock (_logQueue) _logQueue.Enqueue(line);
    }

    private void FlushLog()
    {
        string[] batch;
        lock (_logQueue)
        {
            if (_logQueue.Count == 0) return;
            batch = _logQueue.ToArray();
            _logQueue.Clear();
        }

        // 折叠连续重复行（枚举期各 provider 会重复打印同一条诊断，逐条刷屏没法看）
        var sb = new System.Text.StringBuilder();
        foreach (var raw in batch)
        {
            var body = raw.Length > 20 ? raw[20..] : raw; // 去掉时间戳后再比重复
            if (body == _lastLogLine)
            {
                _lastLogRepeat++;
                continue;
            }
            if (_lastLogRepeat > 0)
                sb.AppendLine($"                          … 上一条重复 {_lastLogRepeat} 次");
            _lastLogRepeat = 0;
            _lastLogLine = body;
            sb.AppendLine(raw);
        }

        _logBox.AppendText(sb.ToString());
        if (_logBox.Lines.Length > MaxLogLines)
        {
            var lines = _logBox.Lines;
            _logBox.Text = string.Join(Environment.NewLine, lines.Skip(lines.Length - MaxLogLines / 2));
            _logBox.SelectionStart = _logBox.TextLength;
        }
        if (_logVisible) _logBox.SelectionStart = _logBox.TextLength;
    }

    // ============================================================ 托盘

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
        var names = devs.Select(d => PlatformInfo.DisplayName(d.Platform) + " · " + d.TrayLabel).ToArray();
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
        ReloadPlatformList();
        ReloadDevices();
        _lblStatus.Text = _ctx.IsAdminMode ? "管理模式 · " + LicenseText() : "用户模式";
    }

    private string LicenseText() => _ctx.License?.IsValid == true
        ? "已授权 · 有效期至 " + _ctx.License!.ValidUntilUtc.ToString("yyyy-MM-dd")
        : "未授权";

    // ============================================================ 平台 / 设备

    /// <summary>填充平台下拉框（中文名 + "全部"）。保持用户当前选择。</summary>
    private void ReloadPlatformList()
    {
        var prev = (_cmbPlatform.SelectedItem as PlatformEntry)?.Key;

        _suppressPlatformChanged = true;
        try
        {
            _cmbPlatform.BeginUpdate();
            _cmbPlatform.Items.Clear();
            _cmbPlatform.Items.Add(new PlatformEntry(PlatformAll, "全部平台"));
            foreach (var p in _ctx.Config.Platform ?? new())
                _cmbPlatform.Items.Add(new PlatformEntry(p, PlatformInfo.ComboLabel(p) + PlatformAvailabilitySuffix(p)));
            _cmbPlatform.EndUpdate();

            var idx = 0;
            if (prev != null)
            {
                for (int i = 0; i < _cmbPlatform.Items.Count; i++)
                    if ((_cmbPlatform.Items[i] as PlatformEntry)?.Key == prev) { idx = i; break; }
            }
            if (_cmbPlatform.Items.Count > 0) _cmbPlatform.SelectedIndex = idx;
        }
        finally
        {
            _suppressPlatformChanged = false;
        }
    }

    private string PlatformAvailabilitySuffix(string platform)
    {
        try { return _ctx.Keys.IsPlatformAvailable(platform) ? "" : "（驱动不可用）"; }
        catch { return "（驱动不可用）"; }
    }

    private sealed record PlatformEntry(string Key, string Display)
    {
        public override string ToString() => Display;
    }

    private string CurrentPlatformKey() => (_cmbPlatform.SelectedItem as PlatformEntry)?.Key ?? PlatformAll;

    /// <summary>
    /// 重新枚举设备。<b>按平台并行扫描，各平台独立完成后立即上屏</b>，
    /// 因此慢平台（恒宝探测要 60 秒以上）不会拖住其它平台的显示。
    /// </summary>
    private async void ReloadDevices()
    {
        if (_busy || IsDisposed) return;
        if (_enumerating) { _pendingReload = true; return; }

        var scope = CurrentPlatformKey();
        _ctx.SelectedPlatform = scope == PlatformAll ? "" : scope;

        var generation = ++_scanGeneration;
        var platforms = scope == PlatformAll
            ? (_ctx.Config.Platform ?? new()).ToList()
            : new List<string> { scope };

        // 切换平台后原选中项已失效
        _devices.Clear();
        _containers.Clear();
        _gridDevices.Rows.Clear();
        _gridCerts.Rows.Clear();
        RefreshSelectionState();

        _enumerating = true;
        _btnRefresh.Enabled = false;
        _lblStatus.Text = $"正在扫描 {platforms.Count} 个平台…";

        var results = new List<PlatformScanResult>();
        var pending = platforms.Select(ScanPlatformAsync).ToList();
        try
        {
            while (pending.Count > 0)
            {
                var finished = await Task.WhenAny(pending);
                pending.Remove(finished);
                var r = await finished;

                // 新一轮扫描已开始（切平台/刷新）：本轮结果作废
                if (IsDisposed || generation != _scanGeneration) return;

                results.Add(r);
                ApplyScanResults(results, platforms);

                // 超时的平台并未被放弃：让它后台跑完，结果到了再增量上屏
                if (r.TimedOut && r.LateWork != null)
                    AttachLateMerge(r, results, platforms, generation);
            }
            FinishScan(platforms, results);
        }
        finally
        {
            if (generation == _scanGeneration)
            {
                _enumerating = false;
                _btnRefresh.Enabled = true;
                if (_pendingReload) { _pendingReload = false; ReloadDevices(); }
            }
        }
    }

    /// <summary>单个平台的扫描结果。</summary>
    /// <param name="LateWork">超时情况下仍在后台运行的任务（用于结果迟到时补上屏）。</param>
    private sealed record PlatformScanResult(
        string Platform,
        List<UsbKeyDevice> Devices,
        bool TimedOut,
        string? Error,
        Task<List<UsbKeyDevice>>? LateWork = null);

    /// <summary>
    /// 扫描单个平台。带<b>超时预算</b>：超过 <see cref="PlatformScanTimeoutMs"/> 就先交回控制权，
    /// 让其它平台的结果尽快上屏；超时的平台在后台继续跑（见 <see cref="AttachLateMerge"/>）。
    /// </summary>
    private async Task<PlatformScanResult> ScanPlatformAsync(string platform)
    {
        if (!_ctx.Keys.IsPlatformAvailable(platform))
            return new PlatformScanResult(platform, new List<UsbKeyDevice>(), false, null);

        var sw = Stopwatch.StartNew();
        var work = Task.Run(() => OnPlatform(platform, () => _ctx.Keys.EnumeratePlatform(platform)));

        if (await Task.WhenAny(work, Task.Delay(PlatformScanTimeoutMs)).ConfigureAwait(true) != work)
        {
            Log.Write($"[扫描] {PlatformInfo.DisplayName(platform)} 超过 {PlatformScanTimeoutMs} ms 未返回，" +
                      "转后台继续扫描（不阻塞其它平台）");
            return new PlatformScanResult(platform, new List<UsbKeyDevice>(), true, null, work);
        }

        try
        {
            var list = Normalize(await work, platform);
            Log.Write($"[扫描] {PlatformInfo.DisplayName(platform)} 完成 → {list.Count} 台设备（{sw.ElapsedMilliseconds} ms）");
            return new PlatformScanResult(platform, list, false, null);
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"扫描平台 {platform} 失败");
            return new PlatformScanResult(platform, new List<UsbKeyDevice>(), false, ex.Message);
        }
    }

    /// <summary>厂商未回填 Platform 时补上，保证"归属"列一定有意义。</summary>
    private static List<UsbKeyDevice> Normalize(List<UsbKeyDevice>? list, string platform)
    {
        var result = list ?? new List<UsbKeyDevice>();
        foreach (var d in result)
            if (string.IsNullOrWhiteSpace(d.Platform)) d.Platform = platform;
        return result;
    }

    /// <summary>超时平台的后台任务完成后，把迟到的结果补上屏（这才是真正的异步：慢平台不阻塞、结果到了就显示）。</summary>
    private void AttachLateMerge(PlatformScanResult timedOut, List<PlatformScanResult> results,
        List<string> platforms, int generation)
    {
        var work = timedOut.LateWork!;
        var platform = timedOut.Platform;
        _ = work.ContinueWith(t =>
        {
            if (t.Status != TaskStatus.RanToCompletion) { _ = t.Exception; return; }
            try
            {
                BeginInvoke(() =>
                {
                    if (IsDisposed || generation != _scanGeneration) return;

                    var list = Normalize(t.Result, platform);
                    // 用真实结果替换掉"超时占位"
                    results.RemoveAll(r => r.Platform.Equals(platform, StringComparison.OrdinalIgnoreCase));
                    results.Add(new PlatformScanResult(platform, list, false, null));

                    ApplyScanResults(results, platforms);
                    Log.Write($"[扫描] {PlatformInfo.DisplayName(platform)} 慢平台扫描完成 → {list.Count} 台设备");
                    UpdateScanStatus(platforms, results);
                });
            }
            catch (InvalidOperationException) { /* 窗体已销毁，忽略 */ }
        }, TaskScheduler.Default);
    }

    /// <summary>把当前已完成的平台结果按平台顺序汇总上屏（增量刷新，设备逐个平台出现）。</summary>
    private void ApplyScanResults(List<PlatformScanResult> results, List<string> platformOrder)
    {
        var keep = SelectedDevice();

        var ordered = new List<UsbKeyDevice>();
        foreach (var p in platformOrder)
        {
            var r = results.FirstOrDefault(x => x.Platform.Equals(p, StringComparison.OrdinalIgnoreCase));
            if (r != null) ordered.AddRange(r.Devices);
        }

        // 重新枚举构造的是全新对象：继承登录态，避免"刷新一下就像被登出了"
        foreach (var d in ordered)
        {
            var old = _devices.FirstOrDefault(o => SameDevice(o, d));
            if (old != null) d.IsLoggedIn = old.IsLoggedIn;
        }
        var cur = _ctx.CurrentDevice;
        if (cur != null)
        {
            var match = ordered.FirstOrDefault(o => SameDevice(o, cur));
            if (match != null) _ctx.CurrentDevice = match;
        }

        _devices.Clear();
        _devices.AddRange(ordered);

        FillDeviceGrid(keep);
        RefreshDeviceDetails();

        // 只有"选中的设备真的换了"才去读卡列容器；否则增量刷新期间会反复读卡
        var after = SelectedDevice();
        if (after != null && !SameDeviceRef(keep, after)) ReloadContainers();
        else RefreshSelectionState();
    }

    /// <summary>全部平台扫描结束后的状态栏与摘要日志。</summary>
    private void FinishScan(List<string> platforms, List<PlatformScanResult> results)
    {
        UpdateScanStatus(platforms, results);

        var scope = platforms.Count == 1 ? PlatformInfo.DisplayName(platforms[0]) : "全部平台";
        var timedOut = results.Where(r => r.TimedOut).Select(r => PlatformInfo.DisplayName(r.Platform)).ToList();
        Log.Write($"[扫描] {scope} → {_devices.Count} 台设备" +
                  (_devices.Count > 0 ? "：" + string.Join("、", _devices.Select(d => d.TrayLabel)) : "") +
                  (timedOut.Count > 0 ? $"（仍在后台扫描：{string.Join("、", timedOut)}）" : ""));

        // 设备集合变了（首次启动 / 插卡）就检查一次证书注册状态
        QueueCertAutoRegister();
    }

    // ============================================================ 证书自动注册

    /// <summary>
    /// 设备集合发生变化时触发一次证书自动注册（后台执行）。
    /// <para>
    /// 触发条件是"平台+序列号的集合变了"：这样首次启动、插入新卡都会跑，
    /// 而同一批设备的反复刷新（切平台、手动刷新）不会重复触发。
    /// 自动注册会读卡列容器并写系统证书库，所以放在后台线程，并按平台门串行化设备访问。
    /// </para>
    /// </summary>
    private void QueueCertAutoRegister()
    {
        if (IsDisposed || _autoRegisterRunning) return;
        if (!_registrar.Enabled) return;

        var signature = string.Join("|", _devices
            .Select(d => d.Platform + ":" + d.SerialNumber)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
        if (signature == _lastDeviceSignature) return;
        _lastDeviceSignature = signature;
        if (signature.Length == 0) return;      // 没有设备，不必跑

        var devices = _devices.ToList();
        _autoRegisterRunning = true;
        Log.Write($"[自动注册] 设备集合变化，检查 {devices.Count} 台设备的证书注册状态");

        Task.Run(() =>
        {
            CertAutoRegisterResult result;
            try
            {
                result = _registrar.Run(_ctx.Keys, devices, OnPlatform);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[自动注册] 执行失败");
                return;
            }
            finally
            {
                _autoRegisterRunning = false;
            }

            if (IsDisposed) return;
            BeginInvoke(() =>
            {
                if (IsDisposed) return;
                foreach (var m in result.Messages) Log.Write("[自动注册] " + m);
                Log.Write($"[自动注册] 完成：{result.Summary()}");
                _lblStatus.Text = "自动注册 " + result.Summary();
                // 注册结果会改变「已注册 / 私钥」两列：用缓存的容器列表重画，不再读一次卡
                FillCertGrid();
            });
        });
    }

    private void UpdateScanStatus(List<string> platforms, List<PlatformScanResult> results)
    {
        var skipped = platforms.Where(p => !_ctx.Keys.IsPlatformAvailable(p))
                               .Select(PlatformInfo.DisplayName).ToList();
        var slow = results.Where(r => r.TimedOut).Select(r => PlatformInfo.DisplayName(r.Platform)).ToList();
        var failed = results.Where(r => r.Error != null).Select(r => PlatformInfo.DisplayName(r.Platform)).ToList();
        // 「已发现但未就绪」的设备（如恒宝 U 宝未进入令牌模式）把原因附在状态栏，避免误判为"没发现"
        var notReady = _devices.FirstOrDefault(d => !string.IsNullOrWhiteSpace(d.Notes));

        _lblStatus.Text = $"已扫描 {_devices.Count} 台设备"
            + (slow.Count > 0 ? $"；{string.Join("、", slow)} 较慢，仍在后台扫描（完成后会自动出现）" : "")
            + (failed.Count > 0 ? $"；扫描失败：{string.Join("、", failed)}" : "")
            + (skipped.Count > 0 ? $"；驱动不可用已跳过：{string.Join("、", skipped)}" : "")
            + (notReady != null ? "；" + notReady.Notes : "");
    }

    /// <summary>
    /// 重建设备表格。
    /// <paramref name="keep"/> 指定要恢复选中的设备：登录/详情刷新后不应该把选中项跳回第一行，
    /// 否则用户看到的是另一台设备的证书，极易误操作到错误设备。
    /// </summary>
    private void FillDeviceGrid(UsbKeyDevice? keep = null)
    {
        _suppressDeviceSel = true;
        try
        {
            _gridDevices.SuspendLayout();
            _gridDevices.Rows.Clear();
            foreach (var d in _devices)
            {
                var platform = string.IsNullOrWhiteSpace(d.Platform) ? "—" : PlatformInfo.DisplayName(d.Platform);
                var vendor = string.IsNullOrWhiteSpace(d.VendorName) ? d.Model : $"{d.VendorName} / {d.Model}";
                // 设备「已发现但未就绪」（例如恒宝 U 宝未进入令牌模式）：状态列标出，并把原因作为单元格提示
                var notReady = !string.IsNullOrWhiteSpace(d.Notes);
                var idx = _gridDevices.Rows.Add(
                    platform,
                    vendor,
                    d.SerialNumber,
                    d.Vid != 0 || d.Pid != 0 ? $"{d.Vid:X4}:{d.Pid:X4}" : "—",
                    string.IsNullOrWhiteSpace(d.FirmwareVersion) ? "—" : d.FirmwareVersion,
                    d.CapacityKb > 0 ? d.CapacityKb.ToString("N0") + " KB" : "—",
                    notReady ? "未就绪" : (d.IsLoggedIn ? "已解锁" : "未解锁"));
                _gridDevices.Rows[idx].Tag = d;
                if (notReady)
                {
                    _gridDevices.Rows[idx].Cells[6].ToolTipText = d.Notes;
                    _gridDevices.Rows[idx].Cells[6].Style.ForeColor = Color.DarkOrange;
                }
            }
            _gridDevices.ResumeLayout();

            var target = keep != null ? FindDeviceRow(keep) : null;
            target ??= _gridDevices.Rows.Count > 0 ? _gridDevices.Rows[0] : null;
            if (target != null)
            {
                _gridDevices.ClearSelection();
                target.Selected = true;
                _gridDevices.CurrentCell = target.Cells[0];
            }
        }
        finally
        {
            _suppressDeviceSel = false;
        }
    }

    private DataGridViewRow? FindDeviceRow(UsbKeyDevice dev)
    {
        // 先按对象匹配；增量扫描会构造新对象，因此再退化为按 平台+序列号 匹配
        foreach (DataGridViewRow r in _gridDevices.Rows)
            if (ReferenceEquals(r.Tag, dev)) return r;
        foreach (DataGridViewRow r in _gridDevices.Rows)
            if (r.Tag is UsbKeyDevice d && SameDevice(d, dev)) return r;
        return null;
    }

    /// <summary>同一台物理设备的判定（平台 + 序列号），用于跨次枚举继承会话状态。</summary>
    private static bool SameDevice(UsbKeyDevice a, UsbKeyDevice b) =>
        string.Equals(a.Platform, b.Platform, StringComparison.OrdinalIgnoreCase) &&
        a.SerialNumber == b.SerialNumber;

    private static bool SameDeviceRef(UsbKeyDevice? a, UsbKeyDevice? b) =>
        a != null && b != null && SameDevice(a, b);

    // ============================================================ 平台访问门

    private object PlatformGate(string? platform) =>
        _platformGates.GetOrAdd(string.IsNullOrWhiteSpace(platform) ? "_default" : platform.Trim(), _ => new object());

    /// <summary>在指定平台的门上串行执行（跨平台可并行，避免慢平台拖住全局）。</summary>
    private void OnPlatform(string? platform, Action work)
    {
        lock (PlatformGate(platform)) work();
    }

    private T OnPlatform<T>(string? platform, Func<T> work)
    {
        lock (PlatformGate(platform)) return work();
    }

    /// <summary>没有设备上下文的操作（如把证书注册/注销到系统证书库）用当前选中设备的平台。</summary>
    private string OpPlatform() => SelectedDevice()?.Platform ?? _ctx.SelectedPlatform;

    /// <summary>当前选中设备：直接来自缓存（绝不重新枚举）。</summary>
    private UsbKeyDevice? SelectedDevice() =>
        _gridDevices.CurrentRow?.Tag as UsbKeyDevice;

    private void OnDeviceSelected()
    {
        RefreshDeviceDetails();
        ReloadContainers();
        RefreshSelectionState();
    }

    private void RefreshDeviceDetails()
    {
        var dev = SelectedDevice();
        if (dev == null)
        {
            _lblDevPlatform.Text = _lblDevModel.Text = _lblDevSerial.Text = "—";
            _lblDevVidPid.Text = _lblDevFw.Text = _lblDevCap.Text = "—";
            _btnLogin.Text = "登录";
            return;
        }
        _lblDevPlatform.Text = string.IsNullOrWhiteSpace(dev.Platform) ? "—" : PlatformInfo.DisplayName(dev.Platform);
        _lblDevModel.Text = string.IsNullOrWhiteSpace(dev.VendorName) ? dev.Model : $"{dev.VendorName} {dev.Model}";
        _lblDevSerial.Text = string.IsNullOrWhiteSpace(dev.SerialNumber) ? "—" : dev.SerialNumber;
        _lblDevVidPid.Text = dev.Vid != 0 || dev.Pid != 0 ? $"{dev.Vid:X4}:{dev.Pid:X4}" : "—";
        _lblDevFw.Text = string.IsNullOrWhiteSpace(dev.FirmwareVersion) ? "—" : dev.FirmwareVersion;
        _lblDevCap.Text = dev.CapacityKb > 0 ? dev.CapacityKb.ToString("N0") + " KB" : "—";
        _btnLogin.Text = dev.IsLoggedIn ? "登出" : "登录";

        // 设备「已发现但未就绪」时（例如恒宝 U 宝未进入令牌模式 C_GetTokenInfo=CKR_FUNCTION_FAILED），
        // 把厂商侧诊断直接显示出来，避免用户误以为"设备根本没被发现"。
        if (!string.IsNullOrWhiteSpace(dev.Notes))
            _lblStatus.Text = dev.Notes;
    }

    /// <summary>
    /// 加载当前设备的容器/证书列表（缓存）。
    /// <para>
    /// 这里<b>刻意不检查登录态</b>：列容器走的是另一套底层接口，多数平台根本不需要 PIN 认证
    /// （例如 BJCA 的 <c>SOF_GetUserList</c> / <c>SOF_GetAllContainerName</c> / <c>SOF_ExportUserCert</c>）。
    /// 早期实现要求"先登录才显示证书"，于是刚导入完证书的空卡因为登不上去而什么都看不到。
    /// 确实需要认证的平台会自己抛错，届时给出提示即可。
    /// </para>
    /// </summary>
    private void ReloadContainers()
    {
        _containers.Clear();
        var dev = SelectedDevice();
        var prov = dev != null ? _ctx.Keys.GetProvider(dev.Platform) : null;
        if (dev == null || prov == null) { FillCertGrid(); return; }

        try
        {
            OnPlatform(dev.Platform, () => _containers.AddRange(prov.ListContainers(dev)));
            if (_containers.Count > 0 && !dev.IsLoggedIn)
                _lblStatus.Text = $"已列出 {_containers.Count} 个容器/证书（未登录，证书详情可能不完整；需要时点「登录」）";
            Log.Write($"[证书] {PlatformInfo.DisplayName(dev.Platform)} {dev.SerialNumber} " +
                      $"→ {_containers.Count} 项（登录={dev.IsLoggedIn}）");
        }
        catch (Exception ex)
        {
            _lblStatus.Text = (dev.IsLoggedIn ? "加载证书列表失败：" : "加载证书列表失败（可能需要先登录）：") + ex.Message;
        }
        FillCertGrid();
    }

    private void FillCertGrid()
    {
        // 空列表时把原因写在标题上：区分"设备上真的没有证书"和"刷新没生效"
        var devNow = SelectedDevice();
        _gbCerts.Text = _containers.Count > 0
            ? $"证书 / 容器（{_containers.Count} 项）"
            : devNow == null
                ? "证书 / 容器"
                : "证书 / 容器（该设备上暂无证书 —— 可点「证书登记」在卡内生成密钥并导入 CA 签发的证书）";

        // 一次性读系统证书库，按指纹判断"注册了没有"（比逐个开库快，也比 provider 自己标的准）
        HashSet<string> inStore;
        try { inStore = CertHelper.RegisteredThumbprints(); }
        catch { inStore = new HashSet<string>(StringComparer.OrdinalIgnoreCase); }

        _suppressCertSel = true;
        try
        {
            _gridCerts.SuspendLayout();
            _gridCerts.Rows.Clear();
            foreach (var c in _containers)
            {
                var registered = !string.IsNullOrEmpty(c.Thumbprint) && inStore.Contains(c.Thumbprint);
                c.IsRegisteredInCsp = registered;

                var idx = _gridCerts.Rows.Add(
                    c.ContentText,
                    c.Name,
                    c.Subject,
                    c.Algorithm,
                    c.KeyUsage,
                    c.ValidityText,
                    c.ContainerUuid,
                    registered ? "是" : "");
                _gridCerts.Rows[idx].Tag = c;

                // 非证书条目（仅密钥 / 空容器）用不同底色提示，避免与真证书混淆
                if (c.Content is KeyContainerContent.KeyOnly or KeyContainerContent.Empty
                    or KeyContainerContent.Unknown)
                {
                    _gridCerts.Rows[idx].DefaultCellStyle.ForeColor = Color.DimGray;
                    _gridCerts.Rows[idx].Cells[0].ToolTipText = c.Algorithm;
                }
            }
            _gridCerts.ResumeLayout();
            if (_gridCerts.Rows.Count > 0)
            {
                _gridCerts.ClearSelection();
                _gridCerts.Rows[0].Selected = true;
                _gridCerts.CurrentCell = _gridCerts.Rows[0].Cells[0];
            }
        }
        finally
        {
            _suppressCertSel = false;
        }
        OnCertSelected();
    }

    private KeyContainer? SelectedCert() => _gridCerts.CurrentRow?.Tag as KeyContainer;

    private void OnCertSelected()
    {
        var c = SelectedCert();
        if (c == null)
        {
            _lblCertSubject.Text = _lblCertAlgo.Text = _lblCertUsage.Text = "—";
            _lblCertEku.Text = _lblCertValidity.Text = _lblCertUuid.Text = "—";
            if (_gridCerts.Rows.Count == 0 && SelectedDevice()?.IsLoggedIn == true)
                _gridCerts.Rows.Clear();
        }
        else
        {
            _lblCertSubject.Text = c.Subject;
            _lblCertAlgo.Text = c.Algorithm;
            _lblCertUsage.Text = c.KeyUsage;
            _lblCertEku.Text = c.ExtendedKeyUsage;
            _lblCertValidity.Text = c.ValidityText;
            _lblCertUuid.Text = c.ContainerUuid;
        }
        RefreshSelectionState();
    }

    private void RefreshSelectionState()
    {
        var dev = SelectedDevice();
        var cert = SelectedCert();
        var prov = dev != null ? _ctx.Keys.GetProvider(dev.Platform) : null;
        bool logged = dev?.IsLoggedIn == true && _ctx.IsLoggedIn;
        bool hasDevice = dev != null;
        bool hasCert = cert != null;
        bool admin = _ctx.IsAdminMode;

        foreach (var (key, btn) in _actionButtons)
        {
            var st = _ctx.Config.GetFeatureState(key);
            if (!admin && (key == FeatureKeys.ImportCert || key == FeatureKeys.ResetDevice))
                st = FeatureState.Disabled;

            btn.Enabled = st == FeatureState.Enabled;
            if (st == FeatureState.Enabled)
            {
                bool needDevice = key is FeatureKeys.Login or FeatureKeys.CloudImport or FeatureKeys.ImportCert
                    or FeatureKeys.EnrollCert or FeatureKeys.ChangePin or FeatureKeys.UnlockDevice
                    or FeatureKeys.ResetDevice;
                bool needCert = key is FeatureKeys.ViewCert or FeatureKeys.ExportCert
                    or FeatureKeys.DeleteCert or FeatureKeys.RegisterCert;
                if (needDevice && !hasDevice) btn.Enabled = false;
                if (needCert && !hasCert) btn.Enabled = false;

                if (key is FeatureKeys.ImportCert)
                {
                    // 能力驱动，而不是一刀切要求登录：
                    // · 不支持导入 PFX 的平台（SKF / ePass3003）直接禁用；
                    // · 只有真正依赖登录会话的平台（模拟设备）才要求已登录；
                    // · BJCA 等用「序列号+PFX密码」导入的平台，空卡未登录也能导入。
                    var canImport = prov != null && prov.SupportsImportPfx
                                    && (!prov.ImportRequiresLogin || logged);
                    btn.Enabled &= canImport;
                    btn.Text = prov != null && !prov.SupportsImportPfx ? "导入证书 ✕" : "导入证书";
                    _toolTip.SetToolTip(btn, prov != null && !prov.SupportsImportPfx
                        ? "该平台私钥卡内生成、不可导入，请改用「证书登记」"
                        : "本地导入 PFX 证书");
                }
                else if (key is FeatureKeys.EnrollCert)
                {
                    btn.Enabled &= prov?.SupportsKeyEnrollment == true;
                    _toolTip.SetToolTip(btn, prov?.SupportsKeyEnrollment == true
                        ? "卡内生成密钥 → 导出 P10 → 导回 CA 签发证书"
                        : "该平台未实现卡内发证流程");
                }
                else if (key is FeatureKeys.ChangePin or FeatureKeys.CloudImport && !logged)
                {
                    btn.Enabled = false;
                }

                // 登录按钮随设备登录态切换文案
                if (key is FeatureKeys.Login) btn.Text = logged ? "登出" : "登录";
            }
        }
        _btnLogin.Enabled = hasDevice && !_busy;
        _btnLogin.Text = dev?.IsLoggedIn == true ? "登出" : "登录";
    }

    private void RefreshAll()
    {
        if (IsDisposed) return;
        ReloadDevices();
    }

    /// <summary>上下文状态变化（登录态、设置保存等）：刷新按钮，并在设置页请求时补跑一次自动注册。</summary>
    private void OnCtxStateChanged()
    {
        if (IsDisposed) return;
        RefreshSelectionState();
        if (!_ctx.CertAutoRegisterRequested) return;
        _ctx.CertAutoRegisterRequested = false;
        _lastDeviceSignature = "";   // 清掉指纹，强制重新检查一轮
        QueueCertAutoRegister();
    }

    private void RefreshLoginState()
    {
        if (_ctx.CurrentDevice != null && !_ctx.IsLoggedIn)
        {
            _lblStatus.Text = "会话已超时，请重新登录";
            var keep = SelectedDevice();
            _ctx.MarkLoggedOut();
            _ctx.CurrentDevice = null;
            foreach (var d in _devices) d.IsLoggedIn = false;
            FillDeviceGrid(keep);
            RefreshDeviceDetails();
            ReloadContainers();
            RefreshSelectionState();
        }
    }

    // ============================================================ 操作

    private void ToggleLogin()
    {
        var dev = SelectedDevice();
        if (dev == null) return;
        var prov = _ctx.Keys.GetProvider(dev.Platform);
        if (prov == null) { MessageBox.Show("未找到该设备的平台驱动。", AppConfig.SoftwareName); return; }

        if (dev.IsLoggedIn)
        {
            RunBusy("正在登出…", () =>
            {
                try { OnPlatform(dev.Platform, () => prov.Logout(dev)); }
                catch (Exception ex) { Log.Error(ex, "登出失败"); }
                dev.IsLoggedIn = false;
                _ctx.MarkLoggedOut();
            });
            FillDeviceGrid(dev);
            RefreshDeviceDetails();
            ReloadContainers();
            RefreshSelectionState();
            _lblStatus.Text = "已登出";
            return;
        }

        var pin = InputDialog.Ask(this, "登录", "请输入 PIN 进行认证：");
        if (pin == null) return;
        try
        {
            RunBusy("正在认证…", () => OnPlatform(dev.Platform, () => prov.Login(dev, pin)));
            dev.IsLoggedIn = true;
            _ctx.MarkLoggedIn(dev);
            _lblStatus.Text = "已登录（解锁）";
            FillDeviceGrid(dev);
            RefreshDeviceDetails();
            ReloadContainers();
            RefreshSelectionState();
        }
        catch (Exception ex)
        {
            MessageBox.Show("登录失败：" + ex.Message, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OnActionClicked(string key)
    {
        var dev = SelectedDevice();
        var cert = SelectedCert();
        var prov = dev != null ? _ctx.Keys.GetProvider(dev.Platform) : null;

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
                case FeatureKeys.Login:
                    ToggleLogin();
                    break;
                case FeatureKeys.CloudImport:
                    MessageUnavailable("云端导入功能暂未开通。");
                    break;
                case FeatureKeys.ImportCert:
                    DoImportPfx(prov!, dev!);
                    break;
                case FeatureKeys.EnrollCert:
                    DoEnroll(prov!, dev!);
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
            // 过去这里会统一追加"该功能需要完成驱动接口逆向对接后可用"，但多数情况
            // 并非接口没对接，而是设备本身不支持该动作（如私钥不可导出/导入），
            // provider 的原文已经说明了原因与替代路径，不再画蛇添足。
            MessageBox.Show(ex.Message, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("操作失败：" + ex.Message, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    /// <summary>敏感/耗时操作期间禁用界面并显示等待光标，避免误点与误判"卡死"。</summary>
    private void RunBusy(string status, Action work)
    {
        _busy = true;
        Cursor = Cursors.WaitCursor;
        _lblStatus.Text = status;
        _root.Enabled = false;
        try
        {
            work();
        }
        finally
        {
            _root.Enabled = true;
            Cursor = Cursors.Default;
            _busy = false;
        }
    }

    /// <summary>打开证书登记向导（卡内生成密钥 → 导出 P10 → 导回签发证书）。</summary>
    private void DoEnroll(IKeyProvider prov, UsbKeyDevice dev)
    {
        if (!prov.SupportsKeyEnrollment)
        {
            MessageBox.Show($"{PlatformInfo.DisplayName(dev.Platform)} 未实现卡内发证流程。",
                AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        using var f = new EnrollForm(prov, dev);
        f.ShowDialog(this);
        ReloadDevices();
    }

    private void DoImportPfx(IKeyProvider prov, UsbKeyDevice dev)
    {
        if (!prov.SupportsImportPfx)
        {
            OfferEnroll(prov, dev,
                $"{PlatformInfo.DisplayName(dev.Platform)} 的私钥在卡内生成、不可导出也不可导入，\n" +
                "因此无法导入外部 PFX。");
            return;
        }

        using var ofd = new OpenFileDialog { Filter = "PFX 证书(*.pfx;*.p12)|*.pfx;*.p12|所有文件|*.*", Title = "选择要导入的 PFX 文件" };
        if (ofd.ShowDialog(this) != DialogResult.OK) return;
        var pwd = InputDialog.Ask(this, "导入证书", "请输入 PFX 文件密码：", masked: true);
        if (pwd == null) return;
        try
        {
            RunBusy("正在导入证书…", () => OnPlatform(dev.Platform, () => prov.ImportPfx(dev, ofd.FileName, pwd)));
            MessageBox.Show("证书导入成功。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            ReloadContainers();
        }
        catch (NotSupportedException ex)
        {
            // 导入不了不是死路：直接引导到卡内发证流程
            OfferEnroll(prov, dev, ex.Message);
        }
    }

    /// <summary>导入 PFX 不可行时，直接引导到「证书登记」（卡内生成密钥 → CSR → 导回证书）。</summary>
    private void OfferEnroll(IKeyProvider prov, UsbKeyDevice dev, string reason)
    {
        if (!prov.SupportsKeyEnrollment)
        {
            MessageBox.Show(reason, "导入证书", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var r = MessageBox.Show(
            reason + Environment.NewLine + Environment.NewLine +
            "是否现在打开「证书登记」向导？" + Environment.NewLine +
            "（卡内生成密钥对 → 导出 PKCS#10 交给 CA 签发 → 把签发证书导回设备）",
            "导入证书", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
        if (r == DialogResult.Yes) DoEnroll(prov, dev);
    }

    private void DoExportCert(IKeyProvider prov, KeyContainer cert)
    {
        var dev = SelectedDevice();
        if (dev == null) return;
        if (!cert.HasCertificate)
        {
            MessageBox.Show($"该条目是「{cert.ContentText}」，没有可导出的证书。",
                AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        using var sfd = new SaveFileDialog
        {
            Filter = "证书(*.cer)|*.cer|证书(*.crt)|*.crt",
            FileName = ContainerLabel(cert) + ".cer",   // 仅密钥/空容器没有证书 CN，回退用容器名
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        RunBusy("正在导出证书…", () => OnPlatform(dev.Platform, () => prov.ExportCertificate(dev, cert, sfd.FileName)));
        MessageBox.Show("证书已导出（仅公钥部分，不含私钥）。", AppConfig.SoftwareName);
    }

    /// <summary>
    /// 容器条目的显示名：优先证书 CN，其次容器名。
    /// （「仅密钥 / 空容器」没有证书 CN，此时用容器名，避免对话框里出现空白引号。）
    /// </summary>
    private static string ContainerLabel(KeyContainer c) =>
        !string.IsNullOrWhiteSpace(c.Name) ? c.Name
        : !string.IsNullOrWhiteSpace(c.ContainerName) ? c.ContainerName
        : c.ContainerUuid;

    /// <summary>
    /// 把「容器名/设备序列号」归一成纯容器名，用于跨通道比对同一容器。
    /// <para>
    /// BJCA 的 <c>SOF_GetUserList</c> 返回 <c>UserKey/5303201812001784</c>（容器名 + '/' + 序列号），
    /// 而 SKF 侧的容器名是纯 <c>UserKey</c>；不归一化就永远匹配不上。
    /// （与 <c>BjcaProvider.ContainerKey</c> 同一套规则。）
    /// </para>
    /// </summary>
    private static string ContainerKeyOf(string? idOrName)
    {
        var v = (idOrName ?? "").Trim();
        var slash = v.IndexOf('/');
        return slash > 0 ? v[..slash].Trim() : v;
    }

    private void DoDeleteCert(IKeyProvider prov, UsbKeyDevice dev, KeyContainer cert)
    {
        // ---------- 1) 选择有删除权限的通道 ----------
        //
        // BJCA 组件对「非本通道创建」的容器没有删除权，会返回「删除容器失败」，
        // 其官方错误码表（BjcaCertAide/errorinfo.json）0x0B000028 的处置建议即为
        // 「是否有此容器；没有此容器删除权限，需厂商删除」——即该通道删不掉别处建的容器。
        // 而同一张卡在 SKF（GM/T 0016）链路下拥有完整的容器管理权限（Roadmap/08 §4 已实测）。
        // 因此这里自动改走 SKF 通道执行删除，让「删除」在一台卡上真正可用。
        bool switchToSkf = false;
        if (dev.Platform == BjcaProvider.Platform)
        {
            var skfProv = _ctx.Keys.GetProvider(SkfProvider.Platform);
            var skfDev = _devices.FirstOrDefault(d => d.Platform == SkfProvider.Platform
                                                   && d.SerialNumber == dev.SerialNumber);
            if (skfProv != null && skfDev != null)
            {
                // 回退前必须先在 SKF 侧按名字找到对应实体，不能直接把 BJCA 的名字交给 SKF。
                //
                // 原因：两侧的「容器名」不是同一套命名空间 ——
                //   BJCA 的 SOF_GetUserList 给的是「容器名/设备序列号」（如 UserKey/5303201812001784），
                //   而 SKF_EnumContainer 给的是纯容器名（UserKey）。
                // 直接把带 "/序列号" 的名字传给 SKF_DeleteContainer，会因找不到容器而返回
                // 含义含糊的 0x0A00002E（实测：与拿一个根本不存在的容器名去调用时是同一个错误码）。
                var skfList = skfProv.ListContainers(skfDev);
                var wantName = ContainerKeyOf(cert.ContainerName);
                var match = skfList.FirstOrDefault(c =>
                    string.Equals(ContainerKeyOf(c.ContainerName), wantName, StringComparison.OrdinalIgnoreCase));

                if (match == null)
                {
                    throw new InvalidOperationException(
                        $"卡上（SKF 视角）不存在容器「{cert.ContainerName}」。" + Environment.NewLine +
                        Environment.NewLine +
                        "原因：该条目只存在于「北京CA」组件自己的记录里（SOF_GetUserList），" +
                        "卡内并没有对应的容器实体。" + Environment.NewLine +
                        "这两者是相互独立的数据源 —— 用 SKF 删除卡内容器，不会同步清理 BJCA 的那份记录。" +
                        Environment.NewLine + Environment.NewLine +
                        "当前卡上真实存在的容器：" +
                        (skfList.Count == 0
                            ? "（无）"
                            : string.Join("、", skfList.Select(c => c.ContainerName))));
                }

                Log.Write($"[删除] BJCA 通道无该容器的删除权限，改由 SKF 通道执行（{dev.SerialNumber} / {match.ContainerName}）");
                prov = skfProv;
                dev = skfDev;
                cert = match;          // 换成 SKF 侧的真实条目：名字与「内容类型」都以卡上为准
                switchToSkf = true;
            }
        }
        bool viaSkf = switchToSkf || prov is SkfProvider;

        // ---------- 2) 确认（按内容类型给出不同措辞） ----------
        var label = ContainerLabel(cert);
        var (what, warn) = cert.Content switch
        {
            KeyContainerContent.Certificate =>
                ($"证书「{label}」", "该容器内的密钥对会一并删除，且无法恢复。"),
            KeyContainerContent.KeyOnly =>
                ($"密钥容器「{label}」", "该容器内只有密钥、尚无证书，删除后密钥无法恢复。"),
            KeyContainerContent.Empty =>
                ($"空容器「{label}」", "该容器内既无密钥也无证书，删除仅清理残留条目。"),
            _ =>
                ($"容器「{label}」", "该条目对应的容器实体会被整体删除，其中的密钥/证书一并消失且无法恢复。"),
        };

        if (MessageBox.Show(
                $"确认从 USB Key 删除{what}？" + Environment.NewLine + warn +
                (switchToSkf ? Environment.NewLine + Environment.NewLine +
                              "说明：当前「北京CA」通道无权删除该容器，将改由同一张卡的「SKF 通用」通道执行。" : ""),
                "删除容器", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        // ---------- 3) SKF 删除需要管理员权限，先取管理口令 ----------
        // 权限来源不是我们的约定，而是中间件强制要求的。零写入对照实验（CertListProbe --probe-delete-perm）实测：
        //   ① 未认证 → SKF_DeleteContainer 返回「用户没有登录（0x0A00002D）」
        //   ② 已认证 → 才会走到「容器是否存在」的判定
        // 即权限检查发生在最前面，无法绕过。原因是 GM/T 0016 的双 PIN 权限模型：
        // 管理口令（type=0）管「结构」——建/删容器、管文件、重设用户 PIN；
        // 用户 PIN（type=1）管「使用」——登录、签名、解密。
        string? adminPin = null;
        if (viaSkf)
        {
            adminPin = InputDialog.Ask(this, "删除容器",
                "SKF 删除容器需要「管理口令（SO PIN）」。\n" +
                "这是 GM/T 0016 的权限模型：管理口令管「结构」（建/删容器、重设用户 PIN），\n" +
                "用户 PIN 管「使用」（登录/签名/解密）。删除容器会销毁其中的密钥与证书，属结构操作。\n" +
                "（实测未认证时中间件直接返回「用户没有登录 0x0A00002D」，无法绕过。）\n" +
                "\n" +
                "出厂未修改过：留空即可（使用默认值 " + SkfProvider.DefaultAdminPin + "）。\n" +
                "已修改过：必须填写，否则删除会被拒绝。",
                masked: true, allowEmpty: true);
            if (adminPin == null) return;                                  // 用户取消
            if (adminPin.Length == 0) adminPin = SkfProvider.DefaultAdminPin;
        }

        // ---------- 4) 执行 ----------
        RunBusy("正在删除容器…", () => OnPlatform(dev.Platform, () =>
        {
            if (viaSkf && prov is SkfProvider skf)
                skf.VerifyAdminPin(dev, adminPin!);                     // 删除的前置条件

            // 只有真证书才需要从系统证书库注销；空容器/仅密钥条目没有指纹，注销无从谈起
            if (cert.HasCertificate && cert.IsRegisteredInCsp)
            {
                try { prov.UnregisterFromCsp(cert); } catch { /* 注销失败不阻断删除 */ }
            }
            prov.DeleteContainer(dev, cert);

            // 走 SKF 删除成功后，再让 BJCA 侧也执行一次「同步删除」，做到任一侧删除、两侧都清。
            if (viaSkf) SyncBjcaDelete(dev.SerialNumber, cert.ContainerName);
        }));
        // 容器已从卡上消失：清掉它的注册记录，否则下次启动会按记录去补注册一个不存在的证书
        if (cert.HasCertificate && !string.IsNullOrEmpty(cert.Thumbprint))
        {
            if (_registrar.Store.RemoveByThumbprint(cert.Thumbprint) > 0) _registrar.Store.Save();
        }

        MessageBox.Show($"{what} 已删除。" + (viaSkf ? "（经 SKF 链路执行）" : ""),
            AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        ReloadContainers();
    }

    /// <summary>
    /// 尽力让 BJCA 组件也执行一次删除，用于刷新它自己的用户列表缓存 ——
    /// 目的是做到「任一侧删除，两侧的列表都清干净」。
    ///
    /// <para><b>为什么需要它</b>：BJCA 组件的删除其实与 SKF 的删除是同一件事 ——
    /// 组件内部就是调 <c>SKF_DeleteContainer</c>（现场 trace 日志
    /// <c>C:\BJCAROOT\BJCAlog\xtx\XTXAppCOM.log</c> 中 <c>cryptousbicwrap.cpp:1167</c> 可证），
    /// 但它额外维护了一份<b>进程内的用户列表缓存</b>
    /// （<c>CryptokenBucket::GetUserListString</c>，<c>cryptobucket.cpp:250</c>）。
    /// SKF 直接删除不会更新那份缓存，于是表现为「卡上已删、BJCA 却仍然列出该证书」。</para>
    ///
    /// <para><b>失败一律忽略</b>：容器既然已从卡上移除，组件必然返回
    /// 「删除容器失败（0x0B000028）」，这属预期结果，不应干扰已成功的删除。</para>
    /// </summary>
    private void SyncBjcaDelete(string sn, string containerName)
    {
        try
        {
            if (_ctx.Keys.GetProvider(BjcaProvider.Platform) is not BjcaProvider bjca || !bjca.IsAvailable)
                return;
            var bjcaDev = _devices.FirstOrDefault(d => d.Platform == BjcaProvider.Platform
                                                    && d.SerialNumber == sn);
            if (bjcaDev == null) return;

            bjca.RemoveContainer(bjcaDev, containerName);
            Log.Write($"[删除] 已请求 BJCA 组件同步删除 {containerName}（刷新其用户列表缓存）");
        }
        catch (Exception ex)
        {
            Log.Write($"[删除] BJCA 侧同步删除未成功（可忽略：容器已从卡上移除）：{ex.Message}");
        }
    }

    private void DoRegisterToggle(IKeyProvider prov, KeyContainer cert)
    {
        var dev = SelectedDevice();
        if (dev == null) return;

        // ---------- 注销 ----------
        if (cert.IsRegisteredInCsp)
        {
            RunBusy("正在注销…", () => OnPlatform(OpPlatform(), () => prov.UnregisterFromCsp(cert)));
            // 必须同时删掉注册记录：否则下次启动的自动注册会把它又加回来
            _registrar.Store.RemoveByThumbprint(cert.Thumbprint);
            _registrar.Store.Save();
            MessageBox.Show("已从系统证书库注销。" + Environment.NewLine +
                            "（本地注册记录已一并删除，重启后不会被自动注册回来）", AppConfig.SoftwareName);
            ReloadContainers();
            return;
        }

        // ---------- 注册 ----------
        RunBusy("正在注册…", () => OnPlatform(OpPlatform(), () => prov.RegisterToCsp(cert)));

        // 持久化：记录"这张证书来自哪台卡"，供下次启动自动注册
        _registrar.Store.Upsert(new CertRegistrationRecord
        {
            Platform = dev.Platform,
            SerialNumber = dev.SerialNumber,
            ContainerName = cert.ContainerName,
            ContainerUuid = cert.ContainerUuid,
            Thumbprint = cert.Thumbprint,
            FriendlyName = cert.Name,
            RegisteredAtUtc = DateTime.UtcNow,
            LastSeenUtc = DateTime.UtcNow,
            NotAfterUtc = cert.NotAfter?.ToUniversalTime(),
        });
        _registrar.Store.Save();

        MessageBox.Show("已注册到系统证书库。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        ReloadContainers();
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
        RunBusy("正在修改密码…", () => OnPlatform(dev.Platform, () => prov.ChangePin(dev, oldPin, newPin)));
        MessageBox.Show("密码修改成功。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void DoUnlock(IKeyProvider prov, UsbKeyDevice dev)
    {
        using var dlg = new ChoiceDialog("解锁设备", "选择解锁方式：", new[] { "PUK 解锁", "Admin Key 解锁", "挑战码解锁" });
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        if (dlg.SelectedIndex == 2)
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
            RunBusy("正在解锁…", () => OnPlatform(dev.Platform, () => prov.UnlockByChallenge(dev, challenge, resp, newPin)));
            MessageBox.Show("解锁成功，PIN 已重置。", AppConfig.SoftwareName);
        }
        else
        {
            var cred = InputDialog.Ask(this, "解锁设备", dlg.SelectedIndex == 0 ? "请输入 PUK：" : "请输入 Admin Key：");
            if (cred == null) return;
            var newPin = InputDialog.Ask(this, "解锁设备", "请输入新的 PIN：");
            if (newPin == null) return;
            Validators.EnsurePin(newPin);
            RunBusy("正在解锁…", () => OnPlatform(dev.Platform, () => prov.Unlock(dev, (UnlockMethod)dlg.SelectedIndex, cred, newPin)));
            MessageBox.Show("解锁成功，PIN 已重置。", AppConfig.SoftwareName);
        }
        ReloadContainers();
    }

    private void DoReset(IKeyProvider prov, UsbKeyDevice dev)
    {
        var platform = prov.PlatformName.ToLowerInvariant();
        bool isLnca = platform is "lnca" or "lnca1" or "lnca2";
        bool isBjca = platform == "bjca";
        bool isSkf = platform == "skf";
        bool needCurrentPin = prov.ResetRequiresCurrentPin;

        string msg;
        if (isSkf)
        {
            msg = "将清空此 USB Key 的全部容器（密钥与证书）与应用内文件，并重设「管理口令」与「用户 PIN」。\n\n" +
                  "说明：SKF（GM/T 0016）接口无法删除卡内应用（需厂商设备认证密钥），\n" +
                  "本操作等价于「清空内容 + 重设两套口令」，不可撤销。是否继续？";
        }
        else if (needCurrentPin)
        {
            msg = "将清空此 U 宝上的全部证书与密钥，并把口令重设为新口令。\n\n" +
                  "说明：本设备未实现 PKCS#11 令牌初始化（C_InitToken / C_InitPIN 均为未实现），\n" +
                  "因此本操作等价于「清空内容 + 重设口令」；如需恢复出厂状态（口令回到 111111、\n" +
                  "卡片文件系统一并复位），请使用厂商工具 CMBCu.exe 或到银行柜台处理。\n\n是否继续？";
        }
        else if (isBjca)
        {
            msg = "将初始化（重置）此 USB Key：清空全部容器、证书与密钥，并重设「管理口令（SO PIN）」与「用户 PIN」。\n\n" +
                  "说明：本操作调用 BJCA 客户端组件的 InitDeviceEx（等同于厂商工具的设备初始化），不可撤销。\n\n是否继续？";
        }
        else if (isLnca)
        {
            msg = "将完全格式化此 USB Key（清除证书、密钥与全部数据区）并重设 PIN，操作不可撤销。是否继续？";
        }
        else
        {
            msg = "将初始化（重置）此 USB Key，所有证书将被清除。是否继续？";
        }
        if (MessageBox.Show(msg, "重置设备", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        string? currentPin = null;
        if (isSkf)
        {
            currentPin = InputDialog.Ask(this, "重置设备",
                "请输入该 USBKey 的「管理口令（SO PIN）」。\n" +
                "出厂未修改过：直接留空，程序使用默认值 " + SkfProvider.DefaultAdminPin + "。\n" +
                "已修改过：必须填写，否则初始化会失败。",
                masked: true, allowEmpty: true);
            if (currentPin == null) return;                    // 取消
            if (currentPin.Length == 0) currentPin = SkfProvider.DefaultAdminPin;  // 留空 = 用默认值
        }
        else if (needCurrentPin)
        {
            currentPin = InputDialog.Ask(this, "重置设备",
                "请输入当前口令（必填：本设备无管理员/PUK 通道，需先通过用户口令认证才能清空并重设）：", masked: true);
            if (string.IsNullOrEmpty(currentPin))
            {
                MessageBox.Show("必须提供当前口令，操作已取消。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }

        var newPin = InputDialog.Ask(this, "重置设备", "设置新的 PIN（6 位起）：");
        if (newPin == null) return;
        Validators.EnsurePin(newPin);

        string? puk = null, admin = null;
        if (isSkf)
        {
            admin = InputDialog.Ask(this, "重置设备",
                "设置新的「管理口令（SO PIN）」：\n留空表示沿用当前管理口令。", masked: true, allowEmpty: true);
            if (string.IsNullOrWhiteSpace(admin)) admin = null;
        }
        else if (needCurrentPin)
        {
            // 该平台没有 PUK / Admin Key 概念，不询问
        }
        else if (isBjca)
        {
            admin = InputDialog.Ask(this, "重置设备",
                "请输入该 USBKey 的「管理口令（SO PIN）」。\n" +
                "出厂未修改过：直接留空，程序使用默认值 " + BjcaProvider.DefaultAdminPin + "。\n" +
                "已修改过：必须填写，否则初始化会失败。", masked: true, allowEmpty: true);
            if (string.IsNullOrWhiteSpace(admin)) admin = null;

            if (MessageBox.Show(
                    "是否自定义设备密钥标签（KeyLabel）？\n\n默认使用 BJCA-UserKey（组件内置默认值）。",
                    "重置设备", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                var label = InputDialog.Ask(this, "重置设备",
                    "请输入设备标签：\n留空表示使用默认 BJCA-UserKey。", masked: false, allowEmpty: true);
                if (!string.IsNullOrWhiteSpace(label)) puk = label.Trim();
            }
        }
        else if (isLnca)
        {
            if (MessageBox.Show(
                    "是否提供管理员口令（SO PIN）？\n\n" +
                    "· 未改过出厂口令的卡：可不填，程序使用 SDK 内置传输密钥。\n" +
                    "· 已改过口令的卡：必须填写，否则 COS 层无法完成格式化。",
                    "重置设备", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                admin = InputDialog.Ask(this, "重置设备",
                    "请输入管理员口令（SO PIN）：\n留空表示跳过。", masked: true, allowEmpty: true);
                if (string.IsNullOrWhiteSpace(admin)) admin = null;
            }

            if (MessageBox.Show("是否提供 PUK / 解锁码？（用于解锁已锁定的用户 PIN；没有可跳过）", "重置设备",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                puk = InputDialog.Ask(this, "重置设备",
                    "请输入 PUK / 解锁码：\n留空表示跳过。", masked: true, allowEmpty: true);
                if (string.IsNullOrWhiteSpace(puk)) puk = null;
            }
        }
        else
        {
            var usePuk = AskPuk();
            if (usePuk)
            {
                puk = InputDialog.Ask(this, "重置设备", "设置 PUK：\n留空则随机生成。", allowEmpty: true);
                if (string.IsNullOrEmpty(puk)) puk = Validators.RandomPassword(8);
                var hasAdmin = MessageBox.Show("是否同时设置 Admin Key？", "重置设备", MessageBoxButtons.YesNo) == DialogResult.Yes;
                if (hasAdmin)
                {
                    admin = InputDialog.Ask(this, "重置设备", "设置 Admin Key：\n留空则随机生成。", allowEmpty: true);
                    if (string.IsNullOrEmpty(admin)) admin = Validators.RandomPassword(16);
                }
            }
        }

        RunBusy("正在重置设备（清空内容并重设口令）…", () =>
        {
            OnPlatform(dev.Platform, () => prov.ResetDevice(dev, newPin, puk, admin, currentPin));
        });
        dev.IsLoggedIn = true;
        _ctx.MarkLoggedIn(dev);

        var successMsg = needCurrentPin ? "设备内容已清空，口令已重设。" : "设备已初始化。";
        if (!needCurrentPin && !isLnca && !isBjca && puk != null)
            successMsg += Environment.NewLine + "请妥善保管重置信息。";
        if (isBjca)
            successMsg += Environment.NewLine + Environment.NewLine +
                          "已重设：管理口令（SO PIN）" + (admin == null ? "（默认值）" : "") +
                          "、用户 PIN。请务必记录新口令。";
        if (isLnca && prov is LncaProvider lnca && lnca.LastResetReport != null)
            successMsg += Environment.NewLine + Environment.NewLine + "执行报告：" + Environment.NewLine + lnca.LastResetReport;
        if (prov is BjcaProvider bjca && !string.IsNullOrEmpty(bjca.LastResetReport))
            successMsg += Environment.NewLine + Environment.NewLine + "执行报告：" + Environment.NewLine + bjca.LastResetReport;
        if (prov is SkfProvider skfProv && !string.IsNullOrEmpty(skfProv.LastResetReport))
            successMsg += Environment.NewLine + Environment.NewLine + "执行报告：" + Environment.NewLine + skfProv.LastResetReport;
        if (prov is HengBaoProvider hb && !string.IsNullOrEmpty(hb.LastResetSummary))
            successMsg += Environment.NewLine + Environment.NewLine + "执行报告：" + Environment.NewLine + hb.LastResetSummary;

        MessageBox.Show(successMsg, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        ReloadDevices();
    }

    private bool AskPuk() =>
        MessageBox.Show("是否设置 PUK？\n（留空或不设置时将随机生成，重置时需使用 PUK/Admin Key）", "重置设备",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;

    private void MessageUnavailable(string msg) =>
        MessageBox.Show(msg, AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);

    private void OnFormClosing(object? s, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            if (_tray != null)
            {
                e.Cancel = true;
                Hide();
                _tray.ShowBalloonTip(1200, AppConfig.SoftwareName, "程序已最小化到托盘。右击图标可退出。", ToolTipIcon.Info);
                return;
            }
        }
        _sessionTimer.Stop();
        _refreshDebounce.Stop();
        _logTimer.Stop();
        Log.Line -= OnLogLine;
        _tray?.Dispose();
        _toolTip.Dispose();
    }
}
